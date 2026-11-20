import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigManager, ConfigValidationError, defaultConfig, validateConfig } from '../../src/config/config.js';

const tmpFile = (content: string | object) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatekeeper-config-'));
  const file = path.join(dir, 'gatekeeper.config.json');
  fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
  return file;
};

const issuesOf = (raw: unknown): string[] => {
  try {
    validateConfig(raw);
    return [];
  } catch (err) {
    if (err instanceof ConfigValidationError) return err.issues;
    throw err;
  }
};

describe('validateConfig', () => {
  test('fills every optional section with defaults', () => {
    expect(validateConfig({})).toEqual(defaultConfig());
  });

  test('accepts the example config shipped in the repo', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '../../gatekeeper.config.json'), 'utf-8'));
    const config = validateConfig(raw);
    expect(config.routes.map((r) => r.pathPrefix)).toEqual(['/api/v1', '/auth']);
    expect(config.server.adminHost).toBe('127.0.0.1');
  });

  test('defaults admin API to loopback and trustProxy to false', () => {
    const config = validateConfig({ server: { port: 9000 } });
    expect(config.server.adminHost).toBe('127.0.0.1');
    expect(config.server.trustProxy).toBe(false);
  });

  test.each([
    [{ server: { port: 'eighty' } }, 'server.port must be an integer'],
    [{ server: { port: 70000 } }, 'server.port must be an integer'],
    [{ server: { trustProxy: 'yes' } }, 'server.trustProxy must be a boolean'],
    [{ routes: {} }, 'routes must be an array'],
    [{ routes: [{ pathPrefix: 'api', targets: ['http://127.0.0.1:1'] }] }, 'must start with "/"'],
    [{ routes: [{ pathPrefix: '/api', targets: [] }] }, 'at least one URL'],
    [{ routes: [{ pathPrefix: '/api', targets: ['not a url'] }] }, 'not a valid URL'],
    [{ routes: [{ pathPrefix: '/api', targets: ['https://example.com'] }] }, 'must use http://'],
    [{ routes: [{ pathPrefix: '/api', targets: ['http://a'], balanceStrategy: 'random' }] }, 'balanceStrategy'],
    [{ routes: [{ pathPrefix: '/api', targets: ['http://a'], rateLimit: { windowMs: 0, maxRequests: 1 } }] }, 'rateLimit.windowMs'],
    [{ firewall: { ipBlacklist: ['10.0.0.300'] } }, 'not a valid IP or CIDR'],
    [{ firewall: { ipWhitelist: ['10.0.0.0/33'] } }, 'not a valid IP or CIDR'],
    [{ firewall: { customBlockedPaths: ['(unclosed'] } }, 'not a valid regular expression'],
    [{ rateLimiter: { globalMaxRequests: -1 } }, 'rateLimiter.globalMaxRequests'],
    [{ healthCheck: { intervalMs: 1 } }, 'healthCheck.intervalMs']
  ])('rejects %j', (raw, expected) => {
    expect(issuesOf(raw).join('\n')).toContain(expected);
  });

  test('rejects duplicated route prefixes and non-object roots', () => {
    const route = { pathPrefix: '/api', targets: ['http://127.0.0.1:1'] };
    expect(issuesOf({ routes: [route, route] }).join()).toContain('duplicated');
    expect(issuesOf([])).toEqual(['config root must be a JSON object']);
  });

  test('reports all issues at once', () => {
    expect(issuesOf({ server: { port: -1, adminPort: 'x' }, firewall: { ipBlacklist: ['nope'] } })).toHaveLength(3);
  });
});

describe('ConfigManager', () => {
  test('loads and validates a file from disk', () => {
    const file = tmpFile({ routes: [{ pathPrefix: '/x', targets: ['http://127.0.0.1:1'] }] });
    const manager = new ConfigManager(file, { watch: false });
    expect(manager.getConfig().routes).toHaveLength(1);
    expect(manager.getPath()).toBe(file);
  });

  test('falls back to defaults when the file does not exist', () => {
    const manager = new ConfigManager(path.join(os.tmpdir(), 'does-not-exist-gatekeeper.json'), { watch: false });
    expect(manager.getConfig()).toEqual(defaultConfig());
  });

  test('fails fast on invalid JSON or invalid values at startup', () => {
    expect(() => new ConfigManager(tmpFile('{ nope'), { watch: false })).toThrow(ConfigValidationError);
    expect(() => new ConfigManager(tmpFile({ server: { port: 'x' } }), { watch: false })).toThrow(/server.port/);
  });

  test('reload applies a valid change and notifies listeners', () => {
    const file = tmpFile({});
    const manager = new ConfigManager(file, { watch: false });
    const listener = jest.fn();
    manager.onChange(listener);

    fs.writeFileSync(file, JSON.stringify({ firewall: { ipBlacklist: ['203.0.113.9'] } }));
    expect(manager.reload()).toBe(true);
    expect(manager.getConfig().firewall.ipBlacklist).toEqual(['203.0.113.9']);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(manager.reload()).toBe(false); // unchanged content is ignored
  });

  test('reload keeps the last good config when the new file is invalid', () => {
    const file = tmpFile({ routes: [{ pathPrefix: '/keep', targets: ['http://127.0.0.1:1'] }] });
    const manager = new ConfigManager(file, { watch: false });
    const listener = jest.fn();
    manager.onChange(listener);

    fs.writeFileSync(file, '{"routes": [ {"pathPrefix": "/half-writ');
    expect(manager.reload()).toBe(false);
    fs.writeFileSync(file, JSON.stringify({ routes: [{ pathPrefix: 'bad', targets: [] }] }));
    expect(manager.reload()).toBe(false);

    expect(manager.getConfig().routes[0].pathPrefix).toBe('/keep');
    expect(listener).not.toHaveBeenCalled();
  });

  test('updateConfig validates, persists to disk and notifies', () => {
    const file = tmpFile({});
    const manager = new ConfigManager(file, { watch: false });
    const listener = jest.fn();
    manager.onChange(listener);

    const firewall = { ...manager.getConfig().firewall, ipBlacklist: ['198.51.100.0/24'] };
    manager.updateConfig({ firewall });
    expect(JSON.parse(fs.readFileSync(file, 'utf-8')).firewall.ipBlacklist).toEqual(['198.51.100.0/24']);
    expect(listener).toHaveBeenCalledTimes(1);

    expect(() => manager.updateConfig({ firewall: { ...firewall, ipBlacklist: ['bogus'] } })).toThrow(
      ConfigValidationError
    );
    expect(manager.getConfig().firewall.ipBlacklist).toEqual(['198.51.100.0/24']);
  });

  test('watches the file and hot-reloads changes', async () => {
    const file = tmpFile({});
    const manager = new ConfigManager(file, { pollIntervalMs: 50 });
    try {
      const changed = new Promise((resolve) => manager.onChange(resolve));
      await new Promise((r) => setTimeout(r, 100));
      fs.writeFileSync(file, JSON.stringify({ rateLimiter: { globalWindowMs: 1000, globalMaxRequests: 7 } }));
      await changed;
      expect(manager.getConfig().rateLimiter.globalMaxRequests).toBe(7);
    } finally {
      manager.close();
    }
  });
});
