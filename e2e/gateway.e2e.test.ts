import fs from 'node:fs';
import { ADMIN_TOKEN, freePort, JsonConfig, startStack, Stack, waitFor } from './support.js';

// Black-box tests: the real CLI entrypoint as a child process, synthetic upstreams,
// and plain HTTP via fetch — no imports from src/.
describe('gatekeeper (dist/index.js) end to end', () => {
  let stack: Stack;
  const admin = (path: string, init: RequestInit = {}) =>
    fetch(`${stack.adminUrl}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json', ...(init.headers ?? {}) }
    });

  beforeAll(async () => {
    stack = await startStack();
  });
  afterAll(async () => {
    await stack?.stop();
  });

  test('routes /api/v1 round-robin across both healthy upstreams', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 4; i++) {
      const res = await fetch(`${stack.proxyUrl}/api/v1/orders/42?expand=items`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.url).toBe('/api/v1/orders/42?expand=items');
      seen.add(body.upstream);
    }
    expect(seen).toEqual(new Set([`demo-upstream-${stack.upstreamPorts[0]}`, `demo-upstream-${stack.upstreamPorts[1]}`]));
  });

  test('forwards POST bodies to the /auth upstream', async () => {
    const res = await fetch(`${stack.proxyUrl}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user: 'demo' })
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      upstream: `demo-upstream-${stack.upstreamPorts[2]}`,
      method: 'POST',
      body: '{"user":"demo"}',
      forwardedFor: '127.0.0.1'
    });
  });

  test.each([
    ['SQL injection', '/api/v1/users?id=1%27%20OR%20%271%27=%271'],
    ['XSS', '/api/v1/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'],
    ['encoded traversal', '/api/v1/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd'],
    ['custom blocked path', '/.env'],
    ['custom blocked path', '/wp-login.php']
  ])('blocks %s with 403 (%s)', async (_name, path) => {
    const res = await fetch(`${stack.proxyUrl}${path}`);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'Forbidden' });
  });

  test('blocks scanner user agents', async () => {
    const res = await fetch(`${stack.proxyUrl}/api/v1/ping`, { headers: { 'user-agent': 'sqlmap/1.8' } });
    expect(res.status).toBe(403);
  });

  test('returns 404 for unrouted paths', async () => {
    expect((await fetch(`${stack.proxyUrl}/unknown`)).status).toBe(404);
  });

  test('admin API rejects requests without the token', async () => {
    expect((await fetch(`${stack.adminUrl}/api/metrics`)).status).toBe(401);
    expect((await fetch(`${stack.adminUrl}/api/health`)).status).toBe(200);
  });

  test('admin blacklist takes effect on live traffic and is persisted to the config file', async () => {
    const add = await admin('/api/firewall/blacklist', { method: 'POST', body: JSON.stringify({ ip: '127.0.0.1' }) });
    expect(add.status).toBe(200);
    const blocked = await fetch(`${stack.proxyUrl}/api/v1/ping`);
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ message: 'IP Blacklisted' });
    expect(JSON.parse(fs.readFileSync(stack.configPath, 'utf-8')).firewall.ipBlacklist).toContain('127.0.0.1');

    const del = await admin('/api/firewall/blacklist', { method: 'DELETE', body: JSON.stringify({ ip: '127.0.0.1' }) });
    expect(del.status).toBe(200);
    expect((await fetch(`${stack.proxyUrl}/api/v1/ping`)).status).toBe(200);
  });

  let lastGood: JsonConfig;

  test('hot-reloads edits to the config file without a restart', async () => {
    const config = JSON.parse(fs.readFileSync(stack.configPath, 'utf-8'));
    lastGood = config;
    config.routes.push({ pathPrefix: '/reports', targets: [`http://127.0.0.1:${stack.upstreamPorts[2]}`] });
    fs.writeFileSync(stack.configPath, JSON.stringify(config, null, 2));
    await waitFor(async () => (await fetch(`${stack.proxyUrl}/reports/daily`)).status === 200, 8_000);

    // an invalid edit is rejected and the last good config stays active
    fs.writeFileSync(stack.configPath, '{ "routes": [ { "pathPrefix": "no-slash" } ] }');
    await waitFor(async () => stack.gateway.output().includes('keeping last valid configuration'), 8_000);
    expect((await fetch(`${stack.proxyUrl}/reports/daily`)).status).toBe(200);
  });

  test('enforces the /auth route limit (10 req/min) with 429 and rate-limit headers', async () => {
    // one /auth request was already made above
    const statuses: number[] = [];
    let last: Response | undefined;
    for (let i = 0; i < 10; i++) {
      last = await fetch(`${stack.proxyUrl}/auth/token`, { method: 'POST' });
      statuses.push(last.status);
    }
    expect(statuses.slice(0, 9).every((s) => s === 200)).toBe(true);
    expect(statuses[9]).toBe(429);
    expect(last!.headers.get('x-ratelimit-limit')).toBe('10');
    expect(Number(last!.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  test('metrics reflect the traffic above', async () => {
    const metrics = await (await admin('/api/metrics')).json();
    expect(metrics.wafBlocks).toBeGreaterThanOrEqual(7);
    expect(metrics.rateLimitHits).toBeGreaterThanOrEqual(1);
    expect(metrics.recentEvents[0]).toMatchObject({ type: 'rate-limit', path: '/auth/token' });
  });

  test('health checks take a dead upstream out of rotation', async () => {
    const deadPort = await freePort();
    lastGood.routes.push({
      pathPrefix: '/flaky',
      targets: [`http://127.0.0.1:${stack.upstreamPorts[0]}`, `http://127.0.0.1:${deadPort}`],
      healthCheckPath: '/health'
    });
    fs.writeFileSync(stack.configPath, JSON.stringify(lastGood, null, 2));
    await waitFor(async () => {
      const statuses = await Promise.all([1, 2, 3, 4].map(async () => (await fetch(`${stack.proxyUrl}/flaky/x`)).status));
      return statuses.every((s) => s === 200);
    }, 10_000, 250);
    for (let i = 0; i < 6; i++) {
      const body = await (await fetch(`${stack.proxyUrl}/flaky/x`)).json();
      expect(body.upstream).toBe(`demo-upstream-${stack.upstreamPorts[0]}`);
    }
  });
});

describe('gatekeeper process lifecycle', () => {
  test('exits 1 with a clear error when the config is invalid', async () => {
    await expect(
      startStack((config) => {
        config.server.port = 70000;
      })
    ).rejects.toThrow(/exited with 1[\s\S]*server\.port/);
  });

  test('shuts down gracefully on SIGTERM with exit code 0', async () => {
    const stack = await startStack();
    try {
      expect(await stack.gateway.stop('SIGTERM')).toBe(0);
      expect(stack.gateway.output()).toContain('Shutting down Gatekeeper');
    } finally {
      await stack.stop();
    }
  });
});
