import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AdminServer } from '../../src/admin/admin-server.js';
import { ConfigManager } from '../../src/config/config.js';
import { MetricsCollector } from '../../src/metrics/metrics.js';
import { request } from '../helpers.js';

const TOKEN = 'test-token-not-a-secret';

function setup(server: Record<string, unknown> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatekeeper-admin-'));
  const file = path.join(dir, 'gatekeeper.config.json');
  fs.writeFileSync(
    file,
    JSON.stringify({
      server: { port: 0, adminPort: 0, adminHost: '127.0.0.1', ...server },
      routes: [{ pathPrefix: '/api', targets: ['http://127.0.0.1:9001'] }]
    })
  );
  const manager = new ConfigManager(file, { watch: false });
  const metrics = new MetricsCollector();
  return { file, manager, metrics };
}

describe('AdminServer with a token', () => {
  const { file, manager, metrics } = setup();
  const admin = new AdminServer(manager, metrics, { token: TOKEN });
  let base: string;
  const auth = { authorization: `Bearer ${TOKEN}` };
  const json = { ...auth, 'content-type': 'application/json' };

  beforeAll(async () => {
    base = `http://127.0.0.1:${(await admin.start()).port}`;
  });
  afterAll(() => admin.stop());

  test('health endpoint is public', async () => {
    expect((await request(`${base}/api/health`)).json()).toEqual({ status: 'ok' });
  });

  test('GET /metrics returns the Prometheus exposition format', async () => {
    metrics.recordRequest(200);
    metrics.recordRequest(503);
    metrics.recordRateLimitHit('192.0.2.9', '/x', 'GET');
    const res = await request(`${base}/metrics`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    const body = res.body;
    expect(body).toContain('gatekeeper_requests_total 2');
    expect(body).toContain('gatekeeper_responses_total{status="200"} 1');
    expect(body).toContain('gatekeeper_responses_total{status="503"} 1');
    expect(body).toContain('gatekeeper_rate_limit_hits_total 1');
  });

  test.each(['/api/metrics', '/api/routes', '/api/firewall/blacklist'])('%s requires the bearer token', async (p) => {
    expect((await request(`${base}${p}`)).status).toBe(401);
    expect((await request(`${base}${p}`, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);
    expect((await request(`${base}${p}`, { headers: auth })).status).toBe(200);
  });

  test('returns metrics and routes', async () => {
    metrics.recordWafBlock('192.0.2.1', '/x', 'GET', 'IP Blacklisted');
    expect((await request(`${base}/api/metrics`, { headers: auth })).json()).toMatchObject({ wafBlocks: 1 });
    expect((await request(`${base}/api/routes`, { headers: auth })).json()).toEqual([
      { pathPrefix: '/api', targets: ['http://127.0.0.1:9001'] }
    ]);
  });

  test('adds and removes blacklist entries and persists them to the config file', async () => {
    const add = await request(`${base}/api/firewall/blacklist`, {
      method: 'POST',
      headers: json,
      body: JSON.stringify({ ip: '203.0.113.0/24' })
    });
    expect(add.json()).toMatchObject({ success: true, changed: true, ipBlacklist: ['203.0.113.0/24'] });
    expect(JSON.parse(fs.readFileSync(file, 'utf-8')).firewall.ipBlacklist).toEqual(['203.0.113.0/24']);

    const again = await request(`${base}/api/firewall/blacklist`, {
      method: 'POST',
      headers: json,
      body: JSON.stringify({ ip: '203.0.113.0/24' })
    });
    expect(again.json()).toMatchObject({ changed: false });

    const del = await request(`${base}/api/firewall/blacklist`, {
      method: 'DELETE',
      headers: json,
      body: JSON.stringify({ ip: '203.0.113.0/24' })
    });
    expect(del.json()).toMatchObject({ changed: true, ipBlacklist: [] });
    expect(manager.getConfig().firewall.ipBlacklist).toEqual([]);
  });

  test.each([
    [{ ...json }, '{"ip":"not-an-ip"}', 400],
    [{ ...json }, '{"ip":"10.0.0.1/40"}', 400],
    [{ ...json }, 'not json', 400],
    [{ ...json }, '{}', 400],
    [{ ...auth, 'content-type': 'text/plain' }, '{"ip":"10.0.0.1"}', 415],
    [{ ...json }, JSON.stringify({ ip: '10.0.0.1', pad: 'x'.repeat(10_000) }), 413]
  ])('rejects invalid blacklist payloads (%#)', async (headers, body, status) => {
    const res = await request(`${base}/api/firewall/blacklist`, { method: 'POST', headers, body }).catch(
      (err: NodeJS.ErrnoException) => ({ status: err.code === 'ECONNRESET' || err.code === 'EPIPE' ? 413 : 0 })
    );
    expect(res.status).toBe(status);
  });

  test('serves the dashboard with a strict CSP and no inline script', async () => {
    const page = await request(`${base}/_admin`);
    expect(page.status).toBe(200);
    expect(page.headers['content-security-policy']).toContain("script-src 'self'");
    expect(page.headers['x-frame-options']).toBe('DENY');
    expect(page.body).toContain('<script src="/_admin/app.js"></script>');
    expect(page.body).not.toMatch(/<script>|onclick=/);
    const js = await request(`${base}/_admin/app.js`);
    expect(js.headers['content-type']).toContain('text/javascript');
    expect(js.body).toContain('textContent');
    expect(js.body).not.toContain('innerHTML');
  });

  test('unknown paths and methods', async () => {
    expect((await request(`${base}/nope`)).status).toBe(404);
    expect((await request(`${base}/api/nope`, { headers: auth })).status).toBe(404);
    expect((await request(`${base}/api/firewall/blacklist`, { method: 'PUT', headers: auth })).status).toBe(405);
  });
});

describe('AdminServer without a token', () => {
  test('is open on loopback', async () => {
    const { manager, metrics } = setup();
    const admin = new AdminServer(manager, metrics);
    const { port } = await admin.start();
    try {
      expect((await request(`http://127.0.0.1:${port}/api/metrics`)).status).toBe(200);
    } finally {
      await admin.stop();
    }
  });

  test('refuses to bind a non-loopback interface', async () => {
    const { manager, metrics } = setup({ adminHost: '0.0.0.0' });
    await expect(new AdminServer(manager, metrics).start()).rejects.toThrow(/GATEKEEPER_ADMIN_TOKEN/);
  });
});
