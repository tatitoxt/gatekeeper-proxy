import { ADMIN_TOKEN, startStack, Stack } from './support.js';

// The compiled entrypoint in clustered mode: primary owns the admin API,
// forked workers share the proxy port and respawn on exit.
describe('gatekeeper cluster mode (dist/index.js)', () => {
  let stack: Stack;

  beforeAll(async () => {
    stack = await startStack((config) => {
      config.cluster = { workers: 2 };
    });
  });
  afterAll(async () => {
    await stack?.stop();
  });

  test('serves the proxy port across forked workers', async () => {
    for (let i = 0; i < 6; i++) {
      const res = await fetch(`${stack!.proxyUrl}/api/v1/orders/1`);
      expect(res.status).toBe(200);
    }
  });

  test('admin metrics aggregate traffic recorded inside workers', async () => {
    await fetch(`${stack!.proxyUrl}/api/v1/orders/2`);
    await fetch(`${stack!.proxyUrl}/api/v1/orders/3`);
    // Workers report counters to the primary every 2s.
    await new Promise((r) => setTimeout(r, 3000));
    const res = await fetch(`${stack!.adminUrl}/api/metrics`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(res.status).toBe(200);
    const metrics = await res.json();
    expect(metrics.totalRequests).toBeGreaterThan(0);
  });

  test('the primary still owns the admin API', async () => {
    const res = await fetch(`${stack!.adminUrl}/api/health`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(res.status).toBe(200);
  });
});
