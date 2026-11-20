import net, { AddressInfo } from 'node:net';
import { ProxyServer } from '../../src/core/proxy.js';
import { GatekeeperConfig } from '../../src/config/config.js';
import { makeConfig, rawRequest, request, startUpstream, Upstream } from '../helpers.js';

describe('ProxyServer (in-process, real sockets)', () => {
  let a: Upstream;
  let b: Upstream;
  let slow: Upstream;
  let proxy: ProxyServer;
  let base: string;
  let port: number;

  const config = (): GatekeeperConfig =>
    makeConfig({
      server: { port: 0, adminPort: 0, host: '127.0.0.1', adminHost: '127.0.0.1', timeoutMs: 300, trustProxy: false },
      routes: [
        { pathPrefix: '/api', targets: [a.url, b.url] },
        { pathPrefix: '/auth', targets: [a.url], rateLimit: { windowMs: 60_000, maxRequests: 2 } },
        { pathPrefix: '/slow', targets: [slow.url] },
        { pathPrefix: '/down', targets: ['http://127.0.0.1:1'] }
      ],
      firewall: {
        enabled: true,
        ipBlacklist: [],
        ipWhitelist: [],
        blockedUserAgents: ['sqlmap'],
        wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
        customBlockedPaths: ['^/\\.env']
      },
      rateLimiter: { globalWindowMs: 60_000, globalMaxRequests: 1000 }
    });

  beforeAll(async () => {
    a = await startUpstream('a');
    b = await startUpstream('b');
    slow = await startUpstream('slow', (_req, res) => {
      setTimeout(() => {
        res.writeHead(200);
        res.end('late');
      }, 1_000);
    });
    proxy = new ProxyServer(config());
    const addr: AddressInfo = await proxy.start();
    port = addr.port;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await proxy.stop();
    await Promise.all([a.close(), b.close(), slow.close()]);
  });

  test('forwards method, path, query and body, and load-balances round-robin', async () => {
    const first = await request(`${base}/api/v1/users?page=2`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"name":"Ada"}'
    });
    const second = await request(`${base}/api/v1/users`);
    expect(first.status).toBe(200);
    const one = first.json<{ upstream: string; url: string; method: string; body: string }>();
    expect(one).toMatchObject({ url: '/api/v1/users?page=2', method: 'POST', body: '{"name":"Ada"}' });
    expect(new Set([one.upstream, second.json().upstream])).toEqual(new Set(['a', 'b']));
  });

  test('re-frames chunked GET bodies so an embedded request cannot be smuggled upstream', async () => {
    const smuggled = 'GET /api/smuggled HTTP/1.1\r\nHost: upstream\r\n\r\n';
    const chunk = Buffer.byteLength(smuggled).toString(16);
    const [beforeA, beforeB] = [a.requests.length, b.requests.length];
    const response = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(port, '127.0.0.1', () => {
        socket.write(
          'GET /api/chunked HTTP/1.1\r\nHost: gatekeeper\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' +
            `${chunk}\r\n${smuggled}\r\n0\r\n\r\n`
        );
      });
      let data = '';
      socket.on('data', (d) => (data += d.toString()));
      socket.on('end', () => resolve(data));
      socket.on('error', reject);
    });
    await new Promise((r) => setTimeout(r, 100));

    expect(response).toMatch(/^HTTP\/1\.1 200/);
    const received = [...a.requests.slice(beforeA), ...b.requests.slice(beforeB)];
    expect(received.map((r) => r.url)).toEqual(['/api/chunked']);
    expect(received[0].body).toBe(smuggled);
  });

  test('sets forwarding headers and strips hop-by-hop headers', async () => {
    const res = await request(`${base}/api/headers`, {
      headers: { 'x-forwarded-for': '6.6.6.6', connection: 'x-drop-me', 'x-drop-me': '1', 'x-keep': 'yes' }
    });
    const { headers } = res.json<{ headers: Record<string, string> }>();
    expect(headers['x-forwarded-for']).toBe('127.0.0.1'); // spoofed value discarded (trustProxy off)
    expect(headers['x-real-ip']).toBe('127.0.0.1');
    expect(headers['x-forwarded-host']).toBe(`127.0.0.1:${port}`);
    expect(headers['x-gatekeeper-proxy']).toBe('1.0');
    expect(headers['x-keep']).toBe('yes');
    expect(headers['x-drop-me']).toBeUndefined();
    expect(res.headers['x-ratelimit-limit']).toBe('1000');
  });

  test('blocks firewall violations before they reach the upstream', async () => {
    const before = a.requests.length + b.requests.length;
    const results = await Promise.all([
      request(`${base}/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E`),
      request(`${base}/api/users?id=1%20OR%201=1`),
      rawRequest(port, '/api/../../etc/passwd'),
      request(`${base}/.env`),
      request(`${base}/api/ok`, { headers: { 'user-agent': 'sqlmap/1.7' } })
    ]);
    expect(results.map((r) => r.status)).toEqual([403, 403, 403, 403, 403]);
    expect(results[0].json()).toMatchObject({ error: 'Forbidden', status: 403 });
    expect(a.requests.length + b.requests.length).toBe(before);
  });

  test('answers malformed percent-encoding with 400 and keeps serving', async () => {
    const bad = await rawRequest(port, '/api/%E0%A4%A');
    expect(bad.status).toBe(400);
    expect(bad.json()).toMatchObject({ error: 'Bad Request', message: 'Malformed URL encoding' });
    expect((await request(`${base}/api/still-alive`)).status).toBe(200);
  });

  test('enforces route rate limits with standard headers', async () => {
    const statuses = [];
    let last;
    for (let i = 0; i < 3; i++) {
      last = await request(`${base}/auth/login`, { method: 'POST' });
      statuses.push(last.status);
    }
    expect(statuses).toEqual([200, 200, 429]);
    expect(last!.headers['x-ratelimit-limit']).toBe('2');
    expect(last!.headers['x-ratelimit-remaining']).toBe('0');
    expect(Number(last!.headers['retry-after'])).toBeGreaterThan(0);
    expect(last!.json()).toMatchObject({ error: 'Too Many Requests', scope: 'route' });
  });

  test('returns 404 for paths without a route (including prefix look-alikes)', async () => {
    expect((await request(`${base}/apiary`)).status).toBe(404);
    expect((await request(`${base}/nothing`)).json()).toMatchObject({ error: 'Not Found' });
  });

  test('returns 502 when the upstream refuses connections', async () => {
    const res = await request(`${base}/down/x`);
    expect(res.status).toBe(502);
    expect(res.json()).toMatchObject({ error: 'Bad Gateway' });
  });

  test('returns 504 when the upstream exceeds server.timeoutMs', async () => {
    const res = await request(`${base}/slow/x`);
    expect(res.status).toBe(504);
    expect(res.json()).toMatchObject({ error: 'Gateway Timeout' });
  });

  test('records metrics and security events', () => {
    const summary = proxy.getMetrics().getSummary();
    expect(summary.wafBlocks).toBeGreaterThanOrEqual(6);
    expect(summary.rateLimitHits).toBe(1);
    expect(summary.statusCounts[502]).toBe(1);
    expect(summary.recentEvents.some((e) => e.type === 'rate-limit' && e.path === '/auth/login')).toBe(true);
  });

  test('applies config updates without restarting', async () => {
    const next = config();
    next.firewall.ipBlacklist = ['127.0.0.1'];
    proxy.updateConfig(next);
    expect((await request(`${base}/api/x`)).json()).toMatchObject({ message: 'IP Blacklisted' });
    proxy.updateConfig(config());
    expect((await request(`${base}/api/x`)).status).toBe(200);
  });
});

describe('ProxyServer behind a trusted proxy', () => {
  let upstream: Upstream;
  let proxy: ProxyServer;
  let base: string;

  beforeAll(async () => {
    upstream = await startUpstream('u');
    proxy = new ProxyServer(
      makeConfig({
        server: { port: 0, adminPort: 0, host: '127.0.0.1', adminHost: '127.0.0.1', timeoutMs: 1000, trustProxy: true },
        routes: [{ pathPrefix: '/', targets: [upstream.url] }],
        firewall: { ...makeConfig().firewall, ipBlacklist: ['203.0.113.7'] }
      })
    );
    base = `http://127.0.0.1:${(await proxy.start()).port}`;
  });
  afterAll(async () => {
    await proxy.stop();
    await upstream.close();
  });

  test('uses the right-most X-Forwarded-For hop for IP rules and appends the peer', async () => {
    const blocked = await request(`${base}/x`, { headers: { 'x-forwarded-for': '198.51.100.1, 203.0.113.7' } });
    expect(blocked.status).toBe(403);
    const ok = await request(`${base}/x`, { headers: { 'x-forwarded-for': '198.51.100.1' } });
    expect(ok.json<{ headers: Record<string, string> }>().headers['x-forwarded-for']).toBe('198.51.100.1, 127.0.0.1');
  });
});

describe('ProxyServer health-based failover', () => {
  test('stops sending traffic to a target that fails health checks and returns 503 when none are left', async () => {
    let bHealthy = true;
    const a = await startUpstream('a', (req, res) => {
      res.writeHead(req.url === '/health' ? 500 : 200);
      res.end('a');
    });
    const b = await startUpstream('b', (req, res) => {
      res.writeHead(req.url === '/health' && !bHealthy ? 500 : 200);
      res.end('b');
    });
    const proxy = new ProxyServer(
      makeConfig({
        routes: [{ pathPrefix: '/svc', targets: [a.url, b.url], healthCheckPath: '/health' }],
        healthCheck: { intervalMs: 60_000, timeoutMs: 500 }
      })
    );
    const base = `http://127.0.0.1:${(await proxy.start()).port}`;
    try {
      await proxy.getLoadBalancer().runHealthChecks();
      const bodies = await Promise.all([1, 2, 3, 4].map(() => request(`${base}/svc/x`).then((r) => r.body)));
      expect(bodies).toEqual(['b', 'b', 'b', 'b']);

      bHealthy = false;
      await proxy.getLoadBalancer().runHealthChecks();
      const res = await request(`${base}/svc/x`);
      expect(res.status).toBe(503);
      expect(res.json()).toMatchObject({ error: 'Service Unavailable' });
    } finally {
      await proxy.stop();
      await a.close();
      await b.close();
    }
  });
});
