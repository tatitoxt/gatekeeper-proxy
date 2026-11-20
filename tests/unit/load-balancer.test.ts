import { LoadBalancer } from '../../src/core/load-balancer.js';
import { RouteConfig } from '../../src/config/config.js';
import { startUpstream, Upstream } from '../helpers.js';

const route = (overrides: Partial<RouteConfig> = {}): RouteConfig => ({
  pathPrefix: '/api',
  targets: ['http://a:1', 'http://b:2', 'http://c:3'],
  ...overrides
});

describe('LoadBalancer', () => {
  test('round-robin cycles through targets', () => {
    const r = route();
    const lb = new LoadBalancer([r]);
    expect([1, 2, 3, 4].map(() => lb.selectTarget(r))).toEqual(['http://a:1', 'http://b:2', 'http://c:3', 'http://a:1']);
  });

  test('least-connections picks the least busy target', () => {
    const r = route({ balanceStrategy: 'least-connections' });
    const lb = new LoadBalancer([r]);
    lb.incrementConnection('/api', 'http://a:1');
    lb.incrementConnection('/api', 'http://b:2');
    expect(lb.selectTarget(r)).toBe('http://c:3');
    lb.incrementConnection('/api', 'http://c:3');
    lb.incrementConnection('/api', 'http://c:3');
    lb.decrementConnection('/api', 'http://a:1');
    expect(lb.selectTarget(r)).toBe('http://a:1');
  });

  test('passive failures only affect routes with a health check and skip that target', () => {
    const checked = route({ healthCheckPath: '/health' });
    const lb = new LoadBalancer([checked]);
    lb.reportFailure('/api', 'http://a:1');
    expect(new Set([1, 2, 3, 4].map(() => lb.selectTarget(checked)))).toEqual(new Set(['http://b:2', 'http://c:3']));

    const unchecked = route();
    const lb2 = new LoadBalancer([unchecked]);
    lb2.reportFailure('/api', 'http://a:1');
    expect(lb2.getTargetStates('/api').every((t) => t.isHealthy)).toBe(true);
  });

  test('returns null when every target is down', () => {
    const r = route({ targets: ['http://a:1'], healthCheckPath: '/health' });
    const lb = new LoadBalancer([r]);
    lb.reportFailure('/api', 'http://a:1');
    expect(lb.selectTarget(r)).toBeNull();
    expect(lb.selectTarget(route({ pathPrefix: '/unknown' }))).toBeNull();
  });

  test('updateRoutes keeps state for unchanged targets and drops removed routes', () => {
    const r = route({ healthCheckPath: '/health' });
    const lb = new LoadBalancer([r, route({ pathPrefix: '/old' })]);
    lb.reportFailure('/api', 'http://a:1');
    lb.updateRoutes([{ ...r, targets: ['http://a:1', 'http://d:4'] }]);
    expect(lb.getTargetStates('/api')).toEqual([
      { url: 'http://a:1', isHealthy: false, activeConnections: 0 },
      { url: 'http://d:4', isHealthy: true, activeConnections: 0 }
    ]);
    expect(lb.getTargetStates('/old')).toEqual([]);
  });

  test('removing healthCheckPath puts previously failed targets back in rotation', () => {
    const r = route({ targets: ['http://a:1'], healthCheckPath: '/health' });
    const lb = new LoadBalancer([r]);
    lb.reportFailure('/api', 'http://a:1');
    expect(lb.selectTarget(r)).toBeNull();
    const withoutChecks = route({ targets: ['http://a:1'] });
    lb.updateRoutes([withoutChecks]);
    expect(lb.selectTarget(withoutChecks)).toBe('http://a:1');
  });

  describe('active health checks against real HTTP servers', () => {
    let healthy: Upstream;
    let failing: Upstream;
    let healthStatus = 200;

    beforeAll(async () => {
      healthy = await startUpstream('healthy', (req, res) => {
        res.writeHead(req.url === '/healthz' ? healthStatus : 404);
        res.end();
      });
      failing = await startUpstream('failing', (_req, res) => {
        res.writeHead(500);
        res.end();
      });
    });
    afterAll(async () => {
      await healthy.close();
      await failing.close();
    });

    test('probes healthCheckPath and marks targets up/down', async () => {
      const r = route({ targets: [healthy.url, failing.url, 'http://127.0.0.1:1'], healthCheckPath: '/healthz' });
      const lb = new LoadBalancer([r], { intervalMs: 60_000, timeoutMs: 1_000 });
      await lb.runHealthChecks();
      expect(lb.getTargetStates('/api').map((t) => t.isHealthy)).toEqual([true, false, false]);
      expect(healthy.requests.at(-1)?.url).toBe('/healthz');

      healthStatus = 503;
      await lb.runHealthChecks();
      expect(lb.selectTarget(r)).toBeNull();

      healthStatus = 200;
      await lb.runHealthChecks();
      expect(lb.selectTarget(r)).toBe(healthy.url);
    });

    test('routes without healthCheckPath are never probed', async () => {
      const before = failing.requests.length;
      const lb = new LoadBalancer([route({ targets: [failing.url] })]);
      await lb.runHealthChecks();
      expect(failing.requests.length).toBe(before);
    });
  });
});
