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
      { url: 'http://a:1', isHealthy: false, activeConnections: 0, consecutiveFailures: 1, openUntil: null, halfOpen: false },
      { url: 'http://d:4', isHealthy: true, activeConnections: 0, consecutiveFailures: 0, openUntil: null, halfOpen: false }
    ]);
    expect(lb.getTargetStates('/old')).toEqual([]);
  });

  describe('circuit breaker', () => {
    const breaker = { failureThreshold: 3, openMs: 30_000 };

    test('opens after consecutive failures and skips the target until openMs', () => {
      const r = route();
      const lb = new LoadBalancer([r], undefined, breaker);
      lb.reportFailure('/api', 'http://a:1');
      lb.reportFailure('/api', 'http://a:1');
      expect(new Set([1, 2].map(() => lb.selectTarget(r)))).not.toEqual(new Set(['http://a:1']));
      lb.reportFailure('/api', 'http://a:1');
      // Breaker open: a:1 is out, also marked unhealthy.
      expect(lb.getTargetStates('/api')[0]).toMatchObject({ isHealthy: false, consecutiveFailures: 3 });
      expect(new Set([1, 2, 3].map(() => lb.selectTarget(r)))).toEqual(new Set(['http://b:2', 'http://c:3']));
    });

    test('opens even without a healthCheckPath and recovers after cooldown', () => {
      jest.useFakeTimers();
      try {
        const r = route({ targets: ['http://a:1'] });
        const lb = new LoadBalancer([r], undefined, breaker);
        for (let i = 0; i < 3; i++) lb.reportFailure('/api', 'http://a:1');
        expect(lb.selectTarget(r)).toBeNull();
        // Cooldown elapsed -> half-open trial admits the target again.
        jest.advanceTimersByTime(breaker.openMs + 1);
        expect(lb.selectTarget(r)).toBe('http://a:1');
        // A failing trial reopens the breaker immediately.
        lb.reportFailure('/api', 'http://a:1');
        expect(lb.selectTarget(r)).toBeNull();
      } finally {
        jest.useRealTimers();
      }
    });

    test('5xx responses feed the breaker without a connectivity-markdown', () => {
      const r = route();
      const lb = new LoadBalancer([r], undefined, breaker);
      lb.reportServerError('/api', 'http://a:1');
      lb.reportServerError('/api', 'http://a:1');
      // Below threshold: still healthy, streak recorded.
      expect(lb.getTargetStates('/api')[0]).toMatchObject({ isHealthy: true, consecutiveFailures: 2 });
      lb.reportServerError('/api', 'http://a:1');
      expect(lb.getTargetStates('/api')[0].openUntil).not.toBeNull();
      // A good response closes the breaker and clears the streak.
      lb.reportSuccess('/api', 'http://a:1');
      expect(lb.getTargetStates('/api')[0]).toMatchObject({ isHealthy: true, consecutiveFailures: 0, openUntil: null });
    });
  });

  test('an open breaker admits only one half-open trial request at a time', () => {
    const r = route({ targets: ['http://a:1', 'http://b:1'] });
    const lb = new LoadBalancer([r], undefined, { failureThreshold: 1, openMs: 0 });
    lb.reportFailure('/api', 'http://a:1');
    // Cooldown elapsed (openMs: 0): first select is the trial, further calls use others.
    expect(lb.selectTarget(r)).toBe('http://a:1');
    expect(lb.getTargetStates('/api')[0].halfOpen).toBe(true);
    // Concurrent callers are routed to other targets until the trial resolves.
    expect(lb.selectTarget(r)).toBe('http://b:1');
    // Trial failed: breaker reopens (and a 0ms cooldown arms the next trial).
    lb.reportFailure('/api', 'http://a:1');
    expect(lb.getTargetStates('/api')[0].halfOpen).toBe(false);
    expect(lb.selectTarget(r)).toBe('http://a:1');
    // Trial succeeded: breaker closes for good.
    lb.reportSuccess('/api', 'http://a:1');
    expect(lb.getTargetStates('/api')[0]).toMatchObject({ halfOpen: false, openUntil: null, consecutiveFailures: 0 });
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
