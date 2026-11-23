import { RateLimiterEngine } from '../../src/rate-limiter/rate-limiter.js';
import type { RateLimiterConfig } from '../../src/config/config.js';

const cfg = (over: Partial<RateLimiterConfig> = {}): RateLimiterConfig => ({
  globalWindowMs: 60_000,
  globalMaxRequests: 3,
  backend: 'memory',
  ...over
});

describe('RateLimiterEngine', () => {
  let clock: number;
  let limiter: RateLimiterEngine;
  const now = () => clock;

  beforeEach(() => {
    clock = 1_000_000;
    limiter = new RateLimiterEngine(cfg(), now);
  });
  afterEach(() => limiter.close());

  test('allows up to the limit, then blocks with remaining 0', async () => {
    const results = await Promise.all([1, 2, 3, 4].map(() => limiter.checkRateLimit('192.0.2.1')));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0]);
    expect(results[3]).toMatchObject({ limit: 3, scope: 'global', resetMs: 60_000 });
  });

  test('tracks IPs independently', async () => {
    for (let i = 0; i < 3; i++) await limiter.checkRateLimit('192.0.2.1');
    expect((await limiter.checkRateLimit('192.0.2.1')).allowed).toBe(false);
    expect((await limiter.checkRateLimit('192.0.2.2')).allowed).toBe(true);
  });

  test('slides the window: old requests expire', async () => {
    await limiter.checkRateLimit('192.0.2.1');
    clock += 30_000;
    await limiter.checkRateLimit('192.0.2.1');
    await limiter.checkRateLimit('192.0.2.1');
    const blocked = await limiter.checkRateLimit('192.0.2.1');
    expect(blocked.allowed).toBe(false);
    expect(blocked.resetMs).toBe(30_000);
    clock += 30_001;
    expect((await limiter.checkRateLimit('192.0.2.1')).allowed).toBe(true);
  });

  test('applies the route limit and reports it when it is the most restrictive', async () => {
    const route = { windowMs: 10_000, maxRequests: 1 };
    const first = await limiter.checkRateLimit('192.0.2.1', '/auth', route);
    expect(first).toMatchObject({ allowed: true, limit: 1, remaining: 0, scope: 'route' });
    const second = await limiter.checkRateLimit('192.0.2.1', '/auth', route);
    expect(second).toMatchObject({ allowed: false, scope: 'route', resetMs: 10_000 });
    // other routes still use the global window
    expect(await limiter.checkRateLimit('192.0.2.1', '/api')).toMatchObject({
      allowed: true,
      scope: 'global'
    });
  });

  test('requests rejected by one window do not consume quota in the other', async () => {
    const route = { windowMs: 60_000, maxRequests: 10 };
    for (let i = 0; i < 3; i++) await limiter.checkRateLimit('192.0.2.1', '/api', route);
    for (let i = 0; i < 5; i++)
      expect((await limiter.checkRateLimit('192.0.2.1', '/api', route)).allowed).toBe(false);
    limiter.updateGlobalConfig(cfg({ globalMaxRequests: 100 }));
    const res = await limiter.checkRateLimit('192.0.2.1', '/api', route);
    expect(res).toMatchObject({ allowed: true, scope: 'route', remaining: 6 });
  });

  test('sweep removes expired records from global and route stores', async () => {
    await limiter.checkRateLimit('192.0.2.1', '/auth', { windowMs: 1_000, maxRequests: 5 });
    await limiter.checkRateLimit('192.0.2.2');
    expect(await limiter.trackedKeys()).toBe(3);
    clock += 1_001;
    expect(await limiter.sweep()).toBe(1);
    clock += 60_000;
    expect(await limiter.sweep()).toBe(2);
    expect(await limiter.trackedKeys()).toBe(0);
  });
});
