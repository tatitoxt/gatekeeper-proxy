import { RateLimiterEngine } from '../../src/rate-limiter/rate-limiter.js';

describe('RateLimiterEngine', () => {
  let clock: number;
  let limiter: RateLimiterEngine;
  const now = () => clock;

  beforeEach(() => {
    clock = 1_000_000;
    limiter = new RateLimiterEngine({ globalWindowMs: 60_000, globalMaxRequests: 3 }, now);
  });
  afterEach(() => limiter.close());

  test('allows up to the limit, then blocks with remaining 0', () => {
    const results = [1, 2, 3, 4].map(() => limiter.checkRateLimit('192.0.2.1'));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0]);
    expect(results[3]).toMatchObject({ limit: 3, scope: 'global', resetMs: 60_000 });
  });

  test('tracks IPs independently', () => {
    for (let i = 0; i < 3; i++) limiter.checkRateLimit('192.0.2.1');
    expect(limiter.checkRateLimit('192.0.2.1').allowed).toBe(false);
    expect(limiter.checkRateLimit('192.0.2.2').allowed).toBe(true);
  });

  test('slides the window: old requests expire', () => {
    limiter.checkRateLimit('192.0.2.1');
    clock += 30_000;
    limiter.checkRateLimit('192.0.2.1');
    limiter.checkRateLimit('192.0.2.1');
    const blocked = limiter.checkRateLimit('192.0.2.1');
    expect(blocked.allowed).toBe(false);
    expect(blocked.resetMs).toBe(30_000);
    clock += 30_001;
    expect(limiter.checkRateLimit('192.0.2.1').allowed).toBe(true);
  });

  test('applies the route limit and reports it when it is the most restrictive', () => {
    const route = { windowMs: 10_000, maxRequests: 1 };
    const first = limiter.checkRateLimit('192.0.2.1', '/auth', route);
    expect(first).toMatchObject({ allowed: true, limit: 1, remaining: 0, scope: 'route' });
    const second = limiter.checkRateLimit('192.0.2.1', '/auth', route);
    expect(second).toMatchObject({ allowed: false, scope: 'route', resetMs: 10_000 });
    // other routes still use the global window
    expect(limiter.checkRateLimit('192.0.2.1', '/api')).toMatchObject({ allowed: true, scope: 'global' });
  });

  test('requests rejected by one window do not consume quota in the other', () => {
    const route = { windowMs: 60_000, maxRequests: 10 };
    for (let i = 0; i < 3; i++) limiter.checkRateLimit('192.0.2.1', '/api', route);
    for (let i = 0; i < 5; i++) expect(limiter.checkRateLimit('192.0.2.1', '/api', route).allowed).toBe(false);
    limiter.updateGlobalConfig({ globalWindowMs: 60_000, globalMaxRequests: 100 });
    const res = limiter.checkRateLimit('192.0.2.1', '/api', route);
    expect(res).toMatchObject({ allowed: true, scope: 'route', remaining: 6 });
  });

  test('sweep removes expired records from global and route stores', () => {
    limiter.checkRateLimit('192.0.2.1', '/auth', { windowMs: 1_000, maxRequests: 5 });
    limiter.checkRateLimit('192.0.2.2');
    expect(limiter.trackedKeys()).toBe(3);
    clock += 1_001;
    expect(limiter.sweep()).toBe(1);
    clock += 60_000;
    expect(limiter.sweep()).toBe(2);
    expect(limiter.trackedKeys()).toBe(0);
  });
});
