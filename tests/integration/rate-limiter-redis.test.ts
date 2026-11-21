import { RateLimiterEngine } from '../../src/rate-limiter/rate-limiter.js';
import type { RateLimiterConfig } from '../../src/config/config.js';

const REDIS_URL = process.env.GATEKEEPER_TEST_REDIS_URL;
const describeRedis = REDIS_URL ? describe : describe.skip;

const cfg = (over: Partial<RateLimiterConfig> = {}): RateLimiterConfig => ({
  globalWindowMs: 60_000,
  globalMaxRequests: 3,
  backend: 'redis',
  redisUrl: REDIS_URL,
  // shared per test file: instances must see the same keys, and the random
  // suffix isolates this run from earlier runs against the same Redis
  keyPrefix: `gk:test:${Date.now()}:${Math.random().toString(16).slice(2)}:`,
  ...over
});

const sharedCfg = cfg();

describeRedis('RateLimiterEngine (Redis backend)', () => {
  let limiter: RateLimiterEngine;
  afterEach(() => limiter.close());

  test('enforces the global limit through Redis', async () => {
    limiter = new RateLimiterEngine(cfg());
    const results = await Promise.all([1, 2, 3, 4].map(() => limiter.checkRateLimit('192.0.2.10')));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3]).toMatchObject({ limit: 3, scope: 'global' });
  });

  test('budget is shared across engine instances (multi-node)', async () => {
    const a = new RateLimiterEngine(sharedCfg);
    const b = new RateLimiterEngine(sharedCfg);
    limiter = a;
    try {
      // Two instances see the same IP as one budget: 3 total, not 3 each.
      expect((await a.checkRateLimit('192.0.2.11')).allowed).toBe(true);
      expect((await b.checkRateLimit('192.0.2.11')).allowed).toBe(true);
      expect((await a.checkRateLimit('192.0.2.11')).allowed).toBe(true);
      const blocked = await b.checkRateLimit('192.0.2.11');
      expect(blocked.allowed).toBe(false);
      expect(blocked.scope).toBe('global');
    } finally {
      await b.close();
    }
  });

  test('route window and global window both apply; rejection commits nothing', async () => {
    limiter = new RateLimiterEngine(cfg({ globalMaxRequests: 10 }));
    const route = { windowMs: 60_000, maxRequests: 2 };
    expect((await limiter.checkRateLimit('192.0.2.12', '/auth', route)).allowed).toBe(true);
    expect((await limiter.checkRateLimit('192.0.2.12', '/auth', route)).allowed).toBe(true);
    const blocked = await limiter.checkRateLimit('192.0.2.12', '/auth', route);
    expect(blocked).toMatchObject({ allowed: false, scope: 'route' });
    // global window only counted the 2 allowed hits, not the rejected one
    const global = await limiter.checkRateLimit('192.0.2.12');
    expect(global).toMatchObject({ allowed: true, scope: 'global', remaining: 10 - 3 });
  });

  test('trackedKeys counts stored windows', async () => {
    limiter = new RateLimiterEngine(cfg());
    await limiter.checkRateLimit('192.0.2.13', '/auth', { windowMs: 60_000, maxRequests: 5 });
    await limiter.checkRateLimit('192.0.2.14');
    expect(await limiter.trackedKeys()).toBe(3);
  });
});
