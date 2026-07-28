import { RateLimiterEngine } from '../src/rate-limiter/rate-limiter.js';

describe('Rate Limiter Engine', () => {
  const globalConfig = {
    globalWindowMs: 60000,
    globalMaxRequests: 3
  };

  const limiter = new RateLimiterEngine(globalConfig);

  test('Allows requests under max limit', () => {
    const r1 = limiter.checkRateLimit('1.2.3.4');
    const r2 = limiter.checkRateLimit('1.2.3.4');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);
  });

  test('Blocks request exceeding max limit', () => {
    limiter.checkRateLimit('1.2.3.4'); // 3rd
    const r4 = limiter.checkRateLimit('1.2.3.4'); // 4th -> blocked
    expect(r4.allowed).toBe(false);
    expect(r4.remaining).toBe(0);
  });

  test('Treats different IPs independently', () => {
    const resOther = limiter.checkRateLimit('5.6.7.8');
    expect(resOther.allowed).toBe(true);
  });
});
