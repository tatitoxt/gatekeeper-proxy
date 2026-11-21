import { RateLimiterConfig } from '../config/config.js';
import { InMemoryRateLimitStore, type RateLimitStore } from './store.js';

export type { RateLimitStore } from './store.js';
import { RedisRateLimitStore } from './redis-store.js';

/** Pick the rate-limit backend from config (default: in-process memory). */
export function createRateLimitStore(config: RateLimiterConfig): RateLimitStore {
  if (config.backend === 'redis') {
    if (!config.redisUrl) {
      throw new Error('rateLimiter.redisUrl is required when rateLimiter.backend is "redis"');
    }
    return new RedisRateLimitStore(config.redisUrl, config.keyPrefix);
  }
  return new InMemoryRateLimitStore();
}
