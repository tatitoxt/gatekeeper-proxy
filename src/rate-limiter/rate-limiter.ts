import { RateLimiterConfig, RouteRateLimit } from '../config/config.js';
import { createRateLimitStore, type RateLimitStore } from './store-factory.js';
import type { RateLimitResult } from './store.js';

export type { RateLimitResult } from './store.js';

/**
 * Sliding-window rate limiter, keyed by client IP. A request is counted only if
 * it passes both the route limit (when configured) and the global per-IP limit,
 * so rejected requests never consume quota.
 *
 * The storage backend is pluggable: in-memory (default, per-process) or Redis
 * (`rateLimiter.backend: 'redis'`), which shares the budget across instances.
 */
export class RateLimiterEngine {
  private globalConfig: RateLimiterConfig;
  private readonly store: RateLimitStore;
  private readonly now: () => number;
  private cleanupTimer: NodeJS.Timeout;

  constructor(
    globalConfig: RateLimiterConfig,
    now: () => number = Date.now,
    store: RateLimitStore = createRateLimitStore(globalConfig)
  ) {
    this.globalConfig = globalConfig;
    this.now = now;
    this.store = store;
    this.cleanupTimer = setInterval(() => {
      void this.sweep();
    }, 60000);
    this.cleanupTimer.unref();
  }

  public updateGlobalConfig(globalConfig: RateLimiterConfig): void {
    this.globalConfig = globalConfig;
  }

  public async checkRateLimit(
    clientIp: string,
    routePrefix?: string,
    routeLimit?: RouteRateLimit
  ): Promise<RateLimitResult> {
    const route =
      routePrefix !== undefined && routeLimit
        ? { key: routePrefix, windowMs: routeLimit.windowMs, maxRequests: routeLimit.maxRequests }
        : null;
    return this.store.check(
      clientIp,
      route,
      {
        windowMs: this.globalConfig.globalWindowMs,
        maxRequests: this.globalConfig.globalMaxRequests
      },
      this.now()
    );
  }

  /** Drops records whose newest request has left its window. Returns the number removed. */
  public async sweep(): Promise<number> {
    return this.store.sweep(this.now());
  }

  public async trackedKeys(): Promise<number> {
    return this.store.trackedKeys();
  }

  public async close(): Promise<void> {
    clearInterval(this.cleanupTimer);
    await this.store.close();
  }
}
