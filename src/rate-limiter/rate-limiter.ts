import { RateLimiterConfig, RouteRateLimit } from '../config/config.js';

interface WindowRecord {
  timestamps: number[];
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Milliseconds until the oldest counted request leaves the window. */
  resetMs: number;
  scope: 'route' | 'global';
}

interface WindowCheck {
  record: WindowRecord;
  result: RateLimitResult;
}

/**
 * In-memory sliding-window log limiter, keyed by client IP. A request is counted only if it
 * passes both the route limit (when configured) and the global per-IP limit, so rejected
 * requests never consume quota.
 */
export class RateLimiterEngine {
  private globalConfig: RateLimiterConfig;
  private globalStore: Map<string, WindowRecord> = new Map();
  private routeStores: Map<string, Map<string, WindowRecord>> = new Map();
  private readonly now: () => number;
  private cleanupTimer: NodeJS.Timeout;

  constructor(globalConfig: RateLimiterConfig, now: () => number = Date.now) {
    this.globalConfig = globalConfig;
    this.now = now;
    this.cleanupTimer = setInterval(() => this.sweep(), 60000);
    this.cleanupTimer.unref();
  }

  public updateGlobalConfig(globalConfig: RateLimiterConfig): void {
    this.globalConfig = globalConfig;
  }

  public checkRateLimit(clientIp: string, routePrefix?: string, routeLimit?: RouteRateLimit): RateLimitResult {
    const now = this.now();
    const checks: WindowCheck[] = [];

    if (routePrefix !== undefined && routeLimit) {
      let store = this.routeStores.get(routePrefix);
      if (!store) {
        store = new Map();
        this.routeStores.set(routePrefix, store);
      }
      checks.push(this.inspect(store, clientIp, now, routeLimit.windowMs, routeLimit.maxRequests, 'route'));
    }
    checks.push(
      this.inspect(
        this.globalStore,
        clientIp,
        now,
        this.globalConfig.globalWindowMs,
        this.globalConfig.globalMaxRequests,
        'global'
      )
    );

    const blocked = checks.find((c) => !c.result.allowed);
    if (blocked) return blocked.result;

    for (const check of checks) check.record.timestamps.push(now);

    // Report the most restrictive window in the response headers.
    return checks.map((c) => c.result).reduce((a, b) => (b.remaining < a.remaining ? b : a));
  }

  /** Drops records whose newest request has left its window. Returns the number removed. */
  public sweep(): number {
    const now = this.now();
    let removed = 0;
    for (const store of [this.globalStore, ...this.routeStores.values()]) {
      for (const [key, record] of store) {
        const newest = record.timestamps[record.timestamps.length - 1];
        if (newest === undefined || newest <= now - record.windowMs) {
          store.delete(key);
          removed++;
        }
      }
    }
    return removed;
  }

  public trackedKeys(): number {
    let total = this.globalStore.size;
    for (const store of this.routeStores.values()) total += store.size;
    return total;
  }

  public close(): void {
    clearInterval(this.cleanupTimer);
  }

  private inspect(
    store: Map<string, WindowRecord>,
    key: string,
    now: number,
    windowMs: number,
    maxRequests: number,
    scope: RateLimitResult['scope']
  ): WindowCheck {
    let record = store.get(key);
    if (!record) {
      record = { timestamps: [], windowMs };
      store.set(key, record);
    }
    record.windowMs = windowMs;
    const windowStart = now - windowMs;
    record.timestamps = record.timestamps.filter((ts) => ts > windowStart);

    const count = record.timestamps.length;
    const oldest = record.timestamps[0] ?? now;
    const resetMs = Math.max(0, oldest + windowMs - now);
    const allowed = count < maxRequests;

    return {
      record,
      result: {
        allowed,
        limit: maxRequests,
        remaining: allowed ? maxRequests - count - 1 : 0,
        resetMs,
        scope
      }
    };
  }
}
