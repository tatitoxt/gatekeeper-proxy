import { RateLimiterConfig } from '../config/config.js';

interface RequestLog {
  timestamps: number[];
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetMs: number;
}

export class RateLimiterEngine {
  private globalConfig: RateLimiterConfig;
  private ipStore: Map<string, RequestLog> = new Map();
  private routeStores: Map<string, Map<string, RequestLog>> = new Map();

  constructor(globalConfig: RateLimiterConfig) {
    this.globalConfig = globalConfig;
    // Periodic cleanup of stale entries every 60 seconds
    const cleanupTimer = setInterval(() => this.cleanup(), 60000);
    if (cleanupTimer.unref) cleanupTimer.unref();
  }

  public updateGlobalConfig(globalConfig: RateLimiterConfig): void {
    this.globalConfig = globalConfig;
  }

  public checkRateLimit(
    clientIp: string,
    routePrefix?: string,
    routeLimit?: { windowMs: number; maxRequests: number }
  ): RateLimitResult {
    const now = Date.now();

    // 1. Check Route-Specific Rate Limit
    if (routePrefix && routeLimit) {
      if (!this.routeStores.has(routePrefix)) {
        this.routeStores.set(routePrefix, new Map());
      }
      const store = this.routeStores.get(routePrefix)!;
      const res = this.evaluateWindow(store, clientIp, now, routeLimit.windowMs, routeLimit.maxRequests);
      if (!res.allowed) return res;
    }

    // 2. Check Global IP Rate Limit
    return this.evaluateWindow(
      this.ipStore,
      clientIp,
      now,
      this.globalConfig.globalWindowMs,
      this.globalConfig.globalMaxRequests
    );
  }

  private evaluateWindow(
    store: Map<string, RequestLog>,
    key: string,
    now: number,
    windowMs: number,
    maxRequests: number
  ): RateLimitResult {
    let record = store.get(key);
    if (!record) {
      record = { timestamps: [] };
      store.set(key, record);
    }

    const windowStart = now - windowMs;
    // Filter timestamps within current sliding window
    record.timestamps = record.timestamps.filter((ts) => ts > windowStart);

    const count = record.timestamps.length;
    const remaining = Math.max(0, maxRequests - count - 1);
    const oldestTs = record.timestamps[0] || now;
    const resetMs = Math.max(0, oldestTs + windowMs - now);

    if (count >= maxRequests) {
      return {
        allowed: false,
        limit: maxRequests,
        remaining: 0,
        resetMs
      };
    }

    record.timestamps.push(now);

    return {
      allowed: true,
      limit: maxRequests,
      remaining,
      resetMs
    };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, record] of this.ipStore.entries()) {
      if (record.timestamps.length === 0 || record.timestamps[record.timestamps.length - 1] < now - 3600000) {
        this.ipStore.delete(ip);
      }
    }
  }
}
