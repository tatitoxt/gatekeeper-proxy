export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Milliseconds until the oldest counted request leaves the window. */
  resetMs: number;
  scope: 'route' | 'global';
}

export interface RateLimitWindow {
  windowMs: number;
  maxRequests: number;
}

/**
 * Storage backend for the sliding-window limiter. `check` must be atomic:
 * it trims expired entries, decides allowance and commits the hit in one step,
 * returning the decision for BOTH the route window (when provided) and the
 * global window — a request only consumes quota when every window allows it.
 */
export interface RateLimitStore {
  check(
    clientIp: string,
    route: (RateLimitWindow & { key: string }) | null,
    global: RateLimitWindow,
    now: number
  ): Promise<RateLimitResult>;
  /** Best-effort cleanup of expired records (Redis stores rely on TTL). */
  sweep(now: number): Promise<number>;
  /** Number of currently tracked client keys, or -1 when not observable. */
  trackedKeys(): Promise<number>;
  close(): Promise<void> | void;
}

interface WindowRecord {
  timestamps: number[];
  windowMs: number;
}

/** In-memory store: per-process, exact sliding-window log keyed by client IP. */
export class InMemoryRateLimitStore implements RateLimitStore {
  private globalStore: Map<string, WindowRecord> = new Map();
  private routeStores: Map<string, Map<string, WindowRecord>> = new Map();

  public check(
    clientIp: string,
    route: (RateLimitWindow & { key: string }) | null,
    global: RateLimitWindow,
    now: number
  ): Promise<RateLimitResult> {
    const checks: { record: WindowRecord; result: RateLimitResult }[] = [];

    if (route) {
      let store = this.routeStores.get(route.key);
      if (!store) {
        store = new Map();
        this.routeStores.set(route.key, store);
      }
      checks.push(this.inspect(store, clientIp, now, route.windowMs, route.maxRequests, 'route'));
    }
    checks.push(this.inspect(this.globalStore, clientIp, now, global.windowMs, global.maxRequests, 'global'));

    const blocked = checks.find((c) => !c.result.allowed);
    if (blocked) return Promise.resolve(blocked.result);

    for (const check of checks) check.record.timestamps.push(now);

    // Report the most restrictive window in the response headers.
    const result = checks
      .map((c) => c.result)
      .reduce((a, b) => (b.remaining < a.remaining ? b : a));
    return Promise.resolve(result);
  }

  public sweep(now: number): Promise<number> {
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
    return Promise.resolve(removed);
  }

  public trackedKeys(): Promise<number> {
    let total = this.globalStore.size;
    for (const store of this.routeStores.values()) total += store.size;
    return Promise.resolve(total);
  }

  public close(): void {
    this.globalStore.clear();
    this.routeStores.clear();
  }

  private inspect(
    store: Map<string, WindowRecord>,
    key: string,
    now: number,
    windowMs: number,
    maxRequests: number,
    scope: RateLimitResult['scope']
  ): { record: WindowRecord; result: RateLimitResult } {
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
