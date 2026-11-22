import http from 'node:http';
import https from 'node:https';
import { CircuitBreakerConfig, HealthCheckConfig, RouteConfig } from '../config/config.js';
import { logger } from '../utils/logger.js';

export interface BackendTargetState {
  url: string;
  isHealthy: boolean;
  activeConnections: number;
  /** Consecutive upstream failures feeding the circuit breaker. */
  consecutiveFailures: number;
  /** Epoch ms until which the breaker keeps this target out; null when closed.
   *  Set to MAX_SAFE_INTEGER while a single half-open trial request is in flight. */
  openUntil: number | null;
  /** True while the post-cooldown trial request is in flight. */
  halfOpen: boolean;
}

interface RouteState {
  route: RouteConfig;
  targets: BackendTargetState[];
  nextIndex: number;
}

/**
 * Chooses a backend per route (round-robin or least-connections). Routes with a
 * `healthCheckPath` are actively probed and also passively marked down on connection
 * errors; routes without one treat every target as always healthy.
 *
 * The circuit breaker is passive and needs no probes: `failureThreshold` consecutive
 * upstream failures (connect errors or 5xx responses) open the breaker and keep the
 * target out for `openMs`, then one half-open trial decides — a success closes it,
 * another failure reopens it for `openMs` again.
 */
export class LoadBalancer {
  private routes: Map<string, RouteState> = new Map();
  private healthConfig: HealthCheckConfig;
  private breakerConfig: CircuitBreakerConfig;
  private timer: NodeJS.Timeout | null = null;

  constructor(
    routes: RouteConfig[],
    healthConfig: HealthCheckConfig = { intervalMs: 10000, timeoutMs: 3000 },
    breakerConfig: CircuitBreakerConfig = { failureThreshold: 5, openMs: 30000 }
  ) {
    this.healthConfig = healthConfig;
    this.breakerConfig = breakerConfig;
    this.updateRoutes(routes);
  }

  public start(): void {
    this.stop();
    void this.runHealthChecks();
    this.timer = setInterval(() => void this.runHealthChecks(), this.healthConfig.intervalMs);
    this.timer.unref();
  }

  public stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  public updateHealthConfig(healthConfig: HealthCheckConfig): void {
    const changed = healthConfig.intervalMs !== this.healthConfig.intervalMs;
    this.healthConfig = healthConfig;
    if (changed && this.timer) this.start();
  }

  public updateCircuitBreakerConfig(breakerConfig: CircuitBreakerConfig): void {
    this.breakerConfig = breakerConfig;
  }

  public updateRoutes(routes: RouteConfig[]): void {
    const next = new Map<string, RouteState>();
    for (const route of routes) {
      const existing = this.routes.get(route.pathPrefix);
      const targets = route.targets.map((url) => {
        const found = existing?.targets.find((t) => t.url === url);
        if (!found) return { url, isHealthy: true, activeConnections: 0, consecutiveFailures: 0, openUntil: null, halfOpen: false };
        // Without health checks nothing would ever mark a target healthy again.
        if (!route.healthCheckPath) found.isHealthy = true;
        return found;
      });
      next.set(route.pathPrefix, { route, targets, nextIndex: existing?.nextIndex ?? 0 });
    }
    this.routes = next;
  }

  /** Returns a healthy target URL, or null when every target of the route is down. */
  public selectTarget(route: RouteConfig): string | null {
    const state = this.routes.get(route.pathPrefix);
    if (!state) return null;
    const now = Date.now();
    for (const t of state.targets) {
      // Breaker cooldown elapsed: the next request becomes the single half-open
      // trial. MAX_SAFE_INTEGER keeps everyone else out until it resolves.
      if (t.openUntil !== null && t.openUntil <= now) {
        t.openUntil = Number.MAX_SAFE_INTEGER;
        t.halfOpen = true;
        if (!t.isHealthy) this.setHealth(route.pathPrefix, t, true);
        return t.url;
      }
    }
    const healthy = state.targets.filter((t) => t.isHealthy && t.openUntil === null);
    if (healthy.length === 0) return null;

    if (route.balanceStrategy === 'least-connections') {
      return healthy.reduce((best, t) => (t.activeConnections < best.activeConnections ? t : best)).url;
    }

    const selected = healthy[state.nextIndex % healthy.length];
    state.nextIndex = (state.nextIndex + 1) % healthy.length;
    return selected.url;
  }

  public getTargetStates(pathPrefix: string): BackendTargetState[] {
    return (this.routes.get(pathPrefix)?.targets ?? []).map((t) => ({ ...t }));
  }

  public incrementConnection(pathPrefix: string, targetUrl: string): void {
    const target = this.find(pathPrefix, targetUrl);
    if (target) target.activeConnections++;
  }

  public decrementConnection(pathPrefix: string, targetUrl: string): void {
    const target = this.find(pathPrefix, targetUrl);
    if (target) target.activeConnections = Math.max(0, target.activeConnections - 1);
  }

  /** Passive health: a connection failure takes the target out until the next successful
   *  probe; consecutive failures also feed the circuit breaker (works without a
   *  healthCheckPath — recovery is a timed half-open trial instead of a probe). */
  public reportFailure(pathPrefix: string, targetUrl: string): void {
    const state = this.routes.get(pathPrefix);
    if (!state) return;
    const target = state.targets.find((t) => t.url === targetUrl);
    if (!target) return;
    target.consecutiveFailures++;
    if (state.route.healthCheckPath) this.setHealth(pathPrefix, target, false);
    this.feedBreaker(pathPrefix, target);
  }

  /** A 5xx upstream response feeds the circuit breaker without marking the target
   *  unhealthy for the probe loop — one bad response is not a connectivity failure. */
  public reportServerError(pathPrefix: string, targetUrl: string): void {
    const target = this.find(pathPrefix, targetUrl);
    if (!target) return;
    target.consecutiveFailures++;
    this.feedBreaker(pathPrefix, target);
  }

  private feedBreaker(pathPrefix: string, target: BackendTargetState): void {
    if (target.consecutiveFailures < this.breakerConfig.failureThreshold) return;
    const opened = target.openUntil === null || target.halfOpen;
    target.halfOpen = false;
    target.openUntil = Date.now() + this.breakerConfig.openMs;
    this.setHealth(pathPrefix, target, false);
    if (opened) {
      logger.warn(
        { route: pathPrefix, target: target.url, failures: target.consecutiveFailures },
        'Circuit breaker opened'
      );
    }
  }

  /** A healthy upstream response closes the breaker and clears the failure streak. */
  public reportSuccess(pathPrefix: string, targetUrl: string): void {
    const target = this.find(pathPrefix, targetUrl);
    if (!target) return;
    target.consecutiveFailures = 0;
    target.openUntil = null;
    target.halfOpen = false;
    if (!target.isHealthy) this.setHealth(pathPrefix, target, true);
  }

  public async runHealthChecks(): Promise<void> {
    const probes: Promise<void>[] = [];
    for (const [prefix, state] of this.routes) {
      const healthPath = state.route.healthCheckPath;
      if (!healthPath) continue;
      for (const target of state.targets) {
        probes.push(this.probe(target.url, healthPath).then((ok) => this.setHealth(prefix, target, ok)));
      }
    }
    await Promise.all(probes);
  }

  private probe(baseUrl: string, healthPath: string): Promise<boolean> {
    return new Promise((resolve) => {
      let settled = false;
      const done = (ok: boolean) => {
        if (!settled) {
          settled = true;
          resolve(ok);
        }
      };
      try {
        const url = new URL(healthPath, baseUrl);
        const transport = url.protocol === 'https:' ? https : http;
        const req = transport.get(url, { timeout: this.healthConfig.timeoutMs }, (res) => {
          res.resume();
          const status = res.statusCode ?? 0;
          done(status >= 200 && status < 400);
        });
        req.on('timeout', () => req.destroy(new Error('health check timeout')));
        req.on('error', () => done(false));
      } catch {
        done(false);
      }
    });
  }

  private setHealth(prefix: string, target: BackendTargetState, healthy: boolean): void {
    if (target.isHealthy !== healthy) {
      logger.warn({ route: prefix, target: target.url, healthy }, 'Backend health changed');
    }
    target.isHealthy = healthy;
  }

  private find(pathPrefix: string, targetUrl: string): BackendTargetState | undefined {
    return this.routes.get(pathPrefix)?.targets.find((t) => t.url === targetUrl);
  }
}
