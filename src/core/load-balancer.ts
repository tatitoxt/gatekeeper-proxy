import http from 'node:http';
import { HealthCheckConfig, RouteConfig } from '../config/config.js';
import { logger } from '../utils/logger.js';

export interface BackendTargetState {
  url: string;
  isHealthy: boolean;
  activeConnections: number;
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
 */
export class LoadBalancer {
  private routes: Map<string, RouteState> = new Map();
  private healthConfig: HealthCheckConfig;
  private timer: NodeJS.Timeout | null = null;

  constructor(routes: RouteConfig[], healthConfig: HealthCheckConfig = { intervalMs: 10000, timeoutMs: 3000 }) {
    this.healthConfig = healthConfig;
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

  public updateRoutes(routes: RouteConfig[]): void {
    const next = new Map<string, RouteState>();
    for (const route of routes) {
      const existing = this.routes.get(route.pathPrefix);
      const targets = route.targets.map((url) => {
        const found = existing?.targets.find((t) => t.url === url);
        return found ?? { url, isHealthy: true, activeConnections: 0 };
      });
      next.set(route.pathPrefix, { route, targets, nextIndex: existing?.nextIndex ?? 0 });
    }
    this.routes = next;
  }

  /** Returns a healthy target URL, or null when every target of the route is down. */
  public selectTarget(route: RouteConfig): string | null {
    const state = this.routes.get(route.pathPrefix);
    if (!state) return null;
    const healthy = state.targets.filter((t) => t.isHealthy);
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

  /** Passive health: a connection failure takes the target out until the next successful probe. */
  public reportFailure(pathPrefix: string, targetUrl: string): void {
    const state = this.routes.get(pathPrefix);
    if (!state?.route.healthCheckPath) return;
    const target = state.targets.find((t) => t.url === targetUrl);
    if (target) this.setHealth(pathPrefix, target, false);
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
        const req = http.get(new URL(healthPath, baseUrl), { timeout: this.healthConfig.timeoutMs }, (res) => {
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
