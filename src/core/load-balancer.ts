import http from 'node:http';
import { RouteConfig } from '../config/config.js';
import { logger } from '../utils/logger.js';

interface BackendTargetState {
  url: string;
  isHealthy: boolean;
  activeConnections: number;
}

export class LoadBalancer {
  private targetStates: Map<string, BackendTargetState[]> = new Map();
  private roundRobinIndexes: Map<string, number> = new Map();

  constructor(routes: RouteConfig[]) {
    this.updateRoutes(routes);
    // Periodically run background health checks every 10 seconds
    const healthTimer = setInterval(() => this.runHealthChecks(), 10000);
    if (healthTimer.unref) healthTimer.unref();
  }

  public updateRoutes(routes: RouteConfig[]): void {
    for (const route of routes) {
      const existing = this.targetStates.get(route.pathPrefix) || [];
      const updated: BackendTargetState[] = route.targets.map((url) => {
        const found = existing.find((t) => t.url === url);
        return found ? found : { url, isHealthy: true, activeConnections: 0 };
      });
      this.targetStates.set(route.pathPrefix, updated);
      if (!this.roundRobinIndexes.has(route.pathPrefix)) {
        this.roundRobinIndexes.set(route.pathPrefix, 0);
      }
    }
  }

  public selectTarget(route: RouteConfig): string | null {
    const targets = this.targetStates.get(route.pathPrefix) || [];
    const healthyTargets = targets.filter((t) => t.isHealthy);

    if (healthyTargets.length === 0) {
      // Fallback to all targets if health check hasn't marked any healthy
      if (targets.length > 0) return targets[0].url;
      return null;
    }

    if (route.balanceStrategy === 'least-connections') {
      healthyTargets.sort((a, b) => a.activeConnections - b.activeConnections);
      return healthyTargets[0].url;
    }

    // Default: Round-Robin
    const currentIndex = this.roundRobinIndexes.get(route.pathPrefix) || 0;
    const selected = healthyTargets[currentIndex % healthyTargets.length];
    this.roundRobinIndexes.set(route.pathPrefix, (currentIndex + 1) % healthyTargets.length);
    return selected.url;
  }

  public incrementConnection(pathPrefix: string, targetUrl: string): void {
    const targets = this.targetStates.get(pathPrefix);
    const target = targets?.find((t) => t.url === targetUrl);
    if (target) target.activeConnections++;
  }

  public decrementConnection(pathPrefix: string, targetUrl: string): void {
    const targets = this.targetStates.get(pathPrefix);
    const target = targets?.find((t) => t.url === targetUrl);
    if (target) target.activeConnections = Math.max(0, target.activeConnections - 1);
  }

  private runHealthChecks(): void {
    for (const [prefix, targets] of this.targetStates.entries()) {
      for (const target of targets) {
        try {
          const urlObj = new URL(target.url);
          const req = http.request(
            {
              host: urlObj.hostname,
              port: urlObj.port || 80,
              path: '/health',
              method: 'GET',
              timeout: 3000
            },
            (res) => {
              target.isHealthy = res.statusCode ? res.statusCode < 500 : true;
            }
          );

          req.on('error', () => {
            target.isHealthy = false;
          });

          req.on('timeout', () => {
            req.destroy();
            target.isHealthy = false;
          });

          req.end();
        } catch {
          target.isHealthy = true;
        }
      }
    }
  }
}
