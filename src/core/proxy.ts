import http, { IncomingMessage, ServerResponse } from 'node:http';
import { URL } from 'node:url';
import { GatekeeperConfig, RouteConfig } from '../config/config.js';
import { FirewallEngine } from '../firewall/firewall.js';
import { RateLimiterEngine } from '../rate-limiter/rate-limiter.js';
import { LoadBalancer } from './load-balancer.js';
import { getClientIp } from '../utils/ip-utils.js';
import { metrics } from '../metrics/metrics.js';
import { logger } from '../utils/logger.js';

export class ProxyServer {
  private config: GatekeeperConfig;
  private firewall: FirewallEngine;
  private rateLimiter: RateLimiterEngine;
  private loadBalancer: LoadBalancer;
  private server: http.Server | null = null;

  constructor(config: GatekeeperConfig) {
    this.config = config;
    this.firewall = new FirewallEngine(config.firewall);
    this.rateLimiter = new RateLimiterEngine(config.rateLimiter);
    this.loadBalancer = new LoadBalancer(config.routes);
  }

  public updateConfig(config: GatekeeperConfig): void {
    this.config = config;
    this.firewall.updateConfig(config.firewall);
    this.rateLimiter.updateGlobalConfig(config.rateLimiter);
    this.loadBalancer.updateRoutes(config.routes);
  }

  public handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const clientIp = getClientIp(req);
    const url = req.url || '/';
    const method = req.method || 'GET';

    // 1. Check Firewall (WAF Rules, IP Blacklist/Whitelist, Attack Patterns)
    const firewallResult = this.firewall.checkRequest(req, clientIp);
    if (!firewallResult.allowed) {
      metrics.recordWafBlock(clientIp, url, method, firewallResult.reason || 'Blocked by WAF');
      metrics.recordRequest(firewallResult.statusCode || 403);
      logger.warn({ clientIp, url, reason: firewallResult.reason }, 'Request blocked by Firewall');

      res.writeHead(firewallResult.statusCode || 403, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Forbidden',
          message: firewallResult.reason || 'Access denied by Gatekeeper Firewall security rules',
          status: firewallResult.statusCode || 403
        })
      );
      return;
    }

    // 2. Match Route
    const matchedRoute = this.matchRoute(url);
    const routeLimit = matchedRoute?.rateLimit;

    // 3. Check Rate Limiter
    const rateLimitResult = this.rateLimiter.checkRateLimit(clientIp, matchedRoute?.pathPrefix, routeLimit);

    // Set standard Rate Limit Headers
    res.setHeader('X-RateLimit-Limit', rateLimitResult.limit);
    res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimitResult.resetMs / 1000));

    if (!rateLimitResult.allowed) {
      metrics.recordRateLimitHit(clientIp, url, method);
      metrics.recordRequest(429);
      res.setHeader('Retry-After', Math.ceil(rateLimitResult.resetMs / 1000));
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Too Many Requests',
          message: 'Rate limit exceeded. Please try again later.',
          status: 429,
          retryAfterSeconds: Math.ceil(rateLimitResult.resetMs / 1000)
        })
      );
      return;
    }

    if (!matchedRoute) {
      metrics.recordRequest(404);
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found', message: 'No matching proxy route found', status: 404 }));
      return;
    }

    // 4. Select Backend Target
    const targetBaseUrl = this.loadBalancer.selectTarget(matchedRoute);
    if (!targetBaseUrl) {
      metrics.recordRequest(503);
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Service Unavailable',
          message: 'All backend targets for this route are unavailable',
          status: 503
        })
      );
      return;
    }

    // 5. Forward Request to Target
    this.forwardRequest(req, res, targetBaseUrl, matchedRoute, clientIp);
  }

  private forwardRequest(
    req: IncomingMessage,
    res: ServerResponse,
    targetBaseUrl: string,
    route: RouteConfig,
    clientIp: string
  ): void {
    try {
      const targetUrl = new URL(req.url || '/', targetBaseUrl);
      const options: http.RequestOptions = {
        hostname: targetUrl.hostname,
        port: targetUrl.port || 80,
        path: targetUrl.pathname + targetUrl.search,
        method: req.method,
        headers: {
          ...req.headers,
          host: targetUrl.host,
          'x-forwarded-for': clientIp,
          'x-forwarded-proto': 'http',
          'x-real-ip': clientIp,
          'x-gatekeeper-proxy': '1.0'
        },
        timeout: this.config.server.timeoutMs || 30000
      };

      this.loadBalancer.incrementConnection(route.pathPrefix, targetBaseUrl);

      const proxyReq = http.request(options, (proxyRes) => {
        metrics.recordRequest(proxyRes.statusCode || 200);
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res, { end: true });

        proxyRes.on('end', () => {
          this.loadBalancer.decrementConnection(route.pathPrefix, targetBaseUrl);
        });
      });

      proxyReq.on('error', (err) => {
        logger.error({ err, targetBaseUrl, path: req.url }, 'Proxy request to backend target failed');
        this.loadBalancer.decrementConnection(route.pathPrefix, targetBaseUrl);
        metrics.recordRequest(502);

        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Bad Gateway',
              message: 'Failed to connect to backend server',
              status: 502
            })
          );
        }
      });

      req.pipe(proxyReq, { end: true });
    } catch (err) {
      logger.error({ err }, 'Invalid target URL formation');
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Server Error', status: 500 }));
    }
  }

  private matchRoute(url: string): RouteConfig | null {
    for (const route of this.config.routes) {
      if (url.startsWith(route.pathPrefix)) {
        return route;
      }
    }
    return null;
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));
      const { port, host } = this.config.server;
      this.server.listen(port, host, () => {
        logger.info({ port, host }, `🛡️ Gatekeeper Proxy running on http://${host}:${port}`);
        resolve();
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Proxy server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}
