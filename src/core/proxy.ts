import http, { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import fs from 'node:fs';
import { AddressInfo, Socket } from 'node:net';
import { Duplex } from 'node:stream';
import { GatekeeperConfig, RouteConfig } from '../config/config.js';
import { FirewallEngine } from '../firewall/firewall.js';
import { RateLimiterEngine } from '../rate-limiter/rate-limiter.js';
import { LoadBalancer } from './load-balancer.js';
import { getClientIp, normalizeIp } from '../utils/ip-utils.js';
import { MetricsCollector } from '../metrics/metrics.js';
import { logger } from '../utils/logger.js';

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

const STATUS_LABELS: Record<number, string> = {
  400: 'Bad Request',
  403: 'Forbidden',
  404: 'Not Found',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout'
};

/** Removes hop-by-hop headers, including any listed in the Connection header (RFC 9110 §7.6.1). */
export function stripHopByHop(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const listed = String(headers.connection || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  const out: IncomingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    // HTTP/2 pseudo-headers (':authority' etc.) must never reach an HTTP/1.1 upstream.
    if (lower.startsWith(':')) continue;
    if (!HOP_BY_HOP_HEADERS.has(lower) && !listed.includes(lower) && value !== undefined) out[lower] = value;
  }
  return out;
}

/**
 * Buffers a request body up to `cap` bytes. `truncated` is true when the body
 * exceeds the cap — every byte read is still kept in `chunks` so the caller
 * can replay the stream faithfully before piping the remainder.
 */
export function readBodyPrefix(req: IncomingMessage, cap: number): Promise<{ chunks: Buffer[]; truncated: boolean }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let truncated = false;
    const finish = () => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      resolve({ chunks, truncated });
    };
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size > cap) {
        truncated = true;
        req.pause();
        finish();
      }
    };
    const onEnd = () => finish();
    const onError = () => {
      truncated = true;
      finish();
    };
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
  });
}

/**
 * Reduces a request target to a normalized path+query against a placeholder origin:
 * resolves dot segments and discards absolute or scheme-relative authorities, so
 * route matching and upstream forwarding both see the canonical client path.
 * Falls back to the raw value when it cannot be parsed.
 */
export function normalizedRequestPath(rawUrl: string): string {
  try {
    const u = new URL(rawUrl, 'http://internal.invalid');
    return u.pathname + u.search;
  } catch {
    return rawUrl;
  }
}

/** Longest-prefix match on whole path segments: "/api" matches "/api" and "/api/x" but not "/apiary". */
export function matchRoute(routes: RouteConfig[], url: string): RouteConfig | null {
  const pathname = url.split('?')[0].split('#')[0] || '/';
  let best: RouteConfig | null = null;
  for (const route of routes) {
    const prefix = route.pathPrefix;
    const matches =
      prefix === '/' ||
      pathname === prefix ||
      pathname.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
    if (matches && (!best || prefix.length > best.pathPrefix.length)) best = route;
  }
  return best;
}

export class ProxyServer {
  private config: GatekeeperConfig;
  private firewall: FirewallEngine;
  private rateLimiter: RateLimiterEngine;
  private loadBalancer: LoadBalancer;
  private readonly metrics: MetricsCollector;
  private server: http.Server | http2.Http2Server | http2.Http2SecureServer | null = null;
  // Tracked so stop() can end long-lived HTTP/2 sessions after the grace period.
  private readonly h2Sessions = new Set<http2.ServerHttp2Session>();
  // Every accepted socket (h1 keep-alive, WS/upgrade tunnels, h2 transports):
  // server.close* helpers cannot see upgraded sockets, so stop() drains these.
  private readonly connections = new Set<Socket>();
  private upstreamAgent: http.Agent;
  private upstreamTlsAgent: http.Agent;
  // One multiplexed client session per origin for routes with upstreamHttp2.
  private readonly h2UpstreamSessions = new Map<string, http2.ClientHttp2Session>();

  constructor(config: GatekeeperConfig, metrics: MetricsCollector = new MetricsCollector()) {
    this.config = config;
    this.metrics = metrics;
    this.firewall = new FirewallEngine(config.firewall);
    this.rateLimiter = new RateLimiterEngine(config.rateLimiter);
    this.loadBalancer = new LoadBalancer(config.routes, config.healthCheck, config.circuitBreaker);
    this.upstreamAgent = ProxyServer.buildAgent(config, false);
    this.upstreamTlsAgent = ProxyServer.buildAgent(config, true);
  }

  private static buildAgent(config: GatekeeperConfig, tls: boolean): http.Agent {
    const u = config.upstream;
    const AgentClass = tls ? https.Agent : http.Agent;
    // maxFreeSockets 0 means "pool nothing": Node would read 0 as falsy and use
    // its default, so disabling keepAlive is the honest way to express it.
    return new AgentClass({
      keepAlive: u.keepAlive && u.maxFreeSockets !== 0,
      maxSockets: u.maxSockets,
      maxFreeSockets: u.maxFreeSockets
    });
  }

  public getMetrics(): MetricsCollector {
    return this.metrics;
  }

  public getLoadBalancer(): LoadBalancer {
    return this.loadBalancer;
  }

  public updateConfig(config: GatekeeperConfig): void {
    if (config.server.port !== this.config.server.port || config.server.host !== this.config.server.host) {
      logger.warn('server.port/server.host changes require a restart; keeping the current listener');
    }
    // Compare before assigning: upstream pool changes need a fresh agent.
    const upstreamChanged = JSON.stringify(config.upstream) !== JSON.stringify(this.config.upstream);
    this.config = config;
    this.firewall.updateConfig(config.firewall);
    this.rateLimiter.updateGlobalConfig(config.rateLimiter);
    this.loadBalancer.updateRoutes(config.routes);
    this.loadBalancer.updateHealthConfig(config.healthCheck);
    this.loadBalancer.updateCircuitBreakerConfig(config.circuitBreaker);
    if (upstreamChanged) {
      const old = this.upstreamAgent;
      const oldTls = this.upstreamTlsAgent;
      this.upstreamAgent = ProxyServer.buildAgent(config, false);
      this.upstreamTlsAgent = ProxyServer.buildAgent(config, true);
      old.destroy();
      oldTls.destroy();
    }
    // Only drop h2 sessions for origins no route uses anymore; surviving
    // sessions keep multiplexing so a reload does not abort in-flight streams.
    const wantedOrigins = new Set(
      config.routes
        .filter((r) => r.upstreamHttp2)
        .flatMap((r) => r.targets.map((t) => new URL(t).origin))
    );
    for (const [origin, session] of this.h2UpstreamSessions) {
      if (!wantedOrigins.has(origin)) {
        session.destroy();
        this.h2UpstreamSessions.delete(origin);
      }
    }
  }

  /** TCP upgrade entry point (WebSocket, CONNECT-style upgrades). Runs the same
   * firewall/rate-limit/route pipeline as HTTP, then tunnels bytes both ways. */
  public handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    this.routeUpgrade(req, socket, head).catch((err) => {
      logger.error({ err, url: req.url }, 'Unhandled error while processing upgrade');
      socket.destroy();
    });
  }

  public handleRequest(req: IncomingMessage, res: ServerResponse): void {
    this.route(req, res).catch((err) => {
      logger.error({ err, url: req.url }, 'Unhandled error while processing request');
      this.sendError(res, 500, 'Unexpected proxy error');
    });
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const clientIp = getClientIp(req, this.config.server.trustProxy);
    const url = req.url || '/';
    const method = req.method || 'GET';

    // 1. Firewall: IP lists, user agents, blocked paths, signature rules
    //    (the route match runs first so per-route WAF overrides apply). Matching
    //    uses the normalized path so dot segments cannot smuggle a request into a
    //    route with weaker WAF rules than the one its final path belongs to.
    const route = matchRoute(this.config.routes, normalizedRequestPath(url));
    const verdict = this.firewall.checkRequest(req, clientIp, route?.waf);
    if (!verdict.allowed) {
      const status = verdict.statusCode || 403;
      const reason = verdict.reason || 'Blocked by firewall';
      this.metrics.recordWafBlock(clientIp, url, method, reason);
      logger.warn({ clientIp, method, url, reason }, 'Request blocked by firewall');
      this.sendError(res, status, reason);
      return;
    }

    // 2. Rate limit (route window and global per-IP window)
    const limit = await this.rateLimiter.checkRateLimit(clientIp, route?.pathPrefix, route?.rateLimit);
    const resetSeconds = Math.ceil(limit.resetMs / 1000);
    res.setHeader('X-RateLimit-Limit', limit.limit);
    res.setHeader('X-RateLimit-Remaining', limit.remaining);
    res.setHeader('X-RateLimit-Reset', resetSeconds);

    if (!limit.allowed) {
      this.metrics.recordRateLimitHit(clientIp, url, method);
      res.setHeader('Retry-After', resetSeconds);
      this.sendError(res, 429, 'Rate limit exceeded. Please try again later.', {
        retryAfterSeconds: resetSeconds,
        scope: limit.scope
      });
      return;
    }

    if (!route) {
      this.sendError(res, 404, 'No matching proxy route found');
      return;
    }

    // 3. Optional WAF body inspection: buffer up to inspectBody.maxBytes,
    //    scan it, then replay the bytes upstream. Oversized or non-matching
    //    bodies stream through uninspected.
    let buffered: Buffer[] | undefined;
    if (this.shouldInspectBody(req)) {
      const { chunks, truncated } = await readBodyPrefix(req, this.config.firewall.inspectBody.maxBytes);
      buffered = chunks;
      if (!truncated) {
        const bodyVerdict = this.firewall.checkBody(Buffer.concat(chunks).toString('utf8'), route.waf);
        if (!bodyVerdict.allowed) {
          const reason = bodyVerdict.reason || 'Blocked by firewall';
          this.metrics.recordWafBlock(clientIp, url, method, reason);
          logger.warn({ clientIp, method, url, reason }, 'Request blocked by firewall (body)');
          this.sendError(res, bodyVerdict.statusCode || 403, reason);
          return;
        }
      }
    }

    // 4. Pick a healthy backend
    const target = this.loadBalancer.selectTarget(route);
    if (!target) {
      this.sendError(res, 503, 'All backend targets for this route are unavailable');
      return;
    }

    this.forward(req, res, target, route, clientIp, buffered);
  }

  /** Returns (and caches) a client session for an h2 upstream origin. Dead
   *  sessions are evicted on 'goaway', 'close' and 'error' so the next
   *  request dials a fresh one. */
  private upstreamH2Session(origin: string): http2.ClientHttp2Session {
    const pooled = this.h2UpstreamSessions.get(origin);
    if (pooled && !pooled.destroyed && !pooled.closed) return pooled;
    const session = http2.connect(origin);
    const evict = () => {
      if (this.h2UpstreamSessions.get(origin) === session) this.h2UpstreamSessions.delete(origin);
    };
    session.once('close', evict);
    session.once('goaway', evict);
    session.once('error', evict);
    this.h2UpstreamSessions.set(origin, session);
    return session;
  }

  private closeUpstreamH2Sessions(): void {
    for (const session of this.h2UpstreamSessions.values()) session.destroy();
    this.h2UpstreamSessions.clear();
  }

  /** True when body inspection applies: enabled, a method that can carry a
   *  body, a matching content type and a declared non-empty body. */
  private shouldInspectBody(req: IncomingMessage): boolean {
    const cfg = this.config.firewall.inspectBody;
    if (!cfg.enabled) return false;
    const method = req.method || 'GET';
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return false;
    if (req.headers['content-length'] === '0') return false;
    // HTTP/2 requests carry bodies in DATA frames without Content-Length and
    // never use Transfer-Encoding: inspect them even with no declared body.
    if (req.headers['content-length'] === undefined && req.headers['transfer-encoding'] === undefined && req.httpVersionMajor < 2) return false;
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    return cfg.contentTypes.some((prefix) => contentType.startsWith(prefix.toLowerCase()));
  }

  private forward(req: IncomingMessage, res: ServerResponse, target: string, route: RouteConfig, clientIp: string, buffered?: Buffer[]): void {
    const targetUrl = new URL(normalizedRequestPath(req.url || '/'), target);
    const peerIp = normalizeIp(req.socket.remoteAddress || '');
    const incoming = stripHopByHop(req.headers);
    const priorForwardedFor = this.config.server.trustProxy ? incoming['x-forwarded-for'] : undefined;

    const headers: IncomingHttpHeaders = {
      ...incoming,
      host: targetUrl.host,
      'x-forwarded-for': priorForwardedFor ? `${priorForwardedFor}, ${peerIp}` : peerIp,
      // HTTP/2 clients send ':authority' instead of 'host'.
      'x-forwarded-host': req.headers.host || req.headers[':authority'],
      'x-forwarded-proto': this.config.server.tls ? 'https' : 'http',
      'x-real-ip': clientIp,
      'x-gatekeeper-proxy': '1.0'
    };
    // Transfer-Encoding is hop-by-hop and stripped above; re-frame chunked bodies so Node does not
    // write them raw (unframed) for methods like GET/DELETE, which would allow request smuggling.
    // HTTP/2 forbids Transfer-Encoding yet bodies may arrive without Content-Length;
    // re-chunk those too so they are never written unframed to an HTTP/1.1 upstream.
    if (headers['content-length'] === undefined && (req.headers['transfer-encoding'] || req.httpVersionMajor >= 2)) {
      headers['transfer-encoding'] = 'chunked';
    }

    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        this.loadBalancer.decrementConnection(route.pathPrefix, target);
      }
    };
    this.loadBalancer.incrementConnection(route.pathPrefix, target);

    if (route.upstreamHttp2) {
      this.forwardH2(req, res, targetUrl, target, route, headers, buffered, release);
      return;
    }

    let timedOut = false;
    const isTlsTarget = targetUrl.protocol === 'https:';
    const proxyReq = (isTlsTarget ? https.request : http.request)({
      agent: isTlsTarget ? this.upstreamTlsAgent : this.upstreamAgent,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isTlsTarget ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers
    });

    proxyReq.setTimeout(this.config.server.timeoutMs, () => {
      timedOut = true;
      proxyReq.destroy(new Error(`Upstream did not respond within ${this.config.server.timeoutMs}ms`));
    });

    proxyReq.on('response', (proxyRes) => {
      const status = proxyRes.statusCode || 502;
      this.metrics.recordRequest(status);
      if (status >= 500) {
        this.loadBalancer.reportServerError(route.pathPrefix, target);
      } else {
        this.loadBalancer.reportSuccess(route.pathPrefix, target);
      }
      res.writeHead(status, stripHopByHop(proxyRes.headers));
      proxyRes.pipe(res);
      proxyRes.on('end', release);
      proxyRes.on('error', () => {
        release();
        res.destroy();
      });
    });

    proxyReq.on('error', (err) => {
      release();
      if (timedOut) {
        logger.error({ target, url: req.url }, 'Upstream request timed out');
      } else {
        logger.error({ err: err.message, target, url: req.url }, 'Upstream request failed');
        this.loadBalancer.reportFailure(route.pathPrefix, target);
      }
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (timedOut) this.sendError(res, 504, 'Upstream server timed out');
      else this.sendError(res, 502, 'Failed to connect to backend server');
    });

    // Client went away before the response finished: stop the upstream request too.
    res.on('close', () => {
      if (!res.writableFinished) proxyReq.destroy();
      release();
    });

    if (buffered) {
      // Body (or its inspected prefix) was already consumed: replay the
      // captured bytes, then either finish or resume the live stream.
      for (const chunk of buffered) proxyReq.write(chunk);
      if (req.readableEnded) {
        proxyReq.end();
      } else {
        req.pipe(proxyReq);
      }
    } else {
      req.pipe(proxyReq);
    }
  }

  /** HTTP/2 upstream path: one pooled client session per origin, the request
   *  becomes a stream on it. Mirrors `forward`'s metrics/health/error flow. */
  private forwardH2(
    req: IncomingMessage,
    res: ServerResponse,
    targetUrl: URL,
    target: string,
    route: RouteConfig,
    headers: IncomingHttpHeaders,
    buffered: Buffer[] | undefined,
    release: () => void
  ): void {
    // `target` is the configured URL string: load-balancer bookkeeping must use
    // the same key `forward` incremented, not the normalized origin.

    const rest = { ...headers };
    delete rest.host; // carried by :authority instead
    const streamHeaders: http2.OutgoingHttpHeaders = {
      ...rest,
      ':method': req.method || 'GET',
      ':path': targetUrl.pathname + targetUrl.search,
      ':scheme': targetUrl.protocol === 'https:' ? 'https' : 'http',
      ':authority': targetUrl.host
    };
    // HTTP/2 forbids connection-scoped headers; a h1 client's 'connection'
    // header makes the upstream answer 400.
    delete streamHeaders['transfer-encoding'];
    delete streamHeaders['connection'];
    delete streamHeaders['keep-alive'];
    delete streamHeaders['proxy-connection'];
    delete streamHeaders['upgrade'];
    if (streamHeaders['te'] !== 'trailers') delete streamHeaders['te'];

    let timedOut = false;
    let stream: http2.ClientHttp2Stream;
    try {
      // endStream:false — Node auto-ends GET/HEAD/DELETE streams, which would make
      // piping a body fail with ERR_STREAM_WRITE_AFTER_END.
      stream = this.upstreamH2Session(targetUrl.origin).request(streamHeaders, { endStream: false });
    } catch (err) {
      release();
      this.loadBalancer.reportFailure(route.pathPrefix, target);
      logger.error({ err, target, url: req.url }, 'HTTP/2 upstream request failed');
      this.sendError(res, 502, 'Failed to connect to backend server');
      return;
    }

    stream.setTimeout(this.config.server.timeoutMs, () => {
      timedOut = true;
      // CANCEL produces 'close', not 'error': answer the client here so it is
      // never left hanging on an upstream that never sent headers.
      if (!res.headersSent) this.sendError(res, 504, 'Upstream server timed out');
      stream.close(http2.constants.NGHTTP2_CANCEL);
    });
    stream.on('close', release);

    stream.on('response', (upstreamHeaders) => {
      const status = Number(upstreamHeaders[':status']) || 502;
      this.metrics.recordRequest(status);
      if (status >= 500) {
        this.loadBalancer.reportServerError(route.pathPrefix, target);
      } else {
        this.loadBalancer.reportSuccess(route.pathPrefix, target);
      }
      const responseHeaders = stripHopByHop(upstreamHeaders as IncomingHttpHeaders);
      res.writeHead(status, responseHeaders);
      stream.pipe(res);
      stream.on('end', release);
    });

    stream.on('error', (err) => {
      release();
      if (timedOut) {
        logger.error({ target, url: req.url }, 'Upstream request timed out');
      } else {
        logger.error({ err: err.message, target, url: req.url }, 'HTTP/2 upstream request failed');
        this.loadBalancer.reportFailure(route.pathPrefix, target);
      }
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (timedOut) this.sendError(res, 504, 'Upstream server timed out');
      else this.sendError(res, 502, 'Failed to connect to backend server');
    });

    res.on('close', () => {
      if (!res.writableFinished) stream.close(http2.constants.NGHTTP2_CANCEL);
      release();
    });

    if (buffered) {
      for (const chunk of buffered) stream.write(chunk);
      if (req.readableEnded) {
        stream.end();
      } else {
        req.pipe(stream);
      }
    } else {
      req.pipe(stream);
    }
  }

  private async routeUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    const clientIp = getClientIp(req, this.config.server.trustProxy);
    const url = req.url || '/';
    const method = req.method || 'GET';

    const route = matchRoute(this.config.routes, normalizedRequestPath(url));
    const verdict = this.firewall.checkRequest(req, clientIp, route?.waf);
    if (!verdict.allowed) {
      const status = verdict.statusCode || 403;
      this.metrics.recordWafBlock(clientIp, url, method, verdict.reason || 'Blocked by firewall');
      logger.warn({ clientIp, url, reason: verdict.reason }, 'Upgrade blocked by firewall');
      this.rejectUpgrade(socket, status);
      return;
    }

    const limit = await this.rateLimiter.checkRateLimit(clientIp, route?.pathPrefix, route?.rateLimit);
    if (!limit.allowed) {
      this.metrics.recordRateLimitHit(clientIp, url, method);
      this.rejectUpgrade(socket, 429);
      return;
    }

    if (!route) {
      this.rejectUpgrade(socket, 404);
      return;
    }
    const target = this.loadBalancer.selectTarget(route);
    if (!target) {
      this.rejectUpgrade(socket, 503);
      return;
    }
    this.forwardUpgrade(req, socket, head, target, route, clientIp);
  }

  /** Writes a bare HTTP error on a raw socket, used before any 101 is sent. */
  private rejectUpgrade(socket: Duplex, status: number): void {
    this.metrics.recordRequest(status);
    const label = STATUS_LABELS[status] || 'Error';
    socket.end(`HTTP/1.1 ${status} ${label}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  }

  private forwardUpgrade(
    req: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    target: string,
    route: RouteConfig,
    clientIp: string
  ): void {
    const targetUrl = new URL(normalizedRequestPath(req.url || '/'), target);
    const peerIp = normalizeIp(req.socket.remoteAddress || '');
    const incoming = stripHopByHop(req.headers);
    const priorForwardedFor = this.config.server.trustProxy ? incoming['x-forwarded-for'] : undefined;
    const headers: IncomingHttpHeaders = {
      ...incoming,
      // upgrade/connection were stripped above; the upstream needs them.
      connection: 'Upgrade',
      upgrade: req.headers.upgrade || 'websocket',
      host: targetUrl.host,
      'x-forwarded-for': priorForwardedFor ? `${priorForwardedFor}, ${peerIp}` : peerIp,
      'x-forwarded-host': req.headers.host,
      'x-forwarded-proto': this.config.server.tls ? 'https' : 'http',
      'x-real-ip': clientIp,
      'x-gatekeeper-proxy': '1.0'
    };

    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        this.loadBalancer.decrementConnection(route.pathPrefix, target);
      }
    };
    this.loadBalancer.incrementConnection(route.pathPrefix, target);

    const isTlsUpgrade = targetUrl.protocol === 'https:';
    const proxyReq = (isTlsUpgrade ? https.request : http.request)({
      agent: isTlsUpgrade ? this.upstreamTlsAgent : this.upstreamAgent,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isTlsUpgrade ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers
    });

    proxyReq.on('upgrade', (proxyRes, proxySocket, upstreamHead) => {
      // Relay the upstream 101 verbatim, then tunnel bytes both directions.
      this.metrics.recordRequest(proxyRes.statusCode || 101);
      this.loadBalancer.reportSuccess(route.pathPrefix, target);
      const lines = [`HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}`];
      for (let i = 0; i < proxyRes.rawHeaders.length; i += 2) {
        lines.push(`${proxyRes.rawHeaders[i]}: ${proxyRes.rawHeaders[i + 1]}`);
      }
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
      // Bytes the upstream parser already consumed past its 101 headers must be
      // replayed too, or the client loses the first frames.
      if (upstreamHead && upstreamHead.length > 0) socket.write(upstreamHead);
      if (head.length > 0) proxySocket.write(head);
      proxySocket.pipe(socket);
      socket.pipe(proxySocket);
      proxySocket.on('close', () => { release(); socket.destroy(); });
      proxySocket.on('error', () => { release(); socket.destroy(); });
      socket.on('close', release);
      socket.on('error', () => { release(); proxySocket.destroy(); });
    });

    proxyReq.on('response', (proxyRes) => {
      // Upstream refused the upgrade with a plain HTTP response: forward it.
      const status = proxyRes.statusCode || 502;
      this.metrics.recordRequest(status);
      if (status >= 500) {
        this.loadBalancer.reportServerError(route.pathPrefix, target);
      } else {
        this.loadBalancer.reportSuccess(route.pathPrefix, target);
      }
      // proxyRes already decoded framing (e.g. chunked): forwarding its raw
      // headers verbatim would describe bytes we never send. Drop transfer
      // framing and end the tunnel when the response ends.
      const filtered = proxyRes.rawHeaders.filter(
        (v, i) => i % 2 === 0 && !['transfer-encoding', 'connection', 'keep-alive'].includes(v.toLowerCase())
      );
      const lines = [`HTTP/1.1 ${proxyRes.statusCode} ${proxyRes.statusMessage}`];
      for (let i = 0; i < filtered.length; i += 2) {
        lines.push(`${filtered[i]}: ${filtered[i + 1]}`);
      }
      lines.push('Connection: close');
      socket.write(`${lines.join('\r\n')}\r\n\r\n`);
      proxyRes.pipe(socket, { end: true });
      proxyRes.on('end', release);
    });

    proxyReq.setTimeout(this.config.server.timeoutMs, () => {
      proxyReq.destroy(new Error(`Upstream did not answer the upgrade within ${this.config.server.timeoutMs}ms`));
    });

    proxyReq.on('error', () => {
      release();
      this.metrics.recordRequest(502);
      this.loadBalancer.reportFailure(route.pathPrefix, target);
      socket.destroy();
    });
    socket.on('close', () => { proxyReq.destroy(); release(); });
    proxyReq.end();
  }

  private sendError(res: ServerResponse, status: number, message: string, extra: Record<string, unknown> = {}): void {
    this.metrics.recordRequest(status);
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: STATUS_LABELS[status] || 'Error', message, status, ...extra }));
  }

  public start(): Promise<AddressInfo> {
    return new Promise((resolve, reject) => {
      const tls = this.config.server.tls;
      const tlsOpts = tls
        ? {
            cert: fs.readFileSync(tls.certFile),
            key: fs.readFileSync(tls.keyFile),
            ca: tls.caFile ? fs.readFileSync(tls.caFile) : undefined,
            requestCert: tls.requestCert,
            rejectUnauthorized: Boolean(tls.caFile && tls.requestCert)
          }
        : undefined;
      // Node's HTTP/2 compat API exposes the same headers/method/url/socket and
      // writeHead/end surface the pipeline uses, so the casts are sound.
      const handler = (
        req: IncomingMessage | http2.Http2ServerRequest,
        res: ServerResponse | http2.Http2ServerResponse
      ) => this.handleRequest(req as IncomingMessage, res as ServerResponse);
      if (this.config.server.http2 && !tlsOpts) {
        // Node only honors allowHTTP1 on the secure server: a cleartext h2c
        // listener speaks prior-knowledge HTTP/2 only.
        logger.warn('server.http2 without server.tls is h2c prior-knowledge only: HTTP/1.1 requests will fail');
      }
      const server = this.config.server.http2
        ? tlsOpts
          ? http2.createSecureServer({ ...tlsOpts, allowHTTP1: true }, handler) // ALPN: h2 or http/1.1
          : http2.createServer(handler) // h2c prior-knowledge
        : tlsOpts
          ? https.createServer(tlsOpts, handler)
          : http.createServer(handler);
      if (this.config.server.http2) {
        (server as http2.Http2Server).on('session', (session) => {
          this.h2Sessions.add(session);
          session.on('close', () => this.h2Sessions.delete(session));
        });
      }
      server.on('connection', (socket) => {
        this.connections.add(socket);
        socket.on('close', () => this.connections.delete(socket));
      });
      server.on('secureConnection', (socket) => {
        this.connections.add(socket);
        socket.on('close', () => this.connections.delete(socket));
      });
      server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head));
      server.on('clientError', (_err, socket) => {
        if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      });
      server.once('error', reject);
      const { port, host } = this.config.server;
      server.listen(port, host, () => {
        server.off('error', reject);
        this.server = server;
        this.loadBalancer.start();
        const address = server.address() as AddressInfo;
        logger.info({ host: address.address, port: address.port }, 'Gatekeeper proxy listening');
        resolve(address);
      });
    });
  }

  public async stop(): Promise<void> {
    this.loadBalancer.stop();
    const closeLimiter = this.rateLimiter.close();
    await new Promise<void>((resolve) => {
      const server = this.server;
      if (!server) return resolve();
      this.server = null;
      server.close(() => resolve());
      // closeIdleConnections/closeAllConnections exist on both h1 and h2 servers
      // at runtime but are not declared on the h2 types.
      const closable = server as http.Server;
      // closeIdleConnections/closeAllConnections exist on h1 servers only; h2
      // sessions are tracked in h2Sessions and destroyed after the same grace.
      if (typeof closable.closeIdleConnections === 'function') closable.closeIdleConnections();
      // Give in-flight requests a grace period, then drop remaining keep-alive sockets.
      setTimeout(() => {
        if (typeof closable.closeAllConnections === 'function') closable.closeAllConnections();
        for (const session of this.h2Sessions) session.destroy();
        this.h2Sessions.clear();
        for (const socket of this.connections) socket.destroy();
        this.connections.clear();
      }, 5000).unref();
    });
    await closeLimiter;
    this.upstreamAgent.destroy();
    this.upstreamTlsAgent.destroy();
    this.closeUpstreamH2Sessions();
  }
}
