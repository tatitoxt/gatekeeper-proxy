import http, { IncomingMessage, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { createHash, timingSafeEqual } from 'node:crypto';
import { ConfigManager, ConfigValidationError } from '../config/config.js';
import { MetricsCollector } from '../metrics/metrics.js';
import { DASHBOARD_HTML, DASHBOARD_JS } from './dashboard-ui.js';
import { isValidIpOrCidr } from '../utils/ip-utils.js';
import { logger } from '../utils/logger.js';

const MAX_BODY_BYTES = 4 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

const DASHBOARD_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store'
};

export interface AdminServerOptions {
  /** Bearer token required for /api/* (except /api/health). */
  token?: string;
}

class HttpError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
  }
}

const sha256 = (value: string) => createHash('sha256').update(value).digest();

export class AdminServer {
  private readonly configManager: ConfigManager;
  private readonly metrics: MetricsCollector;
  private readonly tokenDigest: Buffer | null;
  private server: http.Server | null = null;

  constructor(configManager: ConfigManager, metrics: MetricsCollector, options: AdminServerOptions = {}) {
    this.configManager = configManager;
    this.metrics = metrics;
    this.tokenDigest = options.token ? sha256(options.token) : null;
  }

  public start(): Promise<AddressInfo> {
    const { adminPort, adminHost } = this.configManager.getConfig().server;
    if (!this.tokenDigest && !LOOPBACK_HOSTS.has(adminHost)) {
      return Promise.reject(
        new Error(
          `Refusing to expose the admin API on ${adminHost} without GATEKEEPER_ADMIN_TOKEN. ` +
            'Set a token or bind server.adminHost to 127.0.0.1.'
        )
      );
    }
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        this.handleRequest(req, res).catch((err: unknown) => {
          const status = err instanceof HttpError ? err.status : 500;
          if (status === 500) logger.error({ err }, 'Admin request failed');
          this.json(res, status, { error: err instanceof HttpError ? err.message : 'Internal Server Error' });
        });
      });
      server.once('error', reject);
      server.listen(adminPort, adminHost, () => {
        server.off('error', reject);
        this.server = server;
        const address = server.address() as AddressInfo;
        logger.info(
          { host: address.address, port: address.port, auth: this.tokenDigest ? 'bearer-token' : 'none (loopback only)' },
          'Gatekeeper admin API and dashboard listening on /_admin'
        );
        resolve(address);
      });
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      const server = this.server;
      if (!server) return resolve();
      this.server = null;
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const { pathname } = new URL(req.url || '/', 'http://admin.local');
    const method = req.method || 'GET';

    if (method === 'GET' && (pathname === '/_admin' || pathname === '/_admin/')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...DASHBOARD_HEADERS });
      res.end(DASHBOARD_HTML);
      return;
    }
    if (method === 'GET' && pathname === '/_admin/app.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', ...DASHBOARD_HEADERS });
      res.end(DASHBOARD_JS);
      return;
    }
    if (method === 'GET' && pathname === '/api/health') {
      this.json(res, 200, { status: 'ok' });
      return;
    }

    if (!pathname.startsWith('/api/')) throw new HttpError(404, 'Not Found');
    this.authorize(req);

    if (method === 'GET' && pathname === '/api/metrics') {
      this.json(res, 200, this.metrics.getSummary());
      return;
    }
    if (method === 'GET' && pathname === '/api/routes') {
      this.json(res, 200, this.configManager.getConfig().routes);
      return;
    }
    if (pathname === '/api/firewall/blacklist') {
      if (method === 'GET') {
        this.json(res, 200, { ipBlacklist: this.configManager.getConfig().firewall.ipBlacklist });
        return;
      }
      if (method === 'POST' || method === 'DELETE') {
        const ip = await this.readIpPayload(req);
        const firewall = this.configManager.getConfig().firewall;
        const list = new Set(firewall.ipBlacklist);
        const changed = method === 'POST' ? !list.has(ip) && !!list.add(ip) : list.delete(ip);
        if (changed) {
          try {
            this.configManager.updateConfig({ firewall: { ...firewall, ipBlacklist: [...list] } });
          } catch (err) {
            if (err instanceof ConfigValidationError) throw new HttpError(400, err.issues.join('; '));
            throw err;
          }
          logger.warn({ ip, action: method === 'POST' ? 'block' : 'unblock' }, 'Admin API changed IP blacklist');
        }
        this.json(res, 200, { success: true, changed, ipBlacklist: [...list] });
        return;
      }
      throw new HttpError(405, 'Method Not Allowed');
    }

    throw new HttpError(404, 'Not Found');
  }

  private authorize(req: IncomingMessage): void {
    if (!this.tokenDigest) return;
    const header = req.headers.authorization || '';
    const match = /^Bearer\s+(.+)$/i.exec(header);
    if (!match || !timingSafeEqual(sha256(match[1].trim()), this.tokenDigest)) {
      throw new HttpError(401, 'Unauthorized');
    }
  }

  private async readIpPayload(req: IncomingMessage): Promise<string> {
    // Requiring JSON forces a CORS preflight, so a random web page cannot drive this endpoint.
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
      throw new HttpError(415, 'Content-Type must be application/json');
    }
    const body = await this.readBody(req);
    let payload: unknown;
    try {
      payload = JSON.parse(body);
    } catch {
      throw new HttpError(400, 'Body must be valid JSON');
    }
    const ip = typeof payload === 'object' && payload !== null ? (payload as { ip?: unknown }).ip : undefined;
    if (typeof ip !== 'string' || !isValidIpOrCidr(ip.trim())) {
      throw new HttpError(400, 'Body must be {"ip": "<IPv4/IPv6 address or CIDR>"}');
    }
    return ip.trim();
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(new HttpError(413, 'Payload Too Large'));
          req.resume();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });
  }

  private json(res: ServerResponse, status: number, body: unknown): void {
    if (res.headersSent) return;
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  }
}
