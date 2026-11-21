import http, { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { GatekeeperConfig, defaultConfig } from '../src/config/config.js';

export interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

export interface Upstream {
  url: string;
  port: number;
  requests: RecordedRequest[];
  close(): Promise<void>;
}

export type UpstreamHandler = (req: IncomingMessage, res: ServerResponse, body: string) => void;

/** Synthetic backend that records every request and echoes it back as JSON by default. */
export function startUpstream(name: string, handler?: UpstreamHandler): Promise<Upstream> {
  const requests: RecordedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf-8');
      requests.push({ method: req.method || '', url: req.url || '', headers: req.headers, body });
      if (handler) return handler(req, res, body);
      res.writeHead(200, { 'Content-Type': 'application/json', 'X-Upstream': name });
      res.end(JSON.stringify({ upstream: name, method: req.method, url: req.url, headers: req.headers, body }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        port,
        requests,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections();
            server.close(() => done());
          })
      });
    });
  });
}

export function makeConfig(overrides: Partial<GatekeeperConfig> = {}): GatekeeperConfig {
  const base = defaultConfig();
  return {
    ...base,
    ...overrides,
    server: { ...base.server, port: 0, adminPort: 0, host: '127.0.0.1', ...(overrides.server ?? {}) },
    firewall: { ...base.firewall, ...(overrides.firewall ?? {}) },
    rateLimiter: { ...base.rateLimiter, ...(overrides.rateLimiter ?? {}) },
    healthCheck: { ...base.healthCheck, ...(overrides.healthCheck ?? {}) },
    upstream: { ...base.upstream, ...(overrides.upstream ?? {}) }
  };
}

/** Node does not chunk DELETE/GET bodies by default, so always send Content-Length. */
function withLength(options: { headers?: Record<string, string>; body?: string }): Record<string, string> {
  const headers = { ...(options.headers ?? {}) };
  if (options.body !== undefined) headers['content-length'] = String(Buffer.byteLength(options.body));
  return headers;
}

export interface HttpResult {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  json<T = Record<string, unknown>>(): T;
}

export function request(
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {}
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: options.method || 'GET', headers: withLength(options), agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        resolve({ status: res.statusCode || 0, headers: res.headers, body, json: () => JSON.parse(body) });
      });
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

/** Sends the path verbatim (a URL string would be normalised, e.g. "/a/../b" -> "/b"). */
export function rawRequest(
  port: number,
  path: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {}
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: options.method || 'GET', headers: withLength(options), agent: false },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          resolve({ status: res.statusCode || 0, headers: res.headers, body, json: () => JSON.parse(body) });
        });
      }
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}
