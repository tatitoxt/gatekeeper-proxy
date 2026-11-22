import http from 'node:http';
import http2 from 'node:http2';
import { AddressInfo } from 'node:net';
import { ProxyServer } from '../../src/core/proxy.js';
import { makeConfig } from '../helpers.js';

interface H2Upstream {
  url: string;
  port: number;
  readonly streams: number;
  readonly sessions: number;
  close(): Promise<void>;
}

/** h2c prior-knowledge backend that echoes each request and counts sessions. */
function startH2Upstream(name: string): Promise<H2Upstream> {
  const state = { streams: 0, sessions: 0 };
  const server = http2.createServer();
  server.on('session', () => state.sessions++);
  server.on('stream', (stream, headers) => {
    state.streams++;
    const chunks: Buffer[] = [];
    stream.on('data', (c: Buffer) => chunks.push(c));
    stream.on('end', () => {
      stream.respond({ ':status': 200, 'content-type': 'application/json', 'x-upstream': name });
      stream.end(
        JSON.stringify({
          upstream: name,
          method: headers[':method'],
          url: headers[':path'],
          authority: headers[':authority'],
          forwardedFor: headers['x-forwarded-for'],
          body: Buffer.concat(chunks).toString('utf-8')
        })
      );
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = (server.address() as AddressInfo) || { port: 0 };
      resolve({
        url: `http://127.0.0.1:${port}`,
        port,
        get streams() {
          return state.streams;
        },
        get sessions() {
          return state.sessions;
        },
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          })
      });
    });
  });
}

function h1Request(
  url: string,
  opts: { method?: string; body?: string } = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: opts.method || 'GET' }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

const h2Route = (port: number) =>
  [
    {
      pathPrefix: '/',
      targets: [`http://127.0.0.1:${port}`],
      upstreamHttp2: true,
      waf: {},
      timeoutMs: 5000
    } as never
  ];

describe('HTTP/2 upstreams (route.upstreamHttp2)', () => {
  it('forwards h1 client requests to the upstream over HTTP/2', async () => {
    const upstream = await startH2Upstream('h2-target');
    const proxy = new ProxyServer(makeConfig({ routes: h2Route(upstream.port) }));
    const address = await proxy.start();

    const res = await h1Request(`http://127.0.0.1:${address.port}/hello?x=1`);
    expect(res.status).toBe(200);
    expect(res.headers['x-upstream']).toBe('h2-target');
    const payload = JSON.parse(res.body);
    expect(payload.method).toBe('GET');
    expect(payload.url).toBe('/hello?x=1');
    expect(payload.forwardedFor).toBeTruthy();

    await proxy.stop();
    await upstream.close();
  });

  it('streams the request body to the h2 upstream', async () => {
    const upstream = await startH2Upstream('h2-target');
    const proxy = new ProxyServer(makeConfig({ routes: h2Route(upstream.port) }));
    const address = await proxy.start();

    const res = await h1Request(`http://127.0.0.1:${address.port}/echo`, {
      method: 'POST',
      body: 'payload-body-123'
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).body).toBe('payload-body-123');

    await proxy.stop();
    await upstream.close();
  });

  it('multiplexes requests over one session per origin', async () => {
    const upstream = await startH2Upstream('h2-target');
    const proxy = new ProxyServer(makeConfig({ routes: h2Route(upstream.port) }));
    const address = await proxy.start();

    for (let i = 0; i < 3; i++) {
      const res = await h1Request(`http://127.0.0.1:${address.port}/r${i}`);
      expect(res.status).toBe(200);
    }
    expect(upstream.streams).toBe(3);
    expect(upstream.sessions).toBe(1);

    await proxy.stop();
    await upstream.close();
  });

  it('returns 502 when the h2 upstream is down', async () => {
    const upstream = await startH2Upstream('h2-target');
    const port = upstream.port;
    await upstream.close();
    const proxy = new ProxyServer(makeConfig({ routes: h2Route(port) }));
    const address = await proxy.start();

    const res = await h1Request(`http://127.0.0.1:${address.port}/x`);
    expect(res.status).toBe(502);

    await proxy.stop();
  });
});
