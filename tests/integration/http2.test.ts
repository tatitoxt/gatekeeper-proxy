import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import path from 'node:path';
import { ProxyServer } from '../../src/core/proxy.js';
import { makeConfig, startUpstream } from '../helpers.js';

const fixtures = path.resolve(__dirname, '../fixtures');
const cert = path.join(fixtures, 'cert.pem');
const key = path.join(fixtures, 'key.pem');

/** One GET over an http2 session; resolves with the response headers and body. */
function h2Get(authority: string, pathname: string, opts: http2.SecureClientSessionOptions = {}): Promise<{ status: number; headers: http2.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const client = http2.connect(authority, opts);
    client.on('error', reject);
    const req = client.request({ ':path': pathname, ':method': 'GET' });
    let headers: http2.IncomingHttpHeaders = {};
    req.on('response', (h) => (headers = h));
    let body = '';
    req.setEncoding('utf-8');
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      client.close();
      resolve({ status: Number(headers[':status']) || 0, headers, body });
    });
    req.end();
  });
}

function h1Get(url: string, agent?: https.Agent): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    (url.startsWith('https') ? https : http)
      .get(url, { agent }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, body }));
      })
      .on('error', reject);
  });
}

const route = (port: number) =>
  [{ pathPrefix: '/', targets: [`http://127.0.0.1:${port}`], stripPrefix: false, strategy: 'round-robin', waf: {}, timeoutMs: 5000 } as never];

describe('HTTP/2 listener (server.http2)', () => {
  it('serves h2c prior-knowledge requests and maps :authority to x-forwarded-host', async () => {
    const upstream = await startUpstream('h2-up');
    const proxy = new ProxyServer(
      makeConfig({
        server: { ...makeConfig().server, http2: true },
        routes: route(upstream.port)
      })
    );
    const address = await proxy.start();

    const res = await h2Get(`http://127.0.0.1:${address.port}`, '/hello?x=1');
    expect(res.status).toBe(200);
    expect(res.headers['x-upstream']).toBe('h2-up');
    expect(JSON.parse(res.body).url).toBe('/hello?x=1');

    const recorded = upstream.requests[0];
    // No pseudo-headers leak to the HTTP/1.1 upstream; :authority becomes x-forwarded-host.
    expect(recorded.headers[':authority']).toBeUndefined();
    expect(recorded.headers['x-forwarded-host']).toBe(`127.0.0.1:${address.port}`);

    await proxy.stop();
    await upstream.close();
  });

  it('multiplexes concurrent h2c streams over one session', async () => {
    const upstream = await startUpstream('h2-up');
    const proxy = new ProxyServer(
      makeConfig({
        server: { ...makeConfig().server, http2: true },
        routes: route(upstream.port)
      })
    );
    const address = await proxy.start();

    const client = http2.connect(`http://127.0.0.1:${address.port}`);
    const get = (p: string) =>
      new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = client.request({ ':path': p, ':method': 'GET' });
        let body = '';
        req.setEncoding('utf-8');
        req.on('data', (c) => (body += c));
        req.on('response', (h) => {
          if (h[':status'] !== 200) reject(new Error(`status ${h[':status']}`));
        });
        req.on('end', () => resolve({ status: 200, body }));
        req.on('error', reject);
        req.end();
      });

    // Three streams share one connection; each gets its own response.
    const [a, b, c] = await Promise.all([get('/a'), get('/b'), get('/c')]);
    expect(JSON.parse(a.body).url).toBe('/a');
    expect(JSON.parse(b.body).url).toBe('/b');
    expect(JSON.parse(c.body).url).toBe('/c');
    expect(upstream.requests.length).toBe(3);

    client.close();
    await proxy.stop();
    await upstream.close();
  });

  it('negotiates h2 via ALPN on the TLS listener while HTTP/1.1 still works', async () => {
    const upstream = await startUpstream('h2-up');
    const proxy = new ProxyServer(
      makeConfig({
        server: {
          ...makeConfig().server,
          http2: true,
          tls: { certFile: cert, keyFile: key, requestCert: false }
        },
        routes: route(upstream.port)
      })
    );
    const address = await proxy.start();

    // HTTP/2 over TLS with ALPN negotiation.
    const h2 = await h2Get(`https://127.0.0.1:${address.port}`, '/secure', { rejectUnauthorized: false });
    expect(h2.status).toBe(200);
    expect(JSON.parse(h2.body).headers['x-forwarded-proto']).toBe('https');

    // An HTTP/1.1 client on the same port is unaffected.
    const h1 = await h1Get(`https://127.0.0.1:${address.port}/legacy`, new https.Agent({ rejectUnauthorized: false }));
    expect(h1.status).toBe(200);
    expect(JSON.parse(h1.body).url).toBe('/legacy');

    await proxy.stop();
    await upstream.close();
  });
});
