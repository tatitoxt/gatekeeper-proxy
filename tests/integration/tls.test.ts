import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { AddressInfo } from 'node:net';
import { ProxyServer } from '../../src/core/proxy.js';
import { makeConfig } from '../helpers.js';

const fixtures = path.resolve(__dirname, '../fixtures');
const cert = path.join(fixtures, 'cert.pem');
const key = path.join(fixtures, 'key.pem');

const insecure = new https.Agent({ rejectUnauthorized: false });

function httpsGet(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    https
      .get(url, { agent: insecure }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode || 0, body }));
      })
      .on('error', reject);
  });
}

describe('TLS termination and https upstreams', () => {
  it('serves HTTPS on the proxy listener when server.tls is set', async () => {
    const upstream = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ proto: req.headers['x-forwarded-proto'] }));
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    const upstreamPort = (upstream.address() as AddressInfo).port;

    const proxy = new ProxyServer(
      makeConfig({
        server: { ...makeConfig().server, port: 0, host: '127.0.0.1', tls: { certFile: cert, keyFile: key, requestCert: false } },
        routes: [{ pathPrefix: '/', targets: [`http://127.0.0.1:${upstreamPort}`], stripPrefix: false, strategy: 'round-robin', waf: {}, timeoutMs: 5000 } as never]
      })
    );
    const address = await proxy.start();
    const res = await httpsGet(`https://127.0.0.1:${address.port}/hello`);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).proto).toBe('https');
    await proxy.stop();
    upstream.close();
  });

  it('forwards to https:// upstream targets', async () => {
    const tlsUpstream = https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, (_req, res) => {
      res.writeHead(200);
      res.end('secure upstream');
    });
    await new Promise<void>((r) => tlsUpstream.listen(0, '127.0.0.1', r));
    const upstreamPort = (tlsUpstream.address() as AddressInfo).port;

    const proxy = new ProxyServer(
      makeConfig({
        server: { ...makeConfig().server, port: 0, host: '127.0.0.1' },
        routes: [{ pathPrefix: '/', targets: [`https://127.0.0.1:${upstreamPort}`], stripPrefix: false, strategy: 'round-robin', waf: {}, timeoutMs: 5000 } as never]
      })
    );
    // Upstream cert is self-signed: point the TLS agent at our fixture CA-equivalent (the cert itself).
    (proxy as never as { upstreamTlsAgent: https.Agent }).upstreamTlsAgent = new https.Agent({ rejectUnauthorized: false });
    const address = await proxy.start();
    const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      http.get(`http://127.0.0.1:${address.port}/x`, (r) => {
        let b = '';
        r.on('data', (c) => (b += c));
        r.on('end', () => resolve({ status: r.statusCode || 0, body: b }));
      }).on('error', reject);
    });
    expect(res.status).toBe(200);
    expect(res.body).toBe('secure upstream');
    await proxy.stop();
    tlsUpstream.close();
  });
});
