import net, { AddressInfo } from 'node:net';
import { WebSocketServer, WebSocket } from 'ws';
import { ProxyServer } from '../../src/core/proxy.js';
import { makeConfig } from '../helpers.js';

/** Real RFC 6455 traffic through the proxy: an upstream echo server reached
 * over the gatekeeper's upgrade pipeline (firewall -> rate limit -> route -> tunnel). */
describe('WebSocket proxying', () => {
  let upstream: WebSocketServer;
  let upstreamPort: number;
  let proxy: ProxyServer;
  let proxyPort: number;
  const receivedByUpstream: string[] = [];

  beforeAll(async () => {
    upstream = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    upstream.on('connection', (ws) => {
      ws.on('message', (data) => {
        receivedByUpstream.push(String(data));
        ws.send(`echo:${String(data)}`);
      });
    });
    await new Promise((r) => upstream.on('listening', r));
    upstreamPort = (upstream.address() as AddressInfo).port;

    const config = makeConfig({
      routes: [{ pathPrefix: '/ws', targets: [`http://127.0.0.1:${upstreamPort}`] }]
    });
    proxy = new ProxyServer(config);
    const addr = await proxy.start();
    proxyPort = (addr as AddressInfo).port;
  });

  afterAll(async () => {
    // Drop live tunnels first so proxy.stop() doesn't wait on open sockets.
    for (const c of upstream.clients) c.terminate();
    await proxy.stop();
    await new Promise((r) => upstream.close(r));
  });

  it('relays a WebSocket handshake and echoes frames both ways', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${proxyPort}/ws/channel?room=a`);
    const reply = await new Promise<string>((resolve, reject) => {
      ws.on('open', () => ws.send('hello-gatekeeper'));
      ws.on('message', (d) => resolve(String(d)));
      ws.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 5000);
    });
    expect(reply).toBe('echo:hello-gatekeeper');
    expect(receivedByUpstream).toContain('hello-gatekeeper');
    ws.close();
  });

  it('runs the same route pipeline: a WAF signature match never upgrades', async () => {
    // ..%2f decodes to ../ inside the path and trips the path-traversal signature.
    const ws = new WebSocket(`ws://127.0.0.1:${proxyPort}/ws/..%2fetc`);
    const err = await new Promise<string>((resolve) => {
      ws.on('unexpected-response', (_req, res) => resolve(String(res.statusCode)));
      ws.on('error', () => resolve('error'));
      setTimeout(() => resolve('timeout'), 5000);
    });
    expect(err).toBe('403');
    ws.terminate();
  });

  it('a path with no matching route is rejected before the upgrade', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${proxyPort}/nowhere`);
    const code = await new Promise<string>((resolve) => {
      ws.on('unexpected-response', (_req, res) => resolve(String(res.statusCode)));
      ws.on('error', () => resolve('error'));
      setTimeout(() => resolve('timeout'), 5000);
    });
    expect(code).toBe('404');
    ws.terminate();
  });

  it('ignores an absolute-form request target and still upgrades only the configured upstream', async () => {
    // SSRF probe: the request line points at a dead port; the upgrade must still
    // reach the configured upstream, not the client-supplied authority.
    const statusLine = await new Promise<string>((resolve, reject) => {
      const socket = net.connect(proxyPort, '127.0.0.1', () => {
        socket.write(
          `GET http://127.0.0.1:9/ws HTTP/1.1\r\nHost: attacker\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`
        );
      });
      let data = '';
      socket.on('data', (d) => {
        data += d.toString();
        if (data.includes('\r\n\r\n')) {
          socket.destroy();
          resolve(data.split('\r\n')[0]);
        }
      });
      socket.on('error', reject);
      socket.setTimeout(5000, () => reject(new Error(`timed out, got: ${data}`)));
    });
    expect(statusLine).toContain('101');
  });
});
