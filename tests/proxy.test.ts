import http from 'node:http';
import { ProxyServer } from '../src/core/proxy.js';
import { GatekeeperConfig } from '../src/config/config.js';

describe('Proxy Server Integration', () => {
  let backendServer: http.Server;
  let backendPort: number;
  let proxyServer: ProxyServer;
  const proxyPort = 8999;

  beforeAll((done) => {
    // 1. Spin up mock backend
    backendServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', url: req.url, headers: req.headers }));
    });

    backendServer.listen(0, '127.0.0.1', () => {
      const addr = backendServer.address() as any;
      backendPort = addr.port;

      // 2. Spin up proxy server
      const config: GatekeeperConfig = {
        server: { port: proxyPort, adminPort: 8998, host: '127.0.0.1', timeoutMs: 5000 },
        routes: [
          {
            pathPrefix: '/api',
            targets: [`http://127.0.0.1:${backendPort}`]
          }
        ],
        firewall: {
          enabled: true,
          ipBlacklist: [],
          ipWhitelist: [],
          blockedUserAgents: [],
          wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
          customBlockedPaths: []
        },
        rateLimiter: { globalWindowMs: 60000, globalMaxRequests: 100 }
      };

      proxyServer = new ProxyServer(config);
      proxyServer.start().then(() => done());
    });
  });

  afterAll(async () => {
    await proxyServer.stop();
    backendServer.close();
  });

  test('Forwards request to target backend and returns response', (done) => {
    http.get(`http://127.0.0.1:${proxyPort}/api/v1/users`, (res) => {
      expect(res.statusCode).toBe(200);
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        const json = JSON.parse(data);
        expect(json.status).toBe('ok');
        expect(json.url).toBe('/api/v1/users');
        expect(json.headers['x-gatekeeper-proxy']).toBe('1.0');
        done();
      });
    });
  });

  test('Blocks malicious WAF request before reaching backend', (done) => {
    http.get(`http://127.0.0.1:${proxyPort}/api/test?q=%3Cscript%3Ealert(1)%3C/script%3E`, (res) => {
      expect(res.statusCode).toBe(403);
      done();
    });
  });
});
