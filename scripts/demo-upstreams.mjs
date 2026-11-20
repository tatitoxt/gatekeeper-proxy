#!/usr/bin/env node
// Synthetic backend services for the demo and E2E tests. No real data: every
// response just echoes what the upstream received so routing is observable.
import http from 'node:http';

const ports = (process.env.DEMO_UPSTREAM_PORTS || '9001,9002,9003').split(',').map(Number);
const host = process.env.DEMO_UPSTREAM_HOST || '127.0.0.1';

const servers = ports.map(
  (port) =>
    new Promise((resolve, reject) => {
      const name = `demo-upstream-${port}`;
      const server = http.createServer((req, res) => {
        if (req.url === '/health') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', upstream: name }));
          return;
        }
        let body = '';
        req.setEncoding('utf-8');
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': name });
          res.end(
            JSON.stringify({
              upstream: name,
              method: req.method,
              url: req.url,
              body,
              forwardedFor: req.headers['x-forwarded-for'] ?? null,
              forwardedHost: req.headers['x-forwarded-host'] ?? null
            })
          );
        });
      });
      server.on('error', reject);
      server.listen(port, host, () => resolve(server));
    })
);

const started = await Promise.all(servers);
console.log(`demo upstreams ready on ${ports.map((p) => `http://${host}:${p}`).join(', ')}`);

const shutdown = () => {
  for (const server of started) server.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
