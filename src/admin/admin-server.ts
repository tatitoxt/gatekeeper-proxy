import http, { IncomingMessage, ServerResponse } from 'node:http';
import { ConfigManager } from '../config/config.js';
import { metrics } from '../metrics/metrics.js';
import { getDashboardHtml } from './dashboard-ui.js';
import { logger } from '../utils/logger.js';

export class AdminServer {
  private configManager: ConfigManager;
  private server: http.Server | null = null;

  constructor(configManager: ConfigManager) {
    this.configManager = configManager;
  }

  public start(): Promise<void> {
    return new Promise((resolve) => {
      const config = this.configManager.getConfig();
      const adminPort = config.server.adminPort || 8080;
      const host = config.server.host || '0.0.0.0';

      this.server = http.createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(adminPort, host, () => {
        logger.info({ adminPort }, `📊 Gatekeeper Admin Dashboard & REST API running on http://localhost:${adminPort}/_admin`);
        resolve();
      });
    });
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';
    const method = req.method || 'GET';

    // Dashboard UI
    if (url === '/_admin' || url === '/_admin/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(getDashboardHtml());
      return;
    }

    // REST API - Metrics
    if (url === '/api/metrics' && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(metrics.getSummary()));
      return;
    }

    // REST API - Configured Routes
    if (url === '/api/routes' && method === 'GET') {
      const cfg = this.configManager.getConfig();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(cfg.routes));
      return;
    }

    // REST API - Dynamic IP Blacklist Addition
    if (url === '/api/firewall/blacklist' && method === 'POST') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          const { ip } = JSON.parse(body);
          if (ip) {
            const current = this.configManager.getConfig();
            const blacklist = new Set(current.firewall.ipBlacklist);
            blacklist.add(ip);
            this.configManager.updateConfig({
              firewall: {
                ...current.firewall,
                ipBlacklist: Array.from(blacklist)
              }
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, message: `IP ${ip} blacklisted` }));
            return;
          }
        } catch {
          // ignore error
        }
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid payload' }));
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
