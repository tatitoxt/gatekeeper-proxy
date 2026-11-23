import cluster from 'node:cluster';
import { ConfigManager } from './config/config.js';
import { ProxyServer } from './core/proxy.js';
import { AdminServer } from './admin/admin-server.js';
import { MetricsCollector } from './metrics/metrics.js';
import { logger } from './utils/logger.js';

async function bootstrap(): Promise<void> {
  const configManager = new ConfigManager();
  const metrics = new MetricsCollector();
  const workers = configManager.getConfig().cluster.workers;

  if (workers > 1 && cluster.isPrimary) {
    runPrimary(configManager, workers);
    return;
  }

  const proxyServer = new ProxyServer(configManager.getConfig(), metrics);
  configManager.onChange((config) => proxyServer.updateConfig(config));
  await proxyServer.start();

  let adminServer: AdminServer | undefined;
  if (!cluster.isWorker) {
    adminServer = new AdminServer(configManager, metrics, {
      token: process.env.GATEKEEPER_ADMIN_TOKEN || undefined
    });
    await adminServer.start();
    logger.info({ config: configManager.getPath() }, 'Gatekeeper ready');
  } else {
    // Workers report counters to the primary so the dashboard and Prometheus
    // endpoint reflect real traffic; deltas are merged there.
    const reporter = setInterval(() => {
      if (process.connected) process.send?.({ type: 'gk:metrics', summary: metrics.getSummary() });
    }, 2000);
    reporter.unref();
    logger.info({ worker: process.pid }, 'Gatekeeper worker ready');
  }

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down Gatekeeper');
    configManager.close();
    await Promise.all([proxyServer.stop(), adminServer?.stop()]);
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

/**
 * Primary process in clustered mode: owns the admin server (a single admin
 * listener — workers must not fight for the admin port), forks the workers
 * that share the proxy port, respawns them on unexpected exit and forwards
 * graceful shutdown.
 */
function runPrimary(configManager: ConfigManager, workers: number): void {
  const metrics = new MetricsCollector();
  const lastSummaries = new Map<number, ReturnType<MetricsCollector['getSummary']>>();
  cluster.on('message', (worker, msg: { type?: string; summary?: ReturnType<MetricsCollector['getSummary']> }) => {
    if (msg?.type === 'gk:metrics' && msg.summary) {
      metrics.mergeWorkerSummary(lastSummaries.get(worker.id), msg.summary);
      lastSummaries.set(worker.id, msg.summary);
    }
  });
  const adminServer = new AdminServer(configManager, metrics, {
    token: process.env.GATEKEEPER_ADMIN_TOKEN || undefined
  });

  let shuttingDown = false;
  // The "ready" marker is what scripts and tests wait for: emit it only once
  // every worker has bound the shared proxy port.
  let listening = 0;
  cluster.on('listening', () => {
    if (++listening >= workers) logger.info({ workers }, 'Gatekeeper ready (all workers bound)');
  });
  void adminServer.start().then(() => {
    for (let i = 0; i < workers; i++) cluster.fork();
  }).catch((err: unknown) => {
    logger.fatal({ err: err instanceof Error ? err.message : err }, 'Admin server failed to start');
    process.exit(1);
  });

  // Respawning forever when the proxy port is permanently busy would look like
  // a healthy gateway that never serves traffic: give up after rapid crashes.
  let respawnedAt: number[] = [];
  cluster.on('exit', (worker, code) => {
    lastSummaries.delete(worker.id);
    if (shuttingDown) return;
    respawnedAt.push(Date.now());
    respawnedAt = respawnedAt.filter((t) => Date.now() - t < 30_000);
    if (respawnedAt.length > 5) {
      logger.fatal('Proxy workers keep failing (is the port already in use?); giving up');
      process.exit(1);
    }
    logger.warn({ worker: worker.process.pid, code }, 'Proxy worker exited; respawning');
    cluster.fork();
  });

  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down Gatekeeper primary');
    configManager.close();
    for (const w of Object.values(cluster.workers ?? {})) w?.kill('SIGTERM');
    // Wait for workers to drain (each runs proxyServer.stop()) before exiting:
    // disconnecting early would interrupt their in-flight requests.
    const drained = new Promise<void>((resolve) => {
      const alive = () => Object.keys(cluster.workers ?? {}).length;
      if (alive() === 0) return resolve();
      cluster.on('exit', () => {
        if (alive() === 0) resolve();
      });
      setTimeout(resolve, 8_000).unref();
    });
    void Promise.all([adminServer.stop(), drained]).then(() => process.exit(0));
    setTimeout(() => process.exit(0), 10_000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

bootstrap().catch((err: unknown) => {
  logger.fatal({ err: err instanceof Error ? err.message : err }, 'Gatekeeper failed to start');
  process.exit(1);
});
