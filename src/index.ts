import { ConfigManager } from './config/config.js';
import { ProxyServer } from './core/proxy.js';
import { AdminServer } from './admin/admin-server.js';
import { MetricsCollector } from './metrics/metrics.js';
import { logger } from './utils/logger.js';

async function bootstrap(): Promise<void> {
  const configManager = new ConfigManager();
  const metrics = new MetricsCollector();
  const proxyServer = new ProxyServer(configManager.getConfig(), metrics);
  const adminServer = new AdminServer(configManager, metrics, {
    token: process.env.GATEKEEPER_ADMIN_TOKEN || undefined
  });

  configManager.onChange((config) => proxyServer.updateConfig(config));

  await proxyServer.start();
  await adminServer.start();
  logger.info({ config: configManager.getPath() }, 'Gatekeeper ready');

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down Gatekeeper');
    configManager.close();
    await Promise.all([proxyServer.stop(), adminServer.stop()]);
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

bootstrap().catch((err: unknown) => {
  logger.fatal({ err: err instanceof Error ? err.message : err }, 'Gatekeeper failed to start');
  process.exit(1);
});
