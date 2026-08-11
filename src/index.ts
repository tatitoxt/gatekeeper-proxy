import { ConfigManager } from './config/config.js';
import { ProxyServer } from './core/proxy.js';
import { AdminServer } from './admin/admin-server.js';
import { logger } from './utils/logger.js';

async function bootstrap() {
  logger.info('Starting Gatekeeper Proxy Engine...');

  const configManager = new ConfigManager();
  const initialConfig = configManager.getConfig();

  const proxyServer = new ProxyServer(initialConfig);
  const adminServer = new AdminServer(configManager);

  // Subscribe proxy server to config changes for real-time hot reloading
  configManager.onChange((newConfig) => {
    logger.info('Applying updated configuration to Proxy engine...');
    proxyServer.updateConfig(newConfig);
  });

  await proxyServer.start();
  await adminServer.start();

  logger.info('🛡️ Gatekeeper Proxy Engine initialized and ready for production traffic.');

  const shutdown = async () => {
    logger.info('Shutting down Gatekeeper Proxy...');
    await proxyServer.stop();
    await adminServer.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Fatal error during Gatekeeper Proxy initialization');
  process.exit(1);
});
