import fs from 'node:fs';
import path from 'node:path';
import { logger } from '../utils/logger.js';

export interface RouteConfig {
  pathPrefix: string;
  targets: string[];
  balanceStrategy?: 'round-robin' | 'least-connections';
  healthCheckPath?: string;
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
}

export interface FirewallConfig {
  enabled: boolean;
  ipBlacklist: string[];
  ipWhitelist: string[];
  blockedUserAgents: string[];
  wafRules: {
    blockSqlInjection: boolean;
    blockXss: boolean;
    blockPathTraversal: boolean;
  };
  customBlockedPaths: string[];
}

export interface RateLimiterConfig {
  globalWindowMs: number;
  globalMaxRequests: number;
}

export interface GatekeeperConfig {
  server: {
    port: number;
    adminPort: number;
    host: string;
    timeoutMs: number;
  };
  routes: RouteConfig[];
  firewall: FirewallConfig;
  rateLimiter: RateLimiterConfig;
}

export class ConfigManager {
  private configPath: string;
  private currentConfig: GatekeeperConfig;
  private listeners: ((config: GatekeeperConfig) => void)[] = [];

  constructor(configFilePath?: string) {
    this.configPath = configFilePath || path.resolve(process.cwd(), 'gatekeeper.config.json');
    this.currentConfig = this.loadConfig();
    this.watchConfigFile();
  }

  public getConfig(): GatekeeperConfig {
    return this.currentConfig;
  }

  public onChange(listener: (config: GatekeeperConfig) => void): void {
    this.listeners.push(listener);
  }

  public updateConfig(newConfig: Partial<GatekeeperConfig>): void {
    this.currentConfig = { ...this.currentConfig, ...newConfig };
    this.saveConfig();
    this.notifyListeners();
  }

  private loadConfig(): GatekeeperConfig {
    try {
      if (fs.existsSync(this.configPath)) {
        const raw = fs.readFileSync(this.configPath, 'utf-8');
        const parsed = JSON.parse(raw) as GatekeeperConfig;
        logger.info({ path: this.configPath }, 'Gatekeeper configuration loaded successfully');
        return parsed;
      }
    } catch (err) {
      logger.error({ err, path: this.configPath }, 'Failed to load configuration file. Using defaults.');
    }

    return {
      server: { port: 8000, adminPort: 8080, host: '0.0.0.0', timeoutMs: 30000 },
      routes: [],
      firewall: {
        enabled: true,
        ipBlacklist: [],
        ipWhitelist: [],
        blockedUserAgents: [],
        wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
        customBlockedPaths: []
      },
      rateLimiter: { globalWindowMs: 60000, globalMaxRequests: 300 }
    };
  }

  private saveConfig(): void {
    try {
      fs.writeFileSync(this.configPath, JSON.stringify(this.currentConfig, null, 2), 'utf-8');
      logger.info('Configuration saved to disk');
    } catch (err) {
      logger.error({ err }, 'Failed to save configuration to disk');
    }
  }

  private watchConfigFile(): void {
    if (!fs.existsSync(this.configPath)) return;

    fs.watch(this.configPath, (eventType) => {
      if (eventType === 'change') {
        logger.info('Configuration file changed on disk. Hot reloading...');
        try {
          const freshConfig = this.loadConfig();
          this.currentConfig = freshConfig;
          this.notifyListeners();
        } catch (err) {
          logger.error({ err }, 'Hot reload failed due to invalid configuration syntax');
        }
      }
    });
  }

  private notifyListeners(): void {
    for (const listener of this.listeners) {
      try {
        listener(this.currentConfig);
      } catch (err) {
        logger.error({ err }, 'Error notifying configuration listener');
      }
    }
  }
}
