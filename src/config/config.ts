import fs from 'node:fs';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { isValidIpOrCidr } from '../utils/ip-utils.js';

export type BalanceStrategy = 'round-robin' | 'least-connections';

export interface RouteRateLimit {
  windowMs: number;
  maxRequests: number;
}

export interface WafRuleOverrides {
  blockSqlInjection: boolean;
  blockXss: boolean;
  blockPathTraversal: boolean;
}

export interface RouteConfig {
  pathPrefix: string;
  targets: string[];
  balanceStrategy?: BalanceStrategy;
  healthCheckPath?: string;
  rateLimit?: RouteRateLimit;
  /** Per-route overrides for firewall.wafRules; unset keys inherit the global flags. */
  waf?: Partial<WafRuleOverrides>;
}

export interface FirewallConfig {
  enabled: boolean;
  ipBlacklist: string[];
  ipWhitelist: string[];
  blockedUserAgents: string[];
  wafRules: WafRuleOverrides;
  customBlockedPaths: string[];
  /** Header names (lowercase) whose values are decoded and scanned with the WAF signatures. */
  inspectedHeaders: string[];
}

export interface RateLimiterConfig {
  globalWindowMs: number;
  globalMaxRequests: number;
  /** Storage backend: per-process memory or shared Redis (multi-instance). Undefined means memory. */
  backend?: 'memory' | 'redis';
  /** Redis connection URL, required when backend is 'redis'. */
  redisUrl?: string;
  /** Key prefix for rate-limit sorted sets in Redis. */
  keyPrefix?: string;
}

export interface HealthCheckConfig {
  intervalMs: number;
  timeoutMs: number;
}

export interface ServerConfig {
  port: number;
  adminPort: number;
  host: string;
  /** Interface the admin API binds to. Defaults to loopback. */
  adminHost: string;
  timeoutMs: number;
  /** Trust X-Forwarded-For from exactly one proxy hop in front of Gatekeeper. */
  trustProxy: boolean;
}

export interface UpstreamConfig {
  /** Pool upstream TCP connections (HTTP keep-alive). */
  keepAlive: boolean;
  /** Max concurrent sockets per upstream host. */
  maxSockets: number;
  /** Idle pooled sockets kept for reuse. */
  maxFreeSockets: number;
}

export interface ClusterConfig {
  /**
   * Proxy worker processes sharing the listener via node:cluster. 1 keeps the
   * single-process layout (proxy + admin in one process); >1 forks workers
   * that serve the proxy port while the primary owns the admin server.
   */
  workers: number;
}

export interface GatekeeperConfig {
  server: ServerConfig;
  routes: RouteConfig[];
  firewall: FirewallConfig;
  rateLimiter: RateLimiterConfig;
  healthCheck: HealthCheckConfig;
  upstream: UpstreamConfig;
  cluster: ClusterConfig;
}

export class ConfigPersistError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigPersistError';
  }
}

export class ConfigValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Invalid Gatekeeper configuration:\n  - ${issues.join('\n  - ')}`);
    this.name = 'ConfigValidationError';
  }
}

export function defaultConfig(): GatekeeperConfig {
  return {
    server: {
      port: 8000,
      adminPort: 8080,
      host: '0.0.0.0',
      adminHost: '127.0.0.1',
      timeoutMs: 30000,
      trustProxy: false
    },
    routes: [],
    firewall: {
      enabled: true,
      ipBlacklist: [],
      ipWhitelist: [],
      blockedUserAgents: [],
      wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
      customBlockedPaths: [],
      inspectedHeaders: []
    },
    rateLimiter: { globalWindowMs: 60000, globalMaxRequests: 300, backend: 'memory' },
    healthCheck: { intervalMs: 10000, timeoutMs: 3000 },
    upstream: { keepAlive: true, maxSockets: 256, maxFreeSockets: 64 },
    cluster: { workers: 1 }
  };
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Validates an untrusted (parsed JSON) value and returns a fully populated config.
 * Missing optional sections fall back to defaults; wrong types are reported, never coerced.
 */
export function validateConfig(raw: unknown): GatekeeperConfig {
  const issues: string[] = [];
  const defaults = defaultConfig();

  if (!isObj(raw)) {
    throw new ConfigValidationError(['config root must be a JSON object']);
  }

  const section = (key: string): Obj => {
    const value = raw[key];
    if (value === undefined) return {};
    if (!isObj(value)) {
      issues.push(`${key} must be an object`);
      return {};
    }
    return value;
  };

  const int = (obj: Obj, key: string, where: string, fallback: number, min: number, max: number): number => {
    const v = obj[key];
    if (v === undefined) return fallback;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < min || v > max) {
      issues.push(`${where}.${key} must be an integer between ${min} and ${max}`);
      return fallback;
    }
    return v;
  };

  const bool = (obj: Obj, key: string, where: string, fallback: boolean): boolean => {
    const v = obj[key];
    if (v === undefined) return fallback;
    if (typeof v !== 'boolean') {
      issues.push(`${where}.${key} must be a boolean`);
      return fallback;
    }
    return v;
  };

  const str = (obj: Obj, key: string, where: string, fallback: string): string => {
    const v = obj[key];
    if (v === undefined) return fallback;
    if (typeof v !== 'string' || v.length === 0) {
      issues.push(`${where}.${key} must be a non-empty string`);
      return fallback;
    }
    return v;
  };

  const optStr = (obj: Obj, key: string, where: string): string | undefined => {
    const v = obj[key];
    if (v === undefined) return undefined;
    if (typeof v !== 'string' || v.length === 0) {
      issues.push(`${where}.${key} must be a non-empty string when set`);
      return undefined;
    }
    return v;
  };

  const strArray = (obj: Obj, key: string, where: string): string[] => {
    const v = obj[key];
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.some((item) => typeof item !== 'string')) {
      issues.push(`${where}.${key} must be an array of strings`);
      return [];
    }
    return v as string[];
  };

  const s = section('server');
  const server: ServerConfig = {
    port: int(s, 'port', 'server', defaults.server.port, 0, 65535),
    adminPort: int(s, 'adminPort', 'server', defaults.server.adminPort, 0, 65535),
    host: str(s, 'host', 'server', defaults.server.host),
    adminHost: str(s, 'adminHost', 'server', defaults.server.adminHost),
    timeoutMs: int(s, 'timeoutMs', 'server', defaults.server.timeoutMs, 1, 600000),
    trustProxy: bool(s, 'trustProxy', 'server', defaults.server.trustProxy)
  };
  if (server.port !== 0 && server.port === server.adminPort && server.host === server.adminHost) {
    issues.push('server.port and server.adminPort must differ');
  }

  const cl = section('cluster');
  const cluster: ClusterConfig = {
    workers: int(cl, 'workers', 'cluster', defaults.cluster.workers, 1, 64)
  };

  const u = section('upstream');
  const upstream: UpstreamConfig = {
    keepAlive: bool(u, 'keepAlive', 'upstream', defaults.upstream.keepAlive),
    maxSockets: int(u, 'maxSockets', 'upstream', defaults.upstream.maxSockets, 1, 65535),
    maxFreeSockets: int(u, 'maxFreeSockets', 'upstream', defaults.upstream.maxFreeSockets, 0, 65535)
  };

  const routes: RouteConfig[] = [];
  const rawRoutes = raw.routes ?? [];
  if (!Array.isArray(rawRoutes)) {
    issues.push('routes must be an array');
  } else {
    const seen = new Set<string>();
    rawRoutes.forEach((r: unknown, i: number) => {
      const where = `routes[${i}]`;
      if (!isObj(r)) {
        issues.push(`${where} must be an object`);
        return;
      }
      const pathPrefix = str(r, 'pathPrefix', where, '');
      if (!pathPrefix) {
        issues.push(`${where}.pathPrefix is required (use "/" for a catch-all route)`);
      } else if (!pathPrefix.startsWith('/')) {
        issues.push(`${where}.pathPrefix must start with "/"`);
      }
      if (seen.has(pathPrefix)) issues.push(`${where}.pathPrefix "${pathPrefix}" is duplicated`);
      seen.add(pathPrefix);

      const targets = strArray(r, 'targets', where);
      if (targets.length === 0) issues.push(`${where}.targets must contain at least one URL`);
      for (const target of targets) {
        try {
          const u = new URL(target);
          if (u.protocol !== 'http:') issues.push(`${where}.targets: "${target}" must use http://`);
        } catch {
          issues.push(`${where}.targets: "${target}" is not a valid URL`);
        }
      }

      const route: RouteConfig = { pathPrefix, targets };

      if (r.balanceStrategy !== undefined) {
        if (r.balanceStrategy !== 'round-robin' && r.balanceStrategy !== 'least-connections') {
          issues.push(`${where}.balanceStrategy must be "round-robin" or "least-connections"`);
        } else {
          route.balanceStrategy = r.balanceStrategy;
        }
      }

      if (r.healthCheckPath !== undefined) {
        const hc = str(r, 'healthCheckPath', where, '');
        if (hc && !hc.startsWith('/')) issues.push(`${where}.healthCheckPath must start with "/"`);
        else if (hc) route.healthCheckPath = hc;
      }

      if (r.rateLimit !== undefined) {
        if (!isObj(r.rateLimit)) {
          issues.push(`${where}.rateLimit must be an object`);
        } else {
          route.rateLimit = {
            windowMs: int(r.rateLimit, 'windowMs', `${where}.rateLimit`, 60000, 1, 86400000),
            maxRequests: int(r.rateLimit, 'maxRequests', `${where}.rateLimit`, 100, 1, 1000000)
          };
        }
      }

      if (r.waf !== undefined) {
        if (!isObj(r.waf)) {
          issues.push(`${where}.waf must be an object`);
        } else {
          const known = new Set<string>(['blockSqlInjection', 'blockXss', 'blockPathTraversal']);
          const waf: Partial<WafRuleOverrides> = {};
          for (const key of ['blockSqlInjection', 'blockXss', 'blockPathTraversal'] as const) {
            if (r.waf[key] !== undefined) {
              if (typeof r.waf[key] !== 'boolean') {
                issues.push(`${where}.waf.${key} must be a boolean`);
              } else {
                waf[key] = r.waf[key];
              }
            }
          }
          for (const key of Object.keys(r.waf)) {
            if (!known.has(key)) {
              issues.push(`${where}.waf has unknown rule "${key}"`);
            }
          }
          if (Object.keys(waf).length > 0) route.waf = waf;
        }
      }
      routes.push(route);
    });
  }

  const f = section('firewall');
  const w = isObj(f.wafRules) ? f.wafRules : {};
  if (f.wafRules !== undefined && !isObj(f.wafRules)) issues.push('firewall.wafRules must be an object');
  const firewall: FirewallConfig = {
    enabled: bool(f, 'enabled', 'firewall', defaults.firewall.enabled),
    ipBlacklist: strArray(f, 'ipBlacklist', 'firewall'),
    ipWhitelist: strArray(f, 'ipWhitelist', 'firewall'),
    blockedUserAgents: strArray(f, 'blockedUserAgents', 'firewall'),
    wafRules: {
      blockSqlInjection: bool(w, 'blockSqlInjection', 'firewall.wafRules', true),
      blockXss: bool(w, 'blockXss', 'firewall.wafRules', true),
      blockPathTraversal: bool(w, 'blockPathTraversal', 'firewall.wafRules', true)
    },
    customBlockedPaths: strArray(f, 'customBlockedPaths', 'firewall'),
    inspectedHeaders: strArray(f, 'inspectedHeaders', 'firewall')
  };
  const headerName = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/i;
  for (const h of firewall.inspectedHeaders) {
    if (h.length > 64) issues.push(`firewall.inspectedHeaders: header name exceeds 64 characters`);
    else if (!headerName.test(h)) issues.push(`firewall.inspectedHeaders: "${h}" is not a valid header name`);
  }
  firewall.inspectedHeaders = firewall.inspectedHeaders.map((h) => h.toLowerCase());
  for (const list of ['ipBlacklist', 'ipWhitelist'] as const) {
    for (const entry of firewall[list]) {
      if (!isValidIpOrCidr(entry)) issues.push(`firewall.${list}: "${entry}" is not a valid IP or CIDR`);
    }
  }
  for (const pattern of firewall.customBlockedPaths) {
    try {
      new RegExp(pattern, 'i');
    } catch {
      issues.push(`firewall.customBlockedPaths: "${pattern}" is not a valid regular expression`);
    }
  }

  const rl = section('rateLimiter');
  const backendRaw = str(rl, 'backend', 'rateLimiter', 'memory');
  if (backendRaw !== 'memory' && backendRaw !== 'redis') {
    issues.push(`rateLimiter.backend must be 'memory' or 'redis'`);
  }
  const rateLimiter: RateLimiterConfig = {
    globalWindowMs: int(rl, 'globalWindowMs', 'rateLimiter', defaults.rateLimiter.globalWindowMs, 1, 86400000),
    globalMaxRequests: int(rl, 'globalMaxRequests', 'rateLimiter', defaults.rateLimiter.globalMaxRequests, 1, 10000000),
    backend: backendRaw === 'redis' ? 'redis' : 'memory',
    redisUrl: optStr(rl, 'redisUrl', 'rateLimiter'),
    keyPrefix: optStr(rl, 'keyPrefix', 'rateLimiter')
  };

  const h = section('healthCheck');
  const healthCheck: HealthCheckConfig = {
    intervalMs: int(h, 'intervalMs', 'healthCheck', defaults.healthCheck.intervalMs, 100, 3600000),
    timeoutMs: int(h, 'timeoutMs', 'healthCheck', defaults.healthCheck.timeoutMs, 10, 60000)
  };

  if (issues.length > 0) throw new ConfigValidationError(issues);
  return { server, routes, firewall, rateLimiter, healthCheck, upstream, cluster };
}

export interface ConfigManagerOptions {
  /** Poll the file for changes and hot-reload it. Defaults to true. */
  watch?: boolean;
  pollIntervalMs?: number;
}

export class ConfigManager {
  private readonly configPath: string;
  private currentConfig: GatekeeperConfig;
  private lastRaw: string | null = null;
  private listeners: ((config: GatekeeperConfig) => void)[] = [];
  private watching = false;

  constructor(configFilePath?: string, options: ConfigManagerOptions = {}) {
    this.configPath = path.resolve(
      configFilePath || process.env.GATEKEEPER_CONFIG || path.join(process.cwd(), 'gatekeeper.config.json')
    );
    this.currentConfig = this.loadInitial();
    if (options.watch !== false) this.watchConfigFile(options.pollIntervalMs ?? 1000);
  }

  public getPath(): string {
    return this.configPath;
  }

  public getConfig(): GatekeeperConfig {
    return this.currentConfig;
  }

  public onChange(listener: (config: GatekeeperConfig) => void): void {
    this.listeners.push(listener);
  }

  /** Validates and applies a partial update, then persists it to disk. Throws ConfigValidationError. */
  public updateConfig(patch: Partial<GatekeeperConfig>): void {
    const next = validateConfig({ ...this.currentConfig, ...patch });
    // Persist first: an edit that cannot be saved must fail instead of silently vanishing on restart.
    this.writeConfig(next);
    this.currentConfig = next;
    this.notifyListeners();
  }

  /** Re-reads the file; keeps the last good config if the new content is invalid. */
  public reload(): boolean {
    let raw: string;
    try {
      raw = fs.readFileSync(this.configPath, 'utf-8');
    } catch (err) {
      logger.error({ err, path: this.configPath }, 'Config file could not be read; keeping current config');
      return false;
    }
    if (raw === this.lastRaw) return false;
    try {
      const next = validateConfig(JSON.parse(raw));
      this.lastRaw = raw;
      this.currentConfig = next;
      logger.info({ path: this.configPath }, 'Configuration hot-reloaded');
      this.notifyListeners();
      return true;
    } catch (err) {
      logger.error(
        { err: err instanceof Error ? err.message : err, path: this.configPath },
        'Hot reload rejected; keeping last valid configuration'
      );
      return false;
    }
  }

  public close(): void {
    if (this.watching) {
      fs.unwatchFile(this.configPath);
      this.watching = false;
    }
  }

  private loadInitial(): GatekeeperConfig {
    if (!fs.existsSync(this.configPath)) {
      logger.warn({ path: this.configPath }, 'Config file not found; using built-in defaults (no routes)');
      return defaultConfig();
    }
    const raw = fs.readFileSync(this.configPath, 'utf-8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new ConfigValidationError([`${this.configPath} is not valid JSON: ${(err as Error).message}`]);
    }
    const config = validateConfig(parsed);
    this.lastRaw = raw;
    logger.info({ path: this.configPath, routes: config.routes.length }, 'Configuration loaded');
    return config;
  }

  private writeConfig(config: GatekeeperConfig): void {
    const raw = JSON.stringify(config, null, 2) + '\n';
    try {
      fs.writeFileSync(this.configPath, raw, 'utf-8');
    } catch (err) {
      logger.error({ err, path: this.configPath }, 'Failed to persist configuration to disk');
      throw new ConfigPersistError(`Could not write config file ${this.configPath}: ${(err as Error).message}`);
    }
    this.lastRaw = raw;
  }

  private watchConfigFile(intervalMs: number): void {
    // Polling survives editors that replace the file and Docker bind mounts, unlike fs.watch.
    fs.watchFile(this.configPath, { interval: intervalMs, persistent: false }, (curr, prev) => {
      if (curr.mtimeMs !== prev.mtimeMs || curr.size !== prev.size) this.reload();
    });
    this.watching = true;
  }

  private notifyListeners(): void {
    for (const listener of this.listeners) {
      try {
        listener(this.currentConfig);
      } catch (err) {
        logger.error({ err }, 'Configuration listener failed');
      }
    }
  }
}
