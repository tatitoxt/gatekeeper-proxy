import { IncomingMessage } from 'node:http';
import { FirewallConfig } from '../config/config.js';
import { isIpInRanges } from '../utils/ip-utils.js';

export interface FirewallCheckResult {
  allowed: boolean;
  reason?: string;
  statusCode?: number;
}

export type FirewallRequest = Pick<IncomingMessage, 'headers' | 'url'>;

// Signature heuristics for URL/query inspection. They are intentionally conservative to
// avoid blocking ordinary input such as "O'Brien" or "/select-plan"; they are not a full WAF.
const SQL_INJECTION_PATTERNS: RegExp[] = [
  /\bunion\b\s+(all\s+)?select\b/i,
  /\bselect\b.+\bfrom\b/i,
  /'\s*(or|and)\s+[\w'"]+\s*(=|<|>|like\b)/i,
  /\b(or|and)\s+\d+\s*=\s*\d+/i,
  /'\s*(;|--|#)/,
  /;\s*(drop|delete|insert|update|alter|truncate|exec)\b/i,
  /\b(drop|truncate)\s+table\b/i,
  /\/\*.*\*\//,
  /\b(sleep|benchmark|pg_sleep)\s*\(/i,
  /\bwaitfor\s+delay\b/i,
  /\binformation_schema\b/i
];

const XSS_PATTERNS: RegExp[] = [
  /<\s*script\b/i,
  /<\s*\/\s*script\s*>/i,
  /\b(javascript|vbscript)\s*:/i,
  /<[^>]*\son[a-z]+\s*=/i,
  /<\s*(iframe|embed|object|svg|img)\b[^>]*>/i
];

const PATH_TRAVERSAL_PATTERN = /(^|[\\/=&?])\.\.([\\/&]|$)/;

const MAX_DECODE_PASSES = 3;

/**
 * Decodes repeatedly (to catch double-encoding such as %252e) until the value is stable.
 * Returns null for malformed percent-encoding, which decodeURIComponent would throw on.
 */
export function decodeForInspection(value: string): string | null {
  let current = value;
  for (let i = 0; i < MAX_DECODE_PASSES; i++) {
    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      return null;
    }
    if (next === current) break;
    current = next;
  }
  return current.replace(/\+/g, ' ');
}

export class FirewallEngine {
  private config: FirewallConfig;
  private blockedPathRegexes: { source: string; regex: RegExp }[] = [];

  constructor(config: FirewallConfig) {
    this.config = config;
    this.compile();
  }

  public updateConfig(config: FirewallConfig): void {
    this.config = config;
    this.compile();
  }

  public checkRequest(req: FirewallRequest, clientIp: string): FirewallCheckResult {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // 1. Allowlist: when non-empty, every other IP is rejected.
    if (this.config.ipWhitelist.length > 0 && !isIpInRanges(clientIp, this.config.ipWhitelist)) {
      return { allowed: false, statusCode: 403, reason: 'IP not in Whitelist' };
    }

    // 2. Blocklist
    if (this.config.ipBlacklist.length > 0 && isIpInRanges(clientIp, this.config.ipBlacklist)) {
      return { allowed: false, statusCode: 403, reason: 'IP Blacklisted' };
    }

    // 3. User-Agent substring match
    const userAgent = String(req.headers['user-agent'] || '').toLowerCase();
    for (const blockedAgent of this.config.blockedUserAgents) {
      if (blockedAgent && userAgent.includes(blockedAgent.toLowerCase())) {
        return { allowed: false, statusCode: 403, reason: `Blocked User-Agent (${blockedAgent})` };
      }
    }

    const url = req.url || '/';
    const decodedUrl = decodeForInspection(url);
    if (decodedUrl === null) {
      return { allowed: false, statusCode: 400, reason: 'Malformed URL encoding' };
    }

    // 4. Custom blocked paths (matched against both raw and decoded URL)
    for (const { source, regex } of this.blockedPathRegexes) {
      if (regex.test(url) || regex.test(decodedUrl)) {
        return { allowed: false, statusCode: 403, reason: `Blocked Path Rule (${source})` };
      }
    }

    // 5. Signature rules on the decoded URL
    const { wafRules } = this.config;
    if (wafRules.blockPathTraversal && PATH_TRAVERSAL_PATTERN.test(decodedUrl)) {
      return { allowed: false, statusCode: 403, reason: 'WAF: Path Traversal Attack Detected' };
    }
    if (wafRules.blockSqlInjection && SQL_INJECTION_PATTERNS.some((p) => p.test(decodedUrl))) {
      return { allowed: false, statusCode: 403, reason: 'WAF: SQL Injection Attack Detected' };
    }
    if (wafRules.blockXss && XSS_PATTERNS.some((p) => p.test(decodedUrl))) {
      return { allowed: false, statusCode: 403, reason: 'WAF: Cross-Site Scripting (XSS) Attack Detected' };
    }

    return { allowed: true };
  }

  private compile(): void {
    this.blockedPathRegexes = this.config.customBlockedPaths.map((source) => ({
      source,
      regex: new RegExp(source, 'i')
    }));
  }
}
