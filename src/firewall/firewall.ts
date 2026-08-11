import { IncomingMessage } from 'node:http';
import { FirewallConfig } from '../config/config.js';
import { isIpInRanges } from '../utils/ip-utils.js';

export interface FirewallCheckResult {
  allowed: boolean;
  reason?: string;
  statusCode?: number;
}

export class FirewallEngine {
  private config: FirewallConfig;

  // Common attack detection signatures
  private sqlInjectionPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|GRANT|REVOKE)\b)|(')|(--)|(\/\*)|(\bOR\b\s+\d+=\d+)|(\bAND\b\s+\d+=\d+)/i;
  private xssPattern = /(<script\b[^>]*>)|(javascript:)|(onload\s*=)|(onerror\s*=)|(<iframe\b[^>]*>)|(<embed\b[^>]*>)/i;
  private pathTraversalPattern = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)/i;

  constructor(config: FirewallConfig) {
    this.config = config;
  }

  public updateConfig(config: FirewallConfig): void {
    this.config = config;
  }

  public checkRequest(req: IncomingMessage, clientIp: string): FirewallCheckResult {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // 1. Whitelist check (if present, non-whitelisted IPs are blocked)
    if (this.config.ipWhitelist && this.config.ipWhitelist.length > 0) {
      if (!isIpInRanges(clientIp, this.config.ipWhitelist)) {
        return { allowed: false, statusCode: 403, reason: 'IP not in Whitelist' };
      }
    }

    // 2. Blacklist check
    if (this.config.ipBlacklist && this.config.ipBlacklist.length > 0) {
      if (isIpInRanges(clientIp, this.config.ipBlacklist)) {
        return { allowed: false, statusCode: 403, reason: 'IP Blacklisted' };
      }
    }

    // 3. User-Agent check
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    if (this.config.blockedUserAgents && this.config.blockedUserAgents.length > 0) {
      for (const blockedAgent of this.config.blockedUserAgents) {
        if (userAgent.includes(blockedAgent.toLowerCase())) {
          return { allowed: false, statusCode: 403, reason: `Blocked User-Agent (${blockedAgent})` };
        }
      }
    }

    const url = req.url || '';

    // 4. Custom blocked paths regex check
    if (this.config.customBlockedPaths && this.config.customBlockedPaths.length > 0) {
      for (const pathRegexStr of this.config.customBlockedPaths) {
        const regex = new RegExp(pathRegexStr, 'i');
        if (regex.test(url)) {
          return { allowed: false, statusCode: 403, reason: `Blocked Path Rule (${pathRegexStr})` };
        }
      }
    }

    // 5. WAF Signature Rules Inspection
    const decodedUrl = decodeURIComponent(url);

    if (this.config.wafRules.blockPathTraversal && this.pathTraversalPattern.test(decodedUrl)) {
      return { allowed: false, statusCode: 403, reason: 'WAF: Path Traversal Attack Detected' };
    }

    if (this.config.wafRules.blockSqlInjection && this.sqlInjectionPattern.test(decodedUrl)) {
      return { allowed: false, statusCode: 403, reason: 'WAF: SQL Injection Attack Detected' };
    }

    if (this.config.wafRules.blockXss && this.xssPattern.test(decodedUrl)) {
      return { allowed: false, statusCode: 403, reason: 'WAF: Cross-Site Scripting (XSS) Attack Detected' };
    }

    return { allowed: true };
  }
}
