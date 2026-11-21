import { IncomingMessage } from 'node:http';
import { FirewallConfig, WafRuleOverrides } from '../config/config.js';
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
  let current: string;
  try {
    current = decodeURIComponent(value);
  } catch {
    return null;
  }
  // Later passes are lenient: a decoded literal "%" (from "%25") is legitimate input.
  for (let i = 1; i < MAX_DECODE_PASSES; i++) {
    const next = decodeValidSequences(current);
    if (next === current) break;
    current = next;
  }
  return current.replace(/\+/g, ' ');
}

function decodeValidSequences(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value.replace(/(?:%[0-9a-fA-F]{2})+/g, decodeEscapeRun);
  }
}

/** Decodes each valid UTF-8 sequence (1-4 escapes) in a run, keeping only invalid escapes literal. */
function decodeEscapeRun(run: string): string {
  const escapes = run.match(/%[0-9a-fA-F]{2}/g) ?? [];
  let out = '';
  let i = 0;
  while (i < escapes.length) {
    let consumed = 0;
    for (let n = Math.min(4, escapes.length - i); n >= 1 && consumed === 0; n--) {
      try {
        out += decodeURIComponent(escapes.slice(i, i + n).join(''));
        consumed = n;
      } catch {
        // try a shorter sequence
      }
    }
    if (consumed === 0) {
      out += escapes[i];
      consumed = 1;
    }
    i += consumed;
  }
  return out;
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

  public checkRequest(
    req: FirewallRequest,
    clientIp: string,
    wafOverrides?: Partial<WafRuleOverrides>
  ): FirewallCheckResult {
    if (!this.config.enabled) {
      return { allowed: true };
    }
    const wafRules: WafRuleOverrides = { ...this.config.wafRules, ...wafOverrides };

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
    const urlHit = this.scanValue(decodedUrl, wafRules);
    if (urlHit) {
      return { allowed: false, statusCode: 403, reason: urlHit };
    }

    // 6. Same signatures on the configured headers' decoded values
    for (const name of this.config.inspectedHeaders) {
      const raw = req.headers[name];
      const values = Array.isArray(raw) ? raw : raw === undefined ? [] : [String(raw)];
      for (const value of values) {
        const decoded = decodeForInspection(value);
        if (decoded === null) {
          return { allowed: false, statusCode: 400, reason: `Malformed encoding in ${name} header` };
        }
        const hit = this.scanValue(decoded, wafRules);
        if (hit) {
          return { allowed: false, statusCode: 403, reason: `${hit} (in ${name} header)` };
        }
      }
    }

    return { allowed: true };
  }

  /** Returns the block reason when a decoded value trips a signature, else null. */
  private scanValue(decoded: string, wafRules: WafRuleOverrides): string | null {
    if (wafRules.blockPathTraversal && PATH_TRAVERSAL_PATTERN.test(decoded)) {
      return 'WAF: Path Traversal Attack Detected';
    }
    if (wafRules.blockSqlInjection && SQL_INJECTION_PATTERNS.some((p) => p.test(decoded))) {
      return 'WAF: SQL Injection Attack Detected';
    }
    if (wafRules.blockXss && XSS_PATTERNS.some((p) => p.test(decoded))) {
      return 'WAF: Cross-Site Scripting (XSS) Attack Detected';
    }
    return null;
  }

  private compile(): void {
    this.blockedPathRegexes = this.config.customBlockedPaths.map((source) => ({
      source,
      regex: new RegExp(source, 'i')
    }));
  }
}
