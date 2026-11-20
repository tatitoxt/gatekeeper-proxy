import { decodeForInspection, FirewallEngine, FirewallRequest } from '../../src/firewall/firewall.js';
import { FirewallConfig } from '../../src/config/config.js';

const baseConfig = (): FirewallConfig => ({
  enabled: true,
  ipBlacklist: ['10.0.0.99', '203.0.113.0/24'],
  ipWhitelist: [],
  blockedUserAgents: ['sqlmap'],
  wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
  customBlockedPaths: ['^/\\.env', '^/wp-login\\.php']
});

const req = (url: string, headers: Record<string, string> = {}): FirewallRequest =>
  ({ url, headers }) as FirewallRequest;

const CLIENT = '192.0.2.1';

describe('FirewallEngine', () => {
  const firewall = new FirewallEngine(baseConfig());

  test('blocks blacklisted IPs, including CIDR ranges', () => {
    expect(firewall.checkRequest(req('/api'), '10.0.0.99')).toMatchObject({ allowed: false, reason: 'IP Blacklisted' });
    expect(firewall.checkRequest(req('/api'), '203.0.113.77').allowed).toBe(false);
    expect(firewall.checkRequest(req('/api'), '::ffff:10.0.0.99').allowed).toBe(false);
  });

  test('blocks user agents case-insensitively', () => {
    const res = firewall.checkRequest(req('/api', { 'user-agent': 'SQLMap/1.7' }), CLIENT);
    expect(res).toMatchObject({ allowed: false, statusCode: 403 });
    expect(res.reason).toContain('User-Agent');
  });

  test('blocks custom path rules on raw and decoded URLs', () => {
    expect(firewall.checkRequest(req('/.env.production'), CLIENT).reason).toContain('Blocked Path Rule');
    expect(firewall.checkRequest(req('/%2eenv'), CLIENT).reason).toContain('Blocked Path Rule');
    expect(firewall.checkRequest(req('/wp-login.php'), CLIENT).allowed).toBe(false);
  });

  test.each([
    '/api/users?id=1%20OR%201=1',
    '/api/users?id=1+OR+1=1',
    "/api/users?name=admin'--",
    "/api/users?name=x' OR 'a'='a",
    '/api/items?q=1 UNION ALL SELECT password FROM users',
    '/api/items?q=1;DROP TABLE users',
    '/api/items?q=1/**/',
    '/api/items?q=sleep(5)',
    '/api/items?q=%2527%2520OR%25201%253D1' // double-encoded
  ])('detects SQL injection in %s', (url) => {
    expect(firewall.checkRequest(req(url), CLIENT).reason).toBe('WAF: SQL Injection Attack Detected');
  });

  test.each([
    '/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
    '/search?q=<img src=x onerror=alert(1)>',
    '/search?q=javascript:alert(1)',
    '/search?q=%3Csvg%20onload%3Dalert(1)%3E',
    '/search?q=<iframe src=//evil>'
  ])('detects XSS in %s', (url) => {
    expect(firewall.checkRequest(req(url), CLIENT).reason).toBe('WAF: Cross-Site Scripting (XSS) Attack Detected');
  });

  test.each([
    '/files/../../etc/passwd',
    '/files/..%2f..%2fetc/passwd',
    '/files/%2e%2e/%2e%2e/etc/passwd',
    '/files/%252e%252e%252fetc', // double-encoded
    '/files?path=../secret',
    '/files/..\\windows'
  ])('detects path traversal in %s', (url) => {
    expect(firewall.checkRequest(req(url), CLIENT).reason).toBe('WAF: Path Traversal Attack Detected');
  });

  test.each([
    '/api/v1/users?page=2',
    "/api/v1/users?name=O'Brien",
    '/products/select-plan',
    '/docs/drop-shipping',
    '/api/v1/search?q=update+my+profile',
    '/api/v1/search?q=rock--paper',
    '/files/report..final.pdf',
    '/blog/onboarding=easy'
  ])('allows legitimate request %s', (url) => {
    expect(firewall.checkRequest(req(url, { 'user-agent': 'Mozilla/5.0' }), CLIENT)).toEqual({ allowed: true });
  });

  test('rejects malformed percent-encoding with 400 instead of throwing', () => {
    expect(firewall.checkRequest(req('/api/%E0%A4%A'), CLIENT)).toEqual({
      allowed: false,
      statusCode: 400,
      reason: 'Malformed URL encoding'
    });
  });

  test('allowlist rejects every IP outside it', () => {
    const fw = new FirewallEngine({ ...baseConfig(), ipWhitelist: ['198.51.100.0/24'] });
    expect(fw.checkRequest(req('/'), '198.51.100.20').allowed).toBe(true);
    expect(fw.checkRequest(req('/'), CLIENT)).toMatchObject({ allowed: false, reason: 'IP not in Whitelist' });
  });

  test('individual signature rules can be disabled', () => {
    const fw = new FirewallEngine({
      ...baseConfig(),
      wafRules: { blockSqlInjection: false, blockXss: true, blockPathTraversal: true }
    });
    expect(fw.checkRequest(req('/api?id=1 OR 1=1'), CLIENT).allowed).toBe(true);
  });

  test('disabled firewall allows everything and updateConfig recompiles rules', () => {
    const fw = new FirewallEngine({ ...baseConfig(), enabled: false });
    expect(fw.checkRequest(req('/.env'), '10.0.0.99').allowed).toBe(true);
    fw.updateConfig({ ...baseConfig(), customBlockedPaths: ['^/private'] });
    expect(fw.checkRequest(req('/private/x'), CLIENT).allowed).toBe(false);
    expect(fw.checkRequest(req('/.env'), CLIENT).allowed).toBe(true);
  });
});

describe('decodeForInspection', () => {
  test('decodes up to three layers, maps + to space and flags malformed input', () => {
    expect(decodeForInspection('%25252e')).toBe('.');
    expect(decodeForInspection('a+b')).toBe('a b');
    expect(decodeForInspection('%zz')).toBeNull();
  });

  test('accepts an encoded literal percent sign but still decodes encoded payloads around it', () => {
    expect(decodeForInspection('/api?q=100%25')).toBe('/api?q=100%');
    expect(decodeForInspection('/api?q=100%25%20off')).toBe('/api?q=100% off');
    expect(decodeForInspection('%252e%252e%252f%25')).toBe('../%');
    expect(decodeForInspection('%253C%25FF%253E')).toBe('<%FF>');
    expect(decodeForInspection('%253C%25C3%25A9%25FF')).toBe('<é%FF');
    const engine = new FirewallEngine(baseConfig());
    expect(engine.checkRequest(req('/api?discount=100%25'), CLIENT).allowed).toBe(true);
    expect(engine.checkRequest(req('/files/%252e%252e%252f%25/etc/passwd'), CLIENT).allowed).toBe(false);
  });
});
