import { IncomingMessage } from 'node:http';
import { FirewallEngine } from '../src/firewall/firewall.js';

describe('Firewall Engine (WAF)', () => {
  const config = {
    enabled: true,
    ipBlacklist: ['10.0.0.99'],
    ipWhitelist: [],
    blockedUserAgents: ['sqlmap'],
    wafRules: {
      blockSqlInjection: true,
      blockXss: true,
      blockPathTraversal: true
    },
    customBlockedPaths: ['^/\\.env']
  };

  const firewall = new FirewallEngine(config);

  test('Blocks blacklisted IP address', () => {
    const req = { headers: {}, url: '/api/test' } as IncomingMessage;
    const res = firewall.checkRequest(req, '10.0.0.99');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('Blacklisted');
  });

  test('Blocks blocked user-agent', () => {
    const req = { headers: { 'user-agent': 'sqlmap/1.0' }, url: '/api/test' } as IncomingMessage;
    const res = firewall.checkRequest(req, '192.168.1.1');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('User-Agent');
  });

  test('Detects SQL Injection in URL', () => {
    const req = { headers: {}, url: '/api/users?id=1%20OR%201=1' } as IncomingMessage;
    const res = firewall.checkRequest(req, '192.168.1.1');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('SQL Injection');
  });

  test('Detects XSS Attack in URL', () => {
    const req = { headers: {}, url: '/search?q=%3Cscript%3Ealert(1)%3C/script%3E' } as IncomingMessage;
    const res = firewall.checkRequest(req, '192.168.1.1');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('Cross-Site Scripting');
  });

  test('Detects Directory Traversal Attack', () => {
    const req = { headers: {}, url: '/files/..%2f..%2fetc/passwd' } as IncomingMessage;
    const res = firewall.checkRequest(req, '192.168.1.1');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('Path Traversal');
  });

  test('Allows clean legitimate request', () => {
    const req = { headers: { 'user-agent': 'Mozilla/5.0' }, url: '/api/v1/users?page=2' } as IncomingMessage;
    const res = firewall.checkRequest(req, '192.168.1.1');
    expect(res.allowed).toBe(true);
  });
});
