import { IncomingMessage } from 'node:http';
import { getClientIp, isIpInRanges, isValidIpOrCidr, normalizeIp } from '../../src/utils/ip-utils.js';

const req = (remoteAddress: string, headers: Record<string, string> = {}) =>
  ({ headers, socket: { remoteAddress } }) as unknown as IncomingMessage;

describe('getClientIp', () => {
  test('uses the socket address and ignores X-Forwarded-For by default', () => {
    expect(getClientIp(req('192.0.2.10', { 'x-forwarded-for': '10.0.0.1' }))).toBe('192.0.2.10');
    expect(getClientIp(req('192.0.2.10', { 'x-real-ip': '10.0.0.1' }))).toBe('192.0.2.10');
  });

  test('uses the right-most valid X-Forwarded-For hop when trustProxy is on', () => {
    expect(getClientIp(req('127.0.0.1', { 'x-forwarded-for': '6.6.6.6, 198.51.100.4' }), true)).toBe('198.51.100.4');
    expect(getClientIp(req('127.0.0.1', { 'x-forwarded-for': 'garbage' }), true)).toBe('127.0.0.1');
  });

  test('normalises IPv4-mapped IPv6 addresses', () => {
    expect(getClientIp(req('::ffff:203.0.113.5'))).toBe('203.0.113.5');
    expect(normalizeIp(' ::FFFF:10.1.2.3 ')).toBe('10.1.2.3');
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
  });
});

describe('isValidIpOrCidr', () => {
  test.each(['10.0.0.1', '10.0.0.0/8', '2001:db8::1', '2001:db8::/32', '0.0.0.0/0'])('accepts %s', (v) => {
    expect(isValidIpOrCidr(v)).toBe(true);
  });
  test.each(['10.0.0.256', '10.0.0.0/33', '2001:db8::/129', 'localhost', '10.0.0.0/8/1', '10.0.0.0/x', ''])(
    'rejects %s',
    (v) => {
      expect(isValidIpOrCidr(v)).toBe(false);
    }
  );
});

describe('isIpInRanges', () => {
  test('matches exact addresses, CIDR ranges and mapped addresses', () => {
    expect(isIpInRanges('10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(isIpInRanges('::ffff:10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(isIpInRanges('192.168.0.1', ['10.0.0.0/8', '192.168.0.1'])).toBe(true);
    expect(isIpInRanges('192.168.0.2', ['10.0.0.0/8'])).toBe(false);
  });

  test('matches IPv6 addresses and prefixes without mixing families', () => {
    expect(isIpInRanges('2001:db8::42', ['2001:db8::/32'])).toBe(true);
    expect(isIpInRanges('2001:db9::1', ['2001:db8::/32'])).toBe(false);
    expect(isIpInRanges('2001:db8::1', ['2001:db8:0:0::1'])).toBe(true);
    expect(isIpInRanges('10.0.0.1', ['::/0'])).toBe(false);
  });

  test('never matches empty lists or non-IP input', () => {
    expect(isIpInRanges('10.0.0.1', [])).toBe(false);
    expect(isIpInRanges('not-an-ip', ['0.0.0.0/0'])).toBe(false);
  });
});
