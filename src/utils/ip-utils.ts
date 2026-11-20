import net from 'node:net';
import { IncomingMessage } from 'node:http';
import ipRangeCheck from 'ip-range-check';

/** Strips the IPv4-mapped IPv6 prefix so "::ffff:10.0.0.1" matches "10.0.0.1" rules. */
export function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(trimmed);
  return mapped ? mapped[1] : trimmed;
}

/**
 * Resolves the client IP. X-Forwarded-For is only honoured when `trustProxy` is enabled,
 * otherwise any client could spoof it to dodge IP rules and rate limits. With one trusted
 * hop in front of Gatekeeper, the right-most entry is the address that proxy saw.
 */
export function getClientIp(req: Pick<IncomingMessage, 'headers' | 'socket'>, trustProxy = false): string {
  const socketIp = normalizeIp(req.socket?.remoteAddress || '');

  if (trustProxy) {
    const header = req.headers['x-forwarded-for'];
    const value = Array.isArray(header) ? header.join(',') : header;
    if (value) {
      const hops = value
        .split(',')
        .map((h) => normalizeIp(h))
        .filter((h) => net.isIP(h) !== 0);
      if (hops.length > 0) return hops[hops.length - 1];
    }
  }

  return socketIp || '0.0.0.0';
}

export function isValidIpOrCidr(value: string): boolean {
  if (net.isIP(value) !== 0) return true;
  const [ip, prefix, ...rest] = value.split('/');
  if (rest.length > 0 || prefix === undefined || !/^\d{1,3}$/.test(prefix)) return false;
  const version = net.isIP(ip);
  const bits = Number(prefix);
  return (version === 4 && bits <= 32) || (version === 6 && bits <= 128);
}

export function isIpInRanges(ip: string, ranges: string[]): boolean {
  if (!ranges || ranges.length === 0) return false;
  const normalized = normalizeIp(ip);
  if (net.isIP(normalized) === 0) return false;
  try {
    return ipRangeCheck(normalized, ranges);
  } catch {
    return ranges.includes(normalized);
  }
}
