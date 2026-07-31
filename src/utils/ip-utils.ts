import { IncomingMessage } from 'node:http';
import ipRangeCheck from 'ip-range-check';

export function getClientIp(req: IncomingMessage): string {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    const ips = (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor).split(',');
    if (ips.length > 0 && ips[0].trim()) {
      return ips[0].trim();
    }
  }

  const realIp = req.headers['x-real-ip'];
  if (realIp && !Array.isArray(realIp)) {
    return realIp.trim();
  }

  return req.socket.remoteAddress || '127.0.0.1';
}

export function isIpInRanges(ip: string, ranges: string[]): boolean {
  if (!ranges || ranges.length === 0) return false;
  try {
    return ipRangeCheck(ip, ranges);
  } catch {
    return ranges.includes(ip);
  }
}
