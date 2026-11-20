import { randomUUID } from 'node:crypto';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'firewall' | 'rate-limit';
  ip: string;
  path: string;
  method: string;
  reason: string;
}

const MAX_EVENT_PATH_LENGTH = 512;

/** In-process counters and a bounded ring of recent security events. Reset on restart. */
export class MetricsCollector {
  private totalRequests = 0;
  private statusCounts: Record<number, number> = {};
  private wafBlocks = 0;
  private rateLimitHits = 0;
  private recentEvents: SecurityEvent[] = [];
  private readonly startTime: number;

  constructor(
    private readonly maxEvents = 100,
    private readonly now: () => number = Date.now
  ) {
    this.startTime = now();
  }

  public recordRequest(statusCode: number): void {
    this.totalRequests++;
    this.statusCounts[statusCode] = (this.statusCounts[statusCode] || 0) + 1;
  }

  public recordWafBlock(ip: string, path: string, method: string, reason: string): void {
    this.wafBlocks++;
    this.addEvent('firewall', ip, path, method, reason);
  }

  public recordRateLimitHit(ip: string, path: string, method: string): void {
    this.rateLimitHits++;
    this.addEvent('rate-limit', ip, path, method, 'Rate Limit Exceeded (429)');
  }

  public getSummary() {
    const uptimeSeconds = Math.floor((this.now() - this.startTime) / 1000);
    return {
      uptimeSeconds,
      totalRequests: this.totalRequests,
      statusCounts: { ...this.statusCounts },
      wafBlocks: this.wafBlocks,
      rateLimitHits: this.rateLimitHits,
      averageRequestsPerSecond: uptimeSeconds > 0 ? Number((this.totalRequests / uptimeSeconds).toFixed(2)) : 0,
      recentEvents: [...this.recentEvents]
    };
  }

  private addEvent(type: SecurityEvent['type'], ip: string, path: string, method: string, reason: string): void {
    this.recentEvents.unshift({
      id: randomUUID(),
      timestamp: new Date(this.now()).toISOString(),
      type,
      ip,
      path: path.length > MAX_EVENT_PATH_LENGTH ? path.slice(0, MAX_EVENT_PATH_LENGTH) + '…' : path,
      method,
      reason
    });
    if (this.recentEvents.length > this.maxEvents) this.recentEvents.length = this.maxEvents;
  }
}
