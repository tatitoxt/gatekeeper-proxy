export interface SecurityEvent {
  id: string;
  timestamp: string;
  ip: string;
  path: string;
  method: string;
  reason: string;
}

export class MetricsCollector {
  private totalRequests = 0;
  private statusCounts: Record<number, number> = {};
  private wafBlocks = 0;
  private rateLimitHits = 0;
  private recentEvents: SecurityEvent[] = [];
  private maxEvents = 100;
  private startTime = Date.now();

  public recordRequest(statusCode: number): void {
    this.totalRequests++;
    this.statusCounts[statusCode] = (this.statusCounts[statusCode] || 0) + 1;
  }

  public recordWafBlock(ip: string, path: string, method: string, reason: string): void {
    this.wafBlocks++;
    this.addEvent({
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toISOString(),
      ip,
      path,
      method,
      reason: `WAF: ${reason}`
    });
  }

  public recordRateLimitHit(ip: string, path: string, method: string): void {
    this.rateLimitHits++;
    this.addEvent({
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toISOString(),
      ip,
      path,
      method,
      reason: 'Rate Limit Exceeded (429)'
    });
  }

  public getSummary() {
    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
    return {
      uptimeSeconds,
      totalRequests: this.totalRequests,
      statusCounts: this.statusCounts,
      wafBlocks: this.wafBlocks,
      rateLimitHits: this.rateLimitHits,
      requestsPerSecond: uptimeSeconds > 0 ? (this.totalRequests / uptimeSeconds).toFixed(2) : '0.00',
      recentEvents: this.recentEvents
    };
  }

  private addEvent(event: SecurityEvent): void {
    this.recentEvents.unshift(event);
    if (this.recentEvents.length > this.maxEvents) {
      this.recentEvents.pop();
    }
  }
}

export const metrics = new MetricsCollector();
