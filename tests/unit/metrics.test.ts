import { MetricsCollector } from '../../src/metrics/metrics.js';

describe('MetricsCollector', () => {
  test('counts requests by status and computes the average rate', () => {
    let clock = 0;
    const metrics = new MetricsCollector(100, () => clock);
    metrics.recordRequest(200);
    metrics.recordRequest(200);
    metrics.recordRequest(403);
    clock = 2_000;
    expect(metrics.getSummary()).toMatchObject({
      totalRequests: 3,
      statusCounts: { 200: 2, 403: 1 },
      uptimeSeconds: 2,
      averageRequestsPerSecond: 1.5
    });
  });

  test('keeps a bounded, newest-first ring of typed security events', () => {
    const metrics = new MetricsCollector(2);
    metrics.recordWafBlock('192.0.2.1', '/a', 'GET', 'IP Blacklisted');
    metrics.recordRateLimitHit('192.0.2.2', '/b', 'POST');
    metrics.recordWafBlock('192.0.2.3', '/c', 'GET', 'WAF: SQL Injection Attack Detected');
    const { recentEvents, wafBlocks, rateLimitHits } = metrics.getSummary();
    expect(wafBlocks).toBe(2);
    expect(rateLimitHits).toBe(1);
    expect(recentEvents.map((e) => [e.type, e.path])).toEqual([
      ['firewall', '/c'],
      ['rate-limit', '/b']
    ]);
    expect(recentEvents[0].reason).toBe('WAF: SQL Injection Attack Detected');
  });

  test('truncates very long paths in events', () => {
    const metrics = new MetricsCollector();
    metrics.recordWafBlock('192.0.2.1', '/' + 'x'.repeat(5000), 'GET', 'r');
    expect(metrics.getSummary().recentEvents[0].path.length).toBe(513);
  });

  test('exposes counters in Prometheus text format', () => {
    let clock = 0;
    const metrics = new MetricsCollector(100, () => clock);
    metrics.recordRequest(200);
    metrics.recordRequest(429);
    metrics.recordRequest(429);
    metrics.recordWafBlock('192.0.2.1', '/a', 'GET', 'r');
    metrics.recordRateLimitHit('192.0.2.2', '/b', 'POST');
    clock = 5_000;
    const out = metrics.toPrometheus();
    expect(out).toContain('gatekeeper_uptime_seconds 5');
    expect(out).toContain('gatekeeper_requests_total 3');
    expect(out).toContain('gatekeeper_responses_total{status="200"} 1');
    expect(out).toContain('gatekeeper_responses_total{status="429"} 2');
    expect(out).toContain('gatekeeper_waf_blocks_total 1');
    expect(out).toContain('gatekeeper_rate_limit_hits_total 1');
    expect(out).toMatch(/# TYPE gatekeeper_requests_total counter/);
    expect(out.endsWith('\n')).toBe(true);
  });
});
