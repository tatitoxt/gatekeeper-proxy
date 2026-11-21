#!/usr/bin/env node
// Throughput benchmark: demo upstreams + Gatekeeper + autocannon.
// Usage: npm run bench [-- --json]  — prints per-scenario req/s and latency,
// or a JSON blob with --json for CI/archive.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import autocannon from 'autocannon';

const PROXY_PORT = 18100;
const UPSTREAM_PORTS = [19001, 19002];
const DURATION_S = Number(process.env.BENCH_DURATION_S || 10);
const CONNECTIONS = Number(process.env.BENCH_CONNECTIONS || 50);

const run = (cmd, args, opts = {}) =>
  spawn(cmd, args, { stdio: 'ignore', ...opts });

const waitFor = async (url, tries = 100) => {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${url}`);
};

const shoot = (url, extra = {}) =>
  autocannon({
    url,
    connections: CONNECTIONS,
    duration: DURATION_S,
    ...extra,
  });

async function main() {
  const json = process.argv.includes('--json');
  const procs = [];

  // 1) Demo upstreams on private ports.
  procs.push(
    run('node', ['scripts/demo-upstreams.mjs'], {
      env: { ...process.env, DEMO_UPSTREAM_PORTS: UPSTREAM_PORTS.join(',') },
    })
  );
  await waitFor(`http://127.0.0.1:${UPSTREAM_PORTS[0]}/health`);

  // 2) Gatekeeper with a benchmark config: same routing + WAF as the demo
  //    but rate limits high enough to stay out of the way.
  const dir = mkdtempSync(path.join(tmpdir(), 'gk-bench-'));
  const config = {
    server: {
      port: PROXY_PORT,
      adminPort: 18101,
      host: '127.0.0.1',
      adminHost: '127.0.0.1',
      timeoutMs: 30000,
      trustProxy: false,
    },
    routes: [
      {
        pathPrefix: '/api/v1',
        targets: UPSTREAM_PORTS.map((p) => `http://127.0.0.1:${p}`),
        balanceStrategy: 'round-robin',
        healthCheckPath: '/health',
      },
    ],
    firewall: {
      enabled: true,
      ipBlacklist: [],
      ipWhitelist: [],
      blockedUserAgents: ['sqlmap'],
      wafRules: { blockSqlInjection: true, blockXss: true, blockPathTraversal: true },
      customBlockedPaths: ['^/\\.env.*'],
    },
    rateLimiter: { globalWindowMs: 60000, globalMaxRequests: 1000000 },
    healthCheck: { intervalMs: 60000, timeoutMs: 3000 },
  };
  const configPath = path.join(dir, 'bench.config.json');
  writeFileSync(configPath, JSON.stringify(config, null, 2));

  procs.push(
    run('node', ['dist/index.js'], {
      env: { ...process.env, GATEKEEPER_CONFIG: configPath },
    })
  );
  await waitFor(`http://127.0.0.1:${PROXY_PORT}/api/v1/health`);

  try {
    const baseline = await shoot(`http://127.0.0.1:${UPSTREAM_PORTS[0]}/api/v1/ping`);
    const proxied = await shoot(`http://127.0.0.1:${PROXY_PORT}/api/v1/ping`);
    const wafBlocked = await shoot(
      `http://127.0.0.1:${PROXY_PORT}/api/v1/ping?q=%27%20OR%201%3D1--`
    );

    const summary = (label, r) => ({
      label,
      requests_per_sec: Math.round(r.requests.average),
      latency_ms_p50: r.latency.p50,
      latency_ms_p99: r.latency.p99,
      throughput_mb_s: +(r.throughput.average / 1e6).toFixed(2),
      non_2xx: r.non2xx,
      errors: r.errors,
    });

    const results = [
      summary('upstream direct', baseline),
      summary('through gatekeeper (routing + WAF)', proxied),
      summary('through gatekeeper (WAF-blocked payload)', wafBlocked),
    ];

    if (json) {
      console.log(JSON.stringify({ connections: CONNECTIONS, duration_s: DURATION_S, results }, null, 2));
    } else {
      console.log(`\nautocannon: ${CONNECTIONS} connections x ${DURATION_S}s\n`);
      for (const r of results) {
        console.log(
          `${r.label.padEnd(45)} ${String(r.requests_per_sec).padStart(7)} req/s` +
            `  p50 ${r.latency_ms_p50}ms  p99 ${r.latency_ms_p99}ms` +
            `  ${r.throughput_mb_s} MB/s  non2xx=${r.non_2xx} errors=${r.errors}`
        );
      }
    }
  } finally {
    procs.forEach((p) => p.kill('SIGKILL'));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
