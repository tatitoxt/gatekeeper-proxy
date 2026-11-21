# Benchmarks

Throughput measured with [autocannon](https://github.com/mcollina/autocannon)
against the built proxy (`dist/`) and the synthetic demo upstreams, all on
`127.0.0.1` (loopback, single machine, Node.js single process).

**How to reproduce**

```sh
npm run bench            # build + 3 scenarios, human-readable output
npm run bench -- --json  # machine-readable results
BENCH_DURATION_S=30 BENCH_CONNECTIONS=200 npm run bench
```

**Setup used for the numbers below**

- autocannon: 50 connections × 10 s per scenario
- Benchmark config: same routing (round-robin over 2 upstreams) and WAF
  signatures as `gatekeeper.config.json`; rate limits raised to 1M/min so the
  limiter stays out of the measurement
- Machine: Linux VM, x86-64, Node 22, loopback only (no network stack effects)

**Results (2026-11-21)**

| Scenario | req/s | p50 | p99 | Throughput | non-2xx |
|---|---:|---:|---:|---:|---:|
| Upstream direct (no proxy) | 53,926 | 0 ms | 3 ms | 17.69 MB/s | 0 |
| Through Gatekeeper (routing + WAF) | 3,315 | 12 ms | 45 ms | 1.43 MB/s | 0 |
| Through Gatekeeper (SQLi payload → 403) | 33,145 | 1 ms | 11 ms | 8.68 MB/s | 331,438 |

**Reading the numbers**

- The proxy sustains ~3.3k req/s of full request/response forwarding with
  routing, load-balancing and WAF inspection on the hot path — about 6% of the
  raw upstream. That's the honest cost of a single-process Node proxy; it is
  the number to improve (keep-alive agent pooling, streaming bodies, worker
  processes).
- Blocked requests are ~10× cheaper: the WAF rejects the SQLi probe before any
  upstream connection is made, at ~33k req/s. Attack traffic is absorbed at the
  edge without spending upstream capacity.
- No tuning was applied; numbers are out-of-the-box and machine-dependent.
  They are reported as a reproducible baseline, not a marketing figure.
