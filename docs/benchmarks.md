# Benchmarks

Author: Romain G.

Criterion microbenchmarks live in each product crate's `benches/`
directory. They are the regression coverage for the v1.3.0 hot-path
work (PERF-12 from the performance audit) and should be run before
merging any change that touches the proxy hot path, the WAF
evaluator, the breaker, or the canary hashing.

The e2e suite's performance phase, which compares streams with nginx
and the release with the previous one, is described in [Layer-4 parity
harness](#layer-4-parity-harness) below.

## Running

```bash
# All benches in a crate (release profile, full statistical run):
cargo bench -p lorica
cargo bench -p lorica-waf

# A single bench file:
cargo bench -p lorica --bench circuit_breaker

# A single bench function:
cargo bench -p lorica --bench circuit_breaker -- breaker/is_available

# Quick smoke (skip statistical convergence) for CI:
cargo bench -p lorica --bench canary_bucket -- --quick --noplot
```

HTML reports land under `target/criterion/<bench>/<function>/report/`.

## Coverage today

| Crate         | Bench file        | What it covers                                       |
| ------------- | ----------------- | ---------------------------------------------------- |
| `lorica`      | `circuit_breaker` | `is_available` (closed/unknown), `record_success`, `record_failure`, 4-thread mixed contention |
| `lorica`      | `canary_bucket`   | FNV-1a hashing (short / realistic v4 / realistic v6 / 256-IP batch) |
| `lorica-waf`  | `evaluate`        | Full default CRS ruleset against a clean short request, a noisy realistic request, and a SQLi-matching request |

## Reference numbers (Linux x86_64, idle host)

These are sanity-check baselines, not contractual. A regression that
pushes any of these by more than 2-3x is worth investigating.

| Bench                                            | Typical |
| ------------------------------------------------ | ------- |
| `canary_bucket/short_route_ipv4`                 | ~3 ns   |
| `canary_bucket/realistic_route_ipv4`             | ~15 ns  |
| `canary_bucket/256_ips`                          | ~1.7 us |
| `breaker/is_available/closed_hit`                | ~40 ns  |
| `breaker/record_failure/known_key`               | ~75 ns  |
| `breaker/mixed_4_threads/is_available_x_record_success` | ~220 ns |
| `waf_evaluate/clean_short`                       | ~4 us   |
| `waf_evaluate/noisy_realistic`                   | ~27 us  |
| `waf_evaluate/matches_sqli`                      | ~6 us   |

## Sustained load scenario (v1.3.0 WPAR worker parity)

Design `docs/architecture/worker-shared-state.md` § 12 calls for a
10k+ QPS sustained run against `--workers 4` to validate the cross-
worker rate-limit bound, shmem hashtable saturation, and the p99
overhead vs single-process baseline. The built-in `LoadTestEngine`
(exposed in the dashboard under **Tools -> Load Test** and in the
API as `POST /api/v1/load-tests/run`) runs this scenario without
any out-of-process tooling.

**Baseline (single-process)**:
- Start Lorica with `--workers 0` (or omit the flag).
- Route: `GET /`, 2 healthy backends, token-bucket `rate_limit:
  { capacity: 20, refill_per_sec: 100, scope: per_route }`, WAF on
  (default ruleset), no forward-auth.
- In the dashboard Load Test tab: `target_qps: 10_000`,
  `duration_s: 120`, `concurrency: 200`. Record p50 / p95 / p99,
  measured QPS, error count.

**Worker mode**:
- Same config, restart Lorica with `--workers 4`.
- Run the same load test profile.
- Assertions (documented design § 12 targets):
  - p99 latency within 10 % of single-process baseline.
  - Measured global QPS at the rate-limit: `capacity +
    (100 ms × N_workers × refill_per_sec / 1000)` = 20 + 40 = 60
    admissions per second above refill, not N_workers × full cap.
  - The `shmem hashtable saturated at probe limit` warn log
    (emitted from `lorica-shmem`) must not appear during the run.
    If it does, the hashtable size needs a bump in
    `lorica-shmem::region::SharedRegion` - currently 128 Ki slots
    per table with a 16-probe chain.
  - `lorica_supervisor_rpc_outcome_total{kind="config_reload_*",
    outcome="timeout"}` stays at 0 during the run.

The LoadTestEngine's CPU circuit breaker aborts the run if the test
itself saturates the host CPU - this is a feature, not a failure.
Re-run with a lower concurrency or distribute the client over
multiple hosts via `k6` / `wrk` against the same Lorica instance.

## Not yet covered

The forward-auth verdict cache and the basic-auth credential cache
are exposed only as private internals on `LoricaProxy`. Adding a
`pub(crate)` accessor + a bench would close PERF-12 for those two
paths ; no owner scheduled yet, reopen when someone needs the
numbers.

The request-capture engine (v1.8.0) has no bench either. It is the
one addition that buffers bytes on the request path, so the number
worth having is the cost on a route where a rule matches but nothing
is ever emitted: that is the case an operator pays for continuously,
and the one the design is built around. `docs/capture.md` describes
the caps that bound it.

## Adding a new bench

1. `<crate>/benches/<name>.rs` with `criterion_group!` + `criterion_main!`.
2. In `<crate>/Cargo.toml`:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "<name>"
harness = false
```

3. Run `cargo bench -p <crate> --bench <name>` to verify.

## Layer-4 parity harness

The performance phase of the e2e suite (`tests-e2e-docker/perf/`,
Story 12.12) measures streams against nginx `stream` and the release
against the previous one. It is separate from the Criterion benches
above, from the `bench/` directory and from `lorica-bench`, which is
Lorica's own SLA and load-test feature. What it gates on is a ratio
taken on one machine in one run, never an absolute number: the same
figures on other hardware move together, and a ratio is what the parity
claim and NFR1 are stated in. The thresholds are the acceptance criteria
of Story 12.12 in the [PRD](prd/epic-12-v1.11.0.md); `CHECKS` in
`perf/analyse.py` holds them, with which checks gate and which are only
reported, and every summary prints them beside the ratios.

### What runs against what

Compose project `lorica-e2e-perf` (`tests-e2e-docker/docker-compose.perf.yml`):

- **Three proxies on one cpuset**: Lorica as built from the tree, the
  released 1.10.7 binary (the signed `.deb`, verified with `gpgv` against
  the published key when the image is built), and nginx with its `stream`
  module. Each runs as many workers as the proxy cpuset has cores, and
  Lorica runs in worker mode, since its stream runtime has one thread
  per process. All three stay up; the load alternates between them, so
  no arm pays a warm-up the others do not.
- **The load generators and the backends on cpusets of their own**,
  disjoint from the proxies' and from each other.
- **An equivalent configuration.** nginx's is
  `tests-e2e-docker/perf/nginx-stream.conf`; Lorica's streams and route
  are created by the driver through the management API to match it: the
  same backends, timeouts and buffer size, a per-connection access log on
  both, no splice on either, TCP on one listening socket shared by the
  workers and UDP on one `SO_REUSEPORT` socket per worker, as each proxy
  binds them.

**Layouts.** `perf/run-perf.sh` derives the cpusets from the CPU count
Docker reports: a larger layout, a small one for machines with fewer
CPUs, and `NOT-RUN` below what the small one needs. `PERF_LAYOUT=small`
forces the small layout on a large machine, to rehearse what CI runs.
The local release run must get the larger layout; anything else makes
every gated verdict `INCONCLUSIVE (environment)`. CPUs beyond the layout
stay unassigned, so a larger machine gives the same layout and the same
ratios.

**Environment guard.** Before the first measurement the driver records
the CPU count, memory, kernel, Docker version, image ids, the commit and
whether the tree is clean, and the cpusets. Before every attempt it lists
the running containers outside its project: any one of them makes every
gated verdict `INCONCLUSIVE (environment)`.

### The measurements

- **TCP throughput and CPU per GiB**, upload and download as two series,
  with `iperf3` through a plain TCP stream. CPU is the proxy container's
  cgroup `cpu.stat` over the run, divided by the bytes forwarded. iperf3
  opens `IPERF_STREAMS_PER_WORKER` streams per proxy worker
  (`perf/run-perf.sh`): with a few streams, both proxies' shared
  listening socket often hands every connection to the worker that wakes
  first, and the series then measures which worker took the accepts, not
  the proxy. A multi-worker run in which one process still did more than
  `ONE_WORKER_SHARE` of the proxy's work (`perf/analyse.py`) is kept out
  of its series, with the reason in its record.
- **Connection setup**, `perf-tools/l4_connect_latency.py`: an open-loop
  client at a fixed rate through a non-TLS stream, and a backend stamping
  each `accept` on the same monotonic clock (the containers share one
  kernel), so the latency is the proxy's accept to backend connect. The
  backend closes first, so TIME_WAIT never lands on the proxy's
  ephemeral ports.
- **UDP hold**: at a session count of 80 % of Lorica's derived ceiling,
  read from the budget view, every session is kept alive for the run and
  must lose no echo and never be evicted (the backend counts distinct
  upstream peers, and an evicted session comes back on a new one). Every
  Lorica run must hold; an nginx run that does not makes the measurement
  inconclusive, since the harness is then wrong, not Lorica. The memory
  per 1,000 sessions is the PSS of the Lorica container's processes
  (`smaps_rollup`, so the shared-memory region is not counted once per
  worker), reported, not gated.
- **NFR1**, three arms: **B**, 1.10.7; **L0**, the release with no
  stream; **L1**, the release with one idle TCP stream bound. `oha`
  measures requests per second closed loop, then the p99 at a fixed rate
  of half B's saturation throughput, with coordinated-omission
  correction. Plain HTTP gates; HTTPS is reported only, because the
  release binary and the e2e build compile the crypto library with
  different C compilers.

### Statistics and verdicts

Each measurement runs one discarded warm-up per arm, then repetitions in
which the arms alternate and the first arm rotates.

**Throughput, CPU per GiB, requests per second: the spread rule.** At
least `MIN_REPS` repetitions per arm (`perf/analyse.py`). A series'
spread is its interquartile range over its median, robust to one outlier
run as max minus min is not. A check is conclusive when every series it
compares has a spread of at most `MAX_SPREAD`, and its ratio is median
over median. An inconclusive measurement is run again whole, at most
`PERF_MAX_RERUNS` times (`perf/run-perf.sh`), and judged on its first
conclusive attempt; every attempt is in the report.

**p99 checks (connection setup, NFR1 p99): pooled samples and a
bootstrap interval.** In the first dry run, series of per-run p99s had
spreads of up to a quarter of their median while the p50s of the same
runs held within a few percent, so a p99 series met the spread rule
rarely and by luck, and re-running until it did was a lottery. Instead:

- every latency of every run is kept (`results/perf-<ts>.samples/`), and
  an attempt is complete with `P99_RUNS` runs per arm;
- an arm's runs are pooled, its p99 is the nearest-rank 99th percentile
  of the pool, and the ratio is pooled p99 over pooled p99;
- a `BOOTSTRAP_LEVEL` percentile bootstrap interval brackets the ratio:
  each of `BOOTSTRAP_RESAMPLES` resamples draws whole runs with
  replacement within each arm, independently, so the variation from run
  to run stays in the interval. The seed is `PERF_BOOTSTRAP_SEED`
  (default `DEFAULT_SEED`), recorded in the report, so a report
  recomputes to the same interval;
- `PASS` when the whole interval is within the threshold, `FAIL` when
  the whole interval is beyond it, `INCONCLUSIVE` when it straddles it.
  A complete attempt is not re-run for an inconclusive interval, which
  would bring the lottery back; an incomplete one is re-run as above.

**Verdicts.** `PASS`; `FAIL`, conclusive and over a threshold;
`INCONCLUSIVE`, still unsettled after the re-runs, or the environment
guard; `NOT-RUN`, too few CPUs or a measurement left out; `REPORTED`,
a check that gates nothing. **Inconclusive is not a pass**: on the local
release run it blocks the release until the owner decides, and the
decision is recorded in Story 12.12 before the release pull request.

**Output**, under `tests-e2e-docker/results/`: `perf-<ts>.runs.jsonl`
(every run as it lands, with its raw numbers and the environment record),
`perf-<ts>.samples/`, `perf-<ts>.json` and `perf-summary.md` (one row per
check: values, spreads or intervals, ratio, threshold, attempts,
verdict). The analysis is `perf/analyse.py`, standard library only, run
inside the `perf-tools` container, so the host needs no Python;
`perf/test_analyse.py` covers it.

### Running it locally

The phase needs the machine to itself, like the rest of the e2e suite:
another container makes its verdicts inconclusive by design, and a
concurrent build or test run moves the ratios without the guard seeing
it.

1. Nothing else on Docker: `docker ps -a` empty, or every leftover
   project torn down with `down -v --remove-orphans` (the suite's are
   the main compose file's, `lorica-e2e-l4` and `lorica-e2e-perf`). No
   cargo build, no other test suite, heavy applications closed.
2. Every `.sh` under `tests-e2e-docker/` has LF line endings: a script a
   tool wrote can keep CRLF, and bash in the images fails on it.
3. From `tests-e2e-docker/`:

```bash
# The release run: every phase, every gate, the larger layout required.
./run.sh --build

# The performance phase alone, gated.
./run.sh --only-perf --build

# What CI runs: the small layout, verdicts reported, exit 0 on any verdict.
PERF_LAYOUT=small ./run.sh --only-perf --perf-advisory --build
```

`--only-perf` skips every other phase; `--skip-perf` runs the rest of
the suite without it and is never used for the release run.
`PERF_MEASUREMENTS` runs a subset (a measurement left out reports
`NOT-RUN`, which gates), and `PERF_REPS`, `PERF_P99_REPS` and
`PERF_MAX_RERUNS` change the repetitions within the floors the
statistics need; the header of `perf/run-perf.sh` lists every knob. On
the larger layout without re-runs, expect the phase to take over an
hour.

### What CI runs

The e2e suite is three jobs of `.github/workflows/ci.yml`, on pull
requests to `main` and on pushes of `main` and of tags:

- **E2E (Docker)**, the pre-existing profiles with their stream
  sections, and **E2E (L4)**, the L4 phase ([Parity
  verification](streams.md#parity-verification) in `docs/streams.md`).
  Both gate the release, and **E2E scenario report** then checks their
  two logs together, so that every scenario of the registry reported.
- **E2E (performance)**, this phase with `--perf-advisory`, never gating:
  a shared runner is too noisy for these ratios. It takes the small
  layout of the hosted runner, writes `perf-summary.md` to the job
  summary, and uploads `results/` as an artifact. The release waits for
  it, so its numbers are published in the run that released, and a
  failure or a timeout of the job does not hold the release.

The gate on performance is the local release run.
