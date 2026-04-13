# Benchmarks

Author: Romain G.

Criterion microbenchmarks live in each product crate's `benches/`
directory. They are the regression coverage for the v1.3.0 hot-path
work (PERF-12 from the performance audit) and should be run before
merging any change that touches the proxy hot path, the WAF
evaluator, the breaker, or the canary hashing.

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

## Not yet covered

The forward-auth verdict cache and the basic-auth credential cache
are exposed only as private internals on `LoricaProxy`. Adding a
`pub(crate)` accessor + a bench would close PERF-12 for those two
paths; tracked for v1.4.0.

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
