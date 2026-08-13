# Source Tree

Crate-responsibility map for the Lorica workspace. This document
deliberately stops at crate / top-level-module granularity: per-file
enumerations drift on every release (the v1.0 version of this file
was flagged stale by two audits). For the exact current layout,
`ls <crate>/src/` is authoritative; `docs/BUMP-CHECKLIST.md` lists
every file that pins the product version; `CHANGELOG.md` records
architectural moves per release.

## Product crates (follow the product version)

| Crate | Responsibility |
|-------|----------------|
| `lorica` | The binary. `main.rs` is ~70 LOC of dispatch; `cli.rs` holds the clap surface + rotate-key / unban subcommands; `startup/` holds the three run modes (`supervisor.rs`, `worker.rs`, `single.rs`) plus the shared background-task helpers (`mod.rs`, audit H-9: one source of truth per spawn cluster); `proxy_wiring.rs` + `proxy_wiring/` hold the data plane (see below); `health.rs` the prober; `reload.rs` config/cert hot-reload; `bot.rs`/`bot_rdns.rs` bot-protection stash + rDNS; `connection_filter.rs`, `geoip.rs`, `mtls.rs`, `otel.rs` what their names say. |
| `lorica-config` | SQLite `ConfigStore` (per-entity submodules under `src/store/`, migrations under `src/migrations/`), config models, encryption-at-rest helpers. Sole DB access point for configuration. |
| `lorica-api` | Management plane: axum router + `AppState` (`server.rs`), per-domain handler modules, `middleware/` (sessions, rate limit), `acme/` (issuance / renewal handlers, challenge store, pending manual-DNS state - the pure protocol core lives in `lorica-acme`), `db.rs` (blocking-pool store access, audit H-3), `log_store.rs` + `log_writer.rs` (persistent access/WAF logs + batched background writer, backlog #24), `metrics.rs` (data-plane counters + `/metrics` handler, built on `lorica-metrics`). |
| `lorica-acme` | Pure ACME / Let's Encrypt core, extracted from `lorica-api` in v1.6.0 (backlog #42a): the `instant-acme` protocol driver (HTTP-01, automated + manual DNS-01), CSR generation, its own `AcmeError`, and the DNS-01 provider challengers (Cloudflare, OVH, Route53 behind the `route53` feature). No dependency on the management API. |
| `lorica-metrics` | Shared Prometheus registry + type-safe registration helpers + cross-worker counter aggregation, extracted from `lorica-api` in v1.6.0 to break the `lorica-api -> lorica-bench` / `lorica-notify` cycle. Re-exports `prometheus` so consumers never depend on it directly. |
| `lorica-waf` | WAF engine: rule set, evaluation (`engine/`), IP blocklist, event types. |
| `lorica-notify` | Alert events + notification channels (stdout, email, webhook, slack). |
| `lorica-bench` | Passive SLA collection, active probes, load-test engine + scheduler. |
| `lorica-dashboard` | Svelte 5 frontend (`frontend/`) embedded into the binary via `build.rs` + rust-embed; serves the SPA and the CSP header. |
| `lorica-challenge` | Bot challenges: PoW + image captcha generation, verdict cookie HMAC. |
| `lorica-geoip` | GeoIP / ASN MMDB resolvers with hot-swappable process-wide handles. |
| `lorica-shmem` | Cross-worker shared-memory region (WAF auto-ban counters, rate-limit buckets). |

## `lorica/src/proxy_wiring/` (data plane, backlog #7 layout)

| Module | Responsibility |
|--------|----------------|
| `proxy_wiring.rs` (root) | `LoricaProxy` struct, spawn helpers, cache statics, the `ProxyHttp` trait impl (request_filter orchestration, upstream_peer, response filters, logging), public re-exports. |
| `config.rs` | `ProxyConfig` / `RouteEntry` / smooth-WRR state, route-table construction, `find_route`. |
| `filters.rs` | The request_filter stage methods (`check_*`, audit H-8) + `write_error_response` (audit H-10) + WAF event persistence hand-off. |
| `lb.rs` | Peak-EWMA tracker, per-(route, backend) circuit breaker. |
| `context.rs` | Per-request `RequestCtx`. |
| `worker_rpc.rs` | Worker-side RPC: two-phase config reload, metrics report. |
| `engines.rs` | Mode-switching engines (local vs supervisor-RPC: rate limit, verdict cache, breaker). |
| `helpers.rs`, `error_pages.rs`, `forward_auth.rs`, `mirror_rewrite.rs`, `bot_handlers.rs` | Shared pure helpers, error-page rendering, forward-auth client, request mirroring + response rewriting, bot solve/captcha handlers. |
| `tests.rs`, `cert_reload_commit_tests.rs` | Unit + regression tests for the above. |

## Forked crates (Pingora forks, pinned at 0.1.0)

`lorica-core`, `lorica-proxy`, `lorica-http`, `lorica-error`,
`lorica-tls`, `lorica-lb`, `lorica-cache`, `lorica-memory-cache`,
`lorica-lru`, `lorica-ketama`, `lorica-limits`, `lorica-timeout`,
`lorica-pool`, `lorica-runtime`, `lorica-header-serde`, `tinyufo`
preserve upstream Pingora structure to stay rebaseable. `lorica-tls`
additionally carries the native cert resolver + OCSP stapling;
`lorica-worker`, `lorica-command` are first-party process/IPC crates
that live at 0.1.0 alongside the forks (see backlog #42d for the
version-tier cleanup).

## Tests

Test files mirror the source tree: unit tests live in
`#[cfg(test)]` modules beside the code (or sibling `*_tests.rs`
files for large regression suites), integration tests in each
crate's `tests/`, end-to-end Docker suites in `tests-e2e-docker/`,
frontend tests beside their components (`Foo.svelte` /
`Foo.test.ts`). A new test goes in the same directory layout as the
code under test.

## Packaging

`dist/` holds the `.deb` build script (`build-deb.sh`), the RPM spec
(`rpm/lorica.spec`), and the hardened systemd unit
(`lorica.service`). `Dockerfile` (release) and `Dockerfile.dev`
must list every workspace member; a missing `COPY` breaks
`cargo build --workspace` in Docker.
