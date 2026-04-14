# Roadmap

> Last updated: 2026-04-14 | Current release: v1.3.0 | In progress: v1.4.0
>
> See [COMPARISON.md](COMPARISON.md) for the full competitive feature matrix.
>
> **Status:** Planned | In Progress | Done

---

## v1.2.0 - Proxy hardening & quick wins

Leverage existing Pingora framework hooks and add table-stakes features.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| Cache lock (thundering herd protection) | Done | Very Low | Enable `CacheLock` in proxy_wiring.rs. Prevents stampede on cache miss |
| Stale-while-error | Done | Low | Implement `should_serve_stale()` hook. Serve cached content when upstream fails |
| Custom error pages + maintenance mode | Done | Low | Implement `fail_to_proxy()` hook. Route state: active/maintenance/disabled. Branded HTML for 502/503/504/429 |
| Basic auth per route | Done | Low | HTTP Basic Auth for staging, internal tools. Standard across all competitors |
| Retry policy (enriched) | Done | Low | Extend `retry_attempts` with `retry_on` (status codes), `retry_methods`, `retry_backoff_ms`. Implement `fail_to_connect()` hook for smarter retry decisions |
| Structured JSON logs (file/syslog) | Done | Low | Implement `request_summary()` hook. Configurable log output to file/stdout/syslog. ELK/Loki/Datadog integration |
| Least Connections LB | Done | Low | Stub exists in lorica-lb (`// TODO: least conn`). Standard algorithm |
| gRPC-Web module | Done | Low | Module exists in `lorica-core/src/modules/http/grpc_web.rs`, never instantiated. Browser-compatible gRPC |
| HTTP Range requests | Done | Low | Enable `range_header_filter()`. Default implementation exists in `proxy_cache::range_filter` |
| Cache purge via PURGE method | Done | Low | Implement `is_purge()` hook. Currently purge is API-only |
| OCSP stapling | Done | Low | Standard TLS feature. Supported by Nginx, Caddy, HAProxy, BunkerWeb |
| Docker image | Done | Low | Official Docker image. All competitors provide one |

---

## v1.3.0 - Authentication & advanced routing

Major feature additions that close the gap with Traefik and Nginx.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| Forward auth (external authentication) | Done | Medium | Sub-request to auth service (Authelia, Authentik, Keycloak). Subrequest pipe exists in `lorica-proxy/src/subrequest/`. Enable `allow_spawning_subrequest()` + `early_request_filter()` |
| Header-based routing | Done | Low-Medium | Route by HTTP headers (X-Version, X-Tenant). A/B testing, multi-tenant. Traefik, Caddy, HAProxy all support it |
| Canary / traffic split | Done | Medium | Route X% traffic to backend group A, Y% to group B. Zero-risk deployments |
| mTLS client verification | Done | Medium | `ClientCertVerifier` trait support exists in rustls layer. Zero-trust, B2B |
| Response body rewriting | Done | Medium | Implement `response_body_filter()` hook. Nginx `sub_filter` equivalent |
| Request mirroring | Done | Medium | Duplicate traffic to secondary backend (fire-and-forget). Shadow testing |
| Cache Vary support | Done | Medium | Implement `cache_vary_filter()`. `VarianceBuilder` exists in `lorica-cache/src/variance.rs` |
| Stale-while-revalidate | Done | Low | `stale_writer` support exists in cache lock module. Serve stale while background refresh |
| Cache predictor | Done | Medium | `lorica-cache/src/predictor.rs` exists. Learn which assets are cacheable |
| Connection pre-filter | Done | Low | Replace `AcceptAllFilter` with configurable filter. IP-level filtering before TLS handshake |

### v1.3.0 - Worker-parity audit (WPAR)

Cross-worker shared-state rewrite so `--workers N` behaves like
`--workers 0` instead of amplifying per-worker state by `N`. Design
and rationale in [`docs/architecture/worker-shared-state.md`](docs/architecture/worker-shared-state.md).

| Feature | Status | Effort | Notes |
|---|---|---|---|
| Pipelined RPC framework (`lorica-command`) | Done | 2 d | Sequence-multiplexed in-flight map, bounded outbound queue, per-request timeout. `RpcEndpoint::Inner::drop` explicitly aborts reader + writer (audit fix) |
| `lorica-shmem` crate (memfd + atomic hashtable) | Done | 4 d | Anonymous `memfd_create`, `mmap(MAP_SHARED)`, open-addressing hashtable with SipHash-1-3 + 128-bit randomized key (anti HashDoS). Cross-process atomic counters for WAF flood / auto-ban |
| WPAR-1 per-route token-bucket rate limit | Done | 3 d | Worker-side `LocalBucket` CAS cache syncs every 100 ms with supervisor's authoritative `AuthoritativeBucket`. Aggregate admission bound: `capacity + 100 ms * N_workers * refill_per_sec`. Per-IP bucket eviction at 5 min idle |
| WPAR-1 WAF auto-ban via shmem | Done | - | Per-IP violation counter lives in the shmem hashtable; supervisor is the sole ban issuer on threshold crossing |
| WPAR-2 forward-auth verdict cache RPC | Done | 1 d | `VerdictCacheEngine::{Local, Rpc}`; worker mode routes lookup/push to a supervisor-owned cache with FIFO eviction (16 Ki entries). Allow verdicts carry `response_headers` on the wire so hits skip the auth upstream round trip |
| WPAR-3 circuit breaker RPC | Done | 1 d | `BreakerEngine::{Local, Rpc}` with tri-state `BreakerAdmission::{Allow, Probe, Deny}`. Supervisor owns the state machine; probe slots allocated atomically across workers. Stale-probe detection (audit H-1) prevents deadlock on crashed probe worker |
| WPAR-7 `/metrics` pull-on-scrape | Done | 0.5 d | Prometheus scrape triggers a 500 ms fan-out to every worker; concurrent scrapes dedup via a 250 ms `Instant` lock; non-responders fall back to cached state |
| WPAR-8 two-phase config reload | Done | 1 d | `ConfigReloadPrepare` (2 s timeout, slow: SQLite read + ProxyConfig build) + `ConfigReloadCommit` (500 ms timeout, fast: single ArcSwap). Cross-worker divergence window collapses from ~10-50 ms down to the UDS RTT. `ConfigReloadAbort` RPC drops orphan pending configs on partial failure |
| WPAR multi-worker integration tests | Done | 1.5 d | Per-phase RPC round-trip Rust tests (verdict, breaker, metrics pull, config reload) + 76 / 76 E2E Docker tests in `--workers 2` mode covering sections 1-19c |

Bonus bug found during audit + fixed in v1.3.0: `RpcEndpoint::Inner::drop`
was detach-on-drop (tokio `JoinHandle` default), which kept the reader's
`tx_out` clone alive, which kept the writer task and socket halves
alive, which blocked peer EOF, which hung worker shutdown on the 10 s
`TaskTracker` drain. Now `drop` explicitly calls `handle.abort()` on
both tasks.

### v1.3.0 - audit supply-chain + coverage follow-ups (landed)

The audit round-2 pass identified 7 residual items beyond the
original 3 High + 8 Medium + 8 Low findings (tech debt + supply-
chain hygiene + CI coverage). 6 of them landed in the v1.3.0
release; the last is tracked below in "deferred to v1.3.1".

| Item | Source | Resolution |
|---|---|---|
| `route53` feature off-by-default | Audit SC-M-3 | `lorica-api/Cargo.toml` default flipped to `default = []`. Non-Route53 deployments no longer ship `rustls 0.21 + hyper 0.14`. Enable with `--features route53` when building |
| `brotli 3 -> 8` | Audit SC-L-1 | Bumped `lorica-core/Cargo.toml` to `brotli = "8"`. API source-compatible for our `CompressorWriter` / `DecompressorWriter` usage; no behaviour change |
| `no_debug 3.1.0` inline | Audit SC-L-3 | Inlined as `lorica-tls::no_debug` module (~130 LOC incl. 5 tests). `pub use crate::no_debug::{...}` keeps every downstream `use lorica_tls::NoDebug` working unchanged |
| `daemonize 0.5.0` replacement | RUSTSEC-2025-0069 | Dropped the dep. Production Lorica runs under `systemd Type=simple`; legacy `--daemon` flag now emits a warning and falls through to foreground. Re-implementation plan documented in `lorica-core/src/server/daemon.rs` |
| `eslint-plugin-svelte` in CI | Audit coverage gap | New `eslint.config.js` flat config under `lorica-dashboard/frontend/` enforcing `svelte/no-at-html-tags` + `svelte/no-target-blank` + `no-eval` / `no-implied-eval` family. Wired into the `Lint` CI job as `npm run check` + `npm run lint` |
| `trailofbits/semgrep-rules` in CI | Audit coverage gap | New `Semgrep (security)` CI job running 7 `p/*` rulesets + 4 trailofbits subfolders (`generic` / `javascript` / `rs` / `yaml`). Non-blocking (continue-on-error: true); SARIF uploaded as PR artifact. Gating after the noise floor stabilises |

### v1.3.0 - M-8 refactor landed

| Item | Source | Resolution |
|---|---|---|
| Split `proxy_wiring.rs` (8 Ki LOC) | Audit M-8 | Done. Tests block (~3 k LOC) moved to `lorica/src/proxy_wiring/tests.rs`; BreakerAdmission / BreakerEngine / VerdictCacheEngine / RateLimitEngine moved to `lorica/src/proxy_wiring/engines.rs` (246 LOC). `proxy_wiring.rs` now 5 284 LOC (-38 % vs pre-split). `pub use engines::{...}` re-export keeps the `lorica::proxy_wiring::*` import path working unchanged |

---

## v1.4.0 - Observability & operations

Production observability and operational tooling.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| OpenTelemetry tracing | Planned | Medium | OTLP export for distributed tracing. Traefik, HAProxy, Sozu support it |
| Country blocking (GeoIP) | Planned | Medium | Filter by country code. Useful for compliance and attack surface reduction |
| Bot detection (JS challenge) | Planned | Medium-High | JavaScript challenge / captcha before proxying. BunkerWeb differentiator |

---

## v2.0.0 - Protocol expansion

Major protocol additions.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| TCP/L4 proxying | Planned | High | Stream proxy for databases, MQTT, SSH. SNI-based routing without TLS termination. Supported by Nginx, Traefik, HAProxy, Sozu |
| HTTP/3 (QUIC) | Planned | High | Blocked on [Pingora PR #524](https://github.com/cloudflare/pingora/pull/524) (tokio-quiche integration). Traefik and HAProxy have production support |

---

Author: Romain G.
