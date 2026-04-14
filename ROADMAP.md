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

Production observability and operational tooling. Delivery order: OpenTelemetry
first (instrumentation is reused by the two other epics), then GeoIP, then bot
protection.

### v1.4.0 - OpenTelemetry tracing (OTLP)

Distributed tracing via OTLP so Lorica slots into an existing Jaeger / Tempo /
Datadog backend. Shipped as an **off-by-default Cargo feature (`otel`)**, same
policy as `route53` since the v1.3.0 supply-chain audit (SC-M-3) so non-users
do not pay the dep-graph cost.

| Story | Status | Effort | Notes |
|---|---|---|---|
| 1.1 Feature-gated OTLP deps | Planned | 0.5 d | `opentelemetry`, `opentelemetry-otlp`, `opentelemetry_sdk`, `tracing-opentelemetry`. Feature `otel` on `lorica`, off by default. `.deb` / `.rpm` build scripts stay on default features |
| 1.2 Global config + migration | Planned | 0.5 d | New fields on `GlobalSettings`: `otlp_endpoint` (String), `otlp_protocol` (grpc/http-proto/http-json enum), `otlp_service_name` (String, default "lorica"), `sampling_ratio` (f64 in 0.0..=1.0, default 0.1). Schema migration V34. Dashboard **Settings > Observability** section with "Test connection" button |
| 1.3 W3C context propagation | Planned | 1 d | Parse incoming `traceparent` / `tracestate` in `request_filter`, inject outgoing headers in `upstream_request_filter` so the backend span chains under Lorica's. Fallback: if no incoming `traceparent`, generate a span deterministically tied to the existing `X-Request-Id` |
| 1.4 Request-level root spans | Planned | 1 d | `#[instrument]` on the main request path with child spans for `waf.eval`, `forward_auth`, `mtls.verify`, `cache.lookup`, `upstream.connect`, `upstream.response`. Attributes follow OTel HTTP semconv (`http.request.method`, `url.path`, `http.response.status_code`, `server.address`, `network.peer.address`). Route ID added under `lorica.route_id` for consistency with Prometheus labels |
| 1.5 Log <-> trace correlation | Planned | 0.5 d | `tracing-subscriber` layer injects `trace_id` + `span_id` into the existing JSON log records so operators can jump from a log line to the Jaeger trace. No new log fields in text mode (stays readable) |
| 1.6 Graceful shutdown | Planned | 0.5 d | Flush OTLP batch processor on SIGTERM before the 10 s worker drain so no in-flight spans are lost on restart. Integrates with the existing drain hook in the worker supervisor |
| 1.7 Benchmark + bypass when disabled | Planned | 0.5 d | Bench with `lorica-bench` comparing `--features otel` enabled-vs-disabled at sampling 0.0, 0.1, 1.0 to confirm overhead is under 2 % at 0.1 (matches Tempo / Grafana guidance). Doc the numbers in the release notes |
| 1.8 E2E tests + TESTING-GUIDE | Planned | 1 d | `tests-e2e-docker/` compose variant with Jaeger + Lorica built with `--features otel`; curl a traced request, assert span tree visible via Jaeger API. Add "How to trace a request" section to TESTING-GUIDE |

**Total effort:** ~5.5 d. **Risk:** overhead at sampling 1.0 is backend-bound (Jaeger batch size), not proxy-bound; the default 0.1 keeps steady-state cost negligible.

### v1.4.0 - GeoIP country blocking

Per-route country allow / deny using **DB-IP Lite Country** (CC-BY 4.0, no
account required, monthly updates, `.mmdb` format). Crate `maxminddb` reads
the file, same API as the paid MaxMind GeoLite2 so operators who already have
their own license can swap the DB path. Placement in the pipeline: after
connection pre-filter + IP blocklist, before WAF.

| Story | Status | Effort | Notes |
|---|---|---|---|
| 2.1 `lorica-geoip` crate | Planned | 1 d | New crate wrapping `maxminddb`. `IpAddr -> Option<CountryCode>` lookup, `ArcSwap<maxminddb::Reader>` for hot-reload. Unit tests against a checked-in sample `.mmdb` slice (IPv4 + IPv6 + RFC 1918 return `None`) |
| 2.2 Config (global + per-route) | Planned | 0.5 d | `GlobalSettings.geoip_db_path` (String, optional, default None -> feature disabled), `GlobalSettings.geoip_auto_update_enabled` (bool, default true). Per route: `geoip: Option<GeoIpConfig { mode: Allowlist \| Denylist, countries: Vec<String> }>` where `countries` are ISO 3166-1 alpha-2 codes validated at API boundary. Schema migration V35 |
| 2.3 Auto-update job | Planned | 1 d | Weekly tokio task `GET https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz`, gunzip to temp, sanity-check (size > 1 MiB, lookup 8.8.8.8 returns "US"), atomic rename + ArcSwap publish. Retry on failure with exponential backoff. Fails soft: keep serving with the old DB if the download fails. Attribution comment in the download path per CC-BY 4.0 |
| 2.4 Request-filter wiring | Planned | 0.5 d | After `ip_blocklist` / `ip_allowlist`, before `waf_eval`. Deny returns 403 with the Cloudflare-style error template (reuse default from v1.3.0). Allowlist-with-no-match returns the same 403. Unknown country (reserved range, VPN exit, private IP) bypasses the rule and falls through rather than fail-close |
| 2.5 Metrics + OTel attribute | Planned | 0.5 d | Prometheus: `lorica_geoip_block_total{route_id, country, mode}`. OTel: `client.geo.country_iso_code` attribute on the root span (always populated when the DB is loaded, regardless of per-route rules, since useful for log correlation). Cardinality bounded at ~240 countries * route count |
| 2.6 Dashboard tab | Planned | 1 d | New **GeoIP** tab under the route Protection group. Mode dropdown (allowlist / denylist), country multi-select with flag emoji, ISO code validation at save. Global DB status widget in Settings (path, last update, N countries indexed) |
| 2.7 E2E tests + TESTING-GUIDE | Planned | 0.5 d | curl with `--interface` to fake source IPs in different ranges (requires the test harness to inject `X-Forwarded-For` in `trusted_cidrs` mode). Add "Block a country in 30 seconds" section to TESTING-GUIDE |

**Total effort:** ~5 d. **Risk:** DB-IP download URL stability; mitigated by
the fail-soft policy and the option for operators to override the update URL
via `GlobalSettings.geoip_update_url`. **Open item:** confirm CC-BY 4.0
attribution requirement is met by crediting in `NOTICE` + docs rather than on
every 403 page.

### v1.4.0 - Bot protection (antibot challenges)

Three self-hosted challenge modes, **no third-party dependency**: cookie, JS
proof-of-work, image captcha. Graded-intrusion model (same idea as BunkerWeb:
operator picks the friction level). Evaluated after GeoIP, before forward_auth.
Verdict state reuses the WPAR-2 `VerdictCacheEngine::Rpc` plumbing that
shipped in v1.3.0 so a challenge solved on one worker is honored across the
pool.

| Story | Status | Effort | Notes |
|---|---|---|---|
| 3.1 Design doc + threat model | Planned | 1 d | Document in `docs/architecture/bot-protection.md`: 3 modes, cookie format (HMAC-SHA256 over `{route_id, client_ip_prefix /24 for v4 + /64 for v6, expires_at}`), PoW algorithm (SHA-256 with N leading zero bits, N configurable 14-22), captcha alphabet defaults, bypass-rule precedence. Rotate HMAC secret on each cert renewal to cap forged-cookie lifetime |
| 3.2 `lorica-challenge` crate | Planned | 2 d | New crate. `generate_pow_challenge()`, `verify_pow(nonce, solution)`, `generate_captcha_image() -> (text, png_bytes)` (crate `captcha = "0.0.9"` pure Rust, ~2 KiB per image), cookie sign/verify with constant-time compare. Unit tests at each public boundary |
| 3.3 Config model + migration | Planned | 0.5 d | Per route: `bot_protection: Option<BotProtectionConfig>` with fields `mode` (None / Cookie / Javascript / Captcha), `cookie_ttl_s` (u32, default 86400, max 604800), `pow_difficulty` (u8 in 14..=22, default 18), `captcha_alphabet` (String, default "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", excludes confusables `0/O`, `1/l/I`), `bypass` (BypassRules struct: `ip_cidrs`, `asns`, `countries`, `user_agents` regexes, `rdns` suffixes), `only_country` (Option<Vec<String>> ISO codes, if set the challenge fires *only* for those countries - inverse of country bypass). Schema migration V36 |
| 3.4 Challenge response rendering | Planned | 1 d | Inline HTML page (no external asset) with the PoW worker as embedded JS using `crypto.subtle.digest`, or the captcha `<img>` served from a one-shot URL signed with the cookie nonce. Plain-text fallback if `Accept: text/html` is missing (403 with hint). `noscript` block explains how to contact the operator |
| 3.5 Request-filter wiring | Planned | 1.5 d | Evaluate bypass rules first (each is an early-exit to the backend). Then: if valid verdict cookie -> pass. Else if `only_country` gate misses -> pass. Else serve challenge page (mode-specific). On POST of solution, verify -> set verdict cookie -> 302 to the original URL. rDNS bypass uses a cached reverse lookup (TTL 1h) with forward confirmation to prevent PTR spoofing (same guard as standard rDNS whitelisting) |
| 3.6 Verdict cache cross-worker | Planned | 0.5 d | Reuse `VerdictCacheEngine::Rpc` from WPAR-2. Key = `{route_id}\0{client_ip_prefix}\0{cookie_hmac}`. Single-process mode uses the same in-process cache as forward_auth. No new RPC endpoint |
| 3.7 Metrics + OTel | Planned | 0.5 d | `lorica_bot_challenge_total{route_id, mode, outcome}` where outcome is `shown` / `passed` / `failed` / `bypassed`. OTel span `bot_protection.challenge` with attributes `mode`, `outcome`, `bypass_reason` if applicable |
| 3.8 Dashboard tab | Planned | 1.5 d | New **Bot Protection** tab under Protection. Mode dropdown (Off / Cookie / Javascript / Captcha), difficulty slider for JS mode (14-22 bits with live "expected solve time" estimate: ~50 ms at 14, ~2 s at 20), captcha alphabet editor, bypass rules editor (5 sub-sections matching the 5 bypass categories), only-country multi-select with flag emoji |
| 3.9 E2E tests | Planned | 1 d | `curl` without cookie (expect 200 with HTML challenge), solve PoW manually in test helper, POST solution (expect 302 + cookie), repeat request (expect passthrough). Captcha test exercises the image endpoint and cookie-nonce binding. Bypass matrix tested per category |
| 3.10 TESTING-GUIDE section | Planned | 0.5 d | "Enable bot protection in 1 minute" walkthrough; matrix of the 3 modes with concrete shell commands |

**Total effort:** ~10 d. **Risk:** (a) captcha UX on mobile when alphabet
contains case-sensitive chars; mitigated by the default alphabet. (b) PoW is
not a strong barrier against a headless Chrome farm; the mitigation is the
graded model (operator escalates to captcha if JS PoW stops working). (c)
verdict cookie leak on shared NAT; mitigated by the `/24` (v4) or `/64` (v6)
IP prefix bound in the HMAC, which scopes the cookie to the NAT gateway
rather than a single client and caps replay scope.

**v1.4.0 total effort (sum of all three epics):** ~20.5 d of engineering.
Target date for release branch cut: after Epic 1 ships standalone (weeks
1-2), Epic 2 lands on main (week 3), Epic 3 lands on main (weeks 4-6).

---

## v2.0.0 - Protocol expansion

Major protocol additions.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| TCP/L4 proxying | Planned | High | Stream proxy for databases, MQTT, SSH. SNI-based routing without TLS termination. Supported by Nginx, Traefik, HAProxy, Sozu |
| HTTP/3 (QUIC) | Planned | High | Blocked on [Pingora PR #524](https://github.com/cloudflare/pingora/pull/524) (tokio-quiche integration). Traefik and HAProxy have production support |

---

Author: Romain G.
