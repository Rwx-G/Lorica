# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Author: Rwx-G

## [1.3.0] - 2026-04-14

### Fixed (pre-release audit: 3 High + 7 Medium + 5 Low)

- `SupervisorBreakerRegistry` stale-probe deadlock (audit H-1): if the
  probe-admitted worker crashed between admit and report, the breaker
  entry was pinned in `HalfOpen { probe_in_flight: true }` forever and
  every subsequent query for that `(route, backend)` returned Deny until
  supervisor restart. `HalfOpen` now carries `probe_started_at:
  Option<Instant>`; on the next query observing `elapsed >= cooldown`
  the supervisor synthesises a failed probe, bumps the failure counter,
  transitions back to Open with a fresh cooldown, and emits a warn log.
  Regression test `breaker_registry_stale_probe_recovers_after_cooldown`
- `lorica-worker::fd_passing::recv_worker_fds` kernel-FD leak on error
  paths (audit H-2): the function collected raw `RawFd`s into a `Vec`
  and returned `Err(...)` on UTF-8 validation / fds-tokens mismatch /
  bad `FdKind` token without closing them. Received FDs are now wrapped
  in `OwnedFd` immediately after `recvmsg` so every error path
  `close(2)`s via the RAII drop. Added `MSG_TRUNC` / `MSG_CTRUNC`
  detection so silent kernel truncation returns `InvalidPayload`
  instead of adopting a half-received FD set. Added a compile-time
  size assertion on `PAYLOAD_BUF_SIZE`
- Two-phase config reload non-atomic `connection_filter` publish (audit
  H-3): `PendingProxyConfig` now carries the full `reload::PreparedReload`
  rather than only `Arc<ProxyConfig>`, so the Commit handler calls
  `commit_prepared_reload(proxy_config, filter, prepared)` which
  publishes the ArcSwap and the filter CIDR reload together. Prior
  code re-read the filter separately, opening a short window where
  ProxyConfig v2 ran against filter v1 on reloads that flipped
  `connection_allow_cidrs` / `connection_deny_cidrs`. The worker-side
  RPC listener is now wired with `Some(connection_filter)` at the
  call site (was `None`)
- `EwmaTracker::record` hot-path allocation (audit M-1): the common
  case (backend already known) no longer pays for an `addr.to_string()`
  per request. `get_mut` path + first-sample seeding without the 30 %
  alpha bias
- TOCTOU in `SupervisorVerdictCache::lookup` + `FORWARD_AUTH_VERDICT_
  CACHE` expiry eviction (audit M-2 + M-3): a concurrent fresh insert
  racing with an expiry observation could be evicted by the stale
  lookup. Replaced with `dashmap::DashMap::remove_if` that evicts
  only when the entry's `expires_at` still matches the observation
- `handle_rate_limit_delta` mutex contention on first-seen keys (audit
  M-4): N concurrent `RateLimitDelta` RPCs on a first-seen
  `{route|scope}` previously serialised on the `store` tokio::Mutex for
  N SQLite reads. Added a supervisor-side `rl_policy_cache` DashMap
  that caches per-route policy, invalidated on every reload (both the
  fully-succeeded two-phase commit and the legacy-broadcast fallback)
- Predictable `generate_request_id` IDs (audit M-5): previous
  implementation used `DefaultHasher(SystemTime::nanos XOR
  thread_id)`, which is deterministic given inputs and collides on
  same-nanosecond concurrent same-thread requests. Replaced with
  `OsRng.fill_bytes(16)` for 128 bits of unpredictable ID
- `ConfigReloadAbort` RPC (audit M-7): new wire-additive
  `CommandType::ConfigReloadAbort` (tag 14) fanned out to workers
  that succeeded Prepare when a peer fails; worker drops the pending
  slot on generation match instead of pinning one orphan
  `Arc<ProxyConfig>` per worker until the next reload
- `lorica-shmem::now_ns` silent fallback (audit L-1): `clock_gettime`
  failure now emits a warn log instead of silently returning 0, which
  would stall eviction without any signal to ops
- `lorica-command::IncomingCommand::reply` debug-assert on
  caller-supplied sequence mismatch (audit L-3): release builds still
  overwrite with the originating command's sequence, but wiring bugs
  that pass a different non-zero sequence now surface in tests
- `generate_random_password` deterministic RNG (audit L-5): replaced
  `thread_rng()` with `ChaCha20Rng::from_rng(OsRng)` so the first-run
  admin password pedigree matches `hash_password`'s OS-entropy salt
- `lorica-limits::token_bucket::refill_locked` overflow-defence
  tightening (audit L-6): added a `debug_assert!` that
  `refill_per_sec <= 1_000_000` (the API cap) so future regressions
  surface in tests instead of silently saturating

### Changed

- Supervisor -> worker pipelined-RPC Prometheus counter
  (`lorica_supervisor_rpc_outcome_total{kind, outcome}`): one counter
  spanning `metrics_pull` / `config_reload_{prepare,commit,abort}`
  with `ok` / `timeout` / `error` outcomes. Lets ops tell apart
  "all workers slow on Prepare" (DB contention) from "one worker
  stuck on metrics pull" (downstream issue)
- Fix `RpcEndpoint::Inner::drop` to actually abort reader + writer
  tokio tasks instead of relying on JoinHandle-drop detach semantics,
  so a dropped endpoint actually closes its socket halves and the
  peer sees EOF. Without this, a worker's RPC listener would hang
  past the 10 s TaskTracker drain on supervisor shutdown. Regression
  test `reload_listener_drains_on_supervisor_eof` asserts completion
  within 5 s
- Bumped `dashmap 5.5.3 -> 6.1.0` across `lorica`, `lorica-api`,
  `lorica-limits`; 5.x had iterator-invariant unsoundness fixed in
  6.x (supply-chain audit SC-M-1, SC-M-4)
- Bumped `tokio-tungstenite 0.20.1 -> 0.29.0` in `lorica-proxy` to
  drop a duplicated websocket frame parser and pull in fuzzer-driven
  fixes (supply-chain audit SC-M-2)
- Bumped `brotli 3 -> 8` in `lorica-core` (supply-chain audit
  SC-L-1); API source-compatible for Lorica's `CompressorWriter` /
  `DecompressorWriter` usage
- `lorica-api` feature `route53` flipped to off by default
  (supply-chain audit SC-M-3). Non-Route53 deployments no longer
  ship the `aws-smithy-http-client` dep graph that drags
  `rustls 0.21` + `hyper 0.14`. Users of ACME DNS-01 via Route53
  build with `cargo build --release --features route53`. BREAKING
  for downstream packagers who relied on the default feature
- Inlined `no_debug` (was `no_debug = "3.1.0"` unmaintained single-
  file crate, supply-chain audit SC-L-3) as
  `lorica-tls::no_debug` module. Dropped the dep; public API
  preserved via `pub use crate::no_debug::{...}`
- Dropped `daemonize = "0.5"` dep (RUSTSEC-2025-0069,
  unmaintained). Production Lorica runs under
  `systemd Type=simple`; legacy `--daemon` flag now emits a warning
  and falls through to foreground execution. BREAKING only for
  operators who relied on `--daemon` outside systemd (a non-use-
  case in practice)
- CI: new `Semgrep (security)` job running 7 `p/*` rulesets +
  `trailofbits/semgrep-rules` (generic / javascript / rs / yaml),
  non-blocking with SARIF upload as PR artifact. Closes the
  original `p/bash` / `p/yaml` / `p/sql` coverage gap (audit
  round 1 identified them as 404 on the registry)
- CI: new `Frontend lint` step running `svelte-check` +
  `eslint-plugin-svelte` (flat config with `svelte/no-at-html-tags`
  + `svelte/no-target-blank` + `no-eval` family). Regression
  guard for the Svelte XSS manual audit pass (audit coverage gap)
- Split `lorica/src/proxy_wiring.rs` from 8 561 LOC down to
  5 284 LOC (-38 %) as audit M-8 follow-up. Tests block
  (~3 k LOC) moved to `proxy_wiring/tests.rs`; RPC dispatch
  enums (BreakerAdmission / BreakerEngine / VerdictCacheEngine /
  RateLimitEngine) moved to `proxy_wiring/engines.rs` with a
  `pub use engines::{...}` re-export preserving the existing
  `lorica::proxy_wiring::*` import path. No functional change

### Added

- `/metrics` pull-on-scrape over pipelined RPC (WPAR worker-parity audit, Phase 6 / WPAR-7): Prometheus scrapes now trigger a fresh fan-out to every worker via the pipelined RPC channel before the handler reads the aggregated state. Each worker responds with a `MetricsReport` payload carrying per-request counters (cache_hits / cache_misses / active_connections / ban_entries / EWMA scores / backend connections / per-route request counts / WAF counts); the supervisor aggregates into `AggregatedMetrics` and the scrape encodes it. Dedup via an `Instant`-based lock collapses concurrent scrapes within a 250 ms window into a single fan-out - scraping /metrics from five concurrent Prometheus servers only hits the workers once. Per-worker 500 ms timeout bounds the fan-out; non-responders fall back silently to the cached state (populated by the existing periodic-pull task), so a stuck worker cannot stall a scrape. A 1 s wall-clock watchdog wraps the refresher call in the handler as a last resort. See design § 7
- Forward-auth verdict cache over pipelined RPC (WPAR worker-parity audit, Phase 4 / WPAR-2): `VerdictCacheEngine::Rpc` routes lookup/push through the supervisor in worker mode, so an Allow verdict cached by one worker is served from every worker's hot path on subsequent requests and a session revocation invalidates the cache uniformly across the pool. Single-process mode keeps the per-process `FORWARD_AUTH_VERDICT_CACHE` static unchanged. RPC wire is extended with `ForwardAuthHeader` so cached Allow outcomes can serve the injected upstream headers (Remote-User, Remote-Groups, ...) without a second round trip to the auth backend. Transport failure degrades gracefully: a failed lookup RPC falls through to the upstream auth call (fail-open semantics match the single-process lazy-eviction path); a failed push is fire-and-forget so the downstream request still completes. Supervisor-side cache preserves the existing `FORWARD_AUTH_VERDICT_CACHE` semantics (16 384-entry FIFO, per-route partitioning via NUL-separated key, only Allow verdicts cached, Cache-Control: no-store honored). See `docs/architecture/worker-shared-state.md` § 7
- Circuit-breaker over pipelined RPC (WPAR worker-parity audit, Phase 5 / WPAR-3): `BreakerEngine::Rpc` replaces the per-worker `CircuitBreaker::is_available` / `record_failure` / `record_success` with async `admit()` / `record()` calls that delegate to a supervisor-owned state machine. The supervisor tracks `Closed` / `Open` / `HalfOpen(in-flight probe)` per `(route_id, backend)` so a HalfOpen probe slot is allocated atomically across workers (no two workers can each believe they hold the probe at the same time), and a failure on one worker trips the breaker for every worker. `BreakerDecision` is tri-state: `Allow` (Closed), `AllowProbe` (HalfOpen slot granted), `Deny` (Open). Workers remember a probe-admitted backend on the per-request `ProxyCtx.breaker_probe_backend` so the subsequent outcome report is flagged `was_probe=true`, letting the supervisor close the breaker on probe success or bounce back to Open on probe failure. Transport error fails open so a flaky supervisor channel never DoS's the data plane. Single-process mode keeps the in-process `CircuitBreaker` unchanged under `BreakerEngine::Local`. See design § 7
- Two-phase config reload over pipelined RPC (WPAR worker-parity audit, Phase 7 / WPAR-8): `ConfigReloadPrepare` + `ConfigReloadCommit` replaces the legacy one-shot `CommandType::ConfigReload` on the legacy UDS channel. The Prepare half (2 s timeout, slow path: SQLite read + `ProxyConfig::from_store` + wrr_state preservation + mTLS fingerprint drift detection) runs concurrently on every worker; the Commit half (500 ms timeout, fast path: single ArcSwap) publishes atomically on all workers at once. The divergence window across workers collapses from ~10-50 ms (synchronous reload per worker on legacy channel) to the UDS RTT (microseconds). Per-worker `GenerationGate` enforces monotonicity: a reordered stale Prepare is rejected (`observe`), a commit for a non-matching generation is rejected while the prepared slot is preserved (`observe_commit`). Supervisor coordinator fans out both phases via `coordinate_config_reload`; on Prepare failure the legacy broadcast fallback fires so a partial RPC regression never stalls a config rollout. A worker with no RPC channel yet registered (early supervisor startup) also falls through to the legacy broadcast. See design § 7
- Per-route rate limiting (WPAR worker-parity audit, Phase 3): new `rate_limit: { capacity, refill_per_sec, scope }` config field on `Route` exposes a per-route token-bucket limiter applied after ban-list / IP-blocklist / redirect checks but before mTLS / forward-auth / WAF (cheap rejection of abusive clients before expensive evaluation). `scope: per_ip` (default) creates one bucket per (route, client IP) — isolates abusive clients without penalising the rest; `scope: per_route` creates a single shared bucket for the route — caps aggregate traffic to a fragile origin. Rejected requests return `429 Too Many Requests` with a `Retry-After` header computed from the refill rate. Dashboard: three new inputs under the Protection tab (capacity, refill/s, scope dropdown). API validates `capacity` and `refill_per_sec <= 1_000_000` to prevent `u32::MAX` overflow. Schema migration V33. Built on the `lorica_limits::token_bucket` primitives (Mutex-guarded authoritative bucket with fixed-point 1e6-scale tokens, lazy time-based refill, clock-rewind-is-noop). In multi-worker mode (`--workers N >= 1`) the supervisor holds the authoritative bucket registry and workers keep CAS-based `LocalBucket` caches that sync every 100 ms over a dedicated pipelined RPC socketpair (separate from the legacy command channel). Aggregate admission is bounded at `capacity + 100 ms × N_workers × refill_per_sec` worth of tokens — the design's documented initial-tick over-admission (§ 6) — after which workers converge on the authoritative state
- WAF auto-ban counter migrated to shared memory (WPAR worker-parity audit, Phase 3): per-IP violation counting moved from the supervisor-local DashMap (fed by UDS WAF-event forwarding) to the `lorica-shmem` `waf_auto_ban` atomic hashtable. Workers increment the cross-worker counter directly on each WAF block; the supervisor reads the counter, compares against the configured threshold, and on first crossing broadcasts `BanIp` to all workers then CAS-resets the slot so the next round starts at zero. Eliminates the dashmap/shmem/UDS triple-source skew and gives identical accounting across the pool. Single-process mode keeps the existing per-process fallback path unchanged. See `docs/architecture/worker-shared-state.md` § 5-6
- `lorica-shmem` crate (WPAR worker-parity audit, Phase 2): anonymous memfd-backed shared-memory region for cross-worker atomic counters. `SharedRegion` holds two 128 Ki-slot open-addressing hashtables (`waf_flood`, `waf_auto_ban`) used by WPAR-1 for per-IP flood and auto-ban counts. Each slot is a 64-byte cache line carrying three independent `AtomicU64` fields (key, value, last_update_ns); no seqlock — readers consume `value` with a single atomic load and writers race on commutative `fetch_add`, so there are no torn reads regardless of writer concurrency. Linear probing up to `MAX_PROBE = 16` with a `SATURATED = u64::MAX` sentinel for chain exhaustion (fail-safe: WAF treats saturation as "limit reached"). SipHash-1-3 with a 128-bit supervisor-randomized key (via `getrandom`) prevents an attacker from crafting IPs that collide into the same probe chain. `memfd_create(MFD_CLOEXEC)` + `mmap(MAP_SHARED)`; the supervisor passes the fd to each worker at fork via the existing SCM_RIGHTS machinery. Magic number (ASCII "LORICASHM") and `layout_version` verified on worker open. Synchronous `evict_once(region, now_ns, stale_after)` primitive called by the supervisor's eviction loop; CAS-based slot release leaves `value` / `last_update_ns` for the next claim to reset. 24 unit tests plus 5 fork-based multi-process integration tests (disjoint-key no-crosstalk, same-key commutative-sum, siphash-key shared across children, SIGKILL survivor sanity, probe-chain saturation). See `docs/architecture/worker-shared-state.md` § 5
- `lorica-command` pipelined RPC framework (WPAR worker-parity audit, Phase 1): new `RpcEndpoint` demultiplexes concurrent in-flight requests on a single Unix socket via a background reader task and a per-sequence in-flight map, with a bounded outbound queue (capacity 256) that backpressures through a per-request timeout rather than growing unbounded. In-flight entries are removed on every exit path (Ok, Closed, Timeout) so dead senders cannot linger. Adds an `Envelope` wire frame that carries either a `Command` or a `Response` (required because the two shared leading prost tags), new `CommandType` variants for the upcoming WPAR RPCs (`RateLimitQuery/Delta`, `VerdictLookup/Push`, `BreakerQuery/Report`, `ConfigReloadPrepare/Commit`), typed payload oneofs on `Command` and `Response`, tri-state `BreakerDecision` (`Allow`/`Deny`/`AllowProbe`) per the supervisor-owned HalfOpen-probe model, a `Coalescer<K,V>` dedup primitive with TTL-bounded caching for the upcoming `/metrics` fan-out, and a `GenerationGate` atomic watermark enforcing strictly increasing reload generations. 37 unit tests including concurrency, adjacent-request isolation, peer-drop cleanup, and high-volume pipelining. See `docs/architecture/worker-shared-state.md` § 4
- Connection pre-filter: IP allow/deny CIDR policy enforced at TCP accept, before TLS handshake. Configurable via new `connection_allow_cidrs` and `connection_deny_cidrs` `GlobalSettings` fields; editable in the dashboard Settings tab. Deny always wins; a non-empty allow list switches the filter to default-deny. Hot-reloaded via arc-swap - listener-state stays consistent without rebuilding endpoints, in both single-process and worker modes
- Cache predictor: shared 16-shard LRU (32K keys total) remembers cache keys whose origin responded uncacheable (OriginNotCache, ResponseTooLarge, or user-defined custom reason) and short-circuits the cache state machine on the next request. Reduces cache-lock contention and variance-key computation on known-bypass traffic. Transient errors (InternalError, UpstreamError, storage failures, lock timeouts) are not remembered
- Cache Vary support: per-route `cache_vary_headers` partition the cache by request header values (e.g. Accept-Encoding, Accept-Language) so different clients get separate cache entries under the same URL. Merged with the origin's `Vary` response header so both operator config and RFC 7234 semantics take effect. `Vary: *` anchors the variance on the request URI to keep cache cardinality bounded. Editable in the dashboard Caching tab. Schema migration V25 adds the column with a default of `[]`
- Header-based routing: per-route `header_rules` select a specific backend group based on a request header's value. Supports Exact, Prefix and Regex match types with regex compiled once per route at load time (a malformed regex disables only that rule, never the whole route; the dashboard flags disabled rules with a red badge so operators can republish). Evaluated before path rules so a path rule with its own `backend_ids` can still override. Enables A/B testing (`X-Version: beta`), multi-tenant routing (`X-Tenant: acme`), and similar content-negotiation patterns without touching upstream URLs. New dashboard Header Rules tab. Schema migration V26 adds the column with a default of `[]`
- Canary traffic split: per-route `traffic_splits` send a configurable percentage of requests to alternate backend groups. Assignment is sticky per client IP via a deterministic hash of `(route_id, client_ip)`, so a given user stays on the same version across requests on the same route. Splits are evaluated AFTER header rules (explicit opt-in wins) and BEFORE path rules (URL-specific overrides still win). Dangling backend IDs are logged at load time but consume their weight band (falling back to route defaults) rather than silently rebalancing traffic to the next split. API rejects weight > 100 or cumulative > 100, and non-zero weight with empty backends. New dashboard Canary tab with total-weight summary. Schema migration V27
- Forward authentication: per-route `forward_auth` gates every request through an external authentication service (Authelia, Authentik, Keycloak, oauth2-proxy) before reaching the upstream. The standard `X-Forwarded-*` header set (Method, Proto, Host, Uri, For) plus Cookie, Authorization and User-Agent are sent verbatim to the auth service; 2xx returns allow the request (optional `response_headers` are harvested and injected into the upstream, e.g. `Remote-User`); 401/403/3xx responses are forwarded to the client verbatim (critical for Authelia's login-redirect flow); timeout or connection failure fails closed with 503. Evaluated after route match and WAF but before any backend selection so denied requests never touch the upstream. API validates URL scheme (http/https), host presence, timeout range (1..60000 ms), and non-empty response-header names; a warn log fires when the scheme is `http://` and the host isn't loopback so operators know credentials will traverse cleartext. Optional per-route verdict cache via `verdict_cache_ttl_ms` (default 0 = off, API-capped at 60 s): `Allow` verdicts are cached keyed on the NUL-separated `{route_id}\0{cookie}` literal (no truncated-hash collision surface), honors the auth service's `Cache-Control: no-store` / `no-cache` directives, 16 384-entry bounded FIFO so a cookie-flood attack can't exhaust memory. `Deny` / `FailClosed` are never cached. Dashboard exposure in the Security tab. Schema migration V28
- Request mirroring (shadow testing): per-route `mirror` duplicates requests to one or more secondary backends for A/B validation and shadow testing. Fire-and-forget via a shared reqwest client with redirects disabled and a 256-slot global concurrency semaphore - a saturated or dead shadow never impacts the primary request. Sampling is deterministic per `X-Request-Id` so retries of the same request land on the same mirror decision. Mirror requests carry `X-Lorica-Mirror: 1` so shadow backends can filter the traffic from their own metrics. Request bodies on POST/PUT/PATCH are forwarded in full up to a configurable `max_body_bytes` cap (default 1 MiB, max 128 MiB, 0 = headers-only); requests whose body exceeds the cap are sent to the primary normally but skipped for mirroring (a truncated body would mislead the shadow). Trust model: shadow backends receive Cookie / Authorization / session headers verbatim (matching Nginx `mirror`, Traefik `Mirroring`, Envoy `request_mirror_policies`), so shadows must be deployed in the same trust boundary as the primary - the `X-Lorica-Mirror: 1` marker is for log/metric filtering, not a security boundary. API validates non-empty/deduplicated backend list, sample_percent 0..=100, timeout 1..60000 ms, and max_body_bytes ceiling. Dashboard exposure in the Security tab. Schema migration V29
- Stale-while-revalidate background refresh: when a cached entry is past its TTL but within the route's `stale_while_revalidate_s` window, the proxy now serves the stale body to the client immediately and spawns a background sub-request that fetches fresh content from the upstream, updates the cache, and releases the write lock. The next request sees the refreshed entry without a round-trip. Built on Pingora's `SubrequestSpawner` + the existing cache-lock infrastructure; `response_cache_filter` already emits the SWR/SIE durations on the `CacheMeta`. Past the SWR window, stale hits fall back to synchronous revalidation as before
- Response body rewriting (Nginx `sub_filter` equivalent): per-route `response_rewrite` applies an ordered list of search-and-replace rules to upstream response bodies before they reach the client. Supports literal patterns (default) and regex with capture-group substitution (`$1`, `$2`). Rules compose (each rule runs on the output of the previous one). Only text-ish content is rewritten - configurable `content_type_prefixes` (default `text/`); compressed responses (`Content-Encoding: gzip/br`) pass through unchanged to avoid corrupting the stream. Bodies exceeding `max_body_bytes` (default 1 MiB, cap 128 MiB) stream through verbatim rather than emit a partial rewrite. Cross-chunk patterns are caught because the engine buffers the full body before running rules. `Content-Length` is automatically dropped on rewritten responses (new length differs from origin). API validates regex compilability at write time, non-empty patterns, and bounded limits. Schema migration V30 adds `routes.response_rewrite TEXT` as nullable JSON. Dashboard: dedicated "Rewrite" tab with per-rule reorder/expand UX. HEAD responses, 1xx/204/304 statuses, and cache-enabled routes are skipped (the last is mutually exclusive with rewriting in v1 and is surfaced via a warn log)
- mTLS client verification: per-route `mtls` requires connecting clients to present an X.509 certificate signed by the configured CA bundle and, optionally, constrains which certificate subject organizations are allowed. The TLS handshake verifier is built at listener startup from the union of all per-route CAs (via rustls `WebPkiClientVerifier` with `allow_unauthenticated`), so different routes on the same listener can have different policies. Per-request enforcement runs before forward_auth: `required = true` with no client cert returns 496 ("SSL certificate required"), a presented cert whose O= isn't in `allowed_organizations` returns 495 ("SSL certificate error"). Rustls `ServerConfig` is immutable after build, so changes to `ca_cert_pem` require a restart; toggling `required` and editing `allowed_organizations` hot-reload. API validates PEM decodability, presence of at least one CERTIFICATE block, X.509 DER integrity, a 1 MiB bundle cap, and dedup/non-empty entries in the organization allowlist. Schema migration V31 adds `routes.mtls TEXT` as nullable JSON. Dashboard exposure in the Security tab
- Prometheus counters for every v1.3.0 feature with non-trivial activity, exposed on the existing `GET /metrics` endpoint: `lorica_cache_predictor_bypass_total{route_id}`, `lorica_header_rule_match_total{route_id, rule_index}` (with `rule_index = "default"` for fallthrough), `lorica_canary_split_selected_total{route_id, split_name}` (with `"default"` / `"unnamed"` labels), `lorica_mirror_outcome_total{route_id, outcome}` (outcomes: `spawned`, `dropped_saturated`, `dropped_oversize_body`, `errored`), `lorica_forward_auth_cache_total{route_id, outcome}` (outcomes: `hit`, `miss`). Cardinality is bounded by route count - no user-input-derived labels
- Config-validation endpoints to shorten the save-fail-retry loop when configuring auth and mTLS: `POST /api/v1/validate/mtls-pem` parses a candidate CA PEM and returns the per-cert subjects so operators can confirm their bundle before committing; `POST /api/v1/validate/forward-auth` issues one GET to a candidate auth URL and reports status, elapsed time, and a whitelisted subset of response headers (Location, Remote-User, Remote-Groups, Remote-Email, Content-Type). Surfaced in the dashboard Security tab as inline "Validate PEM" / "Test connection" buttons

### Changed

- Circuit breaker now scopes state by `(route_id, backend)` instead of by backend alone. Two routes that share the same upstream IP:port (common when a single Teleport / nginx front-door multiplexes several virtual hosts on one port) no longer punish each other: failures on one route open the breaker only for that route, leaving sibling routes routable to the same physical backend
- Response body rewriting: compiled rules are now resolved once in `response_filter` and stored on the per-request context, replacing a linear scan of all routes that previously ran on every body chunk. Per-chunk overhead is a pointer clone regardless of route count
- Basic auth credential cache keys are now the raw NUL-joined `"{credential}\0{hash}"` string instead of a 64-bit `DefaultHasher` digest. Two distinct credentials can no longer collide on a truncated hash and share a cache slot (same design as the forward auth verdict cache)
- Forward auth `X-Forwarded-Proto` is now derived from the TLS socket state (`ssl_digest`) instead of HTTP version. h2c (HTTP/2 over plaintext) would previously be reported as `https` to the auth service
- `canary_bucket` now uses FNV-1a with fixed constants instead of `DefaultHasher` (which seeds a random `RandomState` per process). Canary assignments are now stable across restarts and rolling upgrades: the same client IP lands on the same bucket on the new process as on the old one, so a rollout does not silently reshuffle which users see the canary
- `RouteEntry` is now stored as `Arc<RouteEntry>` in `ProxyConfig` and the matched entry is cached in the per-request context during `request_filter`. `upstream_peer` no longer re-runs `find_route` on the same request; the entry is reused as a pointer clone
- Canary / header-rule / path-rule overrides remain strictly fail-closed when all of their backends are breaker-open or unhealthy (502 rather than fallback to route defaults). Documented explicitly in `upstream_peer` so operators know a bad canary surfaces as a visible error on the fraction of traffic routed to it, not as silent absorption by the primary
- Email notification channel update: the masked-password restore path now rejects the request with a clear error when the stored config is missing, unparseable, or carries no `smtp_password`. Prior code silently fell through and persisted the literal `"********"` mask back to the database, erasing the real SMTP password
- Custom WAF rule compilation now caps both the raw pattern length (4 KiB) and the compiled NFA/DFA size (512 KiB) via `RegexBuilder::size_limit`. An authenticated admin submitting a pathological alternation can no longer stall the management API thread or balloon memory during hot-reload. Runtime matching was already linear via the `regex` crate; this closes the compile-time surface
- Pinned `rustls-pemfile = "=2.1.2"` in `lorica` and `lorica-tls` to keep the workspace off the 2.2.0 line flagged unmaintained by RustSec (RUSTSEC-2025-0134). The unmaintained API is not used; pinning is precautionary while rustls upstream lands the in-tree replacement
- E2E Docker harness (`tests-e2e-docker/`) now runs as the non-root `lorica` user end-to-end. The entrypoints no longer need `su` to drop privileges because the exposed ports (9443/8080/8443) are above 1024 and `CAP_NET_BIND_SERVICE` is not required

## [1.2.0] - 2026-04-11

### Added

- Cache lock for thundering herd protection: only one request fetches from upstream on cache miss, others wait for the cached response (10 s timeout)
- Stale-while-error: serve cached responses when upstream fails (60 s) and during background revalidation (10 s), via `should_serve_stale()` hook
- Cache PURGE method: HTTP PURGE requests invalidate cached entries matching the request URI
- gRPC-Web bridge module: transparently converts HTTP/1.1 gRPC-web requests to HTTP/2 gRPC for upstream backends
- Least Connections load balancing algorithm: routes traffic to the backend with the fewest active connections
- HTTP Basic Auth per route: username/password (Argon2id-hashed) with 401 + WWW-Authenticate challenge. Configurable in Security tab
- Maintenance mode per route: returns 503 with Retry-After header and optional custom HTML error page
- Custom error pages: configurable HTML template for upstream errors (502/504) with `{{status}}` and `{{message}}` placeholders, served via `fail_to_proxy()` hook
- Enriched retry policy: `retry_on_methods` field filters which HTTP methods are eligible for retry (e.g. GET, HEAD only), preventing duplicate side-effects on POST/PUT
- Structured log output: `--log-format` CLI option (json/text) and `--log-file` for file output alongside stdout. Propagated to worker processes
- OCSP stapling: automatic OCSP response fetch from CA responder (AIA extension), attached to TLS handshakes via rustls CertifiedKey. Best-effort with warning on failure
- Production Dockerfile: multi-stage build (Node 22 + Rust + Debian slim), non-root user, volume mount at /var/lib/lorica
- Per-route stale cache configuration: `stale_while_revalidate_s` (default 10) and `stale_if_error_s` (default 60) configurable via API and dashboard Caching tab

### Security

- PURGE method restricted to loopback and trusted proxy CIDRs to prevent external cache invalidation
- HTML escape for `{{message}}` placeholder in custom error pages to prevent XSS via crafted upstream error messages
- Basic auth credential verification cache (60 s TTL) avoids Argon2 hot-path overhead on repeated requests

### Changed

- Route struct wrapped in Arc in ProxyConfig to avoid deep-cloning on every request (~300-500ns saved)
- Path rewrite regex wrapped in Arc to avoid compiled NFA/DFA duplication per request
- WAF rule matching uses single `find()` instead of `is_match()` + `find()` (halves regex cost on matches)
- WAF `url_decode` fast path skips decode loop when input has no percent-encoding
- HTML sanitize regexes compiled once at startup via `Lazy<Regex>` instead of per-call

### Fixed

- Per-route IP allowlist/denylist CIDR matching was using string prefix comparison (`starts_with`), which incorrectly matched `10.1.2.3` against `10.1.2.30/24`. Now uses proper network containment via ipnet
- WAF event category filter: filter now applied at SQL level so LIMIT returns correct results when filtering by category (e.g. XSS events were invisible when IP Blocklist dominated the top N rows)
- list_routes() SELECT was missing stale_while_revalidate_s, stale_if_error_s, and retry_on_methods columns, causing maintenance_mode and other v1.2.0 fields to read incorrect values from shifted column indices
- Frontend TypeScript types synchronized with Rust API: WafEvent (route_hostname, action), ProxyInfo (http_port, https_port), GlobalSettings (waf_whitelist_ips), route-form test fixture (v1.2.0 fields)
- Supervisor mutex poison recovery: worker monitor and shutdown no longer panic on poisoned mutex, recover gracefully with warning log
- Encryption key load failure now logs an explicit error instead of silently falling back to unencrypted storage
- Dashboard accessibility: all dialog overlays have Escape key handler, aria-modal, tabindex; all sortable table headers have keyboard Enter handler and role="button"; backdrop has role="presentation"
- Prometheus metric creation uses `expect()` instead of `unwrap()` for better startup diagnostics
- `log_store.rs` `copy_to_sql` handles conversion errors gracefully instead of panicking
- SLA CSV export response builder uses `expect()` instead of `unwrap()`

## [1.1.0] - 2026-04-10

### Added

- Global WAF whitelist IPs in Settings: IPs or CIDRs that bypass WAF evaluation, rate limiting, IP blocklist, and auto-ban entirely. Prevents operators from being auto-banned by false positives (e.g. CMS body content triggering path traversal rules)
- CLI `lorica unban <IP> --password <PASSWORD>` command for emergency IP removal when locked out of the dashboard
- Access logs: configurable entry limit (100/500/1K/5K/10K) and "X of Y entries" total count display
- 12 new WAF rules (49 total): SQLi auth bypass, info schema recon, encoding evasion, NoSQL injection (MongoDB), XSS eval/base64, backup file access, PowerShell/Windows commands, HTTP request smuggling, scanner detection, PHP/Java deserialization, HTTP method abuse
- X-Request-Id header: unique request identifier generated per request, propagated to backends and logged in access logs for end-to-end tracing
- Circuit breaker: per-backend failure tracking that removes backends from rotation after 5 consecutive errors (5xx or connection failures), with 10s cooldown and half-open probe before recovery
- Sticky sessions: cookie-based session affinity per route. When enabled, a `LORICA_SRV` cookie containing the backend ID is set on first request. Subsequent requests are routed to the same backend. Falls back to normal load balancing if the backend is down

### Fixed

- Duplicate access log entries in worker mode: workers now persist logs directly, supervisor only pushes to in-memory buffer for WebSocket streaming
- WAF body scanning false positives: path traversal (930xxx) and protocol violation (920xxx) rules are no longer applied to request bodies, preventing false positives on CMS content containing `..\ ` or similar text
- SLA metrics polluted by proxy-level rejections and connection errors: WAF blocks, bans, rate limits, return_status responses, and upstream/downstream errors (resets, timeouts) are excluded from SLA latency percentiles
- SLA breach notifications not firing in worker mode: supervisor now checks thresholds on every flush cycle regardless of local data, reading SLA metrics flushed by workers
- Access logs: disabling auto-refresh/live toggle did not disconnect WebSocket, choice not persisted across page reloads
- IP blocklist WAF events showing `-` as route when request has no Host header: now falls back to URI authority (IP:port)
- Security page: missing category labels (SSRF, XXE, SSTI, Log4Shell, IP Blocklist, Prototype Pollution) and event filter options
- Client H2 disconnects ("not a result of an error") no longer shown as errors in access logs - status 0 is sufficient
- TCP keepalive on upstream connections (idle 15s, interval 5s, 3 probes) to detect stale/half-closed pooled connections before reuse
- Upstream idle connection timeout (60s) evicts stale connections from the pool
- Upstream keepalive pool auto-sizing at startup: 128 for <= 15 backends, scales to 8 per backend up to 1024 max

## [1.0.0] - 2026-04-09

### Added

**Proxy Engine**

- HTTP/HTTPS reverse proxy built on Cloudflare Pingora with host-based and path-prefix routing, TLS termination via rustls, structured JSON access logging, and configuration hot-reload via arc-swap
- Path rules: ordered sub-path overrides within a route for backends, cache, headers, rate limits, or direct HTTP status responses. First match wins with prefix and exact match types
- Route `redirect_to` field for 301 redirects (www-to-non-www, domain migrations) with automatic path and query string preservation
- Route `return_status` field for direct HTTP status responses (e.g. 403, 404) without proxying
- Catch-all hostname `_` as last-resort fallback when no exact or wildcard match is found
- Path rewriting with strip/add prefix and regex capture groups (linear time, ReDoS-safe)
- Per-backend `h2_upstream` toggle for HTTP/2 upstream (h2c plaintext, ALPN h2 for TLS) enabling gRPC proxying
- Round-robin, Peak EWMA, Consistent Hash, and Random load balancing strategies per route
- Configurable proxy headers, response headers, per-route timeouts, WebSocket passthrough, hostname aliases, force HTTPS redirect, per-route gzip compression and retry attempts
- X-Forwarded-Proto detection via TLS session digest
- SO_REUSEPORT on all proxy listeners for kernel-level connection distribution
- Connection pooling with health-aware backend filtering
- Cookie merge support for upstream responses

**Security**

- WAF engine with 39 OWASP CRS-inspired rules: SQLi, XSS, path traversal, command injection, SSRF (cloud metadata, localhost, internal networks, dangerous URI schemes), Log4Shell/JNDI, XXE, CRLF injection. Detection or blocking mode. Sub-0.5ms evaluation latency
- Custom WAF rules persisted in SQLite, configurable per-rule enable/disable at runtime
- IP blocklist auto-fetched from Data-Shield IPv4 Blocklist (~80,000 entries, O(1) lookup, refreshed every 6h)
- Per-route rate limiting with configurable RPS, burst tolerance, and proper `X-RateLimit-*` response headers
- Auto-ban for IPs exceeding rate limits (configurable threshold and duration), with global supervisor-aggregated counters in multi-worker mode
- Trusted proxies CIDR list for X-Forwarded-For validation, preventing IP spoofing via header injection
- Per-route max connections (503 rejection), global connection limit, adaptive flood defense (auto-halves rate limits under flood)
- Slowloris detection with configurable threshold (408 rejection)
- Security header presets (strict/moderate/none) with custom preset support, IP allowlist/denylist, CORS per route
- Encrypted notification configs and certificate private keys at rest (AES-256-GCM)
- Database file permissions restricted to 0600, encryption key file created atomically with 0600 permissions
- Redacted password hashes in config export; import rejects redacted hashes
- Explicit Argon2id parameters (OWASP-compliant) for password hashing and verification
- Maximum password length (128 chars) to prevent DoS via large Argon2 inputs
- Session invalidation on password change (all sessions except current)
- Per-IP login rate limiting (was global bucket)
- CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers on dashboard
- Recursive URL decoding in WAF (max 3 passes) to prevent double-encoding bypass
- WAF request body scanning for SQL injection, XSS, and command injection in POST data (text bodies up to 1 MB, binary payloads skipped)
- DNS server parameter validation before shell command execution
- 10 MB global API request body size limit
- `#![deny(unsafe_code)]` on pure-logic crates (waf, config, notify, bench, api)
- `cargo-deny` configuration for supply chain auditing
- Empty SNI validates full certificate chain (CA, expiration, revocation)
- Load test target URL restricted to localhost to prevent external attacks
- HTTP request smuggling protections tested (CL.TE desync, TE obfuscation, duplicate CL)
- CRL (Certificate Revocation List) support for upstream TLS via `--upstream-crl-file` with automatic hot-reload every 60s

**TLS & Certificates**

- ACME HTTP-01 automatic provisioning via instant-acme with challenges served on proxy port 80
- ACME DNS-01 automatic provisioning with Cloudflare, Route53 (AWS SDK), and OVH providers
- ACME DNS-01 manual mode (two-step flow for any DNS provider)
- Multi-domain SAN and wildcard certificate support for DNS-01 flows
- Global DNS providers: credentials configured once in Settings, referenced by ID during provisioning
- Smart auto-renewal: certificates remember their provisioning method and DNS credentials, renewing automatically every 12h (30 days before expiry). Manual DNS-01 certificates skipped
- Background certificate expiry check every 12h with CertExpiring notifications at configurable warning/critical thresholds
- SNI-based certificate hot-swap via arc-swap with wildcard support (`*.example.com`)
- Certificate upload parses X.509 metadata (issuer, validity, SAN domains, fingerprint)
- Encryption key rotation via `lorica rotate-key --new-key-file` CLI command
- TLS termination in worker mode with per-worker CertResolver loaded from DB
- HTTPS listener starts unconditionally; TLS works as soon as the first cert is uploaded

**Dashboard**

- Embedded Svelte 5 + TypeScript frontend (~59 KB gzipped) compiled into the binary via rust-embed
- Overview cockpit with system health cards, setup checklist, section helpers with animated expand/collapse
- Routes CRUD with 25+ settings across 7 tabs, path rules tab with reorder and collapsible overrides
- Backends CRUD with address, weight, health check (TCP/HTTP), TLS upstream, HTTP/2 toggle, active connections
- Certificates management with ACME (HTTP-01, DNS-01) and manual upload, manual renewal button
- Security page with WAF event table, category filtering, 39 rule toggles, IP ban list with unban
- SLA page with passive/active side-by-side comparison, latency percentile tables, config editor, CSV/JSON export
- Load test page with config management, clone, one-click execution, real-time SSE progress, historical results with comparison
- Active probes CRUD with route selection and enable/disable toggle
- Access logs with real-time WebSocket streaming (green pulsing indicator), CSV/JSON export with date range picker
- System page with worker table (PID, health, heartbeat latency), CPU/memory/disk gauges
- Settings page with notification channels (structured forms per type), DNS providers, security header presets, config export/import with diff preview, getting started guide toggle
- Nginx config import wizard with path rules and certificate import support
- Notification form with structured fields per channel (SMTP, Webhook, Slack), alert type checkboxes, real test delivery via Test button
- Graceful error handling when backend is unreachable, auto-redirect to login on 401 session expiry
- Light/dark theme toggle, consistent full-width layout, CSS design-token variables

**Notifications**

- Notification system with 5 alert types: cert_expiring, backend_down, waf_alert, config_changed, ip_banned
- Four delivery channels: stdout (structured JSON), SMTP email (STARTTLS), HTTP webhook, Slack
- Per-channel rate limiting (sliding window), channel subscription filtering, event history (100 events)
- Notification history endpoint and dashboard table
- Hot-reload from database configs, broadcast-based AlertSender for proxy hot path

**Monitoring**

- Passive SLA monitoring from real traffic with lock-free atomic counters, time-bucketed aggregation, rolling windows (1h/24h/7d/30d), configurable success criteria
- Active SLA monitoring with synthetic HTTP probes (configurable method, path, status, interval, timeout)
- SLA threshold alerts with automatic notifications when passive SLA drops below target
- Built-in load testing with configurable concurrency, RPS, duration, safe limits, CPU circuit breaker (90%), cron scheduling, SSE streaming, config cloning
- Prometheus metrics at `/metrics`: request count, latency histograms, active connections, backend health, cert expiry, WAF events, system CPU/memory
- Worker metrics aggregation: cache hits/misses, active connections, ban list, EWMA scores from workers to supervisor

**Caching**

- HTTP response cache via Pingora MemCache with LRU eviction (128 MiB cap, TinyUFO algorithm)
- Per-route toggle with configurable TTL and max size, Cache-Control header respect, Authorization/Cookie bypass
- Path rule cache overrides for sub-path-specific caching
- X-Cache-Status response header (HIT/MISS/STALE/REVALIDATED/BYPASS)
- Cache purge and stats APIs

**Worker Mode**

- Process-based worker isolation: supervisor forks N workers, passes listening sockets via SCM_RIGHTS
- Protobuf command channel over Unix socketpair for ConfigReload, heartbeat monitoring (5s interval)
- Graceful shutdown with 30s drain timeout then SIGKILL
- Real-time access log forwarding via Unix domain socket (log.sock) with sub-millisecond latency
- WAF engine in supervisor with global auto-ban counter aggregation across workers
- TLS termination, SLA collection, load testing, notification dispatch all functional in worker mode
- Worker PIDs, health status, and heartbeat latency visible in System dashboard
- Exponential restart backoff (1s-30s), supervisor closes listening sockets after spawning

**Configuration**

- Embedded SQLite database with WAL mode, CRUD for all entities, 13+ schema migrations
- AES-256-GCM encryption for certificate private keys and notification configs at rest
- TOML config export/import with preview and diff, DNS provider CRUD with encrypted credentials
- REST API on localhost:9443 via axum with session-based auth, sliding window session renewal, rate-limited login
- CLI with `--version`, `--data-dir`, `--log-level`, `--management-port`, `--http-port`, `--https-port`, `--workers`, `--upstream-crl-file`
- OpenAPI 3.0.3 specification covering all 85+ endpoints
- IP blocklist and WAF disabled rules persisted in GlobalSettings and restored on restart

**Packaging**

- `.deb` package with systemd service, user creation, permissions, service enable/auto-restart on upgrade
- `.rpm` spec with equivalent packaging
- Security-hardened systemd unit (ProtectSystem, PrivateTmp, NoNewPrivileges, MemoryDenyWriteExecute, SystemCallFilter, LimitNOFILE=65536)
- GitHub Actions CI pipeline (lint, test, build, package) with GPG-signed release artifacts
- NOTICE file crediting Cloudflare Pingora, FORK.md documenting fork lineage

**Testing**

- 892 Rust unit tests across 25 crates (463 product + 429 forked Pingora), 119 frontend Vitest tests, 350+ E2E Docker assertions across standalone and worker modes
- Docker Compose E2E test suite with 350+ assertions across 65+ sections (standalone + worker modes)
- Fuzz testing targets for WAF evaluation and API input
- Reproducible benchmark suite using oha in Docker (single-process, multi-worker, WAF, cache scenarios)
- Performance tuning guide with kernel sysctl, fd limits, worker sizing, cache and rate limit tuning

### Removed

- Windows support removed from forked Pingora crates (Linux-only)

[1.3.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.3.0
[1.2.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.2.0
[1.1.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.1.0
[1.0.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.0.0
