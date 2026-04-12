# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Author: Rwx-G

## Unreleased

### Added

- Forward-auth verdict cache (opt-in): per-route `forward_auth.verdict_cache_ttl_ms` caches successful `Allow` verdicts keyed on the downstream session cookie so subsequent requests from the same session skip the auth sub-request round-trip. Default `0` (off) keeps strict zero-trust semantics. Hard-capped at 60 s by the API validator because cached verdicts delay session-revocation. Only 2xx outcomes are cached; `Deny` and `FailClosed` are always re-evaluated. Honors the auth service's `Cache-Control: no-store` / `no-cache` response directives. In-process per-worker cache with a soft 16 384-entry cap and lazy expiry. Observability via `lorica_forward_auth_cache_total{route_id, outcome}`
- Prometheus counters for every v1.3.0 feature with non-trivial activity: `lorica_cache_predictor_bypass_total{route_id}`, `lorica_header_rule_match_total{route_id, rule_index}` (with `rule_index = "default"` for fallthrough), `lorica_canary_split_selected_total{route_id, split_name}` (with `"default"` / `"unnamed"` labels), `lorica_mirror_outcome_total{route_id, outcome}` (outcomes: `spawned`, `dropped_saturated`, `dropped_oversize_body`, `errored`), `lorica_forward_auth_cache_total{route_id, outcome}`. All registered in `lorica-api::metrics::REGISTRY` and exposed via the existing `GET /metrics` endpoint; cardinality is bounded by route count (no user-input-derived labels)
- Forward-auth `http://` non-loopback warning: API validator logs a warn when the auth URL scheme is plain HTTP and the host isn't loopback (`localhost`, `127.*`, `[::1]`, `*.localhost`), reminding operators that Cookie and Authorization headers are forwarded to the auth service verbatim and will leak in cleartext on non-loopback paths
- Dashboard badge for disabled header-routing rules: `HeaderRuleResponse.disabled` is computed at read time by attempting to compile each rule's regex; the route-form UI surfaces a red badge on rules the proxy skipped at load (e.g. regex-crate version drift after an upgrade, out-of-band DB edit) so the operator can republish

### Security

- Forward-auth verdict cache key is now the literal NUL-separated `"{route_id}\0{cookie}"` concatenation rather than a 64-bit `DefaultHasher` output. A truncated hash had a feasible birthday-collision cost (~2^32 distinct sessions) under which user B could receive user A's cached `Allow` response_headers. Raw-string keys use DashMap's full string-equality lookup, so two distinct (route_id, cookie) pairs can never alias. Memory cost is bounded by the same 16 384-entry cache cap
- Mirror trust boundary documented loudly on `MirrorConfig`: shadow backends receive Cookie / Authorization / session headers verbatim by design (matching Nginx `mirror`, Traefik `Mirroring`, Envoy `request_mirror_policies`) so shadow testing reflects the primary. Operators must deploy shadows in the same trust boundary as the primary. The `X-Lorica-Mirror: 1` marker is for log/metric filtering, not a security boundary

### Fixed

- Forward-auth verdict cache eviction is now a bounded FIFO via a sibling `VecDeque<String>` with O(1) amortised insert cost. The previous `iter().take(N)` strategy was O(n) per cap-overflow insert, creating a DoS surface under a cookie-flood attack where an attacker could sustain ~0.5 ms of per-request DashMap work
- SWR refresh-failure dangling-permit bug: the forked `lorica-cache::WritePermit::Drop` replaced its `debug_assert!(false, "Dangling cache lock started!")` with a `warn!` log so debug-build tests no longer panic on the legitimate SWR subrequest-abandon path (e.g. parent session disconnected before the writer completed). Added a `LockCtx::Drop` safety net in `lorica-proxy::subrequest` that explicitly releases the inner `WritePermit` as `LockStatus::TransientError` when the subrequest future is dropped - a new writer is now correctly elected on the next request for that key, preventing any cache-state drift in both debug and release builds

### Added

- Connection pre-filter: IP allow/deny CIDR policy enforced at TCP accept, before TLS handshake. Configurable via new `connection_allow_cidrs` and `connection_deny_cidrs` `GlobalSettings` fields; editable in the dashboard Settings tab. Deny always wins; a non-empty allow list switches the filter to default-deny. Hot-reloaded via arc-swap - listener-state stays consistent without rebuilding endpoints, in both single-process and worker modes
- Cache predictor: shared 16-shard LRU (32K keys total) remembers cache keys whose origin responded uncacheable (OriginNotCache, ResponseTooLarge, or user-defined custom reason) and short-circuits the cache state machine on the next request. Reduces cache-lock contention and variance-key computation on known-bypass traffic. Transient errors (InternalError, UpstreamError, storage failures, lock timeouts) are not remembered
- Cache Vary support: per-route `cache_vary_headers` partition the cache by request header values (e.g. Accept-Encoding, Accept-Language) so different clients get separate cache entries under the same URL. Merged with the origin's `Vary` response header so both operator config and RFC 7234 semantics take effect. `Vary: *` anchors the variance on the request URI to keep cache cardinality bounded. Editable in the dashboard Caching tab. Schema migration V25 adds the column with a default of `[]`
- Header-based routing: per-route `header_rules` select a specific backend group based on a request header's value. Supports Exact, Prefix and Regex match types with regex compiled once per route at load time (a malformed regex disables only that rule, never the whole route). Evaluated before path rules so a path rule with its own `backend_ids` can still override. Enables A/B testing (`X-Version: beta`), multi-tenant routing (`X-Tenant: acme`), and similar content-negotiation patterns without touching upstream URLs. New dashboard Header Rules tab. Schema migration V26 adds the column with a default of `[]`
- Canary traffic split: per-route `traffic_splits` send a configurable percentage of requests to alternate backend groups. Assignment is sticky per client IP via a deterministic hash of `(route_id, client_ip)`, so a given user stays on the same version across requests on the same route. Splits are evaluated AFTER header rules (explicit opt-in wins) and BEFORE path rules (URL-specific overrides still win). Dangling backend IDs are logged at load time but consume their weight band (falling back to route defaults) rather than silently rebalancing traffic to the next split. API rejects weight > 100 or cumulative > 100, and non-zero weight with empty backends. New dashboard Canary tab with total-weight summary. Schema migration V27
- Forward authentication: per-route `forward_auth` gates every request through an external authentication service (Authelia, Authentik, Keycloak, oauth2-proxy) before reaching the upstream. The standard `X-Forwarded-*` header set (Method, Proto, Host, Uri, For) plus Cookie, Authorization and User-Agent are sent verbatim to the auth service; 2xx returns allow the request (optional `response_headers` are harvested and injected into the upstream, e.g. `Remote-User`); 401/403/3xx responses are forwarded to the client verbatim (critical for Authelia's login-redirect flow); timeout or connection failure fails closed with 503. Evaluated after route match and WAF but before any backend selection so denied requests never touch the upstream. API validates URL scheme (http/https), host presence, timeout range (1..60000 ms) and non-empty response-header names. Dashboard exposure in the Security tab. Schema migration V28
- Request mirroring (shadow testing): per-route `mirror` duplicates requests to one or more secondary backends for A/B validation and shadow testing. Fire-and-forget via a shared reqwest client with redirects disabled and a 256-slot global concurrency semaphore - a saturated or dead shadow never impacts the primary request. Sampling is deterministic per `X-Request-Id` so retries of the same request land on the same mirror decision. Mirror requests carry `X-Lorica-Mirror: 1` so shadow backends can filter the traffic from their own metrics. Request bodies on POST/PUT/PATCH are forwarded in full up to a configurable `max_body_bytes` cap (default 1 MiB, max 128 MiB, 0 = headers-only); requests whose body exceeds the cap are sent to the primary normally but skipped for mirroring (a truncated body would mislead the shadow). API validates non-empty/deduplicated backend list, sample_percent 0..=100, timeout 1..60000 ms, and max_body_bytes ceiling. Dashboard exposure in the Security tab. Schema migration V29
- Stale-while-revalidate background refresh: when a cached entry is past its TTL but within the route's `stale_while_revalidate_s` window, the proxy now serves the stale body to the client immediately and spawns a background sub-request that fetches fresh content from the upstream, updates the cache, and releases the write lock. The next request sees the refreshed entry without a round-trip. Built on Pingora's `SubrequestSpawner` + the existing cache-lock infrastructure; `response_cache_filter` already emits the SWR/SIE durations on the `CacheMeta`. Past the SWR window, stale hits fall back to synchronous revalidation as before
- Response body rewriting (Nginx `sub_filter` equivalent): per-route `response_rewrite` applies an ordered list of search-and-replace rules to upstream response bodies before they reach the client. Supports literal patterns (default) and regex with capture-group substitution (`$1`, `$2`). Rules compose (each rule runs on the output of the previous one). Only text-ish content is rewritten - configurable `content_type_prefixes` (default `text/`); compressed responses (`Content-Encoding: gzip/br`) pass through unchanged to avoid corrupting the stream. Bodies exceeding `max_body_bytes` (default 1 MiB, cap 128 MiB) stream through verbatim rather than emit a partial rewrite. Cross-chunk patterns are caught because the engine buffers the full body before running rules. `Content-Length` is automatically dropped on rewritten responses (new length differs from origin). API validates regex compilability at write time, non-empty patterns, and bounded limits. Schema migration V30 adds `routes.response_rewrite TEXT` as nullable JSON. Dashboard: dedicated "Rewrite" tab with per-rule reorder/expand UX. HEAD responses, 1xx/204/304 statuses, and cache-enabled routes are skipped (the last is mutually exclusive with rewriting in v1 and is surfaced via a warn log)
- mTLS client verification: per-route `mtls` requires connecting clients to present an X.509 certificate signed by the configured CA bundle and, optionally, constrains which certificate subject organizations are allowed. The TLS handshake verifier is built at listener startup from the union of all per-route CAs (via rustls `WebPkiClientVerifier` with `allow_unauthenticated`), so different routes on the same listener can have different policies. Per-request enforcement runs before forward_auth: `required = true` with no client cert returns 496 ("SSL certificate required"), a presented cert whose O= isn't in `allowed_organizations` returns 495 ("SSL certificate error"). Rustls `ServerConfig` is immutable after build, so changes to `ca_cert_pem` require a restart; toggling `required` and editing `allowed_organizations` hot-reload. API validates PEM decodability, presence of at least one CERTIFICATE block, X.509 DER integrity, a 1 MiB bundle cap, and dedup/non-empty entries in the organization allowlist. Schema migration V31 adds `routes.mtls TEXT` as nullable JSON. Dashboard exposure in the Security tab

### Fixed

- Route `get_route` SQL SELECT did not include `cache_vary_headers` (introduced in 1.2.0's unreleased migration), so loading a single route by ID returned an empty list even though the data was persisted correctly. `list_routes` was unaffected. Added a regression test exercising both code paths.

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

[1.2.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.2.0
[1.1.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.1.0
[1.0.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.0.0
