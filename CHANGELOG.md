# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Author: Rwx-G

## [1.0.0] - 2026-04-08

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
- Access logs with real-time WebSocket streaming (green pulsing indicator)
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

- 871 Rust unit tests across 25 crates (442 product + 429 forked Pingora), 350+ E2E Docker assertions across standalone and worker modes
- Docker Compose E2E test suite with 170+ assertions across 35 sections
- Fuzz testing targets for WAF evaluation and API input
- Reproducible benchmark suite using oha in Docker (single-process, multi-worker, WAF, cache scenarios)
- Performance tuning guide with kernel sysctl, fd limits, worker sizing, cache and rate limit tuning

### Changed

- DashMap for ban list and per-route connection counters replacing RwLock<HashMap> for reduced contention
- Route53 DNS-01 provider uses official aws-sdk-route53 crate instead of custom SigV4 signing
- Upgrade reqwest 0.11 to 0.12 across all crates

### Removed

- Windows support removed from forked Pingora crates (Linux-only)

[1.0.0]: https://github.com/Rwx-G/Lorica/releases/tag/v1.0.0
