# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Author: Rwx-G

## [Unreleased]

### Added

- Path rules: ordered sub-path overrides within a single route. Each rule can override backends, cache settings, response headers, rate limits, or return a direct HTTP status. First match wins, supports prefix and exact match types. Dashboard includes a Path Rules tab with reorder, collapsible override sections
- Route `return_status` field: respond with a specific HTTP status code (e.g. 403, 404) without proxying. Combines with `redirect_to` for custom redirect status codes
- Catch-all hostname `_`: routes with hostname `_` act as a last-resort fallback when no exact or wildcard match is found
- Route `redirect_to` field: when set, the route responds with a 301 redirect to the specified URL instead of proxying to backends. The original request path and query string are appended automatically. Enables www-to-non-www redirects, domain migrations, etc.
- Background certificate expiry check task that monitors ALL certificates (ACME and manual) every 12 hours and dispatches `CertExpiring` notifications when certificates are within the `cert_warning_days` or `cert_critical_days` thresholds from global settings. Critical-level alerts use a "CRITICAL:" prefix in the message
- Encryption key rotation via `lorica rotate-key --new-key-file <path>` CLI command. Re-encrypts all certificate private keys and notification configs in a single transaction when rotating the encryption key
- Global WAF auto-ban counter managed by the supervisor instead of per-worker counters. In multi-worker mode the supervisor aggregates WAF block events from all workers via waf.sock and broadcasts BanIp commands when the threshold is reached, fixing the issue where N workers required N*threshold requests to trigger a ban. Single-process mode retains a local fallback counter
- Notification form: structured fields per channel type (SMTP, Webhook, Slack) replacing raw JSON textarea
- Notification form: alert type checkboxes with human-readable labels and select all/none
- Slack notification channel support in dashboard and API
- Real test notification delivery via Test button (sends actual email/webhook/slack)
- Toast notifications for test notification success/failure in dashboard
- Overview: section helper "?" buttons visible independently of getting started guide
- Worker metrics aggregation: cache hits/misses, active connections, ban list, and EWMA scores are now aggregated from workers to supervisor via command channel and displayed in the dashboard and Prometheus `/metrics` endpoint in multi-worker mode
- CRL (Certificate Revocation List) support for upstream TLS connections via `--upstream-crl-file` CLI flag. When set, server certificates are checked against the CRL (PEM or DER format). Propagated to worker processes in multi-worker mode. CRL file changes are detected automatically every 60 seconds and hot-reloaded without restart

### Security

- Load test target URL restricted to localhost (127.0.0.1, localhost, ::1) to prevent the engine from being used to attack external hosts. The dashboard now uses a route selector with path suffix instead of a free-text URL field

### Changed

- Post-install message now lists all CLI flags and notes dashboard is localhost-only
- Upgrade reqwest 0.11 to 0.12 across all crates, eliminating duplicate rustls-pemfile dependency tree

### Fixed

- Overview: fix spacing between section headers and cards when helper is collapsed
- Overview: smooth single-motion expand/collapse animation for section helpers
- Settings: fix theme toggle requiring two clicks (race condition with preferences reload)

### Security

- Encrypt notification config at rest using AES-256-GCM (same key as certificate private keys)
- Mask SMTP password in API responses (returned as `********`)
- Preserve existing SMTP password on update when masked value is submitted
- Fix encryption key file created with restrictive permissions (0600) atomically at creation, eliminating race condition window (`lorica-config/src/crypto.rs`)
- Fix potential panic on invalid private key format during mTLS client cert setup, replaced `.unwrap()` with proper error propagation (`lorica-core/src/connectors/tls/rustls/mod.rs`)
- Redact password hashes from config export; import now rejects redacted hashes with a clear error message
- Add HTTP request smuggling test suite (CL.TE desync, TE obfuscation, duplicate CL, HTTP/1.0+TE rejection)
- Use explicit Argon2id parameters (19 MiB, 2 iterations) instead of library defaults for password hashing
- Empty SNI now validates certificate chain (CA, expiration, revocation) instead of skipping all TLS verification. Only hostname check is skipped when no SNI is available
- Add non-root `USER` to e2e test Dockerfiles (backend, backend-h2, test-runner)
- Pin 11 overly broad `"0"` dependency version specs to minor version across 7 Cargo.toml files

## [0.1.3] - 2026-04-03

### Added

- Real-time access log forwarding in worker mode via Unix domain socket (`/var/lib/lorica/log.sock`). Workers stream logs to the supervisor with sub-millisecond latency, making WebSocket live logs work in multi-worker mode
- WAF engine in supervisor process for worker mode: rules listing, blocklist toggle, custom rules, and event viewing now work in the dashboard when running with `--workers N`
- IP blocklist auto-refresh (every 6h) in supervisor mode, with immediate fetch at startup when enabled
- WAF: 10 new detection rules - SSRF (cloud metadata, localhost, dangerous URI schemes, internal networks), Log4Shell/JNDI injection, XXE (DOCTYPE/ENTITY), CRLF injection. Total: 28 rules across 8 categories
- Dashboard Overview: getting started guide with 10-step interactive setup checklist and per-section "?" helper toggles with contextual explanations. Animated expand/collapse. Dismissible with localStorage persistence and re-enable toggle in Settings
- Dashboard: graceful error handling when backend is unreachable (network error, JSON parse failure). Auto-redirect to login on 401 session expiry
- Self-proxy dashboard guide (`docs/self-proxy-dashboard.md`) with API setup script for exposing the dashboard through Lorica itself
- Certificate upload now parses X.509 metadata (issuer, validity dates, SAN domains, DER fingerprint) instead of hardcoded placeholders
- Manual certificate renewal button on ACME certificates in the dashboard
- ACME auto-renewal background task (checks every 12h, renews at 30 days before expiry)
- ACME HTTP-01 challenges served on proxy port 80 (previously only on management port, which Let's Encrypt cannot reach)
- TLS termination in worker mode: workers create their own CertResolver, load certs from DB, and reload on config changes. HTTPS now works with `--workers N`
- Notification system fully wired: NotifyDispatcher created from DB configs at startup, broadcast-based AlertSender for proxy hot path. Alert dispatch sites for `waf_alert`, `ip_banned`, `backend_down`, `cert_expiring`, `sla_breached`
- Notification history endpoint (`GET /api/v1/notifications/history`) and dashboard table in Settings
- Load testing available in supervisor/worker mode (was single-process only)

### Changed

- Dashboard: all pages now use consistent full-width layout (removed hardcoded max-width on Overview, Logs, System, Settings)
- Dashboard: replaced all hardcoded `rgba()` colors with CSS design-token variables for proper dark/light mode support
- Dashboard: removed redundant scoped CSS overrides in favor of global styles in app.css, added `.btn-secondary` and `.btn-danger` to the design system
- Dashboard Overview: redesigned with header highlight bands, centered card values, stronger section hierarchy, and contextual color logic (orange for unconfigured, green for healthy)
- systemd service file: add `LimitNOFILE=65536` for 10k+ concurrent connections out of the box
- HTTPS listener starts unconditionally (even with no certs). TLS handshakes fail for unknown domains; when the first cert is uploaded and the resolver reloaded, TLS starts working without restart

### Security

- AES-256-GCM encryption enabled for certificate private keys at rest (encryption key auto-generated at `encryption.key`, chmod 0600)
- Database file permissions restricted to 0600 (owner-only read/write)

### Fixed

- Worker mode: supervisor closes listening sockets after spawning workers. Fixes requests hanging indefinitely (kernel was routing connections to supervisor which had no proxy service)
- Worker mode: use `TcpListener::from_raw_fd` instead of `TcpStream::from_raw_fd` for inherited listening sockets (correct socket type)
- Worker mode: respawn recreates listening sockets (previously used closed FDs)
- Worker mode: SLA flush task re-enabled in background runtime. Workers now flush SLA metrics to shared SQLite DB every 60s
- Worker mode: graceful shutdown with 30s drain timeout then SIGKILL (Sozu soft-stop pattern, fixes `systemctl stop lorica` hanging)
- Worker mode: worker PIDs now correctly reported in System dashboard (was hardcoded to 0)
- TLS CertResolver now hot-reloads on certificate upload/update/delete (was only loaded at startup)
- Certificate CRUD triggers proxy config reload (was missing `notify_config_changed`)
- Route certificate removal: setting certificate_id to empty string now clears the TLS association
- Certificate delete shows error toast when cert is referenced by routes (was silent failure)
- Dashboard: all modal/drawer buttons now functional. Root cause: Svelte 5 event delegation incompatible with stopPropagation on container divs, plus RouteDrawer `$effect` tracking `form` as dependency caused state reset on every interaction (fixed via `untrack` + `$derived`)
- Dashboard: HTTP/2 upstream checkbox text no longer wraps to two lines in backend form
- Dashboard: ACME certificate form spacing before "Use staging environment" checkbox in DNS-01 mode
- IP Blocklist toggle: fixed dimensions to match WAF rules toggles
- NFR validation script: threaded backend with `/slow` endpoint for realistic 10k connection holding test

## [0.1.2] - 2026-04-02

### Fixed

- Worker mode: SLA collector no longer panics on startup (tokio::spawn called outside runtime context)
- NFR validation script: password input masked, special characters escaped via jq, HTTP instead of HTTPS for localhost API
- NFR validation script: prerequisite checks (ulimit >= 20000, required tools) with clear error messages before running
- NFR validation script: Python backend suppresses BrokenPipeError under load, SO_REUSEADDR for port reuse
- Dashboard sidebar now stays fixed during page scroll (position: sticky)
- NFR validation script: force `LC_ALL=C` for consistent decimal separator on French locale systems
- Packaging (.deb/.rpm): service auto-restarts on upgrade (no manual `systemctl start` needed)
- Packaging (.deb): removed conffiles prompt on upgrade - service file replaced cleanly, customize via `systemctl edit lorica` (drop-in overrides)
- IP blocklist enabled/disabled state now persisted in GlobalSettings and restored on restart
- WAF disabled rules persisted in GlobalSettings (JSON array) and restored on restart
- WAF custom rules persisted in dedicated `waf_custom_rules` table (migration v13) and restored on restart

## [0.1.1] - 2026-04-02

### Added

- Per-backend `h2_upstream` toggle to force HTTP/2 upstream connections (h2c for plaintext, ALPN h2 for TLS). Enables gRPC proxying via HTTP/2 end-to-end
- SO_REUSEPORT enabled on all proxy listeners (both worker mode and single-process mode) for improved kernel-level connection distribution
- Performance tuning guide (`docs/tuning.md`) covering kernel sysctl, file descriptor limits, worker sizing, cache and rate limit tuning, and production readiness checklist
- Reproducible benchmark suite (`bench/`) using oha in Docker. Supports single-process, multi-worker, WAF, and cache scenarios with JSON output for comparison
- Regex path rewriting per route (`path_rewrite_pattern` + `path_rewrite_replacement`). Supports capture groups ($1, $2). Uses Rust regex crate (linear time, ReDoS-safe by design). Applied after strip/add prefix. Pattern validated and precompiled at config reload. Nginx import wizard parses `rewrite` directives into regex fields

## [0.1.0] - 2026-04-01

### Added

**Proxy Engine (Epics 1-2)**

- HTTP/HTTPS reverse proxy built on Cloudflare Pingora (17 crates, renamed to `lorica-*`). Host-based and path-prefix routing, TLS termination via rustls, structured JSON access logging, and configuration hot-reload via `arc-swap` on API mutations
- Round-robin load balancing with health-aware backend filtering, plus Peak EWMA latency-based selection, Consistent Hash, and Random strategies - selectable per route
- Process-based worker isolation (`lorica-worker`): supervisor forks N worker processes, passes listening sockets via SCM_RIGHTS. Exponential restart backoff (1s-30s), graceful SIGTERM shutdown. Configurable via `--workers N` (default 0 = single-process mode)
- Protobuf command channel (`lorica-command`) between supervisor and workers over Unix socketpair with 8-byte LE size-prefix framing. Dispatches ConfigReload on API changes; workers apply inline without pausing traffic. Heartbeat monitoring every 5s with timeout detection
- SNI-based certificate hot-swap (`lorica-tls`) with wildcard support (`*.example.com`). Multiple certificates per domain sorted by expiration. Atomic swap via `arc-swap` with zero downtime. Integrated through rustls `ResolvesServerCert` trait
- Backend lifecycle management with per-backend active connection tracking (atomic counters), graceful drain on removal (Normal/Closing/Closed states), and load balancer exclusion of draining backends
- TCP and HTTP health checks with configurable interval. Backends marked degraded (>2s latency) or down (unreachable) and excluded from rotation. HTTP probes via `health_check_path` expecting 2xx within timeout
- WebSocket log streaming via `GET /api/v1/logs/ws` with LogBuffer broadcast and frontend auto-connect with polling fallback

**Security (Epics 3, 7)**

- WAF engine (`lorica-waf`) with 18 OWASP CRS-inspired rules covering SQL injection, XSS, path traversal, command injection, and protocol violations. Detection mode (log only) and blocking mode (403). Precompiled regex with URL decoding. Sub-0.5ms evaluation latency. Zero overhead when disabled
- Configurable WAF rule sets - individual rules can be enabled/disabled at runtime via API (`GET/PUT /api/v1/waf/rules/:id`)
- Per-route rate limiting enforcement using `lorica-limits` Rate estimator keyed by route ID + client IP. 429 responses with `Retry-After` header. Burst tolerance via `rate_limit_burst`. Rate limit response headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`)
- Per-route max connections enforcement - 503 rejection when active connections reach limit, with per-route atomic counters that auto-decrement on request completion
- Slowloris detection - requests with headers exceeding `slowloris_threshold_ms` (default 5000ms) rejected with 408 Request Timeout. Disabled when threshold is 0
- Anti-DDoS auto-ban protection - per-IP violation counter (1-minute sliding window) escalates repeated 429s into temporary IP bans when exceeding `auto_ban_threshold`. Banned IPs receive 403 before route lookup or WAF. Configurable duration via `auto_ban_duration_s` (default 1h). Ban list API (`GET /api/v1/bans`, `DELETE /api/v1/bans/:ip`)
- Global connection limit via `max_global_connections` in GlobalSettings. New requests receive 503 when total active proxy connections reach the limit. 0 = unlimited (default)
- Adaptive flood defense - when global RPS exceeds configurable `flood_threshold_rps` (in GlobalSettings), per-IP rate limits are automatically halved. Disabled by default (threshold = 0). Per-second request counter also feeds dashboard metrics
- IP allowlist/denylist per route
- CORS configuration per route (origins, methods, max-age)
- Configurable security header presets ("strict", "moderate", "none") with support for custom presets via `custom_security_presets` in GlobalSettings. Presets include HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**Monitoring (Epic 5)**

- Passive SLA monitoring (`lorica-bench`) - per-route metrics from real traffic with lock-free atomic counters. Time-bucketed aggregation (1-minute resolution), rolling SLA windows (1h, 24h, 7d, 30d), configurable success criteria per route. Background flush to SQLite every 60s. CSV/JSON export. API: `GET /api/v1/sla/overview`, `/sla/routes/:id`, `/sla/routes/:id/buckets`, `PUT /sla/routes/:id/config`, export endpoint
- Active SLA monitoring - synthetic health probes per route/backend with configurable HTTP method, path, expected status, interval (min 5s), and timeout. System-wide `max_active_probes` cap (default 50). ProbeScheduler manages per-probe tokio tasks with automatic reload on config change. API: `CRUD /api/v1/probes`, `GET /sla/routes/:id/active`
- SLA threshold alerts (`sla_breached` alert type) - automatic notifications when passive SLA drops below configured target
- Built-in load testing - concurrent HTTP request generation with configurable concurrency, RPS, duration, and request pattern. Safe limits via global settings (not hardcoded) with explicit confirmation for exceeding them. Auto-abort on error rate threshold (default 10%). CPU circuit breaker at 90% to protect real traffic. SSE real-time streaming, cron-based scheduling, config cloning for reproducible comparisons
- Prometheus metrics at `/metrics` (no auth): request count + latency histogram (route_id, status_code labels), active connections, backend health gauge, certificate expiry days, WAF events by category/action, system CPU and memory

**Route Configuration (Epic 6)**

- 25+ per-route production proxy settings: force HTTPS redirect (301), hostname redirect, hostname aliases, configurable proxy headers (set/remove), response headers (set/remove), security header presets, per-route timeouts (connect/read/send), path rewriting (strip/add prefix), access log toggle, max request body size, WebSocket toggle, rate limiting (RPS + burst), IP allowlist/denylist, CORS, per-route gzip compression and retry attempts (both wired through Pingora fork modifications)

**Caching (Epic 7)**

- HTTP response caching via Pingora MemCache with LRU eviction capped at 128 MiB. Per-route toggle (`cache_enabled`), configurable TTL (`cache_ttl_s`, default 300s) and max size (`cache_max_bytes`). Respects Cache-Control headers; bypasses cache for Authorization/Cookie headers. X-Cache-Status response header (HIT/MISS/STALE/REVALIDATED/BYPASS). Cache purge API (`DELETE /api/v1/cache/routes/:id`). Cache stats API (`GET /api/v1/cache/stats`) with hit/miss counters

**Notifications (Epic 3)**

- Notification system (`lorica-notify`) with 5 alert types: `cert_expiring`, `backend_down`, `waf_alert`, `config_changed`, `ip_banned`. Three delivery channels: stdout (structured JSON, always on), SMTP email (STARTTLS, configurable auth), HTTP webhook (JSON POST with optional Authorization header). Channel subscription filtering and event history ring buffer (100 events)
- Notification rate limiting - per-channel sliding window (default: 10 per 60s) to prevent alert storms

**Service Discovery (Epic 3)**

- Docker Swarm service discovery (`DockerDiscovery`) via Docker daemon socket API (bollard). Health derived from running vs desired task counts. Behind `docker` feature flag
- Kubernetes pod discovery (`K8sDiscovery`) via Kubernetes API (kube-rs), reads Endpoints with ready/not-ready addresses. Behind `kubernetes` feature flag

**Dashboard**

- Embedded Svelte 5 + TypeScript frontend compiled into the binary via `rust-embed` (~59 KB bundle). Login and password change screens, sidebar navigation, light/dark theme toggle
- Overview cockpit dashboard with route/backend/certificate/alert summary cards, SLA chart, request rate sparkline, top routes table, and recent events timeline
- Routes CRUD with collapsible Advanced Configuration section for all 25+ settings, WAF status (Detect/Block/-) in routes table
- Backends CRUD with address, weight, health check (TCP/HTTP), TLS upstream, active connections
- Certificates management with ACME vs manual distinction
- Security page with WAF event table (category filtering), stats cards per attack category, configurable rule toggles, ban list tab with unban controls (auto-refreshes every 10s)
- SLA page with per-route overview cards, passive/active side-by-side comparison, latency percentile tables, SLA config editor, CSV/JSON export, bucket history
- Active Probes page with CRUD management, route selection, enable/disable toggle
- Load Test page with config management, clone, one-click execution with safe limit confirmation, real-time SSE progress panel, abort button, historical results with comparison deltas
- Scrollable access logs with filtering and live WebSocket streaming (green pulsing indicator)
- System metrics page with worker table (health status, PID, heartbeat latency)
- Settings page with notification channel configuration, global settings
- Security Header Presets management in Settings - view builtin presets (strict, moderate, none), create/edit/delete custom presets with name and key=value header pairs
- Config export/import with diff preview
- Nginx config import wizard - paste an `nginx.conf` to auto-create routes, backends, and certificates
- Input validation on all forms, sort/filter on Backends and Routes tables
- DNS-01 ACME form with automatic (Cloudflare, Route53 via AWS SDK) and manual (any provider) modes

**ACME (Epic 4)**

- Automatic TLS certificate provisioning via HTTP-01 challenge using instant-acme. Challenge tokens served at `/.well-known/acme-challenge/:token`. Supports staging and production directories. Consent-driven (admin opt-in per domain). Certs stored with `is_acme=true`
- DNS-01 manual mode for ACME provisioning: two-step flow (`POST /api/v1/acme/provision-dns-manual` and `/confirm`) that returns TXT record info for the user to create at any DNS provider, then confirms and downloads the certificate. Pending challenges stored in memory with 10-minute expiry. Dashboard UI with copyable TXT record fields

**Configuration & API**

- Embedded SQLite database (`lorica-config`) with WAL mode, CRUD for routes, backends, certificates, global settings, notification configs, user preferences, and admin users. AES-256-GCM encryption for certificate private keys at rest
- REST API (`lorica-api`) on localhost:9443 via axum. Session-based authentication with HTTP-only secure cookies, sliding window session renewal, first-run admin password generation, forced password change, rate-limited login. Full CRUD endpoints, config TOML export/import with preview and diff, notification test endpoint. Consistent JSON error envelope. OpenAPI 3.0.3 specification (`openapi.yaml`) covering all 85 endpoints
- CLI (`lorica`) with `--version`, `--data-dir`, `--log-level`, `--management-port`, `--http-port`, `--https-port`, `--workers`. Graceful shutdown on SIGTERM/SIGINT. systemd unit file with security hardening

**Packaging (Epic 4)**

- GitHub Actions CI pipeline (lint, test, build, package). Release workflow on tags creates GitHub Release with binary, `.deb`, and `.rpm` artifacts
- GPG package signing for `.deb` and `.rpm` artifacts in CI
- `.deb` package with systemd service, postinst (user creation, permissions, service enable), prerm/postrm scripts
- Security-hardened systemd unit (MemoryDenyWriteExecute, SystemCallFilter, RestrictNamespaces, UMask)
- NOTICE file crediting Cloudflare Pingora as upstream (Apache-2.0)
- FORK.md documenting fork origin, renaming rules, removed components, and upstream comparison strategy

**Testing**

- 655 Rust unit tests (280 product crates: 97 config, 55 bench, 52 waf, 39 api, 37 notify + 375 forked Pingora crates) and 52 frontend Vitest tests
- Docker Compose-based E2E test suite with 170+ assertions across 35 sections covering auth, dashboard, CRUD, proxy routing, WAF, health checks, certificates, TLS upstream, failover, Prometheus, Peak EWMA, SLA, probes, load testing, route config, rate limiting, CORS, cache, bans, compression, WebSocket blocking, backend validation, and worker isolation
- Fuzz testing targets for WAF evaluation and API input

### Changed

- DashMap for ban list and per-route connection counters in the proxy hot path, replacing `RwLock<HashMap>` for reduced contention under high concurrency
- Route53 DNS-01 provider migrated from custom SigV4 signing to official `aws-sdk-route53` crate. DELETE now uses the exact TXT value (tracked from create). Behind `route53` feature flag (enabled by default)

### Fixed

- `X-RateLimit-Reset` header now returns a real Unix timestamp (current time + 1s) instead of a hardcoded "1", in both 429 responses and normal rate-limited responses
- Settings update (`PUT /api/v1/settings`) now triggers proxy config reload so changes take effect immediately
- Config import diff now detects changes to `flood_threshold_rps` settings
- Database concurrency - added `PRAGMA busy_timeout=5000` and idempotent migration inserts (`INSERT OR IGNORE`) to prevent race conditions with multiple worker processes
- Cache purge endpoint (`DELETE /api/v1/cache/routes/:id`) was a stub - now clears all cached entries and resets hit/miss counters

### Removed

- Windows support - removed all Windows-specific code from forked Pingora crates (787 lines), deleted WinSock bindings, removed `windows-sys` dependency. Project is Linux-only
