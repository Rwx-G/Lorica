# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **WAF engine** (`lorica-waf`) - Optional per-route Web Application Firewall with 18 OWASP CRS-inspired rules covering SQL injection, XSS, path traversal, command injection, and protocol violations. Detection mode (log only) and blocking mode (403 response). Precompiled regex patterns with URL decoding. Event ring buffer (500 events) for dashboard consumption. Sub-0.5ms evaluation latency. Zero overhead when WAF is disabled on a route.
- **Security dashboard** - New Security page showing WAF event table with category filtering, stats cards per attack category, and event clearing. WAF events API: `GET /api/v1/waf/events`, `GET /api/v1/waf/stats`, `DELETE /api/v1/waf/events`.
- **WAF route controls** - WAF enabled/mode toggle in route create/update API and dashboard. Routes table shows WAF status (Detect/Block/-).
- **Topology-aware health checks** - Health check behavior adapts to route topology type. SingleVM: no active probes (passive detection only). HA/Custom: active TCP or HTTP probes. DockerSwarm/Kubernetes: service discovery integration. Multi-route priority resolution (HA > Custom > SingleVM). Global default topology configurable in settings.
- **Configurable WAF rule sets** - Individual WAF rules can be enabled/disabled at runtime via API (`GET/PUT /api/v1/waf/rules/:id`). Security dashboard Rules tab with toggle switches per rule.
- **HTTP health checks** - Backends can specify `health_check_path` (e.g. "/healthz") for HTTP GET probes instead of TCP-only. Expects 2xx response within timeout. DB migration 002 adds the column.
- **Notification rate limiting** - Per-channel sliding window rate limiter (default: 10 per 60s) prevents alert storms. Configurable via `RateLimitConfig`. Suppressed notifications logged with warning.
- **Docker Swarm service discovery** - `DockerDiscovery` connects to Docker daemon via socket API (bollard), lists service tasks, and extracts network endpoint IPs. Behind `docker` feature flag.
- **Kubernetes pod discovery** - `K8sDiscovery` connects to Kubernetes API (kube-rs), reads Endpoints resources with ready/not-ready addresses. Behind `kubernetes` feature flag.
- **Notification channels** (`lorica-notify`) - Alert event system with 4 types: cert_expiring, backend_down, waf_alert, config_changed. Three delivery channels: stdout (always on, structured JSON), SMTP email via lettre (STARTTLS, configurable auth), HTTP webhook via reqwest (JSON POST with optional Authorization header). NotifyDispatcher with channel subscription filtering and event history ring buffer (100 events).

- **Proxy engine** - HTTP/HTTPS reverse proxy forked from Cloudflare Pingora, renamed to Lorica (17 crates). Host-based and path-prefix routing, round-robin load balancing with health-aware filtering, TLS termination via rustls, structured JSON access logging. Configuration hot-reload via `arc-swap` triggered automatically on API mutations.
- **Configuration store** (`lorica-config`) - Embedded SQLite database with WAL mode for crash safety. Data models for routes, backends, certificates, global settings, notification configs, user preferences, and admin users. CRUD operations, database migrations, TOML export/import with referential integrity validation and diff preview. AES-256-GCM encryption for certificate private keys at rest.
- **REST API** (`lorica-api`) - axum-based management API on localhost:9443. Session-based authentication with HTTP-only secure cookies, first-run admin password generation, forced password change, rate-limited login. Full CRUD for routes, backends, certificates, settings, notification configs, and user preferences. Config export/import with preview endpoint. Notification config JSON validation and connection test endpoint. TOML import size limit (1 MB). Consistent JSON error envelope.
- **Embedded dashboard** (`lorica-dashboard`) - Svelte 5 + TypeScript frontend compiled into the binary via `rust-embed` (~59 KB bundle). Login and password change screens, sidebar navigation, and full management UI: overview status cards, route/certificate/backend CRUD, scrollable access logs with filtering, system metrics, settings with notification channels, config export/import with diff preview, light/dark theme toggle.
- **Health checks** - Background TCP health check service with configurable interval. Backends marked as degraded (>2s latency) or down (unreachable) and excluded from rotation.
- **Worker isolation** (`lorica-worker`) - Process-based worker isolation using fork+exec. Supervisor creates TCP listening sockets, forks N worker processes, and passes socket FDs via SCM_RIGHTS. Each worker runs the proxy engine independently. Configurable worker count via `--workers N` (default 0 = single-process mode). Exponential restart backoff (1s-30s) with explicit SIGTERM on shutdown. Per-worker command channels with heartbeat latency monitoring.
- **Command channel** (`lorica-command`) - Protobuf-based command channel between supervisor and worker processes. 8-byte LE size-prefix framing over Unix socketpair. Supervisor dispatches ConfigReload commands when API configuration changes. Workers apply changes inline by reloading from database without pausing traffic. Three-state response protocol (Ok, Error, Processing). Heartbeat health monitoring every 5 seconds with timeout detection.
- **Certificate hot-swap** (`lorica-tls`) - SNI-based certificate resolver with wildcard support (`*.example.com`). Multiple certificates per domain sorted by expiration (longest-lived first). Atomic hot-swap via `arc-swap` with zero downtime during certificate rotation. Certificates loaded from PEM in memory, no temporary files on disk. Integrated via rustls `ResolvesServerCert` trait.
- **Backend lifecycle** - Per-backend active connection tracking via atomic counters. Backend states (Normal, Closing, Closed) with graceful drain on removal. API exposes `lifecycle_state` and `active_connections` per backend. Load balancer filters out Closing/Closed backends from rotation.
- **WebSocket log streaming** - Real-time access log streaming via `GET /api/v1/logs/ws`. LogBuffer broadcasts new entries to all connected WebSocket clients. Frontend auto-connects with polling fallback. Green pulsing indicator shows live connection status.
- **Worker metrics** - Per-worker heartbeat latency tracking via `GET /api/v1/workers` endpoint. Supervisor records heartbeat response times. Dashboard System page shows workers table with health status, PID, and latency.
- **Binary** (`lorica`) - CLI with `--version`, `--data-dir`, `--log-level`, `--management-port`, `--http-port`, `--https-port`, `--workers`. Graceful shutdown on SIGTERM/SIGINT. systemd unit file with security hardening.
- **E2E test suite** - Docker Compose-based end-to-end tests with 4 containers (Lorica, 2 Python backends, bash test runner). 63 assertions covering authentication, dashboard, settings, backends/routes CRUD, proxy routing with round-robin, WAF detection/blocking, WAF rule management, status/system endpoints, access logs, config export/import, notification configs, HTTP health checks, and cleanup. Run with `cd tests-e2e-docker && ./run.sh --build`.
- **Tests** - 312 Rust + frontend unit tests (111 API, 65 config, 41 WAF, 43 notify, 52 frontend). 63 Docker e2e tests. Unit tests across all crates, integration tests gated behind `integration-tests` feature flag.
- NOTICE file crediting Cloudflare Pingora as upstream (Apache-2.0)

### Fixed

- **Database concurrency** - Added `PRAGMA busy_timeout=5000` and idempotent migration inserts (`INSERT OR IGNORE`) to prevent race conditions when multiple worker processes access the database concurrently.

### Removed

- **Windows support** - Removed all Windows-specific code from forked Pingora crates (787 lines). Deleted `windows.rs` WinSock bindings module. Removed `windows-sys` dependency. Project is Linux-only.
