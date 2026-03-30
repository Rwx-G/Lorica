# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Certificate hot-swap** (`lorica-tls`) - SNI-based certificate resolver with wildcard support (`*.example.com`). Multiple certificates per domain sorted by expiration (longest-lived first). Atomic hot-swap via `arc-swap` - zero downtime during certificate rotation. Certificates loaded from PEM in memory, no temporary files on disk. Integrated via rustls `ResolvesServerCert` trait with new `TlsSettings::with_resolver()` API.
- **Command channel** (`lorica-command`) - Protobuf-based command channel between supervisor and worker processes. 8-byte LE size-prefix framing over Unix socketpair. Supervisor dispatches ConfigReload commands to workers when API configuration changes. Workers apply changes inline by reloading from database without pausing traffic. Three-state response protocol (Ok, Error, Processing). Heartbeat health monitoring every 5 seconds with timeout detection.
- **Worker isolation** (`lorica-worker`) - Process-based worker isolation using fork+exec. Supervisor creates TCP listening sockets, forks N worker processes, and passes socket FDs via SCM_RIGHTS. Each worker runs the proxy engine independently. Configurable worker count via `--workers N` (default 0 = single-process mode, N = multi-worker). Supervisor monitors workers and automatically restarts crashed workers with structured logging. Unix-only (Linux/macOS).

### Fixed

- **Database migrations** - Made migration tracking insert idempotent (`INSERT OR IGNORE`) to prevent race conditions when multiple worker processes open the database concurrently.
- **Database concurrency** - Added `PRAGMA busy_timeout=5000` to prevent "database is locked" errors during concurrent worker startup.

### Added

- **Proxy engine** - HTTP/HTTPS reverse proxy forked from Cloudflare Pingora, renamed to Lorica (17 crates). Host-based and path-prefix routing, round-robin load balancing with health-aware filtering, TLS termination via rustls, structured JSON access logging. Configuration hot-reload via `arc-swap` triggered automatically on API mutations.
- **Configuration store** (`lorica-config`) - Embedded SQLite database with WAL mode for crash safety. Data models for routes, backends, certificates, global settings, notification configs, user preferences, and admin users. CRUD operations, database migrations, TOML export/import with referential integrity validation and diff preview. AES-256-GCM encryption for certificate private keys at rest.
- **REST API** (`lorica-api`) - axum-based management API on localhost:9443. Session-based authentication with HTTP-only secure cookies, first-run admin password generation, forced password change, rate-limited login. Full CRUD for routes, backends, certificates, settings, notification configs, and user preferences. Config export/import with preview endpoint. Notification config JSON validation and connection test endpoint. TOML import size limit (1 MB). Consistent JSON error envelope.
- **Embedded dashboard** (`lorica-dashboard`) - Svelte 5 + TypeScript frontend compiled into the binary via `rust-embed` (~59KB bundle). Login and password change screens, sidebar navigation, and full management UI:
  - **Overview** - Status cards (route count, backend health, certificate status)
  - **Routes** - List, create, edit, delete with backend/certificate selectors
  - **Certificates** - Upload PEM, detail view with chain display, self-signed generation with preference memory, configurable expiration thresholds (persisted to settings)
  - **Logs** - Scrollable access log with host/status/text filtering, auto-refresh
  - **System** - CPU/RAM/disk gauges, process metrics, proxy version/uptime/connections
  - **Settings** - Global configuration, notification channel management (email/webhook), preference memory UI, configuration export/import with diff preview, light/dark theme toggle
- **Health checks** - Background TCP health check service with configurable interval. Backends marked as degraded (>2s latency) or down (unreachable) and excluded from rotation.
- **Binary** (`lorica`) - CLI with `--version`, `--data-dir`, `--log-level`, `--management-port`, `--http-port`, `--https-port`. Graceful shutdown on SIGTERM/SIGINT. systemd unit file with security hardening.
- **Tests** - 829 Rust tests + 52 frontend tests (881 total). Unit tests for API error handling, middleware (session store, rate limiter), config models (all enum round-trips), import validation edge cases, diff computation, export round-trips, proxy config building, and load balancing algorithms. Integration tests for all API error scenarios (validation, 404, malformed import, expired sessions, rate limiting).
- NOTICE file crediting Cloudflare Pingora as upstream (Apache-2.0)