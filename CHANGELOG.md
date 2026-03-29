# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- **Tests** - 119 tests total: 31 config store unit tests, 36 API integration tests, 52 frontend tests (Vitest + @testing-library/svelte).
- NOTICE file crediting Cloudflare Pingora as upstream (Apache-2.0)
