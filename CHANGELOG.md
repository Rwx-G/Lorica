# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project documentation: brief, PRD (5 epics, 25 stories), architecture (sharded), brainstorming results
- Initial repository setup with LICENSE, README, CHANGELOG
- **Story 1.1:** Fork Pingora v0.8.0 and rename to Lorica (17 crates, 178 .rs files)
- NOTICE file with Cloudflare Pingora attribution (Apache-2.0)
- **Story 1.2:** `lorica` binary with structured JSON logging, CLI flags (--version, --data-dir, --log-level, --management-port)
- Graceful shutdown on SIGTERM/SIGINT
- systemd unit file with security hardening (`dist/lorica.service`)
- **Story 1.3:** `lorica-config` crate for configuration state and persistence
- Data models: Route, Backend, Certificate, GlobalSettings, AdminUser, UserPreference, NotificationConfig
- Embedded SQLite database with WAL mode for crash safety
- CRUD operations for all configuration entities with route-backend associations
- Database migration system (version-tracked, auto-run on startup)
- TOML export/import with referential integrity validation and version field
- AES-256-GCM encryption for certificate private keys at rest (via ring)
- **Story 1.4:** `lorica-api` crate - REST API foundation with axum
- Session-based authentication with HTTP-only secure cookies (30min timeout)
- First-run admin password generation (random 24-char, logged once to stdout)
- Forced password change on first login
- Rate limiting on login endpoint (5 attempts per minute)
- CRUD endpoints: routes (with backend associations), backends, certificates
- Certificate delete protection when referenced by routes (409 Conflict)
- Status overview endpoint (route/backend/certificate counts and health)
- Configuration export (TOML download) and import (full state replacement)
- Consistent JSON error envelope: `{"error": {"code": "...", "message": "..."}}`
- Localhost-only binding for management port (127.0.0.1:9443)
- OpenAPI 3.0 specification for all API endpoints
- **Story 1.5:** `lorica-dashboard` crate - embedded web dashboard
- Svelte 5 frontend with TypeScript, compiled to ~59KB bundle via Vite
- Login screen consuming `/api/v1/auth/login` with session cookie auth
- First-run password change screen for forced password rotation
- Navigation sidebar: Overview, Routes, Backends, Certificates, Logs, System, Settings
- Overview screen with status cards (route count, backend health, certificate status)
- Static assets embedded in binary via `rust-embed` (< 5MB total)
- `build.rs` auto-compiles frontend during `cargo build` (npm install + build)
- SPA fallback routing (hash-based client-side navigation)
- Dashboard served on management port (9443) alongside REST API
- **Story 1.6:** Dashboard route management - full CRUD for proxy routes
- Routes list screen with data table (hostname, path, backends, TLS, health, enabled)
- Route creation form with backend multi-select, certificate dropdown, load balancing and topology selectors
- Route edit modal with all route parameters
- Route delete with confirmation dialog
- StatusBadge component for health indicators (green/orange/red)
- ConfirmDialog component for destructive action confirmation
- API client methods for routes (list, create, update, delete), backends (list), certificates (list)
- Keyboard navigation for modals (Escape to close, Enter to submit) with ARIA dialog roles
- Vitest + @testing-library/svelte test framework for frontend component testing
- Frontend tests: StatusBadge (6), ConfirmDialog (7), API client (7) - 20 tests total
- **Story 1.7:** Dashboard certificate management - full CRUD for TLS certificates
- Certificates list screen with domain, issuer, expiration date, and expiry status badges
- CertExpiryBadge component with valid/warning/critical/expired states (configurable thresholds)
- Certificate upload via PEM file input or textarea (cert + key)
- Certificate detail view: full chain display, SAN domains, fingerprint, associated routes
- Certificate edit modal for domain and PEM replacement
- Certificate deletion with impact display (affected routes warning, 409 conflict handling)
- Self-signed certificate generation via `rcgen` with preference memory prompt (never/always/once)
- `POST /api/v1/certificates/self-signed` endpoint for real self-signed cert generation
- Configurable expiration thresholds (default: 30 days warning, 7 days critical)
- API client methods for certificates (get, create, update, delete)
- Frontend tests: CertExpiryBadge (10), certificate API client (6) - 16 new tests (36 total)
- **Story 1.8:** Proxy engine wiring - live HTTP/HTTPS proxying from dashboard config
- `LoricaProxy` struct implementing `ProxyHttp` trait for config-driven routing
- Host-based and path-prefix routing with longest-prefix-match semantics
- Round-robin backend selection with health-aware filtering (down/closing excluded)
- TLS termination using certificates loaded from ConfigStore into rustls
- Configuration hot-reload via `arc-swap` (no binary restart needed)
- TCP health check background service with configurable interval
- Structured JSON access logging (method, path, host, status, latency_ms, backend)
- HTTP proxy listener on port 8080, HTTPS on 8443 (configurable via CLI)
- TLS private key file permissions restricted to 0600 on Unix
- Latency-based degraded health detection (backends marked Degraded when TCP connect > 2s)
- TLS key file cleanup on graceful shutdown
- Rust tests: 20 new tests (config linking, routing logic, prefix ordering, health filtering, TCP probing)
- **Story 1.9:** Dashboard logs and system monitoring
- In-memory ring buffer for access log capture (configurable, default 10,000 entries)
- `GET /api/v1/logs` endpoint with filtering by route, status code range, and text search
- `DELETE /api/v1/logs` endpoint for clearing log buffer
- `GET /api/v1/system` endpoint with host metrics (CPU, RAM, disk), process metrics, and proxy info (version, uptime, connections)
- `sysinfo` crate integration for cross-platform system metrics
- Logs dashboard screen: scrollable table with filters (host, status category, search), auto-refresh (5s polling), clear action
- System dashboard screen: CPU/RAM/disk gauge bars with color thresholds, process memory and CPU, proxy version/uptime/connections
- Proxy access logging wired into shared LogBuffer for real-time dashboard viewing
- Rust tests: 5 new integration tests (logs endpoint empty/populated/filtering/clear, system endpoint)
- Frontend tests: 4 new API client tests (getLogs, getLogs with params, clearLogs, getSystem) - 40 total

### Changed

- All crates renamed from `pingora-*` to `lorica-*`
- TLS standardized on rustls only (openssl, boringssl, s2n features removed)
- `serde_yaml` replaced with `serde_yml`
- All crate versions set to 0.1.0

### Removed

- Pingora examples and tests from facade crate
- Sentry integration features
- OpenSSL, BoringSSL, s2n-tls backend crates (not copied)
