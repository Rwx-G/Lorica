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

### Changed

- All crates renamed from `pingora-*` to `lorica-*`
- TLS standardized on rustls only (openssl, boringssl, s2n features removed)
- `serde_yaml` replaced with `serde_yml`
- All crate versions set to 0.1.0

### Removed

- Pingora examples and tests from facade crate
- Sentry integration features
- OpenSSL, BoringSSL, s2n-tls backend crates (not copied)
