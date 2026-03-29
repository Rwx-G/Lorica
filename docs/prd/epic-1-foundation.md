# Epic 1: Foundation - Fork, Strip, and Product Skeleton

**Epic Goal:** Transform the Pingora fork into a working Lorica product with proxy engine, REST API, embedded dashboard, and basic route/backend/certificate management.

**Integration Requirements:** Pingora proxy engine remains functional throughout. Each story adds a product layer without breaking existing proxy capabilities.

---

## Story 1.1: Fork and Strip Pingora

As an infrastructure engineer,
I want a clean Lorica codebase forked from Pingora with unused components removed,
so that I have a minimal, focused foundation to build on.

### Acceptance Criteria

1. Pingora repository cloned, git history removed, fresh repository initialized
2. All crates renamed from `pingora-*` to `lorica-*`
3. All internal `use pingora_*` references updated to `lorica_*`
4. `pingora-openssl`, `pingora-boringssl`, `pingora-s2n` crates removed
5. `pingora-cache`, `pingora-memory-cache`, `pingora-lru`, `tinyufo` crates renamed and kept (HTTP response caching is useful for a reverse proxy)
6. Conditional compilation for non-rustls TLS backends removed
7. Cloudflare-specific code removed (sentry, cf-rustracing)
8. NOTICE file created crediting Cloudflare Pingora as upstream (Apache-2.0)
9. Deprecated dependencies updated (serde_yaml -> serde_yml, nix 0.24 -> 0.29+)
10. `cargo check` and `cargo test` pass on the stripped codebase

### Integration Verification

- IV1: Existing Pingora unit tests pass (adjusted for renames)
- IV2: rustls TLS backend compiles and links correctly as sole TLS provider
- IV3: No references to removed crates remain in the workspace

---

## Story 1.2: Basic Binary and Structured Logging

As an infrastructure engineer,
I want a `lorica` binary with structured logging and systemd readiness,
so that I can run Lorica as a service with proper log output.

### Acceptance Criteria

1. `lorica` binary crate created with clap CLI (minimal flags: `--version`, `--data-dir`)
2. `tracing` + `tracing-subscriber` integrated for structured JSON logging to stdout
3. Log levels configurable via `RUST_LOG` or `--log-level` flag
4. Startup banner with version, data directory path, and management port
5. SIGTERM/SIGINT handled for graceful shutdown
6. Example systemd unit file created in `dist/lorica.service`

### Integration Verification

- IV1: Binary starts and shuts down cleanly
- IV2: JSON log output is parseable by standard tools (jq)
- IV3: systemd unit file passes `systemd-analyze verify`

---

## Story 1.3: Configuration State and Persistence

As an infrastructure engineer,
I want Lorica to persist its configuration in an embedded database,
so that my routes, backends, and certificates survive restarts.

### Acceptance Criteria

1. `lorica-config` crate created
2. Data model defined: Route, Backend, Certificate, GlobalSettings
3. Embedded SQLite database with WAL mode for crash safety
4. CRUD operations for all data model entities
5. Database file created automatically on first launch in data directory
6. Database migrations system for future schema changes
7. TOML export: serialize full state to a TOML file
8. TOML import: deserialize and load a TOML file into the database
9. Unit tests for all CRUD operations and export/import round-trip

### Integration Verification

- IV1: Database survives unclean shutdown (kill -9) without corruption
- IV2: Export -> wipe -> import produces identical state
- IV3: Schema migration runs automatically on binary upgrade

---

## Story 1.4: REST API Foundation

As an infrastructure engineer,
I want a REST API for managing routes, backends, and certificates,
so that the dashboard (and any automation tool) can control Lorica programmatically.

### Acceptance Criteria

1. `lorica-api` crate created with axum
2. API served on management port (default: 9443), bound to localhost only
3. Authentication: session-based with username/password
4. First-run: generate random admin password, log to stdout once
5. Force password change on first API login
6. Endpoints implemented:
   - `POST /api/auth/login`, `POST /api/auth/logout`, `PUT /api/auth/password`
   - `GET/POST /api/routes`, `GET/PUT/DELETE /api/routes/:id`
   - `GET/POST /api/backends`, `GET/PUT/DELETE /api/backends/:id`
   - `GET/POST /api/certificates`, `GET/PUT/DELETE /api/certificates/:id`
   - `GET /api/status` (proxy state overview)
   - `POST /api/config/export`, `POST /api/config/import`
7. All endpoints return JSON with consistent error format
8. API documentation via OpenAPI/Swagger spec

### Integration Verification

- IV1: Management port refuses connections from non-localhost addresses
- IV2: All CRUD operations correctly persist to embedded database
- IV3: Unauthenticated requests receive 401
- IV4: API responses are valid JSON and follow the documented schema

---

## Story 1.5: Dashboard - Embedded Frontend Skeleton

As an infrastructure engineer,
I want a web dashboard embedded in the Lorica binary,
so that I can manage my reverse proxy from a browser without any additional tool.

### Acceptance Criteria

1. `lorica-dashboard` crate created
2. Frontend framework selected and scaffolded (evaluation: Svelte vs Solid vs htmx)
3. Frontend build integrated into Cargo build pipeline (build.rs or pre-build script)
4. Static assets embedded in binary via `rust-embed`
5. Dashboard served on management port alongside the API
6. Login screen functional (consumes `/api/auth/login`)
7. First-run password change screen functional
8. Navigation skeleton: Overview, Routes, Backends, Certificates, Logs, System, Settings
9. Overview screen: placeholder cards for route count, backend health summary, cert status summary
10. Total embedded asset size < 5MB

### Integration Verification

- IV1: Dashboard loads in browser at `https://localhost:9443`
- IV2: Login flow works end-to-end (auth -> session -> dashboard)
- IV3: Binary size increase from dashboard embedding is < 5MB
- IV4: Dashboard is not accessible from non-localhost addresses

---

## Story 1.6: Dashboard - Route Management

As an infrastructure engineer,
I want to view, create, edit, and delete routes from the dashboard,
so that I can manage my proxy configuration visually.

### Acceptance Criteria

1. Routes list screen: table with input URL, destination, TLS status, health status
2. Route creation form: hostname, path, backend selection, TLS certificate selection
3. Route edit: inline or modal editing of all route parameters
4. Route delete: confirmation dialog before deletion
5. Status indicators: green (healthy), orange (degraded), red (down)
6. All operations go through the REST API

### Integration Verification

- IV1: Route created in dashboard appears in API `GET /api/routes`
- IV2: Route deleted in dashboard is removed from proxy configuration
- IV3: Dashboard reflects current state after page refresh

---

## Story 1.7: Dashboard - Certificate Management

As an infrastructure engineer,
I want to manage TLS certificates from the dashboard,
so that I can upload, monitor, and replace certificates without SSH.

### Acceptance Criteria

1. Certificates list screen: domain, issuer, expiration date, status (valid/expiring/expired)
2. Certificate upload: PEM file upload (cert + key) via dashboard
3. Certificate detail: full certificate chain display, associated routes
4. Expiration thresholds: warning at 30 days, critical at 7 days (configurable)
5. Self-signed certificate generation: prompt with preference memory (never/always/once)
6. Certificate deletion: confirmation with impact display (which routes affected)

### Integration Verification

- IV1: Uploaded certificate is usable for TLS termination on configured routes
- IV2: Expiration status is calculated correctly based on current date
- IV3: Certificate deletion blocks if routes still reference it (or shows warning)

---

## Story 1.8: Proxy Engine Wiring

As an infrastructure engineer,
I want Lorica to actually proxy HTTP traffic based on my dashboard configuration,
so that the routes I configure in the UI are live and serving traffic.

### Acceptance Criteria

1. `ProxyHttp` trait implementation that reads route configuration from embedded database
2. Host-based and path-based routing from configuration state
3. Backend selection with round-robin load balancing
4. TLS termination using certificates from the embedded store
5. Proxy listeners start/stop dynamically as routes are added/removed
6. Configuration changes take effect without binary restart (API triggers re-read of config state)
7. Health check implementation: TCP health check for backends, status reflected in API and dashboard
8. Access logging: structured JSON log per request (method, path, status, latency, backend)

### Integration Verification

- IV1: HTTP request to a configured route is proxied to the correct backend
- IV2: HTTPS request terminates TLS and proxies to backend
- IV3: Adding a new route via API makes it live without restart
- IV4: Removing a route via API stops proxying for that hostname/path
- IV5: Backend marked unhealthy is removed from rotation

---

## Story 1.9: Dashboard - Logs and System Monitoring

As an infrastructure engineer,
I want to view access logs and system resource usage in the dashboard,
so that I have full visibility into my proxy's operation.

### Acceptance Criteria

1. Logs screen: scrollable access log with filtering (by route, status code, time range)
2. Log search: text search across log entries
3. System screen: CPU, RAM, and disk usage of the host machine
4. System screen: Lorica process memory and CPU usage
5. System screen: uptime, version, active connection count
6. Metrics refresh automatically (polling or WebSocket)

### Integration Verification

- IV1: Proxied requests appear in the logs screen within 2 seconds
- IV2: System metrics match values from system tools (top, free, df)
- IV3: Log filtering correctly narrows displayed entries

---

## Story 1.10: Configuration Export/Import and Settings

As an infrastructure engineer,
I want to export my full configuration and adjust global settings from the dashboard,
so that I can backup, share, and restore my proxy setup.

### Acceptance Criteria

1. Settings screen: global configuration (management port display, log level, default health check interval)
2. Export button: downloads current state as a TOML file
3. Import function: upload a TOML file, preview changes, apply with confirmation
4. Import shows diff: what will be added, modified, or removed
5. Settings for notification preferences (stdout always on, email/webhook configuration)
6. Preference memory UI: manage stored preferences (never/always/once decisions)

### Integration Verification

- IV1: Exported TOML can be imported on a fresh Lorica instance and produce identical configuration
- IV2: Import preview accurately reflects the changes that will be applied
- IV3: Settings changes take effect immediately without restart
