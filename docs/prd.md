# Lorica Brownfield Enhancement PRD

**Author:** Romain G.
**Date:** 2026-03-28
**Status:** Draft
**Version:** 1.0

---

## 1. Intro Project Analysis and Context

### 1.1 Analysis Source

- Project brief available at: `docs/brief.md`
- Architecture (sharded) available at: `docs/architecture/`
- Brainstorming results available at: `docs/brainstorming-session-results.md`

### 1.2 Current Project State

Lorica does not yet exist as code. The "existing project" is **Cloudflare Pingora v0.8.0**, an open-source Rust reverse proxy framework (Apache-2.0) that will be forked as the foundation.

Pingora provides:
- A battle-tested HTTP/1.1, HTTP/2, WebSocket, and gRPC proxy engine
- Connection pooling (lock-free), load balancing (Round Robin, Consistent Hash, Random)
- TLS termination via multiple backends (OpenSSL, BoringSSL, rustls, s2n)
- Graceful restart via FD transfer
- A custom tokio runtime with work-stealing and pinned modes
- 20 Cargo crates in a workspace

Pingora does **not** provide:
- Any configuration format (all logic is Rust code)
- Any REST API or management interface
- Any dashboard or web UI
- Any declarative routing
- Any structured logging or metrics
- Any WAF capability

The enhancement is to transform this framework into a **dashboard-first, self-administered reverse proxy product**.

### 1.3 Available Documentation Analysis

- [x] Tech Stack Documentation - `docs/architecture/tech-stack.md`
- [x] Source Tree/Architecture - `docs/architecture/source-tree.md`
- [ ] Coding Standards - To be defined
- [ ] API Documentation - To be created (new)
- [ ] External API Documentation - N/A
- [ ] UX/UI Guidelines - To be defined
- [ ] Technical Debt Documentation - N/A (fresh fork)

### 1.4 Enhancement Scope Definition

#### Enhancement Type

- [x] New Feature Addition
- [x] Major Feature Modification
- [ ] Integration with New Systems
- [x] Performance/Scalability Improvements
- [ ] UI/UX Overhaul
- [x] Technology Stack Upgrade
- [ ] Bug Fix and Stability Improvements
- [x] Other: Framework-to-product transformation

#### Enhancement Description

Transform Pingora from a Rust proxy framework (requiring custom code for every deployment) into Lorica, a complete dashboard-first reverse proxy product. This involves stripping unused TLS backends, adding a declarative configuration layer, building a REST API, embedding a web dashboard, implementing topology-aware backend management, and adding an optional WAF layer.

#### Impact Assessment

- [ ] Minimal Impact (isolated additions)
- [ ] Moderate Impact (some existing code changes)
- [ ] Significant Impact (substantial existing code changes)
- [x] Major Impact (architectural changes required)

The core proxy engine remains intact, but the project wraps it in an entirely new product layer (API, dashboard, config, CLI, WAF) and will later replace the concurrency model (threads to process isolation).

### 1.5 Goals and Background Context

#### Goals

- Replace Nginx on production infrastructure with full visibility and control
- Provide a 2-minute onboarding experience: `apt install lorica` -> browser -> configure
- Deliver a single binary with embedded dashboard, zero runtime dependencies
- Enable consent-driven proxy management where nothing happens without admin approval
- Offer optional WAF capabilities based on community rulesets (OWASP CRS)
- Adapt proxy behavior to backend topology (single VM, HA, Docker, K8S)
- Achieve Pingora-level performance (< 1ms added latency, 10K+ concurrent connections per worker)

#### Background Context

Current reverse proxies are either opaque config-file daemons (Nginx) or Go-based tools with different trade-offs (Caddy, Traefik). No existing product combines Rust performance, a dashboard-first approach, Apache-2.0 licensing, and integrated WAF capabilities. Pingora proved Rust works at scale for proxying; Sozu proved process isolation and hot-reload work in Rust. Neither is a complete product. Lorica fills this gap by forking Pingora and building the missing product layer on top, with architectural patterns inspired by Sozu.

### 1.6 Change Log

| Change | Date | Version | Description | Author |
|--------|------|---------|-------------|--------|
| Initial PRD | 2026-03-28 | 1.0 | First draft based on project brief and brainstorming | Romain G. |

---

## 2. Requirements

### 2.1 Functional Requirements

**Core Proxy**

- **FR1:** Lorica shall proxy HTTP/1.1 and HTTP/2 traffic from configured frontend routes to backend servers.
- **FR2:** Lorica shall support WebSocket upgrade and proxy WebSocket traffic transparently.
- **FR3:** Lorica shall terminate TLS using rustls (no OpenSSL) with support for TLS 1.2 and 1.3.
- **FR4:** Lorica shall support SNI-based routing to select the correct certificate and backend per hostname.
- **FR5:** Lorica shall provide load balancing across multiple backends per route (Round Robin, Consistent Hash, Random, Peak EWMA).
- **FR6:** Lorica shall perform health checks on backends and remove unhealthy backends from rotation.
- **FR7:** Lorica shall support graceful restart without dropping active connections (FD transfer).

**Dashboard & API**

- **FR8:** Lorica shall expose a REST API for full CRUD operations on routes, backends, certificates, and configuration.
- **FR9:** Lorica shall serve an embedded web dashboard on a localhost-only management port (default: 9443).
- **FR10:** The dashboard shall display all configured routes with their input URLs and output destinations.
- **FR11:** The dashboard shall display TLS certificate status (valid, expiring soon, expired) with expiration dates for each route.
- **FR12:** The dashboard shall display backend health status (healthy, degraded, down) for each backend.
- **FR13:** The dashboard shall display transfer latency metrics per route.
- **FR14:** The dashboard shall display access logs with filtering and search capabilities.
- **FR15:** The dashboard shall provide a security panel showing scan attempts, access attempts on known admin endpoints, and blocked requests (when WAF is active).
- **FR16:** The dashboard shall display host machine resource utilization (CPU, RAM, disk).
- **FR17:** The dashboard shall allow creating, editing, and deleting routes, backends, and certificates without restarting Lorica.

**Onboarding & Auth**

- **FR18:** On first launch, Lorica shall generate a temporary admin password and display it once in stdout.
- **FR19:** On first login, the dashboard shall force a password change.
- **FR20:** Lorica shall run as a systemd service immediately after package installation.
- **FR21:** The proxy data plane shall not listen on any port until at least one route is configured.

**Configuration & State**

- **FR22:** Lorica shall persist its configuration state in an embedded store (not flat config files).
- **FR23:** Lorica shall support exporting the full configuration as a TOML file for backup and sharing.
- **FR24:** Lorica shall support importing a TOML configuration file to bootstrap or restore state.
- **FR25:** Lorica shall remember user preferences for recurring decisions (e.g., self-signed cert: never/always/once).

**Consent-Driven Design**

- **FR26:** Lorica shall never perform automated actions (certificate provisioning, backend removal, WAF blocking) without explicit admin approval or pre-configured opt-in.
- **FR27:** When no TLS certificate is configured for a route, Lorica shall propose options: manual upload, ACME auto-provisioning, or self-signed certificate - and wait for admin decision.

**Notifications**

- **FR28:** Lorica shall emit structured log events to stdout (JSON format) for all significant events (cert expiry warnings, backend state changes, security events).
- **FR29:** Lorica shall support email notifications for configurable alert types.
- **FR30:** Lorica shall support webhook notifications for configurable alert types.

**WAF (Optional Layer)**

- **FR31:** Lorica shall support an optional WAF mode that can be enabled per route.
- **FR32:** When WAF is disabled, Lorica shall still alert on suspicious patterns in logs (alerting by default).
- **FR33:** WAF rules shall be based on OWASP Core Rule Set (CRS) with regular update support.
- **FR34:** WAF shall operate in detection-only or blocking mode, configurable per route.

**Topology Awareness**

- **FR35:** Lorica shall allow configuring backend topology type per backend group (single VM, HA pair, Docker Swarm, Kubernetes).
- **FR36:** Lorica shall adapt its health check and failover behavior based on the configured topology type.
- **FR37:** Topology rules shall support a two-level hierarchy: global defaults overridden by per-route/per-backend configuration.

**Worker Isolation**

- **FR38:** Lorica shall isolate proxy workers in separate OS processes (fork+exec model).
- **FR39:** If a worker process crashes, other workers shall continue serving traffic.
- **FR40:** Configuration changes shall be propagated to workers via a command channel without restarting worker processes.

**SLA Monitoring**

- **FR41:** Lorica shall compute passive SLA metrics (uptime, latency, error rate) from real user traffic per route.
- **FR42:** Lorica shall send active synthetic probes to backends at configurable intervals to measure internal SLA independently of user traffic.
- **FR43:** The dashboard shall display both passive (public/contractual) and active (internal/engineering) SLA metrics per route with historical trends.
- **FR44:** Lorica shall alert when SLA drops below configurable thresholds (per route, per SLA type).

**Load Testing**

- **FR45:** Lorica shall generate simulated HTTP traffic to backends for load testing (real requests, simulated client).
- **FR46:** Load tests shall be launchable on demand from the dashboard with configurable parameters (concurrent connections, duration, request pattern).
- **FR47:** Load tests shall be schedulable for recurring execution (e.g., weekly) with historical result comparison.
- **FR48:** Load test parameters shall have default safe limits with confirmation required to exceed them.
- **FR49:** Load tests shall auto-abort when backend error rate exceeds a configurable threshold.
- **FR50:** Load test results shall be displayed in real-time in the dashboard during execution, and stored for historical comparison.

### 2.2 Non-Functional Requirements

- **NFR1:** Proxy latency overhead shall be < 1ms per request under normal load (comparable to Pingora benchmarks).
- **NFR2:** Each worker shall support 10,000+ concurrent connections.
- **NFR3:** Dashboard pages shall load in < 200ms.
- **NFR4:** Base binary size (including embedded dashboard assets) shall be < 50MB.
- **NFR5:** Startup time from service start to accepting traffic shall be < 2 seconds.
- **NFR6:** Lorica shall compile and run on Linux x86_64 and aarch64. macOS support for development.
- **NFR7:** All code shall be written in Rust with strict clippy lints and formatted with rustfmt.
- **NFR8:** The codebase shall be fully auditable: no closed-source dependencies, no C code beyond system libraries.
- **NFR9:** The management port shall bind exclusively to localhost (127.0.0.1 / ::1) by default with no option to change this in the dashboard.
- **NFR10:** Lorica shall produce structured JSON logs to stdout, compatible with SIEM/XDR ingestion.
- **NFR11:** Memory usage shall remain stable over time with no unbounded growth (no memory leaks).
- **NFR12:** Configuration state persistence shall survive unclean shutdowns (crash-safe storage).

### 2.3 Compatibility Requirements

- **CR1: Pingora API Compatibility** - Lorica shall maintain compatibility with the `ProxyHttp` trait from Pingora for the proxy engine internals. Custom filters and modules written against Pingora's API should remain functional.
- **CR2: TLS Compatibility** - Lorica shall support all TLS configurations that rustls supports (TLS 1.2, TLS 1.3, standard cipher suites, ECDSA and RSA certificates).
- **CR3: HTTP Standards Compliance** - Lorica shall comply with HTTP/1.1 (RFC 9110/9112) and HTTP/2 (RFC 9113) standards as inherited from Pingora's proxy engine.
- **CR4: Export Format Stability** - The TOML export/import format shall be versioned. Lorica shall be able to import configurations from any prior format version.

---

## 3. User Interface Enhancement Goals

### 3.1 Integration with Existing UI

There is no existing UI - this is a greenfield dashboard built as an integral part of Lorica. The dashboard is the primary management interface, designed from day one alongside the proxy engine.

**Design principles:**
- Appliance-style UI (think network router admin panel, not SaaS dashboard)
- Functional over aesthetic - clarity and information density over visual polish
- Every proxy feature has a corresponding dashboard representation
- Consent-driven: actions require confirmation, preferences are remembered

### 3.2 Modified/New Screens and Views

| Screen | Purpose | Priority |
|--------|---------|----------|
| **Login** | Authentication, first-run password change | MVP |
| **Overview / Dashboard** | At-a-glance status: routes count, backend health, cert status, system resources | MVP |
| **Routes** | List all routes (input URL -> output destination), cert status per route, latency | MVP |
| **Route Detail** | Single route config: backends, TLS, health checks, WAF toggle, topology | MVP |
| **Backends** | List all backends, health status, active connections, response times | MVP |
| **Certificates** | All certs with expiry dates, status (valid/expiring/expired), upload/ACME actions | MVP |
| **Logs** | Access logs with filtering, search, time range selection | MVP |
| **Security** | Scan attempts, admin endpoint probes, WAF blocked requests, trends | Phase 2 |
| **SLA** | Passive (public) and active (internal) SLA per route, historical trends | Phase 3 |
| **Load Tests** | On-demand and scheduled load tests, real-time results, historical comparison | Phase 3 |
| **System** | CPU, RAM, disk of host machine, worker process status | MVP |
| **Settings** | Global rules, notification config (stdout/email/webhook), export/import | MVP |

### 3.3 UI Consistency Requirements

- Consistent navigation pattern across all screens (sidebar or top nav)
- Uniform status indicators: green (healthy/valid), orange (warning/expiring), red (down/expired)
- All destructive actions require explicit confirmation
- Preference memory for recurring decisions (never ask again / always / ask each time)
- Responsive layout for desktop browsers (mobile is not a priority)

---

## 4. Technical Constraints and Integration Requirements

### 4.1 Existing Technology Stack

**Languages:** Rust (proxy engine, API, CLI), JavaScript/TypeScript (dashboard frontend)
**Frameworks:**
- Proxy: Pingora fork (tokio, h2, httparse)
- API: axum or actix-web (to be evaluated)
- Frontend: Svelte, Solid, or htmx (to be evaluated - must produce small bundle for embedding)
**Database:** Embedded (SQLite or sled - to be evaluated)
**Infrastructure:** Single binary, systemd service, Linux primary target
**External Dependencies:**
- rustls 0.23+ (TLS)
- tokio 1 (async runtime)
- OWASP CRS rulesets (WAF, Phase 2+)

### 4.2 Integration Approach

**State Persistence Strategy:** Embedded database (SQLite or sled) for all configuration state. No external database dependency. The database file lives alongside the binary or in a configurable data directory.

**API Integration Strategy:** REST API (JSON) is the single source of truth for all operations. The dashboard is a pure consumer of the API. The CLI (if any) also consumes the API. No operation bypasses the API.

**Frontend Integration Strategy:** Dashboard frontend is compiled to static assets and embedded in the Rust binary via `rust-embed`. Served by the management port listener (localhost:9443). Completely isolated from the proxy data plane.

**Testing Integration Strategy:**
- Rust: unit tests per crate, integration tests for API and proxy behavior
- Frontend: component tests for dashboard
- E2E: full proxy + dashboard tests with real HTTP traffic
- Inherited Pingora tests remain functional for proxy engine

### 4.3 Code Organization and Standards

**File Structure Approach:** Cargo workspace mirroring Pingora's crate structure with new Lorica-specific crates added:

```
lorica/
  lorica/                  # Main binary + CLI
  lorica-core/             # Fork of pingora-core
  lorica-proxy/            # Fork of pingora-proxy
  lorica-http/             # Fork of pingora-http
  lorica-error/            # Fork of pingora-error
  lorica-pool/             # Fork of pingora-pool
  lorica-runtime/          # Fork of pingora-runtime
  lorica-timeout/          # Fork of pingora-timeout
  lorica-tls/              # Fork of pingora-rustls (promoted to primary)
  lorica-lb/               # Fork of pingora-load-balancing
  lorica-ketama/           # Fork of pingora-ketama
  lorica-limits/           # Fork of pingora-limits
  lorica-header-serde/     # Fork of pingora-header-serde
  lorica-config/           # NEW - config state, persistence, export/import
  lorica-command/          # NEW - command channel (Phase 2)
  lorica-worker/           # NEW - process isolation (Phase 2)
  lorica-api/              # NEW - REST API (axum/actix-web)
  lorica-dashboard/        # NEW - frontend assets + embedding
  lorica-waf/              # NEW - WAF engine (Phase 2+)
  lorica-notify/           # NEW - notification channels
  docs/
  tests/
  e2e/
```

**Naming Conventions:** Rust standard (snake_case for functions/variables, CamelCase for types, SCREAMING_SNAKE for constants). All `pingora_*` references renamed to `lorica_*`.

**Coding Standards:** As defined in CLAUDE.md - strict clippy, rustfmt, doc comments on public APIs, no leftover TODOs or debug prints.

**Documentation Standards:** Rust doc comments (`///`) on all public items. Architecture decisions documented in `docs/`.

### 4.4 Deployment and Operations

**Build Process:** `cargo build --release` produces a single static binary with embedded dashboard assets. Frontend build step integrated via `build.rs` or pre-build script.

**Deployment Strategy:**
- Primary: `.deb` package for apt-based distributions
- Secondary: static binary download from GitHub releases
- Future: `.rpm`, Docker image, Helm chart
- Systemd service file included in package

**Monitoring and Logging:**
- Structured JSON logs to stdout (tracing + tracing-subscriber)
- Prometheus metrics endpoint (`/metrics` on management port)
- Dashboard provides built-in monitoring views

**Configuration Management:**
- State persisted in embedded database
- Export/import via TOML for backup, migration, and sharing
- No config file required for normal operation
- Environment variable support for sensitive values (e.g., SMTP password for email notifications)

### 4.5 Risk Assessment and Mitigation

**Technical Risks:**
- rustls is marked "experimental" in Pingora - needs hardening and extensive test coverage
- Embedded database choice (SQLite vs sled) affects crash safety and performance characteristics
- Frontend framework choice affects bundle size and long-term maintainability
- WAF rule engine performance could impact proxy latency if not carefully isolated

**Integration Risks:**
- Replacing Pingora's thread model with process isolation (Phase 2) touches deep internals
- Dashboard frontend build pipeline adds complexity to the Rust build process
- OWASP CRS rules are designed for ModSecurity - adapting them to Rust requires a compatibility layer

**Deployment Risks:**
- systemd integration must handle graceful upgrades correctly
- Embedded database file must survive package upgrades without data loss
- First-run credential generation must be secure and race-condition free

**Mitigation Strategies:**
- Start with SQLite (battle-tested, crash-safe with WAL mode) - switch to sled only if performance requires it
- Implement comprehensive TLS test suite early, including fuzz testing
- Isolate WAF processing in a separate async task to avoid blocking proxy hot path
- Package upgrade scripts preserve data directory and database files
- Frontend framework evaluation before Phase 1 implementation begins

---

## 5. Epic and Story Structure

### Epic Approach

**Epic Structure Decision:** Four epics aligned with the phased delivery strategy. Each epic is self-contained and delivers incremental value. The dashboard-first approach means the API and dashboard are built alongside the proxy from Epic 1, not deferred.

| Epic | Title | Focus |
|------|-------|-------|
| Epic 1 | Foundation - Fork, Strip, and Product Skeleton | Proxy + API + Dashboard MVP |
| Epic 2 | Resilience - Worker Isolation and Hot-Reload | Process isolation, command channel, cert hot-swap |
| Epic 3 | Intelligence - WAF and Topology Awareness | WAF layer, topology-aware backends, notifications |
| Epic 4 | Production - ACME, Metrics, and Packaging | Auto-TLS, Prometheus, packaging, hardening |

---

## 6. Epic 1: Foundation - Fork, Strip, and Product Skeleton

**Epic Goal:** Transform the Pingora fork into a working Lorica product with proxy engine, REST API, embedded dashboard, and basic route/backend/certificate management.

**Integration Requirements:** Pingora proxy engine remains functional throughout. Each story adds a product layer without breaking existing proxy capabilities.

### Story 1.1: Fork and Strip Pingora

As an infrastructure engineer,
I want a clean Lorica codebase forked from Pingora with unused components removed,
so that I have a minimal, focused foundation to build on.

#### Acceptance Criteria

1. Pingora repository cloned, git history removed, fresh repository initialized
2. All crates renamed from `pingora-*` to `lorica-*`
3. All internal `use pingora_*` references updated to `lorica_*`
4. `pingora-openssl`, `pingora-boringssl`, `pingora-s2n` crates removed
5. `pingora-cache`, `pingora-memory-cache`, `pingora-lru`, `tinyufo` crates removed
6. Conditional compilation for non-rustls TLS backends removed
7. Cloudflare-specific code removed (sentry, cf-rustracing)
8. NOTICE file created crediting Cloudflare Pingora as upstream (Apache-2.0)
9. Deprecated dependencies updated (serde_yaml -> serde_yml, nix 0.24 -> 0.29+)
10. `cargo check` and `cargo test` pass on the stripped codebase

#### Integration Verification

- IV1: Existing Pingora unit tests pass (adjusted for renames)
- IV2: rustls TLS backend compiles and links correctly as sole TLS provider
- IV3: No references to removed crates remain in the workspace

---

### Story 1.2: Basic Binary and Structured Logging

As an infrastructure engineer,
I want a `lorica` binary with structured logging and systemd readiness,
so that I can run Lorica as a service with proper log output.

#### Acceptance Criteria

1. `lorica` binary crate created with clap CLI (minimal flags: `--version`, `--data-dir`)
2. `tracing` + `tracing-subscriber` integrated for structured JSON logging to stdout
3. Log levels configurable via `RUST_LOG` or `--log-level` flag
4. Startup banner with version, data directory path, and management port
5. SIGTERM/SIGINT handled for graceful shutdown
6. Example systemd unit file created in `dist/lorica.service`

#### Integration Verification

- IV1: Binary starts and shuts down cleanly
- IV2: JSON log output is parseable by standard tools (jq)
- IV3: systemd unit file passes `systemd-analyze verify`

---

### Story 1.3: Configuration State and Persistence

As an infrastructure engineer,
I want Lorica to persist its configuration in an embedded database,
so that my routes, backends, and certificates survive restarts.

#### Acceptance Criteria

1. `lorica-config` crate created
2. Data model defined: Route, Backend, Certificate, GlobalSettings
3. Embedded SQLite database with WAL mode for crash safety
4. CRUD operations for all data model entities
5. Database file created automatically on first launch in data directory
6. Database migrations system for future schema changes
7. TOML export: serialize full state to a TOML file
8. TOML import: deserialize and load a TOML file into the database
9. Unit tests for all CRUD operations and export/import round-trip

#### Integration Verification

- IV1: Database survives unclean shutdown (kill -9) without corruption
- IV2: Export -> wipe -> import produces identical state
- IV3: Schema migration runs automatically on binary upgrade

---

### Story 1.4: REST API Foundation

As an infrastructure engineer,
I want a REST API for managing routes, backends, and certificates,
so that the dashboard (and any automation tool) can control Lorica programmatically.

#### Acceptance Criteria

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

#### Integration Verification

- IV1: Management port refuses connections from non-localhost addresses
- IV2: All CRUD operations correctly persist to embedded database
- IV3: Unauthenticated requests receive 401
- IV4: API responses are valid JSON and follow the documented schema

---

### Story 1.5: Dashboard - Embedded Frontend Skeleton

As an infrastructure engineer,
I want a web dashboard embedded in the Lorica binary,
so that I can manage my reverse proxy from a browser without any additional tool.

#### Acceptance Criteria

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

#### Integration Verification

- IV1: Dashboard loads in browser at `https://localhost:9443`
- IV2: Login flow works end-to-end (auth -> session -> dashboard)
- IV3: Binary size increase from dashboard embedding is < 5MB
- IV4: Dashboard is not accessible from non-localhost addresses

---

### Story 1.6: Dashboard - Route Management

As an infrastructure engineer,
I want to view, create, edit, and delete routes from the dashboard,
so that I can manage my proxy configuration visually.

#### Acceptance Criteria

1. Routes list screen: table with input URL, destination, TLS status, health status
2. Route creation form: hostname, path, backend selection, TLS certificate selection
3. Route edit: inline or modal editing of all route parameters
4. Route delete: confirmation dialog before deletion
5. Status indicators: green (healthy), orange (degraded), red (down)
6. All operations go through the REST API

#### Integration Verification

- IV1: Route created in dashboard appears in API `GET /api/routes`
- IV2: Route deleted in dashboard is removed from proxy configuration
- IV3: Dashboard reflects current state after page refresh

---

### Story 1.7: Dashboard - Certificate Management

As an infrastructure engineer,
I want to manage TLS certificates from the dashboard,
so that I can upload, monitor, and replace certificates without SSH.

#### Acceptance Criteria

1. Certificates list screen: domain, issuer, expiration date, status (valid/expiring/expired)
2. Certificate upload: PEM file upload (cert + key) via dashboard
3. Certificate detail: full certificate chain display, associated routes
4. Expiration thresholds: warning at 30 days, critical at 7 days (configurable)
5. Self-signed certificate generation: prompt with preference memory (never/always/once)
6. Certificate deletion: confirmation with impact display (which routes affected)

#### Integration Verification

- IV1: Uploaded certificate is usable for TLS termination on configured routes
- IV2: Expiration status is calculated correctly based on current date
- IV3: Certificate deletion blocks if routes still reference it (or shows warning)

---

### Story 1.8: Proxy Engine Wiring

As an infrastructure engineer,
I want Lorica to actually proxy HTTP traffic based on my dashboard configuration,
so that the routes I configure in the UI are live and serving traffic.

#### Acceptance Criteria

1. `ProxyHttp` trait implementation that reads route configuration from embedded database
2. Host-based and path-based routing from configuration state
3. Backend selection with round-robin load balancing
4. TLS termination using certificates from the embedded store
5. Proxy listeners start/stop dynamically as routes are added/removed
6. Configuration changes take effect without binary restart (API triggers re-read of config state)
7. Health check implementation: TCP health check for backends, status reflected in API and dashboard
8. Access logging: structured JSON log per request (method, path, status, latency, backend)

#### Integration Verification

- IV1: HTTP request to a configured route is proxied to the correct backend
- IV2: HTTPS request terminates TLS and proxies to backend
- IV3: Adding a new route via API makes it live without restart
- IV4: Removing a route via API stops proxying for that hostname/path
- IV5: Backend marked unhealthy is removed from rotation

---

### Story 1.9: Dashboard - Logs and System Monitoring

As an infrastructure engineer,
I want to view access logs and system resource usage in the dashboard,
so that I have full visibility into my proxy's operation.

#### Acceptance Criteria

1. Logs screen: scrollable access log with filtering (by route, status code, time range)
2. Log search: text search across log entries
3. System screen: CPU, RAM, and disk usage of the host machine
4. System screen: Lorica process memory and CPU usage
5. System screen: uptime, version, active connection count
6. Metrics refresh automatically (polling or WebSocket)

#### Integration Verification

- IV1: Proxied requests appear in the logs screen within 2 seconds
- IV2: System metrics match values from system tools (top, free, df)
- IV3: Log filtering correctly narrows displayed entries

---

### Story 1.10: Configuration Export/Import and Settings

As an infrastructure engineer,
I want to export my full configuration and adjust global settings from the dashboard,
so that I can backup, share, and restore my proxy setup.

#### Acceptance Criteria

1. Settings screen: global configuration (management port display, log level, default health check interval)
2. Export button: downloads current state as a TOML file
3. Import function: upload a TOML file, preview changes, apply with confirmation
4. Import shows diff: what will be added, modified, or removed
5. Settings for notification preferences (stdout always on, email/webhook configuration)
6. Preference memory UI: manage stored preferences (never/always/once decisions)

#### Integration Verification

- IV1: Exported TOML can be imported on a fresh Lorica instance and produce identical configuration
- IV2: Import preview accurately reflects the changes that will be applied
- IV3: Settings changes take effect immediately without restart

---

## 7. Epic 2: Resilience - Worker Isolation and Hot-Reload

**Epic Goal:** Implement process-based worker isolation, a command channel for hot-reload, and certificate hot-swap - making Lorica resilient to worker crashes and capable of zero-downtime reconfiguration.

**Integration Requirements:** The proxy engine from Epic 1 must continue functioning. Worker isolation wraps the existing proxy in separate processes. The command channel replaces direct database reads with push-based configuration updates.

### Story 2.1: Process-Based Worker Isolation

As an infrastructure engineer,
I want proxy workers to run in separate OS processes,
so that a crash or compromise in one worker does not affect others.

#### Acceptance Criteria

1. `lorica-worker` crate created
2. Main process forks worker processes via fork+exec
3. Each worker runs the proxy engine independently
4. Configurable worker count (default: number of CPU cores)
5. Main process monitors workers and restarts crashed workers
6. Worker crash logged with structured event
7. Listening socket FDs passed to workers via SCM_RIGHTS

#### Integration Verification

- IV1: Killing a worker process (kill -9) does not affect other workers
- IV2: Crashed worker is restarted automatically within 1 second
- IV3: Traffic continues flowing through surviving workers during worker restart

---

### Story 2.2: Command Channel

As an infrastructure engineer,
I want configuration changes to propagate to workers without restart,
so that I can reconfigure my proxy with zero downtime.

#### Acceptance Criteria

1. `lorica-command` crate created
2. Unix socket pair between main process and each worker
3. Protobuf message format with custom framing (8-byte LE size prefix)
4. Configuration diff generation: compare current state with new state, produce minimal changeset
5. Main process dispatches changes to all workers
6. Workers apply changes inline without pausing traffic
7. Three-state response protocol: Ok, Error, Processing
8. Command channel health monitoring (detect unresponsive workers)

#### Integration Verification

- IV1: Route added via API is live on all workers within 1 second
- IV2: No connections are dropped during configuration change
- IV3: Worker reports Error state when a change cannot be applied

---

### Story 2.3: Certificate Hot-Swap

As an infrastructure engineer,
I want to add, replace, and remove TLS certificates without any downtime,
so that certificate rotation is seamless.

#### Acceptance Criteria

1. SNI trie for fast domain-to-certificate lookup (wildcard support)
2. Certificate index: multiple certs per domain, sorted by expiration
3. Add operation: new cert replaces shorter-lived certs automatically
4. Remove operation: fallback to longest-lived remaining cert
5. Replace operation: atomic delete + add
6. Changes propagated to workers via command channel
7. Active TLS connections continue with old cert until they close naturally

#### Integration Verification

- IV1: New certificate is served to new connections within 1 second of upload
- IV2: Existing connections continue on old certificate without interruption
- IV3: Wildcard certificates match subdomains correctly

---

### Story 2.4: Backend Lifecycle Management

As an infrastructure engineer,
I want backends to drain gracefully when removed,
so that active requests complete without errors.

#### Acceptance Criteria

1. Backend states: Normal, Closing, Closed
2. Removing a backend sets it to Closing (no new connections, drain existing)
3. Transition to Closed when active connection count reaches 0
4. Configurable drain timeout (default: 30 seconds, then force close)
5. Backend state visible in dashboard and API
6. Retry policy: exponential backoff (max 6 retries)

#### Integration Verification

- IV1: Active requests complete successfully when backend is set to Closing
- IV2: No new requests are sent to a Closing backend
- IV3: Backend transitions to Closed after drain completes

---

## 8. Epic 3: Intelligence - WAF and Topology Awareness

**Epic Goal:** Add an optional WAF layer with OWASP CRS rules, topology-aware backend management, and notification channels.

**Integration Requirements:** WAF processing must not impact proxy latency for routes where WAF is disabled. Topology awareness integrates with the existing health check and load balancing systems.

### Story 3.1: WAF Engine with OWASP CRS

As an infrastructure engineer,
I want an optional WAF that detects and blocks common attacks,
so that my backends are protected without needing a separate WAF tool.

#### Acceptance Criteria

1. `lorica-waf` crate created
2. OWASP CRS ruleset loading and parsing
3. WAF evaluation pipeline: inspect request headers, path, query, body against rules
4. Two modes per route: detection-only (log) or blocking (403)
5. WAF toggle per route in dashboard and API
6. Alerting by default: even without WAF enabled, suspicious patterns logged
7. WAF events visible in dashboard security panel
8. Performance: < 0.5ms added latency for WAF evaluation

#### Integration Verification

- IV1: Known attack patterns (SQL injection, XSS, path traversal) are detected
- IV2: WAF in blocking mode returns 403 for matched requests
- IV3: WAF in detection mode logs the event but proxies the request normally
- IV4: Routes without WAF enabled have zero WAF latency overhead

---

### Story 3.2: Topology-Aware Backend Management

As an infrastructure engineer,
I want Lorica to adapt its behavior based on my backend infrastructure type,
so that health checks and failover match my actual setup.

#### Acceptance Criteria

1. Topology types: SingleVM, HA, DockerSwarm, Kubernetes, Custom
2. SingleVM: no active health checks, passive failure detection only
3. HA: active health checks, automatic failover to standby
4. DockerSwarm: service discovery via Docker API, drain on container removal
5. Kubernetes: pod discovery via K8S API, awareness of readiness/liveness
6. Custom: user-defined health check and failover rules
7. Global topology defaults configurable in settings
8. Per-backend topology override in route configuration
9. Dashboard shows topology type and adapted behavior per backend

#### Integration Verification

- IV1: SingleVM backend has no health check probes
- IV2: HA backend fails over to standby when primary is down
- IV3: Topology change via dashboard adjusts health check behavior immediately

---

### Story 3.3: Notification Channels

As an infrastructure engineer,
I want to receive notifications for critical events via email or webhook,
so that I am alerted without watching the dashboard constantly.

#### Acceptance Criteria

1. `lorica-notify` crate created
2. Notification types: cert_expiring, backend_down, waf_alert, config_changed
3. Stdout channel: always on, structured JSON log events
4. Email channel: SMTP configuration in settings, configurable alert types
5. Webhook channel: URL + optional auth header, configurable alert types
6. Notification preferences per alert type (enable/disable per channel)
7. Test notification button in dashboard settings
8. Notification history viewable in dashboard

#### Integration Verification

- IV1: Certificate approaching expiration triggers configured notifications
- IV2: Backend going down triggers notification within configured threshold
- IV3: Webhook delivers valid JSON payload to configured URL

---

## 9. Epic 4: Production - ACME, Metrics, and Packaging

**Epic Goal:** Add automatic certificate provisioning, Prometheus metrics, and production packaging for distribution.

**Integration Requirements:** ACME integration works with the existing certificate management system. Metrics endpoint is served on the management port alongside the API and dashboard.

### Story 4.1: ACME / Let's Encrypt Integration

As an infrastructure engineer,
I want Lorica to automatically provision TLS certificates via Let's Encrypt,
so that I don't have to manage certificates manually.

#### Acceptance Criteria

1. ACME client implementation (HTTP-01 challenge)
2. Opt-in per route: admin explicitly enables auto-TLS (consent-driven)
3. Automatic renewal before expiration (configurable threshold, default 30 days)
4. Renewal requires consent or pre-configured auto-approval preference
5. Fallback: if ACME fails, notify admin and continue with existing cert
6. Certificate storage in embedded database alongside manually uploaded certs
7. Dashboard shows ACME-managed vs manually-managed certificates

#### Integration Verification

- IV1: ACME provisioning successfully obtains a certificate from Let's Encrypt staging
- IV2: Auto-renewal triggers at configured threshold
- IV3: ACME failure does not disrupt existing TLS termination

---

### Story 4.2: Prometheus Metrics Endpoint

As an infrastructure engineer,
I want a Prometheus-compatible metrics endpoint,
so that I can integrate Lorica into my existing monitoring stack.

#### Acceptance Criteria

1. `/metrics` endpoint on management port (localhost only)
2. Metrics: request count (by route, status code), latency histograms, active connections
3. Metrics: backend health status, certificate days-to-expiry
4. Metrics: system resources (CPU, RAM, disk)
5. Metrics: WAF events count (by rule, action)
6. Worker-level metrics aggregated at main process

#### Integration Verification

- IV1: Prometheus can scrape `/metrics` and parse all metrics
- IV2: Metric values match dashboard displays
- IV3: No metric cardinality explosion under normal operation

---

### Story 4.3: Peak EWMA Load Balancing

As an infrastructure engineer,
I want latency-based load balancing,
so that traffic is routed to the most responsive backend.

#### Acceptance Criteria

1. Peak EWMA algorithm implemented as load balancing option
2. Tracks connection time with exponential decay
3. Selectable per route alongside existing algorithms (Round Robin, Consistent Hash, Random)
4. Dashboard shows EWMA scores per backend
5. Default algorithm remains Round Robin (opt-in for EWMA)

#### Integration Verification

- IV1: Under heterogeneous backend latency, EWMA routes more traffic to faster backend
- IV2: EWMA adapts within seconds when backend latency changes
- IV3: EWMA does not add measurable latency overhead

---

### Story 4.4: Production Packaging

As an infrastructure engineer,
I want to install Lorica via `apt install lorica`,
so that deployment is simple and follows standard Linux conventions.

#### Acceptance Criteria

1. `.deb` package build pipeline (GitHub Actions or equivalent)
2. Package includes: binary, systemd unit file, default data directory (`/var/lib/lorica`)
3. Post-install script: create lorica system user, set directory permissions, enable service
4. Post-install output: display dashboard URL and temporary credentials
5. Upgrade-safe: database and data directory preserved on package upgrade
6. Static binary also available as GitHub release artifact
7. Package signing for apt repository trust

#### Integration Verification

- IV1: `apt install lorica` on a clean Debian/Ubuntu system results in running service
- IV2: `apt upgrade lorica` preserves existing configuration and database
- IV3: `apt remove lorica` stops the service, `apt purge lorica` removes data directory

---

### Story 4.5: Security Hardening

As an infrastructure engineer,
I want Lorica to be hardened for production deployment,
so that the proxy itself is not a security liability.

#### Acceptance Criteria

1. `cargo audit` clean - no known vulnerabilities in dependencies
2. Fuzz testing for TLS handshake, HTTP parsing, and API input handling
3. Rate limiting on management API (brute-force protection for login)
4. Session timeout and secure cookie flags for dashboard auth
5. No secrets in logs (password, cert private keys masked)
6. systemd hardening: PrivateTmp, NoNewPrivileges, ProtectSystem
7. Security documentation: threat model, hardening guide

#### Integration Verification

- IV1: `cargo audit` returns no vulnerabilities
- IV2: Fuzz testing runs for minimum 1 hour without crashes
- IV3: Brute-force login attempt is rate-limited after 5 failures
- IV4: Private key material never appears in log output
