# Technical Constraints and Integration Requirements

## Existing Technology Stack

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

## Integration Approach

**State Persistence Strategy:** Embedded database (SQLite or sled) for all configuration state. No external database dependency. The database file lives alongside the binary or in a configurable data directory.

**API Integration Strategy:** REST API (JSON) is the single source of truth for all operations. The dashboard is a pure consumer of the API. The CLI (if any) also consumes the API. No operation bypasses the API.

**Frontend Integration Strategy:** Dashboard frontend is compiled to static assets and embedded in the Rust binary via `rust-embed`. Served by the management port listener (localhost:9443). Completely isolated from the proxy data plane.

**Testing Integration Strategy:**
- Rust: unit tests per crate, integration tests for API and proxy behavior
- Frontend: component tests for dashboard
- E2E: full proxy + dashboard tests with real HTTP traffic
- Inherited Pingora tests remain functional for proxy engine

## Code Organization and Standards

**File Structure Approach:** Cargo workspace mirroring Pingora's crate structure with new Lorica-specific crates added. See `docs/architecture/source-tree.md` for full structure.

**Naming Conventions:** Rust standard (snake_case for functions/variables, CamelCase for types, SCREAMING_SNAKE for constants). All `pingora_*` references renamed to `lorica_*`.

**Coding Standards:** As defined in `docs/architecture/coding-standards.md` - strict clippy, rustfmt, doc comments on public APIs, no leftover TODOs or debug prints.

**Documentation Standards:** Rust doc comments (`///`) on all public items. Architecture decisions documented in `docs/`.

## Deployment and Operations

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

## Risk Assessment and Mitigation

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
