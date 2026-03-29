# Source Tree

## Workspace Structure

```
lorica/
  Cargo.toml                    # Workspace root
  NOTICE                        # Cloudflare Pingora attribution
  LICENSE                       # Apache-2.0
  CHANGELOG.md
  README.md

  lorica/                       # Main binary crate
    Cargo.toml
    src/
      main.rs                   # Entry point, CLI, orchestration
      proxy.rs                  # ProxyHttp trait implementation
      signals.rs                # Signal handling (SIGTERM, SIGQUIT, SIGINT)

  lorica-core/                  # Fork of pingora-core
    Cargo.toml
    src/                        # (preserved Pingora structure)
      server/
      protocols/
      connectors/
      listeners/
      apps/
      services/
      modules/
      upstreams/

  lorica-proxy/                 # Fork of pingora-proxy
  lorica-http/                  # Fork of pingora-http
  lorica-error/                 # Fork of pingora-error
  lorica-pool/                  # Fork of pingora-pool
  lorica-runtime/               # Fork of pingora-runtime
  lorica-timeout/               # Fork of pingora-timeout
  lorica-tls/                   # Fork of pingora-rustls (sole TLS backend)
  lorica-lb/                    # Fork of pingora-load-balancing
  lorica-ketama/                # Fork of pingora-ketama
  lorica-limits/                # Fork of pingora-limits
  lorica-header-serde/          # Fork of pingora-header-serde

  lorica-config/                # NEW - Config state & persistence
    Cargo.toml
    src/
      lib.rs
      models.rs                 # Route, Backend, Certificate, etc.
      store.rs                  # ConfigStore - CRUD operations
      state.rs                  # ConfigState - in-memory snapshot
      diff.rs                   # ConfigDiff - minimal changeset generation
      export.rs                 # TOML export
      import.rs                 # TOML import + validation
      migrations/               # SQL migration files
        001_initial.sql

  lorica-api/                   # NEW - REST API
    Cargo.toml
    src/
      lib.rs
      server.rs                 # axum server setup, management listener
      auth.rs                   # Login, sessions, password management
      routes.rs                 # /api/v1/routes endpoints
      backends.rs               # /api/v1/backends endpoints
      certificates.rs           # /api/v1/certificates endpoints
      status.rs                 # /api/v1/status, /api/v1/system
      logs.rs                   # /api/v1/logs endpoint
      config.rs                 # /api/v1/config/export, import
      middleware/
        auth.rs                 # Session validation middleware
        rate_limit.rs           # Rate limiting for login

  lorica-dashboard/             # NEW - Embedded frontend
    Cargo.toml
    src/
      lib.rs                    # rust-embed setup, asset serving
    frontend/                   # Frontend project (Svelte/Solid/htmx)
      package.json
      src/
      dist/                     # Build output - embedded by rust-embed

  lorica-command/               # NEW (Phase 2) - Command channel
    Cargo.toml
    src/
      lib.rs
      channel.rs                # Unix socket channel with protobuf framing
      messages.rs               # Protobuf message definitions
      proto/
        command.proto           # Protobuf schema

  lorica-worker/                # NEW (Phase 2) - Process isolation
    Cargo.toml
    src/
      lib.rs
      manager.rs                # WorkerManager - fork, monitor, restart
      fd_passing.rs             # SCM_RIGHTS FD transfer

  lorica-waf/                   # NEW (Phase 2+) - WAF engine
    Cargo.toml
    src/
      lib.rs
      engine.rs                 # Rule evaluation engine
      rules.rs                  # OWASP CRS rule parsing
      data/
        owasp-crs/              # Bundled rulesets

  lorica-bench/                 # NEW (Phase 3+) - SLA monitoring & load testing
    Cargo.toml
    src/
      lib.rs
      passive_sla.rs            # Metrics collection from real traffic
      active_probes.rs          # Synthetic probe scheduler and executor
      load_test.rs              # Load test engine
      results.rs                # Result storage and historical comparison
      scheduler.rs              # Cron-like test scheduling

  lorica-notify/                # NEW - Notification channels
    Cargo.toml
    src/
      lib.rs
      events.rs                 # AlertEvent types
      channels/
        stdout.rs               # JSON structured log events
        email.rs                # SMTP notifications
        webhook.rs              # HTTP webhook notifications

  dist/                         # Distribution files
    lorica.service              # systemd unit file
    debian/                     # .deb package config

  tests/                        # Integration tests
  e2e/                          # End-to-end tests
  docs/                         # Project documentation
```

## Integration Guidelines

- **File Naming:** snake_case for all Rust files, matching Pingora convention. Frontend follows its framework's convention.
- **Folder Organization:** Each concern in its own crate. Forked crates preserve Pingora's internal structure. New crates follow Rust module conventions.
- **Import/Export Patterns:** All inter-crate dependencies via Cargo.toml. No circular dependencies. Forked crates depend on other forked crates. New crates depend on forked crates but not vice versa (product layer wraps engine, engine doesn't know about product).
