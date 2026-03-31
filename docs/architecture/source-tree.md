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

  lorica-cache/                 # Fork of pingora-cache (HTTP response caching)
  lorica-memory-cache/          # Fork of pingora-memory-cache
  lorica-lru/                   # Fork of pingora-lru
  tinyufo/                      # Cache eviction algorithm (upstream)

  lorica-config/                # NEW - Config state & persistence
    Cargo.toml
    src/
      lib.rs
      models.rs                 # Route, Backend, Certificate, SLA, Probe, LoadTest models
      store.rs                  # ConfigStore - CRUD operations
      crypto.rs                 # AES-256-GCM encryption for private keys
      diff.rs                   # ConfigDiff - minimal changeset generation
      export.rs                 # TOML export
      import.rs                 # TOML import + validation
      error.rs                  # ConfigError types
      migrations/               # SQL migration files
        001_initial.sql
        002_add_health_check_path.sql
        003_sla_metrics.sql
        004_probe_configs.sql
        005_load_tests.sql
        006_sla_bucket_config_snapshot.sql

  lorica-api/                   # NEW - REST API
    Cargo.toml
    src/
      lib.rs
      server.rs                 # axum server setup, management listener
      auth.rs                   # Login, sessions, password management
      routes.rs                 # /api/v1/routes endpoints
      backends.rs               # /api/v1/backends endpoints
      certificates.rs           # /api/v1/certificates endpoints
      status.rs                 # /api/v1/status
      system.rs                 # /api/v1/system (CPU, RAM, disk)
      logs.rs                   # /api/v1/logs endpoint + WebSocket
      config.rs                 # /api/v1/config/export, import
      settings.rs               # /api/v1/settings, notifications, preferences
      waf.rs                    # /api/v1/waf (events, rules, blocklist, custom rules)
      acme.rs                   # /api/v1/acme (Let's Encrypt HTTP-01 + DNS-01)
      metrics.rs                # /metrics (Prometheus exposition)
      workers.rs                # /api/v1/workers (worker heartbeat status)
      sla.rs                    # /api/v1/sla (passive/active SLA monitoring)
      probes.rs                 # /api/v1/probes (active health probes)
      loadtest.rs               # /api/v1/loadtest (load test engine + SSE)
      error.rs                  # ApiError types, JSON envelope helpers
      middleware/
        auth.rs                 # Session validation middleware
        rate_limit.rs           # Rate limiting for login

  lorica-dashboard/             # NEW - Embedded frontend
    Cargo.toml
    src/
      lib.rs                    # rust-embed setup, asset serving
    frontend/                   # Svelte 5 + TypeScript dashboard
      package.json
      index.html
      vite.config.ts
      src/
        main.ts                 # App entry point
        App.svelte              # Root with session check and theme loader
        app.css                 # Design system (tokens, themes, shared styles)
        lib/
          api.ts                # Typed API client (76 endpoints)
          auth.ts               # Auth state store
          router.ts             # Hash-based routing
        components/
          Nav.svelte            # Sidebar navigation (11 entries)
          Card.svelte           # Metric card with color variants
          StatusBadge.svelte    # Health status dot + label
          CertExpiryBadge.svelte # Certificate expiry countdown
          ConfirmDialog.svelte  # Delete confirmation modal
          ShieldIcon.svelte     # Brand icon
        routes/
          Login.svelte          # Authentication
          PasswordChange.svelte # Forced password change
          Dashboard.svelte      # Layout + routing
          Overview.svelte       # Status cards summary
          Routes.svelte         # Route CRUD with backend/cert/WAF config
          Backends.svelte       # Backend CRUD with health checks
          Certificates.svelte   # Cert CRUD + self-signed + ACME provisioning
          Security.svelte       # WAF events/rules/custom rules/IP blocklist
          Sla.svelte            # Passive/active SLA comparison + config + export
          Probes.svelte         # Active probe CRUD
          LoadTest.svelte       # Load test config/run/SSE streaming/results
          Logs.svelte           # Real-time WebSocket access logs
          System.svelte         # CPU/RAM/disk gauges + workers
          Settings.svelte       # Config, notifications, preferences, import/export
          Placeholder.svelte    # 404 fallback
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

  lorica-waf/                   # NEW - WAF engine
    Cargo.toml
    src/
      lib.rs
      engine.rs                 # Rule evaluation engine with custom rule support
      rules.rs                  # 18 OWASP-inspired regex rules
      ip_blocklist.rs           # IPv4 blocklist (800k+ IPs from Data-Shield)

  lorica-bench/                 # NEW - SLA monitoring & load testing
    Cargo.toml
    src/
      lib.rs
      passive_sla.rs            # Lock-free metrics collection from real traffic
      active_probes.rs          # Synthetic probe scheduler and executor
      load_test.rs              # Load test engine with safe limits and CPU circuit breaker
      results.rs                # SLA time-window queries
      scheduler.rs              # Cron-based load test scheduling

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
    rpm/                        # RPM package config
    build-deb.sh                # Debian package build script
    build-rpm.sh                # RPM package build script

  fuzz/                         # Fuzz testing targets
    fuzz_targets/               # cargo-fuzz entry points

  tests-e2e-docker/             # End-to-end tests (Docker Compose)
    docker-compose.yml          # Service definitions
    Dockerfile                  # Multi-stage Lorica build
    run.sh                      # Test orchestrator (--keep, --build, --skip-workers)
    test-runner/
      run-tests.sh              # 26-section single-process test suite
      run-tests-workers.sh      # 6-section worker isolation tests
    backend/                    # Python mock backend for testing

  docs/                         # Project documentation
    security/
      threat-model.md           # Threat categories and mitigations
      hardening-guide.md        # Production deployment security guide
```

## Integration Guidelines

- **File Naming:** snake_case for all Rust files, matching Pingora convention. Frontend follows its framework's convention.
- **Folder Organization:** Each concern in its own crate. Forked crates preserve Pingora's internal structure. New crates follow Rust module conventions.
- **Import/Export Patterns:** All inter-crate dependencies via Cargo.toml. No circular dependencies. Forked crates depend on other forked crates. New crates depend on forked crates but not vice versa (product layer wraps engine, engine doesn't know about product).
