# Tech Stack

## Existing Technology Stack (from Pingora)

| Category | Current Technology | Version | Usage in Enhancement | Notes |
|----------|-------------------|---------|---------------------|-------|
| Language | Rust | 1.84+ (MSRV) | All components | Keep |
| Async Runtime | tokio | 1.x | Proxy engine, API server | Keep |
| HTTP/1.1 Parser | httparse | 1.x | Request/response parsing | Keep |
| HTTP/2 | h2 | >= 0.4.11 | HTTP/2 proxy | Keep |
| HTTP Types | http | 1.x | Type definitions | Keep |
| TLS | rustls | 0.23.12 | TLS termination | Keep - promote to sole backend |
| TLS Async | tokio-rustls | 0.26.0 | Async TLS | Keep |
| Crypto | ring | 0.17.12 | Cryptographic operations | Keep |
| Serialization | serde | 1.0 | Config, API payloads | Keep |
| CLI | clap | 4.5 | Binary CLI arguments | Keep |
| Concurrency | parking_lot | 0.12 | Fast mutexes/rwlocks | Keep |
| Atomic | arc-swap | 1.x | Atomic Arc swapping | Keep |
| Compression | flate2, brotli 3, zstd | Various | Response compression | Keep |
| Unix | nix | 0.24 -> **0.29+** | Syscalls, signals | **Upgrade** |
| YAML | serde_yaml | 0.9 | Server config | **Replace with serde_yml** |
| Socket | socket2 | Latest | Advanced socket ops | Keep |

## New Technology Additions

| Technology | Version | Purpose | Rationale | Integration Method |
|------------|---------|---------|-----------|-------------------|
| axum | 0.7+ | REST API framework | Tokio-native, lightweight, tower middleware ecosystem | New `lorica-api` crate |
| tower | 0.4+ | HTTP middleware | Auth, rate limiting, CORS for API | Used by axum |
| SQLite (rusqlite) | Latest | Config state persistence | Battle-tested, crash-safe (WAL), zero-config, single-file | New `lorica-config` crate |
| rust-embed | Latest | Embed dashboard assets | Compile frontend into binary at build time | New `lorica-dashboard` crate |
| tracing | 0.1+ | Structured logging | Standard Rust ecosystem, JSON output, spans | Replace `log` crate usage |
| tracing-subscriber | 0.3+ | Log formatting | JSON formatter for stdout | Companion to tracing |
| prost | Latest | Protobuf serialization | Command channel protocol (Phase 2) | New `lorica-command` crate |
| sysinfo | Latest | System metrics | CPU, RAM, disk usage for dashboard | New dependency in `lorica-api` |
| argon2 | Latest | Password hashing | Secure admin password storage | New dependency in `lorica-api` |
| toml | Latest | Config export/import | TOML serialization for config files | New dependency in `lorica-config` |
| Frontend TBD | - | Dashboard UI | Svelte, Solid, or htmx - evaluate for bundle size | Build artifact embedded via rust-embed |
