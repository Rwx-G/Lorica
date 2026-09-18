# Tech Stack

> **Baseline note.** Both tables below are the v1.0 planning snapshot
> (the "Upgrade" / "Replace" / "TBD" markers are the choices as they
> stood then). For the current dependency pins, `Cargo.toml` and the
> workspace lockfile are authoritative; the bumps are recorded in
> `CHANGELOG.md`. The frontend was resolved to Svelte 5 + TypeScript +
> Vite 8.
>
> Notable major bumps since the v1.0 baseline: axum 0.8, tower 0.5,
> tower-http 0.7, rusqlite 0.40, rcgen 0.14, sysinfo 0.39,
> opentelemetry 0.32, argon2 0.6. `nix` is split: product crates
> (`lorica-api`, `lorica-shmem`) are on 0.31 while the forked crates
> (`lorica-core`, `lorica-command`, `lorica-worker`) stay on `~0.29`.
>
> Additions after v1.0 that this document never listed:
>
> - `jsonwebtoken` 11 in `lorica-api`, new in v1.8.0, on its
>   `aws_lc_rs` backend (the alternative pulls `rsa` and its open
>   Marvin advisory). It verifies the GitLab ID tokens the automation
>   listener accepts in place of a static token, and mints a test
>   token in the suite.
> - The OTLP **logs** signal, added in v1.7.0 (Story 9.8) behind the
>   `otel` feature on the `lorica` crate. It pulled in no new crate and
>   no version bump: it enables the `logs` feature on the already
>   pinned opentelemetry / opentelemetry_sdk / opentelemetry-otlp 0.32
>   trio. The exporter lives in `lorica/src/otel.rs`.
>
> **The project declares no workspace MSRV.** This document used to
> claim "Rust 1.84+ (MSRV)" for the language row; nothing in the tree
> ever backed that number. There is no `rust-version` key in the
> workspace `Cargo.toml`. `rust-toolchain.toml` pins `channel = "1.95.0"` and
> that single file governs both local development and GitHub Actions
> CI, which is what actually decides whether a build succeeds. Two
> forked crates, `lorica-cache` and `lorica-proxy`, carry their own
> `rust-version = "1.88"` inherited from upstream; nothing else does,
> and nothing enforces it workspace-wide.

## Existing Technology Stack (from Pingora)

| Category | Current Technology | Version | Usage in Enhancement | Notes |
|----------|-------------------|---------|---------------------|-------|
| Language | Rust | 1.95.0 pinned | All components | No workspace MSRV; `rust-toolchain.toml` pins the channel for dev and CI alike |
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
