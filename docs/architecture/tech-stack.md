# Tech Stack

> **Baseline note.** Both tables below are the v1.0 planning snapshot
> (the "Upgrade" / "Replace" / "TBD" markers are the choices as they
> stood then). For the current dependency pins, `Cargo.toml` and the
> workspace lockfile are authoritative; the bumps are recorded in
> `CHANGELOG.md`. The frontend was resolved to Svelte 5 + TypeScript +
> Vite 8.
>
> Notable major bumps since the v1.0 baseline: axum 0.8, tower 0.5,
> tower-http 0.7, rusqlite 0.42, rcgen 0.14, sysinfo 0.40,
> opentelemetry 0.33, argon2 0.6. `nix` 0.31 in
> every crate since v1.10.2 (`lorica-core`, `lorica-command` and
> `lorica-worker` were held on `~0.29` until then). reqwest 0.13 in
> every crate, forks included, since v1.10.2, on its
> `rustls-no-provider` feature: each client is handed a rustls
> configuration from `lorica_tls::http_client` (ring, the webpki bundle
> plus the platform store), so neither `aws-lc-rs` nor the platform
> verifier reqwest 0.13 defaults to is what a client runs on. The
> workspace `clippy.toml` refuses reqwest's own constructors and
> `rustls::ClientConfig::builder` outside `http_client`.
>
> The ACME CA client is not a reqwest client but is on the policy too,
> since v1.10.2: `lorica-acme/src/driver.rs` hands instant-acme a
> `hyper-util` client (`Account::builder_with_http`) whose `hyper-rustls`
> connector speaks `http_client::public()` as given, ALPN included.
> Before, instant-acme's own client verified through
> `rustls-platform-verifier` on the process default provider: the
> platform store without the webpki bundle, offering `h2`. A private
> ACME CA (step-ca, the e2e Pebble fixture) is still trusted through
> `SSL_CERT_FILE`, which the platform half of `public()` reads;
> `lorica-acme/tests/tls_policy.rs` holds that path.
>
> Outbound TLS that is not on that policy:
>
> - **The OTLP/gRPC exporters** (`otel` feature, tonic). tonic takes
>   trust anchors, not a rustls configuration, so Lorica hands them the
>   policy's roots (`http_client::public_roots`); the provider is
>   tonic's choice, the process default (ring, which `main` installs),
>   and the ALPN is tonic's `h2`. Before v1.10.2 an `https` collector
>   was verified against no root at all and always refused.
> - **The Route53 DNS-01 client** (`route53` feature, AWS SDK default
>   HTTPS client). rustls on `aws-lc-rs` with a restricted cipher list,
>   trusting the platform store alone, read once per process. The SDK
>   takes a crypto mode and a trust store rather than a rustls
>   configuration, and only through `aws-smithy-http-client` as a
>   direct dependency.
> - **The cluster plane, the syslog sink and SMTP** are not HTTP clients:
>   the cluster plane pins its own CA and TLS 1.3, the syslog sink takes
>   the policy's provider and versions (`http_client::config_builder`)
>   with its own roots and client certificate, and `lettre` builds its
>   own rustls configuration.
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
>   pinned opentelemetry / opentelemetry_sdk / opentelemetry-otlp
>   trio (version above). The exporter lives in `lorica/src/otel.rs`.
>
> **The project declares no workspace MSRV.** This document used to
> claim "Rust 1.84+ (MSRV)" for the language row; nothing in the tree
> ever backed that number. There is no `rust-version` key in the
> workspace `Cargo.toml`. `rust-toolchain.toml` pins `channel = "1.99.1"` and
> that single file governs both local development and GitHub Actions
> CI, which is what actually decides whether a build succeeds. Two
> forked crates, `lorica-cache` and `lorica-proxy`, carry their own
> `rust-version = "1.88"` inherited from upstream; nothing else does,
> and nothing enforces it workspace-wide.

## Existing Technology Stack (from Pingora)

| Category | Current Technology | Version | Usage in Enhancement | Notes |
|----------|-------------------|---------|---------------------|-------|
| Language | Rust | 1.99.1 pinned | All components | No workspace MSRV; `rust-toolchain.toml` pins the channel for dev and CI alike |
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
| YAML | none (was serde_yaml_ng 0.10) | - | Server config | **Removed in v1.10.2**: `ServerConf` is built in code, see `FORK.md` |
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
