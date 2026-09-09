# Contributing to Lorica

Thank you for considering contributing to Lorica! This document explains how to get started.

## Getting Started

### Prerequisites

- Rust 1.88+ (stable)
- Node.js 22+ (for dashboard frontend; Vite 8 rejects Node 18)
- Linux x86_64 (native builds) or Docker (for development on other platforms)

### Building

```bash
git clone https://github.com/Rwx-G/Lorica.git
cd Lorica
cargo build --release
```

The Svelte frontend is compiled automatically during `cargo build` via `build.rs`.

### Running Tests

```bash
# All Rust unit tests (~2100 tests across 30 crates; see the
# test-coverage table in README.md for the per-layer breakdown)
cargo test

# Product crate tests only
cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench

# Frontend tests (Vitest)
cd lorica-dashboard/frontend && npx vitest run

# E2E tests (Docker required)
cd tests-e2e-docker && ./run.sh --build
```

## Development Workflow

1. **Fork** the repository and create a branch: `feat/<name>` or `fix/<name>`
2. **Develop** - write code, tests, and docs
3. **Validate** - all tests pass, clippy clean, rustfmt applied
4. **Submit** a pull request against `main`

### Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`

**Scopes:** `ui`, `api`, `waf`, `tls`, `proxy`, `worker`, `notify`, `acme`, `config`, `auth`, `health`, `ci`, `security`, `cluster`

### Code Quality

Before submitting, run the same gates as CI (`.github/workflows/ci.yml`),
on Linux or inside the `rust:1-bookworm` image with `cmake` and
`protobuf-compiler` installed. CI exports `RUSTFLAGS="-D warnings"`
(set by `actions-rust-lang/setup-rust-toolchain`), so a rustc warning in
a test target fails the Test and Coverage jobs even when clippy is clean:
export it locally too.

```bash
export RUSTFLAGS="-D warnings"
cargo fmt --all -- --check
cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -- -D warnings
cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings
cargo clippy -p lorica --all-targets --features otel -- -D warnings
cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-command
cargo test -p lorica-core -p lorica-proxy -p lorica-http -p lorica-error -p lorica-tls -p lorica-worker -p lorica-lb -p lorica-pool -p lorica-cache -p lorica-header-serde
cargo audit
```

and, for the dashboard, `npm run check`, `npm run lint` and `npx vitest run`
in `lorica-dashboard/frontend`. The Docker e2e suite
(`tests-e2e-docker/run.sh --build`) is the release gate.

- New code has corresponding tests
- Public functions have doc comments (`///`)

### Changelog

If your change adds a feature, fixes a bug, or changes behavior, update `CHANGELOG.md`:

- Add an entry under `[Unreleased]`
- Use the correct category: Added, Changed, Fixed, Removed, Security

## Architecture

Lorica is a Rust workspace with 31 crates. See [FORK.md](FORK.md) for the Pingora fork lineage and [README.md](README.md) for the architecture overview.

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `lorica/` | CLI binary, supervisor, proxy wiring |
| `lorica-api/` | axum REST API |
| `lorica-config/` | SQLite store, models |
| `lorica-dashboard/` | Svelte 5 frontend |
| `lorica-waf/` | WAF engine, rules |
| `lorica-proxy/` | Pingora proxy engine (forked) |
| `tests-e2e-docker/` | Docker-based E2E tests |
| `docs/` | PRD, architecture, stories |

## Reporting Issues

Use [GitHub Issues](https://github.com/Rwx-G/Lorica/issues). Include:

- Lorica version (`lorica --version`)
- OS and kernel version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
