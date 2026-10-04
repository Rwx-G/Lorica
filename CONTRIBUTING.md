# Contributing to Lorica

Thank you for considering contributing to Lorica! This document explains how to get started.

## Getting Started

### Prerequisites

- Rust 1.95.0. `rust-toolchain.toml` pins it for local builds and CI both, and rustup installs it on first use; do not override it locally, a version skew is exactly what the pin exists to prevent
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
# All Rust tests, the product crates and the Pingora-forked ones
# alike (see the test-coverage table in README.md for the per-layer
# breakdown; a count written here would be stale by the next merge)
cargo test

# Product crate tests only: the list is in README.md, under
# "Running tests"

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

**Scopes:** `ui`, `api`, `waf`, `tls`, `proxy`, `worker`, `notify`, `acme`, `config`, `auth`, `health`, `ci`, `security`, `cluster`, `mcp`

`mcp` covers the `lorica-mcp` crate and the MCP endpoint of the
automation listener; `api` is the management API.

### Code Quality

Before submitting, run the gates CI runs, on Linux or inside the
`rust:1-bookworm` image with `cmake` and `protobuf-compiler` installed.
The commands, crate lists included, live in `.github/workflows/ci.yml`
and nowhere else: a copy of them here ran half of CI's test set before
anyone noticed. Print them from the workflow and run each line:

```bash
grep -E '^\s+run: cargo (fmt|clippy|test)' .github/workflows/ci.yml
```

then `cargo audit`, which the workflow's "Cargo audit" step runs after
`cargo install cargo-audit --locked`. CI exports
`RUSTFLAGS="-D warnings"` (set by
`actions-rust-lang/setup-rust-toolchain`), so a rustc warning in a test
target fails the Test and Coverage jobs even when clippy is clean:
`export RUSTFLAGS="-D warnings"` locally too.

For the dashboard, run `npm run check`, `npm run lint` and `npx vitest run`
in `lorica-dashboard/frontend`. The Docker e2e suite
(`tests-e2e-docker/run.sh --build`) is the release gate.

- New code has corresponding tests
- Public functions have doc comments (`///`)

### Changelog

If your change adds a feature, fixes a bug, or changes behavior, update `CHANGELOG.md`:

- Add an entry under `[Unreleased]`
- Use the correct category: Added, Changed, Fixed, Removed, Security

## Architecture

Lorica is a Rust workspace with 33 crates. See [FORK.md](FORK.md) for the Pingora fork lineage and [README.md](README.md) for the architecture overview.

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
