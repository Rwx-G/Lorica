# Contributing to Lorica

Thank you for considering contributing to Lorica! This document explains how to get started.

## Getting Started

### Prerequisites

- Rust 1.88+ (stable)
- Node.js 18+ (for dashboard frontend)
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
# All Rust unit tests (655 tests across 25 crates)
cargo test

# Product crate tests only (280 tests)
cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench

# Frontend tests (52 Vitest tests)
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

**Scopes:** `proxy`, `ui`, `waf`, `api`, `config`, `tls`, `auth`, `health`, `ci`

### Code Quality

Before submitting:

- `cargo clippy` - no warnings
- `cargo fmt` - all code formatted
- `cargo test` - all tests pass
- New code has corresponding tests
- Public functions have doc comments (`///`)

### Changelog

If your change adds a feature, fixes a bug, or changes behavior, update `CHANGELOG.md`:

- Add an entry under `[Unreleased]`
- Use the correct category: Added, Changed, Fixed, Removed, Security

## Architecture

Lorica is a Rust workspace with 25 crates. See [FORK.md](FORK.md) for the Pingora fork lineage and [README.md](README.md) for the architecture overview.

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
