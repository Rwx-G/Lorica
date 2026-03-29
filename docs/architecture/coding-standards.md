# Coding Standards

## Existing Standards Compliance (from Pingora)

**Code Style:** Standard Rust idioms. No custom style guide in Pingora beyond standard rustfmt.
**Linting Rules:** `cargo clippy` with default lints. Lorica will add `#![deny(clippy::all)]`.
**Testing Patterns:** Unit tests in `#[cfg(test)]` modules within source files. Integration tests in `tests/` directory.
**Documentation Style:** `///` doc comments on public items. Pingora has moderate documentation coverage.

## Enhancement-Specific Standards

- **API Response Format:** All API responses use a consistent JSON envelope: `{"data": ...}` for success, `{"error": {"code": "...", "message": "..."}}` for errors.
- **Error Handling:** Use `thiserror` for typed errors in library crates. Map to HTTP status codes in API layer. Never expose internal error details to API consumers.
- **Database Access:** All database operations go through `ConfigStore`. No raw SQL outside of migration files and the store module.
- **Frontend Build:** Frontend build must produce deterministic output. Embedded assets are part of the binary's reproducible build.

## Critical Integration Rules

- **Existing API Compatibility:** Changes to forked crates must not break the `ProxyHttp` trait or `Peer`/`HttpPeer` abstractions. If a breaking change is needed, it goes through a deprecation cycle.
- **Database Integration:** All schema changes are migrations. No manual DDL. WAL mode is mandatory for crash safety.
- **Error Handling:** Proxy engine errors (forked crates) use `pingora_error::Error` (renamed to `lorica_error::Error`). Product layer errors use `thiserror`-derived types. Bridge at the `ProxyHttp` implementation boundary.
- **Logging Consistency:** All components use `tracing` macros (`info!`, `warn!`, `error!`). Structured fields for machine-parseable output. No `println!` or `eprintln!` in production code.
