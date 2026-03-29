# Testing Strategy

## Integration with Existing Tests

**Existing Test Framework:** Rust's built-in test framework (`#[test]`, `#[tokio::test]`). Pingora has unit tests across crates.
**Test Organization:** Unit tests in-module, integration tests in `tests/` per crate.
**Coverage Requirements:** No formal coverage target. Prioritize: config CRUD, API endpoints, TLS handling, routing logic, WAF rule evaluation.

## New Testing Requirements

### Unit Tests

- **Framework:** Rust built-in `#[test]` and `#[tokio::test]`
- **Location:** `#[cfg(test)]` modules in each source file
- **Coverage Target:** All public functions in new crates. All API endpoint handlers. All config CRUD operations. All export/import round-trips.
- **Integration with Existing:** Forked crate tests must continue passing. New tests don't depend on forked crate internals.

### Integration Tests

- **Scope:** API endpoint tests (HTTP requests to running API server), proxy routing tests (HTTP traffic through proxy), config persistence tests (write, restart, read).
- **Existing System Verification:** Pingora proxy engine tests remain functional after fork and rename.
- **New Feature Testing:** Full proxy lifecycle: create route via API -> verify traffic is proxied -> update route -> verify change -> delete route -> verify traffic stops.

### Regression Testing

- **Existing Feature Verification:** `cargo test` across all workspace crates before each release.
- **Automated Regression Suite:** E2E test suite that stands up a Lorica instance, configures routes via API, sends traffic, and verifies behavior.
- **Manual Testing Requirements:** TLS certificate handling edge cases (expired certs, wildcard matching, SNI fallback). Dashboard UX verification on target browsers.
