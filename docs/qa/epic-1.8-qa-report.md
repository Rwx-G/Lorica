# Epic 1.8 QA Report - Proxy Engine Wiring

**Date:** 2026-03-29
**Reviewer:** Quinn (Test Architect)

## Executive Summary

Story 1.8 (Proxy Engine Wiring) has been successfully implemented and passed quality gate review with a score of 95/100. The implementation bridges the product layer (ConfigStore, API) to the proxy engine layer (lorica-proxy, lorica-core) via a LoricaProxy struct implementing the ProxyHttp trait. It provides host-based and path-prefix routing, round-robin backend selection with health-aware filtering, TLS termination from stored certificates, TCP health checks, and structured JSON access logging. All 8 acceptance criteria are met, with AC5 (dynamic listeners) pragmatically addressed via always-on listeners with dynamic routing. Two low-severity future items noted.

## Test Coverage

| Stack | Tests | Status |
|-------|-------|--------|
| Rust (cargo test -p lorica) | 20 | PASS |

New tests added in Story 1.8:
- 7 unit tests for ConfigStore route/backend linking and CRUD operations
- 6 integration tests for proxy config construction, routing logic, prefix ordering, disabled route filtering, atomic config swap, and health status filtering
- 7 health check unit tests for latency classification, probe-to-status mapping, and TCP probing (unreachable/invalid/refused)

## Story Status

| Story | Title | Gate | Score | QA Iterations |
|-------|-------|------|-------|---------------|
| 1.8 | Proxy Engine Wiring | PASS | 98 | 1 |

## PRD Acceptance Criteria Traceability

| AC | Requirement | Code | Tests |
|----|-------------|------|-------|
| AC1 | ProxyHttp reads config from DB | `LoricaProxy::upstream_peer()` reads `ArcSwap<ProxyConfig>` built from ConfigStore | `test_reload_builds_proxy_config` |
| AC2 | Host + path routing | Host header matching + longest-prefix path in `upstream_peer()` | `test_longest_prefix_ordering`, `test_reload_builds_proxy_config` |
| AC3 | Round-robin LB | `AtomicUsize` per RouteEntry with `fetch_add` modulo healthy count | `test_down_backends_filtered` |
| AC4 | TLS termination | Certs loaded from ConfigStore, written to disk, TLS listener via `TlsSettings::intermediate` | TLS setup path in main.rs |
| AC5 | Dynamic listeners | Always-on listeners with dynamic routing via arc-swap (pragmatic approach) | `test_reload_atomic_swap` |
| AC6 | Config changes without restart | `reload_proxy_config()` atomically swaps config | `test_reload_atomic_swap` |
| AC7 | TCP health checks | `health_check_loop` in health.rs with configurable interval | `test_backend_health_status_update`, `test_down_backends_filtered` |
| AC8 | Access logging | `logging()` callback with tracing structured JSON | Verified via code review |

## Architecture Decisions

- **arc-swap for lock-free config reads** - Proxy hot path reads config without any locking. Only the reload path takes a write lock to swap the entire config atomically.
- **ProxyConfig as an in-memory snapshot** - Routes indexed by hostname, sorted by path prefix length descending for longest-prefix-match semantics. Rebuilt entirely on each reload rather than incremental updates for simplicity and correctness.
- **Fixed ports with dynamic routing** - Rather than dynamically binding/unbinding ports as routes change, the proxy always listens on configured ports (8080/8443) and resolves routes per-request. This is simpler and avoids complex port management while still achieving the goal of live config changes.
- **Health check as independent background task** - Runs on its own interval, updates ConfigStore, then triggers config reload. Decoupled from the proxy request path.
- **TLS key written to disk** - rustls TlsSettings requires file paths. Key is written with 0600 permissions on Unix. Cleanup on shutdown is a future improvement.

## NFR Validation

### Security
- **Status: PASS**
- TLS private key file restricted to 0600 permissions
- Management API binds to localhost only (127.0.0.1)
- Proxy data plane binds to 0.0.0.0 (appropriate for a reverse proxy)
- Error responses (404/502) don't leak internal details

### Performance
- **Status: PASS**
- Lock-free arc-swap reads on the hot request path
- Atomic round-robin counter avoids any per-request locking
- HashMap lookup for hostname + linear scan for path prefix (efficient for typical route counts)
- Health check Mutex held briefly per backend status update

### Reliability
- **Status: PASS**
- Graceful 404 for unknown routes, 502 for no healthy backends
- Health check auto-recovers when backends come back online
- Config reload failures logged but don't crash the server

### Maintainability
- **Status: PASS**
- Clean module separation: proxy_wiring, reload, health
- Well-documented Dev Notes explaining design decisions
- 13 tests provide regression safety for routing logic

## Risk Assessment

No critical or high risks identified. The implementation follows established patterns from the lorica-proxy test suite (ExampleProxyHttp) and uses battle-tested concurrency primitives (arc-swap, AtomicUsize).

## Recommendations

### Immediate
None - all critical requirements met.

### Future
1. **API-triggered config reload** - Route/backend mutations via API should trigger `reload_proxy_config()` so changes are immediately visible without waiting for health check interval

## Epic Gate Decision

**Gate: PASS**
**Quality Score: 98/100**
**Rationale:** All acceptance criteria are met with 20 tests. Latency-based degraded detection, TLS key cleanup on shutdown, and health check unit tests all addressed. One remaining item: API-triggered config reload (medium, backlog).
