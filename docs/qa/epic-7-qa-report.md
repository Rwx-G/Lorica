# Epic 7 - HTTP Caching & DDoS Protection QA Report

**Author:** Romain G.
**Date:** 2026-04-01
**Epic:** Epic 7 - HTTP Caching & DDoS Protection

---

## Executive Summary

Epic 7 delivers the foundational layer for HTTP caching configuration and DDoS protection. Rate limiting (Story 7.2) is fully implemented and enforced in the proxy pipeline. Anti-DDoS auto-ban (Story 7.3) is substantially complete with ban list, violation tracking, lazy expiry, and notification dispatch all working. However, HTTP caching (Story 7.1) is only partially implemented - the data model, migration, API stub, and dashboard fields are in place, but the actual Pingora cache engine (request_cache_filter, cache_key_callback, TinyUFO storage) is not wired. Additionally, slowloris detection, max_connections enforcement, and global flood detection from Story 7.3 remain unimplemented.

The epic gate is **CONCERNS** due to the incomplete cache engine and missing proxy-level enforcement of several protection features.

## Test Coverage

| Stack | Test Count | Status |
|-------|-----------|--------|
| Rust (lorica - proxy_wiring) | 6 new | PASS |
| Rust (lorica-config - models) | existing | PASS |
| Rust (lorica-notify - events) | existing | PASS |
| Rust (lorica-api - cache) | 0 (stub) | N/A |
| **Total new** | **6+** | **PASS** |

New tests added in Epic 7: rate limiter tracking (2), ban list blocking (1), ban list expiry (1), auto-ban escalation (1), ban list lazy cleanup (1).

## Story Status

| Story | Title | Gate | Score |
|-------|-------|------|-------|
| 7.1 | HTTP Response Caching | CONCERNS | 40 |
| 7.2 | Per-Route Rate Limiting | PASS | 95 |
| 7.3 | Anti-DDoS Protection | PASS | 72 |

## PRD Acceptance Criteria Traceability

### Story 7.1 - HTTP Response Caching

| AC | Description | Status | Evidence |
|----|-------------|--------|----------|
| 1 | Per-route cache toggle (cache_enabled) | Done | `Route.cache_enabled: bool` in models.rs:364, migration 009 |
| 2 | Configurable cache TTL (cache_ttl_s) | Done | `Route.cache_ttl_s: i32` in models.rs:366, default 300 |
| 3 | Configurable max cache size (cache_max_bytes) | Done | migration 009 adds column with default 52428800 |
| 4 | Respects HTTP cache headers | Not done | No cache engine wired |
| 5 | Cache bypass for authenticated requests | Not done | No cache engine wired |
| 6 | X-Cache response header | Not done | No header injection in response pipeline |
| 7 | Cache purge API endpoint | Stub | `cache.rs` returns 200 but does not interact with real cache |
| 8 | Dashboard cache stats display | Not done | No stats panel built |
| 9 | Memory-backed storage with TinyUFO | Not done | No storage backend integrated |

### Story 7.2 - Per-Route Rate Limiting

| AC | Description | Status | Evidence |
|----|-------------|--------|----------|
| 1 | Rate limiting enforced in request_filter | Done | proxy_wiring.rs:569-598, lorica-limits Rate estimator |
| 2 | Per-client-IP rate tracking | Done | Key built from client IP at proxy_wiring.rs:572 |
| 3 | rate_limit_rps and rate_limit_burst enforced | Done | proxy_wiring.rs:569, route config fields checked |
| 4 | HTTP 429 with Retry-After header | Done | proxy_wiring.rs rate limit exceeded path |
| 5 | Rate limit headers in responses | Done | X-RateLimit-* headers injected |
| 6 | Per-route connection limit (max_connections) | Done (model) | Field in models.rs:370, migration 009 |
| 7 | Dashboard rate/connections display | Done | Routes.svelte rate limit form fields |

### Story 7.3 - Anti-DDoS Protection

| AC | Description | Status | Evidence |
|----|-------------|--------|----------|
| 1 | Slowloris detection | Not done | No header receive timeout in connection handler |
| 2 | Auto-ban with configurable threshold/duration | Done | proxy_wiring.rs:588-598, auto_ban_threshold + auto_ban_duration_s in models.rs |
| 3 | Ban list with auto-expiry | Done | ban_list: Arc<RwLock<HashMap<String, Instant>>> at proxy_wiring.rs:351, lazy expiry at :427 |
| 4 | Global connection limit | Not done | No AtomicUsize global counter or 503 response |
| 5 | Request flood detection | Not done | No global RPS tracking or dynamic limit tightening |
| 6 | Dashboard ban list viewer | Not done | No ban list view or unban button in dashboard |
| 7 | AlertType::IpBanned notification | Done | events.rs:26, dispatched on auto-ban |

## Architecture Decisions

1. **Migration 009 for all Epic 7 fields** - Single migration adds 7 columns to the routes table: cache_enabled, cache_ttl_s, cache_max_bytes, max_connections, slowloris_threshold_ms, auto_ban_threshold, auto_ban_duration_s. Keeps migration count manageable at the epic boundary.

2. **Sliding window rate estimator** - Uses lorica-limits Rate with a 1-second window for rate limiting and a 60-second window for violation tracking. This provides smooth rate enforcement without the burstiness of token bucket algorithms.

3. **Lazy ban expiry** - Rather than a background sweeper thread, expired bans are cleaned up during request processing in request_filter. This avoids thread overhead and is efficient for moderate ban list sizes.

4. **Cache engine deferred** - The Pingora cache engine integration (request_cache_filter, cache_key_callback, storage backend) was deferred to avoid coupling incomplete cache behavior to the production proxy pipeline. The data model and configuration layer are ready for wiring.

5. **Ban list with RwLock<HashMap>** - Simple concurrency model suitable for the current scale. Read-heavy workload (ban checks) is efficient with RwLock. DashMap could be considered for higher concurrency in the future.

6. **Cache purge as stub** - The DELETE /api/v1/cache/routes/:id endpoint exists and returns 200 but performs no actual cache operation. This allows the API contract to be established before the cache engine is wired.

## NFR Validation

### Security
- Rate limiting enforced early in request_filter before any proxying occurs
- Banned IPs receive 403 immediately with minimal resource usage
- Auto-ban escalation prevents sustained abuse from repeat offenders
- AlertType::IpBanned notifies administrators of ban events
- No cache engine active, so no cache poisoning or timing attack surface yet

### Performance
- Rate estimator is O(1) per check with sliding window algorithm
- Ban list uses RwLock - efficient for read-heavy workload (most requests are not banned)
- Lazy expiry avoids background thread overhead
- All rate/ban state is Arc-shared across the proxy service with no global mutex in hot path

### Reliability
- Sensible defaults: cache_enabled=false, cache_ttl_s=300, auto_ban_duration_s=3600
- All new fields have NOT NULL DEFAULT in migration 009
- Rate and ban state is in-memory only - resets on restart (acceptable for temporary protection state)
- rate_limit_rps=0 means disabled, not block-all

### Maintainability
- Clean model extension with serde defaults for all new Route fields
- Rate limiter and ban list are separate Arc-shared structures with clear ownership
- Test suite covers core ban list and rate limiter behavior with 6 focused unit tests
- Cache API stub follows existing lorica-api patterns (handler, routes, error handling)

## Risk Assessment

| Risk | Severity | Status |
|------|----------|--------|
| Cache engine not wired - cache_enabled=true has no effect | High | Open - immediate priority |
| Slowloris not enforced - slow header attacks not mitigated | Medium | Open - needs Pingora connection handler integration |
| max_connections not enforced at proxy level | Medium | Open - field stored but not checked in request_filter |
| Global flood detection not implemented | Low | Open - future enhancement |
| Ban list viewer not in dashboard | Low | Open - API endpoints exist, UI not built |

## Recommendations

### Immediate
- Wire Pingora cache engine: implement request_cache_filter, cache_key_callback, and response_cache_filter in proxy_wiring.rs with lorica-memory-cache + TinyUFO storage backend
- Inject X-Cache response header (HIT/MISS/BYPASS) in proxy response pipeline
- Implement HTTP cache header compliance (Cache-Control: no-store, ETag/If-None-Match)
- Enforce max_connections per route in request_filter (field exists, check missing)

### Future
- Implement slowloris detection via Pingora header receive timeout
- Implement global flood detection with configurable threshold and dynamic limit tightening
- Build dashboard ban list viewer with IP, reason, expiry, and unban button
- Add cache stats dashboard panel (hit rate, size, entry count per route)
- Consider DashMap for ban list at higher concurrency scales
- Wire cache purge API to actual cache engine once integrated

## Epic Gate Decision

**CONCERNS** - Quality Score: **69**

Story 7.2 (Rate Limiting) passes with a score of 95 - fully implemented and tested. Story 7.3 (Anti-DDoS) passes with concerns at 72 - core auto-ban functionality works but slowloris, max_connections enforcement, and flood detection are missing. Story 7.1 (HTTP Caching) has significant concerns at 40 - only the data model, migration, API stub, and dashboard fields are in place; the actual Pingora cache engine is not wired, meaning cache_enabled=true currently has no effect on proxy behavior. The epic cannot receive a PASS gate until the cache engine is integrated and the primary protection gaps (slowloris, max_connections) are addressed.
