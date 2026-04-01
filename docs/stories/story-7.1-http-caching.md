# Story 7.1: HTTP Response Caching

**Epic:** [Epic 7 - HTTP Caching & DDoS Protection](../prd/epic-7-cache-and-protection.md)
**Status:** Done
**Priority:** P0
**Depends on:** Story 1.8 (proxy engine wiring)

---

As an infrastructure engineer,
I want the proxy to cache static responses in memory,
so that repeated requests for CSS/JS/images are served instantly without hitting the backend.

## Acceptance Criteria

1. Per-route cache toggle (cache_enabled: bool, default false)
2. Configurable cache TTL per route (cache_ttl_s, default 300)
3. Configurable max cache size per route (cache_max_bytes, default 50MB)
4. Respects HTTP cache headers (Cache-Control, ETag, If-Modified-Since)
5. Cache bypass for authenticated requests (Cookie/Authorization headers)
6. Cache status header in response (X-Cache: HIT/MISS/BYPASS)
7. Cache purge API endpoint (DELETE /api/v1/cache/routes/:id)
8. Dashboard cache stats display (hit rate, size, entries)
9. Memory-backed storage using lorica-memory-cache + TinyUFO eviction

## Integration Verification

- IV1: Cached response returns X-Cache: HIT and does not reach backend
- IV2: Cache respects Cache-Control: no-store and does not cache response
- IV3: Cache purge API clears entries and subsequent request returns X-Cache: MISS

## Tasks

- [x] Add cache fields to route model (cache_enabled, cache_ttl_s, cache_max_bytes with defaults)
- [x] Write database migration for new route cache columns
- [ ] Integrate Pingora cache engine with lorica-memory-cache storage backend
- [ ] Implement TinyUFO eviction policy for cache entries
- [ ] Implement cache key generation (method + host + path + query)
- [ ] Implement HTTP cache header respect (Cache-Control, ETag, If-Modified-Since, If-None-Match)
- [ ] Implement cache bypass logic for requests with Cookie or Authorization headers
- [ ] Inject X-Cache response header (HIT/MISS/BYPASS) in proxy response pipeline
- [x] Add cache purge API endpoint (DELETE /api/v1/cache/routes/:id)
- [ ] Expose cache stats via internal metrics (hit count, miss count, size, entry count)
- [x] Update dashboard route form with cache toggle, TTL, and max size inputs
- [ ] Add dashboard cache stats panel (hit rate, current size, entry count per route)
- [ ] Write tests for cache HIT/MISS/BYPASS logic
- [ ] Write tests for HTTP cache header compliance (no-store, no-cache, max-age)
- [ ] Write tests for cache purge API
- [ ] Write tests for TinyUFO eviction when max size exceeded

## Dev Notes

- Cache key: composite of HTTP method + Host header + path + sorted query params
- Only cache GET and HEAD requests - never cache POST/PUT/DELETE
- Cache-Control: no-store must prevent caching entirely; no-cache must revalidate
- ETag/If-None-Match support: return 304 Not Modified when ETag matches
- X-Cache header values: HIT (served from cache), MISS (fetched from backend and cached), BYPASS (not cacheable)
- cache_max_bytes is per route, not global - each route has its own eviction boundary
- TinyUFO provides frequency-based eviction which is better than LRU for CDN-like workloads
- Cache purge should be idempotent - purging an empty cache returns 204
- Default TTL of 300s (5 min) balances freshness with backend load reduction
