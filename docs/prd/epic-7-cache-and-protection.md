# Epic 7: HTTP Caching & DDoS Protection

**Epic Goal:** Activate the Pingora HTTP cache engine for static content acceleration and implement multi-layer DDoS protection with per-route rate limiting, connection limits, slowloris detection, and automatic IP banning.

**Integration Requirements:** HTTP caching hooks into the proxy response pipeline using Pingora's built-in cache engine with lorica-memory-cache storage and TinyUFO eviction. Rate limiting is enforced in request_filter using lorica-limits Rate estimator, tracking per-client-IP counters. Anti-DDoS protection adds connection-level guards (slowloris detection, global connection limits) and an auto-ban system that escalates repeated rate limit violations into temporary IP bans. All settings are per-route where applicable and manageable from the dashboard.

---

## Story 7.1: HTTP Response Caching

As an infrastructure engineer,
I want the proxy to cache static responses in memory,
so that repeated requests for CSS/JS/images are served instantly without hitting the backend.

### Acceptance Criteria

1. Per-route cache toggle (cache_enabled: bool, default false)
2. Configurable cache TTL per route (cache_ttl_s, default 300)
3. Configurable max cache size per route (cache_max_bytes, default 50MB)
4. Respects HTTP cache headers (Cache-Control, ETag, If-Modified-Since)
5. Cache bypass for authenticated requests (Cookie/Authorization headers)
6. Cache status header in response (X-Cache: HIT/MISS/BYPASS)
7. Cache purge API endpoint (DELETE /api/v1/cache/routes/:id)
8. Dashboard cache stats display (hit rate, size, entries)
9. Memory-backed storage using lorica-memory-cache + TinyUFO eviction

### Integration Verification

- IV1: Cached response returns X-Cache: HIT and does not reach backend
- IV2: Cache respects Cache-Control: no-store and does not cache response
- IV3: Cache purge API clears entries and subsequent request returns X-Cache: MISS

---

## Story 7.2: Per-Route Rate Limiting

As an infrastructure engineer,
I want per-route rate limiting to protect backends from traffic spikes and abusive clients.

### Acceptance Criteria

1. Rate limiting enforced in proxy request_filter using lorica-limits Rate estimator
2. Per-client-IP rate tracking (using X-Forwarded-For or direct IP)
3. Route fields rate_limit_rps and rate_limit_burst actually enforced (currently stored but not used)
4. HTTP 429 response when rate exceeded, with Retry-After header
5. Rate limit headers in all responses (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
6. Per-route connection limit (max_connections field, reject with 503 when exceeded)
7. Dashboard shows current rate/connections per route

### Integration Verification

- IV1: Requests exceeding rate_limit_rps receive HTTP 429 with Retry-After header
- IV2: Rate limit headers present in all proxied responses
- IV3: Connections exceeding max_connections receive HTTP 503

---

## Story 7.3: Anti-DDoS Protection

As an infrastructure engineer,
I want automatic DDoS mitigation to protect the proxy and backends from volumetric and application-layer attacks.

### Acceptance Criteria

1. Slowloris detection: abort connections that send headers too slowly (configurable threshold)
2. Auto-ban: IPs exceeding rate limits N times get temporarily banned (configurable ban_duration_s)
3. Ban list stored in memory with auto-expiry
4. Global connection limit (max total proxy connections, reject with 503)
5. Request flood detection: if global RPS exceeds threshold, enable stricter per-IP limits
6. Ban list visible and manageable in dashboard (view, unban)
7. Ban events dispatched to notification system (AlertType::IpBanned)

### Integration Verification

- IV1: Slow header sender gets disconnected after threshold exceeded
- IV2: IP exceeding rate limits repeatedly gets banned and receives immediate 403
- IV3: Ban list displays in dashboard and manual unban takes effect immediately
