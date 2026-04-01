# Story 7.2: Per-Route Rate Limiting

**Epic:** [Epic 7 - HTTP Caching & DDoS Protection](../prd/epic-7-cache-and-protection.md)
**Status:** Draft
**Priority:** P0
**Depends on:** Story 7.1 (HTTP response caching)

---

As an infrastructure engineer,
I want per-route rate limiting to protect backends from traffic spikes and abusive clients.

## Acceptance Criteria

1. Rate limiting enforced in proxy request_filter using lorica-limits Rate estimator
2. Per-client-IP rate tracking (using X-Forwarded-For or direct IP)
3. Route fields rate_limit_rps and rate_limit_burst actually enforced (currently stored but not used)
4. HTTP 429 response when rate exceeded, with Retry-After header
5. Rate limit headers in all responses (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
6. Per-route connection limit (max_connections field, reject with 503 when exceeded)
7. Dashboard shows current rate/connections per route

## Integration Verification

- IV1: Requests exceeding rate_limit_rps receive HTTP 429 with Retry-After header
- IV2: Rate limit headers present in all proxied responses
- IV3: Connections exceeding max_connections receive HTTP 503

## Tasks

- [ ] Wire lorica-limits Rate estimator into proxy request_filter phase
- [ ] Implement client IP extraction (X-Forwarded-For rightmost untrusted, fallback to peer IP)
- [ ] Enforce rate_limit_rps and rate_limit_burst fields from route config
- [ ] Return HTTP 429 with Retry-After header when rate limit exceeded
- [ ] Inject X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset in all responses
- [ ] Implement per-route connection counter (AtomicUsize per route)
- [ ] Enforce max_connections per route, return 503 when exceeded
- [ ] Expose rate limit and connection metrics via internal metrics system
- [ ] Update dashboard route detail view with live rate/connection counters
- [ ] Write tests for rate limiting enforcement (under limit, at limit, over limit)
- [ ] Write tests for Retry-After header calculation
- [ ] Write tests for rate limit response headers
- [ ] Write tests for connection limit enforcement and 503 response
- [ ] Write tests for client IP extraction from X-Forwarded-For

## Dev Notes

- lorica-limits Rate estimator uses a sliding window algorithm - no token bucket needed
- Client IP extraction must handle X-Forwarded-For chains: use rightmost non-trusted IP
- rate_limit_rps=0 means "no limit" (disabled), not "block all"
- rate_limit_burst allows short spikes above rps without triggering 429
- Retry-After header value: seconds until the client can retry (based on window reset)
- X-RateLimit-Reset is a Unix timestamp (seconds), not a duration
- Connection counter must be decremented in upstream_response_filter or on connection close
- Per-route connection tracking uses AtomicUsize for lock-free counting
- Rate limit state is in-memory only - resets on proxy restart (acceptable for this use case)
