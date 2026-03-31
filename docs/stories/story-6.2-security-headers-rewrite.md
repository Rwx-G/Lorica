# Story 6.2: Security Response Headers and Path Rewriting

**Epic:** [Epic 6 - Route Configuration](../prd/epic-6-route-config.md)
**Status:** Draft
**Priority:** P1
**Depends on:** Story 6.1

---

As an infrastructure engineer,
I want security headers on responses and path rewriting rules,
so that I can harden responses and decouple external paths from backend paths.

## Acceptance Criteria

1. Each route can add custom response headers (returned to client)
2. Security header presets: "strict" (HSTS+X-Frame-Options+X-Content-Type-Options+Referrer-Policy), "moderate" (X-Content-Type-Options only), "none"
3. Path rewrite: configurable strip_prefix and add_prefix (e.g., /api/v1 -> / on backend)
4. Per-route access_log_enabled toggle (default true)
5. Dashboard route form includes security preset, custom response headers, path rewrite, and log toggle
6. Tests verify response headers, path rewriting, and log suppression

## Integration Verification

- IV1: Security headers present in client response matching selected preset
- IV2: Backend receives rewritten path when strip_prefix/add_prefix configured
- IV3: Access log entries absent for route with logging disabled

## Tasks

- [x] Add response header fields to route model (HashMap<String, String> for custom response headers)
- [x] Add security_header_preset enum to route model (Strict, Moderate, None)
- [x] Add strip_prefix and add_prefix fields to route model
- [x] Add access_log_enabled boolean field to route model (default true)
- [x] Write database migration for new route columns
- [x] Implement security header preset expansion (strict/moderate/none -> concrete headers)
- [x] Implement response header injection in proxy pipeline (preset + custom merge)
- [x] Implement path rewrite logic (strip_prefix then add_prefix before forwarding)
- [x] Implement per-route access log suppression in logging middleware
- [x] Add API endpoints for route response config CRUD
- [x] Update dashboard route form with security preset dropdown, response headers editor, path rewrite inputs, and log toggle
- [x] Write tests for security header presets (strict, moderate, none)
- [x] Write tests for custom response header injection
- [x] Write tests for path rewrite combinations (strip only, add only, both)
- [x] Write tests for access log suppression

## Dev Notes

- Strict preset headers: Strict-Transport-Security: max-age=63072000; includeSubDomains, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin
- Moderate preset headers: X-Content-Type-Options: nosniff
- Custom response headers override preset headers by key name
- Path rewrite order: strip_prefix first, then prepend add_prefix
- strip_prefix match should be case-sensitive and prefix-only (no partial segment match)
- Example: strip_prefix="/api/v1", add_prefix="/" turns /api/v1/users into /users
- access_log_enabled=false suppresses access log lines but NOT error logs or metrics collection
