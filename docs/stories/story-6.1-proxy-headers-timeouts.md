# Story 6.1: Proxy Headers and Timeouts

**Epic:** [Epic 6 - Route Configuration](../prd/epic-6-route-config.md)
**Status:** Draft
**Priority:** P1
**Depends on:** Story 1.8 (proxy engine wiring)

---

As an infrastructure engineer,
I want configurable proxy headers, per-route timeouts, and HTTP-to-HTTPS redirect,
so that I can control how requests are forwarded to backends and enforce HTTPS.

## Acceptance Criteria

1. Each route has configurable proxy headers (add/override headers forwarded to backend)
2. Each route has configurable timeouts (connect_timeout_s, read_timeout_s, send_timeout_s) with sensible defaults (5s, 60s, 60s)
3. HTTP-to-HTTPS redirect can be enabled per route (returns 301 to https:// equivalent)
4. Default proxy headers (Host, X-Real-IP from client IP, X-Forwarded-For, X-Forwarded-Proto) are always set unless explicitly overridden
5. Dashboard route form includes proxy headers, timeouts, and redirect toggle
6. Tests verify header injection, timeout behavior, and redirect logic

## Integration Verification

- IV1: Proxy headers appear in backend request when inspected
- IV2: Request times out when backend exceeds configured timeout
- IV3: HTTP request returns 301 to HTTPS equivalent when redirect enabled

## Tasks

- [ ] Add proxy header fields to route model (HashMap<String, String> for custom headers)
- [ ] Add timeout fields to route model (connect_timeout_s, read_timeout_s, send_timeout_s with defaults)
- [ ] Add force_https_redirect boolean field to route model
- [ ] Write database migration for new route columns
- [ ] Implement default proxy header injection in proxy pipeline (Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto)
- [ ] Implement custom proxy header override/merge logic
- [ ] Implement per-route timeout application in HTTP client
- [ ] Implement HTTP-to-HTTPS redirect middleware (301 to https:// equivalent)
- [ ] Add API endpoints for route proxy config CRUD
- [ ] Update dashboard route form with proxy headers editor, timeout inputs, and redirect toggle
- [ ] Write tests for header injection (default + custom override)
- [ ] Write tests for timeout behavior (connect, read, send)
- [ ] Write tests for HTTP-to-HTTPS redirect logic

## Dev Notes

- Default timeouts: connect=5s, read=60s, send=60s - match common reverse proxy defaults
- X-Forwarded-For must append client IP to existing header (chain), not replace
- X-Forwarded-Proto should reflect the original client protocol (http or https)
- Custom headers override defaults by key name (case-insensitive match)
- HTTP-to-HTTPS redirect should preserve path, query string, and fragment
- Redirect only applies when force_https_redirect=true AND request scheme is http
- Timeout of 0 means "use global default", not "no timeout"
