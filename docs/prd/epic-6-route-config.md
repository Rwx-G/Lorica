# Epic 6: Route Configuration - Production Proxy Features

**Epic Goal:** Add production-grade proxy configuration per route: HTTP-to-HTTPS redirect, configurable proxy headers, per-route timeouts, security response headers, path rewriting, hostname aliases/redirects, and per-route access log control.

**Integration Requirements:** Route configuration extends the existing route model in the embedded database and proxy engine. Proxy headers and timeouts are applied in the forwarding pipeline. Security headers are injected into responses. Path rewriting transforms the URI before forwarding. Hostname aliases and redirects are resolved during request routing. All settings are manageable from the dashboard route form.

---

## Story 6.1: Proxy Headers and Timeouts

As an infrastructure engineer,
I want configurable proxy headers, per-route timeouts, and HTTP-to-HTTPS redirect,
so that I can control how requests are forwarded to backends and enforce HTTPS.

### Acceptance Criteria

1. Each route has configurable proxy headers (add/override headers forwarded to backend)
2. Each route has configurable timeouts (connect_timeout_s, read_timeout_s, send_timeout_s) with sensible defaults (5s, 60s, 60s)
3. HTTP-to-HTTPS redirect can be enabled per route (returns 301 to https:// equivalent)
4. Default proxy headers (Host, X-Real-IP from client IP, X-Forwarded-For, X-Forwarded-Proto) are always set unless explicitly overridden
5. Dashboard route form includes proxy headers, timeouts, and redirect toggle
6. Tests verify header injection, timeout behavior, and redirect logic

### Integration Verification

- IV1: Proxy headers appear in backend request when inspected
- IV2: Request times out when backend exceeds configured timeout
- IV3: HTTP request returns 301 to HTTPS equivalent when redirect enabled

---

## Story 6.2: Security Response Headers and Path Rewriting

As an infrastructure engineer,
I want security headers on responses and path rewriting rules,
so that I can harden responses and decouple external paths from backend paths.

### Acceptance Criteria

1. Each route can add custom response headers (returned to client)
2. Security header presets: "strict" (HSTS+X-Frame-Options+X-Content-Type-Options+Referrer-Policy), "moderate" (X-Content-Type-Options only), "none"
3. Path rewrite: configurable strip_prefix and add_prefix (e.g., /api/v1 -> / on backend)
4. Per-route access_log_enabled toggle (default true)
5. Dashboard route form includes security preset, custom response headers, path rewrite, and log toggle
6. Tests verify response headers, path rewriting, and log suppression

### Integration Verification

- IV1: Security headers present in client response matching selected preset
- IV2: Backend receives rewritten path when strip_prefix/add_prefix configured
- IV3: Access log entries absent for route with logging disabled

---

## Story 6.3: Hostname Aliases and Redirects

As an infrastructure engineer,
I want hostname aliases and hostname redirects per route,
so that I can serve multiple domains from one route and canonicalize hostnames.

### Acceptance Criteria

1. Route has optional redirect_to_hostname field (301 redirect before proxying)
2. Route has optional hostname_aliases list (additional hostnames that match this route)
3. Dashboard route form includes alias list and redirect hostname
4. Tests verify alias matching and redirect behavior

### Integration Verification

- IV1: Request to alias hostname is routed to correct backend
- IV2: Request to redirected hostname receives 301 to canonical hostname
- IV3: Alias and redirect settings persist across restart
