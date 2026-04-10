# Technical Backlog

## High Priority

| # | Feature | Complexity | Type | Notes |
|---|---------|-----------|------|-------|
| 1 | Forward Auth (external authentication) | Medium | Table-stakes | Sub-request to auth service (Authelia, Authentik, Keycloak) before proxying. Standard SSO/MFA mechanism. Traefik forwardAuth, Nginx auth_request. |
| 3 | Custom Error Pages + Maintenance Mode | Low | Table-stakes | Change route `enabled: bool` to enum `active/maintenance/disabled`. Maintenance returns 503 with configurable HTML page. Custom error pages for 502/503/504/429. |

## Medium Priority

| # | Feature | Complexity | Type | Notes |
|---|---------|-----------|------|-------|
| 4 | Basic Auth per Route | Low | Table-stakes | HTTP Basic Auth on specific routes. Useful for staging, internal tools. |
| 5 | Canary / Traffic Split | Medium | Differentiator | Route X% traffic to backend group A, Y% to group B. Zero-risk deployments. |
| 6 | Header-Based Routing | Low-Medium | Differentiator | Route by HTTP headers (X-Version, X-Tenant). A/B testing, multi-tenant. |
| 7 | Retry Policy (enriched) | Low-Medium | Table-stakes | Extend retry_attempts with retry_on (status codes), retry_methods, retry_backoff_ms. |

## Low Priority

| # | Feature | Complexity | Type | Notes |
|---|---------|-----------|------|-------|
| 8 | Structured JSON Logs (file/syslog) | Medium | Differentiator | Configurable log format, write to file/stdout/syslog. ELK/Loki/Datadog integration. |
| 9 | Request Mirroring | Medium | Differentiator | Duplicate traffic to secondary backend (fire-and-forget). Shadow testing. |
| 10 | mTLS Client Verification | Medium | Differentiator | Require client TLS certificate for specific routes. Zero-trust, B2B. |
| 11 | Response Body Rewriting | Medium-High | Table-stakes | Replace strings in response body (Nginx sub_filter). URL rewriting for legacy apps. |
| 12 | TCP/L4 Proxying | High | Differentiator | Stream proxy for databases, MQTT, SSH. SNI-based routing without TLS termination. |
