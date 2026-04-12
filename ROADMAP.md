# Roadmap

> Last updated: 2026-04-12 | Current release: v1.3.0 | In progress: v1.4.0
>
> See [COMPARISON.md](COMPARISON.md) for the full competitive feature matrix.
>
> **Status:** Planned | In Progress | Done

---

## v1.2.0 - Proxy hardening & quick wins

Leverage existing Pingora framework hooks and add table-stakes features.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| Cache lock (thundering herd protection) | Done | Very Low | Enable `CacheLock` in proxy_wiring.rs. Prevents stampede on cache miss |
| Stale-while-error | Done | Low | Implement `should_serve_stale()` hook. Serve cached content when upstream fails |
| Custom error pages + maintenance mode | Done | Low | Implement `fail_to_proxy()` hook. Route state: active/maintenance/disabled. Branded HTML for 502/503/504/429 |
| Basic auth per route | Done | Low | HTTP Basic Auth for staging, internal tools. Standard across all competitors |
| Retry policy (enriched) | Done | Low | Extend `retry_attempts` with `retry_on` (status codes), `retry_methods`, `retry_backoff_ms`. Implement `fail_to_connect()` hook for smarter retry decisions |
| Structured JSON logs (file/syslog) | Done | Low | Implement `request_summary()` hook. Configurable log output to file/stdout/syslog. ELK/Loki/Datadog integration |
| Least Connections LB | Done | Low | Stub exists in lorica-lb (`// TODO: least conn`). Standard algorithm |
| gRPC-Web module | Done | Low | Module exists in `lorica-core/src/modules/http/grpc_web.rs`, never instantiated. Browser-compatible gRPC |
| HTTP Range requests | Done | Low | Enable `range_header_filter()`. Default implementation exists in `proxy_cache::range_filter` |
| Cache purge via PURGE method | Done | Low | Implement `is_purge()` hook. Currently purge is API-only |
| OCSP stapling | Done | Low | Standard TLS feature. Supported by Nginx, Caddy, HAProxy, BunkerWeb |
| Docker image | Done | Low | Official Docker image. All competitors provide one |

---

## v1.3.0 - Authentication & advanced routing

Major feature additions that close the gap with Traefik and Nginx.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| Forward auth (external authentication) | Done | Medium | Sub-request to auth service (Authelia, Authentik, Keycloak). Subrequest pipe exists in `lorica-proxy/src/subrequest/`. Enable `allow_spawning_subrequest()` + `early_request_filter()` |
| Header-based routing | Done | Low-Medium | Route by HTTP headers (X-Version, X-Tenant). A/B testing, multi-tenant. Traefik, Caddy, HAProxy all support it |
| Canary / traffic split | Done | Medium | Route X% traffic to backend group A, Y% to group B. Zero-risk deployments |
| mTLS client verification | Done | Medium | `ClientCertVerifier` trait support exists in rustls layer. Zero-trust, B2B |
| Response body rewriting | Done | Medium | Implement `response_body_filter()` hook. Nginx `sub_filter` equivalent |
| Request mirroring | Done | Medium | Duplicate traffic to secondary backend (fire-and-forget). Shadow testing |
| Cache Vary support | Done | Medium | Implement `cache_vary_filter()`. `VarianceBuilder` exists in `lorica-cache/src/variance.rs` |
| Stale-while-revalidate | Done | Low | `stale_writer` support exists in cache lock module. Serve stale while background refresh |
| Cache predictor | Done | Medium | `lorica-cache/src/predictor.rs` exists. Learn which assets are cacheable |
| Connection pre-filter | Done | Low | Replace `AcceptAllFilter` with configurable filter. IP-level filtering before TLS handshake |

---

## v1.4.0 - Observability & operations

Production observability and operational tooling.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| OpenTelemetry tracing | Planned | Medium | OTLP export for distributed tracing. Traefik, HAProxy, Sozu support it |
| Country blocking (GeoIP) | Planned | Medium | Filter by country code. Useful for compliance and attack surface reduction |
| Bot detection (JS challenge) | Planned | Medium-High | JavaScript challenge / captcha before proxying. BunkerWeb differentiator |

---

## v2.0.0 - Protocol expansion

Major protocol additions.

| Feature | Status | Effort | Notes |
|---|---|---|---|
| TCP/L4 proxying | Planned | High | Stream proxy for databases, MQTT, SSH. SNI-based routing without TLS termination. Supported by Nginx, Traefik, HAProxy, Sozu |
| HTTP/3 (QUIC) | Planned | High | Blocked on [Pingora PR #524](https://github.com/cloudflare/pingora/pull/524) (tokio-quiche integration). Traefik and HAProxy have production support |

---

Author: Romain G.
