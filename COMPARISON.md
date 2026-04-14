# Lorica - Competitive Feature Comparison

> Last updated: 2026-04-12 | Lorica v1.3.0
>
> **Legend:** Y = Yes | N = No | P = Partial | Paid = Paid/Enterprise only | Plug = Plugin/Module (not built-in)
>
> **Competitors:** Pingora (framework), Sozu, Nginx OSS, Traefik OSS v3, BunkerWeb, Caddy v2, HAProxy CE

---

## 1. Proxy & Routing

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| HTTP/HTTPS reverse proxy | Y | Y | Y | Y | Y | Y | Y | Y |
| Host-based routing | Y | P | Y | Y | Y | Y | Y | Y |
| Path-based routing | Y | P | P | Y | Y | Y | Y | Y |
| Path rewriting (regex) | Y | N | N | Y | Y | P | Y | Y |
| WebSocket proxying | Y | Y | P | Y | Y | Y | Y | Y |
| gRPC proxying | Y | Y | N | Y | Y | Plug | Y | Y |
| HTTP/2 upstream (h2c) | Y | Y | N | Y | Y | P | Y | Y |
| HTTP/3 (QUIC) | N | N | N | N | Y | N | P | Y |
| TLS termination (rustls) | Y | Y | Y | Y | Y | Y | Y | Y |
| SNI-based cert selection | Y | P | Y | Y | Y | Y | Y | Y |
| Wildcard cert support | Y | P | Y | Y | Y | Y | Y | Y |
| Catch-all fallback host | Y | P | P | Y | P | P | Y | Y |
| Domain redirects (301) | Y | N | P | Y | Y | Y | Y | Y |
| Direct status responses | Y | P | Y | Y | Y | Y | Y | Y |
| Connection pooling | Y | Y | Y | Y | Y | Y | Y | Y |
| Sticky sessions (cookie) | Y | P | Y | Paid | Y | Paid | Y | Y |
| Forward auth | Y | N | N | Y | Y | Y | Y | P |
| Header-based routing | Y | P | N | P | Y | N | Y | Y |
| Canary / traffic split (weighted) | Y | N | N | N | P | N | N | Y |
| Response body rewriting | Y | N | N | Y | N | N | N | N |
| **TCP/L4 proxying** | **N** | Y | Y | Y | Y | Y | Plug | Y |
| **UDP proxying** | **N** | N | N | Y | Y | P | Plug | Y |

### Gaps for Lorica

- **TCP/L4 proxying** - Supported by most competitors. Enables database, MQTT, SSH proxying.
- **HTTP/3 (QUIC)** - Traefik and HAProxy have production support. Pingora has an upstream PR pending. Long-term gap.

---

## 2. Load Balancing

| Algorithm | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Round Robin (weighted) | Y | Y | Y | Y | Y | Paid | Y | Y |
| Least Connections | Y | Y | Y | Y | Y | N | Y | Y |
| Peak EWMA | Y | Y | N | N | N | N | N | N |
| Consistent Hash | Y | Y | N | Y | N | N | Y | Y |
| Random | Y | Y | Y | Y | N | N | Y | Y |
| IP Hash | N | N | N | Y | N | N | Y | Y |
| Health-aware filtering | Y | Y | Y | Paid | Y | Paid | Y | Y |
| Traffic mirroring | Y | N | N | N | Y | N | N | N |

### Lorica Strengths

- **Traffic mirroring** - Only Traefik and Lorica ship this natively. Lorica's implementation adds request-body mirroring up to a configurable cap, deterministic per-request-id sampling, and a 256-slot concurrency semaphore so a slow shadow can't starve the primary.

### Gaps for Lorica

- ~~Least Connections~~ - Implemented in v1.2.0.

---

## 3. Security

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| WAF engine (OWASP rules) | Y (49) | N | N | Plug | Plug | Y | Plug | N |
| Custom WAF rules | Y | N | N | Plug | Plug | Y | N | N |
| IP blocklist (auto-fetched) | Y | N | N | N | N | Y | N | N |
| Rate limiting per route | Y | P | N | Y | Y | Y | Plug | Y |
| Auto-ban (repeat offenders) | Y | N | N | N | N | Y | N | N |
| Trusted proxies (XFF) | Y | N | P | N | Y | N | Y | N |
| DDoS protection (flood) | Y | N | P | P | N | Paid | N | P |
| Slowloris detection | Y | N | N | Y | N | N | N | N |
| Security header presets | Y | N | N | N | Y | Y | N | N |
| IP allowlist/denylist | Y | N | N | Y | Y | Y | Y | Y |
| CORS per route | Y | N | N | P | Y | Y | P | P |
| Basic auth per route | Y | N | N | Y | Y | Y | Y | Y |
| **Bot detection (captcha)** | **N** | N | N | N | N | Y | N | N |
| **Country blocking (GeoIP)** | **N** | N | N | Plug | N | Y | N | N |
| Request body scanning | Y | N | N | Plug | Plug | Y | N | N |
| mTLS client verification | Y | Y | N | Y | Y | Y | Y | Y |
| Connection pre-filter (pre-TLS CIDR) | Y | P | P | P | N | N | N | Y |

### Lorica Strengths

- **Built-in WAF** with 49 OWASP rules - only BunkerWeb matches this out-of-the-box. Nginx/Traefik require external plugins.
- **Auto-ban** - Only BunkerWeb has equivalent (Bad Behavior plugin).
- **IP blocklist auto-fetch** - Only BunkerWeb has equivalent (Blacklist plugin + BunkerNet).
- **Slowloris detection** - Rare built-in feature.
- **Connection pre-filter at TCP accept** - CIDR allow/deny evaluated before the TLS handshake, hot-reloaded without rebuilding listeners.

### Gaps for Lorica

- ~~Basic auth per route~~ - Implemented in v1.2.0.
- ~~mTLS client verification~~ - Implemented in v1.3.0.
- **Bot detection** - BunkerWeb's major differentiator (JS challenge, captcha, hCaptcha, Turnstile).
- **Country blocking** - BunkerWeb has it. Useful for compliance and attack surface reduction.

---

## 4. Caching

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| HTTP response cache | Y | P | N | Y | Paid | Paid | Plug | Y |
| LRU eviction | Y | Y | N | Y | - | - | Plug | Y |
| Per-route toggle | Y | P | N | Y | - | - | Plug | Y |
| Cache-Control respect | Y | P | N | Y | - | - | Plug | Y |
| Cache purge API | Y | N | N | Plug | - | - | Plug | N |
| X-Cache-Status header | Y | N | N | P | - | - | Plug | N |
| Vary header partitioning | Y | P | N | Y | - | - | P | Y |
| Stale-while-revalidate (background refresh) | Y | P | N | Y | - | - | Plug | N |
| Cache predictor (learn-uncacheable) | Y | Y | N | N | - | - | N | N |

### Lorica Strengths

- **Built-in HTTP cache** - Traefik requires Enterprise, BunkerWeb requires PRO, Caddy requires plugin. Only Nginx and HAProxy match this natively.
- **Cache purge API** - Not available in Nginx OSS or HAProxy natively.
- **Stale-while-revalidate with true background refresh** - most competitors serve stale on error only; Lorica spawns a background sub-request that refreshes the entry while the current request already has the stale body.
- **Cache predictor** - shared 16-shard LRU remembers deterministically-uncacheable responses so future requests for the same key skip the cache state machine entirely. Only Pingora's framework ships the equivalent.

---

## 5. TLS & Certificates

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| ACME HTTP-01 | Y | N | Y | Plug | Y | Y | Y | Y |
| ACME DNS-01 | Y | N | N | N | Y | Y | Y | Y |
| ACME TLS-ALPN-01 | N | N | N | Plug | Y | N | Y | N |
| Auto-renewal | Y | N | P | N | Y | Y | Y | Y |
| Multi-domain SAN | Y | N | N | N | Y | N | Y | N |
| Wildcard via DNS-01 | Y | N | N | N | Y | Y | Y | Y |
| SNI hot-swap | Y | P | Y | N | Y | N | Y | N |
| CRL support | Y | P | N | Y | N | N | N | Y |
| OCSP stapling | Y | N | N | Y | N | Y | Y | Y |
| mTLS client certs | Y | Y | N | Y | Y | Y | Y | Y |

### Lorica Strengths

- **ACME DNS-01 with 3 providers** (Cloudflare, Route53, OVH) + manual mode - competitive with Traefik and Caddy.
- **SNI hot-swap** via arc-swap - zero-downtime cert rotation.
- **CRL support** - Rare feature, only Nginx and HAProxy match.
- **Per-route mTLS policy** - chain verification at the TLS listener plus per-route enforcement knobs (`required`, org allowlist) that hot-reload without restart. Most competitors only expose a single listener-wide client-cert setting.

### Gaps for Lorica

- ~~mTLS client verification~~ - Implemented in v1.3.0.
- ~~OCSP stapling~~ - Implemented in v1.2.0.

---

## 6. Monitoring & Observability

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Passive SLA monitoring | Y | N | N | N | N | N | N | N |
| Active SLA probes | Y | P | N | Paid | Y | Paid | Y | Y |
| Prometheus metrics | Y | P | P | Plug | Y | P | Y | Y |
| Real-time access logs (WS) | Y | N | N | N | N | N | N | N |
| Built-in load testing | Y | N | N | N | N | N | N | N |
| SLA breach alerts | Y | N | N | N | N | N | N | N |
| **OpenTelemetry tracing** | **N** | P | Y | N | Y | N | P | Y |
| Structured JSON logs | Y | P | Y | Y | Y | Y | Y | Y |

### Lorica Strengths

- **Passive SLA monitoring** - Unique feature. No competitor offers built-in SLA tracking from real traffic.
- **Active SLA probes** - Combined with passive SLA, provides comprehensive uptime monitoring.
- **Built-in load testing** - Unique. No competitor includes this.
- **Real-time WebSocket log streaming** - Unique dashboard feature.
- **SLA breach alerts** - Unique automated alerting.

### Gaps for Lorica

- **OpenTelemetry tracing** - Traefik (native OTLP), HAProxy (OpenTracing filter), Sozu support it. Important for distributed tracing.
- ~~Structured JSON logs to file/syslog~~ - Implemented in v1.2.0.

---

## 7. Management & Dashboard

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Web dashboard (full CRUD) | Y | N | N | Paid | P (RO) | Y | N | P (RO) |
| REST API (full CRUD) | Y | N | N | Paid | P (RO) | Y | Y | Y |
| Config export/import | Y | N | Y | N | N | N | Y | N |
| Nginx config import | Y | N | N | - | N | N | N | N |
| Notification channels | Y | N | N | N | N | N | N | N |
| SMTP/Slack/Webhook alerts | Y | N | N | N | N | N | N | N |
| CLI management | Y | N | Y | Y | Y | Y | Y | Y |
| **Docker label discovery** | **N** | N | N | N | Y | Y | N | N |
| **Kubernetes Ingress** | **N** | N | N | Y | Y | Y | N | Y |
| **Config providers (etcd/Consul)** | **N** | N | N | N | Y | N | N | N |

### Lorica Strengths

- **Full CRUD dashboard** - Only BunkerWeb matches this. Traefik's dashboard is read-only. HAProxy's stats page is read-only.
- **Nginx config import** - Unique feature. No competitor offers migration tooling.
- **Notification channels** (SMTP, Slack, Webhook) - Unique. No competitor has built-in alerting.
- **Config export/import with diff preview** - Unique.

### Gaps for Lorica

- **Service discovery** (Docker, Kubernetes) - Traefik's main differentiator. Important for cloud-native deployments.
- **Config providers** - Traefik supports 10+ providers (Docker, K8s, Consul, etcd, etc.).

---

## 8. Reliability & Operations

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Worker process isolation | Y | P | Y | Y | N | Y | N | N |
| Zero-downtime reload | Y | Y | Y | Y | Y | Y | Y | Y |
| Health checks (TCP/HTTP) | Y | Y | P | Paid | Y | Paid | Y | Y |
| Circuit breaker | Y | P | N | N | Y | N | P | P |
| Graceful drain | Y | Y | Y | Paid | Y | Y | Y | Y |
| Encrypted storage (AES) | Y | N | N | N | N | N | N | N |
| **Retry with backoff** | **P** | N | N | N | Y | N | Y | Y |
| **Hot binary upgrade** | **N** | Y | Y | Y | N | Y | N | Y |

### Lorica Strengths

- **Worker process isolation** with protobuf command channel - only Nginx and Sozu have comparable models.
- **Circuit breaker** - Per-backend failure tracking with half-open probe.
- **Encrypted storage** - Unique. No competitor encrypts secrets at rest.

### Gaps for Lorica

- **Retry with backoff** - Already in backlog. Traefik, Caddy, HAProxy support configurable retry policies.

---

## 9. Packaging & Deployment

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| .deb package | Y | N | N | Y | Y | Y | Y | Y |
| .rpm package | Y | N | N | Y | Y | Y | Y | Y |
| Docker image | Y | N | Y | Y | Y | Y | Y | Y |
| Systemd hardened unit | Y | N | Y | Y | N | N | Y | Y |
| Single binary | Y | N | Y | Y | Y | N | Y | Y |
| GPG-signed releases | Y | N | N | Y | Y | N | Y | N |
| **Helm chart** | **N** | N | N | Y | Y | Y | N | Y |

### Gaps for Lorica

- ~~Docker image~~ - Implemented in v1.2.0.
- **Helm chart** - Nginx, Traefik, BunkerWeb, HAProxy publish official charts; useful for Kubernetes adoption.

---

## Summary: Lorica's Unique Differentiators

These features are either unique to Lorica or extremely rare among competitors:

| Feature | Available In |
|---|---|
| Full CRUD web dashboard (embedded, zero deps) | Lorica, BunkerWeb |
| Built-in SLA monitoring (passive + active) | Lorica only |
| Built-in load testing with SSE streaming | Lorica only |
| Real-time WebSocket log streaming | Lorica only |
| SLA breach notifications (SMTP/Slack/Webhook) | Lorica only |
| Nginx config import wizard | Lorica only |
| Config export/import with diff preview | Lorica only |
| Encrypted secrets at rest (AES-256-GCM) | Lorica only |
| Built-in WAF + auto-ban + IP blocklist | Lorica, BunkerWeb |
| Peak EWMA load balancing | Lorica, Pingora |
| Cache predictor (learn-uncacheable) | Lorica, Pingora |
| Per-route mTLS with hot-reload policy (required + org allowlist) | Lorica only |
| Forward-auth verdict cache (opt-in, TTL-capped, cookie-keyed) | Lorica only |
| Connection pre-filter at TCP accept (hot-reloaded CIDR) | Lorica, HAProxy |

---

## Summary: Priority Gaps to Address

### Table-Stakes (most competitors have these)

| Feature | Backlog? | Competitors With It |
|---|---|---|
| ~~Forward auth (external auth)~~ | ~~Yes (#1)~~ | Implemented in v1.3.0 |
| ~~Basic auth per route~~ | ~~Yes (#4)~~ | Implemented in v1.2.0 |
| ~~Custom error pages + maintenance mode~~ | ~~Yes (#3)~~ | Implemented in v1.2.0 |
| ~~mTLS client verification~~ | ~~Yes (#10)~~ | Implemented in v1.3.0 |
| ~~Retry with backoff~~ | ~~Yes (#7)~~ | Implemented in v1.2.0 (retry_on_methods) |

### Differentiators (competitive advantage opportunities)

| Feature | Backlog? | Competitors With It |
|---|---|---|
| ~~Canary / traffic split~~ | ~~Yes (#5)~~ | Implemented in v1.3.0 |
| ~~Header-based routing~~ | ~~Yes (#6)~~ | Implemented in v1.3.0 |
| ~~Structured JSON logs (file/syslog)~~ | ~~Yes (#8)~~ | Implemented in v1.2.0 |
| ~~Request mirroring~~ | ~~Yes (#9)~~ | Implemented in v1.3.0 |
| TCP/L4 proxying | Yes (#12) | All except Pingora framework |

### Not Yet in Backlog (consider adding)

| Feature | Priority | Rationale |
|---|---|---|
| ~~OCSP stapling~~ | ~~Medium~~ | Implemented in v1.2.0 |
| OpenTelemetry tracing | Medium | Traefik, HAProxy, Sozu support it. Key for distributed systems |
| ~~Least Connections LB~~ | ~~Low~~ | Implemented in v1.2.0 |
| ~~Docker image~~ | ~~Medium~~ | Implemented in v1.2.0 |
| Bot detection (JS challenge/captcha) | Low | Only BunkerWeb has it. Niche but impressive |
| Country blocking (GeoIP) | Low | Only BunkerWeb has it. Useful for compliance |
| ~~Response body rewriting~~ | ~~Low~~ | Implemented in v1.3.0 |
| ~~Cache Vary partitioning~~ | ~~-~~ | Implemented in v1.3.0 |
| ~~Cache predictor~~ | ~~-~~ | Implemented in v1.3.0 |
| ~~Stale-while-revalidate (background refresh)~~ | ~~-~~ | Implemented in v1.3.0 |
| ~~Connection pre-filter (pre-TLS CIDR)~~ | ~~-~~ | Implemented in v1.3.0 |

---

## Pingora Framework: Untapped Capabilities

Lorica is a fork of Cloudflare Pingora. The forked crates already contain significant capabilities that the product does not yet expose. These represent **low-hanging fruit** - the code exists in the workspace, it just needs wiring into the product layer.

### ProxyHttp Trait Hooks

The `ProxyHttp` trait in `lorica-proxy/src/proxy_trait.rs` defines 41 methods. v1.3.0 pushed the used count from 12 to 20+. The remaining unused hooks still unlock features with minimal effort.

#### Tapped in v1.2.0 / v1.3.0

| Hook | Shipped As | Version |
|---|---|---|
| `fail_to_proxy()` | Custom error pages + maintenance mode | v1.2.0 |
| `should_serve_stale()` | Stale-while-error + stale-while-revalidate background refresh | v1.2.0 / v1.3.0 |
| `request_summary()` | Structured JSON access logs | v1.2.0 |
| `is_purge()` + `purge_response_filter()` | Cache purge via HTTP PURGE method | v1.2.0 |
| `range_header_filter()` | HTTP Range requests | v1.2.0 |
| `response_body_filter()` | Response body rewriting | v1.3.0 |
| `allow_spawning_subrequest()` + subrequest pipe | Forward auth + SWR background refresh | v1.3.0 |
| `cache_vary_filter()` | Cache Vary partitioning | v1.3.0 |

#### Still Untapped (remaining opportunities)

| Hook | Feature It Unlocks | Effort |
|---|---|---|
| `upstream_response_filter()` | **Header injection/removal** on upstream responses before caching | Low |
| `suppress_error_log()` | **Noise reduction** - suppress known-benign errors (e.g. client disconnects) | Low |
| `fail_to_connect()` | **Smarter retry decisions** - mark errors as retryable or not | Low |
| `error_while_proxy()` | **Error context enrichment** for better diagnostics | Low |

### Load Balancing (lorica-lb)

| Capability | Location | Status | Effort |
|---|---|---|---|
| **Least Connections** | `lorica-lb/src/selection/mod.rs` (marked `// TODO: least conn`) | Framework stub exists, needs implementation | Low |
| **Health-aware filtering** | Already in `lorica-lb/src/health_check.rs` | Used, but could expose more config | - |

### Cache (lorica-cache)

Most cache capabilities are now wired. Remaining:

| Capability | Location | What It Does | Effort | Status |
|---|---|---|---|---|
| ~~Cache Lock~~ | `lorica-cache/src/lock.rs` | Thundering-herd protection | Low | v1.2.0 |
| ~~Cache Predictor~~ | `lorica-cache/src/predictor.rs` | Learn-uncacheable short-circuit | Medium | v1.3.0 |
| ~~Vary/Variance~~ | `lorica-cache/src/variance.rs` | `Vary`-header cache partitioning | Medium | v1.3.0 |
| ~~Stale-while-revalidate~~ | `lock.rs` `stale_writer` | Serve stale + background refresh | Low | v1.2.0 / v1.3.0 |
| **Streaming Miss** | `storage.rs` `lookup_streaming_write()` | Serve partial content while still fetching from upstream - reduces TTFB for cache misses | Medium | Untapped |

### TLS / mTLS (lorica-core)

| Capability | Location | What It Does | Effort | Status |
|---|---|---|---|---|
| ~~mTLS client verification~~ | `lorica-core/src/listeners/tls/rustls/mod.rs` `set_client_cert_verifier()` | Per-route client-cert chain validation + org allowlist | Medium | v1.3.0 |

### Protocol Support (lorica-core)

| Capability | Location | What It Does | Effort |
|---|---|---|---|
| ~~gRPC-Web module~~ | `lorica-core/src/modules/http/grpc_web.rs` | gRPC-Web to gRPC translation (browser-compatible gRPC) | Low | v1.2.0 |
| ~~Connection filter~~ | `lorica-core/src/listeners/connection_filter.rs` | Per-connection admission control. CIDR allow/deny pre-TLS | Low | v1.3.0 |
| **Custom protocol connectors** | `lorica-core/src/connectors/http/custom/mod.rs` | Non-standard HTTP protocol handling via trait | High | Untapped |

### Error Handling (5 hooks, 0 custom)

All error hooks use defaults. Implementing them enables:

| Hook | Feature | Effort |
|---|---|---|
| `fail_to_proxy()` | Custom error responses with HTML templates per error type | Low |
| `fail_to_connect()` | Smarter retry decisions (mark errors as retryable or not) | Low |
| `error_while_proxy()` | Error context enrichment for better diagnostics | Low |
| `should_serve_stale()` | Graceful degradation - serve cached content on upstream failure | Low |

### Priority Matrix: Pingora Quick Wins (consolidated ledger)

Baseline audit of Pingora-coded-but-unused capabilities, updated as each one ships.

| Feature | Effort | Impact | Status |
|---|---|---|---|
| ~~Cache lock (thundering herd protection)~~ | Very Low | High | v1.2.0 |
| ~~Stale-while-error~~ | Low | High | v1.2.0 |
| ~~Custom error pages~~ | Low | High | v1.2.0 |
| ~~Structured JSON logs~~ | Low | High | v1.2.0 |
| ~~HTTP Range requests~~ | Low | Medium | v1.2.0 |
| ~~Cache purge via PURGE method~~ | Low | Medium | v1.2.0 |
| ~~gRPC-Web module~~ | Low | Medium | v1.2.0 |
| ~~Least Connections LB~~ | Low | Medium | v1.2.0 |
| ~~Connection pre-filter~~ | Low | Medium | v1.3.0 |
| ~~Forward auth (subrequests)~~ | Medium | High | v1.3.0 |
| ~~Response body rewriting~~ | Medium | High | v1.3.0 |
| ~~mTLS client verification~~ | Medium | High | v1.3.0 |
| ~~Cache Vary support~~ | Medium | Medium | v1.3.0 |
| ~~Cache predictor~~ | Medium | Medium | v1.3.0 |
| ~~Stale-while-revalidate (background refresh)~~ | Low | High | v1.3.0 |
| ~~Request mirroring~~ | Medium | Medium | v1.3.0 |
| ~~Canary / traffic split~~ | Medium | High | v1.3.0 |
| ~~Header-based routing~~ | Low-Medium | High | v1.3.0 |
| Streaming cache miss | Medium | Medium | Untapped |
| Upstream response header filter | Low | Low | Untapped |
| Custom protocol connectors | High | Low | Untapped |

---

Author: Romain G.
