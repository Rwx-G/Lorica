<p align="center">
  <img src="docs/assets/lorica-logo.png" alt="Lorica" width="128">
  <h1 align="center">Lorica</h1>
  <p align="center"><strong>A modern, secure, dashboard-first reverse proxy built in Rust</strong></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/version-1.5.0-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Rust-2024-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Linux-0078D6.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Lorica%20Tests-985-brightgreen.svg" alt="Lorica Tests">
  <img src="https://img.shields.io/badge/Pingora%20Tests-568-blue.svg" alt="Inherited Tests">
</p>

---

Lorica is a production-ready reverse proxy with a built-in web dashboard, WAF, SLA monitoring, and HTTP caching. One binary, zero external dependencies. Install it, open your browser, and manage everything from the UI - routes, backends, certificates, security rules, and performance metrics.

Built on [Cloudflare Pingora](https://github.com/cloudflare/pingora), the engine that powers a significant portion of Cloudflare's CDN traffic.

## Key Features

### :shield: Proxy & Routing

- HTTP/HTTPS reverse proxy with host-based and path-prefix routing
- **Path rules** - ordered sub-path overrides within a route for backends, cache, headers, rate limits, or direct HTTP status responses
- **Header-based routing** - per-route rules that pick a backend group by request header value (Exact / Prefix / Regex). A/B testing (`X-Version: beta`), multi-tenant isolation (`X-Tenant: acme`), no upstream URL changes
- **Canary traffic split** - send `X%` of requests to an alternate backend group with sticky-per-IP deterministic bucketing. Multiple splits per route; weights capped at 100 cumulative
- **Response body rewriting** - ordered search-and-replace rules (literal or regex with capture groups) applied to upstream response bodies. Configurable content-type filter, max body cap, streams verbatim over the cap
- TLS termination via rustls (no OpenSSL dependency)
- SNI-based certificate selection with wildcard domain support (`*.example.com`)
- Path rewriting (strip/add prefix, regex with capture groups), hostname aliases, HTTP-to-HTTPS redirect
- Catch-all hostname (`_`) as last-resort fallback, `redirect_to` for domain redirects, `return_status` for direct responses
- **gRPC-Web bridge** - transparently converts HTTP/1.1 gRPC-web requests to HTTP/2 gRPC for upstream backends
- **Maintenance mode** - per-route 503 with Retry-After header and custom HTML error page
- **Custom error pages** - configurable HTML for upstream errors (502/504) with `{{status}}` and `{{message}}` placeholders
- Configurable proxy headers, per-route timeouts, WebSocket passthrough, X-Forwarded-Proto via TLS session detection
- Connection pooling with health-aware backend filtering

### :lock: Security

- **WAF engine** - 49 OWASP CRS-inspired rules (SQLi, XSS, path traversal, command injection, SSRF, Log4Shell, XXE, CRLF)
- **mTLS client verification** - per-route CA bundle + optional organization allowlist. Chain validated at the TLS handshake (rustls `WebPkiClientVerifier`), per-route enforcement returns 496 ("cert required") or 495 ("cert error"). `required` and org-allowlist hot-reload; CA edits take effect on restart
- **Forward authentication** - per-route sub-request to Authelia / Authentik / Keycloak / oauth2-proxy before proxying; 2xx injects response headers into upstream, 401/403/3xx forwarded verbatim to the client, timeout = fail-closed 503. Optional opt-in verdict cache (TTL-capped at 60s, Cookie-keyed) to shortcut hot paths. Under `--workers N` the cache is owned by the supervisor and routed through the pipelined RPC channel, so an Allow verdict cached by one worker is served from every worker, and a session revocation invalidates the cache uniformly (WPAR-2, design § 7)
- **Connection pre-filter** - global IP allow/deny CIDR policy enforced at TCP accept, before the TLS handshake. Deny always wins; non-empty allow switches to default-deny. Hot-reloaded via arc-swap in single-process and worker modes
- **IP blocklist** - auto-fetched from Data-Shield IPv4 Blocklist (~80,000 entries, O(1) lookup, updated every 6h)
- **Rate limiting** - per-route, per-client-IP with configurable RPS and burst tolerance (legacy event-rate estimator `rate_limit_rps` / `rate_limit_burst`)
- **Per-route token-bucket limiter** - exact-semantic admission control via `rate_limit: { capacity, refill_per_sec, scope }`. Runs ahead of mTLS / forward-auth / WAF so abusive clients are rejected cheaply with `429 Too Many Requests` + `Retry-After`. `scope: per_ip` isolates individual clients; `scope: per_route` caps aggregate traffic to a fragile origin. Cross-worker under `--workers N`: each worker's CAS-based `LocalBucket` cache syncs every 100 ms with the supervisor's authoritative state over a dedicated pipelined RPC channel. Aggregate bound: `capacity + 100 ms × N_workers × refill_per_sec` (documented in `docs/architecture/worker-shared-state.md` § 6)
- **Auto-ban** - IPs that repeatedly exceed rate limits (or trip the WAF) are banned automatically (configurable threshold and duration). Under `--workers N`, the WAF auto-ban counter lives in an anonymous `memfd` shared by all workers (no UDS round-trip per block), and the supervisor is the sole ban issuer, broadcasting `BanIp` on threshold crossing
- **Trusted proxies** - CIDR list for X-Forwarded-For validation, prevents IP spoofing via header injection
- **DDoS protection** - per-route max connections, global flood rate tracking
- **Slowloris detection** - rejects slow-header attacks with configurable threshold
- **Security headers** - presets (strict/moderate/none) with HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **HTTP Basic Auth** - per-route username/password authentication (Argon2id-hashed) with cached verification
- **IP allowlist/denylist** and **CORS configuration** per route
- **Certificate export** (v1.4.1, disabled by default) - mirror issued certificates as PEM files under `/var/lib/lorica/exported-certs/<hostname>/{cert,chain,fullchain,privkey}.pem` every time a cert is issued or renewed. Lets Ansible / HAProxy sidecar / backup jobs read the live bundle straight off disk without hitting the HTTP API. Atomic writes (`.tmp` stage + `fsync` + `rename`, cross-mount `EXDEV` fallback), per-file `chmod` + `chown` with configurable owner UID / group GID / octal modes (defaults 0o640 files / 0o750 dirs), fail-soft (export error never blocks the ACME renewal). Per-pattern ACL table narrows which hostnames are exported and with which UID / GID (exact match, leading `*.` wildcard, or bare `*`). Audit-logged + rate-limited `GET /api/v1/certificates/:id/download` complements on-disk export for one-off downloads. Threat model: `docs/security/cert-export-threat-model.md`

### :bar_chart: Monitoring & Observability

- **Passive SLA** - per-route uptime, latency percentiles (p50/p95/p99), rolling windows (1h/24h/7d/30d)
- **Active SLA** - synthetic HTTP probes at configurable intervals, detects outages during low-traffic periods
- **Prometheus metrics** - `/metrics` endpoint with request counts, latency histograms, backend health, WAF events, cert expiry. Per-feature counters for cache-predictor bypass, header-rule matches, canary split selection, mirror outcomes (spawned / dropped / errored), forward-auth verdict cache hit rate - all bounded by route count. Under `--workers N` every scrape triggers a pull-on-scrape fan-out over the pipelined RPC channel so per-worker counters are sub-second fresh; concurrent scrapes dedup into a single fan-out and stuck workers fall back to cached state within a 500 ms per-worker timeout (WPAR-7)
- **Request mirroring (shadow testing)** - duplicate every request to one or more secondary backends (deterministic per `X-Request-Id` sampling, 256-slot concurrency cap, body mirroring up to a configurable cap). Fire-and-forget: mirror failure can never impact the primary
- **Real-time access logs** - WebSocket streaming to the dashboard with filtering
- **Load testing** - built-in load test engine with SSE streaming, cron scheduling, CPU circuit breaker, and result comparison
- **SLA breach alerts** - automatic notifications when SLA drops below target

### :globe_with_meridians: Management

- **Web dashboard** - Svelte 5 UI (~59 KB) embedded in the binary: routes, backends, certs, WAF, SLA, load tests, settings
- **REST API** - full CRUD for all entities, session-based auth, rate-limited login
- **TOML config export/import** - with diff preview before applying changes
- **Nginx config import** - paste an `nginx.conf` to auto-create routes, backends, certificates, and path rules with cert import support
- **ACME / Let's Encrypt** - automatic TLS provisioning via HTTP-01 and DNS-01 challenges (Cloudflare, Route53, OVH providers), multi-domain SAN and wildcard support, smart auto-renewal, OCSP stapling
- **DNS providers** - global DNS credentials configured once in Settings and referenced by ID for certificate provisioning (Cloudflare, Route53, OVH)
- **Notification channels** - stdout, SMTP email, HTTP webhook, Slack with per-channel rate limiting
- **Ban list management** - view and unban auto-banned IPs from the dashboard

### :zap: Performance

- **Pingora engine** - forked from Cloudflare's production proxy framework
- **HTTP cache** - in-memory response caching with LRU eviction (128 MiB cap), TinyUFO algorithm, cache lock (thundering herd protection), stale-while-revalidate **with background refresh** (serves stale immediately, fetches fresh in parallel) and stale-if-error, HTTP PURGE method support
- **Cache Vary** - per-route `cache_vary_headers` partitions the cache by request-header values (e.g. `Accept-Encoding`) merged with the origin's `Vary` response; `Vary: *` anchors on URI to bound cardinality
- **Cache predictor** - 16-shard LRU (32K keys) remembers deterministically-uncacheable responses and short-circuits the cache state machine on subsequent hits, avoiding cache-lock contention on known-bypass traffic
- **Peak EWMA load balancing** - latency-aware backend selection alongside Round Robin, Consistent Hash, Random, Least Connections
- **DashMap** - lock-free concurrent reads for ban list and route connections in the hot path
- **Sub-0.5ms WAF evaluation** - precompiled regex patterns with zero overhead when disabled

### :package: Reliability

- **Worker process isolation** - fork+exec with socket passing via SCM_RIGHTS
- **Protobuf command channel** - supervisor-to-worker config reload without traffic interruption. Under `--workers N`, reloads run as two-phase Prepare + Commit on a pipelined RPC channel so the divergence window between workers collapses to the UDS RTT (microseconds) instead of the per-worker DB-rebuild time (WPAR-8, design § 7). The same RPC plane carries cross-worker circuit-breaker admission (`BreakerDecision::AllowProbe` for HalfOpen) so probe slots are allocated atomically across workers and a failure on one trips the breaker for every worker (WPAR-3)
- **Health checks** - TCP and HTTP probes, backends marked degraded (>2s) or down and removed from rotation
- **Graceful drain** - per-backend active connection tracking with Closing/Closed lifecycle states
- **Certificate hot-swap** - atomic swap via arc-swap, zero downtime during rotation
- **Encrypted storage** - AES-256-GCM encryption for certificate private keys at rest

## Quick Start

### Install from .deb package

```bash
# Download the latest release
wget https://github.com/Rwx-G/Lorica/releases/latest/download/lorica.deb
sudo dpkg -i lorica.deb
```

The package creates a `lorica` user, installs a systemd service (enabled by default), and starts Lorica on ports 8080 (HTTP), 8443 (HTTPS), and 9443 (dashboard).

To customize ports, workers, or log level, edit the systemd unit:

```bash
sudo systemctl edit lorica
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/lorica --data-dir /var/lib/lorica \
  --http-port 80 --https-port 443 --management-port 9443 \
  --workers 4 --log-level info
```

```bash
sudo systemctl restart lorica
```

### Run with Docker

```bash
docker build -t lorica .
docker run -p 8080:8080 -p 8443:8443 -p 9443:9443 \
  -v lorica-data:/var/lib/lorica lorica
```

### Run directly

```bash
lorica --data-dir /var/lib/lorica
```

Open `https://localhost:9443` in your browser. On first run, a random admin password is printed to stdout.

### CLI options

```
lorica [OPTIONS]

Options:
  --data-dir <PATH>          Data directory (default: /var/lib/lorica)
  --management-port <PORT>   Dashboard/API port (default: 9443)
  --http-port <PORT>         HTTP proxy port (default: 8080)
  --https-port <PORT>        HTTPS proxy port (default: 8443)
  --workers <N>              Worker processes (default: 0 = single-process)
  --log-level <LEVEL>        Log level (default: info)
  --log-format <FORMAT>      Log format: json (default) or text
  --log-file <PATH>          Log to file (in addition to stdout)
  --version                  Print version
```

## Dashboard

The dashboard ships inside the binary and is served on the management port (default 9443). No separate frontend server, no npm, no build step - just open your browser.

<p align="center">
  <img src="docs/screenshots/overview-guide.png" alt="Overview - Getting Started Guide" width="100%">
  <br><em>Getting started guide with interactive setup checklist</em>
</p>

<p align="center">
  <img src="docs/screenshots/overview.png" alt="Overview Dashboard" width="100%">
  <br><em>Overview cockpit with system health, routes, security, and performance at a glance</em>
</p>

<p align="center">
  <img src="docs/screenshots/routes.png" alt="Routes Management" width="100%">
  <br><em>Routes table with hostname, backends, WAF mode, health status, and TLS</em>
</p>

<p align="center">
  <img src="docs/screenshots/routesDrawer.png" alt="Route Configuration Drawer" width="100%">
  <br><em>Route editor with 50+ settings across 7 tabs (General, Routing, Transform, Protection, Security, Cache, Upstream)</em>
</p>

<p align="center">
  <img src="docs/screenshots/security.png" alt="Security - WAF Rules" width="100%">
  <br><em>49 WAF rules with per-rule toggle, covering SQLi, XSS, SSRF, Log4Shell, XXE, and more</em>
</p>

<p align="center">
  <img src="docs/screenshots/system.png" alt="System - Workers" width="100%">
  <br><em>System page with worker health, heartbeat latency, CPU/memory gauges, and process metrics</em>
</p>

### Pages

- **Overview** - cockpit dashboard with section helpers, setup checklist, system/route/security/performance cards
- **Routes** - create/edit routes with host matching, path prefixes, load balancing, WAF mode, rate limits, caching, timeouts, security headers, CORS, and 25 other per-route settings
- **Backends** - manage backend addresses, weights, health check type (TCP/HTTP), TLS upstream, active connections
- **Certificates** - upload PEM certificates, view expiry dates, provision via ACME/Let's Encrypt (HTTP-01, DNS-01)
- **Security** - WAF event table with category filtering, 49 rule toggles, IP ban list with unban button
- **SLA** - per-route passive/active SLA side-by-side, latency percentile tables, config editor, CSV/JSON export
- **Load Tests** - test config management with clone, one-click execution, real-time SSE progress panel, historical results
- **Active Probes** - CRUD for synthetic health probes with route selection, HTTP method/path/status/interval/timeout
- **Access Logs** - scrollable real-time log stream via WebSocket with green pulsing indicator
- **System** - worker table with PID, health, heartbeat latency; CPU/memory/disk gauges
- **Settings** - notification channels, security header presets, config export/import with diff preview
- **Theme** - light/dark mode toggle

## Architecture

Lorica is a Rust workspace with 25 crates: 15 forked from Cloudflare Pingora and 10 product crates. See [FORK.md](FORK.md) for the full fork lineage and renaming rules.

| Crate | Purpose |
|-------|---------|
| `lorica` | CLI binary, supervisor, worker orchestration |
| `lorica-proxy` | HTTP/HTTPS proxy engine (Pingora fork) |
| `lorica-tls` | SNI certificate resolver, hot-swap, ACME |
| `lorica-config` | SQLite store, migrations, TOML export/import |
| `lorica-api` | axum REST API, auth, session management |
| `lorica-dashboard` | Svelte 5 frontend embedded via rust-embed |
| `lorica-waf` | WAF engine, OWASP rules, IP blocklist |
| `lorica-notify` | Alert dispatch (stdout, SMTP, webhook) |
| `lorica-bench` | SLA monitoring, load testing engine |
| `lorica-worker` | fork+exec worker isolation, typed FD passing (Listener / Shmem / Rpc) |
| `lorica-command` | Protobuf supervisor-worker command channel + pipelined RpcEndpoint (Envelope framing, in-flight demux, bounded backpressure), `Coalescer`, `GenerationGate` |
| `lorica-shmem` | Anonymous `memfd` region shared across all workers; `AtomicHashTable` for per-IP WAF flood / auto-ban counters; SipHash-1-3 anti-HashDoS; 5-min eviction walker |
| `lorica-lb` | Load balancing (Round Robin, Peak EWMA, Hash, Random, Least Conn) |
| `lorica-cache` | HTTP response cache, LRU eviction |
| `lorica-limits` | Rate estimator + per-route `LocalBucket` / `AuthoritativeBucket` token-bucket primitives (lock-free CAS, 100 ms cross-worker sync) |

Data plane (proxy) and control plane (API/dashboard) are fully separated. API mutations trigger config reload via arc-swap - the proxy picks up changes without restarting.

## Performance

Measured on a single Linux VM (4 vCPU, 8 GB RAM):

| Metric | Value |
|--------|-------|
| Single-process throughput | ~6,500 req/s |
| Multi-worker throughput (4 workers) | ~25,000 req/s |
| WAF evaluation latency | < 0.5 ms per request |
| WAF overhead on throughput | ~6% |
| Dashboard bundle size | ~59 KB (gzipped) |
| Config reload | Zero-downtime (arc-swap) |
| Certificate hot-swap | Zero-downtime (atomic) |

## Configuration Example

Create a route via the REST API:

```bash
# Authenticate
TOKEN=$(curl -sk https://localhost:9443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"password":"your-admin-password"}' \
  -c - | grep session | awk '{print $NF}')

# Create a backend
curl -sk https://localhost:9443/api/v1/backends \
  -b "session=$TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "address": "127.0.0.1:8080",
    "health_check_interval_s": 10,
    "health_check_type": "http",
    "health_check_path": "/healthz"
  }'

# Create a route
curl -sk https://localhost:9443/api/v1/routes \
  -b "session=$TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "hostname": "app.example.com",
    "path_prefix": "/",
    "backend_ids": [1],
    "load_balancing": "peak_ewma",
    "tls_enabled": true,
    "certificate_id": 1,
    "waf_enabled": true,
    "waf_mode": "block",
    "rate_limit_rps": 100,
    "rate_limit_burst": 50,
    "cache_enabled": true,
    "cache_ttl_s": 300,
    "force_https": true,
    "security_headers": "strict"
  }'
```

Or just use the dashboard - it covers all the same operations with zero curl.

## REST API Reference

All endpoints are served on the management port (default `9443`) over HTTPS. Protected endpoints require a session cookie obtained via `/api/v1/auth/login`.

### Public endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/login` | Authenticate (returns session cookie) |
| `POST` | `/api/v1/auth/logout` | Invalidate session |
| `GET` | `/metrics` | Prometheus metrics (no auth) |
| `GET` | `/.well-known/acme-challenge/:token` | ACME HTTP-01 challenge response |

### Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/routes` | List all routes |
| `POST` | `/api/v1/routes` | Create route |
| `GET` | `/api/v1/routes/:id` | Get route |
| `PUT` | `/api/v1/routes/:id` | Update route |
| `DELETE` | `/api/v1/routes/:id` | Delete route |
| `POST` | `/api/v1/validate/mtls-pem` | Parse a candidate client-CA PEM and return per-cert subjects |
| `POST` | `/api/v1/validate/forward-auth` | Probe a candidate forward-auth URL (one GET, status + elapsed) |

### Backends

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/backends` | List all backends |
| `POST` | `/api/v1/backends` | Create backend |
| `GET` | `/api/v1/backends/:id` | Get backend |
| `PUT` | `/api/v1/backends/:id` | Update backend |
| `DELETE` | `/api/v1/backends/:id` | Delete backend |

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/certificates` | List certificates |
| `POST` | `/api/v1/certificates` | Upload PEM certificate |
| `POST` | `/api/v1/certificates/self-signed` | Generate self-signed certificate |
| `GET` | `/api/v1/certificates/:id` | Get certificate |
| `GET` | `/api/v1/certificates/:id/download?part={cert\|key\|chain\|bundle}` | Download PEM material (rate-limited, audit-logged) |
| `PUT` | `/api/v1/certificates/:id` | Update certificate |
| `DELETE` | `/api/v1/certificates/:id` | Delete certificate |
| `GET` | `/api/v1/cert-export/acls` | List per-pattern cert-export ACLs |
| `POST` | `/api/v1/cert-export/acls` | Create a cert-export ACL rule |
| `DELETE` | `/api/v1/cert-export/acls/:id` | Delete a cert-export ACL rule |
| `POST` | `/api/v1/cert-export/reapply` | Re-export every certificate to disk |

### ACME

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/acme/provision` | Provision via HTTP-01 |
| `POST` | `/api/v1/acme/provision-dns` | Provision via DNS-01 |
| `POST` | `/api/v1/acme/provision-dns-manual` | Start manual DNS-01 flow |
| `POST` | `/api/v1/acme/provision-dns-manual/confirm` | Confirm manual DNS-01 |

### WAF

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/waf/events` | Recent WAF events (with category filter) |
| `DELETE` | `/api/v1/waf/events` | Clear WAF events |
| `GET` | `/api/v1/waf/stats` | WAF statistics |
| `GET` | `/api/v1/waf/rules` | List WAF rules |
| `PUT` | `/api/v1/waf/rules/:id` | Enable/disable rule |
| `GET` | `/api/v1/waf/rules/custom` | List custom rules |
| `POST` | `/api/v1/waf/rules/custom` | Create custom rule |
| `DELETE` | `/api/v1/waf/rules/custom/:id` | Delete custom rule |
| `GET` | `/api/v1/waf/blocklist` | Blocklist status |
| `PUT` | `/api/v1/waf/blocklist` | Enable/disable blocklist |
| `POST` | `/api/v1/waf/blocklist/reload` | Reload blocklist |

### SLA & Probes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/sla/overview` | SLA overview for all routes |
| `GET` | `/api/v1/sla/routes/:id` | SLA metrics for route |
| `GET` | `/api/v1/sla/routes/:id/buckets` | Time-bucketed SLA data |
| `GET` | `/api/v1/sla/routes/:id/config` | SLA config |
| `PUT` | `/api/v1/sla/routes/:id/config` | Update SLA config |
| `GET` | `/api/v1/sla/routes/:id/export` | Export SLA data (CSV/JSON) |
| `GET` | `/api/v1/sla/routes/:id/active` | Active probe results |
| `GET` | `/api/v1/probes` | List probes |
| `POST` | `/api/v1/probes` | Create probe |
| `GET` | `/api/v1/probes/route/:route_id` | Probes for route |
| `PUT` | `/api/v1/probes/:id` | Update probe |
| `DELETE` | `/api/v1/probes/:id` | Delete probe |

### Load Testing

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/loadtest/configs` | List configs |
| `POST` | `/api/v1/loadtest/configs` | Create config |
| `PUT` | `/api/v1/loadtest/configs/:id` | Update config |
| `DELETE` | `/api/v1/loadtest/configs/:id` | Delete config |
| `POST` | `/api/v1/loadtest/configs/:id/clone` | Clone config |
| `POST` | `/api/v1/loadtest/start/:config_id` | Start test (requires confirm) |
| `POST` | `/api/v1/loadtest/start/:config_id/confirm` | Confirm and execute |
| `GET` | `/api/v1/loadtest/status` | Current test status |
| `GET` | `/api/v1/loadtest/ws` | WebSocket real-time progress |
| `POST` | `/api/v1/loadtest/abort` | Abort running test |
| `GET` | `/api/v1/loadtest/results/:config_id` | Test results |
| `GET` | `/api/v1/loadtest/results/:config_id/compare` | Compare runs |

### Cache & Bans

| Method | Path | Description |
|--------|------|-------------|
| `DELETE` | `/api/v1/cache/routes/:id` | Purge route cache |
| `GET` | `/api/v1/cache/stats` | Cache hit/miss stats |
| `GET` | `/api/v1/bans` | List banned IPs |
| `DELETE` | `/api/v1/bans/:ip` | Unban IP |

### System & Configuration

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/api/v1/auth/password` | Change password |
| `GET` | `/api/v1/settings` | Global settings |
| `PUT` | `/api/v1/settings` | Update settings |
| `GET` | `/api/v1/status` | System status summary |
| `GET` | `/api/v1/system` | CPU, memory, disk usage |
| `GET` | `/api/v1/workers` | Worker heartbeat metrics |
| `GET` | `/api/v1/logs` | Access logs |
| `DELETE` | `/api/v1/logs` | Clear logs |
| `GET` | `/api/v1/logs/ws` | WebSocket log stream |
| `POST` | `/api/v1/config/export` | Export config as TOML |
| `POST` | `/api/v1/config/import` | Import TOML config |
| `POST` | `/api/v1/config/import/preview` | Preview import diff |
| `GET` | `/api/v1/notifications` | List notification configs |
| `POST` | `/api/v1/notifications` | Create notification config |
| `PUT` | `/api/v1/notifications/:id` | Update notification config |
| `DELETE` | `/api/v1/notifications/:id` | Delete notification config |
| `POST` | `/api/v1/notifications/:id/test` | Test notification channel |
| `GET` | `/api/v1/preferences` | List user preferences |
| `PUT` | `/api/v1/preferences/:id` | Update preference |
| `DELETE` | `/api/v1/preferences/:id` | Delete preference |

## Building from Source

```bash
# Prerequisites
# - Rust 1.88+
# - Node.js 18+ (for dashboard compilation)
# - Linux (x86_64)

git clone https://github.com/Rwx-G/Lorica.git
cd Lorica
cargo build --release

# Binary is at target/release/lorica
# The Svelte frontend is compiled automatically during cargo build.
```

### Running tests

```bash
# All Rust unit tests (1553 tests across 19 crates)
cargo test --workspace

# Product crate tests only (739 tests)
cargo test -p lorica-config -p lorica-api -p lorica -p lorica-waf \
           -p lorica-notify -p lorica-bench -p lorica-worker \
           -p lorica-command -p lorica-limits -p lorica-shmem

# Pingora-forked crate tests (568 tests)
cargo test -p lorica-core -p lorica-proxy -p lorica-http \
           -p lorica-error -p lorica-tls -p lorica-cache \
           -p lorica-pool -p lorica-runtime -p lorica-timeout \
           --features ring -p lorica-lb

# End-to-end tests driving a real Pingora Server (68 tests, 10 binaries)
cargo test -p lorica --test mtls_e2e_test \
                     --test response_rewrite_e2e_test \
                     --test mirror_e2e_test \
                     --test forward_auth_e2e_test \
                     --test swr_e2e_test \
                     --test connection_filter_test \
                     --test canary_e2e_test \
                     --test header_routing_e2e_test \
                     --test proxy_config_test \
                     --test proxy_routing_test

# Frontend tests (178 Vitest tests across 6 files)
cd lorica-dashboard/frontend && npx vitest run
```

#### Test coverage by layer

| Layer | Count | Notes |
|---|---|---|
| Product unit (config, api, lib, waf, notify, bench, worker, command, limits) | 739 | Lorica-specific code |
| Product e2e (real Pingora `Server` + mock backends) | 68 | 10 binaries: mTLS, response rewriting, mirroring, forward auth, SWR, connection filter, canary, header routing, config, routing |
| Pingora-forked crates (core, proxy, http, error, tls, cache, pool, runtime, timeout, lb) | 568 | Inherited upstream coverage kept passing on every change |
| Frontend (vitest / svelte-check) | 178 | Form validation, type safety, component wiring |
| **Total shipping tests** | **1553** | |

#### Docker end-to-end suites

`tests-e2e-docker/` spins Lorica up against real backend containers
and drives 400+ assertions through the actual network stack:

```bash
cd tests-e2e-docker
./run.sh                                    # single-process (315 asserts) + workers mode (86)
docker compose --profile bot run --rm bot-smoke                   # 33 asserts - graded bot challenge
docker compose --profile geoip run --rm geoip-smoke               # 16 asserts - country allow/deny
docker compose --profile rdns run --rm rdns-smoke                 # 8  asserts - forward-confirmed rDNS bypass
docker compose --profile otel run --rm otel-smoke                 # 15 asserts - OTLP + W3C + log/trace correlation
docker compose --profile otel-workers run --rm otel-smoke-workers # 15 asserts - same under --workers 2
```

The two intentional gaps in the Docker harness are:

- **mTLS client-cert handshake** (495 / 496 / 200 based on the
  presented cert). The e2e container starts without any TLS certs
  pre-loaded so the HTTPS listener on port 8443 is never built -
  driving `curl --cert` needs a staged environment. The config
  surface (CA PEM validation, `required` + `allowed_organizations`
  hot-reload) is covered.
- **Connection pre-filter TCP drop** (scanner IP refused at
  `accept()` before TLS). The test-runner sits on the same Docker
  network as Lorica, so any CIDR that would cover a real scanner
  also covers the runner - asserting the drop from inside would be
  self-blocking. The config round-trip (valid CIDR accepted, garbage
  rejected 400) is covered.

Validate both manually on staging when touching the surrounding
code paths.

## systemd Service

The `.deb` and `.rpm` packages install a hardened systemd unit with:

- `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`
- `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`
- `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`
- Runs as dedicated `lorica` user with `CAP_NET_BIND_SERVICE`
- Service auto-starts on install and auto-restarts on upgrade
- Data directory (`/var/lib/lorica`) preserved across upgrades

Customize the service (e.g. enable workers) via drop-in override:

```bash
sudo systemctl edit lorica
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/lorica --workers 6
```

## Performance Tuning

See [docs/tuning.md](docs/tuning.md) for kernel parameters (`sysctl`), file descriptor limits, worker configuration, cache settings, and a production readiness checklist. Run [bench/](bench/) for reproducible throughput measurements.

## Worker Mode

When running with `--workers N >= 1`, see [docs/worker-mode.md](docs/worker-mode.md) for the operational notes (which settings require a supervisor restart, what changes between single-process and worker mode).

## Package Verification

Release `.deb` and `.rpm` packages are GPG-signed. Import the public key to verify:

```bash
curl -fsSL https://github.com/Rwx-G/Lorica/raw/main/docs/lorica-signing-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/lorica.gpg
gpg --verify lorica.deb.asc lorica.deb
```

## Roadmap

| Version | Features | Status |
|---------|----------|--------|
| v1.4.0 | OpenTelemetry tracing (OTLP), GeoIP country blocking, Bot protection (PoW / captcha / cookie with 5-category bypass matrix) | Shipped |
| **v1.5.0** | Operator-input guard-rails on every field with blur + input inline errors; Route `group_name` + filter + colored pill; Certificate download API + dashboard split-menu with private-key confirm; Filesystem certificate export zone with per-pattern ACL, Settings tab, operator re-export endpoint; Path-rule redirect fix ; Security hardening wave: `ammonia` HTML sanitiser, per-endpoint rate limits on management plane, per-route body-size limits with 1 MiB global default, session cookie rotation on password change, `/system` response filter, `rustls-pemfile → rustls-pki-types` migration, `rand 0.9` bump, source-error preservation on `.map_err` chains, WebSocket log-stream backpressure with close-on-slow-client | Current |
| v1.6.0 | AI-crawler (LLM) deny-list as a first-class feature (known-bot User-Agent + rDNS matcher, per-route opt-in / opt-out, Prometheus counter), Hot binary upgrade (zero-downtime restart), Team settings (multiple users, roles, RBAC) ; `proxy_wiring.rs` + `main.rs` module split ; ACME module unit tests with mocked DNS providers | Planned |
| v2.0.0 | HTTP/3 (QUIC), TCP/L4 proxying | Planned |

### Backlog (no planned version yet)

- **Third-party IP-reputation feeds.** Beyond the built-in Data-Shield blocklist: pluggable feed sources (FireHOL, Spamhaus DROP, abuse.ch, custom HTTP endpoints) with per-feed allow / deny policy. Deferred: the stability of the feeds we reviewed (SLA for URL stability, license compatibility with Apache-2.0) is mixed, and the current `connection_deny_cidrs` + Data-Shield combo already covers 95 % of what operators ask for without a third-party trust boundary.
- **PKCS#12 / JKS bundle export.** Complement the PEM export zone with `.p12` / `.jks` for Java keystore consumers. Deferred: `openssl pkcs12 -export` on the already-written PEM files is one line and keeps the Lorica code path free of OpenSSL-versus-rustls format-serialization.
- **Exported-cert orphan cleanup.** When the operator deletes a certificate in the dashboard, the on-disk export directory is NOT removed (by design, v1.5.0 leaves it to the operator). A dashboard "sweep orphans" button is the likely v1.6.x follow-up.
- **Public-API doc coverage pass (`missing_docs`).** Enable `#![warn(missing_docs)]` on `lorica-api` / `lorica-config` / `lorica-challenge` + fill remaining gaps in request / response type fields, settings keys, model fields. Enumerated but deferred from the v1.5.0 hardening wave — it is grind, not mechanical, and would create ~100+ new warnings to triage.

See [CHANGELOG.md](CHANGELOG.md) for release history.

See [COMPARISON.md](COMPARISON.md) for a detailed feature comparison with Nginx, Traefik, HAProxy, Caddy, BunkerWeb, Sozu, and Pingora.

## Not Supported

| Feature | Status | Rationale |
|---------|--------|-----------|
| **HTTP/3 / QUIC** | Planned | Waiting for [Pingora PR #524](https://github.com/cloudflare/pingora/pull/524) (tokio-quiche integration) to merge upstream |
| **io_uring** | Not planned | tokio-uring is unmaintained since 2022. epoll via Tokio delivers sufficient performance (40M req/s at Cloudflare scale) |
| **Windows / macOS** | Not supported | Linux x86_64 only (fork+exec worker model requires Linux) |
| **OpenSSL / BoringSSL** | Removed | rustls is the sole TLS provider |

## License

Apache-2.0 - see [LICENSE](LICENSE).

## Credits

Built on [Pingora](https://github.com/cloudflare/pingora) by Cloudflare (Apache-2.0). See [NOTICE](NOTICE) and [FORK.md](FORK.md) for fork details.

Author: Rwx-G
