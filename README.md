<p align="center">
  <img src="docs/assets/lorica-logo.png" alt="Lorica" width="128">
  <h1 align="center">Lorica</h1>
  <p align="center"><strong>A modern, secure, dashboard-first reverse proxy built in Rust</strong></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/version-0.3.0-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Rust-2024-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Linux-0078D6.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Tests-414%20passing-brightgreen.svg" alt="Tests">
</p>

---

Lorica is a production-ready reverse proxy with a built-in web dashboard, WAF, SLA monitoring, and HTTP caching. One binary, zero external dependencies. Install it, open your browser, and manage everything from the UI - routes, backends, certificates, security rules, and performance metrics.

Built on [Cloudflare Pingora](https://github.com/cloudflare/pingora), the engine that powers a significant portion of Cloudflare's CDN traffic.

## Key Features

### :shield: Proxy & Routing

- HTTP/HTTPS reverse proxy with host-based and path-prefix routing
- TLS termination via rustls (no OpenSSL dependency)
- SNI-based certificate selection with wildcard domain support (`*.example.com`)
- Path rewriting (strip/add prefix), hostname aliases, HTTP-to-HTTPS redirect
- Configurable proxy headers, per-route timeouts, WebSocket passthrough
- Connection pooling with health-aware backend filtering

### :lock: Security

- **WAF engine** - 18 OWASP CRS-inspired rules (SQLi, XSS, path traversal, command injection, protocol violations)
- **IP blocklist** - auto-fetched from Data-Shield IPv4 Blocklist (800k+ entries, O(1) lookup, updated every 6h)
- **Rate limiting** - per-route, per-client-IP with configurable RPS and burst tolerance
- **Auto-ban** - IPs that repeatedly exceed rate limits are banned automatically (configurable threshold and duration)
- **DDoS protection** - per-route max connections, global flood rate tracking
- **Slowloris detection** - rejects slow-header attacks with configurable threshold
- **Security headers** - presets (strict/moderate/none) with HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **IP allowlist/denylist** and **CORS configuration** per route

### :bar_chart: Monitoring & Observability

- **Passive SLA** - per-route uptime, latency percentiles (p50/p95/p99), rolling windows (1h/24h/7d/30d)
- **Active SLA** - synthetic HTTP probes at configurable intervals, detects outages during low-traffic periods
- **Prometheus metrics** - `/metrics` endpoint with request counts, latency histograms, backend health, WAF events, cert expiry
- **Real-time access logs** - WebSocket streaming to the dashboard with filtering
- **Load testing** - built-in load test engine with SSE streaming, cron scheduling, CPU circuit breaker, and result comparison
- **SLA breach alerts** - automatic notifications when SLA drops below target

### :globe_with_meridians: Management

- **Web dashboard** - Svelte 5 UI (~59 KB) embedded in the binary: routes, backends, certs, WAF, SLA, load tests, settings
- **REST API** - full CRUD for all entities, session-based auth, rate-limited login
- **TOML config export/import** - with diff preview before applying changes
- **ACME / Let's Encrypt** - automatic TLS provisioning via HTTP-01 challenge
- **Notification channels** - stdout, SMTP email, HTTP webhook with per-channel rate limiting
- **Ban list management** - view and unban auto-banned IPs from the dashboard

### :zap: Performance

- **Pingora engine** - forked from Cloudflare's production proxy framework
- **HTTP cache** - in-memory response caching with LRU eviction (128 MiB cap), TinyUFO algorithm
- **Peak EWMA load balancing** - latency-aware backend selection alongside Round Robin, Consistent Hash, Random
- **DashMap** - lock-free concurrent reads for ban list and route connections in the hot path
- **Sub-0.5ms WAF evaluation** - precompiled regex patterns with zero overhead when disabled

### :package: Reliability

- **Worker process isolation** - fork+exec with socket passing via SCM_RIGHTS
- **Protobuf command channel** - supervisor-to-worker config reload without traffic interruption
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
sudo systemctl enable --now lorica
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
  --http-port <PORT>         HTTP proxy port (default: 80)
  --https-port <PORT>        HTTPS proxy port (default: 443)
  --workers <N>              Worker processes (default: 0 = single-process)
  --log-level <LEVEL>        Log level (default: info)
  --version                  Print version
```

## Dashboard

The dashboard ships inside the binary and is served on the management port (default 9443). It provides:

- **Overview** - status cards with active routes, backends, certificates, and system health
- **Routes** - create/edit routes with host matching, path prefixes, load balancing, WAF mode, rate limits, caching, timeouts, security headers, CORS, and 25 other per-route settings in a collapsible Advanced Configuration section
- **Backends** - manage backend addresses, weights, health check type (TCP/HTTP), TLS upstream, active connections, lifecycle state
- **Certificates** - upload PEM certificates, view expiry dates, provision via ACME/Let's Encrypt
- **Security** - WAF event table with category filtering, stats per attack category, rule toggle switches, ban list with unban button
- **SLA** - per-route passive/active SLA side-by-side, latency percentile tables, config editor, CSV/JSON export
- **Load Tests** - test config management with clone, one-click execution, real-time SSE progress panel, historical results
- **Active Probes** - CRUD for synthetic health probes with route selection, HTTP method/path/status/interval/timeout
- **Access Logs** - scrollable real-time log stream via WebSocket with green pulsing indicator
- **Settings** - notification channels (stdout/SMTP/webhook), topology config, config export/import with diff preview
- **Theme** - light/dark mode toggle

## Architecture

Lorica is a Rust workspace with 26 crates, forked from Cloudflare Pingora (17 core crates) and extended with 9 product crates:

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
| `lorica-worker` | fork+exec worker isolation, socket passing |
| `lorica-command` | Protobuf supervisor-worker command channel |
| `lorica-lb` | Load balancing (Round Robin, Peak EWMA, Hash, Random) |
| `lorica-cache` | HTTP response cache, LRU eviction |
| `lorica-limits` | Rate estimator for rate limiting |

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

## Building from Source

```bash
# Prerequisites
# - Rust 1.84+
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
# Unit tests (312 Rust + 52 frontend)
cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench
cd lorica-dashboard/frontend && npx vitest run

# E2E tests (63 assertions, Docker required)
cd tests-e2e-docker && ./run.sh --build
```

## systemd Service

The `.deb` package installs a hardened systemd unit with:

- `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`
- `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`
- `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`
- Runs as dedicated `lorica` user with `CAP_NET_BIND_SERVICE`

## License

Apache-2.0 - see [LICENSE](LICENSE).

## Credits

Built on [Pingora](https://github.com/cloudflare/pingora) by Cloudflare (Apache-2.0). See [NOTICE](NOTICE).

Author: Rwx-G
