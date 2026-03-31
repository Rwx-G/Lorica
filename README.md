<p align="center">
  <h1 align="center">Lorica</h1>
  <p align="center">A modern reverse proxy you manage from your browser. Single binary, built-in dashboard, no config files. Powered by Rust and <a href="https://github.com/cloudflare/pingora">Pingora</a>.</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Rust-2024-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/Svelte-5-FF3E00.svg" alt="Svelte">
  <img src="https://img.shields.io/badge/Platform-Linux-0078D6.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-0.3.0--dev-yellow.svg" alt="Status">
  <img src="https://img.shields.io/badge/Tests-414%20passing-brightgreen.svg" alt="Tests">
</p>

---

## The idea

Most reverse proxies are powerful but invisible - you configure them through files, reload a daemon, and hope for the best. Lorica takes a different approach: the dashboard is the product. You manage routes, backends, and certificates from a web UI that ships inside the binary. No YAML, no sidecar, no external database.

One `apt install`, one binary, one management port on localhost. That's the entire setup.

## What it does today

Epics 1-4 are complete. Lorica is a production-ready reverse proxy with security, intelligence, and automation:

- **HTTP/HTTPS proxying** with host-based and path-prefix routing, round-robin load balancing, TLS termination via rustls
- **Web dashboard** (Svelte 5, ~59KB) with route, backend, certificate management, access logs, security panel, system monitoring, and settings
- **REST API** with session-based auth, first-run password setup, rate limiting, and full CRUD for all configuration entities
- **WAF engine** with 18 OWASP CRS-inspired rules (SQL injection, XSS, path traversal, command injection). Detection and blocking modes per route, configurable rule sets
- **Topology-aware health checks** - SingleVM (passive), HA (active TCP/HTTP), Docker Swarm and Kubernetes service discovery
- **Notification channels** - stdout (always on), SMTP email, HTTP webhook with per-channel rate limiting
- **Configuration persistence** in embedded SQLite (WAL mode), with TOML export/import and diff preview
- **Worker isolation** with fork+exec, protobuf command channel, and zero-downtime config reload
- **Certificate hot-swap** with SNI support and wildcard domains, no downtime during rotation
- **ACME / Let's Encrypt** automatic TLS provisioning via HTTP-01 challenge
- **Prometheus metrics** endpoint with request counts, latency histograms, backend health, WAF events
- **Peak EWMA** latency-based load balancing alongside Round Robin, Consistent Hash, Random
- **CI/CD** with GitHub Actions, `.deb` packaging, release automation

## Where it's going

| Epic | Focus | Status |
|------|-------|--------|
| 1. Foundation | Proxy engine, API, dashboard, config management | Done |
| 2. Resilience | Worker process isolation, command channel, zero-downtime reload | Done |
| 3. Intelligence | WAF (OWASP CRS), topology awareness, notifications | Done |
| 4. Production | ACME/Let's Encrypt, Prometheus metrics, Peak EWMA, packaging, security | Done |
| 5. Observability | SLA monitoring (passive + active probes), built-in load testing | Planned |

## Quick look

```
lorica --data-dir /var/lib/lorica
```

Then open `https://localhost:9443` in your browser. On first run, a random admin password is printed to stdout.

## Testing

```bash
# Unit tests (Rust + frontend)
cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify
cd lorica-dashboard/frontend && npx vitest run

# E2E tests (Docker required)
cd tests-e2e-docker && ./run.sh --build
```

324 unit tests + 90 Docker e2e tests = 414 total.

## Tech stack

| Layer | Technology |
|-------|-----------|
| Proxy engine | Rust, Pingora (Cloudflare), rustls |
| API | axum, tower, SQLite (rusqlite) |
| Dashboard | Svelte 5, TypeScript, Vite |
| WAF | Regex-based OWASP CRS rules |
| Notifications | lettre (SMTP), reqwest (webhook) |
| Discovery | bollard (Docker), kube-rs (Kubernetes) |
| Packaging | Single binary via rust-embed |

## Building from source

```bash
# Prerequisites: Rust 1.84+, Node.js 18+
cargo build --release
```

The frontend is compiled automatically during `cargo build`.

## License

Apache-2.0 - see [LICENSE](LICENSE).

Built on [Pingora](https://github.com/cloudflare/pingora) by Cloudflare (Apache-2.0). See [NOTICE](NOTICE).
