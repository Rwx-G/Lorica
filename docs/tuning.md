# Performance Tuning Guide

This guide covers Linux kernel and Lorica settings to optimize throughput, latency, and connection handling under high load.

## Kernel Parameters

Apply these via `sysctl` or persist in `/etc/sysctl.d/99-lorica.conf`:

```bash
# --- Connection handling ---
# Maximum pending connections in the listen queue (default 4096)
net.core.somaxconn = 65535

# Allow reuse of TIME_WAIT sockets for new connections
net.ipv4.tcp_tw_reuse = 1

# Widen the ephemeral port range for outgoing connections
net.ipv4.ip_local_port_range = 1024 65535

# Maximum number of tracked connections (for conntrack/firewall)
net.netfilter.nf_conntrack_max = 1000000

# --- TCP buffers ---
# Increase default and max socket buffer sizes (bytes)
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# TCP auto-tuning buffer sizes: min, default, max (bytes)
net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216

# --- TCP performance ---
# Enable TCP Fast Open for both client and server (bitmask 3)
net.ipv4.tcp_fastopen = 3

# Enable BBR congestion control (better than cubic for high-bandwidth)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- File descriptors ---
# Maximum open files system-wide
fs.file-max = 2097152
```

Apply immediately:

```bash
sudo sysctl -p /etc/sysctl.d/99-lorica.conf
```

## File Descriptor Limits

Each proxy connection uses one file descriptor. For 10k+ concurrent connections:

```bash
# /etc/security/limits.d/lorica.conf
lorica soft nofile 65536
lorica hard nofile 65536

# Or for the current session:
ulimit -n 65536
```

The `.deb` package's systemd unit includes `LimitNOFILE=65536` by default.

## Lorica Settings

### Workers

```bash
# Multi-worker mode: one process per CPU core
lorica --workers 4 --data-dir /var/lib/lorica

# Single-process mode (default)
lorica --data-dir /var/lib/lorica
```

Each worker runs an independent proxy engine. SO_REUSEPORT is enabled automatically so the kernel distributes connections across workers.

**Rule of thumb:** set `--workers` to the number of CPU cores dedicated to proxying. Leave 1-2 cores for the OS and API server.

### Global Settings (via API or dashboard)

| Setting | Default | Description |
|---------|---------|-------------|
| `max_global_connections` | 0 (unlimited) | Total proxy connections cap. 503 when exceeded. |
| `flood_threshold_rps` | 0 (disabled) | When global RPS exceeds this, per-IP rate limits are halved. |

### Per-Route Settings

| Setting | Default | Impact |
|---------|---------|--------|
| `rate_limit_rps` | None | Per-client-IP request rate. Set to avoid a single client saturating a route. |
| `rate_limit_burst` | None | Extra requests allowed above RPS before throttling. |
| `max_connections` | None | Per-route connection cap. 503 when exceeded. |
| `cache_enabled` | false | Enables in-memory response cache. Reduces backend load for cacheable content. |
| `cache_ttl_s` | 300 | Cache lifetime in seconds. |
| `compression_enabled` | false | Gzip response compression. Saves bandwidth at CPU cost. |
| `connect_timeout_s` | 5 | Backend connection timeout. Lower values fail-fast on dead backends. |
| `read_timeout_s` | 60 | Backend response timeout. |

### Per-Backend Settings

| Setting | Default | Impact |
|---------|---------|--------|
| `h2_upstream` | false | Force HTTP/2 to backend (h2c or ALPN h2). Enables multiplexing and gRPC. |

## Connection Pooling

Lorica (via Pingora) maintains a keepalive pool for upstream connections. This avoids TCP/TLS handshake overhead for repeated requests to the same backend.

The pool is shared across all routes pointing to the same backend address. Connections are reused until idle timeout.

## Cache Tuning

The in-memory cache uses TinyUFO eviction (better than LRU for mixed workloads) with a 128 MiB cap.

- **Best for:** static assets, API responses with known TTL
- **Not for:** authenticated responses (bypassed automatically when Cookie/Authorization headers present)
- Cache status is visible via `X-Cache-Status` header (HIT/MISS/BYPASS)
- Purge per-route via `DELETE /api/v1/cache/routes/:id`

## Monitoring Under Load

### Prometheus

Scrape `/metrics` (no auth required) for real-time visibility:

- `lorica_http_requests_total{route_id, status_code}` - request throughput
- `lorica_http_request_duration_seconds` - latency histogram
- `lorica_backend_health{backend_id}` - backend health status
- `lorica_active_connections` - current connection count

### Dashboard

The Overview page shows request rate sparklines and top routes. Use it to identify bottlenecks before diving into Prometheus.

### NFR Validation

For formal capacity testing, use the NFR validation script:

```bash
sudo ./docs/testing/nfr-validate.sh
```

This tests 10k concurrent connections and 10-minute memory stability.

## Quick Checklist

Before going to production:

- [ ] `ulimit -n 65536` (or higher) for the lorica user
- [ ] `net.core.somaxconn = 65535`
- [ ] `net.ipv4.tcp_tw_reuse = 1`
- [ ] `--workers N` set to CPU core count
- [ ] `max_global_connections` set to a sane cap (e.g. 50000)
- [ ] `rate_limit_rps` configured on public-facing routes
- [ ] `cache_enabled` on static/cacheable routes
- [ ] Prometheus scraping `/metrics`
