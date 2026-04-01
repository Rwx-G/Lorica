# Technical Backlog

Items identified during development that are deferred to future stories.

## High Priority

| Source | Description | References |
|--------|-------------|------------|
| Wiring audit | `compression_enabled` stored but no gzip/brotli logic in proxy | `proxy_wiring.rs`, Route model |
| Wiring audit | `retry_attempts` stored but no retry on backend failure | `proxy_wiring.rs`, ProxyHttp trait |
| Wiring audit | `websocket_enabled` stored but no WebSocket upgrade handling | `proxy_wiring.rs`, Route model |

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Epic 4 QA | GPG package signing for apt/yum repository trust | Story 4.4, `dist/build-deb.sh` |
| Wiring audit | Worker/supervisor mode: health checks not started | `main.rs` run_supervisor/run_worker |
| Wiring audit | Worker/supervisor mode: probe scheduler not started | `main.rs` run_supervisor |
| Wiring audit | Worker mode: SLA flush task not started, metrics accumulate in memory | `main.rs` run_worker |
| Wiring audit | Supervisor mode: cache_backend/ban_list/sla_collector = None in AppState | `main.rs` run_supervisor |
| Wiring audit | DNS-01 manual mode (without API provider, 2-step challenge flow) | `lorica-api/src/acme.rs` |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
