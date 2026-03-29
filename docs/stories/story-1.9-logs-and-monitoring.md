# Story 1.9: Dashboard - Logs and System Monitoring

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
**Priority:** P1
**Depends on:** Stories 1.5, 1.8

---

As an infrastructure engineer,
I want to view access logs and system resource usage in the dashboard,
so that I have full visibility into my proxy's operation.

## Acceptance Criteria

1. Logs screen: scrollable access log with filtering (by route, status code, time range)
2. Log search: text search across log entries
3. System screen: CPU, RAM, and disk usage of the host machine
4. System screen: Lorica process memory and CPU usage
5. System screen: uptime, version, active connection count
6. Metrics refresh automatically (polling or WebSocket)

## Integration Verification

- IV1: Proxied requests appear in the logs screen within 2 seconds
- IV2: System metrics match values from system tools (top, free, df)
- IV3: Log filtering correctly narrows displayed entries

## Tasks

- [x] Implement log storage (in-memory ring buffer or SQLite table for recent logs)
- [x] Add `GET /api/v1/logs` endpoint with query params (route, status, time range, search)
- [x] Add `GET /api/v1/system` endpoint using sysinfo crate
- [x] Build logs screen with data table and filters
- [x] Build log search input
- [x] Build system screen with resource gauges/charts
- [x] Implement auto-refresh (polling interval or WebSocket)
- [x] Test log entries appear after proxied requests
- [x] Test system metrics accuracy

## Dev Notes

- Log storage strategy: keep last N entries in memory (configurable, default 10,000)
- For persistent log history, rely on stdout -> journald/SIEM pipeline
- sysinfo crate provides cross-platform CPU, RAM, disk metrics
- Auto-refresh: start with polling (every 5s), consider WebSocket later for real-time
- Active connection count comes from the proxy engine internals

## Dev Agent Record

- Implementation date: 2026-03-29
- Approach: In-memory ring buffer (`LogBuffer`) shared between proxy wiring and API via `Arc`. No SQLite table needed - ring buffer is simpler and sufficient for dashboard viewing. `sysinfo 0.33` used for host and process metrics.
- Key decisions:
  - Ring buffer with `tokio::sync::RwLock` for thread-safe concurrent reads during API calls
  - Proxy logging pushes entries via `rt_handle.spawn()` to bridge sync proxy context to async buffer
  - Disk metrics aggregate all mounted disks (total/available)
  - Process metrics use `sysinfo::Pid::from_u32(std::process::id())`
  - Frontend uses 5s polling interval with toggle, no WebSocket (as per dev notes)

## File List

| File | Change |
|------|--------|
| `lorica-api/src/logs.rs` | New - LogBuffer ring buffer, LogEntry, GET/DELETE /api/v1/logs handlers |
| `lorica-api/src/system.rs` | New - GET /api/v1/system handler with sysinfo metrics |
| `lorica-api/src/lib.rs` | Modified - export logs and system modules |
| `lorica-api/src/server.rs` | Modified - AppState gains log_buffer and started_at, 3 new routes |
| `lorica-api/src/tests.rs` | Modified - test_state updated, 5 new integration tests |
| `lorica-api/Cargo.toml` | Modified - add sysinfo dependency |
| `lorica/src/proxy_wiring.rs` | Modified - LoricaProxy gains log_buffer, logging() pushes to buffer |
| `lorica/src/main.rs` | Modified - create LogBuffer, pass to proxy and API |
| `lorica/Cargo.toml` | Modified - add chrono dependency |
| `lorica-dashboard/frontend/src/lib/api.ts` | Modified - add log/system types and API methods |
| `lorica-dashboard/frontend/src/lib/api.test.ts` | Modified - 4 new API client tests |
| `lorica-dashboard/frontend/src/routes/Logs.svelte` | New - Logs screen |
| `lorica-dashboard/frontend/src/routes/System.svelte` | New - System monitoring screen |
| `lorica-dashboard/frontend/src/routes/Dashboard.svelte` | Modified - wire Logs and System screens |
| `CHANGELOG.md` | Modified - Story 1.9 entries |
