# Story 1.9: Dashboard - Logs and System Monitoring

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Implement log storage (in-memory ring buffer or SQLite table for recent logs)
- [ ] Add `GET /api/v1/logs` endpoint with query params (route, status, time range, search)
- [ ] Add `GET /api/v1/system` endpoint using sysinfo crate
- [ ] Build logs screen with data table and filters
- [ ] Build log search input
- [ ] Build system screen with resource gauges/charts
- [ ] Implement auto-refresh (polling interval or WebSocket)
- [ ] Test log entries appear after proxied requests
- [ ] Test system metrics accuracy

## Dev Notes

- Log storage strategy: keep last N entries in memory (configurable, default 10,000)
- For persistent log history, rely on stdout -> journald/SIEM pipeline
- sysinfo crate provides cross-platform CPU, RAM, disk metrics
- Auto-refresh: start with polling (every 5s), consider WebSocket later for real-time
- Active connection count comes from the proxy engine internals
