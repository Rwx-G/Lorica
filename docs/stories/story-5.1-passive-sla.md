# Story 5.1: Passive SLA Monitoring (Public/Contractual)

**Epic:** [Epic 5 - Observability](../prd/epic-5-observability.md)
**Status:** Done
**Priority:** P2
**Depends on:** Story 1.8 (proxy engine wiring)

---

As an infrastructure engineer,
I want SLA metrics calculated from real user traffic,
so that I have an accurate picture of what my users actually experience.

## Acceptance Criteria

1. Per-route metrics collected from real traffic: request count, success rate, latency percentiles (p50, p95, p99)
2. SLA calculation: uptime percentage based on configurable success criteria (e.g., < 500ms and 2xx = "available")
3. Time-windowed SLA: rolling 24h, 7d, 30d windows
4. Historical SLA data persisted in embedded database
5. Dashboard SLA view: per-route SLA percentage, latency trends, error rate graphs
6. SLA threshold alerts: notify when SLA drops below configurable target (e.g., 99.9%)
7. SLA data exportable for reporting

## Integration Verification

- IV1: SLA percentage matches manual calculation from access logs
- IV2: SLA alert triggers when error rate exceeds threshold
- IV3: Historical data survives restart

## Tasks

- [x] Design SLA metrics data model (time-bucketed aggregates)
- [x] Implement metrics collector in ProxyHttp logging() callback
- [x] Implement time-windowed aggregation (24h, 7d, 30d rolling windows)
- [x] Implement SLA percentage calculation with configurable success criteria
- [x] Persist aggregated metrics to SQLite (not per-request - aggregated buckets)
- [x] Add SLA API endpoints (`GET /api/v1/sla/routes/:id`)
- [ ] Build dashboard SLA view with charts (latency trends, error rate, uptime %)
- [x] Implement SLA threshold alerts (integrate with lorica-notify)
- [x] Implement SLA data export (CSV or JSON)
- [x] Write tests for SLA calculation accuracy

## Dev Notes

- Passive SLA = the "public" number. This is what clients experience.
- Store aggregated time buckets (e.g., 1-minute resolution), not individual requests
- SLA success criteria configurable per route: "2xx AND latency < Xms = available"
- Default SLA target: 99.9% (configurable per route)
- Use hdrhistogram or similar for efficient percentile computation
- A backend with 0 traffic in a window should NOT count as 100% SLA - it's "no data"
- SLA config (success criteria, target %) is snapshotted in each time bucket so historical reporting stays consistent after config changes (migration 006)
