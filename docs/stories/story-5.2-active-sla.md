# Story 5.2: Active SLA Monitoring (Internal/Engineering)

**Epic:** [Epic 5 - Observability](../prd/epic-5-observability.md)
**Status:** Done
**Priority:** P2
**Depends on:** Story 5.1

---

As an infrastructure engineer,
I want synthetic health probes sent to backends at regular intervals,
so that I can detect outages even when there is no user traffic.

## Acceptance Criteria

1. Configurable synthetic probes per route/backend (HTTP method, path, expected status, interval)
2. Default probe: `GET /` expecting 2xx, every 30 seconds
3. Probe results tracked independently from real traffic: latency, status, success rate
4. Active SLA calculation: uptime based on probe results (independent of user traffic)
5. Dashboard shows both passive and active SLA side by side per route
6. Active SLA detects outages during low-traffic periods (night, weekends)
7. Probe configuration manageable from dashboard

## Integration Verification

- IV1: Backend taken offline is detected by active probes within configured interval
- IV2: Active SLA shows degradation while passive SLA shows 100% (no traffic scenario)
- IV3: Probe intervals are respected under load

## Tasks

- [x] Design probe configuration model (method, path, expected status, interval, timeout)
- [x] Implement probe scheduler (tokio interval task per probe)
- [x] Implement probe execution (HTTP request to backend via reqwest)
- [x] Track probe results separately from real traffic metrics
- [x] Calculate active SLA from probe results
- [x] Add probe config to route/backend API endpoints
- [x] Build dashboard probe configuration UI
- [x] Build side-by-side passive/active SLA display
- [x] Integrate probe failure alerts with lorica-notify
- [x] Write tests for probe scheduling accuracy
- [x] Write test for outage detection during zero-traffic window

## Dev Notes

- Active SLA = the "internal" number. Engineering quality metric.
- Key insight: a backend can have 100% passive SLA (no users during outage) but 95% active SLA (probes detected the outage)
- Probes run from the main process, not from workers (avoid probe duplication)
- Probe results stored in same time-bucket format as passive metrics
- Don't confuse health checks (Story 1.8 - TCP, used for load balancing) with SLA probes (HTTP, used for monitoring). Health checks affect routing; probes only measure.
- System-wide max_active_probes limit (default 50) configurable via global settings prevents probe overload
- Probes resolve backend addresses from the route's configured backends instead of localhost
