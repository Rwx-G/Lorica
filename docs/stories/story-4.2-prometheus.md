# Story 4.2: Prometheus Metrics Endpoint

**Epic:** [Epic 4 - Production](../prd/epic-4-production.md)
**Status:** Done
**Priority:** P2
**Depends on:** Epic 1 complete

---

As an infrastructure engineer,
I want a Prometheus-compatible metrics endpoint,
so that I can integrate Lorica into my existing monitoring stack.

## Acceptance Criteria

1. `/metrics` endpoint on management port (localhost only)
2. Metrics: request count (by route, status code), latency histograms, active connections
3. Metrics: backend health status, certificate days-to-expiry
4. Metrics: system resources (CPU, RAM, disk)
5. Metrics: WAF events count (by rule, action)
6. Worker-level metrics aggregated at main process

## Integration Verification

- IV1: Prometheus can scrape `/metrics` and parse all metrics
- IV2: Metric values match dashboard displays
- IV3: No metric cardinality explosion under normal operation

## Tasks

- [x] Add prometheus crate dependency
- [x] Define metric registry with all metrics
- [x] Implement request counter (labels: route_id, status_code)
- [x] Implement latency histogram (labels: route_id)
- [x] Implement active connections gauge
- [x] Implement backend health gauge (labels: backend_id, address)
- [x] Implement cert expiry gauge (labels: domain)
- [x] Implement system resource gauges (cpu, memory)
- [x] Add `/metrics` endpoint to management API
- [ ] Aggregate worker metrics at main process (deferred - requires command channel extension)
- [x] Test with metric encoding verification
- [x] Verify bounded label cardinality (route_id not hostname)

## Dev Notes

- Use prometheus crate (same one Pingora optionally uses)
- Keep label cardinality low - route hostname, not full path
- Latency histogram buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 5s
- Worker metrics aggregation requires command channel (deferred to after Story 2.2)
