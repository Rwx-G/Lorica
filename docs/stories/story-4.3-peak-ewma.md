# Story 4.3: Peak EWMA Load Balancing

**Epic:** [Epic 4 - Production](../prd/epic-4-production.md)
**Status:** Done
**Priority:** P2
**Depends on:** Story 1.8

---

As an infrastructure engineer,
I want latency-based load balancing,
so that traffic is routed to the most responsive backend.

## Acceptance Criteria

1. Peak EWMA algorithm implemented as load balancing option
2. Tracks connection time with exponential decay
3. Selectable per route alongside existing algorithms (Round Robin, Consistent Hash, Random)
4. Dashboard shows EWMA scores per backend
5. Default algorithm remains Round Robin (opt-in for EWMA)

## Integration Verification

- IV1: Under heterogeneous backend latency, EWMA routes more traffic to faster backend
- IV2: EWMA adapts within seconds when backend latency changes
- IV3: EWMA does not add measurable latency overhead

## Tasks

- [x] Implement Peak EWMA algorithm in proxy_wiring.rs
- [x] Track connection establishment time per backend
- [x] Implement exponential decay for latency scores (alpha=0.3)
- [x] Add EWMA as selectable algorithm in route configuration
- [ ] Display EWMA scores in dashboard backend view (deferred - API for scores needed)
- [x] Write unit tests for EWMA selection and decay
- [x] Write tests with heterogeneous backend latencies

## Dev Notes

- Peak EWMA concept from Sozu (reimplemented, not copied)
- Exponential decay weight: recent connections count more than old ones
- EWMA score = peak latency * decay factor
- Selection: choose backend with lowest EWMA score
- No overhead for routes using other algorithms
