# Story 2.4: Backend Lifecycle Management

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Draft
**Priority:** P1
**Depends on:** Story 2.2

---

As an infrastructure engineer,
I want backends to drain gracefully when removed,
so that active requests complete without errors.

## Acceptance Criteria

1. Backend states: Normal, Closing, Closed
2. Removing a backend sets it to Closing (no new connections, drain existing)
3. Transition to Closed when active connection count reaches 0
4. Configurable drain timeout (default: 30 seconds, then force close)
5. Backend state visible in dashboard and API
6. Retry policy: exponential backoff (max 6 retries)

## Integration Verification

- IV1: Active requests complete successfully when backend is set to Closing
- IV2: No new requests are sent to a Closing backend
- IV3: Backend transitions to Closed after drain completes

## Tasks

- [ ] Add lifecycle_state field to Backend model (Normal, Closing, Closed)
- [ ] Implement state machine transitions
- [ ] Modify load balancer to skip Closing/Closed backends
- [ ] Implement active connection tracking per backend
- [ ] Implement drain timeout with force close
- [ ] Implement exponential backoff retry policy
- [ ] Expose backend state in API and dashboard
- [ ] Write tests for graceful drain under active connections
- [ ] Write tests for drain timeout

## Dev Notes

- Pattern inspired by Sozu's backend lifecycle (concepts only)
- Active connection count tracked atomically per backend
- Drain timeout prevents indefinite waiting for slow connections
- Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s (max 6 retries)
