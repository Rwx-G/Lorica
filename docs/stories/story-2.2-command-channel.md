# Story 2.2: Command Channel

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Draft
**Priority:** P1
**Depends on:** Story 2.1

---

As an infrastructure engineer,
I want configuration changes to propagate to workers without restart,
so that I can reconfigure my proxy with zero downtime.

## Acceptance Criteria

1. `lorica-command` crate created
2. Unix socket pair between main process and each worker
3. Protobuf message format with custom framing (8-byte LE size prefix)
4. Configuration diff generation: compare current state with new state, produce minimal changeset
5. Main process dispatches changes to all workers
6. Workers apply changes inline without pausing traffic
7. Three-state response protocol: Ok, Error, Processing
8. Command channel health monitoring (detect unresponsive workers)

## Integration Verification

- IV1: Route added via API is live on all workers within 1 second
- IV2: No connections are dropped during configuration change
- IV3: Worker reports Error state when a change cannot be applied

## Tasks

- [ ] Create `lorica-command` crate
- [ ] Define protobuf schema (`command.proto`)
- [ ] Implement Channel with custom framing (8-byte LE size prefix)
- [ ] Implement ConfigDiff in lorica-config (compare states, minimal changeset)
- [ ] Implement message dispatch from main to all workers
- [ ] Implement worker-side change application
- [ ] Implement 3-state response protocol (Ok, Error, Processing)
- [ ] Implement channel health monitoring (heartbeat/timeout)
- [ ] Write tests for diff generation
- [ ] Write tests for zero-downtime config change

## Dev Notes

- Custom framing rationale (from Sozu analysis): prost's built-in delimiter size may change
- Double buffer architecture for non-blocking I/O on the channel
- ConfigDiff uses sorted collections with Added/Removed/Changed semantics
- Processing state allows tracking long operations like connection draining
