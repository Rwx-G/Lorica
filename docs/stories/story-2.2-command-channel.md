# Story 2.2: Command Channel

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Done
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

- [x] Create `lorica-command` crate
- [x] Define protobuf schema (`command.proto`)
- [x] Implement Channel with custom framing (8-byte LE size prefix)
- [x] Implement ConfigDiff in lorica-config (compare states, minimal changeset)
- [x] Implement message dispatch from main to all workers
- [x] Implement worker-side change application
- [x] Implement 3-state response protocol (Ok, Error, Processing)
- [x] Implement channel health monitoring (heartbeat/timeout)
- [x] Write tests for diff generation
- [x] Write tests for zero-downtime config change

## Dev Notes

- Custom framing rationale (from Sozu analysis): prost's built-in delimiter size may change
- Double buffer architecture for non-blocking I/O on the channel
- ConfigDiff uses sorted collections with Added/Removed/Changed semantics
- Processing state allows tracking long operations like connection draining

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### Debug Log References
None.

### Completion Notes
- `lorica-command` crate with protobuf messages (prost derives, no protoc needed), `CommandChannel` with 8-byte LE framing, async I/O via tokio
- Three-state response protocol: Ok, Error, Processing
- Supervisor dispatches ConfigReload when API signals mutations, receives responses
- Workers run a background command channel listener thread; reload config from DB on command
- Heartbeat every 5s from supervisor with timeout detection
- ConfigDiff already existed in lorica-config (diff.rs) - reused for import comparisons
- SQLite busy_timeout (5s) added to prevent "database is locked" during concurrent startup
- 13 new tests in lorica-command, 221 total, 0 failures

### File List
- `lorica-command/Cargo.toml` (new)
- `lorica-command/src/lib.rs` (new)
- `lorica-command/src/messages.rs` (new)
- `lorica-command/src/channel.rs` (new)
- `lorica-command/proto/command.proto` (new - documentation)
- `lorica-worker/src/manager.rs` (modified - expose WorkerHandle, cmd_fd)
- `lorica/Cargo.toml` (modified - add lorica-command, nix deps)
- `lorica/src/main.rs` (modified - command channel integration)
- `lorica-config/src/store.rs` (modified - busy_timeout)
- `Cargo.toml` (modified - add lorica-command to workspace)
- `Dockerfile.dev` (modified)
- `tests-e2e-docker/Dockerfile` (modified)

### Change Log
- feat(command): create lorica-command crate with protobuf messages and framed channel
- feat(command): integrate command channel into supervisor/worker lifecycle
- fix(config): add PRAGMA busy_timeout for concurrent worker DB access
