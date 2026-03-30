# Story 2.1: Process-Based Worker Isolation

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Review
**Priority:** P1
**Depends on:** Epic 1 complete

---

As an infrastructure engineer,
I want proxy workers to run in separate OS processes,
so that a crash or compromise in one worker does not affect others.

## Acceptance Criteria

1. `lorica-worker` crate created
2. Main process forks worker processes via fork+exec
3. Each worker runs the proxy engine independently
4. Configurable worker count (default: number of CPU cores)
5. Main process monitors workers and restarts crashed workers
6. Worker crash logged with structured event
7. Listening socket FDs passed to workers via SCM_RIGHTS

## Integration Verification

- IV1: Killing a worker process (kill -9) does not affect other workers
- IV2: Crashed worker is restarted automatically within 1 second
- IV3: Traffic continues flowing through surviving workers during worker restart

## Tasks

- [x] Create `lorica-worker` crate
- [x] Implement WorkerManager (fork, exec, monitor)
- [x] Implement FD passing via SCM_RIGHTS (nix crate)
- [x] Add `lorica worker` subcommand for worker binary mode
- [x] Implement worker health monitoring in main process
- [x] Implement automatic worker restart on crash
- [x] Add worker count configuration
- [x] Write tests for worker crash resilience
- [x] Write tests for FD passing

## Dev Notes

- Pattern inspired by Sozu (concepts only, no code copying)
- Worker binary mode: `lorica worker --id <id> --cmd-fd <fd> --data-dir <dir> --log-level <level>`
- Main process creates unix socket pairs before fork for command channel
- SCM_RIGHTS allows passing file descriptors between processes
- This is Unix-only (fork+exec) - Windows falls back to single-process mode (--workers 0)

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### Debug Log References
None - implementation was clean.

### Completion Notes
- `lorica-worker` crate with `fd_passing` (SCM_RIGHTS send/recv, socketpair, clear_cloexec) and `manager` (WorkerManager: fork+exec, monitor, restart) modules
- `lorica-core::server::Server::set_listen_fds()` added to allow workers to inject pre-received FDs into the server bootstrap mechanism
- `lorica/src/main.rs` refactored into 3 modes: supervisor (forks workers, runs API), worker (receives FDs, runs proxy), single-process (original behavior, --workers 0)
- `lorica-config` migration made idempotent (`INSERT OR IGNORE`) for concurrent worker DB access
- Supervisor forks workers BEFORE creating any tokio runtime (required for correct fork behavior)
- 10 new unit tests in lorica-worker, 208 total tests across modified crates, 0 failures
- Dockerfile.dev added for Linux build/test in Docker from Windows

### File List
- `lorica-worker/Cargo.toml` (new)
- `lorica-worker/src/lib.rs` (new)
- `lorica-worker/src/fd_passing.rs` (new)
- `lorica-worker/src/manager.rs` (new)
- `lorica-core/src/server/mod.rs` (modified - added set_listen_fds)
- `lorica-core/src/server/bootstrap_services.rs` (modified - added set_fds)
- `lorica/Cargo.toml` (modified - added lorica-worker dep)
- `lorica/src/main.rs` (modified - supervisor/worker/single-process modes)
- `lorica-config/src/store.rs` (modified - idempotent migration)
- `Cargo.toml` (modified - added lorica-worker to workspace)
- `Dockerfile.dev` (new)

### Change Log
- feat(worker): create lorica-worker crate with fd_passing and manager modules
- feat(worker): add supervisor mode with fork+exec worker isolation
- feat(worker): add --workers CLI flag (0=single-process, N=multi-worker)
- fix(config): make migration idempotent for concurrent worker access
