# Story 2.1: Process-Based Worker Isolation

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Draft
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

- [ ] Create `lorica-worker` crate
- [ ] Implement WorkerManager (fork, exec, monitor)
- [ ] Implement FD passing via SCM_RIGHTS (nix crate)
- [ ] Add `lorica worker` subcommand for worker binary mode
- [ ] Implement worker health monitoring in main process
- [ ] Implement automatic worker restart on crash
- [ ] Add worker count configuration
- [ ] Write tests for worker crash resilience
- [ ] Write tests for FD passing

## Dev Notes

- Pattern inspired by Sozu (concepts only, no code copying)
- Worker binary mode: `lorica worker --id <id> --fd <fd> --scm <scm_fd>`
- Main process creates unix socket pairs before fork for command channel
- SCM_RIGHTS allows passing file descriptors between processes
- This is Unix-only (fork+exec) - Windows support deferred
