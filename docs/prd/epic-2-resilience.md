# Epic 2: Resilience - Worker Isolation and Hot-Reload

**Epic Goal:** Implement process-based worker isolation, a command channel for hot-reload, and certificate hot-swap - making Lorica resilient to worker crashes and capable of zero-downtime reconfiguration.

**Integration Requirements:** The proxy engine from Epic 1 must continue functioning. Worker isolation wraps the existing proxy in separate processes. The command channel replaces direct database reads with push-based configuration updates.

---

## Story 2.1: Process-Based Worker Isolation

As an infrastructure engineer,
I want proxy workers to run in separate OS processes,
so that a crash or compromise in one worker does not affect others.

### Acceptance Criteria

1. `lorica-worker` crate created
2. Main process forks worker processes via fork+exec
3. Each worker runs the proxy engine independently
4. Configurable worker count (default: number of CPU cores)
5. Main process monitors workers and restarts crashed workers
6. Worker crash logged with structured event
7. Listening socket FDs passed to workers via SCM_RIGHTS

### Integration Verification

- IV1: Killing a worker process (kill -9) does not affect other workers
- IV2: Crashed worker is restarted automatically within 1 second
- IV3: Traffic continues flowing through surviving workers during worker restart

---

## Story 2.2: Command Channel

As an infrastructure engineer,
I want configuration changes to propagate to workers without restart,
so that I can reconfigure my proxy with zero downtime.

### Acceptance Criteria

1. `lorica-command` crate created
2. Unix socket pair between main process and each worker
3. Protobuf message format with custom framing (8-byte LE size prefix)
4. Configuration diff generation: compare current state with new state, produce minimal changeset
5. Main process dispatches changes to all workers
6. Workers apply changes inline without pausing traffic
7. Three-state response protocol: Ok, Error, Processing
8. Command channel health monitoring (detect unresponsive workers)

### Integration Verification

- IV1: Route added via API is live on all workers within 1 second
- IV2: No connections are dropped during configuration change
- IV3: Worker reports Error state when a change cannot be applied

---

## Story 2.3: Certificate Hot-Swap

As an infrastructure engineer,
I want to add, replace, and remove TLS certificates without any downtime,
so that certificate rotation is seamless.

### Acceptance Criteria

1. SNI trie for fast domain-to-certificate lookup (wildcard support)
2. Certificate index: multiple certs per domain, sorted by expiration
3. Add operation: new cert replaces shorter-lived certs automatically
4. Remove operation: fallback to longest-lived remaining cert
5. Replace operation: atomic delete + add
6. Changes propagated to workers via command channel
7. Active TLS connections continue with old cert until they close naturally

### Integration Verification

- IV1: New certificate is served to new connections within 1 second of upload
- IV2: Existing connections continue on old certificate without interruption
- IV3: Wildcard certificates match subdomains correctly

---

## Story 2.4: Backend Lifecycle Management

As an infrastructure engineer,
I want backends to drain gracefully when removed,
so that active requests complete without errors.

### Acceptance Criteria

1. Backend states: Normal, Closing, Closed
2. Removing a backend sets it to Closing (no new connections, drain existing)
3. Transition to Closed when active connection count reaches 0
4. Configurable drain timeout (default: 30 seconds, then force close)
5. Backend state visible in dashboard and API
6. Retry policy: exponential backoff (max 6 retries)

### Integration Verification

- IV1: Active requests complete successfully when backend is set to Closing
- IV2: No new requests are sent to a Closing backend
- IV3: Backend transitions to Closed after drain completes
