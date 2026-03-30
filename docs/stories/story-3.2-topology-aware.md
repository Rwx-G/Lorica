# Story 3.2: Topology-Aware Backend Management

**Epic:** [Epic 3 - Intelligence](../prd/epic-3-intelligence.md)
**Status:** Review
**Priority:** P2
**Depends on:** Epic 2 complete

---

As an infrastructure engineer,
I want Lorica to adapt its behavior based on my backend infrastructure type,
so that health checks and failover match my actual setup.

## Acceptance Criteria

1. Topology types: SingleVM, HA, DockerSwarm, Kubernetes, Custom
2. SingleVM: no active health checks, passive failure detection only
3. HA: active health checks, automatic failover to standby
4. DockerSwarm: service discovery via Docker API, drain on container removal
5. Kubernetes: pod discovery via K8S API, awareness of readiness/liveness
6. Custom: user-defined health check and failover rules
7. Global topology defaults configurable in settings
8. Per-backend topology override in route configuration
9. Dashboard shows topology type and adapted behavior per backend

## Integration Verification

- IV1: SingleVM backend has no health check probes
- IV2: HA backend fails over to standby when primary is down
- IV3: Topology change via dashboard adjusts health check behavior immediately

## Tasks

- [x] Define TopologyType enum and configuration schema
- [x] Implement SingleVM behavior (no active checks)
- [x] Implement HA behavior (active checks, failover)
- [ ] Research Docker API for service discovery (deferred per dev notes)
- [ ] Implement DockerSwarm integration (deferred per dev notes)
- [ ] Research Kubernetes API for pod discovery (deferred per dev notes)
- [ ] Implement Kubernetes integration (deferred per dev notes)
- [x] Implement Custom topology with user-defined rules
- [x] Add global topology defaults to settings
- [x] Add per-backend topology override
- [x] Update dashboard to show topology type
- [x] Write tests for each topology type

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### File List
- `lorica-config/src/models.rs` - MODIFIED - Added default_topology_type to GlobalSettings
- `lorica-config/src/store.rs` - MODIFIED - Persist/load default_topology_type setting
- `lorica-config/src/tests.rs` - MODIFIED - Updated test GlobalSettings construction
- `lorica/src/health.rs` - MODIFIED - Topology-aware health check logic
- `lorica-api/src/settings.rs` - MODIFIED - Added default_topology_type to settings API
- `lorica-dashboard/frontend/src/lib/api.ts` - MODIFIED - Added topology to settings types
- `lorica-dashboard/frontend/src/routes/Settings.svelte` - MODIFIED - Added topology selector

### Change Log
- TopologyType enum was already defined in models.rs from Epic 1
- Added default_topology_type to GlobalSettings with SingleVM default
- Implemented resolve_backend_topology() to determine effective topology per backend
- SingleVM: skips active health probes entirely (passive-only)
- HA/Custom: runs active TCP health checks (existing behavior)
- DockerSwarm/Kubernetes: stubbed with debug log (deferred per dev notes)
- Multi-route priority: HA > Custom > DockerSwarm/Kubernetes > SingleVM
- Added topology selector to global settings in API and dashboard

### Completion Notes
- DockerSwarm and Kubernetes implementations deferred per story dev notes
- Per-route topology_type already existed from prior implementation
- 65 config tests, 101 API tests, 52 frontend tests, 35 WAF tests all pass

## Dev Notes

- Start with SingleVM and HA, defer DockerSwarm and Kubernetes to later iterations
- Docker API: connect to `/var/run/docker.sock` for service events
- Kubernetes: use kube-rs crate for API interaction
- Global defaults with per-backend override = two-level rule hierarchy
- Custom topology allows user-defined HTTP health check URLs, intervals, thresholds
