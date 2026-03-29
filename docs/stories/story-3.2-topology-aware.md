# Story 3.2: Topology-Aware Backend Management

**Epic:** [Epic 3 - Intelligence](../prd/epic-3-intelligence.md)
**Status:** Draft
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

- [ ] Define TopologyType enum and configuration schema
- [ ] Implement SingleVM behavior (no active checks)
- [ ] Implement HA behavior (active checks, failover)
- [ ] Research Docker API for service discovery
- [ ] Implement DockerSwarm integration
- [ ] Research Kubernetes API for pod discovery
- [ ] Implement Kubernetes integration
- [ ] Implement Custom topology with user-defined rules
- [ ] Add global topology defaults to settings
- [ ] Add per-backend topology override
- [ ] Update dashboard to show topology type
- [ ] Write tests for each topology type

## Dev Notes

- Start with SingleVM and HA, defer DockerSwarm and Kubernetes to later iterations
- Docker API: connect to `/var/run/docker.sock` for service events
- Kubernetes: use kube-rs crate for API interaction
- Global defaults with per-backend override = two-level rule hierarchy
- Custom topology allows user-defined HTTP health check URLs, intervals, thresholds
