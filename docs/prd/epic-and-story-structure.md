# Epic and Story Structure

## Epic Approach

**Epic Structure Decision:** Four epics aligned with the phased delivery strategy. Each epic is self-contained and delivers incremental value. The dashboard-first approach means the API and dashboard are built alongside the proxy from Epic 1, not deferred.

| Epic | Title | Focus | Stories |
|------|-------|-------|---------|
| [Epic 1](./epic-1-foundation.md) | Foundation - Fork, Strip, and Product Skeleton | Proxy + API + Dashboard MVP | 10 stories |
| [Epic 2](./epic-2-resilience.md) | Resilience - Worker Isolation and Hot-Reload | Process isolation, command channel, cert hot-swap | 4 stories |
| [Epic 3](./epic-3-intelligence.md) | Intelligence - WAF and Topology Awareness | WAF layer, topology-aware backends, notifications | 3 stories |
| [Epic 4](./epic-4-production.md) | Production - ACME, Metrics, and Packaging | Auto-TLS, Prometheus, packaging, hardening | 5 stories |
| [Epic 5](./epic-5-observability.md) | Observability - SLA Monitoring and Load Testing | Passive/active SLA, load testing, scheduling | 3 stories |
