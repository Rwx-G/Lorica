# Epic and Story Structure

## Epic Approach

**Epic Structure Decision:** Each epic is self-contained and delivers incremental value. The dashboard-first approach means the API and dashboard are built alongside the proxy from Epic 1, not deferred. Epics 1-5 covered the foundation through the v1.0.0 / v1.1.0 release line ; Epics 6-7 layered on production proxy features and HTTP caching / DDoS protection ; Epic 8 covers the v1.6.0 release cycle (multi-user RBAC, AI bot defense, hot binary upgrade, plus the open audit-closure backlog).

| Epic | Title | Focus | Stories |
|------|-------|-------|---------|
| [Epic 1](./epic-1-foundation.md) | Foundation - Fork, Strip, and Product Skeleton | Proxy + API + Dashboard MVP | 10 stories |
| [Epic 2](./epic-2-resilience.md) | Resilience - Worker Isolation and Hot-Reload | Process isolation, command channel, cert hot-swap | 4 stories |
| [Epic 3](./epic-3-intelligence.md) | Intelligence - WAF and Topology Awareness | WAF layer, topology-aware backends, notifications | 3 stories |
| [Epic 4](./epic-4-production.md) | Production - ACME, Metrics, and Packaging | Auto-TLS, Prometheus, packaging, hardening | 5 stories |
| [Epic 5](./epic-5-observability.md) | Observability - SLA Monitoring and Load Testing | Passive/active SLA, load testing, scheduling | 3 stories |
| [Epic 6](./epic-6-route-config.md) | Route Configuration - Production Proxy Features | Headers, timeouts, security presets, path rewriting, hostname aliases | 3 stories |
| [Epic 7](./epic-7-cache-and-protection.md) | HTTP Caching & DDoS Protection | Cache engine, rate limiting, anti-DDoS, auto-ban | 3 stories |
| [Epic 8](./epic-8-v1.6.0.md) | Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0) | RBAC, AI crawler deny-list, hot binary upgrade, module split, audit-closure backlog | 12 stories |
