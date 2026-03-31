# Technical Backlog

Items identified during development that are deferred to future stories.

## High Priority

| Source | Description | References |
|--------|-------------|------------|

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Epic 4 QA | DNS-01 ACME challenge for NAT/internal deployments | Story 4.1, `acme.rs` |
| Epic 4 QA | ACME auto-renewal background task (currently manual trigger) | Story 4.1, `acme.rs` |
| Epic 4 QA | Worker-level Prometheus metrics aggregation via command channel | Story 4.2, `metrics.rs` |
| Epic 4 QA | GPG package signing for apt repository trust | Story 4.4, `dist/build-deb.sh` |
| Epic 3 QA | Docker Swarm event watching for real-time task changes | Story 3.2, `discovery/docker.rs` |
| Epic 3 QA | Kubernetes watch API for endpoint change streaming | Story 3.2, `discovery/kubernetes.rs` |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| Epic 4 QA | Per-backend EWMA scores API endpoint + dashboard display | Story 4.3, `proxy_wiring.rs` |
| Epic 4 QA | Grafana dashboard template for Prometheus metrics | Story 4.2 |
| Epic 4 QA | RPM packaging for RHEL/CentOS | Story 4.4 |
| Epic 4 QA | Docker Hub image publication | Story 4.4 |
| Epic 4 QA | Migrate serde_yml to serde_yaml_ng (Pingora upstream) | Story 4.5, RUSTSEC-2025-0068 |
| Epic 4 QA | Fuzz testing as scheduled CI job (weekly) | Story 4.5, `fuzz/` |
| Epic 4 QA | SBOM generation in release pipeline | Story 4.4 |
| Epic 3 QA | Custom user-defined regex WAF rules via API | Story 3.1, `lorica-waf` |
| Epic 3 QA | Slack/Discord notification channels | Story 3.3, `lorica-notify` |
