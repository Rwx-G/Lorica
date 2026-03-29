# Epic 3: Intelligence - WAF and Topology Awareness

**Epic Goal:** Add an optional WAF layer with OWASP CRS rules, topology-aware backend management, and notification channels.

**Integration Requirements:** WAF processing must not impact proxy latency for routes where WAF is disabled. Topology awareness integrates with the existing health check and load balancing systems.

---

## Story 3.1: WAF Engine with OWASP CRS

As an infrastructure engineer,
I want an optional WAF that detects and blocks common attacks,
so that my backends are protected without needing a separate WAF tool.

### Acceptance Criteria

1. `lorica-waf` crate created
2. OWASP CRS ruleset loading and parsing
3. WAF evaluation pipeline: inspect request headers, path, query, body against rules
4. Two modes per route: detection-only (log) or blocking (403)
5. WAF toggle per route in dashboard and API
6. Alerting by default: even without WAF enabled, suspicious patterns logged
7. WAF events visible in dashboard security panel
8. Performance: < 0.5ms added latency for WAF evaluation

### Integration Verification

- IV1: Known attack patterns (SQL injection, XSS, path traversal) are detected
- IV2: WAF in blocking mode returns 403 for matched requests
- IV3: WAF in detection mode logs the event but proxies the request normally
- IV4: Routes without WAF enabled have zero WAF latency overhead

---

## Story 3.2: Topology-Aware Backend Management

As an infrastructure engineer,
I want Lorica to adapt its behavior based on my backend infrastructure type,
so that health checks and failover match my actual setup.

### Acceptance Criteria

1. Topology types: SingleVM, HA, DockerSwarm, Kubernetes, Custom
2. SingleVM: no active health checks, passive failure detection only
3. HA: active health checks, automatic failover to standby
4. DockerSwarm: service discovery via Docker API, drain on container removal
5. Kubernetes: pod discovery via K8S API, awareness of readiness/liveness
6. Custom: user-defined health check and failover rules
7. Global topology defaults configurable in settings
8. Per-backend topology override in route configuration
9. Dashboard shows topology type and adapted behavior per backend

### Integration Verification

- IV1: SingleVM backend has no health check probes
- IV2: HA backend fails over to standby when primary is down
- IV3: Topology change via dashboard adjusts health check behavior immediately

---

## Story 3.3: Notification Channels

As an infrastructure engineer,
I want to receive notifications for critical events via email or webhook,
so that I am alerted without watching the dashboard constantly.

### Acceptance Criteria

1. `lorica-notify` crate created
2. Notification types: cert_expiring, backend_down, waf_alert, config_changed
3. Stdout channel: always on, structured JSON log events
4. Email channel: SMTP configuration in settings, configurable alert types
5. Webhook channel: URL + optional auth header, configurable alert types
6. Notification preferences per alert type (enable/disable per channel)
7. Test notification button in dashboard settings
8. Notification history viewable in dashboard

### Integration Verification

- IV1: Certificate approaching expiration triggers configured notifications
- IV2: Backend going down triggers notification within configured threshold
- IV3: Webhook delivers valid JSON payload to configured URL
