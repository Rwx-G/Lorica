# Epic 5: Observability - SLA Monitoring and Load Testing

**Epic Goal:** Add dual SLA monitoring (passive from real traffic, active from synthetic probes) and built-in load testing with scheduling and safety guards, giving engineers full visibility into backend performance and capacity.

**Integration Requirements:** Passive SLA monitoring hooks into the existing proxy engine's request/response pipeline. Active probes and load tests generate traffic from Lorica itself toward backends. Results are stored in the embedded database and displayed in the dashboard.

---

## Story 5.1: Passive SLA Monitoring (Public/Contractual)

As an infrastructure engineer,
I want SLA metrics calculated from real user traffic,
so that I have an accurate picture of what my users actually experience.

### Acceptance Criteria

1. Per-route metrics collected from real traffic: request count, success rate, latency percentiles (p50, p95, p99)
2. SLA calculation: uptime percentage based on configurable success criteria (e.g., < 500ms and 2xx = "available")
3. Time-windowed SLA: rolling 24h, 7d, 30d windows
4. Historical SLA data persisted in embedded database
5. Dashboard SLA view: per-route SLA percentage, latency trends, error rate graphs
6. SLA threshold alerts: notify when SLA drops below configurable target (e.g., 99.9%)
7. SLA data exportable for reporting

### Integration Verification

- IV1: SLA percentage matches manual calculation from access logs
- IV2: SLA alert triggers when error rate exceeds threshold
- IV3: Historical data survives restart

---

## Story 5.2: Active SLA Monitoring (Internal/Engineering)

As an infrastructure engineer,
I want synthetic health probes sent to backends at regular intervals,
so that I can detect outages even when there is no user traffic.

### Acceptance Criteria

1. Configurable synthetic probes per route/backend (HTTP method, path, expected status, interval)
2. Default probe: `GET /` expecting 2xx, every 30 seconds
3. Probe results tracked independently from real traffic: latency, status, success rate
4. Active SLA calculation: uptime based on probe results (independent of user traffic)
5. Dashboard shows both passive and active SLA side by side per route
6. Active SLA detects outages during low-traffic periods (night, weekends)
7. Probe configuration manageable from dashboard

### Integration Verification

- IV1: Backend taken offline is detected by active probes within configured interval
- IV2: Active SLA shows degradation while passive SLA shows 100% (no traffic scenario)
- IV3: Probe intervals are respected under load

---

## Story 5.3: Built-in Load Testing

As an infrastructure engineer,
I want to run load tests from Lorica against my backends,
so that I can verify my infrastructure handles the expected traffic without needing external tools.

### Acceptance Criteria

1. Load test engine built into Lorica (generates real HTTP requests to backends)
2. Configurable parameters: concurrent connections, requests per second, duration, request pattern (URL, method, headers, body)
3. Dashboard UI with slider controls for parameters
4. Default safe limits (e.g., 100 concurrent connections, 60 seconds max)
5. Exceeding safe limits requires explicit confirmation popup
6. Auto-abort when backend error rate exceeds configurable threshold (default: 10% 5xx)
7. Real-time results in dashboard during execution: latency curve, throughput, error rate, active connections
8. Test results stored in database with historical comparison view
9. Schedulable tests: recurring execution (e.g., weekly) with automatic result comparison
10. Historical trend: detect performance degradation over time (e.g., same test, 6 months apart)

### Integration Verification

- IV1: Load test generates expected number of concurrent connections to backend
- IV2: Auto-abort triggers when error rate exceeds threshold
- IV3: Scheduled test executes at configured time and stores results
- IV4: Historical comparison shows performance delta between test runs
