# User Interface Enhancement Goals

## Integration with Existing UI

There is no existing UI - this is a greenfield dashboard built as an integral part of Lorica. The dashboard is the primary management interface, designed from day one alongside the proxy engine.

**Design principles:**
- Appliance-style UI (think network router admin panel, not SaaS dashboard)
- Functional over aesthetic - clarity and information density over visual polish
- Every proxy feature has a corresponding dashboard representation
- Consent-driven: actions require confirmation, preferences are remembered

## Modified/New Screens and Views

| Screen | Purpose | Priority |
|--------|---------|----------|
| **Login** | Authentication, first-run password change | MVP |
| **Overview / Dashboard** | At-a-glance status: routes count, backend health, cert status, system resources | MVP |
| **Routes** | List all routes (input URL -> output destination), cert status per route, latency | MVP |
| **Route Detail** | Single route config: backends, TLS, health checks, WAF toggle, topology | MVP |
| **Backends** | List all backends, health status, active connections, response times | MVP |
| **Certificates** | All certs with expiry dates, status (valid/expiring/expired), upload/ACME actions | MVP |
| **Logs** | Access logs with filtering, search, time range selection | MVP |
| **Security** | Scan attempts, admin endpoint probes, WAF blocked requests, trends | Phase 2 |
| **SLA** | Passive (public) and active (internal) SLA per route, historical trends | Phase 3 |
| **Load Tests** | On-demand and scheduled load tests, real-time results, historical comparison | Phase 3 |
| **System** | CPU, RAM, disk of host machine, worker process status | MVP |
| **Settings** | Global rules, notification config (stdout/email/webhook), export/import | MVP |

## UI Consistency Requirements

- Consistent navigation pattern across all screens (sidebar or top nav)
- Uniform status indicators: green (healthy/valid), orange (warning/expiring), red (down/expired)
- All destructive actions require explicit confirmation
- Preference memory for recurring decisions (never ask again / always / ask each time)
- Responsive layout for desktop browsers (mobile is not a priority)
