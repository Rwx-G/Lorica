# Epic 4: Production - ACME, Metrics, and Packaging

**Epic Goal:** Add automatic certificate provisioning, Prometheus metrics, and production packaging for distribution.

**Integration Requirements:** ACME integration works with the existing certificate management system. Metrics endpoint is served on the management port alongside the API and dashboard.

---

## Story 4.1: ACME / Let's Encrypt Integration

As an infrastructure engineer,
I want Lorica to automatically provision TLS certificates via Let's Encrypt,
so that I don't have to manage certificates manually.

### Acceptance Criteria

1. ACME client implementation (HTTP-01 challenge)
2. Opt-in per route: admin explicitly enables auto-TLS (consent-driven)
3. Automatic renewal before expiration (configurable threshold, default 30 days)
4. Renewal requires consent or pre-configured auto-approval preference
5. Fallback: if ACME fails, notify admin and continue with existing cert
6. Certificate storage in embedded database alongside manually uploaded certs
7. Dashboard shows ACME-managed vs manually-managed certificates

### Integration Verification

- IV1: ACME provisioning successfully obtains a certificate from Let's Encrypt staging
- IV2: Auto-renewal triggers at configured threshold
- IV3: ACME failure does not disrupt existing TLS termination

---

## Story 4.2: Prometheus Metrics Endpoint

As an infrastructure engineer,
I want a Prometheus-compatible metrics endpoint,
so that I can integrate Lorica into my existing monitoring stack.

### Acceptance Criteria

1. `/metrics` endpoint on management port (localhost only)
2. Metrics: request count (by route, status code), latency histograms, active connections
3. Metrics: backend health status, certificate days-to-expiry
4. Metrics: system resources (CPU, RAM, disk)
5. Metrics: WAF events count (by rule, action)
6. Worker-level metrics aggregated at main process

### Integration Verification

- IV1: Prometheus can scrape `/metrics` and parse all metrics
- IV2: Metric values match dashboard displays
- IV3: No metric cardinality explosion under normal operation

---

## Story 4.3: Peak EWMA Load Balancing

As an infrastructure engineer,
I want latency-based load balancing,
so that traffic is routed to the most responsive backend.

### Acceptance Criteria

1. Peak EWMA algorithm implemented as load balancing option
2. Tracks connection time with exponential decay
3. Selectable per route alongside existing algorithms (Round Robin, Consistent Hash, Random)
4. Dashboard shows EWMA scores per backend
5. Default algorithm remains Round Robin (opt-in for EWMA)

### Integration Verification

- IV1: Under heterogeneous backend latency, EWMA routes more traffic to faster backend
- IV2: EWMA adapts within seconds when backend latency changes
- IV3: EWMA does not add measurable latency overhead

---

## Story 4.4: Production Packaging

As an infrastructure engineer,
I want to install Lorica via `apt install lorica`,
so that deployment is simple and follows standard Linux conventions.

### Acceptance Criteria

1. `.deb` package build pipeline (GitHub Actions or equivalent)
2. Package includes: binary, systemd unit file, default data directory (`/var/lib/lorica`)
3. Post-install script: create lorica system user, set directory permissions, enable service
4. Post-install output: display dashboard URL and temporary credentials
5. Upgrade-safe: database and data directory preserved on package upgrade
6. Static binary also available as GitHub release artifact
7. Package signing for apt repository trust

### Integration Verification

- IV1: `apt install lorica` on a clean Debian/Ubuntu system results in running service
- IV2: `apt upgrade lorica` preserves existing configuration and database
- IV3: `apt remove lorica` stops the service, `apt purge lorica` removes data directory

---

## Story 4.5: Security Hardening

As an infrastructure engineer,
I want Lorica to be hardened for production deployment,
so that the proxy itself is not a security liability.

### Acceptance Criteria

1. `cargo audit` clean - no known vulnerabilities in dependencies
2. Fuzz testing for TLS handshake, HTTP parsing, and API input handling
3. Rate limiting on management API (brute-force protection for login)
4. Session timeout and secure cookie flags for dashboard auth
5. No secrets in logs (password, cert private keys masked)
6. systemd hardening: PrivateTmp, NoNewPrivileges, ProtectSystem
7. Security documentation: threat model, hardening guide

### Integration Verification

- IV1: `cargo audit` returns no vulnerabilities
- IV2: Fuzz testing runs for minimum 1 hour without crashes
- IV3: Brute-force login attempt is rate-limited after 5 failures
- IV4: Private key material never appears in log output
