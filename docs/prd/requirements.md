# Requirements

## Functional Requirements

**Core Proxy**

- **FR1:** Lorica shall proxy HTTP/1.1 and HTTP/2 traffic from configured frontend routes to backend servers.
- **FR2:** Lorica shall support WebSocket upgrade and proxy WebSocket traffic transparently.
- **FR3:** Lorica shall terminate TLS using rustls (no OpenSSL) with support for TLS 1.2 and 1.3.
- **FR4:** Lorica shall support SNI-based routing to select the correct certificate and backend per hostname.
- **FR5:** Lorica shall provide load balancing across multiple backends per route (Round Robin, Consistent Hash, Random, Peak EWMA).
- **FR6:** Lorica shall perform health checks on backends and remove unhealthy backends from rotation.
- **FR7:** Lorica shall support graceful restart without dropping active connections (FD transfer).

**Dashboard & API**

- **FR8:** Lorica shall expose a REST API for full CRUD operations on routes, backends, certificates, and configuration.
- **FR9:** Lorica shall serve an embedded web dashboard on a localhost-only management port (default: 9443).
- **FR10:** The dashboard shall display all configured routes with their input URLs and output destinations.
- **FR11:** The dashboard shall display TLS certificate status (valid, expiring soon, expired) with expiration dates for each route.
- **FR12:** The dashboard shall display backend health status (healthy, degraded, down) for each backend.
- **FR13:** The dashboard shall display transfer latency metrics per route.
- **FR14:** The dashboard shall display access logs with filtering and search capabilities.
- **FR15:** The dashboard shall provide a security panel showing scan attempts, access attempts on known admin endpoints, and blocked requests (when WAF is active).
- **FR16:** The dashboard shall display host machine resource utilization (CPU, RAM, disk).
- **FR17:** The dashboard shall allow creating, editing, and deleting routes, backends, and certificates without restarting Lorica.

**Onboarding & Auth**

- **FR18:** On first launch, Lorica shall generate a temporary admin password and display it once in stdout.
- **FR19:** On first login, the dashboard shall force a password change.
- **FR20:** Lorica shall run as a systemd service immediately after package installation.
- **FR21:** The proxy data plane shall not listen on any port until at least one route is configured.

**Configuration & State**

- **FR22:** Lorica shall persist its configuration state in an embedded store (not flat config files).
- **FR23:** Lorica shall support exporting the full configuration as a TOML file for backup and sharing.
- **FR24:** Lorica shall support importing a TOML configuration file to bootstrap or restore state.
- **FR25:** Lorica shall remember user preferences for recurring decisions (e.g., self-signed cert: never/always/once).

**Consent-Driven Design**

- **FR26:** Lorica shall never perform automated actions (certificate provisioning, backend removal, WAF blocking) without explicit admin approval or pre-configured opt-in.
- **FR27:** When no TLS certificate is configured for a route, Lorica shall propose options: manual upload, ACME auto-provisioning, or self-signed certificate - and wait for admin decision.

**Notifications**

- **FR28:** Lorica shall emit structured log events to stdout (JSON format) for all significant events (cert expiry warnings, backend state changes, security events).
- **FR29:** Lorica shall support email notifications for configurable alert types.
- **FR30:** Lorica shall support webhook notifications for configurable alert types.

**WAF (Optional Layer)**

- **FR31:** Lorica shall support an optional WAF mode that can be enabled per route.
- **FR32:** When WAF is disabled, Lorica shall still alert on suspicious patterns in logs (alerting by default).
- **FR33:** WAF rules shall be based on OWASP Core Rule Set (CRS) with regular update support.
- **FR34:** WAF shall operate in detection-only or blocking mode, configurable per route.

**Topology Awareness**

- **FR35:** Lorica shall allow configuring backend topology type per backend group (single VM, HA pair, Docker Swarm, Kubernetes).
- **FR36:** Lorica shall adapt its health check and failover behavior based on the configured topology type.
- **FR37:** Topology rules shall support a two-level hierarchy: global defaults overridden by per-route/per-backend configuration.

**Worker Isolation**

- **FR38:** Lorica shall isolate proxy workers in separate OS processes (fork+exec model).
- **FR39:** If a worker process crashes, other workers shall continue serving traffic.
- **FR40:** Configuration changes shall be propagated to workers via a command channel without restarting worker processes.

**SLA Monitoring**

- **FR41:** Lorica shall compute passive SLA metrics (uptime, latency, error rate) from real user traffic per route.
- **FR42:** Lorica shall send active synthetic probes to backends at configurable intervals to measure internal SLA independently of user traffic.
- **FR43:** The dashboard shall display both passive (public/contractual) and active (internal/engineering) SLA metrics per route with historical trends.
- **FR44:** Lorica shall alert when SLA drops below configurable thresholds (per route, per SLA type).

**Load Testing**

- **FR45:** Lorica shall generate simulated HTTP traffic to backends for load testing (real requests, simulated client).
- **FR46:** Load tests shall be launchable on demand from the dashboard with configurable parameters (concurrent connections, duration, request pattern).
- **FR47:** Load tests shall be schedulable for recurring execution (e.g., weekly) with historical result comparison.
- **FR48:** Load test parameters shall have default safe limits with confirmation required to exceed them.
- **FR49:** Load tests shall auto-abort when backend error rate exceeds a configurable threshold.
- **FR50:** Load test results shall be displayed in real-time in the dashboard during execution, and stored for historical comparison.

## Non-Functional Requirements

- **NFR1:** Proxy latency overhead shall be < 1ms per request under normal load (comparable to Pingora benchmarks).
- **NFR2:** Each worker shall support 10,000+ concurrent connections.
- **NFR3:** Dashboard pages shall load in < 200ms.
- **NFR4:** Base binary size (including embedded dashboard assets) shall be < 50MB.
- **NFR5:** Startup time from service start to accepting traffic shall be < 2 seconds.
- **NFR6:** Lorica shall compile and run on Linux x86_64. No aarch64, macOS, or Windows support.
- **NFR7:** All code shall be written in Rust with strict clippy lints and formatted with rustfmt.
- **NFR8:** The codebase shall be fully auditable: no closed-source dependencies, no C code beyond system libraries.
- **NFR9:** The management port shall bind exclusively to localhost (127.0.0.1 / ::1) by default with no option to change this in the dashboard.
- **NFR10:** Lorica shall produce structured JSON logs to stdout, compatible with SIEM/XDR ingestion.
- **NFR11:** Memory usage shall remain stable over time with no unbounded growth (no memory leaks).
- **NFR12:** Configuration state persistence shall survive unclean shutdowns (crash-safe storage).

## Compatibility Requirements

- **CR1: Pingora API Compatibility** - Lorica shall maintain compatibility with the `ProxyHttp` trait from Pingora for the proxy engine internals. Custom filters and modules written against Pingora's API should remain functional.
- **CR2: TLS Compatibility** - Lorica shall support all TLS configurations that rustls supports (TLS 1.2, TLS 1.3, standard cipher suites, ECDSA and RSA certificates).
- **CR3: HTTP Standards Compliance** - Lorica shall comply with HTTP/1.1 (RFC 9110/9112) and HTTP/2 (RFC 9113) standards as inherited from Pingora's proxy engine.
- **CR4: Export Format Stability** - The TOML export/import format shall be versioned. Lorica shall be able to import configurations from any prior format version.
