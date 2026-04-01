# Project Brief: Lorica

**Author:** Romain G.
**Date:** 2026-03-28
**Status:** Draft
**License:** Apache-2.0

---

## Executive Summary

Lorica is a modern, secure, dashboard-first reverse proxy built in Rust. It delivers a complete RP/WAF solution in a single binary with an embedded control plane - REST API and web dashboard - designed for engineers who want full visibility and control over their infrastructure without relying on third-party tools or unauditable code.

The primary problem: current reverse proxies are either opaque configuration-file-driven daemons (Nginx) or Go-based tools with different security trade-offs (Caddy, Traefik). None offers a Rust-native, dashboard-first, auditable product with optional WAF capabilities out of the box.

The target market is infrastructure engineers and sysadmins managing their own reverse proxies who need observability, security, and ease of use without compromising on performance.

The value proposition: **a reverse proxy you understand in 10 minutes and can audit entirely.**

---

## Problem Statement

### Current State and Pain Points

Infrastructure engineers managing reverse proxies today face systemic opacity:

- **Configuration sprawl** - Dozens of hardcoded `.conf` files (Nginx) with no overview or dependency mapping. No way to see at a glance which URLs point to which backends, which snippets are shared, which configurations are active.
- **Certificate blindness** - TLS certificates managed manually with no monitoring of expiration dates. Discovery of expired certs happens when users report errors, not proactively.
- **Zero observability** - No built-in dashboard showing route state, backend health, transfer latency, or security events. The admin must mentally reconstruct system state by reading flat files and parsing logs manually.
- **Security black hole** - No visibility into scan attempts, brute-force patterns, or access attempts on known admin endpoints. Security monitoring requires bolting on separate tools (fail2ban, ModSecurity, ELK stack).
- **Performance opacity** - No insight into per-route latency, backend response times, or resource utilization from the proxy's perspective.

### Why Existing Solutions Fall Short

| Solution | Limitation |
|----------|-----------|
| **Nginx** | Config-file-driven, no built-in dashboard, WAF requires third-party modules, C codebase with historical CVE surface (OpenSSL) |
| **Caddy** | Go-based (GC pauses, higher memory), limited WAF capabilities, Caddyfile is simpler but still file-driven |
| **Traefik** | Go-based, complex configuration model (labels, providers), dashboard is read-only, no WAF |
| **HAProxy** | Powerful but steep learning curve, config-file-driven, C codebase, limited dashboard |
| **Pingora** | Rust framework, not a product - no config format, no API, no dashboard, requires coding |
| **Sozu** | Rust product but CLI-only, no dashboard, AGPL license limits adoption, limited community |

### Why Now

- Pingora (Cloudflare, 2024) proved Rust can replace Nginx in production at scale
- Sozu (Clever Cloud) proved worker isolation and zero-copy are achievable in Rust
- Neither provides a complete, operational, dashboard-first tool out of the box
- The Rust ecosystem for networking (tokio, rustls, hyper, h2) is now mature
- Growing demand for auditable, self-hosted infrastructure tools in the post-cloud era

---

## Proposed Solution

### Core Concept

Lorica is a **network appliance in software form**: a single binary that runs as a service, exposes an admin dashboard on a localhost-only management port, and proxies traffic on separate data ports. The mental model is a managed network switch, not a Unix daemon.

### Approach

Built as a fork of Cloudflare's Pingora (Apache-2.0), augmented with architectural patterns reimplemented from Clever Cloud's Sozu (concepts only - AGPL prevents code reuse):

- **From Pingora:** battle-tested proxy engine (HTTP/1.1, HTTP/2, WebSocket, gRPC), connection pooling, load balancing, graceful restart
- **From Sozu (concepts):** process-based worker isolation, command channel for hot-reload, diff-based config state, certificate hot-swap, backend lifecycle management
- **New (Lorica):** dashboard-first control plane, REST API, topology-aware backend management, optional WAF, consent-driven design

### Key Differentiators

1. **Dashboard-first** - The dashboard is the product, not an add-on. Every feature is designed with its visual representation from the start. No config files needed for normal operation.
2. **Consent-driven** - Lorica never acts without explicit admin approval. It proposes, waits for confirmation, and remembers preferences. No magic, no surprises.
3. **Topology-aware** - Adapts behavior based on backend type (single VM, HA pair, Docker Swarm, Kubernetes). Most proxies treat all backends identically.
4. **Rust + Apache-2.0** - Fully auditable, forkable, no viral license. rustls only - no OpenSSL, reduced attack surface.
5. **Single binary with embedded control plane** - REST API + web dashboard compiled into the binary. Zero runtime dependencies.
6. **Process isolation** - Each worker runs as a separate OS process. If one crashes or is compromised, others continue.

### Why This Will Succeed

- No existing product combines dashboard-first UX with Rust performance and Apache-2.0 licensing
- The fork strategy accelerates time-to-MVP by leveraging Pingora's battle-tested proxy engine
- Solo dev + AI-assisted development enables rapid iteration without organizational overhead
- The "appliance" mental model is proven in networking (Ubiquiti, pfSense) but absent in reverse proxies

---

## Target Users

### Primary User Segment: Infrastructure Engineers / Sysadmins

- **Profile:** Engineers managing their own servers, VMs, or container infrastructure. Comfortable with Linux, networking, and TLS concepts. May be solo or part of a small team.
- **Current workflow:** Managing Nginx/HAProxy via SSH, editing config files, manually tracking certificate expiration, using separate tools for monitoring and security.
- **Pain points:** Opacity of current tools, manual certificate management, no unified dashboard, security monitoring requires separate tooling, no visibility into proxy performance.
- **Goals:** Single pane of glass for reverse proxy management. Confidence that their proxy is secure, performant, and correctly configured. Reduced time spent on routine proxy administration.

### Secondary User Segment: Security-Conscious DevOps Teams

- **Profile:** Teams in organizations requiring auditable infrastructure. May have compliance requirements around TLS, access logging, and intrusion detection.
- **Current workflow:** Nginx + ModSecurity + ELK + Grafana + custom scripts. Multiple tools bolted together.
- **Pain points:** Tool sprawl, configuration drift between environments, audit trail gaps, CVE exposure from OpenSSL/C codebases.
- **Goals:** Consolidated RP/WAF solution that is auditable (Rust, open source, Apache-2.0), with built-in security monitoring and structured logging for SIEM integration.

---

## Goals & Success Metrics

### Project Objectives

- Deliver a production-ready reverse proxy that replaces Nginx for the author's own infrastructure
- Create a tool that any sysadmin can install and configure in under 10 minutes
- Build an open-source project that attracts contributors through quality and clarity
- Maintain a single-binary deployment model throughout all phases

### User Success Metrics

- Time from `apt install` to first route proxied in HTTPS: < 5 minutes
- Time to understand the full state of the proxy: < 30 seconds (one dashboard glance)
- Zero certificate expiration surprises (proactive notifications)
- Reduction in SSH sessions needed for proxy management: aim for zero in daily operations

### Key Performance Indicators (KPIs)

- **Proxy latency overhead:** < 1ms added latency per request (comparable to Pingora benchmarks)
- **Concurrent connections per worker:** 10,000+ (inherited from Pingora/Sozu design)
- **Dashboard response time:** < 200ms for any page load
- **Memory footprint:** < 50MB base for the binary + dashboard
- **Startup time:** < 2 seconds from service start to accepting traffic

---

## MVP Scope

### Core Features (Must Have)

- **Reverse proxy engine:** HTTP/1.1 and HTTP/2 proxying to backends, inherited from Pingora fork
- **TLS termination:** rustls-based, certificate upload via dashboard, SNI support
- **REST API:** Full CRUD for routes, backends, and certificates. The backbone that the dashboard consumes.
- **Web dashboard:** Embedded in binary, served on localhost-only management port (9443). Shows routes, backends, certificate status, basic metrics.
- **Route management:** Add/edit/remove routes via dashboard. Host-based and path-based routing.
- **Backend health:** Basic TCP health checks, backend status visible in dashboard.
- **Structured logging:** JSON stdout output, redirectable to SIEM/XDR.
- **Config export/import:** Export current state as TOML/JSON file. Import to bootstrap a new instance.
- **Onboarding flow:** First launch generates temp admin credentials, displayed once. Dashboard guides first configuration.
- **Graceful restart:** Inherited from Pingora's FD transfer mechanism.
- **Alerting (stdout):** Log suspicious patterns (scan attempts, repeated 4xx on admin endpoints).

### Out of Scope for MVP

- WAF with OWASP CRS rules (Phase 2+)
- Topology-aware backend management (Phase 2+)
- Process-based worker isolation (Phase 2+)
- Email and webhook notifications (Phase 2+)
- ACME / Let's Encrypt integration (Phase 3+)
- Cluster mode / multi-instance aggregation (long-term vision)
- DNS-based service discovery (Phase 3+)
- Rate limiting middleware (Phase 3+)
- HTTP response cache (inherited from Pingora, available from Phase 1)
- Remote access to dashboard (out of scope - use Teleport/SSH/VPN)
- Slack/Telegram/Discord notifications (out of scope - webhook covers these)
- Static file serving / web server features (out of scope - never)

### MVP Success Criteria

The MVP is successful when the author can fully replace Nginx on at least one production server: all routes migrated, TLS working, dashboard providing full visibility, and the system running stable for 30 days without manual intervention beyond the dashboard.

---

## Post-MVP Vision

### Phase 2 Features

- **Process-based worker isolation:** Fork+exec model inspired by Sozu. Each worker is a separate OS process.
- **Hot-reload via command channel:** Unix socket with protobuf framing. Config changes without restart.
- **Certificate hot-swap:** SNI trie with automatic fallback, add/remove certs without downtime.
- **Backend lifecycle:** Normal/Closing/Closed states with graceful connection draining.
- **WAF layer:** Optional, based on OWASP CRS rulesets with regular updates. Alerting by default, blocking when configured.
- **Topology-aware backends:** Adaptive behavior based on backend type (single VM, HA, Docker, K8S).
- **Global rules + user overrides:** Two-level rule hierarchy for backend management.
- **Email and webhook notifications:** Certificate expiration, backend down, security events.

### Phase 3 Features

- **ACME / Let's Encrypt:** Automatic certificate provisioning (opt-in, consent-driven).
- **Security dashboard panel:** Scan detection, blocked requests, pattern trends.
- **Peak EWMA load balancing:** Latency-based distribution for heterogeneous backends.
- **DNS-based service discovery:** Dynamic upstream resolution.
- **Rate limiting middleware:** Built on Pingora's rate limiting primitives.
- **Advanced metrics:** Prometheus endpoint, per-route latency histograms, bandwidth tracking.
- **Dual SLA monitoring:** Passive SLA from real traffic (public/contractual) + active SLA from synthetic probes (internal/engineering). Two numbers, two purposes.
- **Built-in load testing:** Generate simulated traffic from Lorica itself. On-demand and schedulable. Safety guards (default limits, confirmation popup, auto-abort on error threshold). Historical comparison to detect performance degradation over time.

### Long-term Vision

- Multi-instance dashboard aggregation (view multiple Lorica instances from one place)
- Docker Swarm and Kubernetes native integrations (API-driven discovery)
- Auto-scaling triggers via webhook when load thresholds are crossed
- Community-contributed notification plugins
- HTTP response cache dashboard integration (cache stats, purge controls)

### Expansion Opportunities

- Package for major Linux distributions (apt, yum, pacman)
- Docker image for containerized deployments
- Helm chart for Kubernetes-based deployment of Lorica itself
- Commercial support offering for enterprise users

---

## Technical Considerations

### Platform Requirements

- **Primary target:** Linux x86_64 only
- **Development:** Linux (via Docker on other host OSes)
- **No support:** aarch64, macOS, Windows (fork+exec worker model requires Linux)
- **Performance target:** Comparable to Pingora benchmarks (Cloudflare production-proven)

### Technology Preferences

- **Proxy engine:** Rust, forked from Pingora (tokio async runtime, h2, httparse)
- **TLS:** rustls only (no OpenSSL, no BoringSSL, no s2n)
- **Dashboard frontend:** Lightweight framework compiled into binary via `rust-embed` (to be evaluated: Svelte, Solid, or vanilla with htmx)
- **REST API:** Rust (axum or actix-web, to be decided)
- **State persistence:** Embedded storage (SQLite or sled, to be evaluated)
- **Serialization:** protobuf for command channel, JSON for API, TOML for config export/import
- **Logging:** `tracing` + `tracing-subscriber` for structured JSON output

### Architecture Considerations

- **Repository structure:** Cargo workspace with multiple crates (`lorica-core`, `lorica-proxy`, `lorica-tls`, `lorica-api`, etc.)
- **Service architecture:** Single binary, two isolated planes (data plane on proxy ports, control plane on localhost:9443)
- **Integration requirements:** Docker API (future), Kubernetes API (future), ACME protocol (future), OWASP CRS rulesets (future)
- **Security model:**
  - Management port binds to localhost only
  - Consent-driven design - no automated actions without admin approval
  - Process isolation between workers (Phase 2)
  - No secrets in config files (support env var references)
  - Regular dependency auditing (cargo-audit)

---

## Constraints & Assumptions

### Constraints

- **Budget:** None (open-source passion project)
- **Timeline:** No deadline. Quality over speed. Ship when ready.
- **Resources:** Solo developer + Claude (AI-assisted development)
- **Technical:** Fork of Pingora constrains initial architecture. rustls "experimental" status in Pingora requires hardening. Worker isolation via fork() is Unix-only.
- **Legal:** Pingora code is Apache-2.0 (can copy with attribution). Sozu code is AGPL-3.0 (concepts only, zero code copying). Must maintain Cloudflare copyright notices on forked files.

### Key Assumptions

- Pingora's proxy engine is production-quality and suitable as a foundation (validated by Cloudflare's usage at scale)
- rustls can be hardened to production-grade TLS termination within the Pingora codebase
- A lightweight frontend framework can produce a responsive dashboard that compiles to < 5MB of static assets
- SQLite or sled can handle the configuration state persistence needs without adding runtime dependencies
- The OWASP CRS ruleset can be adapted for use in a Rust-based WAF engine
- Solo dev + AI can maintain velocity sufficient to reach MVP within a reasonable timeframe
- The target audience (sysadmins managing their own infra) is large enough to sustain an open-source community

---

## Risks & Open Questions

### Key Risks

- **rustls maturity in Pingora:** The rustls backend is marked "experimental" in Pingora. Hardening it for production TLS termination requires significant testing investment. Mitigation: extensive TLS test suite, fuzz testing, comparison against OpenSSL behavior.
- **Concurrency model migration:** Switching from Pingora's thread-based model to process-based worker isolation (Phase 2) is a deep architectural change. Mitigation: design Phase 1 with isolation in mind, even if not implemented yet.
- **Fork maintenance burden:** Tracking upstream Pingora updates while diverging the codebase creates ongoing maintenance work. Mitigation: progressive independence from upstream, cherry-pick security fixes only.
- **Dashboard scope creep:** A dashboard-first approach risks turning the project into a frontend project. Mitigation: minimal viable dashboard, focus on functionality over aesthetics.
- **WAF rule engine complexity:** Implementing a performant rule engine for OWASP CRS is non-trivial. Mitigation: defer to Phase 2+, evaluate existing Rust WAF crates before building from scratch.

### Open Questions

- What is the optimal persistence layer for config state? (SQLite vs sled vs structured JSON file)
- Which frontend framework best fits the "compile into binary" constraint? (Svelte, Solid, htmx, other)
- How granular should access control be on the dashboard? (single admin vs multi-user RBAC)
- How does Lorica handle upgrades of its own binary while maintaining configuration state?
- Should Lorica support backend TLS (mTLS to upstream) from MVP or defer?
- What is the right packaging strategy for initial distribution? (static binary download, apt repo, both)
- How to handle IPv6-only backends?

### Areas Needing Further Research

- Frontend framework evaluation for embedded dashboard (bundle size, reactivity, build tooling)
- OWASP CRS ruleset format and parsing requirements
- Docker API integration patterns for topology-aware backends
- Kubernetes API integration for pod/service discovery
- ACME protocol implementation options in Rust (existing crates vs custom)
- Competitive analysis of pfSense/OPNsense dashboard UX (appliance model reference)

---

## Appendices

### A. Research Summary

Two upstream projects were analyzed in depth (full analysis in `docs/architecture/introduction.md`):

**Pingora (Cloudflare):**
- 20-crate Rust workspace, Apache-2.0
- Battle-tested proxy engine: HTTP/1.1, HTTP/2, WebSocket, gRPC
- Connection pooling, load balancing (Round Robin, Consistent Hash, Random)
- Custom tokio runtime, graceful restart via FD transfer
- Missing: config format, API, dashboard, CLI, routing DSL, ACME, structured logging

**Sozu (Clever Cloud):**
- 4-crate Rust workspace, AGPL-3.0 (code cannot be copied)
- Process-based worker isolation via fork+exec
- Unix socket command channel with protobuf framing
- Diff-based config state with hot-reload
- Certificate hot-swap with SNI trie
- Backend lifecycle management (Normal/Closing/Closed)
- Zero-copy HTTP parsing (Kawa)

### B. Brainstorming Results

Full brainstorming session results available in `docs/brainstorming-session-results.md`. Key decisions that emerged:

1. Dashboard-first architecture (Phase 1, not Phase 3)
2. Appliance model (no config file as primary operating mode)
3. Consent-driven design philosophy
4. Management port on localhost only
5. Topology-aware backend management
6. RP/WAF only - never a web server
7. Notifications: stdout, email, webhook only
8. Cluster mode deferred (pose hinges, don't build door)
9. Dual SLA monitoring (passive/public + active/internal)
10. Built-in load testing with safety guards and scheduling

### C. References

- [Pingora GitHub](https://github.com/cloudflare/pingora)
- [Sozu GitHub](https://github.com/sozu-proxy/sozu)
- [Sozu architecture blog post](https://www.clever.cloud/blog/engineering/2017/07/24/hot-reloading-configuration-why-and-how/)
- [OWASP Core Rule Set](https://coreruleset.org/)
- [rustls](https://github.com/rustls/rustls)
- Project docs: `docs/prd.md`, `docs/architecture.md`, `docs/brainstorming-session-results.md`

---

## Next Steps

### Immediate Actions

1. Review and validate this project brief
2. Create the PRD (brownfield PRD template) based on this brief
3. Define the architecture document (brownfield architecture template)
4. Evaluate frontend frameworks for embedded dashboard (Svelte vs Solid vs htmx)
5. Evaluate persistence layer (SQLite vs sled)
6. Execute the Pingora fork procedure (clone, strip, rename)

### PM Handoff

This Project Brief provides the full context for Lorica. Please start in 'PRD Generation Mode', review the brief thoroughly to work with the user to create the PRD section by section as the template indicates, asking for any necessary clarification or suggesting improvements.
