# Brainstorming Session Results - Lorica

**Author:** Romain G.
**Date:** 2026-03-28
**Facilitator:** BMad Master

---

## Executive Summary

- **Topic:** Lorica - full project scope exploration (product vision, architecture, UX, security, features)
- **Techniques used:** What If Scenarios, Reversal, Role Playing, Time Shifting
- **Approach:** Progressive flow (warm-up -> divergent -> convergent -> synthesis)
- **Constraints:** Solo dev + Claude, no budget, no deadline, building the RP the author wants to find on the market
- **Key outcome:** Lorica is redefined as a **dashboard-first appliance**, not a daemon-with-UI

---

## Session Insights

### Insight 1: The Core Pain - Opacity

**Source:** Warm-up phase - current Nginx frustrations

The root problem is not that Nginx doesn't work - it's that it's a black box:
- Dozens of hardcoded .conf files with no overview
- TLS certificates with no visibility on expiration
- No monitoring of route state, performance, or security
- The admin must mentally reconstruct system state by reading flat files

**Implication for Lorica:** Visibility is not a feature, it's the product. Every aspect of the proxy must be observable from the dashboard.

---

### Insight 2: Dashboard-First Architecture

**Source:** What If #1 and #2

**Decision:** The dashboard is not a Phase 3 add-on. It is the primary interface from day one.

This changes the entire architecture:
- The REST API is the backbone - the dashboard consumes it
- Every proxy feature is designed with its visual representation from the start
- TOML config files become import/export, not the operating mode
- The mental model is an **appliance** (like a network router), not a Unix daemon

**Design principles:**
- No config file needed for normal operation
- First launch = empty dashboard, ready to configure
- State persisted in embedded storage
- Config files are for sharing, backup, and migration

---

### Insight 3: Control Plane Isolation

**Source:** What If #7 and follow-up discussion

**Decisions:**
- Dashboard assets compiled into the binary (`rust-embed` / `include_bytes!`)
- Management port (9443) is separate from proxy traffic (443)
- Management port binds to **localhost only** - never exposed on the network
- Remote access is out of scope - use existing tools (Teleport, SSH tunnel, VPN, bastion)
- The control plane remains accessible even if the data plane is under load

**Rationale:** Lorica must not create its own attack surface. Two isolated worlds: data plane (proxy traffic) and control plane (admin dashboard).

---

### Insight 4: Consent-Driven Design

**Source:** TLS certificate discussion

**Philosophy:** Lorica never acts without explicit admin approval.

- Proposes sensible defaults, but waits for confirmation
- TLS options: manual upload or ACME/Let's Encrypt (both available, auto-TLS suggested but not forced)
- If no TLS chosen: proposes self-signed with preference memory (never / always / once)
- Every automated action requires opt-in
- Remembers preferences to avoid repetitive prompts

**This is a design principle, not just a feature.** It applies to:
- Certificate management
- Backend health actions (drain, remove)
- WAF rule activation
- Configuration changes
- Notifications

---

### Insight 5: Topology-Aware Proxy

**Source:** What If #3

**Concept:** Lorica adapts its behavior based on what sits behind it.

| Backend Type | Lorica Behavior |
|---|---|
| Single VM, no alternative | Passive mode - no health checks, no failover |
| VM with HA pair | Active health checks, automatic failover |
| Docker Swarm | Discovery via Docker API, drain on container removal |
| Kubernetes | Integration with K8S API, pod/service awareness |

**Rule hierarchy:**
- **Global rules** - project-wide defaults (sane out of the box)
- **User overrides** - per-route or per-backend customization

This is a differentiator: most reverse proxies treat all backends the same.

---

### Insight 6: Security as a Layer, Not the Core

**Source:** Warm-up + WAF discussion

**Decisions:**
- Alerting is default behavior (log suspicious patterns)
- WAF is optional, activated per configuration
- Rules based on existing community rulesets (OWASP CRS) with regular updates
- Lorica does not reinvent security rules - it integrates proven ones

**Dashboard security panel shows:**
- Scan attempts detected
- Access attempts on known admin endpoints
- Blocked requests (when WAF is active)
- Pattern trends over time

---

### Insight 7: Notification Channels - Keep It Simple

**Source:** What If #4

**Three built-in channels only:**
1. **stdout** - structured logs, redirectable to SIEM/XDR/any collector
2. **email** - direct notifications
3. **webhook** - integration with anything else

**No Slack, Telegram, Discord** - out of scope. Webhook covers these via existing integrations.

**Notification triggers:**
- Certificate expiring (configurable threshold)
- Backend down
- Spike in 4xx/5xx or blocked requests
- Configuration changes via dashboard

---

### Insight 8: Cluster Mode - Not Now, But Don't Close the Door

**Source:** What If #5

**Decision:** Each Lorica instance is autonomous. No cluster mode in MVP or near-term roadmap.

**But:** The architecture (REST API + config export/import) naturally enables future aggregation without redesigning the core.

**Rationale:**
- Distributed consensus adds massive complexity
- Solo dev should not tackle distributed systems on day one
- External orchestration (Ansible, Terraform) can already deploy identical configs to N instances
- "Pose the hinges, don't build the door"

---

### Insight 9: Hard Boundaries - What Lorica Is NOT

**Source:** What If #6 (Reversal)

**Lorica is NOT a web server.** It will never:
- Serve static files for users
- Execute CGI/FastCGI/PHP-FPM
- Host user content
- Act as an application server

**Lorica IS:**
- A reverse proxy
- A WAF (optional layer)
- A control plane for both

The only web content Lorica serves is its own admin dashboard, compiled into the binary.

---

### Insight 10: Onboarding Experience

**Source:** What If #7 (Role Playing)

**The ideal first 2 minutes:**

```
$ apt install lorica
> Lorica installed. Dashboard available at https://localhost:9443
> Temporary credentials: admin / <random-password>

$ # That's it for the CLI
```

1. Open browser -> `https://localhost:9443`
2. Login with temp credentials -> forced password change
3. Dashboard is empty and ready - start adding routes
4. Guided flow: add first route, first backend, first certificate

**Technical implications:**
- Lorica runs as a systemd service immediately after install
- Management port (9443) active by default
- Proxy ports listen on nothing until routes are configured
- One-time password displayed at install, never stored in clear

---

### Insight 11: Built-in SLA Monitoring and Load Testing

**Source:** Post-session follow-up brainstorming

Lorica sits at the single entry point of all traffic - it already sees everything. This makes it the natural place to measure and test backend performance.

**Two types of SLA monitoring:**
- **SLA passif (public/contractual):** Calculated from real user traffic. Uptime, latency, error rate. This is the number you give to clients: "99.95% availability."
- **SLA actif (internal/engineering):** Synthetic probes sent at regular intervals. Detects outages even at 3 AM when no users are active. The real infrastructure quality metric.

**Key insight:** A backend can show 100% SLA publicly simply because nobody called it during a 2-hour outage. The internal SLA would catch this. This distinction is rarely made in existing tools.

**Built-in load testing:**
- Lorica generates traffic itself (single binary, no external tool dependency)
- Real requests to backends, simulated client
- On-demand from dashboard + schedulable (recurring tests for long-term regression detection)
- Critical use case: "My app was fine at launch, but after 6 months of data growth, can it still handle 1000 concurrent connections?"

**Safety - consent-driven:**
- Slider controls with reasonable defaults
- Exceeding normal limits triggers confirmation popup
- Auto-abort when error rate exceeds configurable threshold
- Real-time results visible in dashboard during test execution

---

### Insight 12: The Adoption Pitch

**Source:** Time Shifting to 2028

**Why people adopt Lorica:**

> "Finally a reverse proxy you understand in 10 minutes and can audit entirely."

The triangle:
1. **Ease of use** - dashboard-first, near-zero learning curve
2. **Total transparency** - auditable code, observable state, exportable config
3. **Rust performance + security** - no OpenSSL, no C memory bugs, process isolation

---

## Idea Categorization

### Immediate Opportunities (Core MVP)

1. Dashboard-first architecture with REST API backbone
2. Management port on localhost:9443, isolated from proxy traffic
3. Assets compiled into binary (single binary preserved)
4. Consent-driven design philosophy across all features
5. Onboarding: apt install -> browser -> configure
6. Alerting by default on suspicious patterns (stdout)
7. Config export/import (not config-file-driven operation)

### Future Innovations (Post-MVP)

8. Topology-aware backend management (VM/HA/Docker/K8S)
9. WAF layer with OWASP CRS integration
10. ACME/Let's Encrypt auto-TLS (opt-in)
11. Email and webhook notification channels
12. Backend lifecycle with graceful drain
13. Peak EWMA load balancing
14. Security dashboard panel (scans, blocked requests, trends)
15. SLA monitoring - passive (real traffic) and active (synthetic probes)
16. Built-in load testing with safety guards and scheduling

### Moonshots (Long-term Vision)

17. Multi-instance aggregation dashboard
18. Plugin system for community notification channels
19. Auto-scaling triggers via webhook on load detection

### Dropped / Out of Scope

- Remote access to dashboard (use Teleport/SSH/VPN)
- Slack/Telegram/Discord notifications (webhook covers these)
- Static file serving / web server features
- Cluster mode with distributed state
- Built-in security rules (use OWASP CRS)

---

## Revised Phase Strategy

The brainstorming revealed that the original phasing (proxy first, dashboard last) should be inverted:

| Phase | Original Plan | Revised Plan |
|---|---|---|
| 1 | Fork Pingora, basic proxy + TOML config | Fork Pingora, basic proxy + **REST API + dashboard skeleton** |
| 2 | Sozu patterns (workers, command channel) | Sozu patterns + **dashboard features** (route management, cert management) |
| 3 | REST API + dashboard (add-on) | **Topology awareness** + WAF layer + notifications |
| 4 | ACME, DNS discovery, rate limiting | ACME, auto-scaling hooks, security dashboard |

**Key shift:** The API and dashboard move from Phase 3 to Phase 1. They are the product, not an enhancement.

---

## Action Planning

### Top 3 Priority Ideas

1. **Dashboard-first architecture**
   - Rationale: This is the product identity. Every design decision flows from it.
   - Next steps: Define API schema, choose frontend framework (compiled into binary), design first screens
   - Research needed: `rust-embed` vs `include_bytes!`, lightweight frontend framework suitable for embedding

2. **Consent-driven design philosophy**
   - Rationale: This differentiates Lorica from every other proxy. It's a trust contract with the admin.
   - Next steps: Document the design principle formally, define the consent patterns (never/always/once), apply to all feature designs
   - Research needed: None - this is a design decision

3. **Topology-aware backend management**
   - Rationale: This is the killer differentiator. No other RP does this.
   - Next steps: Define the topology types and their default behaviors, design the rule hierarchy (global + override)
   - Research needed: Docker API, Kubernetes API, health check patterns per topology type

### Resources Needed

- Pingora fork (already planned)
- Frontend framework evaluation for embedded dashboard
- OWASP CRS ruleset format analysis
- Docker/K8S API integration research

---

## Reflection

### What worked well
- What If scenarios opened directions not covered in initial docs
- Role Playing (onboarding experience) produced concrete UX decisions
- Reversal (what Lorica is NOT) clarified scope boundaries

### Areas for further exploration
- Dashboard UI/UX design (wireframes, component library)
- Frontend tech stack for the embedded dashboard
- Detailed API schema design
- ACME integration approach
- WAF rule engine architecture

### Questions for future sessions
- How does Lorica handle upgrades of its own binary while maintaining state?
- What is the persistence layer for config state? (SQLite? sled? JSON?)
- How granular should RBAC be on the dashboard? (single admin vs multi-user)
- Should Lorica support IPv6-only backends?
- How to handle backend TLS (mTLS to upstream)?
