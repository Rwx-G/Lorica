# Intro Project Analysis and Context

## Analysis Source

- Project brief available at: `docs/brief.md`
- Brainstorming results available at: `docs/brainstorming-session-results.md`

## Current Project State

Lorica does not yet exist as code. The "existing project" is **Cloudflare Pingora v0.8.0**, an open-source Rust reverse proxy framework (Apache-2.0) that will be forked as the foundation.

Pingora provides:
- A battle-tested HTTP/1.1, HTTP/2, WebSocket, and gRPC proxy engine
- Connection pooling (lock-free), load balancing (Round Robin, Consistent Hash, Random)
- TLS termination via multiple backends (OpenSSL, BoringSSL, rustls, s2n)
- Graceful restart via FD transfer
- A custom tokio runtime with work-stealing and pinned modes
- 20 Cargo crates in a workspace

Pingora does **not** provide:
- Any configuration format (all logic is Rust code)
- Any REST API or management interface
- Any dashboard or web UI
- Any declarative routing
- Any structured logging or metrics
- Any WAF capability

The enhancement is to transform this framework into a **dashboard-first, self-administered reverse proxy product**.

## Available Documentation Analysis

- [x] Tech Stack Documentation - `docs/architecture/tech-stack.md`
- [x] Source Tree/Architecture - `docs/architecture/source-tree.md`
- [x] Coding Standards - `docs/architecture/coding-standards.md`
- [ ] API Documentation - To be created (new)
- [ ] External API Documentation - N/A
- [ ] UX/UI Guidelines - To be defined
- [ ] Technical Debt Documentation - N/A (fresh fork)

## Enhancement Scope Definition

### Enhancement Type

- [x] New Feature Addition
- [x] Major Feature Modification
- [ ] Integration with New Systems
- [x] Performance/Scalability Improvements
- [ ] UI/UX Overhaul
- [x] Technology Stack Upgrade
- [ ] Bug Fix and Stability Improvements
- [x] Other: Framework-to-product transformation

### Enhancement Description

Transform Pingora from a Rust proxy framework (requiring custom code for every deployment) into Lorica, a complete dashboard-first reverse proxy product. This involves stripping unused TLS backends, adding a declarative configuration layer, building a REST API, embedding a web dashboard, implementing topology-aware backend management, and adding an optional WAF layer.

### Impact Assessment

- [ ] Minimal Impact (isolated additions)
- [ ] Moderate Impact (some existing code changes)
- [ ] Significant Impact (substantial existing code changes)
- [x] Major Impact (architectural changes required)

The core proxy engine remains intact, but the project wraps it in an entirely new product layer (API, dashboard, config, CLI, WAF) and will later replace the concurrency model (threads to process isolation).

## Goals and Background Context

### Goals

- Replace Nginx on production infrastructure with full visibility and control
- Provide a 2-minute onboarding experience: `apt install lorica` -> browser -> configure
- Deliver a single binary with embedded dashboard, zero runtime dependencies
- Enable consent-driven proxy management where nothing happens without admin approval
- Offer optional WAF capabilities based on community rulesets (OWASP CRS)
- Adapt proxy behavior to backend topology (single VM, HA, Docker, K8S)
- Achieve Pingora-level performance (< 1ms added latency, 10K+ concurrent connections per worker)

### Background Context

Current reverse proxies are either opaque config-file daemons (Nginx) or Go-based tools with different trade-offs (Caddy, Traefik). No existing product combines Rust performance, a dashboard-first approach, Apache-2.0 licensing, and integrated WAF capabilities. Pingora proved Rust works at scale for proxying; Sozu proved process isolation and hot-reload work in Rust. Neither is a complete product. Lorica fills this gap by forking Pingora and building the missing product layer on top, with architectural patterns inspired by Sozu.

## Change Log

| Change | Date | Version | Description | Author |
|--------|------|---------|-------------|--------|
| Initial PRD | 2026-03-28 | 1.0 | First draft based on project brief and brainstorming | Romain G. |
