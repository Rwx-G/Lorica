# Introduction

## Existing Project Analysis

### Current Project State

- **Primary Purpose:** Pingora is an HTTP proxy framework - a set of Rust libraries for building custom proxy servers. It is not a standalone product.
- **Current Tech Stack:** Rust 1.84+, tokio 1, h2, httparse, rustls/openssl/boringssl/s2n (multi-backend), serde, clap. 20-crate Cargo workspace.
- **Architecture Style:** Library/framework with trait-based extension points. Users implement the `ProxyHttp` trait to define proxy behavior in Rust code. No declarative configuration.
- **Deployment Method:** Compiled as part of a custom binary by the framework consumer. No standalone deployment.

### Available Documentation

- `docs/brief.md` - Project brief with vision, positioning, and MVP scope
- `docs/prd.md` - Full PRD with 40 FRs, 12 NFRs, 4 epics, 17 stories
- `docs/brainstorming-session-results.md` - Design decisions from brainstorming

### Identified Constraints

- Pingora's rustls backend is marked "experimental" - needs hardening
- Process isolation (fork+exec) is Unix-only - limits Windows support
- Sozu code is AGPL-3.0 - only concepts can be reimplemented, zero code copying
- serde_yaml 0.9 and nix 0.24 are deprecated - must be updated during fork
- Pingora has no config format, no API, no dashboard - entire product layer is new
- Single binary constraint means dashboard frontend must be embeddable (< 5MB assets)

## Change Log

| Change | Date | Version | Description | Author |
|--------|------|---------|-------------|--------|
| Initial architecture | 2026-03-28 | 1.0 | First draft based on PRD and technical analysis | Romain G. |
