# Next Steps

## Story Manager Handoff

This architecture document defines the technical blueprint for Lorica. Key integration requirements:

- **Architecture reference:** `docs/architecture/` (sharded architecture documents)
- **PRD reference:** `docs/prd.md` (requirements and stories)
- **Critical constraint:** Proxy engine (forked crates) must remain functional at all times. Each story adds product layer without breaking proxy.
- **First story:** Story 1.1 (Fork and Strip Pingora) - foundation for everything else
- **Integration checkpoints:** After each story, verify `cargo test` passes across all workspace crates

Story implementation should follow Epic 1 sequentially (1.1 -> 1.2 -> ... -> 1.10). Stories within Epics 2-4 can be parallelized where dependencies allow.

## Developer Handoff

Implementation guide for Lorica development:

- **Architecture:** `docs/architecture/` - component responsibilities, data models, API design
- **Coding standards:** Rust strict clippy, rustfmt, tracing for logging, thiserror for errors, doc comments on public APIs
- **Integration rules:** Product layer wraps engine (new crates depend on forked crates, never reverse). All state through ConfigStore. All operations through API.
- **Compatibility:** ProxyHttp trait, Peer/HttpPeer abstractions must not break. Forked crate tests must pass.
- **Implementation order:**
  1. Fork and strip (Story 1.1) - establish the codebase
  2. Binary and logging (Story 1.2) - bootable binary
  3. Config persistence (Story 1.3) - data layer
  4. REST API (Story 1.4) - control interface
  5. Dashboard skeleton (Story 1.5) - visual interface
  6. Route management UI (Story 1.6) - first user-facing feature
  7. Certificate management (Story 1.7) - TLS management
  8. Proxy wiring (Story 1.8) - connect config to proxy engine
  9. Logs and monitoring (Story 1.9) - observability
  10. Settings and export/import (Story 1.10) - config lifecycle
- **Risk mitigation:** Run `cargo test` after every significant change. Keep forked crate modifications minimal in Epic 1. Document any Pingora internal changes in commit messages.
