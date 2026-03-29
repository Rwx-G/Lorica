# Enhancement Scope and Integration Strategy

## Enhancement Overview

**Enhancement Type:** Framework-to-product transformation
**Scope:** Strip unused Pingora components, add product layer (config, API, dashboard, WAF, worker isolation), rewire concurrency model
**Integration Impact:** Major - the proxy engine core stays intact, but it gets wrapped in entirely new infrastructure

## Integration Approach

**Code Integration Strategy:** Pingora crates are forked and renamed (`pingora-*` -> `lorica-*`). The proxy engine internals remain largely untouched. New product crates (`lorica-config`, `lorica-api`, `lorica-dashboard`, etc.) wrap the engine and provide the product layer. The `ProxyHttp` trait implementation in the `lorica` binary crate bridges config state to proxy behavior.

**State Persistence Strategy:** New embedded SQLite database (WAL mode) managed by `lorica-config`. Pingora has no persistence - all state is new. No schema migration from an existing system.

**API Integration Strategy:** New REST API (`lorica-api`) served on the management port. Pingora has no API - this is entirely additive. The API is the single interface for all management operations; both the dashboard and CLI consume it.

**UI Integration Strategy:** New embedded dashboard (`lorica-dashboard`). Frontend assets compiled into the binary via `rust-embed`. Served on the management port (localhost:9443) alongside the API. Completely isolated from the proxy data plane.

## Compatibility Requirements

- **Existing API Compatibility:** The `ProxyHttp` trait and core proxy abstractions (Peer, HttpPeer, TransportConnector) must remain functional. Custom filters/modules written against Pingora's API should work with minimal adaptation.
- **Database Schema Compatibility:** N/A - new database, no existing schema.
- **UI/UX Consistency:** N/A - no existing UI.
- **Performance Impact:** Product layer (API, dashboard, config reads) must not add measurable latency to the proxy hot path. Proxy data plane performance must remain at Pingora benchmark levels.
