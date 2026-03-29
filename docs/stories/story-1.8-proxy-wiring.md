# Story 1.8: Proxy Engine Wiring

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
**Priority:** P0
**Depends on:** Stories 1.3, 1.4

---

As an infrastructure engineer,
I want Lorica to actually proxy HTTP traffic based on my dashboard configuration,
so that the routes I configure in the UI are live and serving traffic.

## Acceptance Criteria

1. `ProxyHttp` trait implementation that reads route configuration from embedded database
2. Host-based and path-based routing from configuration state
3. Backend selection with round-robin load balancing
4. TLS termination using certificates from the embedded store
5. Proxy listeners start/stop dynamically as routes are added/removed
6. Configuration changes take effect without binary restart (API triggers re-read of config state)
7. Health check implementation: TCP health check for backends, status reflected in API and dashboard
8. Access logging: structured JSON log per request (method, path, status, latency, backend)

## Integration Verification

- IV1: HTTP request to a configured route is proxied to the correct backend
- IV2: HTTPS request terminates TLS and proxies to backend
- IV3: Adding a new route via API makes it live without restart
- IV4: Removing a route via API stops proxying for that hostname/path
- IV5: Backend marked unhealthy is removed from rotation

## Tasks

- [x] Implement `ProxyHttp` trait in `lorica/src/proxy_wiring.rs`
- [x] Implement `upstream_peer()` - read config state, select backend
- [x] Implement host-based routing in `upstream_peer()`
- [x] Implement path-prefix matching for route selection
- [x] Implement round-robin backend selection
- [x] Load TLS certificates from ConfigStore into rustls
- [x] Implement dynamic routing (config changes live without restart via arc-swap)
- [x] Implement config reload trigger from API (arc-swap)
- [x] Implement TCP health check background service
- [x] Implement access logging in `logging()` callback
- [x] Write integration tests for routing logic
- [x] Write tests for TLS certificate loading path

## Dev Notes

- The ProxyHttp implementation bridges the product layer (config) to the engine layer (proxy)
- `arc-swap` atomically swaps the in-memory ProxyConfig when API triggers a reload
- Health check runs as a background tokio task, updates backend status in ConfigStore
- Access log fields: method, path, host, status, latency_ms, backend, error (if any)
- Proxy listeners bind to 0.0.0.0 (data plane), management API binds to localhost only
- Dynamic listener management (AC5) is implemented via always-on listeners with dynamic routing:
  the proxy listens on fixed ports (8080 HTTP, 8443 HTTPS) and routes are resolved per-request
  from the arc-swap config. Adding/removing routes via API triggers config reload, making changes
  live without binary restart. True port-level dynamic binding would require changes to lorica-core
  Server framework and is deferred to Phase 2 (story 2.x).
- Longest-prefix-match: routes for the same hostname are sorted by path_prefix length descending
- Down backends (health_status=Down) and closing backends (lifecycle_state!=Normal) are excluded
  from round-robin selection in upstream_peer()

## File List

| File | Change |
|------|--------|
| `lorica/Cargo.toml` | Added lorica-config, lorica-api, lorica-error, arc-swap, async-trait, serde_json deps; enabled lb feature by default |
| `lorica/src/lib.rs` | Export proxy_wiring and reload modules |
| `lorica/src/main.rs` | Wire proxy engine, API server, health checks, TLS listener |
| `lorica/src/proxy_wiring.rs` | New - LoricaProxy ProxyHttp impl, ProxyConfig, RouteEntry |
| `lorica/src/reload.rs` | New - reload_proxy_config() to build ProxyConfig from ConfigStore |
| `lorica/src/health.rs` | New - TCP health check background loop |
| `lorica/tests/proxy_config_test.rs` | New - 7 unit tests for config store route/backend linking |
| `lorica/tests/proxy_routing_test.rs` | New - 6 integration tests for routing logic |

## Change Log

- Implemented LoricaProxy (ProxyHttp trait) with host-based and path-prefix routing
- Added round-robin backend selection with health-aware filtering
- Added arc-swap based config hot-reload (no restart needed)
- Added TCP health check background service
- Added structured JSON access logging via tracing
- Added TLS termination support loading certificates from ConfigStore
- Added 13 tests covering config loading, routing logic, and health filtering

## Dev Agent Record

| Step | Action | Result |
|------|--------|--------|
| 1 | Implement ProxyHttp trait in proxy_wiring.rs | Done - LoricaProxy with upstream_peer, logging, connected_to_upstream |
| 2 | Implement ProxyConfig and arc-swap reload | Done - ProxyConfig::from_store(), reload::reload_proxy_config() |
| 3 | Implement TCP health check loop | Done - health.rs with configurable interval |
| 4 | Wire main.rs with proxy engine, API, health checks | Done - all three services started |
| 5 | Add TLS listener from ConfigStore certificates | Done - writes PEM to data/tls/, adds TLS listener |
| 6 | Write unit and integration tests | Done - 13 tests all passing |
