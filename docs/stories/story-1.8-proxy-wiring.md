# Story 1.8: Proxy Engine Wiring

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
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

- [ ] Implement `ProxyHttp` trait in `lorica/src/proxy.rs`
- [ ] Implement `upstream_peer()` - read config state, select backend
- [ ] Implement host-based routing in `request_filter()`
- [ ] Implement path-prefix matching for route selection
- [ ] Implement round-robin backend selection via lorica-lb
- [ ] Load TLS certificates from ConfigStore into rustls
- [ ] Implement dynamic listener management (start/stop on route add/remove)
- [ ] Implement config reload trigger from API (arc-swap or watch channel)
- [ ] Implement TCP health check background service
- [ ] Implement access logging in `logging()` callback
- [ ] Write integration tests with real HTTP traffic
- [ ] Write TLS termination tests

## Dev Notes

- The ProxyHttp implementation bridges the product layer (config) to the engine layer (proxy)
- Use `arc-swap` to atomically swap config state when API triggers a reload
- Health check runs as a background tokio task, updates backend status in ConfigStore
- Access log format: `{"timestamp", "method", "path", "host", "status", "latency_ms", "backend", "bytes"}`
- Proxy listeners should bind to 0.0.0.0 (data plane), not localhost (that's management only)
- FR21: Don't bind proxy ports until at least one route exists
