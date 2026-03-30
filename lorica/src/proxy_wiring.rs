// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica_api::logs::{LogBuffer, LogEntry};
use lorica_config::models::{Backend, Certificate, HealthStatus, LifecycleState, Route, WafMode};
use lorica_core::protocols::Digest;
use lorica_core::upstreams::peer::HttpPeer;
use lorica_error::{Error, ErrorType, Result};
use lorica_proxy::{ProxyHttp, Session};
use lorica_waf::WafEngine;
use tracing::{info, warn};

/// In-memory snapshot of a route and its backends for fast lookup.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteEntry {
    pub route: Route,
    pub backends: Vec<Backend>,
    pub certificate: Option<Certificate>,
    /// Round-robin counter for this route.
    pub rr_counter: Arc<AtomicUsize>,
}

/// In-memory configuration snapshot used by the proxy.
///
/// This struct is atomically swapped via `ArcSwap` when the API triggers a reload.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Routes indexed by hostname for fast matching.
    /// Each hostname maps to a list of routes sorted by path_prefix length (longest first).
    pub routes_by_host: HashMap<String, Vec<RouteEntry>>,
}

impl ProxyConfig {
    /// Build from config store data.
    pub fn from_store(
        routes: Vec<Route>,
        backends: Vec<Backend>,
        certificates: Vec<Certificate>,
        route_backend_links: Vec<(String, String)>,
    ) -> Self {
        let backend_map: HashMap<String, Backend> =
            backends.into_iter().map(|b| (b.id.clone(), b)).collect();
        let cert_map: HashMap<String, Certificate> = certificates
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();

        // Build route_id -> backend_ids mapping
        let mut route_backends_map: HashMap<String, Vec<String>> = HashMap::new();
        for (route_id, backend_id) in route_backend_links {
            route_backends_map
                .entry(route_id)
                .or_default()
                .push(backend_id);
        }

        let mut routes_by_host: HashMap<String, Vec<RouteEntry>> = HashMap::new();

        for route in routes {
            if !route.enabled {
                continue;
            }

            let route_backends: Vec<Backend> = route_backends_map
                .get(&route.id)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| backend_map.get(id).cloned())
                        .collect()
                })
                .unwrap_or_default();

            let certificate = route
                .certificate_id
                .as_ref()
                .and_then(|cid| cert_map.get(cid).cloned());

            let entry = RouteEntry {
                route: route.clone(),
                backends: route_backends,
                certificate,
                rr_counter: Arc::new(AtomicUsize::new(0)),
            };

            routes_by_host
                .entry(route.hostname.clone())
                .or_default()
                .push(entry);
        }

        // Sort each host's routes by path_prefix length descending (longest prefix match first)
        for entries in routes_by_host.values_mut() {
            entries.sort_by(|a, b| b.route.path_prefix.len().cmp(&a.route.path_prefix.len()));
        }

        ProxyConfig { routes_by_host }
    }
}

/// Per-backend active connection counter.
///
/// Thread-safe counters keyed by backend address. Used to track how many
/// active connections each backend has, enabling graceful drain on removal.
#[derive(Debug, Default)]
pub struct BackendConnections {
    counts: std::sync::RwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl BackendConnections {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the connection count for a backend, returning the counter.
    pub fn increment(&self, addr: &str) -> Arc<AtomicU64> {
        let counts = self.counts.read().unwrap();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(counter);
        }
        drop(counts);

        let mut counts = self.counts.write().unwrap();
        let counter = counts
            .entry(addr.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
        Arc::clone(counter)
    }

    /// Decrement the connection count for a backend.
    pub fn decrement(&self, addr: &str) {
        let counts = self.counts.read().unwrap();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get the current connection count for a backend.
    pub fn get(&self, addr: &str) -> u64 {
        let counts = self.counts.read().unwrap();
        counts
            .get(addr)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Per-request context carried through the proxy pipeline.
pub struct RequestCtx {
    /// When the request started processing.
    pub start_time: Instant,
    /// The selected backend address (for logging).
    pub backend_addr: Option<String>,
    /// The matched route hostname (for logging).
    pub matched_host: Option<String>,
    /// The matched route path prefix (for logging).
    pub matched_path: Option<String>,
    /// Whether WAF blocked this request.
    pub waf_blocked: bool,
}

/// The Lorica ProxyHttp implementation that routes traffic based on database configuration.
pub struct LoricaProxy {
    /// The current in-memory config, atomically swappable.
    pub config: Arc<ArcSwap<ProxyConfig>>,
    /// Shared log buffer for dashboard access log viewing.
    pub log_buffer: Arc<LogBuffer>,
    /// Live counter of active proxy connections (global).
    pub active_connections: Arc<AtomicU64>,
    /// Per-backend connection counters for graceful drain.
    pub backend_connections: Arc<BackendConnections>,
    /// WAF engine for request inspection.
    pub waf_engine: Arc<WafEngine>,
}

impl LoricaProxy {
    pub fn new(
        config: Arc<ArcSwap<ProxyConfig>>,
        log_buffer: Arc<LogBuffer>,
        active_connections: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config,
            log_buffer,
            active_connections,
            backend_connections: Arc::new(BackendConnections::new()),
            waf_engine: Arc::new(WafEngine::new()),
        }
    }

    /// Return a reference to the WAF engine for API access.
    pub fn waf_engine(&self) -> &Arc<WafEngine> {
        &self.waf_engine
    }
}

#[async_trait]
impl ProxyHttp for LoricaProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            start_time: Instant::now(),
            backend_addr: None,
            matched_host: None,
            matched_path: None,
            waf_blocked: false,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let req = session.req_header();

        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h))
            .unwrap_or("");

        let path = req.uri.path();
        let query = req.uri.query();
        let config = self.config.load();

        // Find matching route to check WAF settings
        let route_entry = config.routes_by_host.get(host).and_then(|entries| {
            entries
                .iter()
                .find(|e| path.starts_with(&e.route.path_prefix))
        });

        let entry = match route_entry {
            Some(e) => e,
            None => return Ok(false), // No route = let upstream_peer handle 404
        };

        // Skip WAF evaluation entirely if not enabled (zero overhead)
        if !entry.route.waf_enabled {
            return Ok(false);
        }

        // Collect headers for inspection
        let headers: Vec<(&str, &str)> = req
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let name_str = name.as_str();
                // Only inspect relevant headers (skip large/binary ones)
                match name_str {
                    "user-agent" | "referer" | "cookie" | "x-forwarded-for"
                    | "content-type" | "authorization" | "origin" => {
                        value.to_str().ok().map(|v| (name_str, v))
                    }
                    n if n.starts_with("x-") => {
                        value.to_str().ok().map(|v| (name_str, v))
                    }
                    _ => None,
                }
            })
            .collect();

        let waf_mode = match entry.route.waf_mode {
            WafMode::Detection => lorica_waf::WafMode::Detection,
            WafMode::Blocking => lorica_waf::WafMode::Blocking,
        };

        let verdict = self.waf_engine.evaluate(waf_mode, path, query, &headers, host);

        match verdict {
            lorica_waf::WafVerdict::Blocked(_) => {
                ctx.waf_blocked = true;
                ctx.matched_host = Some(host.to_string());
                ctx.matched_path = Some(path.to_string());

                let header = lorica_http::ResponseHeader::build(403, None)?;
                session.write_response_header(Box::new(header), true).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let req = session.req_header();

        // Extract the Host header
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| {
                // Strip port from host header if present
                h.split(':').next().unwrap_or(h)
            })
            .unwrap_or("");

        let path = req.uri.path();
        let config = self.config.load();

        // Find matching route by hostname then longest path prefix
        let route_entry = config.routes_by_host.get(host).and_then(|entries| {
            entries
                .iter()
                .find(|e| path.starts_with(&e.route.path_prefix))
        });

        let entry = match route_entry {
            Some(e) => e,
            None => {
                return Error::e_explain(
                    ErrorType::HTTPStatus(404),
                    format!("no route configured for host={host} path={path}"),
                );
            }
        };

        ctx.matched_host = Some(entry.route.hostname.clone());
        ctx.matched_path = Some(entry.route.path_prefix.clone());

        // Filter healthy backends
        let healthy_backends: Vec<&Backend> = entry
            .backends
            .iter()
            .filter(|b| {
                b.health_status != HealthStatus::Down && b.lifecycle_state == LifecycleState::Normal
            })
            .collect();

        if healthy_backends.is_empty() {
            return Error::e_explain(
                ErrorType::HTTPStatus(502),
                format!(
                    "no healthy backends for route host={host} path={}",
                    entry.route.path_prefix
                ),
            );
        }

        // Round-robin selection
        let idx = entry.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_backends.len();
        let backend = healthy_backends[idx];

        ctx.backend_addr = Some(backend.address.clone());
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.backend_connections.increment(&backend.address);

        let peer = Box::new(HttpPeer::new(
            &*backend.address,
            backend.tls_upstream,
            if backend.tls_upstream {
                // Use the backend address host as SNI
                backend.address.split(':').next().unwrap_or("").to_string()
            } else {
                String::new()
            },
        ));

        Ok(peer)
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        let elapsed = ctx.start_time.elapsed();
        let downstream = session.as_downstream();
        let req = downstream.req_header();

        let method = req.method.as_str();
        let path = req.uri.path();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let status = session
            .as_downstream()
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let backend_addr = ctx.backend_addr.as_deref().unwrap_or("-");

        let error_str = e.map(|err| err.to_string());
        let latency_ms = elapsed.as_millis() as u64;

        if let Some(ref err) = error_str {
            warn!(
                method = method,
                path = path,
                host = host,
                status = status,
                latency_ms = latency_ms,
                backend = backend_addr,
                error = %err,
                "request completed with error"
            );
        } else {
            info!(
                method = method,
                path = path,
                host = host,
                status = status,
                latency_ms = latency_ms,
                backend = backend_addr,
                "request completed"
            );
        }

        // Only decrement if upstream_peer() actually incremented the counter
        if let Some(ref addr) = ctx.backend_addr {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            self.backend_connections.decrement(addr);
        }

        // Push to the in-memory log buffer for dashboard viewing
        let entry = LogEntry {
            id: 0, // assigned by LogBuffer
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: method.to_string(),
            path: path.to_string(),
            host: host.to_string(),
            status,
            latency_ms,
            backend: backend_addr.to_string(),
            error: error_str,
        };
        self.log_buffer.push(entry).await;
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        _digest: Option<&Digest>,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::*;

    fn make_route(id: &str, hostname: &str, path: &str, enabled: bool) -> Route {
        let now = Utc::now();
        Route {
            id: id.into(),
            hostname: hostname.into(),
            path_prefix: path.into(),
            certificate_id: None,
            load_balancing: LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: WafMode::Detection,
            topology_type: TopologyType::SingleVm,
            enabled,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_backend(id: &str, addr: &str) -> Backend {
        let now = Utc::now();
        Backend {
            id: id.into(),
            address: addr.into(),
            weight: 100,
            health_status: HealthStatus::Healthy,
            health_check_enabled: true,
            health_check_interval_s: 10,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_certificate(id: &str, domain: &str) -> Certificate {
        let now = Utc::now();
        Certificate {
            id: id.into(),
            domain: domain.into(),
            san_domains: vec![],
            fingerprint: "sha256:test".into(),
            cert_pem: "cert".into(),
            key_pem: "key".into(),
            issuer: "test".into(),
            not_before: now,
            not_after: now,
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
        }
    }

    #[test]
    fn test_from_store_empty() {
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![]);
        assert!(config.routes_by_host.is_empty());
    }

    #[test]
    fn test_from_store_single_route_with_backend() {
        let route = make_route("r1", "example.com", "/", true);
        let backend = make_backend("b1", "10.0.0.1:8080");
        let links = vec![("r1".into(), "b1".into())];

        let config = ProxyConfig::from_store(vec![route], vec![backend], vec![], links);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].backends.len(), 1);
        assert_eq!(entries[0].backends[0].address, "10.0.0.1:8080");
    }

    #[test]
    fn test_from_store_disabled_routes_excluded() {
        let r1 = make_route("r1", "example.com", "/", true);
        let r2 = make_route("r2", "disabled.com", "/", false);

        let config = ProxyConfig::from_store(vec![r1, r2], vec![], vec![], vec![]);
        assert!(config.routes_by_host.contains_key("example.com"));
        assert!(!config.routes_by_host.contains_key("disabled.com"));
    }

    #[test]
    fn test_from_store_longest_path_prefix_first() {
        let r1 = make_route("r1", "example.com", "/", true);
        let r2 = make_route("r2", "example.com", "/api", true);
        let r3 = make_route("r3", "example.com", "/api/v1", true);

        let config = ProxyConfig::from_store(vec![r1, r2, r3], vec![], vec![], vec![]);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].route.path_prefix, "/api/v1");
        assert_eq!(entries[1].route.path_prefix, "/api");
        assert_eq!(entries[2].route.path_prefix, "/");
    }

    #[test]
    fn test_from_store_route_without_backends() {
        let route = make_route("r1", "example.com", "/", true);

        let config = ProxyConfig::from_store(vec![route], vec![], vec![], vec![]);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].backends.is_empty());
    }

    #[test]
    fn test_from_store_certificate_association() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.certificate_id = Some("c1".into());
        let cert = make_certificate("c1", "example.com");

        let config = ProxyConfig::from_store(vec![route], vec![], vec![cert], vec![]);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].certificate.is_some());
        assert_eq!(entries[0].certificate.as_ref().unwrap().domain, "example.com");
    }

    #[test]
    fn test_from_store_missing_certificate_is_none() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.certificate_id = Some("nonexistent".into());

        let config = ProxyConfig::from_store(vec![route], vec![], vec![], vec![]);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].certificate.is_none());
    }

    #[test]
    fn test_from_store_multiple_backends_per_route() {
        let route = make_route("r1", "example.com", "/", true);
        let b1 = make_backend("b1", "10.0.0.1:8080");
        let b2 = make_backend("b2", "10.0.0.2:8080");
        let links = vec![
            ("r1".into(), "b1".into()),
            ("r1".into(), "b2".into()),
        ];

        let config = ProxyConfig::from_store(vec![route], vec![b1, b2], vec![], links);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries[0].backends.len(), 2);
    }

    #[test]
    fn test_from_store_multiple_hosts() {
        let r1 = make_route("r1", "foo.com", "/", true);
        let r2 = make_route("r2", "bar.com", "/", true);

        let config = ProxyConfig::from_store(vec![r1, r2], vec![], vec![], vec![]);
        assert_eq!(config.routes_by_host.len(), 2);
        assert!(config.routes_by_host.contains_key("foo.com"));
        assert!(config.routes_by_host.contains_key("bar.com"));
    }

    #[test]
    fn test_from_store_dangling_backend_link_ignored() {
        let route = make_route("r1", "example.com", "/", true);
        let links = vec![("r1".into(), "nonexistent-backend".into())];

        let config = ProxyConfig::from_store(vec![route], vec![], vec![], links);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].backends.is_empty());
    }

    #[test]
    fn test_from_store_rr_counter_starts_at_zero() {
        let route = make_route("r1", "example.com", "/", true);

        let config = ProxyConfig::from_store(vec![route], vec![], vec![], vec![]);
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries[0].rr_counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_proxy_config_default_is_empty() {
        let config = ProxyConfig::default();
        assert!(config.routes_by_host.is_empty());
    }

    // ---- BackendConnections ----

    #[test]
    fn test_backend_connections_increment_decrement() {
        let bc = BackendConnections::new();
        bc.increment("10.0.0.1:8080");
        bc.increment("10.0.0.1:8080");
        assert_eq!(bc.get("10.0.0.1:8080"), 2);

        bc.decrement("10.0.0.1:8080");
        assert_eq!(bc.get("10.0.0.1:8080"), 1);
    }

    #[test]
    fn test_backend_connections_unknown_backend() {
        let bc = BackendConnections::new();
        assert_eq!(bc.get("nonexistent:8080"), 0);
    }

    #[test]
    fn test_backend_connections_multiple_backends() {
        let bc = BackendConnections::new();
        bc.increment("10.0.0.1:8080");
        bc.increment("10.0.0.2:8080");
        bc.increment("10.0.0.2:8080");
        assert_eq!(bc.get("10.0.0.1:8080"), 1);
        assert_eq!(bc.get("10.0.0.2:8080"), 2);
    }
}
