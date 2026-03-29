// Copyright 2026 Romain G. (Lorica)
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica_config::models::{Backend, Certificate, HealthStatus, LifecycleState, Route};
use lorica_core::protocols::Digest;
use lorica_core::upstreams::peer::HttpPeer;
use lorica_error::{Error, ErrorType, Result};
use lorica_proxy::{ProxyHttp, Session};
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
        let cert_map: HashMap<String, Certificate> =
            certificates.into_iter().map(|c| (c.id.clone(), c)).collect();

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
}

/// The Lorica ProxyHttp implementation that routes traffic based on database configuration.
pub struct LoricaProxy {
    /// The current in-memory config, atomically swappable.
    pub config: Arc<ArcSwap<ProxyConfig>>,
}

impl LoricaProxy {
    pub fn new(config: Arc<ArcSwap<ProxyConfig>>) -> Self {
        Self { config }
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
        let route_entry = config
            .routes_by_host
            .get(host)
            .and_then(|entries| {
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
                b.health_status != HealthStatus::Down
                    && b.lifecycle_state == LifecycleState::Normal
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

        let peer = Box::new(HttpPeer::new(
            &*backend.address,
            backend.tls_upstream,
            if backend.tls_upstream {
                // Use the backend address host as SNI
                backend
                    .address
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string()
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

        if let Some(err) = e {
            warn!(
                method = method,
                path = path,
                host = host,
                status = status,
                latency_ms = elapsed.as_millis() as u64,
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
                latency_ms = elapsed.as_millis() as u64,
                backend = backend_addr,
                "request completed"
            );
        }
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        _digest: Option<&Digest>,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Ok(())
    }
}
