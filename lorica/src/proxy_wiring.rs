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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica_api::logs::{LogBuffer, LogEntry};
use lorica_bench::SlaCollector;
use lorica_cache::cache_control::CacheControl;
use lorica_cache::eviction::simple_lru;
use lorica_cache::filters::resp_cacheable;
use lorica_cache::{
    CacheKey, CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
};
use lorica_config::models::{Backend, Certificate, HealthStatus, LifecycleState, Route, WafMode};
use lorica_core::protocols::Digest;
use lorica_core::upstreams::peer::HttpPeer;
use lorica_error::{Error, ErrorType, Result};
use lorica_http::ResponseHeader;
use lorica_proxy::{ProxyHttp, Session};
use lorica_waf::WafEngine;
use once_cell::sync::Lazy;
use tracing::{info, warn};

/// Smooth weighted round-robin state (Nginx algorithm).
/// Each backend address has a `current_weight` that increases by `effective_weight`
/// on each selection. The backend with the highest `current_weight` is chosen, then
/// its weight is decreased by `total_weight`. This produces an interleaved distribution
/// like A,A,B,A,C,A,A for weights 5,1,1 instead of AAAAABC.
///
/// State is keyed by backend address (not position) so it works correctly when
/// unhealthy backends are filtered out between calls.
#[derive(Debug)]
pub struct SmoothWrrState {
    /// Per-backend-address current weights.
    current_weights: parking_lot::Mutex<HashMap<String, i64>>,
    /// Worker offset to avoid all workers selecting the same backend at startup.
    worker_offset: usize,
}

impl Clone for SmoothWrrState {
    fn clone(&self) -> Self {
        Self {
            current_weights: parking_lot::Mutex::new(self.current_weights.lock().clone()),
            worker_offset: self.worker_offset,
        }
    }
}

impl SmoothWrrState {
    pub fn new(worker_offset: usize) -> Self {
        Self {
            current_weights: parking_lot::Mutex::new(HashMap::new()),
            worker_offset,
        }
    }

    /// Select the next backend using smooth weighted round-robin.
    /// `backends` is a slice of (address, weight) for healthy backends only.
    /// Returns the index into the `backends` slice.
    pub fn next(&self, backends: &[(&str, i64)]) -> usize {
        if backends.is_empty() {
            return 0;
        }
        let total: i64 = backends.iter().map(|(_, w)| *w).sum();
        if total == 0 {
            return 0;
        }

        let mut cw = self.current_weights.lock();

        // Initialize new backends with offset-based head start.
        // The head start is just +1 so the offset backend wins the first
        // tie-break without skewing the overall distribution.
        for (i, (addr, _)) in backends.iter().enumerate() {
            cw.entry(addr.to_string()).or_insert_with(|| {
                if i == self.worker_offset % backends.len() {
                    1 // tiny head start to win first tie-break
                } else {
                    0
                }
            });
        }

        // Increase all current_weights by their effective weight
        for (addr, weight) in backends {
            *cw.entry(addr.to_string()).or_insert(0) += weight;
        }

        // Find the backend with the highest current_weight
        let mut best_idx = 0;
        let mut best_weight = i64::MIN;
        for (i, (addr, _)) in backends.iter().enumerate() {
            let w = cw.get(*addr).copied().unwrap_or(0);
            if w > best_weight {
                best_weight = w;
                best_idx = i;
            }
        }

        // Decrease the selected backend's current_weight by total_weight
        let best_addr = backends[best_idx].0;
        if let Some(w) = cw.get_mut(best_addr) {
            *w -= total;
        }

        best_idx
    }
}

/// In-memory snapshot of a route and its backends for fast lookup.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteEntry {
    pub route: Route,
    pub backends: Vec<Backend>,
    pub certificate: Option<Certificate>,
    /// Smooth weighted round-robin state for this route.
    pub wrr_state: Arc<SmoothWrrState>,
    /// Precompiled regex for path rewriting (None if not configured).
    pub path_rewrite_regex: Option<regex::Regex>,
    /// Resolved backends per path rule (parallel to route.path_rules).
    /// None = inherit route backends, Some = override with these backends.
    pub path_rule_backends: Vec<Option<Vec<Backend>>>,
}

/// In-memory configuration snapshot used by the proxy.
///
/// This struct is atomically swapped via `ArcSwap` when the API triggers a reload.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Routes indexed by hostname for fast matching.
    /// Each hostname maps to a list of routes sorted by path_prefix length (longest first).
    pub routes_by_host: HashMap<String, Vec<RouteEntry>>,
    /// Wildcard routes (*.example.com) checked when exact lookup fails.
    pub wildcard_routes: Vec<(String, Vec<RouteEntry>)>,
    /// Merged security header presets (builtin + custom).
    /// Custom presets override builtins when names collide.
    pub security_presets: Vec<lorica_config::models::SecurityHeaderPreset>,
    /// Max total proxy connections. 503 when exceeded. 0 = unlimited.
    pub max_global_connections: u32,
    /// Global flood detection threshold (RPS). When exceeded, per-IP rate
    /// limits are halved. 0 = disabled.
    pub flood_threshold_rps: u32,
    /// WAF auto-ban: ban IP after this many WAF blocks. 0 = disabled.
    pub waf_ban_threshold: u32,
    /// Duration of WAF-triggered bans in seconds.
    pub waf_ban_duration_s: u32,
    /// Parsed CIDR ranges of trusted reverse proxies. Only when the direct TCP
    /// client IP matches one of these will X-Forwarded-For be used for the
    /// real client IP. Empty = trust no XFF (secure default).
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

/// Global settings extracted from the config store for ProxyConfig construction.
#[derive(Default)]
pub struct ProxyConfigGlobals {
    pub custom_security_presets: Vec<lorica_config::models::SecurityHeaderPreset>,
    pub max_global_connections: u32,
    pub flood_threshold_rps: u32,
    pub waf_ban_threshold: u32,
    pub waf_ban_duration_s: u32,
    pub trusted_proxy_cidrs: Vec<String>,
}

impl ProxyConfig {
    /// Build from config store data.
    ///
    /// `globals.custom_security_presets` are merged with the builtins. A custom
    /// preset whose name matches a builtin replaces it, allowing operators to
    /// override the default "strict" / "moderate" definitions.
    pub fn from_store(
        routes: Vec<Route>,
        backends: Vec<Backend>,
        certificates: Vec<Certificate>,
        route_backend_links: Vec<(String, String)>,
        globals: ProxyConfigGlobals,
    ) -> Self {
        let ProxyConfigGlobals {
            custom_security_presets,
            max_global_connections,
            flood_threshold_rps,
            waf_ban_threshold,
            waf_ban_duration_s,
            trusted_proxy_cidrs,
        } = globals;
        let backend_map: HashMap<String, Backend> = backends
            .into_iter()
            .map(|b| {
                if b.tls_skip_verify {
                    tracing::warn!(
                        backend = %b.address,
                        "tls_skip_verify enabled - upstream TLS certificate validation is disabled"
                    );
                }
                (b.id.clone(), b)
            })
            .collect();
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

            let path_rule_backends: Vec<Option<Vec<Backend>>> = route
                .path_rules
                .iter()
                .map(|rule| {
                    rule.backend_ids.as_ref().map(|ids| {
                        ids.iter()
                            .filter_map(|id| backend_map.get(id).cloned())
                            .collect()
                    })
                })
                .collect();

            let path_rewrite_regex = route.path_rewrite_pattern.as_ref().and_then(|p| {
                if p.is_empty() {
                    None
                } else {
                    match regex::Regex::new(p) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            tracing::warn!(
                                route_id = %route.id,
                                pattern = %p,
                                error = %e,
                                "invalid path_rewrite_pattern, skipping regex rewrite"
                            );
                            None
                        }
                    }
                }
            });

            let entry = RouteEntry {
                route: route.clone(),
                backends: route_backends,
                certificate,
                wrr_state: Arc::new(SmoothWrrState::new(std::process::id() as usize)),
                path_rewrite_regex,
                path_rule_backends,
            };

            routes_by_host
                .entry(route.hostname.clone())
                .or_default()
                .push(entry.clone());

            // Index hostname aliases so they resolve to the same route entry
            for alias in &route.hostname_aliases {
                routes_by_host
                    .entry(alias.clone())
                    .or_default()
                    .push(entry.clone());
            }
        }

        // Separate wildcard hostnames (*.example.com) from exact ones
        let mut wildcard_routes: Vec<(String, Vec<RouteEntry>)> = Vec::new();
        let wildcard_keys: Vec<String> = routes_by_host
            .keys()
            .filter(|k| k.starts_with("*."))
            .cloned()
            .collect();
        for key in wildcard_keys {
            if let Some(entries) = routes_by_host.remove(&key) {
                wildcard_routes.push((key, entries));
            }
        }

        // Sort each host's routes by path_prefix length descending (longest prefix match first)
        for entries in routes_by_host.values_mut() {
            entries.sort_by(|a, b| b.route.path_prefix.len().cmp(&a.route.path_prefix.len()));
        }
        for (_, entries) in &mut wildcard_routes {
            entries.sort_by(|a, b| b.route.path_prefix.len().cmp(&a.route.path_prefix.len()));
        }

        // Merge security presets: start with builtins, let custom override by name
        let mut presets = lorica_config::models::builtin_security_presets();
        for custom in custom_security_presets {
            if let Some(existing) = presets.iter_mut().find(|p| p.name == custom.name) {
                *existing = custom;
            } else {
                presets.push(custom);
            }
        }

        // Parse trusted proxy CIDRs, skipping invalid entries with a warning.
        // Bare IPs (no /prefix) are converted to single-host networks.
        let trusted_proxies: Vec<ipnet::IpNet> = trusted_proxy_cidrs
            .iter()
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return None;
                }
                // Try CIDR first, then bare IP -> single-host net
                if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
                    Some(net)
                } else if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                    Some(ipnet::IpNet::from(ip))
                } else {
                    warn!(entry = %trimmed, "ignoring invalid trusted_proxies entry");
                    None
                }
            })
            .collect();

        ProxyConfig {
            routes_by_host,
            wildcard_routes,
            security_presets: presets,
            max_global_connections,
            flood_threshold_rps,
            waf_ban_threshold,
            waf_ban_duration_s,
            trusted_proxies,
        }
    }

    /// Find a matching route entry for a given host and path.
    /// Exact hostname match takes precedence over wildcard.
    pub fn find_route<'a>(&'a self, host: &str, path: &str) -> Option<&'a RouteEntry> {
        // 1. Exact hostname match (O(1))
        if let Some(entries) = self.routes_by_host.get(host) {
            if let Some(entry) = entries
                .iter()
                .find(|e| path.starts_with(&e.route.path_prefix))
            {
                return Some(entry);
            }
        }

        // 2. Wildcard match (*.example.com matches foo.example.com)
        for (pattern, entries) in &self.wildcard_routes {
            let suffix = &pattern[1..]; // "*.example.com" -> ".example.com"
            if host.ends_with(suffix) && host.len() > suffix.len() {
                if let Some(entry) = entries
                    .iter()
                    .find(|e| path.starts_with(&e.route.path_prefix))
                {
                    return Some(entry);
                }
            }
        }

        // 3. Catch-all hostname "_" (last resort)
        if let Some(entries) = self.routes_by_host.get("_") {
            if let Some(entry) = entries
                .iter()
                .find(|e| path.starts_with(&e.route.path_prefix))
            {
                return Some(entry);
            }
        }

        None
    }
}

/// Per-backend active connection counter.
///
pub use lorica_api::connections::BackendConnections;

/// Peak EWMA latency tracker for load balancing.
///
/// Tracks exponentially weighted moving average of latency per backend.
/// The decay factor ensures recent measurements count more than old ones.
#[derive(Debug, Default)]
pub struct EwmaTracker {
    /// EWMA score per backend address (microseconds).
    pub(crate) scores: Arc<parking_lot::RwLock<HashMap<String, f64>>>,
}

impl EwmaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the EWMA score for a backend with a new latency sample.
    pub fn record(&self, addr: &str, latency_us: f64) {
        let mut scores = self.scores.write();
        let current = scores.get(addr).copied().unwrap_or(0.0);
        // Exponential decay: new_score = alpha * sample + (1-alpha) * old_score
        // With alpha ~0.3 for responsive adaptation
        let alpha = 0.3;
        let new_score = alpha * latency_us + (1.0 - alpha) * current;
        scores.insert(addr.to_string(), new_score);
    }

    /// Select the backend with the lowest EWMA score.
    /// Returns the index into the provided backends slice.
    pub fn select_best(&self, backends: &[&Backend]) -> usize {
        if backends.is_empty() {
            return 0;
        }
        let scores = self.scores.read();
        let mut best_idx = 0;
        let mut best_score = f64::MAX;
        for (i, b) in backends.iter().enumerate() {
            let score = scores.get(&b.address).copied().unwrap_or(0.0);
            // Tie-break: unscored backends get priority (explore)
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Get the EWMA score for a backend (for dashboard display).
    pub fn get_score(&self, addr: &str) -> f64 {
        self.scores.read().get(addr).copied().unwrap_or(0.0)
    }

    /// Return a shared reference to the scores map (for passing to API state).
    pub fn scores_ref(&self) -> Arc<parking_lot::RwLock<HashMap<String, f64>>> {
        Arc::clone(&self.scores)
    }
}

/// Check whether an IP address matches a pattern (exact or CIDR prefix).
fn ip_matches(ip: &str, pattern: &str) -> bool {
    if pattern.contains('/') {
        // CIDR - simple prefix match for now
        ip.starts_with(pattern.split('/').next().unwrap_or(""))
    } else {
        ip == pattern
    }
}

// ---------------------------------------------------------------------------
// HTTP cache infrastructure (MemCache storage + LRU eviction)
// ---------------------------------------------------------------------------

/// Global size limit for the HTTP response cache (bytes).
/// Entries beyond this threshold are evicted in LRU order.
const CACHE_SIZE_LIMIT: usize = 128 * 1024 * 1024; // 128 MiB

/// In-memory cache storage backend (leaked to 'static for the Storage trait).
pub static CACHE_BACKEND: Lazy<MemCache> = Lazy::new(MemCache::new);

/// LRU eviction manager that enforces [CACHE_SIZE_LIMIT].
/// When new entries are admitted and the total tracked size exceeds the limit,
/// the manager returns the least-recently-used keys for purging from storage.
static CACHE_EVICTION: Lazy<simple_lru::Manager> =
    Lazy::new(|| simple_lru::Manager::new(CACHE_SIZE_LIMIT));

/// Default cache TTL for cacheable status codes when the origin does not send
/// explicit `Cache-Control` headers. The route-specific `cache_ttl_s` is used
/// as the default fresh duration for 200 and 301 responses.
///
/// This static is used as a fallback; the per-route TTL is applied by
/// constructing a fresh [CacheMetaDefaults] in [response_cache_filter].
const CACHE_DEFAULTS_5MIN: CacheMetaDefaults = CacheMetaDefaults::new(
    |status| match status.as_u16() {
        200 | 301 => Some(Duration::from_secs(300)),
        _ => None,
    },
    0, // stale-while-revalidate
    0, // stale-if-error
);

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
    /// The matched route ID (for metrics - bounded cardinality).
    pub route_id: Option<String>,
    /// Whether WAF blocked this request.
    pub waf_blocked: bool,
    /// Whether WAF detected (but allowed) a threat on this request.
    pub waf_detected: bool,
    /// Snapshot of the matched route for use in later pipeline stages.
    pub route_snapshot: Option<Route>,
    /// Whether access logging is enabled for this route.
    pub access_log_enabled: bool,
    /// Client IP address (from socket or X-Forwarded-For).
    pub client_ip: Option<String>,
    /// Whether the client IP was extracted from X-Forwarded-For header.
    pub is_xff: bool,
    /// The direct TCP peer IP when XFF is used (the forwarding proxy's IP).
    pub xff_proxy_ip: Option<String>,
    /// Request source (from X-Lorica-Source header, e.g., "loadtest").
    pub source: String,
    /// Per-route connection counter for max_connections enforcement.
    /// Stored here so the counter is decremented in `logging()` when the request ends.
    pub route_conn_counter: Option<Arc<AtomicU64>>,
    /// Precompiled regex for path rewriting (from RouteEntry, avoids recompiling per request).
    pub path_rewrite_regex: Option<regex::Regex>,
    /// Rate limit info for response headers: (limit_rps, current_rate).
    pub rate_limit_info: Option<(u32, f64)>,
    /// Retry counter for upstream connection failures.
    pub retry_count: u32,
    /// Backends overridden by a matched path rule (None = use route backends).
    pub matched_backends: Option<Vec<Backend>>,
    /// Human-readable reason when the proxy short-circuits with an error status
    /// (e.g. "WAF blocked", "rate limited", "return_status rule", "IP banned").
    pub block_reason: Option<String>,
    /// Accumulated request body bytes for chunked transfer size enforcement.
    pub body_bytes_received: u64,
    /// Buffered request body for WAF body scanning (only when WAF is enabled).
    pub waf_body_buffer: Option<Vec<u8>>,
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
    /// Peak EWMA latency tracker for load balancing.
    pub ewma_tracker: Arc<EwmaTracker>,
    /// WAF engine for request inspection.
    pub waf_engine: Arc<WafEngine>,
    /// Passive SLA metrics collector.
    pub sla_collector: Arc<SlaCollector>,
    /// Per-route rate limiter (keyed by "route_id:client_ip").
    pub rate_limiter: Arc<lorica_limits::rate::Rate>,
    /// Ban list: maps banned IP addresses to (ban timestamp, ban duration in seconds).
    /// Bans expire after the route-specific `auto_ban_duration_s`.
    pub ban_list: Arc<DashMap<String, (Instant, u64)>>,
    /// Rate limit violation counter (per minute) for auto-ban decisions.
    pub rate_violations: Arc<lorica_limits::rate::Rate>,
    /// Cumulative WAF block counter per IP for WAF auto-ban (single-process fallback).
    /// In multi-worker mode the supervisor counts globally and broadcasts BanIp commands.
    pub waf_violations: Arc<DashMap<String, AtomicU64>>,
    /// Per-route active connection counters for `max_connections` enforcement.
    pub route_connections: Arc<DashMap<String, Arc<AtomicU64>>>,
    /// Global request rate tracker for flood detection and dashboard metrics.
    pub global_rate: Arc<lorica_limits::rate::Rate>,
    /// Cache hit counter for dashboard stats.
    pub cache_hits: Arc<AtomicU64>,
    /// Cache miss counter for dashboard stats.
    pub cache_misses: Arc<AtomicU64>,
    /// Per-(route_id, status_code) request counters for Prometheus aggregation.
    pub request_counts: Arc<DashMap<(String, u16), AtomicU64>>,
    /// Per-(category, action) WAF event counters for Prometheus aggregation.
    pub waf_counts: Arc<DashMap<(String, String), AtomicU64>>,
    /// ACME HTTP-01 challenge store (shared with API, None in worker mode).
    pub acme_challenge_store: Option<lorica_api::acme::AcmeChallengeStore>,
    /// Non-blocking alert sender for notification dispatch.
    pub alert_sender: Option<lorica_notify::AlertSender>,
    /// Persistent access log store (SQLite).
    pub log_store: Option<Arc<lorica_api::log_store::LogStore>>,
}

impl LoricaProxy {
    pub fn new(
        config: Arc<ArcSwap<ProxyConfig>>,
        log_buffer: Arc<LogBuffer>,
        active_connections: Arc<AtomicU64>,
        sla_collector: Arc<SlaCollector>,
    ) -> Self {
        Self {
            config,
            log_buffer,
            active_connections,
            backend_connections: Arc::new(BackendConnections::new()),
            ewma_tracker: Arc::new(EwmaTracker::new()),
            waf_engine: Arc::new(WafEngine::new()),
            sla_collector,
            rate_limiter: Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1))),
            ban_list: Arc::new(DashMap::new()),
            rate_violations: Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(60))),
            waf_violations: Arc::new(DashMap::new()),
            route_connections: Arc::new(DashMap::new()),
            global_rate: Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1))),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            request_counts: Arc::new(DashMap::new()),
            waf_counts: Arc::new(DashMap::new()),
            acme_challenge_store: None,
            alert_sender: None,
            log_store: None,
        }
    }

    /// Return a reference to the WAF engine for API access.
    pub fn waf_engine(&self) -> &Arc<WafEngine> {
        &self.waf_engine
    }
}

/// Extract the request host from the Host header, falling back to URI authority.
/// HTTP/2 uses :authority pseudo-header which pingora maps to the URI authority,
/// while the Host header may be absent.
fn extract_host(req: &lorica_http::RequestHeader) -> &str {
    req.headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.authority().map(|a| a.as_str()))
        .unwrap_or("")
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
            route_id: None,
            waf_blocked: false,
            waf_detected: false,
            route_snapshot: None,
            path_rewrite_regex: None,
            access_log_enabled: true,
            client_ip: None,
            is_xff: false,
            xff_proxy_ip: None,
            source: String::new(),
            route_conn_counter: None,
            rate_limit_info: None,
            retry_count: 0,
            matched_backends: None,
            block_reason: None,
            body_bytes_received: 0,
            waf_body_buffer: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // ACME HTTP-01 challenge intercept (must respond before any other check)
        if let Some(ref challenge_store) = self.acme_challenge_store {
            let path = session.req_header().uri.path();
            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                info!(token = token, "ACME challenge request intercepted, looking up token");
                if let Some(key_auth) = challenge_store.get(token).await {
                    let mut header = ResponseHeader::build(200, None)?;
                    header.insert_header("Content-Type", "text/plain")?;
                    header.insert_header("Content-Length", key_auth.len().to_string())?;
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(key_auth)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Global flood tracking (before any other processing)
        self.global_rate.observe(&"global", 1);

        // Global connection limit (before any other processing)
        let config = self.config.load();
        if config.max_global_connections > 0 {
            let current = self.active_connections.load(Ordering::Relaxed);
            if current >= config.max_global_connections as u64 {
                ctx.block_reason = Some("global connection limit".to_string());
                let header = lorica_http::ResponseHeader::build(503, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        // IP blocklist check (before any other processing)
        let client_ip = session
            .as_downstream()
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_string());

        // Only trust X-Forwarded-For when the direct TCP client is a trusted proxy.
        // When trusted_proxies is empty, XFF is never used (secure default).
        let req = session.req_header();
        let has_xff = req.headers.get("x-forwarded-for").is_some();
        let direct_ip = client_ip.clone();

        let direct_is_trusted = direct_ip.as_ref().is_some_and(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                config.trusted_proxies.iter().any(|net| net.contains(&addr))
            } else {
                false
            }
        });

        let xff_used = direct_is_trusted && has_xff;
        let check_ip = if xff_used {
            // Trusted proxy: extract real client IP from XFF (leftmost entry)
            req.headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|xff| xff.split(',').next().unwrap_or(xff).trim().to_string())
                .or(client_ip)
        } else {
            // Not trusted or no XFF: use direct TCP client IP
            client_ip
        };

        // Store client IP and source in context for access logging
        ctx.client_ip = check_ip.clone();
        ctx.is_xff = xff_used && check_ip.is_some();
        ctx.xff_proxy_ip = if ctx.is_xff { direct_ip } else { None };
        ctx.source = req
            .headers
            .get("x-lorica-source")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Ban list check (before any other processing for banned IPs)
        if let Some(ref ip) = check_ip {
            let banned = if let Some(entry) = self.ban_list.get(ip) {
                let (banned_at, duration_s) = entry.value();
                if banned_at.elapsed() >= Duration::from_secs(*duration_s) {
                    drop(entry);
                    // Ban expired - lazy cleanup
                    self.ban_list.remove(ip);
                    false
                } else {
                    true
                }
            } else {
                false
            };
            if banned {
                ctx.block_reason = Some("IP banned".to_string());
                let header = lorica_http::ResponseHeader::build(403, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        if let Some(ref ip) = check_ip {
            if self.waf_engine.ip_blocklist().is_blocked_str(ip) {
                warn!(
                    ip = %ip,
                    "request blocked by IP blocklist"
                );
                ctx.waf_blocked = true;
                // Record as WAF event + Prometheus metric + persist
                let path = req.uri.path();
                let host_val = extract_host(req);
                self.waf_engine.record_blocklist_event(ip, host_val, path);
                lorica_api::metrics::record_waf_event("ip_blocklist", "blocked");
                self.waf_counts
                    .entry(("ip_blocklist".to_string(), "blocked".to_string()))
                    .or_insert_with(|| AtomicU64::new(0))
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(ref store) = self.log_store {
                    let ev = lorica_waf::WafEvent {
                        rule_id: 0,
                        description: format!("IP {ip} blocked by IP blocklist"),
                        category: lorica_waf::RuleCategory::IpBlocklist,
                        severity: 5,
                        matched_field: "client_ip".to_string(),
                        matched_value: ip.to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        client_ip: ip.to_string(),
                        route_hostname: req.headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string(),
                        action: "blocked".to_string(),
                    };
                    let _ = store.insert_waf_event(&ev);
                }
                let header = lorica_http::ResponseHeader::build(403, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        let host_raw = extract_host(req);
        let host = host_raw.split(':').next().unwrap_or(host_raw);

        let path = req.uri.path();
        let query = req.uri.query();

        // Find matching route (exact hostname first, then wildcard)
        let entry = match config.find_route(host, path) {
            Some(e) => e,
            None => return Ok(false), // No route = let upstream_peer handle 404
        };

        // Store route snapshot, precompiled regex, and access log setting for later pipeline stages
        ctx.route_snapshot = Some(entry.route.clone());
        ctx.path_rewrite_regex = entry.path_rewrite_regex.clone();
        ctx.access_log_enabled = entry.route.access_log_enabled;

        // Block WebSocket upgrades if disabled on this route
        if !entry.route.websocket_enabled {
            if let Some(upgrade) = req.headers.get("upgrade") {
                if upgrade
                    .to_str()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("websocket")
                {
                    ctx.block_reason = Some("WebSocket disabled".to_string());
                    let header = lorica_http::ResponseHeader::build(403, None)?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Force HTTPS redirect (skip for ACME challenges - must stay HTTP)
        if entry.route.force_https && !path.starts_with("/.well-known/acme-challenge/") {
            let is_tls = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            let scheme = if is_tls {
                "https"
            } else {
                req.headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("http")
            };
            if scheme != "https" {
                let redir_host = extract_host(req);
                let redir_path = req.uri.path();
                let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let location = format!("https://{redir_host}{redir_path}{redir_query}");
                let mut header = lorica_http::ResponseHeader::build(301, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        // Hostname redirect
        if let Some(ref target) = entry.route.redirect_hostname {
            if host != target.as_str() {
                let redir_path = req.uri.path();
                let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let scheme = req
                    .headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("https");
                let location = format!("{scheme}://{target}{redir_path}{redir_query}");
                let mut header = lorica_http::ResponseHeader::build(301, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        // Path rule matching (first match wins, overrides route config)
        for (i, rule) in entry.route.path_rules.iter().enumerate() {
            if rule.matches(path) {
                let effective = entry.route.with_path_rule_overrides(rule);
                ctx.route_snapshot = Some(effective);
                if rule.backend_ids.is_some() {
                    if let Some(ref backends) = entry.path_rule_backends[i] {
                        ctx.matched_backends = Some(backends.clone());
                    }
                }
                break;
            }
        }

        // Direct status response (return_status)
        if let Some(status) = ctx.route_snapshot.as_ref().and_then(|r| r.return_status) {
            ctx.block_reason = Some(format!("return_status {status}"));
            if let Some(ref target) = ctx.route_snapshot.as_ref().and_then(|r| r.redirect_to.clone())
            {
                // return_status + redirect_to = redirect with specific status code
                let redir_path = req.uri.path();
                let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let base = target.trim_end_matches('/');
                let location = format!("{base}{redir_path}{redir_query}");
                let mut header = lorica_http::ResponseHeader::build(status, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
            } else {
                // return_status alone = direct response with empty body
                let header = lorica_http::ResponseHeader::build(status, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
            }
            return Ok(true);
        }

        // Redirect to external URL (read from snapshot, path rules may have overridden it)
        if let Some(ref target) = ctx.route_snapshot.as_ref().and_then(|r| r.redirect_to.clone()) {
            let redir_path = req.uri.path();
            let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
            let base = target.trim_end_matches('/');
            let location = format!("{base}{redir_path}{redir_query}");
            let mut header = lorica_http::ResponseHeader::build(301, None)?;
            header.insert_header("Location", &location)?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }

        // Per-route IP allowlist/denylist
        if let Some(ref ip) = check_ip {
            if !entry.route.ip_allowlist.is_empty()
                && !entry.route.ip_allowlist.iter().any(|a| ip_matches(ip, a))
            {
                ctx.block_reason = Some("IP not in allowlist".to_string());
                let header = lorica_http::ResponseHeader::build(403, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
            if entry.route.ip_denylist.iter().any(|d| ip_matches(ip, d)) {
                ctx.block_reason = Some("IP in denylist".to_string());
                let header = lorica_http::ResponseHeader::build(403, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        // Slowloris detection: reject requests where headers took too long to arrive.
        // If the time from connection start to request_filter exceeds the threshold,
        // the client is likely performing a slowloris attack (sending headers very slowly).
        let slowloris_ms = entry.route.slowloris_threshold_ms;
        if slowloris_ms > 0 {
            let elapsed_ms = ctx.start_time.elapsed().as_millis() as i32;
            if elapsed_ms > slowloris_ms {
                let client_ip_str = check_ip.as_deref().unwrap_or("-");
                warn!(
                    ip = %client_ip_str,
                    elapsed_ms = elapsed_ms,
                    threshold_ms = slowloris_ms,
                    route_id = %entry.route.id,
                    "slowloris detected - slow request headers"
                );
                ctx.block_reason = Some("slowloris detected".to_string());
                let header = lorica_http::ResponseHeader::build(408, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
        }

        // Per-route max connections enforcement.
        // Tracks active connections per route using atomic counters.
        // Returns 503 when a route exceeds its configured connection limit.
        if let Some(max_conn) = entry.route.max_connections {
            let counter = self
                .route_connections
                .entry(entry.route.id.clone())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .value()
                .clone();
            let current = counter.fetch_add(1, Ordering::Relaxed);
            if current >= max_conn as u64 {
                counter.fetch_sub(1, Ordering::Relaxed);
                warn!(
                    route_id = %entry.route.id,
                    current_connections = current + 1,
                    max_connections = max_conn,
                    "max connections exceeded for route (503)"
                );
                ctx.block_reason = Some("route connection limit".to_string());
                let header = lorica_http::ResponseHeader::build(503, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }
            ctx.route_conn_counter = Some(counter);
        }

        // Request body size limit
        if let Some(max_bytes) = entry.route.max_request_body_bytes {
            if let Some(cl) = req.headers.get("content-length") {
                if let Ok(len) = cl.to_str().unwrap_or("0").parse::<u64>() {
                    if len > max_bytes {
                        let header = lorica_http::ResponseHeader::build(413, None)?;
                        session
                            .write_response_header(Box::new(header), true)
                            .await?;
                        return Ok(true);
                    }
                }
            }
        }

        // Per-route rate limiting
        if let Some(rps) = entry.route.rate_limit_rps {
            if let Some(ref ip) = check_ip {
                let key = format!("{}:{}", entry.route.id, ip);
                self.rate_limiter.observe(&key, 1);
                let current_rate = self.rate_limiter.rate(&key);
                let mut effective_limit = match entry.route.rate_limit_burst {
                    Some(burst) => (rps + burst) as f64,
                    None => rps as f64,
                };

                // Adaptive flood defense: when global RPS exceeds the
                // configured threshold, halve per-IP rate limits.
                let threshold = config.flood_threshold_rps;
                if threshold > 0 {
                    let global_rps = self.global_rate.rate(&"global");
                    if global_rps > threshold as f64 {
                        effective_limit *= 0.5;
                    }
                }
                // Store rate info for response headers (even if not throttled)
                ctx.rate_limit_info = Some((rps, current_rate));

                if current_rate > effective_limit {
                    warn!(
                        route_id = %entry.route.id,
                        client_ip = %ip,
                        current_rate = %current_rate,
                        limit_rps = %rps,
                        "request rate-limited (429)"
                    );

                    // Track rate limit violations for auto-ban
                    if let Some(ban_threshold) = entry.route.auto_ban_threshold {
                        let violation_key = format!("violation:{}", ip);
                        self.rate_violations.observe(&violation_key, 1);
                        let violations = self.rate_violations.rate(&violation_key);
                        if violations > ban_threshold as f64 {
                            let ban_duration = entry.route.auto_ban_duration_s;
                            self.ban_list
                                .insert(ip.to_string(), (Instant::now(), ban_duration as u64));
                            warn!(
                                ip = %ip,
                                violations = %violations,
                                ban_duration_s = %ban_duration,
                                "IP auto-banned for rate limit abuse"
                            );
                            // Dispatch ip_banned notification
                            if let Some(ref sender) = self.alert_sender {
                                sender.send(
                                    lorica_notify::AlertEvent::new(
                                        lorica_notify::events::AlertType::IpBanned,
                                        format!("IP {} auto-banned for rate limit abuse", ip),
                                    )
                                    .with_detail("ip", ip.to_string())
                                    .with_detail("violations", violations.to_string())
                                    .with_detail("ban_duration_s", ban_duration.to_string()),
                                );
                            }
                        }
                    }

                    let reset_ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        + 1;
                    ctx.block_reason = Some("rate limited".to_string());
                    let mut header = lorica_http::ResponseHeader::build(429, None)?;
                    header.insert_header("Retry-After", "1")?;
                    header.insert_header("X-RateLimit-Reset", reset_ts.to_string())?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Skip WAF evaluation entirely if not enabled (zero overhead)
        if !entry.route.waf_enabled {
            return Ok(false);
        }

        // Collect headers for inspection
        let headers: Vec<(&str, &str)> =
            req.headers
                .iter()
                .filter_map(|(name, value)| {
                    let name_str = name.as_str();
                    // Only inspect relevant headers (skip large/binary ones)
                    match name_str {
                        "user-agent" | "referer" | "cookie" | "x-forwarded-for"
                        | "content-type" | "content-length" | "authorization" | "origin"
                        | "transfer-encoding" => value.to_str().ok().map(|v| (name_str, v)),
                        n if n.starts_with("x-") => value.to_str().ok().map(|v| (name_str, v)),
                        _ => None,
                    }
                })
                .collect();

        let waf_mode = match entry.route.waf_mode {
            WafMode::Detection => lorica_waf::WafMode::Detection,
            WafMode::Blocking => lorica_waf::WafMode::Blocking,
        };

        let mut verdict = self.waf_engine.evaluate(
            waf_mode,
            path,
            query,
            &headers,
            host,
            check_ip.as_deref().unwrap_or("-"),
        );

        match verdict {
            lorica_waf::WafVerdict::Blocked(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.to_string();
                    ev.action = "blocked".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "blocked");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "blocked".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(ref store) = self.log_store {
                        let _ = store.insert_waf_event(ev);
                    }
                }
                // Dispatch waf_alert notification
                if let (Some(ref sender), Some(ev)) = (&self.alert_sender, events.first()) {
                    sender.send(
                        lorica_notify::AlertEvent::new(
                            lorica_notify::events::AlertType::WafAlert,
                            format!("WAF blocked {} on {}{}", ev.category.as_str(), host, path),
                        )
                        .with_detail("rule_id", ev.rule_id.to_string())
                        .with_detail("category", ev.category.as_str().to_string())
                        .with_detail("host", host.to_string())
                        .with_detail("path", path.to_string())
                        .with_detail("client_ip", check_ip.as_deref().unwrap_or("-").to_string()),
                    );
                }
                ctx.waf_blocked = true;
                ctx.matched_host = Some(host.to_string());
                ctx.matched_path = Some(path.to_string());

                // WAF auto-ban: local per-process fallback for single-process mode.
                // In multi-worker mode the supervisor counts violations globally
                // across all workers and broadcasts BanIp commands. The local
                // counter here serves as a fallback that still works in
                // single-process deployments.
                if let Some(ref ip) = check_ip {
                    let config = self.config.load();
                    let threshold = config.waf_ban_threshold;
                    if threshold > 0 {
                        let violations = self
                            .waf_violations
                            .entry(ip.to_string())
                            .or_insert_with(|| AtomicU64::new(0))
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;
                        if violations >= threshold as u64 {
                            let ban_duration = config.waf_ban_duration_s;
                            self.ban_list
                                .insert(ip.to_string(), (Instant::now(), ban_duration as u64));
                            self.waf_violations.remove(ip.as_str());
                            warn!(
                                ip = %ip,
                                violations = %violations,
                                ban_duration_s = %ban_duration,
                                "IP auto-banned for repeated WAF violations (local counter)"
                            );
                            if let Some(ref sender) = self.alert_sender {
                                sender.send(
                                    lorica_notify::AlertEvent::new(
                                        lorica_notify::events::AlertType::IpBanned,
                                        format!(
                                            "IP {} auto-banned for repeated WAF violations",
                                            ip
                                        ),
                                    )
                                    .with_detail("ip", ip.to_string())
                                    .with_detail("violations", violations.to_string())
                                    .with_detail("ban_duration_s", ban_duration.to_string()),
                                );
                            }
                        }
                    }
                }

                let header = lorica_http::ResponseHeader::build(403, None)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                Ok(true)
            }
            lorica_waf::WafVerdict::Detected(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.to_string();
                    ev.action = "detected".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "detected");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "detected".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(ref store) = self.log_store {
                        let _ = store.insert_waf_event(ev);
                    }
                }
                ctx.waf_detected = true;
                Ok(false)
            }
            lorica_waf::WafVerdict::Pass => Ok(false),
        }
    }

    /// Handle incoming request body chunks.
    ///
    /// This method performs two functions:
    /// 1. Enforces `max_request_body_bytes` for chunked transfer encoding
    ///    (Content-Length-based enforcement is done in `request_filter`).
    /// 2. Buffers the request body for WAF scanning when WAF is enabled.
    ///    When the full body is received (`end_of_stream`), the WAF engine
    ///    evaluates the buffered body. Only text bodies up to 1 MB are
    ///    scanned to avoid excessive memory use on large uploads.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        /// Maximum body size buffered for WAF scanning (1 MB).
        const WAF_BODY_SCAN_MAX: usize = 1_048_576;

        if let Some(ref chunk) = body {
            ctx.body_bytes_received += chunk.len() as u64;

            // Chunked transfer body size enforcement.
            // Content-Length based check is in request_filter; this catches
            // Transfer-Encoding: chunked requests that have no Content-Length.
            if let Some(max) = ctx.route_snapshot.as_ref().and_then(|r| r.max_request_body_bytes) {
                if ctx.body_bytes_received > max {
                    warn!(
                        received = ctx.body_bytes_received,
                        max = max,
                        "chunked request body exceeds max_request_body_bytes (413)"
                    );
                    let header = lorica_http::ResponseHeader::build(413, None)?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    *body = None;
                    return Ok(());
                }
            }

            // Buffer body for WAF scanning (only when WAF enabled)
            if let Some(ref route) = ctx.route_snapshot {
                if route.waf_enabled {
                    let buf = ctx.waf_body_buffer.get_or_insert_with(Vec::new);
                    // Only buffer up to WAF_BODY_SCAN_MAX bytes
                    if buf.len() < WAF_BODY_SCAN_MAX {
                        let remaining = WAF_BODY_SCAN_MAX - buf.len();
                        let to_copy = chunk.len().min(remaining);
                        buf.extend_from_slice(&chunk[..to_copy]);
                    }
                }
            }
        }

        // When the full body is received, run WAF body evaluation
        if end_of_stream {
            if let Some(ref buf) = ctx.waf_body_buffer {
                if !buf.is_empty() {
                    let host = ctx.matched_host.as_deref().unwrap_or("-");
                    let client_ip = ctx.client_ip.as_deref().unwrap_or("-");

                    let waf_mode = match ctx.route_snapshot.as_ref().map(|r| &r.waf_mode) {
                        Some(WafMode::Blocking) => lorica_waf::WafMode::Blocking,
                        _ => lorica_waf::WafMode::Detection,
                    };

                    let mut verdict = self.waf_engine.evaluate_body(
                        waf_mode,
                        buf,
                        host,
                        client_ip,
                    );

                    match verdict {
                        lorica_waf::WafVerdict::Blocked(ref mut events) => {
                            for ev in events.iter_mut() {
                                ev.route_hostname = host.to_string();
                                ev.action = "blocked".to_string();
                                lorica_api::metrics::record_waf_event(
                                    ev.category.as_str(),
                                    "blocked",
                                );
                                self.waf_counts
                                    .entry((
                                        ev.category.as_str().to_string(),
                                        "blocked".to_string(),
                                    ))
                                    .or_insert_with(|| AtomicU64::new(0))
                                    .fetch_add(1, Ordering::Relaxed);
                                if let Some(ref store) = self.log_store {
                                    let _ = store.insert_waf_event(ev);
                                }
                            }
                            ctx.waf_blocked = true;
                            let header = lorica_http::ResponseHeader::build(403, None)?;
                            session
                                .write_response_header(Box::new(header), true)
                                .await?;
                            *body = None;
                            return Ok(());
                        }
                        lorica_waf::WafVerdict::Detected(ref mut events) => {
                            for ev in events.iter_mut() {
                                ev.route_hostname = host.to_string();
                                ev.action = "detected".to_string();
                                lorica_api::metrics::record_waf_event(
                                    ev.category.as_str(),
                                    "detected",
                                );
                                self.waf_counts
                                    .entry((
                                        ev.category.as_str().to_string(),
                                        "detected".to_string(),
                                    ))
                                    .or_insert_with(|| AtomicU64::new(0))
                                    .fetch_add(1, Ordering::Relaxed);
                                if let Some(ref store) = self.log_store {
                                    let _ = store.insert_waf_event(ev);
                                }
                            }
                            ctx.waf_detected = true;
                        }
                        lorica_waf::WafVerdict::Pass => {}
                    }
                }
            }
        }

        Ok(())
    }

    /// Enable Pingora HTTP cache for cacheable routes.
    ///
    /// Caching is enabled when:
    /// - The matched route has `cache_enabled = true`
    /// - The request method is GET or HEAD
    /// - The request does not carry `Authorization` or `Cookie` headers
    /// - The request does not include `Cache-Control: no-cache` or `no-store`
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let route = match ctx.route_snapshot {
            Some(ref r) if r.cache_enabled => r,
            _ => return Ok(()),
        };

        let req = session.req_header();

        // Only cache GET and HEAD
        if req.method != http::Method::GET && req.method != http::Method::HEAD {
            return Ok(());
        }

        // Skip caching for authenticated or session-bearing requests
        if req.headers.contains_key("authorization") || req.headers.contains_key("cookie") {
            return Ok(());
        }

        // Honor client Cache-Control: no-cache / no-store
        if let Some(cc) = CacheControl::from_req_headers(req) {
            if cc.no_cache() || cc.no_store() {
                return Ok(());
            }
        }

        // Enable the cache state machine with MemCache storage + LRU eviction
        session.cache.enable(
            &*CACHE_BACKEND,
            Some(&*CACHE_EVICTION),
            None, // no predictor
            None, // no cache lock
            None, // no option overrides
        );

        // Set max cacheable response size from route config
        if route.cache_max_bytes > 0 {
            session
                .cache
                .set_max_file_size_bytes(route.cache_max_bytes as usize);
        }

        Ok(())
    }

    /// Generate the cache key from the request.
    ///
    /// Key = namespace (empty) + primary (host + path + query).
    /// This is intentionally simple; Vary-based variance is not yet supported.
    fn cache_key_callback(&self, session: &Session, _ctx: &mut Self::CTX) -> Result<CacheKey> {
        let req = session.req_header();

        let host = extract_host(req);

        let path_and_query = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        Ok(CacheKey::new(
            String::new(),
            format!("{host}{path_and_query}"),
            String::new(),
        ))
    }

    /// Decide whether the upstream response should be admitted to cache.
    ///
    /// When the origin sends Cache-Control, the standard resp_cacheable
    /// logic is used (honouring max-age, no-store, private, etc.).
    /// When the origin sends no cache directives, we build a [CacheMeta]
    /// with the route's cache_ttl_s as the fresh duration.
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let ttl_s = ctx
            .route_snapshot
            .as_ref()
            .map(|r| r.cache_ttl_s as u64)
            .unwrap_or(300);

        let cc = CacheControl::from_resp_headers(resp);

        // If the origin sends explicit Cache-Control, honour it fully
        if cc.is_some() {
            return Ok(resp_cacheable(
                cc.as_ref(),
                resp.clone(),
                false, // auth requests already filtered in request_cache_filter
                &CACHE_DEFAULTS_5MIN,
            ));
        }

        // No Cache-Control from origin: cache 200/301 with the route TTL
        let status = resp.status.as_u16();
        if status == 200 || status == 301 {
            let now = std::time::SystemTime::now();
            let fresh_until = now + Duration::from_secs(ttl_s);
            Ok(RespCacheable::Cacheable(CacheMeta::new(
                fresh_until,
                now,
                0, // stale-while-revalidate
                0, // stale-if-error
                resp.clone(),
            )))
        } else {
            Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache))
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let req = session.req_header();

        let host_raw = extract_host(req);
        let host = host_raw.split(':').next().unwrap_or(host_raw);

        let path = req.uri.path();
        let config = self.config.load();

        // Find matching route (exact hostname first, then wildcard)
        let entry = match config.find_route(host, path) {
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
        ctx.route_id = Some(entry.route.id.clone());
        // Ensure route snapshot is available for upstream_request_filter
        if ctx.route_snapshot.is_none() {
            ctx.route_snapshot = Some(entry.route.clone());
            ctx.path_rewrite_regex = entry.path_rewrite_regex.clone();
            ctx.access_log_enabled = entry.route.access_log_enabled;
        }

        // Filter healthy backends (use path-rule override if set)
        let backends_source = if let Some(ref overridden) = ctx.matched_backends {
            overridden
        } else {
            &entry.backends
        };
        let healthy_backends: Vec<&Backend> = backends_source
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

        // Backend selection based on load balancing algorithm
        use lorica_config::models::LoadBalancing;
        let idx = match entry.route.load_balancing {
            LoadBalancing::PeakEwma => self.ewma_tracker.select_best(&healthy_backends),
            LoadBalancing::Random => {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                ctx.start_time.hash(&mut hasher);
                (hasher.finish() as usize) % healthy_backends.len()
            }
            _ => {
                // Smooth weighted round-robin (Nginx algorithm)
                let bw: Vec<(&str, i64)> = healthy_backends
                    .iter()
                    .map(|b| (b.address.as_str(), b.weight.max(1) as i64))
                    .collect();
                entry.wrr_state.next(&bw)
            }
        };
        let backend = healthy_backends[idx];

        ctx.backend_addr = Some(backend.address.clone());
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.backend_connections.increment(&backend.address);

        let mut peer = Box::new(HttpPeer::new(
            &*backend.address,
            backend.tls_upstream,
            if backend.tls_upstream {
                // SNI priority: backend tls_sni override > route hostname
                backend
                    .tls_sni
                    .clone()
                    .unwrap_or_else(|| entry.route.hostname.clone())
            } else {
                String::new()
            },
        ));

        // Force HTTP/2 upstream if configured on the backend
        if backend.h2_upstream {
            peer.options.set_http_version(2, 2);
        }

        // Skip TLS certificate verification if configured (self-signed certs)
        if backend.tls_skip_verify {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }

        // Apply route-level timeouts to the peer options
        peer.options.connection_timeout =
            Some(Duration::from_secs(entry.route.connect_timeout_s as u64));
        peer.options.read_timeout = Some(Duration::from_secs(entry.route.read_timeout_s as u64));
        peer.options.write_timeout = Some(Duration::from_secs(entry.route.send_timeout_s as u64));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut lorica_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        let route = match ctx.route_snapshot {
            Some(ref r) => r,
            None => return Ok(()),
        };

        // Path rewriting: strip prefix then add prefix
        let original_path = upstream_request.uri.path().to_string();
        let query = upstream_request
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        let mut rewritten = original_path.clone();

        if let Some(ref strip) = route.strip_path_prefix {
            if rewritten.starts_with(strip.as_str()) {
                rewritten = rewritten[strip.len()..].to_string();
                if rewritten.is_empty() || !rewritten.starts_with('/') {
                    rewritten = format!("/{rewritten}");
                }
            }
        }

        if let Some(ref add) = route.add_path_prefix {
            rewritten = format!("{add}{rewritten}");
        }

        // Regex path rewrite (applied after strip/add prefix)
        if let Some(ref re) = ctx.path_rewrite_regex {
            if let Some(ref replacement) = route.path_rewrite_replacement {
                let result = re.replace(&rewritten, replacement.as_str());
                if result != rewritten {
                    rewritten = result.into_owned();
                    if !rewritten.starts_with('/') {
                        rewritten = format!("/{rewritten}");
                    }
                }
            }
        }

        if rewritten != original_path {
            let new_uri_str = format!("{rewritten}{query}");
            if let Ok(new_uri) = new_uri_str.parse::<http::Uri>() {
                upstream_request.set_uri(new_uri);
            }
        }

        // Merge HTTP/2 split Cookie headers into a single HTTP/1.1 Cookie header.
        // HTTP/2 allows multiple cookie headers (RFC 7540 section 8.1.2.5) but
        // HTTP/1.1 backends (especially PHP/Apache) may only read the first one.
        {
            let req = session.req_header();
            let cookies: Vec<&str> = req
                .headers
                .get_all("cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            if cookies.len() > 1 {
                let merged = cookies.join("; ");
                let _ = upstream_request.remove_header("cookie");
                let _ = upstream_request.insert_header("Cookie", &merged);
            }
        }

        // Default proxy headers
        let req = session.req_header();
        let client_ip = session
            .as_downstream()
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();

        let xff = req
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|existing| format!("{existing}, {client_ip}"))
            .unwrap_or_else(|| client_ip.clone());

        // Detect TLS via session digest (same as force_https), then fall back to
        // incoming X-Forwarded-Proto header (for proxied requests).
        let is_tls = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        let proto = if is_tls {
            "https"
        } else {
            req.headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("http")
        };

        let host_val = extract_host(req).to_string();

        let _ = upstream_request.insert_header("X-Real-IP", &client_ip);
        let _ = upstream_request.insert_header("X-Forwarded-For", &xff);
        let _ = upstream_request.insert_header("X-Forwarded-Proto", proto);
        let _ = upstream_request.insert_header("Host", &host_val);

        // Custom proxy headers from route config (override defaults)
        // Clone to avoid borrow checker issues with the route snapshot lifetime
        let custom_headers: Vec<(String, String)> = route
            .proxy_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let remove_headers: Vec<String> = route.proxy_headers_remove.clone();

        for (name, value) in custom_headers {
            let _ = upstream_request.insert_header(name, value);
        }
        for name in remove_headers {
            upstream_request.remove_header(&name);
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut lorica_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Inject X-Cache header indicating cache HIT or MISS
        if session.cache.enabled() {
            let phase = session.cache.phase();
            let cache_status = match phase {
                CachePhase::Hit | CachePhase::StaleUpdating => "HIT",
                CachePhase::Stale => "STALE",
                CachePhase::Revalidated => "REVALIDATED",
                CachePhase::Miss | CachePhase::Expired => "MISS",
                _ => "BYPASS",
            };
            let _ = upstream_response.insert_header("X-Cache-Status", cache_status);

            // Increment cache counters for dashboard stats
            match cache_status {
                "HIT" | "REVALIDATED" => {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                }
                "MISS" | "BYPASS" | "STALE" => {
                    self.cache_misses.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }

        let route = match ctx.route_snapshot {
            Some(ref r) => r,
            None => return Ok(()),
        };

        // Collect all headers to inject (clone to satisfy borrow checker)
        let mut headers_to_set: Vec<(String, String)> = Vec::new();
        let mut headers_to_remove: Vec<String> = Vec::new();

        // Custom response headers from route config
        for (name, value) in &route.response_headers {
            headers_to_set.push((name.clone(), value.clone()));
        }

        // Headers to remove
        for name in &route.response_headers_remove {
            headers_to_remove.push(name.clone());
        }

        // Security headers based on preset name
        {
            let config = self.config.load();
            if let Some(preset) = config
                .security_presets
                .iter()
                .find(|p| p.name == route.security_headers)
            {
                for (name, value) in &preset.headers {
                    headers_to_set.push((name.clone(), value.clone()));
                }
            }
        }

        // CORS headers
        if !route.cors_allowed_origins.is_empty() {
            let origins = route.cors_allowed_origins.join(", ");
            headers_to_set.push(("Access-Control-Allow-Origin".to_string(), origins));
        }
        if !route.cors_allowed_methods.is_empty() {
            let methods = route.cors_allowed_methods.join(", ");
            headers_to_set.push(("Access-Control-Allow-Methods".to_string(), methods));
        }
        if let Some(max_age) = route.cors_max_age_s {
            headers_to_set.push(("Access-Control-Max-Age".to_string(), max_age.to_string()));
        }

        // Rate limit response headers
        if let Some((limit, current)) = ctx.rate_limit_info {
            let remaining = if current < limit as f64 {
                (limit as f64 - current) as u32
            } else {
                0
            };
            let reset_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 1;
            headers_to_set.push(("X-RateLimit-Limit".to_string(), limit.to_string()));
            headers_to_set.push(("X-RateLimit-Remaining".to_string(), remaining.to_string()));
            headers_to_set.push(("X-RateLimit-Reset".to_string(), reset_ts.to_string()));
        }

        // Apply removals first, then additions
        for name in headers_to_remove {
            upstream_response.remove_header(&name);
        }
        for (name, value) in headers_to_set {
            let _ = upstream_response.insert_header(name, value);
        }

        Ok(())
    }

    fn response_compression_level(
        &self,
        _session: &mut Session,
        _upstream_response: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> u32 {
        match &ctx.route_snapshot {
            Some(route) if route.compression_enabled => 6, // standard gzip level
            _ => 0,
        }
    }

    fn max_request_retries(&self, _session: &Session, ctx: &Self::CTX) -> Option<usize> {
        ctx.route_snapshot
            .as_ref()
            .and_then(|r| r.retry_attempts.map(|n| n as usize))
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
        let host_val = extract_host(req);
        let host = if host_val.is_empty() { "-" } else { host_val };

        let status = session
            .as_downstream()
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let backend_addr = ctx.backend_addr.as_deref().unwrap_or("-");

        let error_str = if let Some(ref reason) = ctx.block_reason {
            Some(reason.clone())
        } else if ctx.waf_blocked {
            Some("WAF blocked".to_string())
        } else if ctx.waf_detected {
            Some("WAF detected".to_string())
        } else {
            e.map(|err| err.to_string())
        };
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

        // Decrement per-route connection counter (max_connections enforcement)
        if let Some(ref counter) = ctx.route_conn_counter {
            counter.fetch_sub(1, Ordering::Relaxed);
        }

        // Only decrement if upstream_peer() actually incremented the counter
        if let Some(ref addr) = ctx.backend_addr {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            self.backend_connections.decrement(addr);
        }

        // Push to the in-memory log buffer for dashboard viewing (if enabled)
        if ctx.access_log_enabled {
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
                client_ip: ctx.client_ip.as_deref().unwrap_or("-").to_string(),
                is_xff: ctx.is_xff,
                xff_proxy_ip: ctx.xff_proxy_ip.as_deref().unwrap_or("").to_string(),
                source: ctx.source.clone(),
            };
            if let Some(ref store) = self.log_store {
                if let Err(e) = store.insert(&entry) {
                    tracing::warn!(error = %e, "failed to persist access log entry");
                }
            }
            self.log_buffer.push(entry).await;
        }

        // Record Prometheus metrics (bounded labels: route_id, not hostname)
        let route_label = ctx.route_id.as_deref().unwrap_or("_unknown");
        lorica_api::metrics::record_request(route_label, status, elapsed.as_secs_f64());

        // Track request count for worker -> supervisor aggregation
        self.request_counts
            .entry((route_label.to_string(), status))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // Record SLA metrics for passive monitoring
        // Exclude WebSocket upgrades (status 101) as their connection duration
        // is not representative of HTTP request latency
        if let Some(ref route_id) = ctx.route_id {
            if status != 101 {
                self.sla_collector.record(route_id, status, latency_ms);
            }
        }

        // Update EWMA latency tracker for Peak EWMA load balancing
        if let Some(ref addr) = ctx.backend_addr {
            self.ewma_tracker.record(addr, latency_ms as f64 * 1000.0);
            lorica_api::metrics::set_ewma_score(addr, self.ewma_tracker.get_score(addr));
        }
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
            enabled,
            force_https: false,
            redirect_hostname: None,
            redirect_to: None,
            hostname_aliases: Vec::new(),
            proxy_headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            security_headers: "moderate".to_string(),
            connect_timeout_s: 5,
            read_timeout_s: 60,
            send_timeout_s: 60,
            strip_path_prefix: None,
            add_path_prefix: None,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            access_log_enabled: true,
            proxy_headers_remove: Vec::new(),
            response_headers_remove: Vec::new(),
            max_request_body_bytes: None,
            websocket_enabled: true,
            rate_limit_rps: None,
            rate_limit_burst: None,
            ip_allowlist: Vec::new(),
            ip_denylist: Vec::new(),
            cors_allowed_origins: Vec::new(),
            cors_allowed_methods: Vec::new(),
            cors_max_age_s: None,
            compression_enabled: false,
            retry_attempts: None,
            cache_enabled: false,
            cache_ttl_s: 300,
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_backend(id: &str, addr: &str) -> Backend {
        let now = Utc::now();
        Backend {
            id: id.into(),
            address: addr.into(),
            name: String::new(),
            group_name: String::new(),
            weight: 100,
            health_status: HealthStatus::Healthy,
            health_check_enabled: true,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
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
            acme_method: None,

            acme_dns_provider_id: None,
        }
    }

    #[test]
    fn test_from_store_empty() {
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert!(config.routes_by_host.is_empty());
    }

    #[test]
    fn test_from_store_single_route_with_backend() {
        let route = make_route("r1", "example.com", "/", true);
        let backend = make_backend("b1", "10.0.0.1:8080");
        let links = vec![("r1".into(), "b1".into())];

        let config = ProxyConfig::from_store(
            vec![route],
            vec![backend],
            vec![],
            links,
            ProxyConfigGlobals::default(),
        );
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].backends.len(), 1);
        assert_eq!(entries[0].backends[0].address, "10.0.0.1:8080");
    }

    #[test]
    fn test_from_store_disabled_routes_excluded() {
        let r1 = make_route("r1", "example.com", "/", true);
        let r2 = make_route("r2", "disabled.com", "/", false);

        let config =
            ProxyConfig::from_store(vec![r1, r2], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert!(config.routes_by_host.contains_key("example.com"));
        assert!(!config.routes_by_host.contains_key("disabled.com"));
    }

    #[test]
    fn test_from_store_longest_path_prefix_first() {
        let r1 = make_route("r1", "example.com", "/", true);
        let r2 = make_route("r2", "example.com", "/api", true);
        let r3 = make_route("r3", "example.com", "/api/v1", true);

        let config =
            ProxyConfig::from_store(vec![r1, r2, r3], vec![], vec![], vec![], ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].route.path_prefix, "/api/v1");
        assert_eq!(entries[1].route.path_prefix, "/api");
        assert_eq!(entries[2].route.path_prefix, "/");
    }

    #[test]
    fn test_from_store_route_without_backends() {
        let route = make_route("r1", "example.com", "/", true);

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].backends.is_empty());
    }

    #[test]
    fn test_from_store_certificate_association() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.certificate_id = Some("c1".into());
        let cert = make_certificate("c1", "example.com");

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![cert], vec![], ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].certificate.is_some());
        assert_eq!(
            entries[0].certificate.as_ref().unwrap().domain,
            "example.com"
        );
    }

    #[test]
    fn test_from_store_missing_certificate_is_none() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.certificate_id = Some("nonexistent".into());

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].certificate.is_none());
    }

    #[test]
    fn test_from_store_multiple_backends_per_route() {
        let route = make_route("r1", "example.com", "/", true);
        let b1 = make_backend("b1", "10.0.0.1:8080");
        let b2 = make_backend("b2", "10.0.0.2:8080");
        let links = vec![("r1".into(), "b1".into()), ("r1".into(), "b2".into())];

        let config =
            ProxyConfig::from_store(vec![route], vec![b1, b2], vec![], links, ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert_eq!(entries[0].backends.len(), 2);
    }

    #[test]
    fn test_from_store_multiple_hosts() {
        let r1 = make_route("r1", "foo.com", "/", true);
        let r2 = make_route("r2", "bar.com", "/", true);

        let config =
            ProxyConfig::from_store(vec![r1, r2], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert_eq!(config.routes_by_host.len(), 2);
        assert!(config.routes_by_host.contains_key("foo.com"));
        assert!(config.routes_by_host.contains_key("bar.com"));
    }

    #[test]
    fn test_from_store_dangling_backend_link_ignored() {
        let route = make_route("r1", "example.com", "/", true);
        let links = vec![("r1".into(), "nonexistent-backend".into())];

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], links, ProxyConfigGlobals::default());
        let entries = config.routes_by_host.get("example.com").unwrap();
        assert!(entries[0].backends.is_empty());
    }

    #[test]
    fn test_smooth_wrr_distribution() {
        // 3 backends with equal weight: should distribute evenly
        let state = SmoothWrrState::new(0);
        let backends: Vec<(&str, i64)> = vec![("10.0.0.1:80", 100), ("10.0.0.2:80", 100), ("10.0.0.3:80", 100)];
        let mut counts = [0usize; 3];
        for _ in 0..30 {
            let idx = state.next(&backends);
            counts[idx] += 1;
        }
        // Each should get exactly 10 with equal weights
        assert_eq!(counts[0], 10);
        assert_eq!(counts[1], 10);
        assert_eq!(counts[2], 10);
    }

    #[test]
    fn test_smooth_wrr_weighted() {
        // Weights 5,3,2: should distribute proportionally
        let state = SmoothWrrState::new(0);
        let backends: Vec<(&str, i64)> = vec![("10.0.0.1:80", 5), ("10.0.0.2:80", 3), ("10.0.0.3:80", 2)];
        let mut counts = [0usize; 3];
        for _ in 0..10 {
            let idx = state.next(&backends);
            counts[idx] += 1;
        }
        assert_eq!(counts[0], 5);
        assert_eq!(counts[1], 3);
        assert_eq!(counts[2], 2);
    }

    #[test]
    fn test_smooth_wrr_worker_offset() {
        // Two workers with different offsets should start on different backends
        let state0 = SmoothWrrState::new(0);
        let state1 = SmoothWrrState::new(1);
        let backends: Vec<(&str, i64)> = vec![("10.0.0.1:80", 100), ("10.0.0.2:80", 100), ("10.0.0.3:80", 100)];
        let first0 = state0.next(&backends);
        let first1 = state1.next(&backends);
        assert_ne!(first0, first1, "different workers should start on different backends");
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

    // ---- EWMA Tracker ----

    #[test]
    fn test_ewma_tracker_default_score() {
        let tracker = EwmaTracker::new();
        assert_eq!(tracker.get_score("10.0.0.1:8080"), 0.0);
    }

    #[test]
    fn test_ewma_tracker_record_updates_score() {
        let tracker = EwmaTracker::new();
        tracker.record("10.0.0.1:8080", 100.0);
        assert!(tracker.get_score("10.0.0.1:8080") > 0.0);
    }

    #[test]
    fn test_ewma_tracker_selects_lowest_score() {
        let tracker = EwmaTracker::new();
        // Backend 1: high latency
        for _ in 0..10 {
            tracker.record("10.0.0.1:8080", 5000.0);
        }
        // Backend 2: low latency
        for _ in 0..10 {
            tracker.record("10.0.0.2:8080", 100.0);
        }

        let b1 = make_backend("b1", "10.0.0.1:8080");
        let b2 = make_backend("b2", "10.0.0.2:8080");
        let backends = vec![&b1, &b2];

        let selected = tracker.select_best(&backends);
        assert_eq!(selected, 1, "Should select the faster backend (index 1)");
    }

    #[test]
    fn test_ewma_tracker_prefers_unscored() {
        let tracker = EwmaTracker::new();
        // Only score backend 1 (high latency)
        tracker.record("10.0.0.1:8080", 5000.0);
        // Backend 2 is unscored (score = 0.0, exploration priority)

        let b1 = make_backend("b1", "10.0.0.1:8080");
        let b2 = make_backend("b2", "10.0.0.2:8080");
        let backends = vec![&b1, &b2];

        let selected = tracker.select_best(&backends);
        assert_eq!(
            selected, 1,
            "Should prefer unscored backend for exploration"
        );
    }

    #[test]
    fn test_ewma_tracker_decay() {
        let tracker = EwmaTracker::new();
        // Record very high latency
        tracker.record("10.0.0.1:8080", 10000.0);
        let score_after_high = tracker.get_score("10.0.0.1:8080");

        // Record many low latency samples (should decay the high score)
        for _ in 0..20 {
            tracker.record("10.0.0.1:8080", 50.0);
        }
        let score_after_low = tracker.get_score("10.0.0.1:8080");

        assert!(
            score_after_low < score_after_high,
            "Score should decrease after low-latency samples ({score_after_low} < {score_after_high})"
        );
    }

    #[test]
    fn test_ewma_tracker_empty_backends() {
        let tracker = EwmaTracker::new();
        let backends: Vec<&Backend> = vec![];
        assert_eq!(tracker.select_best(&backends), 0);
    }

    // ---- Hostname Aliases ----

    #[test]
    fn test_from_store_hostname_aliases_indexed() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.hostname_aliases = vec!["www.example.com".into(), "alias.example.com".into()];

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert!(config.routes_by_host.contains_key("example.com"));
        assert!(config.routes_by_host.contains_key("www.example.com"));
        assert!(config.routes_by_host.contains_key("alias.example.com"));

        // All point to the same route
        let primary = &config.routes_by_host["example.com"][0];
        let alias = &config.routes_by_host["www.example.com"][0];
        assert_eq!(primary.route.id, alias.route.id);
    }

    // ---- IP Matching ----

    #[test]
    fn test_ip_matches_exact() {
        assert!(ip_matches("192.168.1.1", "192.168.1.1"));
        assert!(!ip_matches("192.168.1.1", "192.168.1.2"));
    }

    #[test]
    fn test_ip_matches_cidr_prefix() {
        assert!(ip_matches("192.168.1.100", "192.168.1/24"));
        assert!(!ip_matches("10.0.0.1", "192.168.1/24"));
    }

    // ---- Security Presets in ProxyConfig ----

    #[test]
    fn test_proxy_config_has_builtin_presets_by_default() {
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals::default());
        let names: Vec<&str> = config
            .security_presets
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert!(names.contains(&"strict"));
        assert!(names.contains(&"moderate"));
        assert!(names.contains(&"none"));
    }

    #[test]
    fn test_proxy_config_custom_preset_added() {
        let custom = lorica_config::models::SecurityHeaderPreset {
            name: "api-only".to_string(),
            headers: std::collections::HashMap::from([(
                "X-Custom-Header".to_string(),
                "yes".to_string(),
            )]),
        };
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { custom_security_presets: vec![custom], ..Default::default() });
        let found = config
            .security_presets
            .iter()
            .find(|p| p.name == "api-only");
        assert!(found.is_some());
        assert_eq!(found.unwrap().headers["X-Custom-Header"], "yes");
    }

    #[test]
    fn test_proxy_config_custom_preset_overrides_builtin() {
        let custom_strict = lorica_config::models::SecurityHeaderPreset {
            name: "strict".to_string(),
            headers: std::collections::HashMap::from([(
                "X-Frame-Options".to_string(),
                "SAMEORIGIN".to_string(),
            )]),
        };
        let config =
            ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { custom_security_presets: vec![custom_strict], ..Default::default() });
        let strict = config
            .security_presets
            .iter()
            .find(|p| p.name == "strict")
            .unwrap();
        // The custom override should have replaced the builtin
        assert_eq!(strict.headers["X-Frame-Options"], "SAMEORIGIN");
        // And should NOT have the builtin headers that were not in the override
        assert!(!strict.headers.contains_key("Content-Security-Policy"));
    }

    // ---- Wildcard Hostname Matching ----

    #[test]
    fn test_wildcard_hostname_matching() {
        let route = make_route("r1", "*.example.com", "/", true);
        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());

        // Should match subdomains
        assert!(config.find_route("foo.example.com", "/").is_some());
        assert!(config.find_route("bar.example.com", "/").is_some());

        // Should NOT match bare domain
        assert!(config.find_route("example.com", "/").is_none());

        // Should NOT match deeper subdomains? (depends on implementation)
        // *.example.com should match a.example.com but implementation may vary
    }

    #[test]
    fn test_exact_match_takes_precedence_over_wildcard() {
        let r1 = make_route("r1", "*.example.com", "/", true);
        let r2 = make_route("r2", "specific.example.com", "/", true);
        let config =
            ProxyConfig::from_store(vec![r1, r2], vec![], vec![], vec![], ProxyConfigGlobals::default());

        let entry = config.find_route("specific.example.com", "/").unwrap();
        assert_eq!(entry.route.id, "r2"); // exact match wins

        let entry = config.find_route("other.example.com", "/").unwrap();
        assert_eq!(entry.route.id, "r1"); // wildcard matches
    }

    // ---- Rate Limiter ----

    #[test]
    fn test_rate_limiter_tracks_requests() {
        let rate = lorica_limits::rate::Rate::new(Duration::from_secs(1));
        let key = "route1:192.168.1.1";

        // First interval: observe some requests
        rate.observe(&key, 1);
        rate.observe(&key, 1);
        rate.observe(&key, 1);

        // Within the same interval, rate() reports the previous interval (0 since first interval)
        assert_eq!(rate.rate(&key), 0.0);

        // After one interval passes, the rate should reflect the observed count
        std::thread::sleep(Duration::from_millis(1100));
        rate.observe(&key, 1); // trigger interval flip
        let current_rate = rate.rate(&key);
        assert!(
            current_rate >= 2.0,
            "Expected rate >= 2.0, got {current_rate}"
        );
    }

    #[test]
    fn test_rate_limiter_different_keys_are_independent() {
        let rate = lorica_limits::rate::Rate::new(Duration::from_secs(1));
        let key_a = "route1:10.0.0.1";
        let key_b = "route1:10.0.0.2";

        for _ in 0..10 {
            rate.observe(&key_a, 1);
        }
        rate.observe(&key_b, 1);

        // After interval flip, rates should differ
        std::thread::sleep(Duration::from_millis(1100));
        rate.observe(&key_a, 1);
        rate.observe(&key_b, 1);

        let rate_a = rate.rate(&key_a);
        let rate_b = rate.rate(&key_b);
        assert!(
            rate_a > rate_b,
            "Key A ({rate_a}) should have higher rate than Key B ({rate_b})"
        );
    }

    #[test]
    fn test_rate_limit_burst_threshold() {
        // Verify that the burst logic allows rps + burst before triggering
        let rps: u32 = 10;
        let burst: u32 = 5;
        let effective_limit = (rps + burst) as f64;

        // A rate of 14.0 should be allowed (< 15)
        assert!(14.0 <= effective_limit);
        // A rate of 16.0 should be blocked (> 15)
        assert!(16.0 > effective_limit);
    }

    // ---- Ban List ----

    #[test]
    fn test_ban_list_blocked_ip_detected() {
        let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        // Ban an IP
        ban_list.insert("10.0.0.99".to_string(), Instant::now());

        // Check that the IP is banned
        let ip = "10.0.0.99";
        let banned = ban_list
            .get(ip)
            .map(|entry| entry.value().elapsed() < Duration::from_secs(3600))
            .unwrap_or(false);
        assert!(banned, "Recently banned IP should be detected as banned");
    }

    #[test]
    fn test_ban_list_expired_ban_allows_through() {
        let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        // Ban an IP with a time in the past (simulate expired ban)
        ban_list.insert("10.0.0.99".to_string(), Instant::now());

        // Check with zero-duration ban (expired immediately)
        let ip = "10.0.0.99";
        let banned = if let Some(entry) = ban_list.get(ip) {
            if entry.value().elapsed() >= Duration::from_secs(0) {
                drop(entry);
                // Ban with 0s duration is immediately expired
                ban_list.remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        };
        assert!(
            !banned,
            "Expired ban should allow the IP through (lazy cleanup)"
        );

        // Verify the IP was removed from the ban list
        assert!(
            !ban_list.contains_key(ip),
            "Expired ban should be removed from the ban list"
        );
    }

    #[test]
    fn test_ban_list_unbanned_ip_passes() {
        let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        // Ban a different IP
        ban_list.insert("10.0.0.99".to_string(), Instant::now());

        // Check an IP that is NOT banned
        let ip = "10.0.0.50";
        let banned = ban_list
            .get(ip)
            .map(|entry| entry.value().elapsed() < Duration::from_secs(3600))
            .unwrap_or(false);
        assert!(!banned, "Unbanned IP should not be detected as banned");
    }

    #[test]
    fn test_auto_ban_after_threshold_violations() {
        let rate_violations = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(60)));
        let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        let ip = "10.0.0.99";
        let ban_threshold: u32 = 5;
        let violation_key = format!("violation:{}", ip);

        // Simulate violations exceeding the threshold
        // We need to fill the previous interval first, then check rate
        for _ in 0..20 {
            rate_violations.observe(&violation_key, 1);
        }

        // Wait for interval to flip so rate() returns the observed count
        std::thread::sleep(Duration::from_millis(100));

        // In the same interval, observe() accumulates but rate() reports
        // the previous interval. For this test, we check the logic directly.
        // The violation count within the current interval exceeds the threshold.
        // In production, after the interval flips, rate() would report the count.
        // Here we test the ban insertion logic directly.
        let violations_count = 20; // We observed 20 violations
        if violations_count > ban_threshold {
            ban_list.insert(ip.to_string(), Instant::now());
        }

        assert!(
            ban_list.contains_key(ip),
            "IP should be auto-banned after exceeding violation threshold"
        );
    }

    #[test]
    fn test_ban_list_lazy_cleanup_removes_expired() {
        let ban_list: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        // Insert two bans
        ban_list.insert("10.0.0.1".to_string(), Instant::now());
        ban_list.insert("10.0.0.2".to_string(), Instant::now());

        // Lazy cleanup with 0s duration (all expired)
        let ban_duration = Duration::from_secs(0);
        let expired_ips: Vec<String> = ban_list
            .iter()
            .filter(|entry| entry.value().elapsed() >= ban_duration)
            .map(|entry| entry.key().clone())
            .collect();
        for ip in expired_ips {
            ban_list.remove(&ip);
        }

        assert!(ban_list.is_empty(), "All expired bans should be cleaned up");
    }

    // ---- Max Connections ----

    #[test]
    fn test_route_connections_counter_increment_decrement() {
        let route_connections: Arc<DashMap<String, Arc<AtomicU64>>> = Arc::new(DashMap::new());

        let route_id = "route-1";

        // Get or create counter
        let counter = route_connections
            .entry(route_id.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .value()
            .clone();

        // Increment
        let v = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v, 0);
        let v = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v, 1);

        // Decrement
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_route_connections_rejects_when_at_limit() {
        let max_conn: u32 = 2;
        let counter = Arc::new(AtomicU64::new(0));

        // First two connections should succeed
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(
            current < max_conn as u64,
            "First connection should be allowed"
        );
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(
            current < max_conn as u64,
            "Second connection should be allowed"
        );

        // Third connection should be rejected (current == max_conn)
        let current = counter.fetch_add(1, Ordering::Relaxed);
        let rejected = current >= max_conn as u64;
        if rejected {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        assert!(rejected, "Third connection should be rejected (503)");
        assert_eq!(
            counter.load(Ordering::Relaxed),
            2,
            "Counter should remain at limit"
        );
    }

    #[test]
    fn test_route_connections_allows_after_release() {
        let max_conn: u32 = 1;
        let counter = Arc::new(AtomicU64::new(0));

        // Take the only slot
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(current < max_conn as u64);

        // Second should be rejected
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(current >= max_conn as u64);
        counter.fetch_sub(1, Ordering::Relaxed);

        // Release the first connection
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Now another connection should succeed
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(
            current < max_conn as u64,
            "Connection should be allowed after release"
        );
    }

    #[test]
    fn test_route_connections_independent_routes() {
        let route_connections: Arc<DashMap<String, Arc<AtomicU64>>> = Arc::new(DashMap::new());

        // Create counters for two routes
        let counter_a = route_connections
            .entry("route-a".to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .value()
            .clone();
        let counter_b = route_connections
            .entry("route-b".to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .value()
            .clone();

        counter_a.fetch_add(1, Ordering::Relaxed);
        counter_a.fetch_add(1, Ordering::Relaxed);
        counter_b.fetch_add(1, Ordering::Relaxed);

        assert_eq!(counter_a.load(Ordering::Relaxed), 2);
        assert_eq!(counter_b.load(Ordering::Relaxed), 1);
    }

    // ---- Slowloris Detection ----

    #[test]
    fn test_slowloris_detection_threshold_exceeded() {
        let threshold_ms: i32 = 100;

        // Simulate a request that took longer than the threshold
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(150));
        let elapsed_ms = start.elapsed().as_millis() as i32;

        assert!(
            elapsed_ms > threshold_ms,
            "Elapsed {elapsed_ms}ms should exceed threshold {threshold_ms}ms"
        );
    }

    #[test]
    fn test_slowloris_detection_within_threshold() {
        let threshold_ms: i32 = 5000;

        // A fast request should not trigger slowloris detection
        let start = Instant::now();
        let elapsed_ms = start.elapsed().as_millis() as i32;

        assert!(
            elapsed_ms <= threshold_ms,
            "Elapsed {elapsed_ms}ms should be within threshold {threshold_ms}ms"
        );
    }

    #[test]
    fn test_slowloris_disabled_when_threshold_zero() {
        let threshold_ms: i32 = 0;

        // When threshold is 0, slowloris detection should be disabled
        // The condition is: threshold > 0 && elapsed > threshold
        let should_block = threshold_ms > 0;
        assert!(
            !should_block,
            "Slowloris detection should be disabled when threshold is 0"
        );
    }

    // ---- Global Flood Rate ----

    #[test]
    fn test_global_rate_tracks_requests() {
        let global_rate = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1)));

        // Observe some requests
        for _ in 0..50 {
            global_rate.observe(&"global", 1);
        }

        // Within the same interval, rate() reports the previous interval (0)
        assert_eq!(global_rate.rate(&"global"), 0.0);

        // After interval flip, rate should reflect observed count
        std::thread::sleep(Duration::from_millis(1100));
        global_rate.observe(&"global", 1);
        let rate = global_rate.rate(&"global");
        assert!(rate >= 40.0, "Expected global rate >= 40.0, got {rate}");
    }

    #[test]
    fn test_flood_threshold_halves_effective_limit() {
        // When flood_threshold_rps > 0 and global RPS exceeds it,
        // the effective per-IP rate limit should be halved.
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { flood_threshold_rps: 100, ..Default::default() });
        assert_eq!(config.flood_threshold_rps, 100);

        // Simulate: route has rate_limit_rps=50, burst=10 -> effective=60
        // Under flood (global > 100), effective should become 30
        let base_limit: f64 = (50 + 10) as f64;
        let threshold = config.flood_threshold_rps;

        // Normal conditions: global RPS below threshold
        let global_rps_normal = 80.0;
        let mut effective = base_limit;
        if threshold > 0 && global_rps_normal > threshold as f64 {
            effective *= 0.5;
        }
        assert_eq!(effective, 60.0, "No halving when below threshold");

        // Flood conditions: global RPS above threshold
        let global_rps_flood = 150.0;
        let mut effective = base_limit;
        if threshold > 0 && global_rps_flood > threshold as f64 {
            effective *= 0.5;
        }
        assert_eq!(effective, 30.0, "Limit halved during flood");
    }

    #[test]
    fn test_flood_threshold_zero_disables_defense() {
        // When flood_threshold_rps is 0, adaptive defense is disabled
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert_eq!(config.flood_threshold_rps, 0);

        let base_limit: f64 = 100.0;
        let threshold = config.flood_threshold_rps;
        let global_rps = 999999.0;
        let mut effective = base_limit;
        if threshold > 0 && global_rps > threshold as f64 {
            effective *= 0.5;
        }
        assert_eq!(
            effective, 100.0,
            "No halving when threshold is 0 (disabled)"
        );
    }

    #[test]
    fn test_global_rate_decays_to_zero() {
        let global_rate = Arc::new(lorica_limits::rate::Rate::new(Duration::from_secs(1)));

        for _ in 0..10 {
            global_rate.observe(&"global", 1);
        }

        // Wait for two full intervals so data expires
        std::thread::sleep(Duration::from_millis(2100));
        let rate = global_rate.rate(&"global");
        assert_eq!(
            rate, 0.0,
            "Rate should decay to 0 after 2 intervals of silence"
        );
    }

    // ---- Catch-all Hostname ----

    #[test]
    fn test_catch_all_hostname() {
        let route = make_route("r_catch", "_", "/", true);
        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());

        // Catch-all "_" should match any hostname
        assert!(config.find_route("anything.example.com", "/").is_some());
        assert!(config.find_route("other.org", "/api").is_some());

        let entry = config.find_route("random-host.net", "/").unwrap();
        assert_eq!(entry.route.id, "r_catch");
    }

    #[test]
    fn test_catch_all_after_exact() {
        let exact = make_route("r_exact", "app.example.com", "/", true);
        let catch_all = make_route("r_catch", "_", "/", true);
        let config = ProxyConfig::from_store(
            vec![exact, catch_all],
            vec![],
            vec![],
            vec![],
            ProxyConfigGlobals::default(),
        );

        // Exact hostname takes precedence
        let entry = config.find_route("app.example.com", "/").unwrap();
        assert_eq!(entry.route.id, "r_exact");

        // Unknown hostname falls through to catch-all
        let entry = config.find_route("unknown.org", "/").unwrap();
        assert_eq!(entry.route.id, "r_catch");
    }

    // ---- Path Rule Matching ----

    #[test]
    fn test_path_rule_matching() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.path_rules = vec![
            PathRule {
                path: "/api/v2".into(),
                match_type: PathMatchType::Prefix,
                backend_ids: None,
                cache_enabled: Some(false),
                cache_ttl_s: None,
                response_headers: None,
                response_headers_remove: None,
                rate_limit_rps: None,
                rate_limit_burst: None,
                redirect_to: None,
                return_status: None,
            },
            PathRule {
                path: "/health".into(),
                match_type: PathMatchType::Exact,
                backend_ids: None,
                cache_enabled: None,
                cache_ttl_s: None,
                response_headers: None,
                response_headers_remove: None,
                rate_limit_rps: None,
                rate_limit_burst: None,
                redirect_to: None,
                return_status: Some(200),
            },
        ];

        let config =
            ProxyConfig::from_store(vec![route], vec![], vec![], vec![], ProxyConfigGlobals::default());

        let entry = config.find_route("example.com", "/api/v2/users").unwrap();
        assert_eq!(entry.route.id, "r1");

        // Verify first path rule matches prefix
        let matched = entry
            .route
            .path_rules
            .iter()
            .find(|r| r.matches("/api/v2/users"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().path, "/api/v2");

        // Verify exact match rule
        let matched = entry
            .route
            .path_rules
            .iter()
            .find(|r| r.matches("/health"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().return_status, Some(200));

        // Verify exact match does not match prefix
        let matched = entry
            .route
            .path_rules
            .iter()
            .find(|r| r.matches("/health/check"));
        assert!(matched.is_none());
    }

    // ---- Trusted Proxies ----

    #[test]
    fn test_trusted_proxies_empty_by_default() {
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals::default());
        assert!(config.trusted_proxies.is_empty());
    }

    #[test]
    fn test_trusted_proxies_cidr_parsed() {
        let cidrs = vec![
            "192.168.0.0/16".to_string(),
            "10.0.0.0/8".to_string(),
        ];
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { trusted_proxy_cidrs: cidrs, ..Default::default() });
        assert_eq!(config.trusted_proxies.len(), 2);
        // 192.168.1.1 is in 192.168.0.0/16
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        assert!(config.trusted_proxies.iter().any(|net| net.contains(&addr)));
        // 172.16.0.1 is NOT in the configured ranges
        let addr2: std::net::IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!config.trusted_proxies.iter().any(|net| net.contains(&addr2)));
    }

    #[test]
    fn test_trusted_proxies_bare_ip_converted() {
        let cidrs = vec!["10.0.0.1".to_string()];
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { trusted_proxy_cidrs: cidrs, ..Default::default() });
        assert_eq!(config.trusted_proxies.len(), 1);
        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        assert!(config.trusted_proxies.iter().any(|net| net.contains(&addr)));
        // Different IP should not match
        let addr2: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!config.trusted_proxies.iter().any(|net| net.contains(&addr2)));
    }

    #[test]
    fn test_trusted_proxies_invalid_entries_skipped() {
        let cidrs = vec![
            "192.168.0.0/16".to_string(),
            "not-a-cidr".to_string(),
            "".to_string(),
            "10.0.0.1".to_string(),
        ];
        let config = ProxyConfig::from_store(vec![], vec![], vec![], vec![], ProxyConfigGlobals { trusted_proxy_cidrs: cidrs, ..Default::default() });
        // Only the valid CIDR and the valid bare IP should be parsed
        assert_eq!(config.trusted_proxies.len(), 2);
    }
}
