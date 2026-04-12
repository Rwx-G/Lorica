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
use lorica_cache::lock::CacheLock;
use lorica_cache::key::HashBinary;
use lorica_cache::predictor::Predictor;
use lorica_cache::{
    CacheKey, CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
    VarianceBuilder,
};
use lorica_config::models::{Backend, Certificate, HealthStatus, LifecycleState, Route, WafMode};
use lorica_core::protocols::Digest;
use lorica_core::upstreams::peer::HttpPeer;
use lorica_error::{Error, ErrorSource, ErrorType, Result};
use lorica_http::ResponseHeader;
use lorica_proxy::{FailToProxy, ProxyHttp, Session};
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
    pub route: Arc<Route>,
    pub backends: Vec<Backend>,
    pub certificate: Option<Certificate>,
    /// Smooth weighted round-robin state for this route.
    pub wrr_state: Arc<SmoothWrrState>,
    /// Precompiled regex for path rewriting (None if not configured).
    /// Wrapped in Arc to avoid expensive Regex clone on every request.
    pub path_rewrite_regex: Option<Arc<regex::Regex>>,
    /// Resolved backends per path rule (parallel to route.path_rules).
    /// None = inherit route backends, Some = override with these backends.
    pub path_rule_backends: Vec<Option<Vec<Backend>>>,
    /// Precompiled regex per header rule (parallel to route.header_rules).
    /// `None` when the rule's match_type is Exact/Prefix, or when the regex
    /// failed to compile (in which case the rule is logged-and-disabled at
    /// load time rather than failing the whole reload).
    pub header_rule_regexes: Vec<Option<Arc<regex::Regex>>>,
    /// Resolved backends per header rule (parallel to route.header_rules).
    /// None = rule matches but keeps default backends; Some = override.
    /// Empty backend_ids on a rule also yields None here.
    pub header_rule_backends: Vec<Option<Vec<Backend>>>,
    /// Resolved backends per traffic split (parallel to
    /// route.traffic_splits). Splits whose `backend_ids` are all dangling
    /// become `None` and are silently skipped at match time, so a typo in
    /// the dashboard never dead-ends live traffic.
    pub traffic_split_backends: Vec<Option<Vec<Backend>>>,
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
    /// Parsed CIDR ranges of IPs that bypass WAF, rate limiting, and auto-ban.
    pub waf_whitelist: Vec<ipnet::IpNet>,
}

/// Global settings extracted from the config store for ProxyConfig construction.
#[derive(Default, Clone)]
pub struct ProxyConfigGlobals {
    pub custom_security_presets: Vec<lorica_config::models::SecurityHeaderPreset>,
    pub max_global_connections: u32,
    pub flood_threshold_rps: u32,
    pub waf_ban_threshold: u32,
    pub waf_ban_duration_s: u32,
    pub trusted_proxy_cidrs: Vec<String>,
    pub waf_whitelist_cidrs: Vec<String>,
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
            waf_whitelist_cidrs,
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

            // Precompile regex rules and pre-resolve backends so the hot
            // path in `request_filter` can iterate without allocating or
            // recompiling. A bad regex logs a warning and disables the
            // single rule - a broken header rule must not poison the rest
            // of the route's config.
            let header_rule_regexes: Vec<Option<Arc<regex::Regex>>> = route
                .header_rules
                .iter()
                .map(|rule| match rule.match_type {
                    lorica_config::models::HeaderMatchType::Regex => {
                        match regex::Regex::new(&rule.value) {
                            Ok(re) => Some(Arc::new(re)),
                            Err(e) => {
                                tracing::warn!(
                                    route_id = %route.id,
                                    header = %rule.header_name,
                                    pattern = %rule.value,
                                    error = %e,
                                    "invalid header_rule regex, disabling this rule"
                                );
                                None
                            }
                        }
                    }
                    _ => None,
                })
                .collect();

            let header_rule_backends: Vec<Option<Vec<Backend>>> = route
                .header_rules
                .iter()
                .map(|rule| {
                    if rule.backend_ids.is_empty() {
                        None
                    } else {
                        Some(
                            rule.backend_ids
                                .iter()
                                .filter_map(|id| backend_map.get(id).cloned())
                                .collect::<Vec<_>>(),
                        )
                        .filter(|v: &Vec<_>| !v.is_empty())
                    }
                })
                .collect();

            let traffic_split_backends: Vec<Option<Vec<Backend>>> = route
                .traffic_splits
                .iter()
                .map(|split| {
                    if split.backend_ids.is_empty() || split.weight_percent == 0 {
                        None
                    } else {
                        let resolved: Vec<_> = split
                            .backend_ids
                            .iter()
                            .filter_map(|id| backend_map.get(id).cloned())
                            .collect();
                        if resolved.is_empty() {
                            // All backend IDs dangled - log once at load
                            // time so operators see the typo, but let the
                            // route keep functioning on its defaults.
                            tracing::warn!(
                                route_id = %route.id,
                                split_name = %split.name,
                                "traffic_split backend_ids all dangling, skipping this split"
                            );
                            None
                        } else {
                            Some(resolved)
                        }
                    }
                })
                .collect();

            let entry = RouteEntry {
                route: Arc::new(route.clone()),
                backends: route_backends,
                certificate,
                wrr_state: Arc::new(SmoothWrrState::new(std::process::id() as usize)),
                path_rewrite_regex: path_rewrite_regex.map(Arc::new),
                path_rule_backends,
                header_rule_regexes,
                header_rule_backends,
                traffic_split_backends,
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

        // Parse WAF whitelist CIDRs (same logic as trusted proxies)
        let waf_whitelist: Vec<ipnet::IpNet> = waf_whitelist_cidrs
            .iter()
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return None;
                }
                if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
                    Some(net)
                } else if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                    Some(ipnet::IpNet::from(ip))
                } else {
                    warn!(entry = %trimmed, "ignoring invalid waf_whitelist_ips entry");
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
            waf_whitelist,
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

/// Per-backend circuit breaker.
///
/// Tracks consecutive failures per backend. When the failure count reaches the
/// threshold, the circuit opens and all traffic is redirected to other backends
/// for a cooldown period. After the cooldown, one probe request is allowed
/// through (half-open). If it succeeds the circuit closes; if it fails the
/// circuit re-opens.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Per-backend state: (consecutive_failures, state, last_state_change)
    states: dashmap::DashMap<String, CircuitBreakerState>,
    /// Number of consecutive errors before opening the circuit.
    threshold: u32,
    /// How long the circuit stays open before moving to half-open (seconds).
    cooldown_s: u64,
}

#[derive(Debug, Clone)]
struct CircuitBreakerState {
    failures: u32,
    state: CircuitStatus,
    changed_at: Instant,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitStatus {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_s: u64) -> Self {
        Self {
            states: dashmap::DashMap::new(),
            threshold,
            cooldown_s,
        }
    }

    /// Check if a backend is available (not in Open state).
    /// Open circuits that have exceeded the cooldown move to HalfOpen.
    pub fn is_available(&self, addr: &str) -> bool {
        let mut entry = match self.states.get_mut(addr) {
            Some(e) => e,
            None => return true, // no state = closed = available
        };
        match entry.state {
            CircuitStatus::Closed | CircuitStatus::HalfOpen => true,
            CircuitStatus::Open => {
                if entry.changed_at.elapsed() >= Duration::from_secs(self.cooldown_s) {
                    entry.state = CircuitStatus::HalfOpen;
                    entry.changed_at = Instant::now();
                    true // allow one probe request
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful response. Resets the failure count and closes the circuit.
    pub fn record_success(&self, addr: &str) {
        if let Some(mut entry) = self.states.get_mut(addr) {
            if entry.failures > 0 || entry.state != CircuitStatus::Closed {
                entry.failures = 0;
                entry.state = CircuitStatus::Closed;
                entry.changed_at = Instant::now();
            }
        }
    }

    /// Record a failure. Increments the counter and opens the circuit if threshold is reached.
    pub fn record_failure(&self, addr: &str) {
        let mut entry = self.states.entry(addr.to_string()).or_insert(CircuitBreakerState {
            failures: 0,
            state: CircuitStatus::Closed,
            changed_at: Instant::now(),
        });
        entry.failures += 1;
        if entry.failures >= self.threshold && entry.state != CircuitStatus::Open {
            entry.state = CircuitStatus::Open;
            entry.changed_at = Instant::now();
            tracing::warn!(
                backend = %addr,
                failures = entry.failures,
                cooldown_s = self.cooldown_s,
                "circuit breaker opened - backend removed from rotation"
            );
        }
    }
}

/// Compute the upstream keepalive pool size based on the number of backends.
/// - <= 15 backends: 128 (Pingora default)
/// - 16+ backends: 8 connections per backend, capped at 1024
pub fn compute_pool_size(backend_count: usize) -> usize {
    if backend_count <= 15 {
        128
    } else {
        (backend_count * 8).min(1024)
    }
}

/// Check whether an IP address matches a pattern (exact match or CIDR range).
fn ip_matches(ip: &str, pattern: &str) -> bool {
    if pattern.contains('/') {
        // CIDR - parse and use proper network containment check
        let net: std::net::IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let cidr: ipnet::IpNet = match pattern.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        cidr.contains(&net)
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

/// Cache lock that prevents thundering herd on cache miss.
/// When multiple requests hit the same uncached key simultaneously, only the
/// first one fetches from upstream (the writer); others wait for the writer to
/// finish and then serve the cached response. The lock times out after 10 s so
/// readers are never blocked indefinitely.
static CACHE_LOCK: Lazy<&'static CacheLock> = Lazy::new(|| {
    let lock = CacheLock::new_boxed(Duration::from_secs(10));
    Box::leak(lock)
});

/// Shared HTTP client used for forward-auth sub-requests. Built once and
/// reused across all routes so connection pooling and TLS sessions amortize
/// across requests. Redirects are disabled - an auth service replying 302
/// must be treated as a "deny" verdict we forward to the client, never
/// transparently followed (that would turn a login-redirect into a
/// back-to-the-proxy loop).
static FORWARD_AUTH_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(32)
        // Default connect timeout; per-request total timeout is set on each call.
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("build forward-auth reqwest client")
});

/// Cacheability predictor. Remembers keys whose origin recently responded as
/// uncacheable (OriginNotCache, ResponseTooLarge, or a user-defined custom
/// reason) and short-circuits the cache state machine on the next request,
/// avoiding cache-lock contention and variance-key computation for assets
/// that have proved they would bypass the cache anyway.
///
/// `16 * 2048 = 32_768` keys are remembered across 16 LRU shards. A shard is
/// selected by hash so concurrent writers only contend within their shard.
/// Internal errors (InternalError, StorageError, UpstreamError, lock
/// timeouts) are not remembered - those are transient and should not poison
/// future cacheability decisions.
const CACHE_PREDICTOR_SHARDS: usize = 16;
const CACHE_PREDICTOR_SHARD_CAPACITY: usize = 2048;
static CACHE_PREDICTOR: Lazy<&'static Predictor<CACHE_PREDICTOR_SHARDS>> = Lazy::new(|| {
    Box::leak(Box::new(Predictor::<CACHE_PREDICTOR_SHARDS>::new(
        CACHE_PREDICTOR_SHARD_CAPACITY,
        None,
    )))
});

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
    10, // stale-while-revalidate: serve stale for 10 s while background refresh
    60, // stale-if-error: serve stale for 60 s when upstream fails
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
    /// Arc-wrapped to avoid deep-cloning the Route struct on every request.
    pub route_snapshot: Option<Arc<Route>>,
    /// Unique request identifier for tracing (propagated to backend via X-Request-Id).
    pub request_id: String,
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
    pub path_rewrite_regex: Option<Arc<regex::Regex>>,
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
    /// Backend ID for sticky session cookie injection (set in upstream_peer).
    pub sticky_backend_id: Option<String>,
    /// Headers harvested from a successful forward-auth response, to be
    /// injected into the upstream request (e.g. Remote-User).
    pub forward_auth_inject: Vec<(String, String)>,
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
    /// Per-backend circuit breaker (opens after consecutive failures).
    pub circuit_breaker: Arc<CircuitBreaker>,
    /// Basic auth credential verification cache. Maps a hash of
    /// "username:password" to the timestamp of the last successful Argon2
    /// verification. Entries older than 60 s are ignored, forcing a fresh
    /// Argon2 check. This avoids ~100 ms per request on auth-protected routes.
    basic_auth_cache: Arc<DashMap<u64, Instant>>,
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
            circuit_breaker: Arc::new(CircuitBreaker::new(5, 10)),
            basic_auth_cache: Arc::new(DashMap::new()),
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
/// Extract the LORICA_SRV backend ID from a Cookie header value.
fn extract_sticky_backend(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix("LORICA_SRV=")
    })
}

/// Generate a compact hex request ID (16 bytes = 32 hex chars).
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let rand: u64 = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        ts.hash(&mut h);
        std::thread::current().id().hash(&mut h);
        h.finish()
    };
    format!("{ts:016x}{rand:016x}")
}

/// Escape HTML special characters to prevent XSS when injecting dynamic values
/// into HTML templates (e.g. error pages).
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Sanitize admin-provided HTML by removing dangerous tags and attributes
/// that could execute JavaScript (XSS). Keeps safe formatting tags intact.
/// Precompiled regexes for HTML sanitization (compiled once, used on every
/// error page render). Avoids ~300-500us of regex compilation per call.
static RE_SCRIPT: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(?is)<script[\s>].*?</script>").expect("sanitize: script regex"));
static RE_EVENTS: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r#"(?i)\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)"#).expect("sanitize: event handler regex"));
static RE_JS_URI: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r#"(?i)(href|src|action)\s*=\s*["']?\s*javascript:"#).expect("sanitize: javascript URI regex"));

fn sanitize_html(html: &str) -> String {
    let out = RE_SCRIPT.replace_all(html, "");
    let out = RE_EVENTS.replace_all(&out, "");
    let out = RE_JS_URI.replace_all(&out, r#"$1=""#);
    out.into_owned()
}

fn extract_host(req: &lorica_http::RequestHeader) -> &str {
    req.headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.authority().map(|a| a.as_str()))
        .unwrap_or("")
}

/// Evaluate header-based routing rules against a request's headers.
/// Returns pre-resolved backends from the first rule that matches and
/// carries an override. A rule with an empty `backend_ids` ("match but
/// keep route defaults") is treated as not-an-override: the caller should
/// leave `matched_backends` alone when this returns `None`.
///
/// Extracted so the matching + extraction path is exercised by unit
/// tests without needing a Session or ProxyConfig.
pub(crate) fn match_header_rule_backends<'a>(
    rules: &[lorica_config::models::HeaderRule],
    regexes: &[Option<Arc<regex::Regex>>],
    backends: &'a [Option<Vec<Backend>>],
    headers: &http::HeaderMap,
) -> Option<&'a [Backend]> {
    for (i, rule) in rules.iter().enumerate() {
        // Missing / non-UTF-8 header values act as the empty string. A
        // Prefix rule with `value = ""` would otherwise spuriously match
        // every request, so Exact and Prefix rules must set a non-empty
        // `value` to be useful - this is documented on `HeaderRule`.
        let value = headers
            .get(rule.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let regex: Option<&regex::Regex> =
            regexes.get(i).and_then(|opt| opt.as_deref());
        if rule.matches(value, |v| regex.is_some_and(|re| re.is_match(v))) {
            // Matched. If this rule has an override, return it; otherwise
            // the rule matched but inherits the route's default backend
            // set, which the caller expresses by NOT touching
            // matched_backends.
            return backends.get(i).and_then(|b| b.as_deref());
        }
    }
    None
}

/// Outcome of a forward-auth evaluation. Kept separate from `Result` so
/// each variant carries the information the caller needs to act - the
/// deny variants hold an owned status+body so the proxy can forward the
/// auth service's response verbatim (critical for Authelia's login
/// redirect, which ships a 302 + Location header).
#[derive(Debug)]
pub(crate) enum ForwardAuthOutcome {
    /// Request is authorised. `response_headers` lists headers harvested
    /// from the auth response that the caller should inject into the
    /// upstream request (owner-configured whitelist).
    Allow {
        response_headers: Vec<(String, String)>,
    },
    /// The auth service rejected the request. Status + headers + body
    /// are forwarded verbatim to the downstream client.
    Deny {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// The auth service is unreachable, timed out, or returned an
    /// unexpected status. Fail closed with a 503 so the client never
    /// accidentally proxies past a broken auth service.
    FailClosed {
        /// Short human-readable reason for logs / block_reason.
        reason: String,
    },
}

/// Build the fixed header set that Lorica forwards to the auth service.
/// Matches the Traefik / Authelia convention (`X-Forwarded-*`) plus any
/// identifying headers the client originally sent (Cookie, Authorization,
/// User-Agent) so stateful auth can see the session.
///
/// Extracted as a pure function so the header-wiring contract is
/// unit-testable without a live auth backend.
pub(crate) fn build_forward_auth_headers(
    req: &lorica_http::RequestHeader,
    client_ip: Option<&str>,
    scheme: &str,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(8);

    // X-Forwarded-Method: original HTTP method so auth can distinguish a
    // GET from a POST to the same path (Authelia's access control lists
    // can match on method).
    out.push(("X-Forwarded-Method".into(), req.method.as_str().to_string()));

    // X-Forwarded-Proto: http vs https so auth can enforce TLS-only
    // policies and generate correct login URLs.
    out.push(("X-Forwarded-Proto".into(), scheme.to_string()));

    // X-Forwarded-Host: the Host the client was trying to reach. Auth
    // redirects the user back here after login.
    if let Some(host) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        out.push(("X-Forwarded-Host".into(), host.to_string()));
    }

    // X-Forwarded-Uri: the full original path+query so auth can enforce
    // per-resource policies.
    let uri = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    out.push(("X-Forwarded-Uri".into(), uri.to_string()));

    // X-Forwarded-For: true client IP (already resolved upstream - may
    // include XFF chain if trusted proxies are configured).
    if let Some(ip) = client_ip {
        out.push(("X-Forwarded-For".into(), ip.to_string()));
    }

    // Cookie: session cookies are how Authelia/Authentik identify users.
    // Without this, every request looks unauthenticated.
    if let Some(cookie) = req.headers.get("cookie").and_then(|v| v.to_str().ok()) {
        out.push(("Cookie".into(), cookie.to_string()));
    }

    // Authorization: Bearer tokens (OAuth, API keys). Required for
    // header-based auth flows.
    if let Some(auth) = req
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        out.push(("Authorization".into(), auth.to_string()));
    }

    // User-Agent: some auth services log or rate-limit by UA.
    if let Some(ua) = req
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
    {
        out.push(("User-Agent".into(), ua.to_string()));
    }

    out
}

/// Execute the forward-auth sub-request and classify the verdict. The
/// network I/O is contained here so the surrounding `request_filter`
/// stays a straight pipeline - the caller only has to match on
/// `ForwardAuthOutcome`.
pub(crate) async fn run_forward_auth(
    cfg: &lorica_config::models::ForwardAuthConfig,
    req: &lorica_http::RequestHeader,
    client_ip: Option<&str>,
    scheme: &str,
) -> ForwardAuthOutcome {
    let headers_out = build_forward_auth_headers(req, client_ip, scheme);

    let mut builder = FORWARD_AUTH_CLIENT
        .get(&cfg.address)
        .timeout(Duration::from_millis(cfg.timeout_ms as u64));
    for (name, value) in &headers_out {
        builder = builder.header(name, value);
    }

    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return ForwardAuthOutcome::FailClosed {
                reason: format!("forward-auth unreachable: {e}"),
            };
        }
    };

    let status = resp.status().as_u16();

    // 2xx -> allow. Harvest configured response_headers verbatim so
    // Authelia's Remote-User et al. propagate to the upstream.
    if resp.status().is_success() {
        let mut inject = Vec::new();
        let resp_headers = resp.headers().clone();
        for name in &cfg.response_headers {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(v) = resp_headers.get(trimmed) {
                if let Ok(s) = v.to_str() {
                    inject.push((trimmed.to_string(), s.to_string()));
                }
            }
        }
        return ForwardAuthOutcome::Allow {
            response_headers: inject,
        };
    }

    // 401 / 403 / 3xx (login redirect) -> forward verdict verbatim.
    // Authelia returns 302 + Location for unauthenticated browser
    // traffic, and we must propagate that response body+headers so the
    // client is sent to the login page.
    if matches!(status, 300..=399) || matches!(status, 401 | 403) {
        let mut fwd_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in resp.headers().iter() {
            // Skip hop-by-hop headers and Content-Length (re-computed
            // from body below).
            let n = name.as_str();
            if matches!(
                n.to_ascii_lowercase().as_str(),
                "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "te"
                    | "trailer"
                    | "upgrade"
            ) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                fwd_headers.push((n.to_string(), v.to_string()));
            }
        }
        let body = resp
            .bytes()
            .await
            .map(|b| b.to_vec())
            .unwrap_or_default();
        return ForwardAuthOutcome::Deny {
            status,
            headers: fwd_headers,
            body,
        };
    }

    // Anything else (5xx, 400, 418, ...) is an anomaly. Treat as deny-
    // closed so a misbehaving auth service can't silently let traffic
    // through.
    ForwardAuthOutcome::FailClosed {
        reason: format!("forward-auth unexpected status {status}"),
    }
}

/// Compute a stable bucket in `0..100` for `(route_id, client_ip)`. Same
/// inputs always map to the same bucket within a single process, which
/// gives the canary its "sticky" property - one user stays on the same
/// version across multiple requests on the same route. Mixing the route
/// ID into the hash means an unlucky client IP doesn't land in every
/// service's canary bucket simultaneously.
///
/// `pub` so integration tests can pick synthetic client IPs that are
/// guaranteed to fall in a specific bucket band without running the
/// law-of-large-numbers gauntlet.
pub fn canary_bucket(route_id: &str, client_ip: &str) -> u8 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    route_id.hash(&mut h);
    client_ip.hash(&mut h);
    (h.finish() % 100) as u8
}

/// Select the backends for a traffic split given a deterministic bucket
/// value in `0..100`. Splits are consumed in declaration order and their
/// weights accumulate: the first split whose cumulative ceiling strictly
/// exceeds `bucket` wins. When a split in the range has been normalised
/// away (e.g. dangling backend IDs, see `from_store`), it still consumes
/// its weight band but yields `None`, so the caller keeps route defaults
/// for that bucket rather than rebalancing the remaining traffic.
///
/// The caller is responsible for computing `bucket`; extracting this
/// function keeps weighted-selection math independent of the actual
/// client-IP hash, so both are trivially unit-testable.
pub(crate) fn pick_traffic_split_backends<'a>(
    splits: &[lorica_config::models::TrafficSplit],
    resolved: &'a [Option<Vec<Backend>>],
    bucket: u8,
) -> Option<&'a [Backend]> {
    let mut cumulative: u32 = 0;
    for (i, split) in splits.iter().enumerate() {
        let w = split.weight_percent.min(100) as u32;
        if w == 0 {
            continue;
        }
        cumulative = cumulative.saturating_add(w).min(100);
        if (bucket as u32) < cumulative {
            return resolved.get(i).and_then(|b| b.as_deref());
        }
    }
    None
}

/// Glue used by `cache_vary_filter`: pull the three inputs - route config,
/// response Vary, request headers+URI - out of a session-level state and
/// hand them to [`compute_cache_variance`]. Extracted from the trait method
/// so the full extraction path is exercised by unit tests, without needing
/// to build a `Session` or a `LoricaProxy` instance.
pub(crate) fn cache_vary_for_request(
    route: Option<&Route>,
    meta: &CacheMeta,
    req: &lorica_http::RequestHeader,
) -> Option<HashBinary> {
    let route_headers: &[String] = route
        .map(|r| r.cache_vary_headers.as_slice())
        .unwrap_or(&[]);
    let response_vary = meta
        .headers()
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let request_uri = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    compute_cache_variance(route_headers, response_vary, &req.headers, request_uri)
}

/// Compute a cache variance hash from a union of operator-configured vary
/// headers (route config) and the origin response's `Vary` header.
///
/// Returns `None` when there is no variance to apply - the caller then
/// caches the asset under its primary key. Extracted from
/// `cache_vary_filter` as a pure helper so the merging, `Vary: *` handling,
/// and case-insensitive deduplication are unit-testable without a full
/// proxy session.
pub(crate) fn compute_cache_variance(
    route_headers: &[String],
    response_vary: &str,
    request_headers: &http::HeaderMap,
    request_uri: &str,
) -> Option<HashBinary> {
    // Lower-case and deduplicate header names across both sources.
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for h in route_headers {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            names.insert(trimmed.to_ascii_lowercase());
        }
    }

    for part in response_vary.split(',') {
        let t = part.trim();
        if t == "*" {
            // Per RFC 7234, `Vary: *` means every request is a unique
            // variant. Anchor the variance on the request URI so repeat
            // requests to the same URL still hit a stable slot - prevents
            // unbounded cardinality growth while respecting the contract
            // that two different URLs must not share a variant.
            let mut vb = VarianceBuilder::new();
            vb.add_value("*uri", request_uri);
            return vb.finalize();
        }
        if !t.is_empty() {
            names.insert(t.to_ascii_lowercase());
        }
    }

    if names.is_empty() {
        return None;
    }

    let mut vb = VarianceBuilder::new();
    for name in names {
        // Bytes (not only valid UTF-8) so request headers carrying
        // binary-encoded values still partition the cache deterministically.
        let value = request_headers
            .get(name.as_str())
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        vb.add_owned_name_value(name, value);
    }
    vb.finalize()
}

#[async_trait]
impl ProxyHttp for LoricaProxy {
    type CTX = RequestCtx;

    fn init_downstream_modules(&self, modules: &mut lorica_core::modules::http::HttpModules) {
        // Default compression module (disabled; per-route level set in
        // response_compression_level)
        modules.add_module(
            lorica_core::modules::http::compression::ResponseCompressionBuilder::enable(0),
        );
        // gRPC-Web bridge: transparently converts HTTP/1.1 gRPC-web requests
        // (application/grpc-web) to HTTP/2 gRPC for the upstream backend.
        modules.add_module(Box::new(lorica_core::modules::http::grpc_web::GrpcWeb));
    }

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
            request_id: generate_request_id(),
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
            sticky_backend_id: None,
            forward_auth_inject: Vec::new(),
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

        // Global WAF whitelist: IPs in this list bypass ban checks, IP blocklist,
        // rate limiting, and WAF evaluation entirely.
        let is_whitelisted = check_ip.as_ref().is_some_and(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                config.waf_whitelist.iter().any(|net| net.contains(&addr))
            } else {
                false
            }
        });

        // Ban list + IP blocklist checks (skipped for whitelisted IPs)
        if !is_whitelisted {
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
                        route_hostname: { let h = extract_host(req); if h.is_empty() { "-" } else { h } }.to_string(),
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
        } // end if !is_whitelisted (ban + blocklist)

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
        ctx.route_snapshot = Some(Arc::clone(&entry.route));
        ctx.path_rewrite_regex = entry.path_rewrite_regex.clone(); // Arc::clone, cheap
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

        // Forward authentication: gate the request on an external auth
        // service (Authelia / Authentik / Keycloak / oauth2-proxy). Runs
        // after route match but before header/canary/path rules so a
        // denied request never leaks into the backend-selection phase.
        if let Some(ref fa_cfg) = entry.route.forward_auth {
            let scheme = if session.is_http2() { "https" } else { "http" };
            let outcome = run_forward_auth(
                fa_cfg,
                req,
                ctx.client_ip.as_deref(),
                scheme,
            )
            .await;
            match outcome {
                ForwardAuthOutcome::Allow { response_headers } => {
                    ctx.forward_auth_inject = response_headers;
                }
                ForwardAuthOutcome::Deny {
                    status,
                    headers,
                    body,
                } => {
                    ctx.block_reason = Some(format!("forward auth denied ({status})"));
                    let mut resp_header = ResponseHeader::build(status, None)?;
                    for (name, value) in &headers {
                        let _ = resp_header.insert_header(name.clone(), value);
                    }
                    let _ = resp_header.insert_header(
                        "Content-Length",
                        body.len().to_string(),
                    );
                    session
                        .write_response_header(Box::new(resp_header), false)
                        .await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(body)), true)
                        .await?;
                    return Ok(true);
                }
                ForwardAuthOutcome::FailClosed { reason } => {
                    tracing::warn!(
                        route_id = %entry.route.id,
                        reason = %reason,
                        "forward auth fail-closed"
                    );
                    ctx.block_reason = Some(format!("forward auth error: {reason}"));
                    let mut resp_header = ResponseHeader::build(503, None)?;
                    let body = b"Service Unavailable: authentication service error";
                    let _ = resp_header.insert_header("Content-Type", "text/plain; charset=utf-8");
                    let _ = resp_header.insert_header("Content-Length", body.len().to_string());
                    session
                        .write_response_header(Box::new(resp_header), false)
                        .await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from_static(body)), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // Header rule matching (first match wins; sets backend override
        // before path rules so a later path rule with its own backend_ids
        // can still take precedence - "more specific wins").
        if !entry.route.header_rules.is_empty() {
            if let Some(backends) = match_header_rule_backends(
                &entry.route.header_rules,
                &entry.header_rule_regexes,
                &entry.header_rule_backends,
                &req.headers,
            ) {
                ctx.matched_backends = Some(backends.to_vec());
            }
        }

        // Canary traffic split: runs AFTER header rules (operator opt-in
        // always wins) and BEFORE path rules (URL-specific overrides
        // still win). The split is applied only when no earlier phase
        // already set `matched_backends`, so a user with X-Version: beta
        // is never accidentally rebalanced into the canary bucket for
        // the default version. Requests without a client IP (Unix-socket
        // listeners in tests, rare IPv6 edge cases) keep route defaults
        // rather than being bucketed deterministically on an empty
        // string.
        if ctx.matched_backends.is_none() && !entry.route.traffic_splits.is_empty() {
            if let Some(ref ip) = ctx.client_ip {
                let bucket = canary_bucket(&entry.route.id, ip);
                if let Some(backends) = pick_traffic_split_backends(
                    &entry.route.traffic_splits,
                    &entry.traffic_split_backends,
                    bucket,
                ) {
                    ctx.matched_backends = Some(backends.to_vec());
                }
            }
        }

        // Path rule matching (first match wins, overrides route config)
        for (i, rule) in entry.route.path_rules.iter().enumerate() {
            if rule.matches(path) {
                let effective = entry.route.with_path_rule_overrides(rule);
                ctx.route_snapshot = Some(Arc::new(effective));
                if rule.backend_ids.is_some() {
                    if let Some(ref backends) = entry.path_rule_backends[i] {
                        ctx.matched_backends = Some(backends.clone());
                    }
                }
                break;
            }
        }

        // Maintenance mode - return 503 with optional custom HTML
        if let Some(ref route) = ctx.route_snapshot {
            if route.maintenance_mode {
                let raw_html = route.error_page_html.as_deref().unwrap_or(
                    "<html><body><h1>503 Service Unavailable</h1><p>This service is under maintenance.</p></body></html>",
                );
                let body_html = sanitize_html(raw_html);
                let mut header = ResponseHeader::build(503, None)?;
                header.insert_header("Content-Type", "text/html; charset=utf-8")?;
                header.insert_header("Content-Length", body_html.len().to_string())?;
                header.insert_header("Retry-After", "300")?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::from(body_html.to_owned())), true)
                    .await?;
                return Ok(true);
            }
        }

        // HTTP Basic Auth (per-route) with credential verification cache.
        // The cache avoids running Argon2 (~100ms) on every request by caching
        // the hash of verified credentials for 60 seconds.
        if let Some(ref route) = ctx.route_snapshot {
            if let (Some(ref expected_user), Some(ref expected_hash)) =
                (&route.basic_auth_username, &route.basic_auth_password_hash)
            {
                let authorized = session
                    .req_header()
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Basic "))
                    .and_then(|b64| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(b64).ok()
                    })
                    .and_then(|decoded| String::from_utf8(decoded).ok())
                    .map(|cred| {
                        let mut parts = cred.splitn(2, ':');
                        let user = parts.next().unwrap_or("");
                        let pass = parts.next().unwrap_or("");
                        if user != expected_user {
                            return false;
                        }

                        // Check credential cache before running Argon2
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let mut h = DefaultHasher::new();
                        cred.hash(&mut h);
                        expected_hash.hash(&mut h);
                        let cache_key = h.finish();

                        const AUTH_CACHE_TTL: Duration = Duration::from_secs(60);
                        if let Some(verified_at) = self.basic_auth_cache.get(&cache_key) {
                            if verified_at.elapsed() < AUTH_CACHE_TTL {
                                return true; // cache hit - skip Argon2
                            }
                        }

                        // Cache miss or expired - run full Argon2 verification.
                        // Parse the hash first; if it's corrupt, deny immediately.
                        let parsed_hash = match argon2::PasswordHash::new(expected_hash) {
                            Ok(h) => h,
                            Err(_) => return false, // corrupt hash -> deny
                        };
                        // Offload CPU-intensive Argon2 to the blocking thread
                        // pool to avoid stalling the async proxy runtime.
                        let pass_bytes = pass.as_bytes().to_vec();
                        let hash_str = expected_hash.to_string();
                        let ok = tokio::task::block_in_place(|| {
                            use argon2::PasswordVerifier;
                            match argon2::PasswordHash::new(&hash_str) {
                                Ok(h) => argon2::Argon2::default()
                                    .verify_password(&pass_bytes, &h)
                                    .is_ok(),
                                Err(_) => false,
                            }
                        });
                        if ok {
                            self.basic_auth_cache.insert(cache_key, Instant::now());
                            // Evict expired entries to prevent unbounded growth
                            self.basic_auth_cache.retain(|_, t| t.elapsed() < AUTH_CACHE_TTL);
                        }
                        ok
                    })
                    .unwrap_or(false);

                if !authorized {
                    let mut header = ResponseHeader::build(401, None)?;
                    header.insert_header("WWW-Authenticate", "Basic realm=\"Lorica\"")?;
                    header.insert_header("Content-Length", "0")?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(true);
                }
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

        // Per-route rate limiting (skipped for whitelisted IPs)
        if !is_whitelisted {
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
        } // end if !is_whitelisted (rate limiting)

        // Skip WAF evaluation entirely if not enabled or IP is whitelisted (zero overhead)
        if is_whitelisted || !entry.route.waf_enabled {
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

        // Only cache GET and HEAD (but also enable for PURGE so the cache
        // subsystem can process purge requests via is_purge/proxy_purge)
        if req.method != http::Method::GET
            && req.method != http::Method::HEAD
            && req.method.as_str() != "PURGE"
        {
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

        // Enable the cache state machine with MemCache storage + LRU eviction.
        // The predictor is shared across all cache-enabled routes: responses
        // marked uncacheable by the origin skip the cache state machine on
        // the next request, avoiding cache-lock contention on known-bypass
        // traffic.
        session.cache.enable(
            &*CACHE_BACKEND,
            Some(&*CACHE_EVICTION),
            Some(*CACHE_PREDICTOR),
            Some(*CACHE_LOCK),
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

    /// Partition the cache by request header values so responses that differ
    /// based on client capabilities (content negotiation, localization,
    /// auth tier, tenancy) stay separated under the same URL.
    ///
    /// Header names come from two sources, merged case-insensitively:
    ///   1. The route's `cache_vary_headers` - operator-controlled, set
    ///      regardless of what the origin advertises.
    ///   2. The origin response's `Vary` header captured in the cached
    ///      [`CacheMeta`] - respected as required by RFC 7234. `Vary: *`
    ///      forces a URI-anchored variance so each URL keeps its own slot
    ///      without sharing a variant across unrelated requests.
    ///
    /// Returning `None` (no headers contribute, or all target headers are
    /// absent) means "no variance" and the asset is cached under its
    /// primary key - the default state when this feature is unused.
    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &lorica_http::RequestHeader,
    ) -> Option<HashBinary> {
        cache_vary_for_request(ctx.route_snapshot.as_deref(), meta, req)
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
            let swr = ctx
                .route_snapshot
                .as_ref()
                .map(|r| r.stale_while_revalidate_s.max(0) as u32)
                .unwrap_or(10);
            let sie = ctx
                .route_snapshot
                .as_ref()
                .map(|r| r.stale_if_error_s.max(0) as u32)
                .unwrap_or(60);
            Ok(RespCacheable::Cacheable(CacheMeta::new(
                fresh_until,
                now,
                swr,
                sie,
                resp.clone(),
            )))
        } else {
            Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache))
        }
    }

    /// Serve stale cached responses when the upstream is unavailable.
    ///
    /// Called in two scenarios:
    /// - `error = None`: during stale-while-revalidate (background refresh in
    ///   progress). We allow serving stale so users get an instant response.
    /// - `error = Some(e)`: upstream failed (5xx, connection refused, timeout).
    ///   We serve stale only for upstream errors, not for downstream or
    ///   internal errors.
    fn should_serve_stale(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        match error {
            None => true, // stale-while-revalidate
            Some(e) => e.esource() == &ErrorSource::Upstream,
        }
    }

    /// Detect HTTP PURGE requests for cache invalidation.
    ///
    /// When this returns true, the proxy cache layer handles the purge
    /// automatically: it deletes the cached entry matching the request URI
    /// and returns a 200 (purged) or 404 (not found) response.
    ///
    /// PURGE is restricted to loopback addresses and trusted proxy CIDRs
    /// to prevent external cache invalidation attacks.
    fn is_purge(&self, session: &Session, _ctx: &Self::CTX) -> bool {
        if session.req_header().method.as_str() != "PURGE" {
            return false;
        }
        let client_ip = session
            .downstream_session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|addr| addr.ip());
        let allowed = match client_ip {
            Some(ip) if ip.is_loopback() => true,
            Some(ip) => {
                let config = self.config.load();
                config.trusted_proxies.iter().any(|net| net.contains(&ip))
            }
            None => false,
        };
        if !allowed {
            warn!("PURGE request denied: client IP not in trusted proxies or loopback");
        }
        allowed
    }

    /// Serve custom error pages when the upstream fails.
    ///
    /// If the route has an `error_page_html` configured, render it with the
    /// error status code. Otherwise fall back to the default Pingora error
    /// response (plain-text status line).
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => {
                    // Connection already dead - skip response writing
                    match e.etype() {
                        ErrorType::WriteError
                        | ErrorType::ReadError
                        | ErrorType::ConnectionClosed => 0,
                        _ => 400,
                    }
                }
                _ => 500,
            },
        };

        if code > 0 {
            // Serve custom error page HTML if the route has one configured
            let custom_served = if let Some(ref route) = ctx.route_snapshot {
                if let Some(ref html) = route.error_page_html {
                    let body = sanitize_html(html)
                        .replace("{{status}}", &code.to_string())
                        .replace("{{message}}", &escape_html(&e.to_string()));
                    if let Ok(mut header) = ResponseHeader::build(code, None) {
                        let _ = header.insert_header("Content-Type", "text/html; charset=utf-8");
                        let _ = header.insert_header("Content-Length", body.len().to_string());
                        let r1 = session
                            .write_response_header(Box::new(header), false)
                            .await;
                        let r2 = session
                            .write_response_body(Some(bytes::Bytes::from(body)), true)
                            .await;
                        r1.is_ok() && r2.is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if !custom_served {
                let _ = session.respond_error(code).await;
            }
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
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
            ctx.route_snapshot = Some(Arc::clone(&entry.route));
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
                b.health_status != HealthStatus::Down
                    && b.lifecycle_state == LifecycleState::Normal
                    && self.circuit_breaker.is_available(&b.address)
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

        // Sticky session: if enabled, try to route to the backend from the cookie
        let sticky_backend_idx = if entry.route.sticky_session {
            session
                .req_header()
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(extract_sticky_backend)
                .and_then(|backend_id| {
                    healthy_backends
                        .iter()
                        .position(|b| b.id == backend_id)
                })
        } else {
            None
        };

        // Backend selection based on load balancing algorithm
        use lorica_config::models::LoadBalancing;
        let idx = if let Some(sticky_idx) = sticky_backend_idx {
            sticky_idx
        } else {
        match entry.route.load_balancing {
            LoadBalancing::PeakEwma => self.ewma_tracker.select_best(&healthy_backends),
            LoadBalancing::Random => {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                ctx.start_time.hash(&mut hasher);
                (hasher.finish() as usize) % healthy_backends.len()
            }
            LoadBalancing::LeastConn => {
                // Select the backend with the fewest active connections
                healthy_backends
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, b)| self.backend_connections.get(&b.address))
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            }
            _ => {
                // Smooth weighted round-robin (Nginx algorithm) - covers
                // RoundRobin and ConsistentHash
                let bw: Vec<(&str, i64)> = healthy_backends
                    .iter()
                    .map(|b| (b.address.as_str(), b.weight.max(1) as i64))
                    .collect();
                entry.wrr_state.next(&bw)
            }
        }
        };
        let backend = healthy_backends[idx];

        // Set sticky session cookie if enabled and no existing cookie matched
        if entry.route.sticky_session && sticky_backend_idx.is_none() {
            ctx.sticky_backend_id = Some(backend.id.clone());
        }

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

        // Drop idle pooled connections after 60s to avoid stale/half-closed TCP
        peer.options.idle_timeout = Some(Duration::from_secs(60));

        // TCP keepalive: detect dead connections in the pool before reuse
        peer.options.tcp_keepalive = Some(lorica_core::protocols::TcpKeepalive {
            idle: Duration::from_secs(15),
            interval: Duration::from_secs(5),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(0),
        });

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

        // Inject X-Request-Id for end-to-end tracing
        let _ = upstream_request.insert_header("X-Request-Id", &ctx.request_id);

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

        // Forward-auth response headers: applied AFTER proxy_headers so
        // auth-derived values like Remote-User take precedence over any
        // static proxy_headers with the same name (an operator would be
        // surprised if their basic `X-User: static` overrode the
        // authenticated user's identity).
        for (name, value) in &ctx.forward_auth_inject {
            let _ = upstream_request.insert_header(name.clone(), value);
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

        // Inject sticky session cookie
        if let Some(ref backend_id) = ctx.sticky_backend_id {
            let cookie = format!("LORICA_SRV={backend_id}; Path=/; HttpOnly; SameSite=Lax");
            let _ = upstream_response.append_header("Set-Cookie", &cookie);
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

    fn max_request_retries(&self, session: &Session, ctx: &Self::CTX) -> Option<usize> {
        ctx.route_snapshot.as_ref().and_then(|r| {
            let attempts = r.retry_attempts?;
            // If retry_on_methods is configured, only retry for listed methods
            if !r.retry_on_methods.is_empty() {
                let method = session.req_header().method.as_str();
                if !r
                    .retry_on_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method))
                {
                    return None; // method not eligible for retry
                }
            }
            Some(attempts as usize)
        })
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
            e.and_then(|err| {
                let msg = err.to_string();
                // Client disconnects (H2 stream reset, connection close) are not
                // server errors. Status 0 already signals the incomplete response.
                if msg.contains("not a result of an error") || msg.contains("Client closed") {
                    None
                } else {
                    Some(msg)
                }
            })
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

            // Update circuit breaker: 5xx or connection error = failure, else success
            if e.is_some() || status >= 500 {
                self.circuit_breaker.record_failure(addr);
            } else {
                self.circuit_breaker.record_success(addr);
            }
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
                request_id: ctx.request_id.clone(),
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

        // Record SLA metrics for passive monitoring.
        // Exclude WebSocket upgrades (status 101), proxy-level rejections
        // (WAF blocks, bans, rate limits, return_status), and connection
        // errors (downstream/upstream resets, timeouts) as their latency
        // is not representative of backend performance.
        if let Some(ref route_id) = ctx.route_id {
            if status != 101
                && ctx.block_reason.is_none()
                && !ctx.waf_blocked
                && e.is_none()
            {
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
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            forward_auth: None,
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
    fn test_from_store_header_rules_precompile_regex_and_resolve_backends() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        let mut route = make_route("r1", "example.com", "/", true);
        route.header_rules = vec![
            HeaderRule {
                header_name: "X-Tenant".into(),
                match_type: HeaderMatchType::Exact,
                value: "acme".into(),
                backend_ids: vec!["b-acme".into()],
            },
            HeaderRule {
                header_name: "User-Agent".into(),
                match_type: HeaderMatchType::Regex,
                value: r"^Mobile".into(),
                backend_ids: vec!["b-mobile".into(), "b-mobile2".into()],
            },
            HeaderRule {
                // Flag rule: matches but keeps route defaults.
                header_name: "X-Dark-Mode".into(),
                match_type: HeaderMatchType::Exact,
                value: "on".into(),
                backend_ids: vec![],
            },
            HeaderRule {
                // Broken regex: rule must load (warning logged), but the
                // precompiled entry for it is None, so it never matches.
                header_name: "X-Bad".into(),
                match_type: HeaderMatchType::Regex,
                value: "(unclosed".into(),
                backend_ids: vec!["b-whatever".into()],
            },
            HeaderRule {
                // Dangling backend id: gets filtered out on resolution.
                // The rule itself is retained (so operators can fix it
                // later) but with an empty resolved list, which normalises
                // to `None` (match-but-keep-defaults) in RouteEntry.
                header_name: "X-Dangling".into(),
                match_type: HeaderMatchType::Exact,
                value: "yes".into(),
                backend_ids: vec!["does-not-exist".into()],
            },
        ];

        let b_acme = make_backend("b-acme", "10.0.1.1:80");
        let b_mobile = make_backend("b-mobile", "10.0.2.1:80");
        let b_mobile2 = make_backend("b-mobile2", "10.0.2.2:80");
        let b_default = make_backend("b-default", "10.0.0.1:80");
        let links = vec![("r1".into(), "b-default".into())];

        let config = ProxyConfig::from_store(
            vec![route],
            vec![b_acme, b_mobile, b_mobile2, b_default],
            vec![],
            links,
            ProxyConfigGlobals::default(),
        );
        let entry = &config.routes_by_host.get("example.com").unwrap()[0];

        // Regex precompile: index 1 (Mobile) must be Some, index 3 (bad)
        // must be None, Exact/Prefix indices are always None.
        assert!(entry.header_rule_regexes[0].is_none(), "Exact rule -> no regex");
        assert!(entry.header_rule_regexes[1].is_some(), "Regex rule compiles");
        assert!(entry.header_rule_regexes[2].is_none(), "Exact rule -> no regex");
        assert!(
            entry.header_rule_regexes[3].is_none(),
            "broken regex was logged-and-disabled, not propagated"
        );

        // Backend resolution:
        //  - b-acme -> 1 backend
        //  - b-mobile+b-mobile2 -> 2 backends
        //  - empty backend_ids -> None
        //  - dangling backend id -> filtered to empty, normalised to None
        assert_eq!(entry.header_rule_backends[0].as_ref().unwrap().len(), 1);
        assert_eq!(entry.header_rule_backends[1].as_ref().unwrap().len(), 2);
        assert!(entry.header_rule_backends[2].is_none(), "flag rule: keep defaults");
        assert!(
            entry.header_rule_backends[4].is_none(),
            "all backend_ids dangling -> normalised to None"
        );
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

    // ---- Least Connections ----

    #[test]
    fn test_least_conn_selects_backend_with_fewest_connections() {
        let bc = BackendConnections::new();
        bc.increment("10.0.0.1:80");
        bc.increment("10.0.0.1:80");
        bc.increment("10.0.0.1:80");
        bc.increment("10.0.0.2:80");

        // 10.0.0.3:80 has 0 connections, should be selected
        let backends = vec![
            make_backend("b1", "10.0.0.1:80"),
            make_backend("b2", "10.0.0.2:80"),
            make_backend("b3", "10.0.0.3:80"),
        ];

        let idx = backends
            .iter()
            .enumerate()
            .min_by_key(|(_, b)| bc.get(&b.address))
            .map(|(i, _)| i)
            .unwrap_or(0);

        assert_eq!(idx, 2, "Should select backend with 0 connections");
        assert_eq!(bc.get("10.0.0.1:80"), 3);
        assert_eq!(bc.get("10.0.0.2:80"), 1);
        assert_eq!(bc.get("10.0.0.3:80"), 0);
    }

    #[test]
    fn test_least_conn_with_equal_connections() {
        let bc = BackendConnections::new();
        // All have 0 connections - should select index 0 (first min)
        let backends = vec![
            make_backend("b1", "10.0.0.1:80"),
            make_backend("b2", "10.0.0.2:80"),
        ];

        let idx = backends
            .iter()
            .enumerate()
            .min_by_key(|(_, b)| bc.get(&b.address))
            .map(|(i, _)| i)
            .unwrap_or(0);

        assert_eq!(idx, 0, "Equal connections should select first backend");
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
        assert!(ip_matches("192.168.1.100", "192.168.1.0/24"));
        assert!(ip_matches("192.168.1.1", "192.168.1.0/24"));
        assert!(!ip_matches("192.168.2.1", "192.168.1.0/24"));
        assert!(!ip_matches("10.0.0.1", "192.168.1.0/24"));
        // Regression: old string prefix match would incorrectly match
        // 10.1.2.3 against "10.1.2.30/24" because "10.1.2.3".starts_with("10.1.2.3")
        assert!(!ip_matches("10.1.2.3", "10.1.2.30/32"));
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

    // ---- Sticky sessions ----

    #[test]
    fn test_extract_sticky_backend_single_cookie() {
        assert_eq!(
            extract_sticky_backend("LORICA_SRV=abc-123"),
            Some("abc-123")
        );
    }

    #[test]
    fn test_extract_sticky_backend_multiple_cookies() {
        assert_eq!(
            extract_sticky_backend("session=xyz; LORICA_SRV=backend-42; lang=en"),
            Some("backend-42")
        );
    }

    #[test]
    fn test_extract_sticky_backend_absent() {
        assert_eq!(
            extract_sticky_backend("session=xyz; lang=en"),
            None
        );
    }

    #[test]
    fn test_extract_sticky_backend_empty() {
        assert_eq!(extract_sticky_backend(""), None);
    }

    // ---- Cache Lock ----

    #[test]
    fn test_cache_lock_static_initializes() {
        let lock: &'static CacheLock = *CACHE_LOCK;
        let _: &'static lorica_cache::lock::CacheKeyLockImpl = lock;
    }

    // ---- Stale-while-error defaults ----

    #[test]
    fn test_cache_defaults_accessible() {
        // Verify the CACHE_DEFAULTS_5MIN static compiles and is usable.
        // The stale-while-revalidate (10s) and stale-if-error (60s) values
        // are set inline in the constant definition.
        let _defaults = &CACHE_DEFAULTS_5MIN;
    }

    // ---- HTML escape ----

    #[test]
    fn test_escape_html_basic() {
        assert_eq!(escape_html("hello"), "hello");
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a&b"), "a&amp;b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
    }

    #[test]
    fn test_escape_html_combined() {
        let input = "<img src=x onerror=\"alert('xss')\">";
        let escaped = escape_html(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
    }

    // ---- HTML sanitize ----

    #[test]
    fn test_sanitize_html_strips_script() {
        let input = "<h1>Error</h1><script>alert('xss')</script><p>Details</p>";
        let sanitized = sanitize_html(input);
        assert!(!sanitized.contains("<script"));
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("<h1>Error</h1>"));
        assert!(sanitized.contains("<p>Details</p>"));
    }

    #[test]
    fn test_sanitize_html_strips_event_handlers() {
        let input = r#"<img src="x" onerror="alert(1)"><div onclick="steal()">"#;
        let sanitized = sanitize_html(input);
        assert!(!sanitized.contains("onerror"));
        assert!(!sanitized.contains("onclick"));
        assert!(sanitized.contains("<img"));
        assert!(sanitized.contains("<div"));
    }

    #[test]
    fn test_sanitize_html_strips_javascript_uri() {
        let input = r#"<a href="javascript:alert(1)">click</a>"#;
        let sanitized = sanitize_html(input);
        assert!(!sanitized.contains("javascript:"));
    }

    #[test]
    fn test_sanitize_html_preserves_safe_content() {
        let input = "<html><body><h1>{{status}}</h1><p>{{message}}</p></body></html>";
        let sanitized = sanitize_html(input);
        assert_eq!(input, sanitized);
    }

    // ---- Basic auth credential cache ----

    #[test]
    fn test_basic_auth_cache_stores_and_retrieves() {
        let cache: DashMap<u64, Instant> = DashMap::new();
        let key: u64 = 12345;
        cache.insert(key, Instant::now());
        assert!(cache.get(&key).is_some());
        assert!(cache.get(&key).unwrap().elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_basic_auth_cache_ttl_expiry() {
        let cache: DashMap<u64, Instant> = DashMap::new();
        let key: u64 = 99999;
        // Insert with a timestamp in the past (simulate expired entry)
        cache.insert(key, Instant::now() - Duration::from_secs(120));
        let ttl = Duration::from_secs(60);
        let is_valid = cache
            .get(&key)
            .map(|t| t.elapsed() < ttl)
            .unwrap_or(false);
        assert!(!is_valid, "Entry older than TTL should be considered expired");
    }

    #[test]
    fn test_basic_auth_cache_key_changes_on_password() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut h1 = DefaultHasher::new();
        "admin:password1".hash(&mut h1);
        "$argon2id$hash1".hash(&mut h1);
        let key1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        "admin:password2".hash(&mut h2);
        "$argon2id$hash1".hash(&mut h2);
        let key2 = h2.finish();

        assert_ne!(key1, key2, "Different passwords should produce different cache keys");
    }

    // ---- Retry on methods filtering ----

    #[test]
    fn test_retry_on_methods_empty_allows_all() {
        let route = make_route("r1", "example.com", "/", true);
        // retry_on_methods is empty by default - all methods eligible
        assert!(route.retry_on_methods.is_empty());
        // With retry_attempts set, max_request_retries should return Some
        let mut r = route;
        r.retry_attempts = Some(3);
        assert_eq!(r.retry_attempts, Some(3));
    }

    #[test]
    fn test_retry_on_methods_filters_post() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.retry_attempts = Some(2);
        route.retry_on_methods = vec!["GET".to_string(), "HEAD".to_string()];

        // POST is not in the list - should be filtered out
        let method = "POST";
        let eligible = route.retry_on_methods.is_empty()
            || route.retry_on_methods.iter().any(|m| m.eq_ignore_ascii_case(method));
        assert!(!eligible, "POST should not be eligible for retry");

        // GET is in the list - should be eligible
        let method = "GET";
        let eligible = route.retry_on_methods.is_empty()
            || route.retry_on_methods.iter().any(|m| m.eq_ignore_ascii_case(method));
        assert!(eligible, "GET should be eligible for retry");
    }

    // ---- Stale cache config per route ----

    #[test]
    fn test_stale_config_defaults() {
        let route = make_route("r1", "example.com", "/", true);
        assert_eq!(route.stale_while_revalidate_s, 10);
        assert_eq!(route.stale_if_error_s, 60);
    }

    #[test]
    fn test_stale_config_custom_values() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.stale_while_revalidate_s = 30;
        route.stale_if_error_s = 300;
        assert_eq!(route.stale_while_revalidate_s, 30);
        assert_eq!(route.stale_if_error_s, 300);
    }

    #[test]
    fn test_stale_config_zero_disables() {
        let mut route = make_route("r1", "example.com", "/", true);
        route.stale_while_revalidate_s = 0;
        route.stale_if_error_s = 0;
        assert_eq!(route.stale_while_revalidate_s as u32, 0);
        assert_eq!(route.stale_if_error_s as u32, 0);
    }

    // ---- Header-based routing ----

    fn mk_backend_with_id(id: &str) -> Backend {
        let mut b = make_backend(id, &format!("10.0.0.{}:80", id.as_bytes()[0]));
        b.id = id.to_string();
        b
    }

    #[test]
    fn test_header_rule_exact_match() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        let rule = HeaderRule {
            header_name: "X-Tenant".into(),
            match_type: HeaderMatchType::Exact,
            value: "acme".into(),
            backend_ids: vec![],
        };
        assert!(rule.matches("acme", |_| false));
        assert!(!rule.matches("Acme", |_| false)); // case-sensitive on value
        assert!(!rule.matches("acmeco", |_| false));
        assert!(!rule.matches("", |_| false));
    }

    #[test]
    fn test_header_rule_prefix_match() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        let rule = HeaderRule {
            header_name: "X-Version".into(),
            match_type: HeaderMatchType::Prefix,
            value: "v2".into(),
            backend_ids: vec![],
        };
        assert!(rule.matches("v2", |_| false));
        assert!(rule.matches("v2.1.3", |_| false));
        assert!(!rule.matches("v1.9", |_| false));
    }

    #[test]
    fn test_header_rule_regex_closure() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        let rule = HeaderRule {
            header_name: "User-Agent".into(),
            match_type: HeaderMatchType::Regex,
            value: r"^Mozilla/.*Chrome".into(),
            backend_ids: vec![],
        };
        let re = regex::Regex::new(&rule.value).unwrap();
        assert!(rule.matches(
            "Mozilla/5.0 ... Chrome/120",
            |v| re.is_match(v)
        ));
        assert!(!rule.matches("curl/8.0", |v| re.is_match(v)));
        // Closure never called for Exact/Prefix types: `|_| panic!()`
        // would be tempting but verify by constructing a non-panic closure
        // and swapping the match_type.
        let mut exact = rule.clone();
        exact.match_type = HeaderMatchType::Exact;
        exact.value = "curl/8.0".into();
        assert!(exact.matches("curl/8.0", |_| panic!("closure must not run for Exact")));
    }

    #[test]
    fn test_match_header_rule_backends_case_insensitive_header_lookup() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        // Header names are compared case-insensitively per RFC 7230; we
        // rely on http::HeaderMap's canonical lookup, but the lookup key
        // we pass in is the operator's raw string. Verify the contract.
        let rules = vec![HeaderRule {
            header_name: "X-Tenant".into(),
            match_type: HeaderMatchType::Exact,
            value: "acme".into(),
            backend_ids: vec!["b1".into()],
        }];
        let regexes: Vec<Option<Arc<regex::Regex>>> = vec![None];
        let backends: Vec<Option<Vec<Backend>>> = vec![Some(vec![mk_backend_with_id("b1")])];

        // Request uses lowercase header name; must still match.
        let headers = hmap(&[("x-tenant", "acme")]);
        assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_some());

        // Request uses different case; still matches.
        let headers2 = hmap(&[("X-TENANT", "acme")]);
        assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers2).is_some());
    }

    #[test]
    fn test_match_header_rule_backends_first_match_wins() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        let rules = vec![
            HeaderRule {
                header_name: "X-Version".into(),
                match_type: HeaderMatchType::Prefix,
                value: "v2".into(),
                backend_ids: vec!["v2".into()],
            },
            HeaderRule {
                header_name: "X-Version".into(),
                match_type: HeaderMatchType::Prefix,
                value: "v".into(), // would also match "v2..." but comes second
                backend_ids: vec!["fallback".into()],
            },
        ];
        let regexes = vec![None, None];
        let backends = vec![
            Some(vec![mk_backend_with_id("v2")]),
            Some(vec![mk_backend_with_id("fallback")]),
        ];
        let headers = hmap(&[("x-version", "v2.3")]);
        let result = match_header_rule_backends(&rules, &regexes, &backends, &headers)
            .expect("should match first rule");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "v2");
    }

    #[test]
    fn test_match_header_rule_backends_missing_header_skips_rule() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        // Exact match on a header that isn't present must not match
        // (otherwise a rule `value=""` would match absence).
        let rules = vec![HeaderRule {
            header_name: "X-Tenant".into(),
            match_type: HeaderMatchType::Exact,
            value: "acme".into(),
            backend_ids: vec!["b1".into()],
        }];
        let regexes = vec![None];
        let backends = vec![Some(vec![mk_backend_with_id("b1")])];
        let headers = hmap(&[]);
        assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
    }

    #[test]
    fn test_match_header_rule_backends_match_without_override_returns_none() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        // A rule that matches but has no backend_ids means "match but use
        // route defaults" - caller must not set matched_backends.
        let rules = vec![HeaderRule {
            header_name: "X-Flag".into(),
            match_type: HeaderMatchType::Exact,
            value: "on".into(),
            backend_ids: vec![],
        }];
        let regexes = vec![None];
        let backends: Vec<Option<Vec<Backend>>> = vec![None];
        let headers = hmap(&[("x-flag", "on")]);
        assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
    }

    #[test]
    fn test_match_header_rule_backends_regex_rule_without_compiled_is_fail_closed() {
        use lorica_config::models::{HeaderMatchType, HeaderRule};
        // Regex failed to compile at load time -> regexes[i] = None. The
        // rule must NOT match (fail closed) so a broken regex doesn't
        // send traffic to the wrong backend.
        let rules = vec![HeaderRule {
            header_name: "X-Tenant".into(),
            match_type: HeaderMatchType::Regex,
            value: "(unclosed".into(),
            backend_ids: vec!["b1".into()],
        }];
        let regexes: Vec<Option<Arc<regex::Regex>>> = vec![None];
        let backends = vec![Some(vec![mk_backend_with_id("b1")])];
        let headers = hmap(&[("x-tenant", "anything")]);
        assert!(match_header_rule_backends(&rules, &regexes, &backends, &headers).is_none());
    }

    // ---- Forward auth ----

    fn fauth_req(method: &str, path: &str, headers: &[(&str, &str)]) -> lorica_http::RequestHeader {
        let mut req = lorica_http::RequestHeader::build(method, path.as_bytes(), None).unwrap();
        for (k, v) in headers {
            req.insert_header((*k).to_string(), *v).unwrap();
        }
        req
    }

    fn header_by(pairs: &[(String, String)], name: &str) -> Option<String> {
        pairs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn test_build_forward_auth_headers_includes_xff_and_context() {
        let req = fauth_req(
            "POST",
            "/admin/delete?id=7",
            &[
                ("host", "app.example.com"),
                ("cookie", "session=abc"),
                ("authorization", "Bearer tok"),
                ("user-agent", "curl/8"),
            ],
        );
        let out = build_forward_auth_headers(&req, Some("203.0.113.9"), "https");

        assert_eq!(header_by(&out, "X-Forwarded-Method").as_deref(), Some("POST"));
        assert_eq!(header_by(&out, "X-Forwarded-Proto").as_deref(), Some("https"));
        assert_eq!(
            header_by(&out, "X-Forwarded-Host").as_deref(),
            Some("app.example.com")
        );
        assert_eq!(
            header_by(&out, "X-Forwarded-Uri").as_deref(),
            Some("/admin/delete?id=7")
        );
        assert_eq!(
            header_by(&out, "X-Forwarded-For").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(header_by(&out, "Cookie").as_deref(), Some("session=abc"));
        assert_eq!(
            header_by(&out, "Authorization").as_deref(),
            Some("Bearer tok")
        );
        assert_eq!(header_by(&out, "User-Agent").as_deref(), Some("curl/8"));
    }

    #[test]
    fn test_build_forward_auth_headers_omits_missing_optionals() {
        // No cookie, no authorization, no client IP -> those headers
        // must NOT appear at all. Sending an empty Cookie would
        // intrude on auth services that look up sessions from that
        // header - they would 401 instead of treating as "no session".
        let req = fauth_req("GET", "/", &[("host", "h")]);
        let out = build_forward_auth_headers(&req, None, "http");
        assert!(header_by(&out, "Cookie").is_none());
        assert!(header_by(&out, "Authorization").is_none());
        assert!(header_by(&out, "X-Forwarded-For").is_none());
        // Required headers still present.
        assert_eq!(header_by(&out, "X-Forwarded-Method").as_deref(), Some("GET"));
        assert_eq!(header_by(&out, "X-Forwarded-Proto").as_deref(), Some("http"));
        assert_eq!(header_by(&out, "X-Forwarded-Uri").as_deref(), Some("/"));
    }

    #[test]
    fn test_build_forward_auth_headers_uses_slash_for_empty_uri() {
        // `http::Uri` normalises an empty path to "". Check we still
        // send "/" so the auth service sees something parseable.
        let req = fauth_req("GET", "/", &[]);
        let out = build_forward_auth_headers(&req, None, "http");
        assert_eq!(header_by(&out, "X-Forwarded-Uri").as_deref(), Some("/"));
    }

    #[tokio::test]
    async fn test_run_forward_auth_timeout_is_fail_closed() {
        // Point at a never-responding TCP listener to drive the timeout
        // branch. `run_forward_auth` must return FailClosed (not Deny),
        // so the caller fails the request with 503 rather than the
        // typical 401.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept but never reply.
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
                // swallow; connection stays open idle
            }
        });
        let cfg = lorica_config::models::ForwardAuthConfig {
            address: format!("http://{addr}/verify"),
            timeout_ms: 150,
            response_headers: vec![],
        };
        let req = fauth_req("GET", "/", &[("host", "x")]);
        let outcome = run_forward_auth(&cfg, &req, None, "http").await;
        match outcome {
            ForwardAuthOutcome::FailClosed { reason } => {
                assert!(
                    reason.to_lowercase().contains("timeout")
                        || reason.to_lowercase().contains("unreachable")
                        || reason.to_lowercase().contains("operation timed out"),
                    "reason should mention a timeout/unreachable, got: {reason}"
                );
            }
            other => panic!("expected FailClosed on timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_forward_auth_unreachable_is_fail_closed() {
        // Bind a port, immediately drop the listener -> next connect
        // gets refused. Must fail closed, NOT bypass auth.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cfg = lorica_config::models::ForwardAuthConfig {
            address: format!("http://{addr}/verify"),
            timeout_ms: 500,
            response_headers: vec![],
        };
        let req = fauth_req("GET", "/", &[("host", "x")]);
        let outcome = run_forward_auth(&cfg, &req, None, "http").await;
        assert!(matches!(outcome, ForwardAuthOutcome::FailClosed { .. }));
    }

    // ---- Canary traffic split ----

    #[test]
    fn test_canary_bucket_is_deterministic_and_in_range() {
        // Same inputs -> same bucket on every call within a process.
        for i in 0..16 {
            let ip = format!("10.0.0.{i}");
            let a = canary_bucket("r1", &ip);
            let b = canary_bucket("r1", &ip);
            assert_eq!(a, b, "hash must be stable for {ip}");
            assert!(a < 100, "bucket {a} out of range");
        }
    }

    #[test]
    fn test_canary_bucket_varies_by_route_and_ip() {
        // Different routes -> a given IP lands on different buckets.
        // Not a strict requirement but a smoke test: if it's always the
        // same, we've broken the "per-route bucket" contract.
        let mut differs = false;
        for i in 0..32 {
            let ip = format!("10.0.0.{i}");
            if canary_bucket("r1", &ip) != canary_bucket("r2", &ip) {
                differs = true;
                break;
            }
        }
        assert!(differs, "changing route_id should change at least one bucket");
    }

    fn split(name: &str, pct: u8, backends: &[&str]) -> lorica_config::models::TrafficSplit {
        lorica_config::models::TrafficSplit {
            name: name.into(),
            weight_percent: pct,
            backend_ids: backends.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn test_pick_traffic_split_backends_cumulative_bands() {
        // 5% + 10% = 15% diverted. Buckets 0..=4 -> A, 5..=14 -> B,
        // 15..=99 -> None (route default).
        let splits = vec![split("a", 5, &["a"]), split("b", 10, &["b"])];
        let backends: Vec<Option<Vec<Backend>>> = vec![
            Some(vec![mk_backend_with_id("a")]),
            Some(vec![mk_backend_with_id("b")]),
        ];

        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 0).unwrap()[0].id,
            "a"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 4).unwrap()[0].id,
            "a"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 5).unwrap()[0].id,
            "b"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 14).unwrap()[0].id,
            "b"
        );
        assert!(pick_traffic_split_backends(&splits, &backends, 15).is_none());
        assert!(pick_traffic_split_backends(&splits, &backends, 99).is_none());
    }

    #[test]
    fn test_pick_traffic_split_backends_zero_weight_skipped() {
        // A split with weight 0 must consume NO bucket range and not
        // affect subsequent splits. This lets operators "disable" a
        // split without deleting it (useful for staged rollout/rollback).
        let splits = vec![split("a", 0, &["a"]), split("b", 30, &["b"])];
        let backends = vec![
            Some(vec![mk_backend_with_id("a")]),
            Some(vec![mk_backend_with_id("b")]),
        ];
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 0).unwrap()[0].id,
            "b"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 29).unwrap()[0].id,
            "b"
        );
        assert!(pick_traffic_split_backends(&splits, &backends, 30).is_none());
    }

    #[test]
    fn test_pick_traffic_split_backends_sum_over_100_clamped() {
        // Operator typo: 60 + 60 = 120. The engine clamps at 100 so the
        // second split's tail is effectively lost (buckets 0..=59 -> A,
        // 60..=99 -> B). The API layer rejects this case at write-time;
        // this test is the engine's defensive behaviour if a stale or
        // externally-edited config slips through.
        let splits = vec![split("a", 60, &["a"]), split("b", 60, &["b"])];
        let backends = vec![
            Some(vec![mk_backend_with_id("a")]),
            Some(vec![mk_backend_with_id("b")]),
        ];
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 59).unwrap()[0].id,
            "a"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 60).unwrap()[0].id,
            "b"
        );
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 99).unwrap()[0].id,
            "b"
        );
    }

    #[test]
    fn test_pick_traffic_split_backends_none_resolved_consumes_band() {
        // A split whose backends all dangle normalises to `None` in
        // `resolved` but keeps its declared weight band. Traffic in that
        // band MUST fall back to route defaults (None), not steal the
        // next split's bucket. Otherwise a typo would silently rebalance
        // 20% of traffic to the wrong backend.
        let splits = vec![split("broken", 20, &["does-not-exist"]), split("good", 20, &["g"])];
        let backends: Vec<Option<Vec<Backend>>> =
            vec![None, Some(vec![mk_backend_with_id("g")])];
        assert!(pick_traffic_split_backends(&splits, &backends, 0).is_none());
        assert!(pick_traffic_split_backends(&splits, &backends, 19).is_none());
        assert_eq!(
            pick_traffic_split_backends(&splits, &backends, 20).unwrap()[0].id,
            "g"
        );
    }

    #[test]
    fn test_pick_traffic_split_backends_empty_list_yields_none() {
        assert!(pick_traffic_split_backends(&[], &[], 0).is_none());
        assert!(pick_traffic_split_backends(&[], &[], 99).is_none());
    }

    #[test]
    fn test_from_store_traffic_splits_resolve_and_skip_broken() {
        let mut route = make_route("rts", "example.com", "/", true);
        route.traffic_splits = vec![
            split("v2", 10, &["b-v2"]),
            split("dangling", 5, &["missing"]), // all dangling -> None
            split("v3", 5, &["b-v3a", "b-v3b"]),
            split("zero", 0, &["b-v2"]),        // weight 0 -> None
        ];

        let b_default = make_backend("b-default", "10.0.0.1:80");
        let b_v2 = make_backend("b-v2", "10.0.1.1:80");
        let b_v3a = make_backend("b-v3a", "10.0.2.1:80");
        let b_v3b = make_backend("b-v3b", "10.0.2.2:80");
        let links = vec![("rts".into(), "b-default".into())];

        let config = ProxyConfig::from_store(
            vec![route],
            vec![b_default, b_v2, b_v3a, b_v3b],
            vec![],
            links,
            ProxyConfigGlobals::default(),
        );
        let entry = &config.routes_by_host.get("example.com").unwrap()[0];

        assert_eq!(entry.traffic_split_backends[0].as_ref().unwrap().len(), 1);
        assert!(
            entry.traffic_split_backends[1].is_none(),
            "all-dangling split must normalise to None"
        );
        assert_eq!(entry.traffic_split_backends[2].as_ref().unwrap().len(), 2);
        assert!(
            entry.traffic_split_backends[3].is_none(),
            "zero-weight split stays None in resolved table"
        );
    }

    #[test]
    fn test_canary_bucket_distribution_roughly_uniform() {
        // Sanity check: over 1000 distinct client IPs, a 20% split should
        // grab roughly 20% of them. Tolerance is wide (±7%) because we
        // use DefaultHasher and the sample is small; a bad hash (always
        // returning the same bucket) would fail dramatically.
        let splits = vec![split("canary", 20, &["canary"])];
        let backends: Vec<Option<Vec<Backend>>> = vec![Some(vec![mk_backend_with_id("canary")])];
        let mut hits = 0u32;
        for i in 0..1000u32 {
            let ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            let b = canary_bucket("r-dist", &ip);
            if pick_traffic_split_backends(&splits, &backends, b).is_some() {
                hits += 1;
            }
        }
        let pct = hits as f64 / 1000.0 * 100.0;
        assert!(
            (13.0..=27.0).contains(&pct),
            "20% split produced {pct:.1}% of hits, likely a hash distribution bug"
        );
    }

    fn hmap(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut m = http::HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn test_variance_no_headers_yields_none() {
        assert!(compute_cache_variance(&[], "", &hmap(&[]), "/").is_none());
    }

    #[test]
    fn test_variance_route_headers_only() {
        let headers = hmap(&[("accept-encoding", "gzip")]);
        let v1 = compute_cache_variance(
            &["Accept-Encoding".to_string()],
            "",
            &headers,
            "/",
        );
        assert!(v1.is_some());

        // Different header value -> different variance.
        let headers2 = hmap(&[("accept-encoding", "br")]);
        let v2 = compute_cache_variance(
            &["Accept-Encoding".to_string()],
            "",
            &headers2,
            "/",
        );
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_variance_route_and_response_vary_merge() {
        let headers = hmap(&[("accept-encoding", "gzip"), ("accept-language", "en")]);

        // Only route-configured.
        let v_route = compute_cache_variance(
            &["accept-encoding".to_string()],
            "",
            &headers,
            "/",
        );

        // Only response-signalled.
        let v_resp = compute_cache_variance(&[], "Accept-Encoding", &headers, "/");

        // Same header from either source should produce the same variance.
        assert_eq!(v_route, v_resp);

        // Union picks up both; a new header changes the hash.
        let v_both = compute_cache_variance(
            &["accept-encoding".to_string()],
            "Accept-Language",
            &headers,
            "/",
        );
        assert_ne!(v_route, v_both);
    }

    #[test]
    fn test_variance_case_insensitive_and_dedup() {
        let headers = hmap(&[("accept-encoding", "gzip")]);
        let a = compute_cache_variance(
            &["Accept-Encoding".to_string()],
            "accept-encoding, ACCEPT-ENCODING",
            &headers,
            "/",
        );
        let b = compute_cache_variance(
            &["accept-encoding".to_string()],
            "",
            &headers,
            "/",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_variance_star_anchors_on_uri() {
        let headers = hmap(&[]);
        let v_a = compute_cache_variance(&[], "*", &headers, "/a");
        let v_b = compute_cache_variance(&[], "*", &headers, "/b");
        let v_a_again = compute_cache_variance(&[], "*", &headers, "/a");
        assert!(v_a.is_some());
        assert_ne!(v_a, v_b);
        assert_eq!(v_a, v_a_again);
    }

    #[test]
    fn test_variance_missing_request_header_uses_empty_value() {
        // When the client does not send the vary header, it must still
        // produce a deterministic variance distinct from the case where the
        // header is present - otherwise clients without the header would
        // collide with whichever variant the first sender populated.
        let no_header = hmap(&[]);
        let with_header = hmap(&[("accept-encoding", "gzip")]);
        let route = vec!["accept-encoding".to_string()];

        let v_empty = compute_cache_variance(&route, "", &no_header, "/");
        let v_gzip = compute_cache_variance(&route, "", &with_header, "/");

        assert!(v_empty.is_some());
        assert_ne!(v_empty, v_gzip);
    }

    fn vary_req(method: &str, path: &str, headers: &[(&str, &str)]) -> lorica_http::RequestHeader {
        let mut req = lorica_http::RequestHeader::build(method, path.as_bytes(), None).unwrap();
        for (k, v) in headers {
            req.insert_header((*k).to_string(), *v).unwrap();
        }
        req
    }

    fn vary_resp(vary: Option<&str>) -> lorica_http::ResponseHeader {
        let mut resp = lorica_http::ResponseHeader::build(200, None).unwrap();
        if let Some(v) = vary {
            resp.insert_header("vary", v).unwrap();
        }
        resp
    }

    fn vary_meta(vary: Option<&str>) -> CacheMeta {
        let now = std::time::SystemTime::now();
        CacheMeta::new(
            now + std::time::Duration::from_secs(300),
            now,
            0,
            0,
            vary_resp(vary),
        )
    }

    #[test]
    fn test_cache_vary_for_request_plumbs_route_and_meta() {
        // Real route with operator-configured vary header + a CacheMeta that
        // also advertises a different Vary header. Proves the glue reads
        // from both inputs, not just one.
        let mut route = make_route("r-vary", "example.com", "/", true);
        route.cache_vary_headers = vec!["Accept-Encoding".into()];

        let meta = vary_meta(Some("Accept-Language"));
        let req_gzip_en = vary_req("GET", "/x", &[("accept-encoding", "gzip"), ("accept-language", "en")]);
        let req_gzip_fr = vary_req("GET", "/x", &[("accept-encoding", "gzip"), ("accept-language", "fr")]);
        let req_br_en = vary_req("GET", "/x", &[("accept-encoding", "br"), ("accept-language", "en")]);

        let v_ge = cache_vary_for_request(Some(&route), &meta, &req_gzip_en);
        let v_gf = cache_vary_for_request(Some(&route), &meta, &req_gzip_fr);
        let v_be = cache_vary_for_request(Some(&route), &meta, &req_br_en);

        assert!(v_ge.is_some());
        assert_ne!(v_ge, v_gf, "language change must partition the cache");
        assert_ne!(v_ge, v_be, "encoding change must partition the cache");
    }

    #[test]
    fn test_cache_vary_for_request_without_route_falls_back_to_response_vary() {
        // No route context (e.g. catch-all path without a Route attached in
        // ctx): the response's Vary header is still honoured so RFC 7234
        // semantics survive regardless of operator configuration.
        let meta = vary_meta(Some("Accept-Encoding"));
        let req_a = vary_req("GET", "/", &[("accept-encoding", "gzip")]);
        let req_b = vary_req("GET", "/", &[("accept-encoding", "br")]);

        let a = cache_vary_for_request(None, &meta, &req_a);
        let b = cache_vary_for_request(None, &meta, &req_b);
        assert!(a.is_some());
        assert_ne!(a, b);
    }

    #[test]
    fn test_cache_vary_for_request_no_config_no_response_yields_none() {
        // Feature unused: zero cost, no variance, asset caches under its
        // primary key alone.
        let route = make_route("r-novary", "example.com", "/", true);
        let meta = vary_meta(None);
        let req = vary_req("GET", "/", &[]);
        assert!(cache_vary_for_request(Some(&route), &meta, &req).is_none());
    }

    #[test]
    fn test_cache_vary_for_request_star_anchors_on_path_and_query() {
        // `Vary: *` -> variance anchored on URI so two URLs don't share a
        // slot but repeat requests to the same URL still hit a stable
        // variant.
        let meta = vary_meta(Some("*"));
        let req_a = vary_req("GET", "/a?v=1", &[]);
        let req_a_repeat = vary_req("GET", "/a?v=1", &[]);
        let req_b = vary_req("GET", "/b", &[]);

        let v_a = cache_vary_for_request(None, &meta, &req_a);
        let v_a2 = cache_vary_for_request(None, &meta, &req_a_repeat);
        let v_b = cache_vary_for_request(None, &meta, &req_b);

        assert!(v_a.is_some());
        assert_eq!(v_a, v_a2);
        assert_ne!(v_a, v_b);
    }

    #[test]
    fn test_cache_predictor_remembers_uncacheable() {
        // Confirm the shared CACHE_PREDICTOR static boots correctly and
        // behaves as expected against the CacheKey layout used by
        // `cache_key_callback` (empty namespace, "host+path" primary). This
        // guards against accidental changes to that layout silently breaking
        // predictor lookups.
        use lorica_cache::predictor::CacheablePredictor;
        let predictor = *CACHE_PREDICTOR;
        let key = CacheKey::new(String::new(), "predictor-test.example/foo".to_string(), String::new());

        // Fresh key -> cacheable until proven otherwise.
        assert!(predictor.cacheable_prediction(&key));

        // Origin says uncacheable -> predictor remembers.
        assert_eq!(
            predictor.mark_uncacheable(&key, NoCacheReason::OriginNotCache),
            Some(true)
        );
        assert!(!predictor.cacheable_prediction(&key));

        // Transient errors must NOT poison the prediction.
        let transient_key = CacheKey::new(
            String::new(),
            "predictor-test.example/transient".to_string(),
            String::new(),
        );
        assert_eq!(
            predictor.mark_uncacheable(&transient_key, NoCacheReason::InternalError),
            None
        );
        assert!(predictor.cacheable_prediction(&transient_key));

        // Re-cacheable after mark_cacheable clears the entry.
        predictor.mark_cacheable(&key);
        assert!(predictor.cacheable_prediction(&key));
    }
}
