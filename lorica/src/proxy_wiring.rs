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
use lorica_cache::key::HashBinary;
use lorica_cache::lock::CacheLock;
use lorica_cache::predictor::Predictor;
use lorica_cache::{
    CacheKey, CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
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
    /// Pre-resolved mirror backends (flattened from
    /// `route.mirror.backend_ids`). Empty when the feature is off or
    /// when all configured IDs dangle - either way, `spawn_mirrors` is
    /// a no-op.
    pub mirror_backends: Vec<Backend>,
    /// Pre-compiled response-rewrite rules (parallel to
    /// `route.response_rewrite.rules`). An entry is `None` when the
    /// source rule's regex failed to compile - that rule is silently
    /// skipped at runtime. Empty vec when the feature is off.
    pub response_rewrite_compiled: Vec<Option<CompiledRewriteRule>>,
    /// Pre-compiled mTLS enforcement state (required flag + a
    /// pre-lowercased org allowlist). `None` when mTLS is disabled
    /// for this route. Chain validation itself is done by the
    /// listener-level rustls verifier; per-request decisions (does
    /// this route require a cert, did it present one, does the
    /// organization match) happen in `request_filter`.
    pub mtls_enforcer: Option<MtlsEnforcer>,
}

/// Runtime-side view of a route's mTLS policy: the bits we check at
/// request time. The CA bundle itself is installed on the listener at
/// startup and is not needed here.
#[derive(Debug, Clone)]
pub struct MtlsEnforcer {
    pub required: bool,
    pub allowed_organizations: Vec<String>,
}

/// In-memory configuration snapshot used by the proxy.
///
/// This struct is atomically swapped via `ArcSwap` when the API triggers a reload.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Routes indexed by hostname for fast matching.
    /// Each hostname maps to a list of routes sorted by path_prefix length (longest first).
    pub routes_by_host: HashMap<String, Vec<Arc<RouteEntry>>>,
    /// Wildcard routes (*.example.com) checked when exact lookup fails.
    pub wildcard_routes: Vec<(String, Vec<Arc<RouteEntry>>)>,
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

        let mut routes_by_host: HashMap<String, Vec<Arc<RouteEntry>>> = HashMap::new();

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

            let response_rewrite_compiled: Vec<Option<CompiledRewriteRule>> = route
                .response_rewrite
                .as_ref()
                .map(|cfg| {
                    cfg.rules
                        .iter()
                        .enumerate()
                        .map(|(i, rule)| compile_rewrite_rule(rule, &route.id, i))
                        .collect()
                })
                .unwrap_or_default();

            let mirror_backends: Vec<Backend> = route
                .mirror
                .as_ref()
                .map(|cfg| {
                    cfg.backend_ids
                        .iter()
                        .filter_map(|id| backend_map.get(id).cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if route.mirror.is_some()
                && mirror_backends.is_empty()
                && route
                    .mirror
                    .as_ref()
                    .map(|m| !m.backend_ids.is_empty())
                    .unwrap_or(false)
            {
                tracing::warn!(
                    route_id = %route.id,
                    "mirror.backend_ids all dangling, mirroring is inert for this route"
                );
            }

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

            let mtls_enforcer = route.mtls.as_ref().map(|m| MtlsEnforcer {
                required: m.required,
                allowed_organizations: m.allowed_organizations.clone(),
            });

            let entry = Arc::new(RouteEntry {
                route: Arc::new(route.clone()),
                backends: route_backends,
                certificate,
                wrr_state: Arc::new(SmoothWrrState::new(std::process::id() as usize)),
                path_rewrite_regex: path_rewrite_regex.map(Arc::new),
                path_rule_backends,
                header_rule_regexes,
                header_rule_backends,
                traffic_split_backends,
                mirror_backends,
                response_rewrite_compiled,
                mtls_enforcer,
            });

            routes_by_host
                .entry(route.hostname.clone())
                .or_default()
                .push(Arc::clone(&entry));

            // Index hostname aliases so they resolve to the same route entry
            for alias in &route.hostname_aliases {
                routes_by_host
                    .entry(alias.clone())
                    .or_default()
                    .push(Arc::clone(&entry));
            }
        }

        // Separate wildcard hostnames (*.example.com) from exact ones
        let mut wildcard_routes: Vec<(String, Vec<Arc<RouteEntry>>)> = Vec::new();
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
    pub fn find_route<'a>(&'a self, host: &str, path: &str) -> Option<&'a Arc<RouteEntry>> {
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
    ///
    /// Hot path: we try `get_mut` first with a write lock already held
    /// so the common case (backend already known) avoids the
    /// `addr.to_string()` allocation that `insert` would incur. Only
    /// the first-seen backend per process pays for the `String`
    /// (audit M-1).
    pub fn record(&self, addr: &str, latency_us: f64) {
        let alpha = 0.3;
        let mut scores = self.scores.write();
        if let Some(current) = scores.get_mut(addr) {
            *current = alpha * latency_us + (1.0 - alpha) * *current;
        } else {
            // First-seen: seed the decay with the sample itself.
            scores.insert(addr.to_string(), latency_us);
        }
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

/// Per-(route, backend) circuit breaker.
///
/// Tracks consecutive failures per (route, backend) pair rather than per
/// backend alone. This matters when several routes share the same upstream
/// IP:port but exercise different paths on it - for example two virtual
/// hosts both pointing at `10.0.0.1:3080` where one path always succeeds
/// and the other structurally fails. Keying on the route prevents failures
/// on one route from tripping the breaker for siblings that are actually
/// healthy against the same physical backend.
///
/// When the failure count reaches the threshold, the circuit opens for that
/// (route, backend) pair and traffic on that route is redirected to other
/// backends for a cooldown period. After the cooldown, one probe request is
/// allowed through (half-open). If it succeeds the circuit closes; if it
/// fails the circuit re-opens.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Per-(route_id, backend) state: (consecutive_failures, state, last_state_change)
    states: dashmap::DashMap<(String, String), CircuitBreakerState>,
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

    /// Check if a backend is available for the given route (not in Open state).
    /// Open circuits that have exceeded the cooldown move to HalfOpen.
    pub fn is_available(&self, route_id: &str, addr: &str) -> bool {
        let key = (route_id.to_string(), addr.to_string());
        let mut entry = match self.states.get_mut(&key) {
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
    pub fn record_success(&self, route_id: &str, addr: &str) {
        let key = (route_id.to_string(), addr.to_string());
        if let Some(mut entry) = self.states.get_mut(&key) {
            if entry.failures > 0 || entry.state != CircuitStatus::Closed {
                entry.failures = 0;
                entry.state = CircuitStatus::Closed;
                entry.changed_at = Instant::now();
            }
        }
    }

    /// Record a failure. Increments the counter and opens the circuit if threshold is reached.
    pub fn record_failure(&self, route_id: &str, addr: &str) {
        let key = (route_id.to_string(), addr.to_string());
        let mut entry = self.states.entry(key).or_insert(CircuitBreakerState {
            failures: 0,
            state: CircuitStatus::Closed,
            changed_at: Instant::now(),
        });
        entry.failures += 1;
        if entry.failures >= self.threshold && entry.state != CircuitStatus::Open {
            entry.state = CircuitStatus::Open;
            entry.changed_at = Instant::now();
            tracing::warn!(
                route_id = %route_id,
                backend = %addr,
                failures = entry.failures,
                cooldown_s = self.cooldown_s,
                "circuit breaker opened - backend removed from rotation for this route"
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

/// Compact a client IP into a `u64` key for the shmem hashtables.
///
/// `lorica_shmem` pre-hashes this with its secret siphash key before
/// slotting, so the only requirement here is a deterministic, low-cost
/// serialisation of the IP into 64 bits. IPv4 becomes its 32-bit value;
/// IPv6 folds the two 64-bit halves via XOR; an unparseable string
/// falls back to a deterministic FNV-1a rollup so malformed inputs
/// still route consistently (they should not reach this path in
/// practice).
pub fn ip_to_shmem_key(ip: &str) -> u64 {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => u32::from(v4) as u64,
        Ok(IpAddr::V6(v6)) => {
            let o = v6.octets();
            let high = u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
            let low = u64::from_be_bytes([o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]]);
            high ^ low
        }
        Err(_) => {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in ip.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
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
    /// Full matched `RouteEntry` captured in `request_filter` so
    /// `upstream_peer` does not need to re-run `config.find_route`.
    /// Cheap (pointer clone) since the entry is already `Arc`'d in
    /// `ProxyConfig`. `None` when no route matched (request_filter
    /// returned `Ok(false)` and upstream_peer will 404).
    pub matched_route_entry: Option<Arc<RouteEntry>>,
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
    /// Response-body rewrite state. `Some(Active(buf))` while we're
    /// buffering the upstream response to rewrite it at end-of-stream;
    /// `Some(Overflowed)` if the body exceeded `max_body_bytes` (we
    /// then flush the buffer and stream the rest verbatim - better
    /// than a half-rewritten body). `None` means the feature is off
    /// for this response (Content-Type/Encoding didn't qualify).
    pub response_rewrite_state: Option<ResponseRewriteState>,
    /// Precompiled rewrite rules for this response, resolved once in
    /// `response_filter` from the current ProxyConfig and stored here
    /// so `response_body_filter` does not re-scan the routes map on
    /// every chunk (which was O(routes) per chunk under load). `Arc`
    /// so clones stay cheap.
    pub response_rewrite_rules: Option<Arc<Vec<Option<CompiledRewriteRule>>>>,

    /// Pending mirror sub-request awaiting the downstream request body.
    /// Populated in `request_filter` when the route has mirroring
    /// enabled and the request carries a body; fired in
    /// `request_body_filter` on `end_of_stream`. `None` for requests
    /// that don't mirror, or that have already fired (no-body methods
    /// fire immediately from `request_filter`).
    pub mirror_pending: Option<MirrorPending>,
    /// Accumulating body state for a pending mirror. Separate from
    /// `mirror_pending` so the buffer can be taken without disturbing
    /// the pending metadata.
    pub mirror_body_state: Option<MirrorBodyState>,
    /// Address of the backend admitted via a HalfOpen probe slot on
    /// this request, when any. Drives `was_probe=true` on the
    /// subsequent `BreakerEngine::record(...)` call for that exact
    /// backend so the supervisor can close the breaker on success (or
    /// bounce back to Open on failure). `None` for requests that went
    /// out on a Closed breaker.
    pub breaker_probe_backend: Option<String>,
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
    /// Per-backend circuit breaker engine. Single-process deployments
    /// hold the state machine in-process (`BreakerEngine::Local`);
    /// worker-mode deployments delegate admission and outcome
    /// reporting to the supervisor via the pipelined RPC channel so
    /// probe-slot allocation and state transitions stay consistent
    /// across workers (design § 7 WPAR-3).
    pub circuit_breaker_engine: BreakerEngine,
    /// Basic auth credential verification cache. Maps a hash of
    /// "username:password" to the timestamp of the last successful Argon2
    /// verification. Entries older than 60 s are ignored, forcing a fresh
    /// Argon2 check. This avoids ~100 ms per request on auth-protected routes.
    /// HTTP Basic Auth credential cache. Keys are the NUL-joined
    /// concatenation `"{Authorization-header-value}\0{expected_hash}"`
    /// stored verbatim - NOT a 64-bit hash digest - so two
    /// distinct credentials cannot collide and share a cache slot,
    /// which would let one bypass Argon2. Same design as the forward
    /// auth verdict cache (see SEC-AUD-01).
    basic_auth_cache: Arc<DashMap<String, Instant>>,
    /// Cross-worker shared-memory region. `Some` in worker mode
    /// (populated from the memfd the supervisor passes at fork),
    /// `None` in single-process mode. Holds cross-worker WAF counters
    /// and future shared-state primitives (see
    /// `docs/architecture/worker-shared-state.md` § 5). `'static`
    /// because the mapping lives for the process lifetime.
    pub shmem: Option<&'static lorica_shmem::SharedRegion>,
    /// Per-route token-bucket rate limiters keyed by
    /// `"{route_id}|{scope_key}"`. In single-process mode each entry
    /// is an [`lorica_limits::token_bucket::AuthoritativeBucket`]; in
    /// worker mode each entry is a [`LocalBucket`] synced every 100 ms
    /// with the supervisor via the pipelined RPC channel (see design
    /// § 6). The [`RateLimitEngine`] enum hides the dispatch.
    pub rate_limit_buckets: RateLimitEngine,
    /// Forward-auth verdict cache engine. Single-process mode uses the
    /// process-local static cache; worker mode delegates to the
    /// supervisor via the pipelined RPC channel so Allow verdicts
    /// propagate across workers and a session revocation invalidates
    /// the cache for every worker at once. See design § 7 WPAR-2.
    pub verdict_cache: VerdictCacheEngine,
    /// Two-phase config reload pending state (WPAR-8). When the
    /// supervisor issues `ConfigReloadPrepare`, the worker reads the
    /// DB, builds a fresh `ProxyConfig`, and stashes it here keyed by
    /// generation. The subsequent `ConfigReloadCommit` pops this slot
    /// and does the ArcSwap atomically across all workers at once,
    /// collapsing the divergence window from ~10-50 ms down to the
    /// UDS RTT between workers (microseconds). See design § 7 WPAR-8.
    pub pending_proxy_config: Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
}

/// Prepared-but-not-yet-committed proxy config. Held by workers
/// between `ConfigReloadPrepare` and `ConfigReloadCommit`. Carries the
/// full [`crate::reload::PreparedReload`] rather than only the
/// `ProxyConfig` so the Commit side can publish both the ArcSwap and
/// the connection-filter update atomically (audit H-3). See § 7
/// WPAR-8.
pub struct PendingProxyConfig {
    pub generation: u64,
    pub prepared: crate::reload::PreparedReload,
}


// Audit M-8: BreakerAdmission / BreakerEngine / VerdictCacheEngine /
// RateLimitEngine moved to proxy_wiring/engines.rs to keep this
// file below the refactor threshold. Re-exported here so
// `lorica::proxy_wiring::BreakerEngine` (etc.) still resolves.
pub mod forward_auth;
pub(crate) use forward_auth::{run_forward_auth_keyed, ForwardAuthOutcome};
#[cfg(test)]
pub(crate) use forward_auth::{
    build_forward_auth_headers, run_forward_auth, verdict_cache_key, verdict_cache_reset_for_test,
};

pub mod mirror_rewrite;
pub(crate) use mirror_rewrite::{
    apply_response_rewrites, build_mirror_forward_headers, compile_rewrite_rule,
    mirror_sample_hit, request_has_body, should_rewrite_response, spawn_mirrors,
    CompiledRewriteRule, MirrorBodyState, MirrorPending, ResponseRewriteState,
};
#[cfg(test)]
pub(crate) use mirror_rewrite::build_mirror_url;

pub mod helpers;
// `pub` (not `pub(crate)`) for `canary_bucket` and `evaluate_mtls`
// because they're re-exported by integration tests under `tests/`
// (canary_e2e_test, mtls_e2e_test).
pub use helpers::{canary_bucket, evaluate_mtls};
pub(crate) use helpers::{
    cache_vary_for_request, downstream_ssl_digest, extract_host, sanitize_html,
};
#[cfg(test)]
pub(crate) use helpers::{
    compute_cache_variance, match_header_rule_backends, pick_traffic_split_backends,
};

pub mod engines;
pub use engines::{BreakerAdmission, BreakerEngine, RateLimitEngine, VerdictCacheEngine};


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
            circuit_breaker_engine: BreakerEngine::local(5, 10),
            basic_auth_cache: Arc::new(DashMap::new()),
            shmem: None,
            rate_limit_buckets: RateLimitEngine::authoritative(),
            verdict_cache: VerdictCacheEngine::local(),
            pending_proxy_config: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    /// Spawn a background task that prunes expired entries from the
    /// basic-auth credential cache every `interval`. Without this,
    /// expired entries linger until the next successful verification
    /// inserts a new entry (which is when `retain` runs); under a
    /// sustained password-spray with no successful logins the cache
    /// would grow until process restart. The task is registered with
    /// the supplied `TaskTracker` so it drains on graceful shutdown.
    pub fn spawn_basic_auth_cache_prune(
        &self,
        tracker: &tokio_util::task::TaskTracker,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        const AUTH_CACHE_TTL: Duration = Duration::from_secs(60);
        let cache = Arc::clone(&self.basic_auth_cache);
        tracker.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the immediate tick
            loop {
                ticker.tick().await;
                cache.retain(|_, t| t.elapsed() < AUTH_CACHE_TTL);
            }
        })
    }

    /// Spawn a background prune task for `rate_limit_buckets`.
    ///
    /// For `scope = per_ip` every distinct client IP gets its own
    /// `AuthoritativeBucket` (~100 B each). Without eviction, a scan
    /// or high-cardinality traffic pattern leaks memory at the rate
    /// of "one bucket per unique IP" until process restart. This
    /// task walks the map on `interval` and drops any bucket whose
    /// `last_activity_ns` is older than `idle_ttl`. A future request
    /// from the same key reconstructs a fresh bucket, which starts
    /// at full capacity — acceptable (and arguably desirable) since
    /// the client has been idle past the TTL anyway.
    pub fn spawn_rate_limit_prune(
        &self,
        tracker: &tokio_util::task::TaskTracker,
        interval: Duration,
        idle_ttl: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let engine = self.rate_limit_buckets.clone();
        let idle_ttl_ns = idle_ttl.as_nanos() as u64;
        tracker.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the immediate tick
            loop {
                ticker.tick().await;
                let now = lorica_shmem::now_ns();
                match &engine {
                    RateLimitEngine::Authoritative(map) => {
                        map.retain(|_, b| now.saturating_sub(b.last_activity_ns()) < idle_ttl_ns);
                    }
                    RateLimitEngine::Local(_) => {
                        // Worker mode: the supervisor sync task drops
                        // entries via take_delta returning 0 — the local
                        // cache is kept small by the sync loop walking
                        // it. Eviction is supervisor-side (future
                        // follow-up: forward idle-key hints from
                        // supervisor). No-op here.
                    }
                }
            }
        })
    }

    /// Spawn a background task that syncs the worker-side `LocalBucket`
    /// cache with the supervisor's authoritative bucket registry every
    /// `interval`. Called on workers only (single-process mode uses
    /// `RateLimitEngine::Authoritative`, no sync needed).
    ///
    /// Each tick the task walks every entry of the local map, pulls out
    /// the accumulated `take_delta`, batches the non-zero entries into a
    /// `RateLimitDelta` RPC payload, sends it to the supervisor, and on
    /// the reply refreshes each bucket's token count with the
    /// authoritative snapshot. See design § 6.
    pub fn spawn_rate_limit_sync(
        &self,
        tracker: &tokio_util::task::TaskTracker,
        rpc: lorica_command::RpcEndpoint,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let engine = self.rate_limit_buckets.clone();
        tracker.spawn(async move {
            let buckets = match engine {
                RateLimitEngine::Local(map) => map,
                RateLimitEngine::Authoritative(_) => {
                    tracing::debug!(
                        "rate-limit sync task launched on Authoritative engine; exiting"
                    );
                    return;
                }
            };
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the immediate tick
            loop {
                ticker.tick().await;
                // Phase 1: drain local deltas into a batched payload.
                let mut entries: Vec<lorica_command::RateLimitEntry> = Vec::new();
                for item in buckets.iter() {
                    let consumed = item.value().take_delta();
                    if consumed > 0 {
                        entries.push(lorica_command::RateLimitEntry {
                            key: item.key().clone(),
                            consumed,
                        });
                    }
                }
                if entries.is_empty() {
                    continue;
                }
                // Phase 2: push to the supervisor.
                let payload = lorica_command::command::Payload::RateLimitDelta(
                    lorica_command::RateLimitDelta {
                        entries: entries.clone(),
                    },
                );
                let resp = rpc
                    .request_rpc(
                        lorica_command::CommandType::RateLimitDelta,
                        payload,
                        Duration::from_millis(500),
                    )
                    .await;
                match resp {
                    Ok(resp) => match resp.payload {
                        Some(lorica_command::response::Payload::RateLimitDeltaResult(r)) => {
                            // Phase 3: refresh local buckets with the
                            // authoritative snapshot.
                            for snap in r.snapshots {
                                if let Some(b) = buckets.get(&snap.key) {
                                    b.value().refresh(snap.remaining);
                                }
                            }
                        }
                        _ => {
                            tracing::debug!(
                                "rate-limit sync: unexpected reply payload; buckets left stale"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            entries = entries.len(),
                            "rate-limit sync: RPC failed; buckets left stale until next tick"
                        );
                    }
                }
            }
        })
    }

    /// Return a reference to the WAF engine for API access.
    pub fn waf_engine(&self) -> &Arc<WafEngine> {
        &self.waf_engine
    }

    /// Spawn the worker-side pipelined RPC listener that handles
    /// supervisor-initiated commands on the shared RPC channel
    /// (`ConfigReloadPrepare`, `ConfigReloadCommit`, `MetricsRequest`).
    ///
    /// Drops silently on supervisor EOF; dies with the runtime when
    /// the worker shuts down.
    ///
    /// The Prepare half reads the DB, rebuilds a fresh `ProxyConfig`,
    /// and stashes it in `self.pending_proxy_config` keyed by the
    /// generation number. The Commit half pops the stash and does
    /// the single-instruction `ArcSwap`, collapsing the divergence
    /// window across workers to the UDS RTT (microseconds). See
    /// design § 7 WPAR-8.
    ///
    /// Generation monotonicity is enforced by
    /// [`lorica_command::GenerationGate`] so a reordered Prepare is
    /// rejected rather than silently overwriting a fresher pending
    /// config.
    ///
    /// `MetricsRequest` (WPAR-7) builds an instant snapshot of the
    /// worker's per-request counters, ban list, EWMA scores, backend
    /// connections, request counts, and WAF counts and replies with
    /// a `Response` carrying a `MetricsReport` payload so /metrics
    /// pull-on-scrape can aggregate concurrently across workers.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_worker_rpc_listener(
        &self,
        tracker: &tokio_util::task::TaskTracker,
        mut incoming: lorica_command::IncomingCommands,
        store: Arc<tokio::sync::Mutex<lorica_config::ConfigStore>>,
        connection_filter: Option<Arc<crate::connection_filter::GlobalConnectionFilter>>,
        worker_id: u32,
    ) -> tokio::task::JoinHandle<()> {
        let proxy_config = Arc::clone(&self.config);
        let pending = Arc::clone(&self.pending_proxy_config);
        let gate = Arc::new(lorica_command::GenerationGate::new());
        let metrics_ctx = WorkerMetricsCtx {
            ban_list: Arc::clone(&self.ban_list),
            ewma_scores: self.ewma_tracker.scores_ref(),
            backend_connections: Arc::clone(&self.backend_connections),
            request_counts: Arc::clone(&self.request_counts),
            waf_counts: Arc::clone(&self.waf_counts),
            cache_hits: Arc::clone(&self.cache_hits),
            cache_misses: Arc::clone(&self.cache_misses),
            active_connections: Arc::clone(&self.active_connections),
        };
        tracker.spawn(async move {
            tracing::info!(worker_id, "worker RPC listener started");
            while let Some(inc) = incoming.recv().await {
                match inc.command_type() {
                    lorica_command::CommandType::ConfigReloadPrepare => {
                        handle_config_reload_prepare(
                            inc,
                            &store,
                            &proxy_config,
                            &pending,
                            &gate,
                            worker_id,
                        )
                        .await;
                    }
                    lorica_command::CommandType::ConfigReloadCommit => {
                        handle_config_reload_commit(
                            inc,
                            &proxy_config,
                            &pending,
                            connection_filter.as_ref(),
                            &gate,
                            worker_id,
                        )
                        .await;
                    }
                    lorica_command::CommandType::ConfigReloadAbort => {
                        handle_config_reload_abort(inc, &pending, worker_id).await;
                    }
                    lorica_command::CommandType::MetricsRequest => {
                        handle_metrics_request(inc, &metrics_ctx, worker_id).await;
                    }
                    other => {
                        tracing::debug!(
                            worker_id,
                            command_type = ?other,
                            "worker RPC: supervisor-initiated command has no handler"
                        );
                        let _ = inc
                            .reply_error("no worker-side handler for this command")
                            .await;
                    }
                }
            }
            tracing::info!(worker_id, "worker RPC listener exiting (supervisor EOF)");
        })
    }
}

/// Handles needed for the worker-side `MetricsRequest` RPC. Mirrors
/// the fields the legacy command-channel handler reads to build a
/// `MetricsReport`, clonable via `Arc` so the listener task can own
/// its own handle without holding the whole `LoricaProxy`.
#[derive(Clone)]
struct WorkerMetricsCtx {
    ban_list: Arc<DashMap<String, (Instant, u64)>>,
    ewma_scores: Arc<parking_lot::RwLock<std::collections::HashMap<String, f64>>>,
    backend_connections: Arc<BackendConnections>,
    request_counts: Arc<DashMap<(String, u16), AtomicU64>>,
    waf_counts: Arc<DashMap<(String, String), AtomicU64>>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
}

/// Worker-side handler for `CommandType::MetricsRequest` on the
/// pipelined RPC channel (WPAR-7). Builds an instant snapshot of
/// per-request counters (cache, bans, EWMA, backend conns, request
/// counts, WAF counts) into a `MetricsReport` and replies with it as
/// a `Response::MetricsReport` payload so the supervisor's pull-on-
/// scrape coordinator can aggregate across workers within a single
/// 500 ms budget.
async fn handle_metrics_request(
    inc: lorica_command::IncomingCommand,
    ctx: &WorkerMetricsCtx,
    worker_id: u32,
) {
    use lorica_command::{
        BackendConnEntry, BanReportEntry, EwmaReportEntry, MetricsReport, RequestCountEntry,
        WafCountEntry,
    };

    let ban_entries: Vec<BanReportEntry> = ctx
        .ban_list
        .iter()
        .filter_map(|entry| {
            let (ip, (banned_at, duration_s)) = (entry.key(), entry.value());
            let elapsed = banned_at.elapsed().as_secs();
            if elapsed >= *duration_s {
                return None;
            }
            Some(BanReportEntry {
                ip: ip.clone(),
                remaining_seconds: duration_s - elapsed,
                ban_duration_seconds: *duration_s,
            })
        })
        .collect();

    let ewma_entries: Vec<EwmaReportEntry> = ctx
        .ewma_scores
        .read()
        .iter()
        .map(|(addr, score)| EwmaReportEntry {
            backend_address: addr.clone(),
            score_us: *score,
        })
        .collect();

    let backend_conn_entries: Vec<BackendConnEntry> = ctx
        .backend_connections
        .snapshot()
        .into_iter()
        .map(|(addr, conns)| BackendConnEntry {
            backend_address: addr,
            connections: conns,
        })
        .collect();

    let request_entries: Vec<RequestCountEntry> = ctx
        .request_counts
        .iter()
        .map(|entry| {
            let ((route_id, status_code), counter) = (entry.key(), entry.value());
            RequestCountEntry {
                route_id: route_id.clone(),
                status_code: *status_code as u32,
                count: counter.load(Ordering::Relaxed),
            }
        })
        .collect();

    let waf_entries: Vec<WafCountEntry> = ctx
        .waf_counts
        .iter()
        .map(|entry| {
            let ((category, action), counter) = (entry.key(), entry.value());
            WafCountEntry {
                category: category.clone(),
                action: action.clone(),
                count: counter.load(Ordering::Relaxed),
            }
        })
        .collect();

    let mut report = MetricsReport::new(
        worker_id,
        0, // total_requests not tracked yet (matches legacy)
        ctx.active_connections.load(Ordering::Relaxed),
    );
    report.cache_hits = ctx.cache_hits.load(Ordering::Relaxed);
    report.cache_misses = ctx.cache_misses.load(Ordering::Relaxed);
    report.ban_entries = ban_entries;
    report.ewma_entries = ewma_entries;
    report.backend_conn_entries = backend_conn_entries;
    report.request_entries = request_entries;
    report.waf_entries = waf_entries;

    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            lorica_command::response::Payload::MetricsReport(report),
        ))
        .await;
}

/// Worker-side handler for `ConfigReloadPrepare`. Reads the DB and
/// builds a fresh `ProxyConfig`, then stashes it in the pending slot.
/// Generation must strictly exceed the gate watermark; replies Ok on
/// success, Error on build failure or generation regression.
async fn handle_config_reload_prepare(
    inc: lorica_command::IncomingCommand,
    store: &Arc<tokio::sync::Mutex<lorica_config::ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    gate: &Arc<lorica_command::GenerationGate>,
    worker_id: u32,
) {
    let prepare = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadPrepare(p)) => p,
        _ => {
            let _ = inc
                .reply_error("malformed ConfigReloadPrepare payload")
                .await;
            return;
        }
    };
    if let Err(e) = gate.observe(prepare.generation) {
        tracing::warn!(
            worker_id,
            generation = prepare.generation,
            error = %e,
            "ConfigReloadPrepare rejected: stale generation"
        );
        let _ = inc.reply_error(format!("stale generation: {e}")).await;
        return;
    }
    match crate::reload::build_proxy_config(store, proxy_config, None).await {
        Ok(prepared) => {
            *pending.lock() = Some(PendingProxyConfig {
                generation: prepare.generation,
                prepared,
            });
            tracing::info!(
                worker_id,
                generation = prepare.generation,
                "ConfigReloadPrepare: pending config built and stashed (with connection-filter CIDRs)"
            );
            let _ = inc.reply(lorica_command::Response::ok(0)).await;
        }
        Err(e) => {
            tracing::error!(
                worker_id,
                generation = prepare.generation,
                error = %e,
                "ConfigReloadPrepare failed to build new ProxyConfig"
            );
            let _ = inc
                .reply_error(format!("Prepare failed to build config: {e}"))
                .await;
        }
    }
}

/// Worker-side handler for `ConfigReloadAbort`. Drops the pending
/// slot if its generation matches. A mismatch or an empty slot is a
/// silent no-op (Ok reply) - Abort is advisory; the worker is free
/// to already have moved on. Closes audit M-7 orphan.
async fn handle_config_reload_abort(
    inc: lorica_command::IncomingCommand,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    worker_id: u32,
) {
    let abort = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadAbort(a)) => a,
        _ => {
            let _ = inc
                .reply_error("malformed ConfigReloadAbort payload")
                .await;
            return;
        }
    };
    let dropped = {
        let mut slot = pending.lock();
        match *slot {
            Some(ref p) if p.generation == abort.generation => {
                *slot = None;
                true
            }
            _ => false,
        }
    };
    if dropped {
        tracing::info!(
            worker_id,
            generation = abort.generation,
            "ConfigReloadAbort: pending config dropped"
        );
    } else {
        tracing::debug!(
            worker_id,
            generation = abort.generation,
            "ConfigReloadAbort: no matching pending (already committed or already dropped)"
        );
    }
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

/// Worker-side handler for `ConfigReloadCommit`. Pops the pending
/// slot, verifies the generation, and atomically ArcSwaps. A commit
/// with no pending entry or a mismatched generation replies Error so
/// the supervisor's coordinator can decide whether to retry.
async fn handle_config_reload_commit(
    inc: lorica_command::IncomingCommand,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    connection_filter: Option<&Arc<crate::connection_filter::GlobalConnectionFilter>>,
    gate: &Arc<lorica_command::GenerationGate>,
    worker_id: u32,
) {
    let commit = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadCommit(c)) => c,
        _ => {
            let _ = inc
                .reply_error("malformed ConfigReloadCommit payload")
                .await;
            return;
        }
    };
    if let Err(e) = gate.observe_commit(commit.generation) {
        tracing::warn!(
            worker_id,
            generation = commit.generation,
            error = %e,
            "ConfigReloadCommit rejected: stale generation"
        );
        let _ = inc.reply_error(format!("stale commit: {e}")).await;
        return;
    }
    // Pop the prepared snapshot atomically. It carries the ProxyConfig
    // AND the connection-filter CIDRs AND any mTLS fingerprint drift,
    // so the single `commit_prepared_reload` call below publishes them
    // together - no partial-state window between ArcSwap and filter
    // reload (audit H-3).
    let prepared = {
        let mut slot = pending.lock();
        match slot.take() {
            Some(p) if p.generation == commit.generation => Some(p.prepared),
            Some(p) => {
                let pending_gen = p.generation;
                // Put it back: a late commit for an older generation
                // should not clobber a fresher pending.
                *slot = Some(p);
                tracing::warn!(
                    worker_id,
                    pending_generation = pending_gen,
                    commit_generation = commit.generation,
                    "ConfigReloadCommit generation mismatch"
                );
                None
            }
            None => None,
        }
    };
    match prepared {
        Some(prepared) => {
            crate::reload::commit_prepared_reload(proxy_config, connection_filter, prepared);
            tracing::info!(
                worker_id,
                generation = commit.generation,
                "ConfigReloadCommit: pending config swapped in"
            );
            let _ = inc.reply(lorica_command::Response::ok(0)).await;
        }
        None => {
            let _ = inc
                .reply_error(format!(
                    "no matching pending for generation {}",
                    commit.generation
                ))
                .await;
        }
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
///
/// Uses `OsRng` (getrandom) so request IDs are unpredictable and
/// collision-resistant even under concurrent same-nanosecond requests
/// on the same thread (audit M-5). The prior `DefaultHasher`
/// implementation was SipHash-keyed per process and emitted
/// deterministic output given `(now, thread_id)` inputs, so an
/// attacker observing a few IDs could predict future ones.
fn generate_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hi = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let lo = u64::from_le_bytes(bytes[8..].try_into().expect("8 bytes"));
    format!("{hi:016x}{lo:016x}")
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
            matched_route_entry: None,
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
            mirror_pending: None,
            mirror_body_state: None,
            breaker_probe_backend: None,
            response_rewrite_state: None,
            response_rewrite_rules: None,
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
                info!(
                    token = token,
                    "ACME challenge request intercepted, looking up token"
                );
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
                            route_hostname: {
                                let h = extract_host(req);
                                if h.is_empty() {
                                    "-"
                                } else {
                                    h
                                }
                            }
                            .to_string(),
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

        // Find matching route (exact hostname first, then wildcard).
        // Cache the matched entry in ctx so upstream_peer does not
        // re-run find_route on the same request.
        let entry = match config.find_route(host, path) {
            Some(e) => e,
            None => return Ok(false), // No route = let upstream_peer handle 404
        };
        ctx.matched_route_entry = Some(Arc::clone(entry));

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

        // Per-route token-bucket rate limit. Runs after ban/blocklist
        // and redirects so that an abusive client is rejected before
        // we touch WAF / mtls / forward_auth. See design § 6 and
        // `lorica_limits::token_bucket::AuthoritativeBucket`.
        //
        // Whitelisted IPs bypass the limiter (same policy as WAF ban
        // checks — an operator who added an IP to the whitelist has
        // made a deliberate trust decision).
        if let Some(ref rl) = entry.route.rate_limit {
            if !is_whitelisted {
                let scope_key = match rl.scope {
                    lorica_config::models::RateLimitScope::PerIp => {
                        ctx.client_ip.as_deref().unwrap_or("unknown").to_string()
                    }
                    lorica_config::models::RateLimitScope::PerRoute => "__route__".to_string(),
                };
                let key = format!("{}|{}", entry.route.id, scope_key);
                let admitted =
                    self.rate_limit_buckets
                        .try_consume(&key, rl, 1, lorica_shmem::now_ns());
                if !admitted {
                    ctx.block_reason = Some("rate limited".to_string());
                    let mut header = lorica_http::ResponseHeader::build(429, None)?;
                    // Retry-After in seconds. For any configured refill
                    // rate >= 1 tok/s, 1 second is the right advice
                    // (one token refills in <= 1 s). A zero refill means
                    // a one-shot bucket that never refills — advise a
                    // generous 60 s backoff instead of a tight loop.
                    let retry_after: u64 = if rl.refill_per_sec >= 1 { 1 } else { 60 };
                    let _ = header.insert_header("Retry-After", retry_after.to_string());
                    let _ = header.insert_header("Content-Type", "text/plain; charset=utf-8");
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        // mTLS client verification: runs before forward_auth so a
        // request that failed to present a valid client cert is
        // rejected cheaply (no auth sub-request spawned). The listener
        // has already validated the cert chain against the union CA
        // bundle; we just check presence and the per-route org
        // allowlist.
        //
        // 495 / 496 are the semi-standard "SSL cert error" / "SSL cert
        // required" codes used by Nginx; reqwest and common clients
        // surface them as meaningful errors and they don't collide
        // with our other rejection paths.
        if let Some(ref enforcer) = entry.mtls_enforcer {
            let verdict = evaluate_mtls(enforcer, downstream_ssl_digest(session).as_deref());
            if let Some(status) = verdict {
                ctx.block_reason = Some(format!("mtls rejected ({status})"));
                let mut resp_header = ResponseHeader::build(status, None)?;
                let body: &[u8] = match status {
                    496 => b"SSL certificate required",
                    495 => b"SSL certificate error",
                    _ => b"Forbidden",
                };
                let _ = resp_header.insert_header("Content-Type", "text/plain; charset=utf-8");
                let _ = resp_header.insert_header("Content-Length", body.len().to_string());
                session
                    .write_response_header(Box::new(resp_header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
                    .await?;
                return Ok(true);
            }
        }

        // Forward authentication: gate the request on an external auth
        // service (Authelia / Authentik / Keycloak / oauth2-proxy). Runs
        // after route match but before header/canary/path rules so a
        // denied request never leaks into the backend-selection phase.
        if let Some(ref fa_cfg) = entry.route.forward_auth {
            // Detect TLS from the downstream socket, not HTTP version:
            // h2c (HTTP/2 over plaintext) would otherwise be reported
            // as https to the auth service, which is misleading and
            // may trigger redirect loops.
            let is_tls = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            let scheme = if is_tls { "https" } else { "http" };
            let outcome = run_forward_auth_keyed(
                fa_cfg,
                req,
                ctx.client_ip.as_deref(),
                scheme,
                &entry.route.id,
                &self.verdict_cache,
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
                    let _ = resp_header.insert_header("Content-Length", body.len().to_string());
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
        // can still take precedence - "more specific wins"). Also
        // emits a Prometheus counter so operators can see rule-match
        // activity in metrics, not just logs. `rule_index = "default"`
        // means no rule matched.
        if !entry.route.header_rules.is_empty() {
            let mut matched_idx: Option<usize> = None;
            for (i, rule) in entry.route.header_rules.iter().enumerate() {
                let value = req
                    .headers
                    .get(rule.header_name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let regex: Option<&regex::Regex> = entry
                    .header_rule_regexes
                    .get(i)
                    .and_then(|opt| opt.as_deref());
                if rule.matches(value, |v| regex.is_some_and(|re| re.is_match(v))) {
                    matched_idx = Some(i);
                    if let Some(b) = entry.header_rule_backends.get(i).and_then(|b| b.as_ref()) {
                        ctx.matched_backends = Some(b.clone());
                    }
                    break;
                }
            }
            match matched_idx {
                Some(i) => {
                    // Stack-allocated itoa buffer avoids the per-request
                    // String allocation that the old `i.to_string()`
                    // performed on every header-rule match. ~1-2% CPU
                    // saved at high QPS on routes with many rules.
                    let mut buf = itoa::Buffer::new();
                    lorica_api::metrics::inc_header_rule_match(&entry.route.id, buf.format(i));
                }
                None => lorica_api::metrics::inc_header_rule_match(&entry.route.id, "default"),
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
                // Inline walk so we know which split matched (for the
                // split_name metric label). Mirrors
                // `pick_traffic_split_backends` logic; the helper stays
                // as-is for its unit-test callers.
                let mut cumulative: u32 = 0;
                let mut matched_split_name: Option<&str> = None;
                for (i, split) in entry.route.traffic_splits.iter().enumerate() {
                    let w = split.weight_percent.min(100) as u32;
                    if w == 0 {
                        continue;
                    }
                    cumulative = cumulative.saturating_add(w).min(100);
                    if (bucket as u32) < cumulative {
                        if let Some(backends) =
                            entry.traffic_split_backends.get(i).and_then(|b| b.as_ref())
                        {
                            ctx.matched_backends = Some(backends.clone());
                            matched_split_name = Some(if split.name.is_empty() {
                                "unnamed"
                            } else {
                                split.name.as_str()
                            });
                        }
                        break;
                    }
                }
                match matched_split_name {
                    Some(name) => {
                        lorica_api::metrics::inc_canary_split_selected(&entry.route.id, name)
                    }
                    None => {
                        lorica_api::metrics::inc_canary_split_selected(&entry.route.id, "default")
                    }
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

        // Request mirroring: fire-and-forget shadow copies. For body-
        // less requests (GET/HEAD/DELETE, or any request without
        // Content-Length / Transfer-Encoding) we spawn immediately.
        // For body-bearing requests we stash the metadata in
        // `ctx.mirror_pending` and fire in `request_body_filter` once
        // the body is buffered - so shadow backends see the same
        // request body as the primary, up to the configured
        // max_body_bytes cap.
        if let Some(ref mirror_cfg) = entry.route.mirror {
            if !entry.mirror_backends.is_empty()
                && mirror_sample_hit(&ctx.request_id, mirror_cfg.sample_percent)
            {
                let headers = build_mirror_forward_headers(req, &ctx.request_id);
                let path = req
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let method = req.method.clone();
                let max_body = mirror_cfg.max_body_bytes as usize;
                let body_expected = max_body > 0 && request_has_body(req);

                if body_expected {
                    // Defer mirror firing until request_body_filter has
                    // buffered the full body.
                    ctx.mirror_pending = Some(MirrorPending {
                        cfg: mirror_cfg.clone(),
                        backends: entry.mirror_backends.clone(),
                        method,
                        path_and_query: path,
                        headers,
                        request_id: ctx.request_id.clone(),
                        max_body_bytes: max_body,
                        route_id: entry.route.id.clone(),
                    });
                    ctx.mirror_body_state = Some(MirrorBodyState::Active(Vec::new()));
                } else {
                    // No body to buffer (or operator opted into
                    // headers-only via max_body_bytes = 0): fire now.
                    spawn_mirrors(
                        mirror_cfg,
                        &entry.mirror_backends,
                        method,
                        path,
                        headers,
                        None,
                        ctx.request_id.clone(),
                        entry.route.id.clone(),
                    );
                }
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

                        // Check credential cache before running Argon2.
                        // Key is the NUL-joined literal "{cred}\0{hash}"
                        // so two distinct credentials cannot collide on
                        // a truncated 64-bit digest (which, at a small
                        // cache size, is not worth the bypass risk).
                        let mut cache_key =
                            String::with_capacity(cred.len() + 1 + expected_hash.len());
                        cache_key.push_str(&cred);
                        cache_key.push('\0');
                        cache_key.push_str(expected_hash.as_str());

                        const AUTH_CACHE_TTL: Duration = Duration::from_secs(60);
                        if let Some(verified_at) = self.basic_auth_cache.get(&cache_key) {
                            if verified_at.elapsed() < AUTH_CACHE_TTL {
                                return true; // cache hit - skip Argon2
                            }
                        }

                        // Cache miss or expired - run full Argon2 verification.
                        // Parse the hash first; if it's corrupt, deny immediately
                        // without paying the cost of block_in_place.
                        if argon2::PasswordHash::new(expected_hash).is_err() {
                            return false;
                        }
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
                            self.basic_auth_cache
                                .retain(|_, t| t.elapsed() < AUTH_CACHE_TTL);
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
            if let Some(ref target) = ctx
                .route_snapshot
                .as_ref()
                .and_then(|r| r.redirect_to.clone())
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
        if let Some(ref target) = ctx
            .route_snapshot
            .as_ref()
            .and_then(|r| r.redirect_to.clone())
        {
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

                // WAF auto-ban counter. Two modes:
                //
                // - Multi-worker (`self.shmem.is_some()`): increment the
                //   cross-worker `waf_auto_ban` atomic counter. The
                //   supervisor reads the counter on each UDS WAF event,
                //   decides when the threshold is crossed, broadcasts
                //   `BanIp` to all workers, and resets the slot. Workers
                //   never issue bans directly — the supervisor is the
                //   sole authority so the ban is consistent across the
                //   pool.
                //
                // - Single-process (`self.shmem.is_none()`): fall back to
                //   the per-process `waf_violations` DashMap + local
                //   `ban_list` insertion, as before.
                if let Some(ref ip) = check_ip {
                    let config = self.config.load();
                    let threshold = config.waf_ban_threshold;
                    if threshold > 0 {
                        if let Some(region) = self.shmem {
                            // Multi-worker: just bump the shmem counter.
                            let tagged = region.tagged(ip_to_shmem_key(ip.as_str()));
                            let _ =
                                region
                                    .waf_auto_ban
                                    .increment(tagged, 1, lorica_shmem::now_ns());
                        } else {
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
            if let Some(max) = ctx
                .route_snapshot
                .as_ref()
                .and_then(|r| r.max_request_body_bytes)
            {
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

            // Buffer body for mirror sub-request. Independent of WAF
            // buffering: WAF caps at 1 MiB hardcoded, mirror uses the
            // route's configurable max_body_bytes. Overflow switches
            // the state to Overflowed so the mirror is skipped at
            // end_of_stream (a truncated body would lie to the shadow).
            if let Some(ref pending) = ctx.mirror_pending {
                if let Some(state) = ctx.mirror_body_state.take() {
                    match state {
                        MirrorBodyState::Active(mut buf) => {
                            if buf.len() + chunk.len() > pending.max_body_bytes {
                                tracing::debug!(
                                    max = pending.max_body_bytes,
                                    "mirror: body exceeded max_body_bytes, skipping"
                                );
                                ctx.mirror_body_state = Some(MirrorBodyState::Overflowed);
                            } else {
                                buf.extend_from_slice(chunk);
                                ctx.mirror_body_state = Some(MirrorBodyState::Active(buf));
                            }
                        }
                        MirrorBodyState::Overflowed => {
                            ctx.mirror_body_state = Some(MirrorBodyState::Overflowed);
                        }
                    }
                }
            }
        }

        // End of stream: fire the mirror sub-request with the buffered
        // body (or skip it on overflow). Must happen regardless of
        // WAF status - WAF may allow the request while the mirror has
        // overflowed, or vice versa.
        if end_of_stream {
            if let (Some(pending), Some(body_state)) =
                (ctx.mirror_pending.take(), ctx.mirror_body_state.take())
            {
                match body_state {
                    MirrorBodyState::Active(buf) => {
                        spawn_mirrors(
                            &pending.cfg,
                            &pending.backends,
                            pending.method,
                            pending.path_and_query,
                            pending.headers,
                            Some(buf),
                            pending.request_id,
                            pending.route_id,
                        );
                    }
                    MirrorBodyState::Overflowed => {
                        // Buffer exceeded max_body_bytes: skip silently.
                        // Already logged at overflow time.
                        lorica_api::metrics::inc_mirror_outcome(
                            &pending.route_id,
                            "dropped_oversize_body",
                        );
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

                    let mut verdict = self
                        .waf_engine
                        .evaluate_body(waf_mode, buf, host, client_ip);

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
        // Snapshot a few fields out of ctx.route_snapshot as owned
        // values so we can re-borrow ctx mutably later in the function
        // (cache_key_callback takes `&mut ctx`). Without this the
        // short-lived immutable reborrow locks us out of the helper.
        let (route_id, cache_max_bytes) = match ctx.route_snapshot {
            Some(ref r) if r.cache_enabled => (r.id.clone(), r.cache_max_bytes),
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

        // Observability: peek the predictor for this key and count
        // bypass hits BEFORE enabling the cache. Pingora's cache
        // state machine will consult the same predictor again
        // internally, but doing the observation here is the only
        // place we have the route_id in scope. The double read is
        // cheap (sharded LRU) compared to the cache-lock work it
        // saves.
        if let Ok(observed_key) = self.cache_key_callback(session, ctx) {
            use lorica_cache::predictor::CacheablePredictor as _;
            if !(*CACHE_PREDICTOR).cacheable_prediction(&observed_key) {
                lorica_api::metrics::inc_cache_predictor_bypass(&route_id);
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
        if cache_max_bytes > 0 {
            session
                .cache
                .set_max_file_size_bytes(cache_max_bytes as usize);
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
                        let r1 = session.write_response_header(Box::new(header), false).await;
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

        // Fast path: request_filter already matched and cached the
        // entry. Fall back to a fresh find_route only when ctx is
        // empty (e.g. request_filter returned Ok(false) and we need
        // to emit a 404 through the normal upstream_peer path).
        let config_guard;
        let entry: Arc<RouteEntry> = match ctx.matched_route_entry.as_ref() {
            Some(cached) => Arc::clone(cached),
            None => {
                config_guard = self.config.load();
                match config_guard.find_route(host, path) {
                    Some(e) => Arc::clone(e),
                    None => {
                        return Error::e_explain(
                            ErrorType::HTTPStatus(404),
                            format!("no route configured for host={host} path={path}"),
                        );
                    }
                }
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

        // Filter healthy backends (path-rule / header-rule / canary
        // override wins when set).
        //
        // Intentional fail-closed design: when an override group
        // (canary split, header rule, path rule) has all its backends
        // Down / Draining / breaker-Open, we return 502 rather than
        // silently falling back to the route's default backends. A
        // silent fallback would mask a broken deployment - an
        // operator rolling out a bad canary would see their primary
        // absorb the traffic and assume the release is healthy. The
        // explicit 502 (with the matching Prometheus counter) makes
        // the failure visible. If a graceful fallback is desired on
        // a given route, operators should use small weights on the
        // canary split so the default band still covers the majority
        // of traffic.
        let backends_source = if let Some(ref overridden) = ctx.matched_backends {
            overridden
        } else {
            &entry.backends
        };
        // Breaker admission is async (may hit the supervisor RPC in
        // worker mode), so we walk the backends manually instead of a
        // sync `filter()`. We also track which backend - if any - was
        // admitted via a HalfOpen probe; the outcome report in
        // `logging()` uses this to flag `was_probe` correctly.
        let mut healthy_backends: Vec<&Backend> = Vec::with_capacity(backends_source.len());
        let mut probe_backend: Option<String> = None;
        for b in backends_source.iter() {
            if b.health_status == HealthStatus::Down
                || b.lifecycle_state != LifecycleState::Normal
            {
                continue;
            }
            match self
                .circuit_breaker_engine
                .admit(&entry.route.id, &b.address)
                .await
            {
                BreakerAdmission::Allow => healthy_backends.push(b),
                BreakerAdmission::Probe => {
                    // Only one probe per request; later Probes for the
                    // same route-backend would deny anyway. Record the
                    // first one and stop asking for more probes on
                    // subsequent backends - `is_available` already
                    // drained the slot, but a probe we don't use would
                    // leave the breaker stuck in HalfOpen. For a
                    // multi-backend route we still want to prefer the
                    // probe-admitted backend (it's the only one that
                    // can close the breaker on success), so we push
                    // it to the head of the list.
                    healthy_backends.insert(0, b);
                    if probe_backend.is_none() {
                        probe_backend = Some(b.address.clone());
                    }
                }
                BreakerAdmission::Deny => {}
            }
        }
        // Remember for logging(): the outcome report must flag
        // `was_probe=true` for this specific backend so the supervisor
        // can finalize the HalfOpen state machine.
        ctx.breaker_probe_backend = probe_backend;

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
                .and_then(|backend_id| healthy_backends.iter().position(|b| b.id == backend_id))
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

        // Decide if response-body rewriting will fire for this response.
        // Done at header-phase so we can drop Content-Length (our
        // rewritten body will have a different length) before the
        // response line is sent.
        //
        // Skip HEAD requests: the response MUST report the Content-Length
        // a GET would produce (RFC 7231 s4.3.2), and HEAD carries no
        // body for us to rewrite. Stripping Content-Length here would
        // break clients that size their follow-up GET based on HEAD.
        //
        // Also skip 1xx / 204 / 304 responses: they are defined as
        // having no body, and stripping Content-Length on a 304 would
        // corrupt the revalidation contract.
        let is_head = session
            .req_header()
            .method
            .as_str()
            .eq_ignore_ascii_case("HEAD");
        let status = upstream_response.status.as_u16();
        let body_forbidden = matches!(status, 100..=199 | 204 | 304);
        // v1 scope: response rewriting is mutually exclusive with
        // caching. Pingora's cache captures raw upstream bytes and
        // replays them through response_body_filter on cache hits,
        // so naively combining the two would either double-rewrite
        // (if the cache stored rewritten bytes) or silently break
        // the stream framing (the cache relies on the
        // upstream-reported Content-Length we would strip). Pick
        // one per route; rewriting wins over caching with a loud
        // warning, because rewriting is typically the stricter
        // security / integrity requirement.
        let cache_active = session.cache.enabled();
        if cache_active && route.response_rewrite.is_some() {
            tracing::warn!(
                route_id = %route.id,
                "response_rewrite disabled for this response because the route also has cache_enabled; caching + rewriting are mutually exclusive in v1"
            );
        }
        if let Some(ref rr_cfg) = route.response_rewrite {
            if !is_head && !body_forbidden && !cache_active {
                let ct = upstream_response
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let ce = upstream_response
                    .headers
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if should_rewrite_response(rr_cfg, ct, ce) {
                    // Strip Content-Length; the framework will emit the
                    // rewritten body as chunked. Transfer-Encoding is
                    // likewise re-derived by the server.
                    upstream_response.remove_header("content-length");
                    ctx.response_rewrite_state = Some(ResponseRewriteState::Active(Vec::new()));
                    // Resolve compiled rules ONCE from the cached
                    // route entry and hand them to response_body_filter
                    // via ctx. Prior code re-scanned routes on every
                    // chunk (O(routes) per chunk under load); now the
                    // per-chunk path is a pointer clone.
                    if let Some(entry) = ctx.matched_route_entry.as_ref() {
                        ctx.response_rewrite_rules =
                            Some(Arc::new(entry.response_rewrite_compiled.clone()));
                    }
                }
            }
        }

        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Fast path: feature off for this response.
        if ctx.response_rewrite_state.is_none() {
            return Ok(None);
        }

        // Resolve the configured cap and compiled rules. Config absent
        // would be an engine bug (we only set state when config exists)
        // but guard anyway so we fail open (stream unchanged).
        let (max_body_bytes, compiled) = {
            let route = match ctx.route_snapshot.as_ref() {
                Some(r) => r,
                None => {
                    ctx.response_rewrite_state = None;
                    return Ok(None);
                }
            };
            let cfg = match route.response_rewrite.as_ref() {
                Some(c) => c,
                None => {
                    ctx.response_rewrite_state = None;
                    return Ok(None);
                }
            };
            (cfg.max_body_bytes as usize, route.clone())
        };
        // Compiled rules were resolved once in response_filter and
        // stored in ctx - a pointer clone here, no per-chunk scan.
        let rules = ctx
            .response_rewrite_rules
            .clone()
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let route_id = compiled.id.as_str();

        // Accumulate or overflow.
        let state = ctx.response_rewrite_state.take();
        let (mut buffer, was_overflowed) = match state {
            Some(ResponseRewriteState::Active(buf)) => (buf, false),
            Some(ResponseRewriteState::Overflowed) => (Vec::new(), true),
            None => return Ok(None),
        };

        if was_overflowed {
            // Already overflowed: stream chunks verbatim, state stays
            // Overflowed until end_of_stream when we clear it.
            if end_of_stream {
                // no-op; drop state
            } else {
                ctx.response_rewrite_state = Some(ResponseRewriteState::Overflowed);
            }
            return Ok(None);
        }

        if let Some(chunk) = body.take() {
            if buffer.len().saturating_add(chunk.len()) > max_body_bytes {
                tracing::debug!(
                    route_id = %route_id,
                    max = max_body_bytes,
                    "response_rewrite: body exceeded max_body_bytes, streaming verbatim"
                );
                // Flush what we buffered so far plus the current chunk.
                // The downstream already received no bytes for this
                // response (we've suppressed previous chunks), so the
                // entire response body must be emitted now.
                let mut flush = std::mem::take(&mut buffer);
                flush.extend_from_slice(&chunk);
                *body = Some(bytes::Bytes::from(flush));
                ctx.response_rewrite_state = Some(ResponseRewriteState::Overflowed);
                return Ok(None);
            }
            buffer.extend_from_slice(&chunk);
            // Suppress the chunk: we'll emit the rewritten body at
            // end_of_stream in one go.
            *body = None;
        }

        if end_of_stream {
            let rewritten = apply_response_rewrites(&buffer, rules.as_slice());
            *body = Some(bytes::Bytes::from(rewritten));
            // Drop state; no more chunks expected.
        } else {
            ctx.response_rewrite_state = Some(ResponseRewriteState::Active(buffer));
        }

        Ok(None)
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

            // Update circuit breaker: 5xx or connection error = failure, else success.
            // Keyed by (route_id, backend) so a failing route does not punish
            // sibling routes that share the same upstream IP:port. In
            // worker mode the supervisor owns the state machine and
            // `record(...)` issues an RPC; `was_probe` is derived from
            // `ctx.breaker_probe_backend` so a HalfOpen probe can
            // transition the breaker back to Closed on success.
            if let Some(ref route_id) = ctx.route_id {
                let success = e.is_none() && status < 500;
                let was_probe = ctx
                    .breaker_probe_backend
                    .as_deref()
                    .map(|probe_addr| probe_addr == addr.as_str())
                    .unwrap_or(false);
                self.circuit_breaker_engine
                    .record(route_id, addr, success, was_probe)
                    .await;
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
            if status != 101 && ctx.block_reason.is_none() && !ctx.waf_blocked && e.is_none() {
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
mod tests;
