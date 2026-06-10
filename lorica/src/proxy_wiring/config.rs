// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Route-table configuration snapshot (backlog #7 step 3).
//!
//! `ProxyConfig` + `RouteEntry` construction from the config store
//! (`from_store`), hostname/path route lookup (`find_route`), the
//! smooth weighted round-robin state, and keepalive pool sizing.

use std::collections::HashMap;
use std::sync::Arc;

use lorica_config::models::{Backend, Certificate, Route};
use tracing::warn;

use super::{compile_rewrite_rule, CompiledRewriteRule};

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
        // `contains_key` first so the steady state (all backends known)
        // does zero `String` allocations inside the mutex; only a
        // first-seen backend pays for the owned key (audit #41a, was
        // 2N allocations per request via `entry(addr.to_string())`).
        for (i, (addr, _)) in backends.iter().enumerate() {
            if !cw.contains_key(*addr) {
                let head_start = if i == self.worker_offset % backends.len() {
                    1 // tiny head start to win first tie-break
                } else {
                    0
                };
                cw.insert((*addr).to_string(), head_start);
            }
        }

        // Increase all current_weights by their effective weight.
        // Every address was ensured present just above, so the lookup
        // never misses.
        for (addr, weight) in backends {
            if let Some(w) = cw.get_mut(*addr) {
                *w += weight;
            }
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
/// Some fields are only read via the `Debug` derive (diagnostic
/// serialisation) or by conditional code paths; `dead_code` is
/// suppressed to keep the struct complete.
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
    /// Pre-compiled regex set for bot-protection `bypass.user_agents`.
    /// Built once at config-reload time so the per-request evaluate()
    /// path does not re-compile patterns on every hit. `None` when
    /// bot-protection is disabled or the UA bypass list is empty.
    pub bot_ua_regex_set: Option<Arc<regex::RegexSet>>,
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
    /// Story 8.2 AC #3 - global default applied when an AI-bot
    /// crawler's verification (Rdns / IpRanges) fails. Per-route
    /// `Route.ai_bot_spoofed_fallback` overrides this.
    pub ai_bot_treat_spoofed_as: lorica_config::models::SpoofedFallback,
    /// Story 8.2 AC #11 - inject `X-Lorica-Verified-Bot` +
    /// `X-Lorica-Bot-Verification` headers upstream when verification
    /// confirms.
    pub ai_bot_inject_headers: bool,
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
    /// Story 8.2 AC #3 / #11. Both fields plumbed at config-load
    /// time and exposed read-only on `ProxyConfig` for filter-chain
    /// consumption (no hot-path settings lookup).
    pub ai_bot_treat_spoofed_as: lorica_config::models::SpoofedFallback,
    pub ai_bot_inject_headers: bool,
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
            ai_bot_treat_spoofed_as,
            ai_bot_inject_headers,
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

            let bot_ua_regex_set = route.bot_protection.as_ref().and_then(|bp| {
                let pats = &bp.bypass.user_agents;
                if pats.is_empty() {
                    return None;
                }
                match regex::RegexSet::new(pats) {
                    Ok(set) => Some(Arc::new(set)),
                    Err(e) => {
                        warn!(
                            route_id = %route.id,
                            error = %e,
                            "bot bypass UA regex set failed to compile; \
                             UA bypass disabled for this route"
                        );
                        None
                    }
                }
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
                bot_ua_regex_set,
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
            entries.sort_by_key(|e| std::cmp::Reverse(e.route.path_prefix.len()));
        }
        for (_, entries) in &mut wildcard_routes {
            entries.sort_by_key(|e| std::cmp::Reverse(e.route.path_prefix.len()));
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
            ai_bot_treat_spoofed_as,
            ai_bot_inject_headers,
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
