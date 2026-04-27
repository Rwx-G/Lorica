// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `check_<name>` helpers extracted from `request_filter`
//! (Story 8.1 AC #5). Each method on `LoricaProxy` returns
//! `Option<Decision>` (sync) or `Result<Option<Decision>>` (async /
//! fallible) and folds one early-return branch from the original
//! ~1800-LOC `request_filter` body. The top-level filter chain reads
//! as a sequence of :
//!
//! ```text
//! if let Some(d) = self.check_X(...).await? {
//!     return write_decision(session, &ctx.request_id, d).await;
//! }
//! ```
//!
//! 11 helpers landed here ; the 5 that resisted clean extraction
//! (return_status, legacy rate_limit_rps with auto-ban, WAF block in
//! request_filter / request_body_filter, async forward_auth) stay
//! inline in `proxy_wiring.rs` with a documented exception.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use lorica_proxy::Session;

use super::super::build_redirect_location;
use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::helpers::{downstream_ssl_digest, evaluate_mtls, extract_host, ip_matches};
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
    /// Reject the request when the process-wide active-connection
    /// counter is at or above the configured `max_global_connections`.
    /// Returns `None` when the limit is unset (0) or the current
    /// count is below it. Pre-route check : no per-route override is
    /// consultable, so the default Lorica error page is rendered.
    pub(crate) fn check_global_connection_limit(&self, ctx: &mut RequestCtx) -> Option<Decision> {
        let config = self.config.load();
        if config.max_global_connections == 0 {
            return None;
        }
        let current = self.active_connections.load(Ordering::Relaxed);
        if current >= config.max_global_connections as u64 {
            ctx.block_reason = Some("global connection limit".to_string());
            Some(Decision::reject(503, "Global connection limit exceeded"))
        } else {
            None
        }
    }

    /// Reject when the client IP is in the auto-ban list and the
    /// ban has not yet expired. Lazy-evicts expired bans on lookup
    /// so the map does not grow unbounded with stale entries. Pre-
    /// route check.
    pub(crate) fn check_ip_banned(&self, ctx: &mut RequestCtx, client_ip: &str) -> Option<Decision> {
        let banned = if let Some(entry) = self.ban_list.get(client_ip) {
            let (banned_at, duration_s) = entry.value();
            if banned_at.elapsed() >= Duration::from_secs(*duration_s) {
                drop(entry);
                // Ban expired - lazy cleanup
                self.ban_list.remove(client_ip);
                false
            } else {
                true
            }
        } else {
            false
        };
        if banned {
            ctx.block_reason = Some("IP banned".to_string());
            Some(Decision::reject(403, "IP banned"))
        } else {
            None
        }
    }

    /// Reject when the client IP matches the WAF IP blocklist
    /// (Data-Shield ~80k-entry CIDR set, refreshed every 6h). Records
    /// a WAF event + Prometheus counter + persists to the SQLite
    /// store on hit. Pre-route check.
    ///
    /// `req` is taken explicitly (rather than re-derived from
    /// `session.req_header()` inside the helper) so the caller can
    /// keep its outstanding immutable borrow through the call - the
    /// outer `request_filter` body uses the same `req` reference for
    /// XFF parsing and host extraction further down.
    pub(crate) fn check_ip_blocked(
        &self,
        req: &lorica_http::RequestHeader,
        ctx: &mut RequestCtx,
        client_ip: &str,
    ) -> Option<Decision> {
        if !self.waf_engine.ip_blocklist().is_blocked_str(client_ip) {
            return None;
        }
        warn!(
            ip = %client_ip,
            "request blocked by IP blocklist"
        );
        ctx.waf_blocked = true;
        let path = req.uri.path();
        let host_val = extract_host(req);
        self.waf_engine.record_blocklist_event(client_ip, host_val, path);
        lorica_api::metrics::record_waf_event("ip_blocklist", "blocked");
        self.waf_counts
            .entry(("ip_blocklist".to_string(), "blocked".to_string()))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
        let host_label = if host_val.is_empty() {
            "-".to_string()
        } else {
            host_val.to_string()
        };
        let ev = lorica_waf::WafEvent {
            rule_id: 0,
            description: format!("IP {client_ip} blocked by IP blocklist"),
            category: lorica_waf::RuleCategory::IpBlocklist,
            severity: 5,
            matched_field: "client_ip".to_string(),
            matched_value: client_ip.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: client_ip.to_string(),
            route_hostname: host_label,
            action: "blocked".to_string(),
        };
        self.persist_waf_event(&ev);
        Some(Decision::reject(403, "IP blocked"))
    }

    /// Reject WebSocket upgrade attempts when the matched route has
    /// `websocket_enabled = false`. Returns `None` for non-upgrade
    /// requests or when the route allows WebSocket. Route-aware check
    /// (runs after `find_route` succeeds).
    pub(crate) fn check_websocket_disabled(
        &self,
        req: &lorica_http::RequestHeader,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
    ) -> Option<Decision> {
        if entry.route.websocket_enabled {
            return None;
        }
        let upgrade = req.headers.get("upgrade")?;
        if !upgrade
            .to_str()
            .unwrap_or("")
            .eq_ignore_ascii_case("websocket")
        {
            return None;
        }
        ctx.block_reason = Some("WebSocket disabled".to_string());
        Some(
            Decision::reject(403, "WebSocket upgrades disabled on this route")
                .with_html(entry.route.error_page_html.clone()),
        )
    }

    /// Reject with 503 + `Retry-After: 300` when the matched route is
    /// in `maintenance_mode`. Reads from `ctx.route_snapshot` so the
    /// caller does not need a separate `entry` reference.
    pub(crate) fn check_maintenance_mode(&self, ctx: &mut RequestCtx) -> Option<Decision> {
        let route = ctx.route_snapshot.as_ref()?;
        if !route.maintenance_mode {
            return None;
        }
        ctx.block_reason = Some("maintenance mode".to_string());
        Some(
            Decision::reject(503, "Service under maintenance")
                .with_html(route.error_page_html.clone())
                .with_header("Retry-After", "300".to_string()),
        )
    }

    /// Reject when the client IP fails the per-route allow / deny
    /// list. Allowlist takes precedence : a non-empty allowlist that
    /// the IP is NOT in returns 403. A denylist match also returns
    /// 403. CIDR ranges + bare IPs are both supported (see
    /// `helpers::ip_matches`).
    pub(crate) fn check_ip_allow_deny(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        client_ip: &str,
    ) -> Option<Decision> {
        if !entry.route.ip_allowlist.is_empty()
            && !entry
                .route
                .ip_allowlist
                .iter()
                .any(|a| ip_matches(client_ip, a))
        {
            ctx.block_reason = Some("IP not in allowlist".to_string());
            return Some(
                Decision::reject(403, "IP not in allowlist")
                    .with_html(entry.route.error_page_html.clone()),
            );
        }
        if entry
            .route
            .ip_denylist
            .iter()
            .any(|d| ip_matches(client_ip, d))
        {
            ctx.block_reason = Some("IP in denylist".to_string());
            return Some(
                Decision::reject(403, "IP in denylist")
                    .with_html(entry.route.error_page_html.clone()),
            );
        }
        None
    }

    /// Reject with 408 when request headers took longer than
    /// `route.slowloris_threshold_ms` to arrive (slow-headers attack
    /// detection). The threshold is measured from `ctx.start_time`.
    /// `client_ip` is logged-only ; the comparison uses ctx timing.
    pub(crate) fn check_slowloris(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        client_ip: Option<&str>,
    ) -> Option<Decision> {
        let slowloris_ms = entry.route.slowloris_threshold_ms;
        if slowloris_ms <= 0 {
            return None;
        }
        let elapsed_ms = ctx.start_time.elapsed().as_millis() as i32;
        if elapsed_ms <= slowloris_ms {
            return None;
        }
        warn!(
            ip = %client_ip.unwrap_or("-"),
            elapsed_ms = elapsed_ms,
            threshold_ms = slowloris_ms,
            route_id = %entry.route.id,
            "slowloris detected - slow request headers"
        );
        ctx.block_reason = Some("slowloris detected".to_string());
        Some(
            Decision::reject(408, "Request headers took too long")
                .with_html(entry.route.error_page_html.clone()),
        )
    }

    /// Per-route token-bucket rate limit (the new `RateLimit` struct
    /// path - distinct from the legacy `rate_limit_rps` engine). Runs
    /// after ban / blocklist + redirects so abusive clients get
    /// rejected before WAF / mTLS / forward-auth. Whitelisted IPs
    /// bypass.
    pub(crate) fn check_token_bucket_rate_limit(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        is_whitelisted: bool,
    ) -> Option<Decision> {
        let rl = entry.route.rate_limit.as_ref()?;
        if is_whitelisted {
            return None;
        }
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
        if admitted {
            return None;
        }
        ctx.block_reason = Some("rate limited".to_string());
        // Retry-After in seconds. For any configured refill rate >= 1
        // tok/s, 1 second is the right advice (one token refills in
        // <= 1 s). A zero refill means a one-shot bucket that never
        // refills - advise a generous 60 s backoff instead of a tight
        // loop.
        let retry_after: u64 = if rl.refill_per_sec >= 1 { 1 } else { 60 };
        Some(
            Decision::reject(429, "Rate limit exceeded")
                .with_html(entry.route.error_page_html.clone())
                .with_header("Retry-After", retry_after.to_string()),
        )
    }

    /// Per-route mTLS enforcement gate. The listener has already
    /// validated the cert chain against the union CA bundle ; this
    /// helper just checks presence and the per-route organisation
    /// allowlist. Returns 495 (cert error) or 496 (cert required)
    /// per the semi-standard Nginx mapping.
    pub(crate) fn check_mtls(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
    ) -> Option<Decision> {
        let enforcer = entry.mtls_enforcer.as_ref()?;
        let status = evaluate_mtls(enforcer, downstream_ssl_digest(session).as_deref())?;
        ctx.block_reason = Some(format!("mtls rejected ({status})"));
        let message = match status {
            496 => "SSL certificate required",
            495 => "SSL certificate error",
            _ => "Forbidden",
        };
        Some(
            Decision::reject(status, message)
                .with_html(entry.route.error_page_html.clone()),
        )
    }

    /// Per-route active-connection cap (`max_connections`). Increments
    /// the counter on admission and stashes its handle in
    /// `ctx.route_conn_counter` so the logging() hook decrements it
    /// when the request finishes. Rejects with 503 + decrements back
    /// when the limit is reached.
    pub(crate) fn check_route_conn_limit(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
    ) -> Option<Decision> {
        let max_conn = entry.route.max_connections?;
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
            let custom_html = ctx
                .route_snapshot
                .as_ref()
                .and_then(|r| r.error_page_html.clone());
            return Some(
                Decision::reject(503, "Route connection limit exceeded").with_html(custom_html),
            );
        }
        ctx.route_conn_counter = Some(counter);
        None
    }

    /// Resolve the client's GeoIP country (when a DB is loaded), record
    /// it on the OTel root span for traffic analytics, and reject with
    /// 403 when the route's `geoip` config blocks the resolved country.
    /// Returns `(cached_country, decision)` so the caller can reuse
    /// the resolved country for downstream bot-protection bypass
    /// matching without paying a redundant `mmdb decode_path` call.
    pub(crate) fn check_geoip(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        client_ip: Option<&str>,
    ) -> (Option<String>, Option<Decision>) {
        let Some(ip_str) = client_ip else {
            return (None, None);
        };
        let Ok(ip_addr) = ip_str.parse::<std::net::IpAddr>() else {
            return (None, None);
        };
        let Some(country) = self.geoip_resolver.lookup_country(ip_addr) else {
            // DB miss / unknown range; fall through without blocking.
            // No OTel attribute when country is unknown - omitting is
            // semantically clearer than setting an empty string.
            return (None, None);
        };
        let cached_country = country.as_str().to_string();
        // Always stamp the country on the root tracing span -- the
        // attribute is useful even on requests that are not blocked
        // (traffic analytics per country, anomaly detection).
        ctx.root_tracing_span
            .record("client.geo.country_iso_code", country.as_str());

        let Some(ref geoip_cfg) = entry.route.geoip else {
            return (Some(cached_country), None);
        };
        if !geoip_cfg.blocks(country.as_str()) {
            return (Some(cached_country), None);
        }
        use lorica_config::models::GeoIpMode;
        let mode_str = match geoip_cfg.mode {
            GeoIpMode::Allowlist => "allowlist",
            GeoIpMode::Denylist => "denylist",
        };
        // Prometheus counter: bounded cardinality (routes * ~240
        // countries * 2 modes). Use entry.route.id directly - the
        // per-request ctx.route_id is only assigned further down the
        // filter (after response_headers + auth checks) and would
        // show up as "_unknown" here.
        lorica_api::metrics::inc_geoip_block(
            entry.route.id.as_str(),
            country.as_str(),
            mode_str,
        );
        let reason = format!("GeoIP blocked ({country} via {mode_str})");
        ctx.block_reason = Some(reason.clone());
        (
            Some(cached_country),
            Some(
                Decision::reject(403, reason)
                    .with_html(entry.route.error_page_html.clone()),
            ),
        )
    }

    /// Per-route `return_status` directive : when set, the request
    /// short-circuits with the configured status code instead of being
    /// proxied. Two shapes :
    ///
    /// - `return_status` alone : direct response with the default
    ///   Lorica error page (or per-route `error_page_html` override).
    /// - `return_status + redirect_to` : `Location:` redirect with
    ///   the configured status (typically 301 / 302) + no body. The
    ///   target URL is built via `build_redirect_location` which
    ///   honours the path-rule `literal_redirect` flag.
    pub(crate) fn check_return_status(
        &self,
        req: &lorica_http::RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Option<Decision> {
        let route = ctx.route_snapshot.as_ref()?;
        let status = route.return_status?;
        ctx.block_reason = Some(format!("return_status {status}"));
        if let Some(ref target) = route.redirect_to {
            let location = build_redirect_location(
                target,
                req.uri.path(),
                req.uri.query(),
                ctx.path_rule_literal_redirect,
            );
            return Some(Decision::redirect(status, location));
        }
        let error_page_html = route.error_page_html.clone();
        Some(
            Decision::reject(status, format!("return_status {status}"))
                .with_html(error_page_html),
        )
    }
}
