// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! IP-based `check_<name>` helpers : auto-ban table lookup, WAF IP
//! blocklist (Data-Shield), and per-route allow / deny lists. The
//! three run early in the filter chain to short-circuit obviously
//! abusive or out-of-policy clients before any route-aware processing
//! kicks in.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::helpers::{extract_host, ip_matches};
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
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
}
