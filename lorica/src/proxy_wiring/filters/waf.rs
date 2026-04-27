// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! WAF `check_<name>` helpers. Two phases :
//!
//! - `check_waf_request_filter` evaluates request headers + path /
//!   query in `request_filter` (before the body arrives) and is the
//!   sole driver of WAF auto-ban (shmem cross-worker counter when
//!   shmem is configured, per-process `waf_violations` DashMap +
//!   local `ban_list` insertion otherwise).
//! - `check_waf_body_filter` evaluates the buffered request body in
//!   `request_body_filter` once the full stream has been received.
//!   No auto-ban escalation in the body path - the rule taxonomy is
//!   more discriminating in the header phase.
//!
//! Whitelisted IPs and routes without `waf_enabled` short-circuit
//! both helpers to None.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::warn;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::helpers::ip_to_shmem_key;
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
    /// Per-route WAF evaluation in `request_filter`. Collects relevant
    /// request headers (skips large / binary ones), runs the WAF
    /// engine in the route's configured mode, then handles the
    /// resulting verdict. On `Blocked` the helper records metrics,
    /// persists events, dispatches a WafAlert, bumps the auto-ban
    /// counter (shmem in multi-worker mode, per-process
    /// `waf_violations` DashMap in single-process mode), issues a
    /// local ban + IpBanned alert when the threshold is crossed, then
    /// returns `Decision::reject(403, "Request blocked by WAF")`. On
    /// `Detected` it records + persists with `action="detected"`,
    /// sets `ctx.waf_detected = true`, and returns None. On `Pass`
    /// it returns None.
    ///
    /// Whitelisted IPs and routes without `waf_enabled` short-circuit
    /// to None (no WAF eval). The caller is responsible for skipping
    /// downstream WAF body scanning when this helper returns None.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_waf_request_filter(
        &self,
        req: &lorica_http::RequestHeader,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        host: &str,
        path: &str,
        query: Option<&str>,
        client_ip: Option<&str>,
        is_whitelisted: bool,
    ) -> Option<Decision> {
        if is_whitelisted || !entry.route.waf_enabled {
            return None;
        }

        // Collect headers for inspection (skip large / binary ones).
        let headers: Vec<(&str, &str)> = req
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let name_str = name.as_str();
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
            lorica_config::models::WafMode::Detection => lorica_waf::WafMode::Detection,
            lorica_config::models::WafMode::Blocking => lorica_waf::WafMode::Blocking,
        };

        let mut verdict = self.waf_engine.evaluate(
            waf_mode,
            path,
            query,
            &headers,
            host,
            client_ip.unwrap_or("-"),
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
                    self.persist_waf_event(ev);
                }
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
                        .with_detail("client_ip", client_ip.unwrap_or("-").to_string()),
                    );
                }
                ctx.waf_blocked = true;
                ctx.matched_host = Some(host.to_string());
                ctx.matched_path = Some(path.to_string());

                // WAF auto-ban counter. Multi-worker (shmem.is_some) :
                // bump the cross-worker `waf_auto_ban` atomic ; the
                // supervisor reads it on each UDS event, decides on
                // threshold cross, broadcasts BanIp, resets the slot.
                // Single-process (shmem.is_none) : fall back to the
                // per-process `waf_violations` DashMap + local ban_list
                // insertion.
                if let Some(ip) = client_ip {
                    let config = self.config.load();
                    let threshold = config.waf_ban_threshold;
                    if threshold > 0 {
                        if let Some(region) = self.shmem {
                            let tagged = region.tagged(ip_to_shmem_key(ip));
                            let _ = region.waf_auto_ban.increment(
                                tagged,
                                1,
                                lorica_shmem::now_ns(),
                            );
                        } else {
                            let violations = self
                                .waf_violations
                                .entry(ip.to_string())
                                .or_insert_with(|| AtomicU64::new(0))
                                .fetch_add(1, Ordering::Relaxed)
                                + 1;
                            if violations >= threshold as u64 {
                                let ban_duration = config.waf_ban_duration_s;
                                self.ban_list.insert(
                                    ip.to_string(),
                                    (Instant::now(), ban_duration as u64),
                                );
                                self.waf_violations.remove(ip);
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
                                        .with_detail(
                                            "ban_duration_s",
                                            ban_duration.to_string(),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }

                Some(
                    Decision::reject(403, "Request blocked by WAF")
                        .with_html(entry.route.error_page_html.clone()),
                )
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
                    self.persist_waf_event(ev);
                }
                ctx.waf_detected = true;
                None
            }
            lorica_waf::WafVerdict::Pass => None,
        }
    }

    /// Per-route WAF body evaluation in `request_body_filter`. Runs
    /// the WAF engine against the buffered request body once the full
    /// stream has been received. Distinct from `check_waf_request_
    /// filter` which evaluates headers + path/query in `request_filter`
    /// before the body arrives. The body path has no auto-ban
    /// escalation (auto-ban is driven by header-phase blocks where the
    /// rule taxonomy is more discriminating).
    ///
    /// On `Blocked` records metrics + persists events with action=
    /// "blocked" and returns `Decision::reject(403, "Request body
    /// blocked by WAF")`. On `Detected` records + persists with
    /// action="detected", sets `ctx.waf_detected`, returns None. On
    /// `Pass` returns None.
    ///
    /// Returns None when the body buffer is empty / absent (no body
    /// to scan).
    pub(crate) fn check_waf_body_filter(&self, ctx: &mut RequestCtx) -> Option<Decision> {
        let buf = ctx.waf_body_buffer.as_ref()?;
        if buf.is_empty() {
            return None;
        }
        let host = ctx.matched_host.as_deref().unwrap_or("-").to_string();
        let client_ip = ctx.client_ip.as_deref().unwrap_or("-").to_string();
        let waf_mode = match ctx.route_snapshot.as_ref().map(|r| &r.waf_mode) {
            Some(lorica_config::models::WafMode::Blocking) => lorica_waf::WafMode::Blocking,
            _ => lorica_waf::WafMode::Detection,
        };

        let mut verdict = self
            .waf_engine
            .evaluate_body(waf_mode, buf, &host, &client_ip);

        match verdict {
            lorica_waf::WafVerdict::Blocked(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.clone();
                    ev.action = "blocked".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "blocked");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "blocked".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    self.persist_waf_event(ev);
                }
                ctx.waf_blocked = true;
                let custom_html = ctx
                    .route_snapshot
                    .as_ref()
                    .and_then(|r| r.error_page_html.clone());
                Some(
                    Decision::reject(403, "Request body blocked by WAF").with_html(custom_html),
                )
            }
            lorica_waf::WafVerdict::Detected(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.clone();
                    ev.action = "detected".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "detected");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "detected".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    self.persist_waf_event(ev);
                }
                ctx.waf_detected = true;
                None
            }
            lorica_waf::WafVerdict::Pass => None,
        }
    }
}
