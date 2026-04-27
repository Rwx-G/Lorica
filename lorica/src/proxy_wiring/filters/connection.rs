// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Connection-management `check_<name>` helpers : process-wide and
//! per-route active-connection caps, WebSocket upgrade gating, and
//! slow-headers (slowloris) detection. All four return early-rejection
//! `Decision`s based on connection state at request entry, before any
//! heavier per-request processing (WAF, rate limit, auth) runs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::warn;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
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
}
