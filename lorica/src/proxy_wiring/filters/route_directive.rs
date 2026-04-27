// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Route-config directive helpers : maintenance mode (503 +
//! Retry-After) and `return_status` (direct response or `Location:`
//! redirect). Both express explicit operator intent on the route and
//! short-circuit the proxy chain without consulting any runtime
//! signal (rate, WAF, auth).

use super::super::build_redirect_location;
use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::LoricaProxy;

impl LoricaProxy {
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
