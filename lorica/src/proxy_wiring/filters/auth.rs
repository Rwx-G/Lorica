// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Authentication-gate `check_<name>` helpers : per-route mTLS
//! enforcement (495 / 496) and forward-auth sub-request dispatch
//! (Allow / Deny / FailClosed). Both run after IP / rate / WAF checks
//! so unauthenticated requests get throttled or filtered before the
//! comparatively expensive auth-service round-trip.

use std::sync::Arc;

use lorica_proxy::Session;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::forward_auth::{run_forward_auth_keyed, ForwardAuthOutcome};
use super::super::helpers::{downstream_ssl_digest, evaluate_mtls};
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
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

    /// Forward authentication gate. When the route has a
    /// `forward_auth` config, dispatches a sub-request to the auth
    /// service (Authelia / Authentik / Keycloak / oauth2-proxy) and
    /// translates the verdict to one of three outcomes :
    ///
    /// On `Allow`, harvests the response_headers the auth service
    /// asked us to inject (e.g. `Remote-User: alice`) into
    /// `ctx.forward_auth_inject` and returns None ; downstream proxy
    /// processing continues. On `Deny`, returns
    /// `Decision::passthrough` with the auth service's status +
    /// custom headers + custom body forwarded verbatim to the client.
    /// On `FailClosed` (timeout, network error), returns
    /// `Decision::reject(503, "Authentication service unavailable")`.
    ///
    /// Routes without `forward_auth` configured short-circuit to
    /// None (no sub-request, zero overhead).
    pub(crate) async fn check_forward_auth(
        &self,
        session: &Session,
        req: &lorica_http::RequestHeader,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
    ) -> Option<Decision> {
        let fa_cfg = entry.route.forward_auth.as_ref()?;
        // Detect TLS from the downstream socket, not HTTP version :
        // h2c (HTTP/2 over plaintext) would otherwise be reported as
        // https to the auth service, which is misleading and may
        // trigger redirect loops.
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
                None
            }
            ForwardAuthOutcome::Deny {
                status,
                headers,
                body,
            } => {
                ctx.block_reason = Some(format!("forward auth denied ({status})"));
                Some(Decision::passthrough(status, headers, body))
            }
            ForwardAuthOutcome::FailClosed { reason } => {
                tracing::warn!(
                    route_id = %entry.route.id,
                    reason = %reason,
                    "forward auth fail-closed"
                );
                ctx.block_reason = Some(format!("forward auth error: {reason}"));
                Some(
                    Decision::reject(503, "Authentication service unavailable")
                        .with_html(entry.route.error_page_html.clone()),
                )
            }
        }
    }
}
