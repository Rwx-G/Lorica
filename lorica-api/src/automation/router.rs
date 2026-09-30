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

//! The automation router: `whoami`, the environment resource, the read
//! surface and the write surface, the admin tier's settings write
//! included.
//!
//! `GET /automation/v1/whoami` exists so the whole chain - source
//! filter, TLS, bearer verification, scope gate, audit - is testable
//! on its own. It reports the token back to its own holder and reaches
//! nothing else, so it stays useful as the call an automation makes to
//! check that its credential is still live and still carries what it
//! expects. The environment paths (Story 10.4) live in
//! [`super::environments`], the read paths (Story 11.1) in
//! [`super::read`] and the write paths (Story 11.2) in
//! [`super::write`]; the MCP endpoint (Story 11.1 AC #9) is in
//! [`super::mcp`]. They are mounted here, and only here, so
//! the OpenAPI drift gate in `tests/openapi_contract.rs` sees every
//! automation route in one file.
//!
//! # Two routers from one route table
//!
//! [`build_automation_router`] is the listener's: every path, the MCP
//! endpoint included, under the bearer gate, the scope gate, the body
//! cap, the response hardening, the panic net and the audit layer.
//! [`in_process_router`] is the one the MCP binding runs a tool's call
//! through, in process (Story 11.2): the same route table without the
//! MCP endpoint, under the scope gate alone. It has no bearer gate
//! because the principal is already established and travels as a
//! request extension, no audit layer because the MCP POST that drove
//! the call is the request being audited, and no body cap because the
//! tool layer bounded the body before it was built. The scope gate is
//! the point: a tool's call is authorized by the same matrix as a call
//! over the socket, so a tool mis-declared against the matrix is
//! refused by the plane and not merely absent from a list.

use std::sync::OnceLock;

use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use lorica_config::models::{AutomationScope, OwnerKind, PipelineIdentity};
use serde::Serialize;
use tracing::Instrument;

use super::auth::AutomationPrincipal;
use super::environments::{
    delete_environment, get_environment, list_environments, put_environment,
};
use crate::error::json_data;
use crate::server::AppState;

/// Body cap for the automation plane.
///
/// The ceiling is deliberately far below the management plane's
/// 1 MiB: an environment declaration is a small JSON document (a
/// hostname, a handful of backends, sixteen labels at most), and the
/// cap is easier to raise for one endpoint that needs it than to
/// notice once it is wide. `lorica-mcp` bounds a write tool's body at
/// the same figure before it is built, and a test pins the two.
pub const AUTOMATION_BODY_CAP: usize = 64 * 1024;

/// What `whoami` reports.
#[derive(Debug, Serialize)]
pub struct WhoAmI {
    /// The token's operator-facing label, or the ID token's project
    /// path.
    pub name: String,
    /// The id an operator withdraws: the token's lookup half, or the
    /// issuer entry's id for an ID token.
    pub public_id: String,
    /// Which credential authenticated the request.
    pub kind: OwnerKind,
    /// Everything this credential may do.
    pub scopes: Vec<AutomationScope>,
    /// The CI job behind an ID token; absent for a static token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<PipelineIdentity>,
}

/// `GET /automation/v1/whoami` - the credential behind this request.
///
/// Never reports a secret: the node holds only a static token's HMAC,
/// and an ID token's signature is the issuer's.
pub async fn whoami(principal: AutomationPrincipal) -> axum::Json<serde_json::Value> {
    json_data(WhoAmI {
        name: principal.principal.clone(),
        public_id: principal.grant_id.clone(),
        kind: principal.kind,
        scopes: principal.scopes.clone(),
        pipeline: principal.pipeline.clone(),
    })
}

/// Wrap `router` in the audit layer and the panic net underneath it.
///
/// The two belong together and in this order. The audit layer promises
/// that EVERY request lands a row; an inner service that unwinds would
/// carry that promise away with it, and skip the row in precisely the
/// case an operator most wants one. `CatchPanicLayer` turns the unwind
/// into a 500 that returns normally, so the audit layer sees a status
/// like any other and records it with outcome `error`.
///
/// The panic net sits INSIDE the audit layer and OUTSIDE everything
/// else but the request's tracing span, so it covers the bearer gate
/// and the scope gate as well as the handlers, and so the audit layer
/// itself is never the thing being caught. The span sits between the
/// two, in the task the audit layer runs the request in.
///
/// The test router in [`super::audit`] is built through this same
/// function, which is the only way a test can assert the order the
/// production listener actually runs.
pub(super) fn with_audit_and_panic_net(router: Router, state: AppState) -> Router {
    router
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(automation_request_span))
        // `from_fn_with_state` rather than an `Extension`: the audit
        // layer is outermost, so it runs BEFORE any extension a layer
        // below inserts into the request on the way down.
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::audit::audit_automation_request,
        ))
}

/// Run the request inside an `automation_request` span naming its
/// method and path, the automation plane's `api_request` (backlog #92
/// a).
///
/// Directly inside the audit layer, so it runs in the task that layer
/// spawns and needs no span carried across the spawn: every gate and the
/// handler run inside it, and an MCP call's `mcp_tool_call` spans
/// ([`super::mcp::InProcessPlane`]) are its children, so with the
/// `otel` build a trace follows a model's call from the listener into
/// the handler the tool ran. The path and never the query: a filter
/// value is the caller's text.
async fn automation_request_span(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let span = tracing::info_span!(
        "automation_request",
        "http.request.method" = %req.method(),
        "url.path" = %req.uri().path(),
    );
    next.run(req).instrument(span).await
}

/// Add the two response headers every answer on this plane carries.
///
/// `no-store` because the answers are operational data: client
/// addresses, matched attack payloads, which node holds which
/// certificate. The plane is machine-facing with no browser in the
/// path, so neither header defends against a vector that exists today;
/// they are there for the client library or the future gateway that
/// caches or sniffs without being asked to. Written as a middleware
/// rather than `SetResponseHeaderLayer` so the crate gains no
/// `tower-http` feature for two constants.
async fn hardened_response(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    response
}

/// The route table of the plane, before any layer and without the MCP
/// endpoint: what both routers are built from.
///
/// The MCP endpoint is mounted by [`build_automation_router`] alone,
/// so a tool cannot reach the endpoint that is running it.
fn plane_routes() -> Router {
    Router::new()
        .route("/automation/v1/whoami", get(whoami))
        .route("/automation/v1/environments", get(list_environments))
        .route(
            "/automation/v1/environments/{name}",
            get(get_environment)
                .put(put_environment)
                .delete(delete_environment),
        )
        // The read surface (Story 11.1). Every one of these is a
        // wrapper over the management handler that already answers it;
        // the scope each sits behind is declared in
        // [`super::scope::required_scope`], without which it would be
        // reachable by no token at all.
        .route("/automation/v1/logs", get(super::read::list_logs))
        .route(
            "/automation/v1/waf/events",
            get(super::read::list_waf_events),
        )
        .route("/automation/v1/waf/stats", get(super::read::waf_stats))
        .route(
            "/automation/v1/sla/overview",
            get(super::read::sla_overview),
        )
        .route(
            "/automation/v1/sla/routes/{id}",
            get(super::read::route_sla),
        )
        .route(
            "/automation/v1/cluster/status",
            get(super::read::cluster_status),
        )
        .route("/automation/v1/backends", get(super::read::list_backends))
        .route("/automation/v1/routes", get(super::read::list_routes))
        .route(
            "/automation/v1/certificates",
            get(super::read::list_certificates),
        )
        // The write surface (Story 11.2). Every one of these runs the
        // management handler's own body with the token as the actor;
        // the scope each sits behind is declared in
        // [`super::scope::required_scope`] for its verb alone. There is
        // no route that takes a PEM body: the certificate create, the
        // self-signed generate and the single-certificate update are
        // deliberately absent, and the matrix declares nothing for them.
        .route("/automation/v1/routes", post(super::write::create_route))
        .route(
            "/automation/v1/routes/{id}",
            put(super::write::update_route).delete(super::write::delete_route),
        )
        .route(
            "/automation/v1/routes/{id}/certificate",
            put(super::write::bind_certificate),
        )
        .route(
            "/automation/v1/backends",
            post(super::write::create_backend),
        )
        .route(
            "/automation/v1/backends/{id}",
            put(super::write::update_backend).delete(super::write::delete_backend),
        )
        .route(
            "/automation/v1/certificates/{id}/renew",
            post(super::write::renew_certificate),
        )
        // The admin tier (Story 11.3): one verb on the settings
        // document, bounded by `super::write::SETTINGS_ALLOWLIST`. No
        // `GET`: the document is not readable on this plane, and no
        // path under users, tokens or the cluster's membership is
        // mounted here for any verb.
        .route(
            "/automation/v1/settings",
            put(super::write::update_settings),
        )
}

/// The per-credential budget of every write on this plane, one window
/// of [`crate::server::RL_WINDOW_S`] seconds.
///
/// The dashboard's writes are budgeted by a layer on each management
/// route, which the automation plane does not mount, and every settings
/// write is a proxy reload and, on a control plane, a replication round
/// to the fleet. So the plane budgets its own writes, per credential
/// rather than per address: a model in a retry loop or a leaked token
/// spends its own window and nobody else's. The settings write keeps
/// the dashboard's own figure for it; every other write shares the
/// figure the dashboard gives route writes. "Credential" is
/// [`AutomationPrincipal::budget_key`]: a static token, or one project
/// under an OIDC issuer entry, never the whole entry. The environment
/// resource's writes are budgeted here too, since 1.9.0. The MCP
/// endpoint is not a write here: its tool calls come back through
/// [`in_process_router`], where this same budget weighs each write they
/// make, beside the endpoint's own invocation budget.
fn write_budget(method: &http::Method, path: &str) -> Option<(&'static str, u32)> {
    if *method == http::Method::GET || *method == http::Method::HEAD {
        return None;
    }
    if path == super::mcp::MCP_PATH {
        return None;
    }
    if path == super::scope::SETTINGS_PATH {
        return Some(("automation_settings", crate::server::RL_SETTINGS_UPDATE));
    }
    Some(("automation_write", crate::server::RL_ROUTES_CUD))
}

/// Refuse a write with a 429 once its credential has spent the window
/// [`write_budget`] gives it. Runs inside the scope gate, so a request
/// the gate refuses spends nothing.
async fn budget_writes(
    axum::extract::Extension(state): axum::extract::Extension<AppState>,
    principal: AutomationPrincipal,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, crate::error::ApiError> {
    let Some((bucket, limit)) = write_budget(request.method(), request.uri().path()) else {
        return Ok(next.run(request).await);
    };
    state
        .automation_writes
        .check_bucket(
            bucket,
            &principal.budget_key(),
            limit,
            crate::server::RL_WINDOW_S,
        )
        .await
        .map_err(|retry_after_s| crate::error::ApiError::RateLimitedBecause {
            retry_after_s,
            reason: format!(
                "this credential has made {limit} writes of this kind in the last {} seconds, \
                 the most this plane accepts",
                crate::server::RL_WINDOW_S
            ),
        })?;
    Ok(next.run(request).await)
}

/// Every authorization-class layer this plane runs on an authenticated
/// request, on both routers: the scope gate, then the write budget.
///
/// [`in_process_router`] and [`build_automation_router`] are built
/// through this one function so that what authorizes a call over the
/// socket is what authorizes a call in process by construction, and a
/// per-token check added for the listener cannot be silently absent
/// in process. Authentication, audit, the body cap and the response
/// hardening are the listener's own and stay in
/// [`build_automation_router`]: the in-process binding has an
/// established principal, an outer request being audited, a body the
/// tool layer bounded, and no wire.
fn authorized(router: Router) -> Router {
    router
        .layer(axum::middleware::from_fn(budget_writes))
        .layer(axum::middleware::from_fn(super::scope::authorize_scope))
}

/// The router the in-process MCP binding runs a tool's call through:
/// the plane's routes under [`authorized`], and nothing else.
///
/// Built once for the process and shared, since it captures no state:
/// the [`AppState`], the [`AutomationPrincipal`] and the connection
/// info travel as extensions of each request the binding builds, which
/// is exactly where the handlers and the scope gate read them from on
/// the listener. See the module documentation for what is deliberately
/// not layered here.
pub(super) fn in_process_router() -> Router {
    static IN_PROCESS: OnceLock<Router> = OnceLock::new();
    IN_PROCESS
        .get_or_init(|| authorized(plane_routes()))
        .clone()
}

/// Build the automation-plane router.
///
/// Layer order, outermost first:
///
/// 1. [`super::audit::audit_automation_request`] - outermost, so a
///    request refused by the bearer gate still lands a row.
/// 2. [`automation_request_span`] - the request's tracing span, in the
///    task the audit layer runs the request in.
/// 3. `CatchPanicLayer` - see [`with_audit_and_panic_net`].
/// 4. [`hardened_response`] - outside the gates, so a 401 and a 403
///    carry the headers too.
/// 5. [`super::auth::require_automation_auth`] - the bearer check.
/// 6. [`authorized`] - every authorization-class layer, the scope
///    floor today, shared with [`in_process_router`].
///
/// There is deliberately NO cookie layer, NO CSRF layer and NO session
/// store here. The two management planes share no credential, and the
/// cheapest way to keep that true is for this router to have no way to
/// read one.
pub fn build_automation_router(state: AppState) -> Router {
    let routed = authorized(
        plane_routes()
            // The MCP endpoint (Story 11.1 AC #9). `post` and nothing
            // else: revision 2026-07-28 removed the standalone GET
            // stream and the session DELETE, so both answer the 405
            // this mounting produces rather than a handler that
            // explains they are gone.
            .route("/automation/v1/mcp", post(super::mcp::mcp_endpoint)),
    )
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        super::auth::require_automation_auth,
    ))
    .layer(axum::middleware::from_fn(hardened_response))
    .layer(axum::extract::DefaultBodyLimit::max(AUTOMATION_BODY_CAP))
    .layer(axum::Extension(state.clone()));
    with_audit_and_panic_net(routed, state)
}
