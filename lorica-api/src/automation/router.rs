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
//! [`super::mcp`]. They are mounted here, and only here, from one
//! declared table, [`route_table`]: both routers are built from it, and
//! the OpenAPI drift gate in `tests/openapi_contract.rs`, the scope
//! matrix's surface tests and the admin tier's sweeps read it, so no
//! test depends on how this file is formatted.
//!
//! # Two routers from one route table
//!
//! [`build_automation_router`] is the listener's: every path, the MCP
//! endpoint included, under the bearer gate, the scope gate, the body
//! cap, the response hardening, the panic net and the audit layer.
//! [`in_process_router`] is the one the MCP binding runs a tool's call
//! through, in process (Story 11.2): the same route table without the
//! MCP endpoint, under the scope gate and the write budget alone
//! ([`authorized`]). It has no bearer gate
//! because the principal is already established and travels as a
//! request extension, no audit layer because the MCP POST that drove
//! the call is the request being audited, and no body cap because the
//! tool layer bounded the body before it was built. The scope gate is
//! the point: a tool's call is authorized by the same matrix as a call
//! over the socket, so a tool mis-declared against the matrix is
//! refused by the plane and not merely absent from a list.

use std::sync::OnceLock;

use axum::handler::Handler;
use axum::response::Response;
use axum::routing::MethodRouter;
use axum::Router;
use lorica_config::models::{AutomationScope, OwnerKind, PipelineIdentity};
use serde::Serialize;
use tracing::Instrument;

use super::auth::AutomationPrincipal;
use super::environments::{
    delete_environment, get_environment, list_environments, put_environment,
};
use super::scope::{
    required_scope, ScopeRequirement, BACKENDS_PATH, BACKEND_TEMPLATE, CERTIFICATES_PATH,
    CERTIFICATE_RENEW_TEMPLATE, CLUSTER_STATUS_PATH, ENVIRONMENTS_PATH, ENVIRONMENT_TEMPLATE,
    LOGS_PATH, ROUTES_PATH, ROUTE_CERTIFICATE_TEMPLATE, ROUTE_TEMPLATE, SETTINGS_PATH,
    SLA_OVERVIEW_PATH, SLA_ROUTE_TEMPLATE, WAF_EVENTS_PATH, WAF_STATS_PATH, WHOAMI_PATH,
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

/// One `(verb, path)` the automation plane mounts, and the handler
/// that answers it.
///
/// Only [`route_table`] builds one, so every entry a test reads is one
/// the routers are folded from.
pub struct AutomationRoute {
    /// The verb this entry mounts, and the only one it answers.
    pub method: http::Method,
    /// The path as the router matches it, which is also how
    /// `openapi-automation.yaml` spells it and how the request metric
    /// labels it: the path constants of [`super::scope`].
    pub path: &'static str,
    /// The handler's Rust path, as [`std::any::type_name`] reports it
    /// for the function mounted, so a test can find the handler's
    /// source without a second spelling of its name.
    pub handler: &'static str,
    method_router: MethodRouter,
}

impl AutomationRoute {
    fn get<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        Self {
            method: http::Method::GET,
            path,
            handler: std::any::type_name::<H>(),
            method_router: axum::routing::get(handler),
        }
    }

    fn post<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        Self {
            method: http::Method::POST,
            path,
            handler: std::any::type_name::<H>(),
            method_router: axum::routing::post(handler),
        }
    }

    fn put<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        Self {
            method: http::Method::PUT,
            path,
            handler: std::any::type_name::<H>(),
            method_router: axum::routing::put(handler),
        }
    }

    fn delete<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        Self {
            method: http::Method::DELETE,
            path,
            handler: std::any::type_name::<H>(),
            method_router: axum::routing::delete(handler),
        }
    }

    /// What the scope matrix demands of a credential on this entry,
    /// asked of [`required_scope`] with the path's template, which the
    /// matrix answers the way it answers a concrete id. `None` would be
    /// a mounted route no token reaches, and a test refuses it.
    pub fn requirement(&self) -> Option<ScopeRequirement> {
        required_scope(&self.method, self.path)
    }
}

/// Every route the automation plane mounts, the MCP endpoint included:
/// the one statement both routers are built from and every test that
/// enumerates the plane reads.
///
/// The scope each entry sits behind is declared in
/// [`super::scope::required_scope`] and not here; the matrix stays the
/// one fail-closed function that decides, and
/// [`AutomationRoute::requirement`] reads it.
///
/// ```
/// let table = lorica_api::automation::route_table();
/// assert!(table
///     .iter()
///     .any(|route| route.method == http::Method::GET && route.path == "/automation/v1/whoami"));
/// assert!(table.iter().all(|route| route.requirement().is_some()));
/// ```
pub fn route_table() -> Vec<AutomationRoute> {
    vec![
        AutomationRoute::get(WHOAMI_PATH, whoami),
        AutomationRoute::get(ENVIRONMENTS_PATH, list_environments),
        AutomationRoute::get(ENVIRONMENT_TEMPLATE, get_environment),
        AutomationRoute::put(ENVIRONMENT_TEMPLATE, put_environment),
        AutomationRoute::delete(ENVIRONMENT_TEMPLATE, delete_environment),
        // The read surface (Story 11.1). Every one of these is a
        // wrapper over the management handler that already answers it.
        AutomationRoute::get(LOGS_PATH, super::read::list_logs),
        AutomationRoute::get(WAF_EVENTS_PATH, super::read::list_waf_events),
        AutomationRoute::get(WAF_STATS_PATH, super::read::waf_stats),
        AutomationRoute::get(SLA_OVERVIEW_PATH, super::read::sla_overview),
        AutomationRoute::get(SLA_ROUTE_TEMPLATE, super::read::route_sla),
        AutomationRoute::get(CLUSTER_STATUS_PATH, super::read::cluster_status),
        AutomationRoute::get(BACKENDS_PATH, super::read::list_backends),
        AutomationRoute::get(ROUTES_PATH, super::read::list_routes),
        AutomationRoute::get(CERTIFICATES_PATH, super::read::list_certificates),
        // The write surface (Story 11.2). Every one of these runs the
        // management handler's own body with the token as the actor.
        // There is no route that takes a PEM body: the certificate
        // create, the self-signed generate and the single-certificate
        // update are deliberately absent, and the matrix declares
        // nothing for them.
        AutomationRoute::post(ROUTES_PATH, super::write::create_route),
        AutomationRoute::put(ROUTE_TEMPLATE, super::write::update_route),
        AutomationRoute::delete(ROUTE_TEMPLATE, super::write::delete_route),
        AutomationRoute::put(ROUTE_CERTIFICATE_TEMPLATE, super::write::bind_certificate),
        AutomationRoute::post(BACKENDS_PATH, super::write::create_backend),
        AutomationRoute::put(BACKEND_TEMPLATE, super::write::update_backend),
        AutomationRoute::delete(BACKEND_TEMPLATE, super::write::delete_backend),
        AutomationRoute::post(CERTIFICATE_RENEW_TEMPLATE, super::write::renew_certificate),
        // The admin tier (Story 11.3): one verb on the settings
        // document, bounded by `super::write::SETTINGS_ALLOWLIST`. No
        // `GET`: the document is not readable on this plane, and no
        // path under users, tokens or the cluster's membership is
        // mounted here for any verb.
        AutomationRoute::put(SETTINGS_PATH, super::write::update_settings),
        // The MCP endpoint (Story 11.1 AC #9). `POST` and nothing
        // else: revision 2026-07-28 removed the standalone GET stream
        // and the session DELETE, so both answer the 405 this mounting
        // produces rather than a handler that explains they are gone.
        // `plane_routes` leaves it out, so a tool cannot reach the
        // endpoint that is running it.
        AutomationRoute::post(super::mcp::MCP_PATH, super::mcp::mcp_endpoint),
    ]
}

/// A router mounting `routes` and nothing else, before any layer.
///
/// Two entries on one path merge into one method router, which is how
/// a collection answers both its listing and its create.
fn mounted(routes: impl IntoIterator<Item = AutomationRoute>) -> Router {
    routes.into_iter().fold(Router::new(), |router, route| {
        router.route(route.path, route.method_router)
    })
}

/// The route table of the plane, before any layer and without the MCP
/// endpoint: what [`in_process_router`] is built from.
fn plane_routes() -> Router {
    mounted(
        route_table()
            .into_iter()
            .filter(|route| route.path != super::mcp::MCP_PATH),
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
///    gate and the write budget, shared with [`in_process_router`].
///
/// There is deliberately NO cookie layer, NO CSRF layer and NO session
/// store here. The two management planes share no credential, and the
/// cheapest way to keep that true is for this router to have no way to
/// read one.
pub fn build_automation_router(state: AppState) -> Router {
    let routed = authorized(mounted(route_table()))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::require_automation_auth,
        ))
        .layer(axum::middleware::from_fn(hardened_response))
        .layer(axum::extract::DefaultBodyLimit::max(AUTOMATION_BODY_CAP))
        .layer(axum::Extension(state.clone()));
    with_audit_and_panic_net(routed, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    const EVERY_VERB: [http::Method; 5] = [
        http::Method::GET,
        http::Method::POST,
        http::Method::PUT,
        http::Method::DELETE,
        http::Method::PATCH,
    ];

    /// `path` with each `{parameter}` given a concrete one-segment value.
    fn concrete(path: &str) -> String {
        path.split('/')
            .map(|segment| {
                if segment.starts_with('{') {
                    "x-1"
                } else {
                    segment
                }
            })
            .collect::<Vec<&str>>()
            .join("/")
    }

    /// What `router` answers to a bodiless `method` on `path`. No
    /// extension is installed, so a routed request fails in its
    /// handler's extractors with anything but 404 or 405, which are the
    /// two statuses only the routing itself produces here.
    async fn answered(router: &Router, method: &http::Method, path: &str) -> http::StatusCode {
        let request = http::Request::builder()
            .method(method.clone())
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("test setup");
        router
            .clone()
            .oneshot(request)
            .await
            .expect("infallible")
            .status()
    }

    fn routed(status: http::StatusCode) -> bool {
        status != http::StatusCode::NOT_FOUND && status != http::StatusCode::METHOD_NOT_ALLOWED
    }

    /// Assert that `router` answers exactly `table`'s `(verb, path)`
    /// pairs: each one routed, every other verb on a path of the table a
    /// 405, and a path outside the table a 404.
    async fn mounts_exactly(router: Router, table: &[(http::Method, &'static str)]) {
        let paths: std::collections::BTreeSet<&str> = table.iter().map(|(_, path)| *path).collect();
        for path in &paths {
            for method in &EVERY_VERB {
                let status = answered(&router, method, &concrete(path)).await;
                if table.iter().any(|(m, p)| m == method && p == path) {
                    assert!(
                        routed(status),
                        "{method} {path} is in the table and answered {status}"
                    );
                } else {
                    assert_eq!(
                        status,
                        http::StatusCode::METHOD_NOT_ALLOWED,
                        "{method} {path} is not in the table"
                    );
                }
            }
        }
        assert_eq!(
            answered(
                &router,
                &http::Method::GET,
                "/automation/v1/not-in-the-table"
            )
            .await,
            http::StatusCode::NOT_FOUND
        );
    }

    fn pairs(table: &[AutomationRoute]) -> Vec<(http::Method, &'static str)> {
        table
            .iter()
            .map(|route| (route.method.clone(), route.path))
            .collect()
    }

    /// Who answered a request through the listener's router.
    #[derive(Debug, PartialEq, Eq)]
    enum AnsweredBy {
        /// axum's own 404 or 405, which carry no body.
        Routing,
        /// The scope gate's refusal of a pair the matrix declares for
        /// no token.
        UndeclaredRefusal,
        /// Anything past both: a handler ran.
        Handler,
    }

    #[tokio::test]
    async fn the_listener_router_reaches_a_handler_for_exactly_the_tables_pairs() {
        // Through `build_automation_router` itself, with a token holding
        // every scope, so the bearer gate and the scope gate let a
        // declared pair through to whatever the listener mounts. The
        // gates answer for every request, routed or not, so a pair is
        // mounted exactly when a handler answers it.
        let f = crate::automation::test_support::a_node_with_something_to_write().await;
        let router = build_automation_router(f.state.clone());
        let answered_by = |method: http::Method, path: String| {
            let router = router.clone();
            let bearer = f.bearer.clone();
            async move {
                let response = router
                    .oneshot(
                        http::Request::builder()
                            .method(method)
                            .uri(path)
                            .header(http::header::AUTHORIZATION, bearer)
                            .body(axum::body::Body::empty())
                            .expect("test setup"),
                    )
                    .await
                    .expect("infallible");
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("the body reads");
                if (status == http::StatusCode::NOT_FOUND
                    || status == http::StatusCode::METHOD_NOT_ALLOWED)
                    && body.is_empty()
                {
                    AnsweredBy::Routing
                } else if status == http::StatusCode::FORBIDDEN
                    && String::from_utf8_lossy(&body).contains("declares no automation scope")
                {
                    AnsweredBy::UndeclaredRefusal
                } else {
                    AnsweredBy::Handler
                }
            }
        };

        let table = pairs(&route_table());
        let paths: std::collections::BTreeSet<&str> = table.iter().map(|(_, path)| *path).collect();
        for path in paths {
            for method in EVERY_VERB {
                let by = answered_by(method.clone(), concrete(path)).await;
                if table.iter().any(|(m, p)| *m == method && *p == path) {
                    assert_eq!(by, AnsweredBy::Handler, "{method} {path} is in the table");
                } else {
                    assert_ne!(
                        by,
                        AnsweredBy::Handler,
                        "{method} {path} is not in the table"
                    );
                }
            }
        }
        let outside = answered_by(
            http::Method::GET,
            "/automation/v1/not-in-the-table".to_string(),
        )
        .await;
        assert_ne!(outside, AnsweredBy::Handler);
    }

    #[tokio::test]
    async fn the_in_process_router_mounts_the_table_without_the_mcp_endpoint() {
        let table: Vec<(http::Method, &'static str)> = pairs(&route_table())
            .into_iter()
            .filter(|(_, path)| *path != super::super::mcp::MCP_PATH)
            .collect();
        mounts_exactly(plane_routes(), &table).await;
        assert_eq!(
            answered(
                &plane_routes(),
                &http::Method::POST,
                super::super::mcp::MCP_PATH
            )
            .await,
            http::StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn every_route_in_the_table_is_declared_in_the_scope_matrix() {
        // A mounted route the matrix declares nothing for is refused for
        // every token: a dead route, or a declaration somebody forgot.
        let table = route_table();
        assert!(!table.is_empty());
        for route in &table {
            assert!(
                route.requirement().is_some(),
                "{} {} is mounted and declared for no token",
                route.method,
                route.path
            );
        }
    }

    #[test]
    fn each_entry_names_the_function_it_mounts() {
        let table = route_table();
        let whoami_entry = table
            .iter()
            .find(|route| route.path == WHOAMI_PATH)
            .expect("whoami is mounted");
        assert_eq!(
            whoami_entry.handler,
            "lorica_api::automation::router::whoami"
        );
        for route in &table {
            assert!(
                route.handler.starts_with("lorica_api::automation::"),
                "{} {} is handled by {}",
                route.method,
                route.path,
                route.handler
            );
        }
    }
}
