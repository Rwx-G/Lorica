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

//! Scope authorization for the automation plane.
//!
//! The whole matrix lives in [`required_scope`], the way the whole
//! role matrix lives in [`crate::middleware::authorize::required_role`]
//! and for the same reasons: the policy stays reviewable in one
//! screen, and an endpoint added without touching this file lands on
//! the fail-closed default instead of on whatever its author assumed.
//!
//! # Why a missing scope is 403 and not 401
//!
//! By the time this layer runs, the caller has proved which credential
//! they hold. Answering 401 would tell them to present a credential
//! they already presented successfully, and would send a scope mistake
//! down the same path as a credential mistake: the automation retries,
//! or worse, an operator re-mints a token that was never the problem.
//! 403 says the token is real and the grant is not there, which is the
//! one sentence that leads to the right fix.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use lorica_config::models::AutomationScope;

use super::auth::AutomationPrincipal;
use crate::error::ApiError;

/// What a path on the automation plane demands of the credential that
/// reaches it.
///
/// `Option<AutomationScope>` had two states and used `None` for
/// "reachable by nobody", which leaves nowhere to put a path that any
/// authenticated caller may have. That is a third state and not a
/// wider grant: see [`ScopeRequirement::AnyLiveToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRequirement {
    /// Every token that got past the bearer gate reaches this path,
    /// whatever it carries.
    ///
    /// Reserved for two kinds of path, and nothing else.
    ///
    /// One discloses nothing the caller did not already present.
    /// `whoami` is that: it reports the presented token's own label, its
    /// lookup half and its own grants. Putting a scope in front of it
    /// would mean a token minted for one job cannot ask what it is,
    /// which is precisely what the MCP server's startup introspection
    /// has to do with a token carrying only read grants.
    ///
    /// The other carries its own authorization inside the request,
    /// because one requirement per path cannot express what it needs.
    /// [`super::mcp::MCP_PATH`] is that: an MCP request names its own
    /// tool and each tool has its own scope, so the endpoint is reached
    /// by any live token and every `tools/call` is authorized against
    /// the presented token's scopes, in the same matrix, by the tool
    /// registry [`lorica_mcp::server::McpServer::over`] builds for that
    /// one request. `tests/mcp_catalogue_scopes.rs` pins the scope each
    /// tool names against the scope this matrix puts on the path it
    /// reads.
    ///
    /// It is not a wider grant in either case. It is the statement that
    /// the path's own gate is somewhere else, and the somewhere else is
    /// named here.
    AnyLiveToken,
    /// The named scope, and a 403 for a token that does not carry it.
    Scope(AutomationScope),
}

/// What a request needs, or `None` when nothing has been declared for
/// it.
///
/// `None` refuses every token, including one carrying every scope in
/// the enum. Naming the widest grant as the default would look
/// fail-closed and would not be: a route added without a declaration
/// would stay reachable by exactly the tokens that can do the most
/// damage, and nothing would say so. Refusing outright turns a missing
/// declaration into a 403 for everyone, which is a bug someone reports
/// on the first call rather than a grant nobody notices.
///
/// ```
/// use lorica_api::automation::{required_scope, ScopeRequirement};
/// use lorica_config::models::AutomationScope;
///
/// assert_eq!(
///     required_scope(&http::Method::GET, "/automation/v1/whoami"),
///     Some(ScopeRequirement::AnyLiveToken)
/// );
/// assert_eq!(
///     required_scope(&http::Method::GET, "/automation/v1/environments"),
///     Some(ScopeRequirement::Scope(AutomationScope::EnvironmentsRead))
/// );
/// // An undeclared path is reachable by nobody, not by the most
/// // privileged token.
/// assert_eq!(
///     required_scope(&http::Method::GET, "/automation/v1/not-a-route"),
///     None
/// );
/// ```
pub fn required_scope(method: &http::Method, path: &str) -> Option<ScopeRequirement> {
    declaration(method, path).map(|(_, requirement)| requirement)
}

/// The path template this request matched, or `None` for a path the
/// plane declares nothing for.
///
/// Templates and not raw paths, because the consumer is a metric label:
/// an environment name and a route id are the caller's own text, and a
/// counter labelled by them grows one series per value anyone ever
/// sends, which is how a scrape target runs out of memory. Derived from
/// the same arms [`required_scope`] reads, so a path cannot be declared
/// and unlabelled, or labelled under a spelling the document does not
/// use.
pub fn path_template(method: &http::Method, path: &str) -> Option<&'static str> {
    declaration(method, path).map(|(template, _)| template)
}

/// What the matrix says about one `(method, path)` pair: the template
/// it is documented under, and what it demands of a credential.
///
/// One match with two readers, rather than a second matrix that would
/// have to be kept in step with this one by memory.
fn declaration(method: &http::Method, path: &str) -> Option<(&'static str, ScopeRequirement)> {
    // The method guard is not decoration: the arm below is path-shaped,
    // so without it a `POST /automation/v1/whoami` added later would
    // inherit "any live token reaches this" from a rule written about a
    // read.
    if *method == http::Method::GET && path == WHOAMI_PATH {
        return Some((WHOAMI_PATH, ScopeRequirement::AnyLiveToken));
    }

    // The MCP endpoint (Story 11.1 AC #9), declared for EVERY method on
    // purpose, which is the opposite of the rule one line above and has
    // its own reason. The router mounts it for `POST` alone, so a `GET`
    // or a `DELETE` on it is a verb that does not exist here and the
    // revision says to answer `405`. Leaving those verbs undeclared
    // would make the scope gate answer `403` first, which tells a client
    // its token lacks a grant when the truth is that the path answers
    // one verb. What the endpoint requires of a credential is decided
    // per tool call inside it: see [`ScopeRequirement::AnyLiveToken`].
    if path == super::mcp::MCP_PATH {
        return Some((super::mcp::MCP_PATH, ScopeRequirement::AnyLiveToken));
    }

    // The environment resource (Story 10.4): the collection, and one
    // environment by name. Exactly one path segment after the
    // collection, so a deeper path stays undeclared and refused.
    if let Some(rest) = path.strip_prefix(ENVIRONMENTS_PATH) {
        let is_one = one_segment_under(path, ENVIRONMENTS_PATH);
        if rest.is_empty() || is_one {
            let template = if is_one {
                ENVIRONMENT_TEMPLATE
            } else {
                ENVIRONMENTS_PATH
            };
            return match *method {
                http::Method::GET => Some((
                    template,
                    ScopeRequirement::Scope(AutomationScope::EnvironmentsRead),
                )),
                http::Method::PUT | http::Method::DELETE if is_one => Some((
                    template,
                    ScopeRequirement::Scope(AutomationScope::EnvironmentsWrite),
                )),
                _ => None,
            };
        }
    }

    // The read surface (Story 11.1). Every one of these is a GET and
    // nothing else: the tier exists to be unable to change anything, so
    // a verb the router does not mount inherits no grant here either.
    if *method == http::Method::GET {
        if let Some((template, scope)) = read_declaration(path) {
            return Some((template, ScopeRequirement::Scope(scope)));
        }
    }

    // The write surface (Story 11.2). Each entry is one management
    // write behind its own write scope, consulted for the one verb the
    // router mounts it under and for no other; a read scope reaches
    // none of them, and `GET` is never consulted here.
    if let Some((template, scope)) = write_declaration(method, path) {
        return Some((template, ScopeRequirement::Scope(scope)));
    }

    None
}

/// The template and the scope behind each `(verb, path)` of the write
/// surface, or `None` for a pair that is not one of them.
///
/// Write-only by construction: a `GET` is answered `None` before any
/// path is looked at, so the read surface cannot inherit a write scope
/// from here, and each arm names its verb, so a verb the router does
/// not mount stays undeclared and refused for every token.
///
/// What is absent is absent on purpose (Story 11.2 AC #6): no verb on
/// the certificate collection, no `PUT` on one certificate, nothing
/// under `self-signed`. Those are the management paths that accept a
/// PEM body, and key material enters this node through the management
/// API, by a human, never through a token.
fn write_declaration(method: &http::Method, path: &str) -> Option<(&'static str, AutomationScope)> {
    use http::Method;
    if *method == Method::GET {
        return None;
    }
    let is_post = *method == Method::POST;
    let is_put = *method == Method::PUT;
    let is_put_or_delete = is_put || *method == Method::DELETE;

    if is_post && path == ROUTES_PATH {
        return Some((ROUTES_PATH, AutomationScope::RoutesWrite));
    }
    if is_put_or_delete && one_segment_under(path, ROUTES_PATH) {
        return Some((ROUTE_TEMPLATE, AutomationScope::RoutesWrite));
    }
    if is_put && one_resource_action(path, ROUTES_PATH, "certificate") {
        return Some((
            ROUTE_CERTIFICATE_TEMPLATE,
            AutomationScope::CertificatesWrite,
        ));
    }
    if is_post && path == BACKENDS_PATH {
        return Some((BACKENDS_PATH, AutomationScope::BackendsWrite));
    }
    if is_put_or_delete && one_segment_under(path, BACKENDS_PATH) {
        return Some((BACKEND_TEMPLATE, AutomationScope::BackendsWrite));
    }
    if is_post && one_resource_action(path, CERTIFICATES_PATH, "renew") {
        return Some((
            CERTIFICATE_RENEW_TEMPLATE,
            AutomationScope::CertificatesWrite,
        ));
    }
    None
}

/// Whether `path` is `<collection>/<id>/<action>` with a non-empty,
/// single-segment id: one named resource and one verb on it, which is
/// the only shape a write on a sub-resource takes on this plane.
fn one_resource_action(path: &str, collection: &str, action: &str) -> bool {
    path.strip_prefix(collection)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.strip_suffix(action))
        .and_then(|id_and_slash| id_and_slash.strip_suffix('/'))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// The template and the scope behind each path of the read surface, or
/// `None` for a path that is not one of them.
///
/// Read-only by construction: [`declaration`] consults it for `GET`
/// alone, so no write scope can be reached from here.
fn read_declaration(path: &str) -> Option<(&'static str, AutomationScope)> {
    match path {
        LOGS_PATH => Some((LOGS_PATH, AutomationScope::LogsRead)),
        WAF_EVENTS_PATH => Some((WAF_EVENTS_PATH, AutomationScope::WafRead)),
        WAF_STATS_PATH => Some((WAF_STATS_PATH, AutomationScope::WafRead)),
        SLA_OVERVIEW_PATH => Some((SLA_OVERVIEW_PATH, AutomationScope::SlaRead)),
        CLUSTER_STATUS_PATH => Some((CLUSTER_STATUS_PATH, AutomationScope::ClusterRead)),
        BACKENDS_PATH => Some((BACKENDS_PATH, AutomationScope::BackendsRead)),
        ROUTES_PATH => Some((ROUTES_PATH, AutomationScope::RoutesRead)),
        CERTIFICATES_PATH => Some((CERTIFICATES_PATH, AutomationScope::CertificatesRead)),
        // One resource under a collection, and exactly one: a deeper
        // path stays undeclared and is refused for every token.
        _ if one_segment_under(path, SLA_ROUTES_PATH) => {
            Some((SLA_ROUTE_TEMPLATE, AutomationScope::SlaRead))
        }
        _ => None,
    }
}

/// Whether `path` is exactly one non-empty segment under `collection`.
///
/// The OpenAPI gate asks with the parameter normalised to `{}`, which
/// is a segment like any other, so the same rule answers both the live
/// path and the documented one.
fn one_segment_under(path: &str, collection: &str) -> bool {
    path.strip_prefix(collection)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|last| !last.is_empty() && !last.contains('/'))
}

/// The identity path, the only one any live token reaches.
const WHOAMI_PATH: &str = "/automation/v1/whoami";

/// The environment collection path; single environments hang under it.
const ENVIRONMENTS_PATH: &str = "/automation/v1/environments";

/// How `openapi-automation.yaml` spells one environment, and how the
/// metric labels it.
const ENVIRONMENT_TEMPLATE: &str = "/automation/v1/environments/{name}";

/// The access log.
pub(super) const LOGS_PATH: &str = "/automation/v1/logs";

/// Recent WAF events.
pub(super) const WAF_EVENTS_PATH: &str = "/automation/v1/waf/events";

/// The WAF summary counters.
pub(super) const WAF_STATS_PATH: &str = "/automation/v1/waf/stats";

/// Passive SLA for every route.
pub(super) const SLA_OVERVIEW_PATH: &str = "/automation/v1/sla/overview";

/// Passive SLA per route; one route id hangs under it.
pub(super) const SLA_ROUTES_PATH: &str = "/automation/v1/sla/routes";

/// How `openapi-automation.yaml` spells one route's SLA, and how the
/// metric labels it.
const SLA_ROUTE_TEMPLATE: &str = "/automation/v1/sla/routes/{id}";

/// This node's cluster role and applied configuration.
///
/// The fleet ROSTER (`/automation/v1/cluster/nodes`) is deliberately
/// not declared here and not mounted. The management plane gates it at
/// `Operator` rather than `Viewer`, because it discloses each
/// follower's source address and the hostnames whose certificate
/// private keys it holds; an automation credential carries scopes and
/// no role, so a `cluster:read` token reading it would stand a role
/// above where the management matrix put that answer. Status is
/// `Viewer` on both planes.
pub(super) const CLUSTER_STATUS_PATH: &str = "/automation/v1/cluster/status";

/// The backend listing, and the backend create.
pub(super) const BACKENDS_PATH: &str = "/automation/v1/backends";

/// How `openapi-automation.yaml` spells one backend, and how the
/// metric labels it.
const BACKEND_TEMPLATE: &str = "/automation/v1/backends/{id}";

/// The route listing, and the route create.
pub(super) const ROUTES_PATH: &str = "/automation/v1/routes";

/// How `openapi-automation.yaml` spells one route, and how the metric
/// labels it.
const ROUTE_TEMPLATE: &str = "/automation/v1/routes/{id}";

/// How `openapi-automation.yaml` spells one route's certificate
/// binding, and how the metric labels it.
const ROUTE_CERTIFICATE_TEMPLATE: &str = "/automation/v1/routes/{id}/certificate";

/// Certificate metadata; never a PEM body and never key material.
pub(super) const CERTIFICATES_PATH: &str = "/automation/v1/certificates";

/// How `openapi-automation.yaml` spells one certificate's renewal, and
/// how the metric labels it.
const CERTIFICATE_RENEW_TEMPLATE: &str = "/automation/v1/certificates/{id}/renew";

/// Axum middleware enforcing [`required_scope`] against the
/// authenticated principal.
///
/// Runs INSIDE [`super::auth::require_automation_auth`], so the
/// [`AutomationPrincipal`] extension is always present; a missing one
/// is a wiring fault and fails closed with a 500 rather than letting
/// the request through. A path with no declared scope is refused for
/// every token and logged at ERROR: see [`required_scope`].
pub async fn authorize_scope(req: Request, next: Next) -> Result<Response, ApiError> {
    let principal = req
        .extensions()
        .get::<AutomationPrincipal>()
        .ok_or_else(|| {
            ApiError::Internal("automation principal missing in the scope gate".into())
        })?;

    let path = req.uri().path().to_string();
    let Some(requirement) = required_scope(req.method(), &path) else {
        // A route reachable through this listener with no entry in the
        // matrix above. Loud, because the alternative is a grant that
        // nobody chose and nobody sees.
        tracing::error!(
            path = %path,
            method = %req.method(),
            "automation route has no declared scope; refusing it until one is added"
        );
        return Err(ApiError::Forbidden(
            "this path declares no automation scope and is reachable by no token".into(),
        ));
    };
    if let ScopeRequirement::Scope(needed) = requirement {
        if !principal.has_scope(needed) {
            // The message names the missing scope. That is not a
            // disclosure: the caller already holds the token and can
            // read its own scopes from `whoami`; what they cannot do is
            // guess which one this path wanted.
            return Err(ApiError::Forbidden(format!(
                "this token does not carry the {} scope",
                scope_str(needed)
            )));
        }
    }

    Ok(next.run(req).await)
}

/// The wire spelling of a scope, matching its serde rename so an
/// operator reads the same string in the error, in the audit row and
/// in the token.
///
/// The vocabulary is owned by the serde renames on `AutomationScope`.
/// This match restates it once, for the messages an operator reads
/// here and in [`super::audit`], and the test below walks
/// [`AutomationScope::ALL`] to assert it agrees with serde, so a
/// variant added to the enum stops this file compiling and a variant
/// spelled differently here fails that test. The other restatements are
/// named in the comment above the enum.
pub(super) fn scope_str(scope: AutomationScope) -> &'static str {
    match scope {
        AutomationScope::EnvironmentsWrite => "environments:write",
        AutomationScope::EnvironmentsRead => "environments:read",
        AutomationScope::RoutesRead => "routes:read",
        AutomationScope::CertificatesRead => "certificates:read",
        AutomationScope::LogsRead => "logs:read",
        AutomationScope::WafRead => "waf:read",
        AutomationScope::SlaRead => "sla:read",
        AutomationScope::ClusterRead => "cluster:read",
        AutomationScope::BackendsRead => "backends:read",
        AutomationScope::RoutesWrite => "routes:write",
        AutomationScope::BackendsWrite => "backends:write",
        AutomationScope::CertificatesWrite => "certificates:write",
    }
}

/// Every path of the read surface beside the scope it sits behind, as a
/// request a test can actually send.
///
/// Test-only, and deliberately spelled out rather than read back from
/// [`read_declaration`]: a list derived from the code under test agrees
/// with that code whatever it says. It is the ONE statement of the
/// surface, walked by this module's matrix tests and by the AC #5
/// secret sweep in `crate::tests` alike, so a path added to the matrix
/// and forgotten in either place fails in the other rather than
/// shrinking a sweep in silence.
#[cfg(test)]
pub(crate) const READ_SURFACE: &[(&str, AutomationScope)] = &[
    ("/automation/v1/logs", AutomationScope::LogsRead),
    ("/automation/v1/waf/events", AutomationScope::WafRead),
    ("/automation/v1/waf/stats", AutomationScope::WafRead),
    ("/automation/v1/sla/overview", AutomationScope::SlaRead),
    ("/automation/v1/sla/routes/r-1", AutomationScope::SlaRead),
    (
        "/automation/v1/cluster/status",
        AutomationScope::ClusterRead,
    ),
    ("/automation/v1/backends", AutomationScope::BackendsRead),
    ("/automation/v1/routes", AutomationScope::RoutesRead),
    (
        "/automation/v1/certificates",
        AutomationScope::CertificatesRead,
    ),
];

/// Every `(verb, path)` of the write surface beside the scope it sits
/// behind, as a request a test can actually send.
///
/// The same statement [`READ_SURFACE`] makes for the reads, for the
/// same reason: spelled out rather than read back from
/// [`write_declaration`], walked by this module's matrix tests and by
/// the write-surface tests in `crate::tests` alike, so a write path
/// added to the matrix and forgotten in either place fails in the
/// other. The verb is a `&str` and not an `http::Method` so the list
/// can be a `const` without a question about drop glue.
#[cfg(test)]
pub(crate) const WRITE_SURFACE: &[(&str, &str, AutomationScope)] = &[
    (
        "POST",
        "/automation/v1/routes",
        AutomationScope::RoutesWrite,
    ),
    (
        "PUT",
        "/automation/v1/routes/r-1",
        AutomationScope::RoutesWrite,
    ),
    (
        "DELETE",
        "/automation/v1/routes/r-1",
        AutomationScope::RoutesWrite,
    ),
    (
        "PUT",
        "/automation/v1/routes/r-1/certificate",
        AutomationScope::CertificatesWrite,
    ),
    (
        "POST",
        "/automation/v1/backends",
        AutomationScope::BackendsWrite,
    ),
    (
        "PUT",
        "/automation/v1/backends/b-1",
        AutomationScope::BackendsWrite,
    ),
    (
        "DELETE",
        "/automation/v1/backends/b-1",
        AutomationScope::BackendsWrite,
    ),
    (
        "POST",
        "/automation/v1/certificates/c-1/renew",
        AutomationScope::CertificatesWrite,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    /// The verb of one [`WRITE_SURFACE`] entry.
    fn verb(spelled: &str) -> Method {
        spelled.parse().expect("the write surface spells its verbs")
    }

    /// What the write surface declares for `(method, path)`, or `None`
    /// when it declares nothing there.
    fn written(method: &Method, path: &str) -> Option<ScopeRequirement> {
        WRITE_SURFACE
            .iter()
            .find(|(spelled, written_path, _)| verb(spelled) == *method && *written_path == path)
            .map(|(_, _, scope)| ScopeRequirement::Scope(*scope))
    }

    #[test]
    fn whoami_is_reachable_by_any_live_token_and_only_on_get() {
        assert_eq!(
            required_scope(&Method::GET, WHOAMI_PATH),
            Some(ScopeRequirement::AnyLiveToken)
        );
        // The arm is method-guarded, so a verb the router does not
        // mount inherits nothing from it.
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            assert_eq!(required_scope(&method, WHOAMI_PATH), None, "{method}");
        }
    }

    #[test]
    fn an_undeclared_path_is_reachable_by_nobody_not_by_the_widest_token() {
        // The tempting default is the widest scope, which reads as
        // fail-closed and is not: it leaves a route added without a
        // declaration open to exactly the tokens that can do the most,
        // and says nothing. `None` refuses every token, so the missing
        // declaration surfaces as a 403 on the first call.
        for path in [
            "/automation/v1/tokens",
            "/automation/v1/environments/pr-42/backends",
            "/automation/v1/environments/",
            "/automation/v1/whoami/extra",
            "/",
        ] {
            assert_eq!(required_scope(&Method::GET, path), None, "{path}");
        }
    }

    #[test]
    fn the_environment_paths_read_with_read_and_write_with_write() {
        let read = Some(ScopeRequirement::Scope(AutomationScope::EnvironmentsRead));
        let write = Some(ScopeRequirement::Scope(AutomationScope::EnvironmentsWrite));
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/environments"),
            read
        );
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/environments/pr-42"),
            read
        );
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/environments/pr-42"),
            write
        );
        assert_eq!(
            required_scope(&Method::DELETE, "/automation/v1/environments/pr-42"),
            write
        );
        // The OpenAPI gate asks with the parameter normalised away.
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/environments/{}"),
            write
        );
        // No verb the router does not mount inherits a scope: a POST on
        // the collection or a PUT on it is refused for every token.
        assert_eq!(
            required_scope(&Method::POST, "/automation/v1/environments"),
            None
        );
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/environments"),
            None
        );
        assert_eq!(
            required_scope(&Method::POST, "/automation/v1/environments/pr-42"),
            None
        );
    }

    /// A principal carrying exactly `scopes`, and otherwise the
    /// narrowest grant a minted token can have.
    fn principal_carrying(scopes: Vec<AutomationScope>) -> AutomationPrincipal {
        AutomationPrincipal {
            kind: lorica_config::models::OwnerKind::StaticToken,
            principal: "acme-ci".to_string(),
            grant_id: "0123456789abcdef01234567".to_string(),
            scopes,
            allowed_hostnames: vec!["*.review.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            pipeline: None,
            required_environment_slug: None,
        }
    }

    /// `GET path` through the scope layer alone, with `principal`
    /// already installed, against a handler that answers on every path
    /// the caller reaches.
    async fn through_the_layer(principal: AutomationPrincipal, path: &str) -> http::StatusCode {
        through_the_layer_with(Method::GET, principal, path).await
    }

    /// [`through_the_layer`] for any verb.
    async fn through_the_layer_with(
        method: Method,
        principal: AutomationPrincipal,
        path: &str,
    ) -> http::StatusCode {
        use axum::body::Body;
        use axum::routing::any;
        use axum::{Extension, Router};
        use http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route(path, any(|| async { "reached" }))
            .layer(axum::middleware::from_fn(authorize_scope))
            .layer(Extension(principal));

        app.oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .expect("test setup: request builds"),
        )
        .await
        .expect("test setup: request runs")
        .status()
    }

    #[tokio::test]
    async fn the_layer_refuses_an_undeclared_path_for_a_token_holding_every_scope() {
        // The matrix test above asserts the function. This one asserts
        // the layer consults it, which is the half a caller meets: a
        // handler mounted on a path with no declaration must be
        // unreachable, and unreachable by the widest token there is.
        let widest = principal_carrying(AutomationScope::ALL.to_vec());
        assert_eq!(
            through_the_layer(widest, "/automation/v1/tokens").await,
            http::StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn the_layer_lets_any_live_token_reach_whoami_whatever_it_carries() {
        // The case the MCP server's startup introspection is: a token
        // whose grants say nothing about environments still has to be
        // able to ask what it is. Asserted through the layer and not
        // only on the matrix, because the layer is where the old rule
        // turned this into a 403.
        for scopes in [
            vec![AutomationScope::LogsRead],
            vec![AutomationScope::EnvironmentsWrite],
            AutomationScope::ALL.to_vec(),
        ] {
            assert_eq!(
                through_the_layer(principal_carrying(scopes.clone()), WHOAMI_PATH).await,
                http::StatusCode::OK,
                "{scopes:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_layer_still_refuses_a_scoped_path_the_token_does_not_carry() {
        // The mirror of the test above: widening `whoami` must not have
        // widened anything else on the plane.
        let reader = principal_carrying(vec![AutomationScope::LogsRead]);
        assert_eq!(
            through_the_layer(reader, "/automation/v1/environments").await,
            http::StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn every_read_path_declares_its_scope_and_only_on_get() {
        for (path, scope) in READ_SURFACE {
            assert_eq!(
                required_scope(&Method::GET, path),
                Some(ScopeRequirement::Scope(*scope)),
                "{path}"
            );
            // The read tier exists to be unable to change anything. A
            // verb on a read path is either one the write surface
            // declares, behind a write scope of its own, or nothing: a
            // rule written about a read grants no other verb.
            for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                assert_eq!(
                    required_scope(&method, path),
                    written(&method, path),
                    "{method} {path}"
                );
            }
        }
    }

    #[test]
    fn every_write_path_declares_its_scope_on_its_verb_and_on_no_other() {
        for (spelled, path, scope) in WRITE_SURFACE {
            let method = verb(spelled);
            assert_eq!(
                required_scope(&method, path),
                Some(ScopeRequirement::Scope(*scope)),
                "{method} {path}"
            );
            assert!(
                scope_str(*scope).ends_with(":write"),
                "{method} {path} sits behind {}, which is not a write scope",
                scope_str(*scope)
            );
            // `GET` on a write path is the read surface's business or
            // nobody's; it never inherits the write scope.
            assert_ne!(
                required_scope(&Method::GET, path),
                Some(ScopeRequirement::Scope(*scope)),
                "GET {path} inherits the write scope"
            );
            for other in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                if other == method {
                    continue;
                }
                assert_eq!(
                    required_scope(&other, path),
                    written(&other, path),
                    "{other} {path}"
                );
            }
        }
    }

    #[test]
    fn no_path_that_takes_key_material_is_declared_for_any_verb() {
        // Story 11.2 AC #6. The management paths that accept a PEM body
        // are the certificate create, the self-signed generate and the
        // single-certificate update. None of them is declared here for
        // any verb, so none is reachable by any token, whatever it
        // carries; the binding and the renewal are the only certificate
        // writes on this plane.
        for (method, path) in [
            (Method::POST, "/automation/v1/certificates"),
            (Method::PUT, "/automation/v1/certificates"),
            (Method::POST, "/automation/v1/certificates/self-signed"),
            (Method::PUT, "/automation/v1/certificates/c-1"),
            (Method::POST, "/automation/v1/certificates/c-1"),
            (Method::DELETE, "/automation/v1/certificates/c-1"),
            (Method::GET, "/automation/v1/certificates/c-1/download"),
            (Method::POST, "/automation/v1/acme/provision"),
        ] {
            assert_eq!(required_scope(&method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn a_write_on_a_sub_resource_names_exactly_one_resource() {
        let bind = Some(ScopeRequirement::Scope(AutomationScope::CertificatesWrite));
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/routes/r-1/certificate"),
            bind
        );
        // The OpenAPI gate asks with the parameter normalised away.
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/routes/{}/certificate"),
            bind
        );
        for path in [
            "/automation/v1/routes//certificate",
            "/automation/v1/routes/r-1/x/certificate",
            "/automation/v1/routes/r-1/certificate/",
            "/automation/v1/certificates//renew",
            "/automation/v1/certificates/c-1/renew/now",
        ] {
            assert_eq!(required_scope(&Method::PUT, path), None, "PUT {path}");
            assert_eq!(required_scope(&Method::POST, path), None, "POST {path}");
        }
        // `routes/certificate` is a route whose id is `certificate`,
        // one segment under the collection, and a route update is what
        // the matrix says it is; the binding needs the action segment
        // after the id.
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/routes/certificate"),
            Some(ScopeRequirement::Scope(AutomationScope::RoutesWrite))
        );
    }

    #[tokio::test]
    async fn no_write_path_is_reachable_by_a_token_holding_every_other_scope() {
        // Each write refused by the widest token that lacks exactly its
        // own grant, through the layer: a token carrying every read
        // scope there is, the environment write included, reaches no
        // route, backend or certificate write.
        for (spelled, path, scope) in WRITE_SURFACE {
            let everything_else: Vec<AutomationScope> = AutomationScope::ALL
                .iter()
                .copied()
                .filter(|held| held != scope)
                .collect();
            assert_eq!(
                through_the_layer_with(verb(spelled), principal_carrying(everything_else), path)
                    .await,
                http::StatusCode::FORBIDDEN,
                "{spelled} {path}"
            );
            assert_eq!(
                through_the_layer_with(verb(spelled), principal_carrying(vec![*scope]), path).await,
                http::StatusCode::OK,
                "{spelled} {path}"
            );
        }
    }

    #[tokio::test]
    async fn no_read_path_is_reachable_by_a_token_holding_every_other_scope() {
        // Each path refused by the widest token that lacks exactly its
        // own grant. Asserted through the layer, because the matrix
        // agreeing with itself proves nothing about what a caller meets.
        for (path, scope) in READ_SURFACE {
            let everything_else: Vec<AutomationScope> = AutomationScope::ALL
                .iter()
                .copied()
                .filter(|held| held != scope)
                .collect();
            assert_eq!(
                through_the_layer(principal_carrying(everything_else), path).await,
                http::StatusCode::FORBIDDEN,
                "{path}"
            );
        }
    }

    #[test]
    fn a_deeper_read_path_stays_undeclared() {
        // The collections that take one id take exactly one. Anything
        // beyond it has no entry, and no entry is a 403 for every
        // token, including one carrying every scope.
        for path in [
            "/automation/v1/sla/routes",
            "/automation/v1/sla/routes/",
            "/automation/v1/sla/routes/r-1/buckets",
            "/automation/v1/waf/rules",
            "/automation/v1/logs/export",
            "/automation/v1/certificates/c-1",
            "/automation/v1/routes/r-1",
            "/automation/v1/backends/b-1",
        ] {
            assert_eq!(required_scope(&Method::GET, path), None, "{path}");
        }
    }

    #[test]
    fn the_fleet_roster_is_reachable_by_no_token_on_this_plane() {
        // The management plane gates the roster at `Operator`, one role
        // above where this surface stands, because it discloses each
        // follower's source address and the hostnames whose private
        // keys it holds. `cluster:read` reaches status and nothing
        // else, and an undeclared path is refused for every token
        // including one carrying every scope.
        for path in [
            "/automation/v1/cluster/nodes",
            "/automation/v1/cluster/nodes/n-1",
            "/automation/v1/cluster/nodes/{}",
            "/automation/v1/cluster/nodes/n-1/activate",
        ] {
            assert_eq!(required_scope(&Method::GET, path), None, "{path}");
        }
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/cluster/status"),
            Some(ScopeRequirement::Scope(AutomationScope::ClusterRead))
        );
    }

    #[test]
    fn the_openapi_gate_sees_the_same_scope_with_the_parameter_normalised() {
        // `tests/openapi_contract.rs` asks with `{}` where the id is.
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/sla/routes/{}"),
            Some(ScopeRequirement::Scope(AutomationScope::SlaRead))
        );
    }

    #[test]
    fn every_declared_path_carries_the_template_the_document_spells_it_with() {
        // The metric's label vocabulary. A caller-chosen id must
        // collapse into the template, or one time series per route id
        // anyone ever asks about ends up in the scrape.
        assert_eq!(
            path_template(&Method::GET, "/automation/v1/sla/routes/r-1"),
            Some("/automation/v1/sla/routes/{id}")
        );
        assert_eq!(
            path_template(&Method::PUT, "/automation/v1/environments/pr-42"),
            Some("/automation/v1/environments/{name}")
        );
        assert_eq!(
            path_template(&Method::GET, "/automation/v1/environments"),
            Some("/automation/v1/environments")
        );
        for (path, _scope) in READ_SURFACE {
            assert!(
                path_template(&Method::GET, path).is_some(),
                "{path} is declared and has no template"
            );
        }
        for (spelled, path, _scope) in WRITE_SURFACE {
            let template = path_template(&verb(spelled), path);
            assert!(
                template.is_some(),
                "{spelled} {path} is declared and has no template"
            );
            assert!(
                !template
                    .is_some_and(|t| t.contains("r-1") || t.contains("b-1") || t.contains("c-1")),
                "{spelled} {path} labels the metric with the caller's own id: {template:?}"
            );
        }
        assert_eq!(
            path_template(&Method::PUT, "/automation/v1/routes/r-1/certificate"),
            Some("/automation/v1/routes/{id}/certificate")
        );
        assert_eq!(
            path_template(&Method::POST, "/automation/v1/certificates/c-1/renew"),
            Some("/automation/v1/certificates/{id}/renew")
        );
        // Undeclared is unlabelled, the same way it is unreachable.
        assert_eq!(path_template(&Method::GET, "/automation/v1/tokens"), None);
    }

    #[tokio::test]
    async fn the_layer_lets_a_read_token_reach_its_own_path_and_nothing_else() {
        let logs_only = principal_carrying(vec![AutomationScope::LogsRead]);
        assert_eq!(
            through_the_layer(logs_only.clone(), "/automation/v1/logs").await,
            http::StatusCode::OK
        );
        assert_eq!(
            through_the_layer(logs_only, "/automation/v1/waf/events").await,
            http::StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn every_scope_spells_itself_the_way_the_wire_does() {
        for scope in AutomationScope::ALL {
            assert_eq!(
                serde_json::to_string(scope).expect("scope serialises"),
                format!("\"{}\"", scope_str(*scope)),
                "{scope:?}"
            );
        }
    }
}
