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
    /// Reserved for a path that discloses nothing the caller did not
    /// already present. `whoami` is the one: it reports the presented
    /// token's own label, its lookup half and its own grants. Putting a
    /// scope in front of it would mean a token minted for one job
    /// cannot ask what it is, which is precisely what the MCP server's
    /// startup introspection has to do with a token carrying only read
    /// grants.
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

    None
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
const LOGS_PATH: &str = "/automation/v1/logs";

/// Recent WAF events.
const WAF_EVENTS_PATH: &str = "/automation/v1/waf/events";

/// The WAF summary counters.
const WAF_STATS_PATH: &str = "/automation/v1/waf/stats";

/// Passive SLA for every route.
const SLA_OVERVIEW_PATH: &str = "/automation/v1/sla/overview";

/// Passive SLA per route; one route id hangs under it.
const SLA_ROUTES_PATH: &str = "/automation/v1/sla/routes";

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
const CLUSTER_STATUS_PATH: &str = "/automation/v1/cluster/status";

/// The backend listing.
const BACKENDS_PATH: &str = "/automation/v1/backends";

/// The route listing.
const ROUTES_PATH: &str = "/automation/v1/routes";

/// Certificate metadata; never a PEM body and never key material.
const CERTIFICATES_PATH: &str = "/automation/v1/certificates";

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
/// operator reads the same string in the error and in the token.
///
/// The vocabulary is owned by the serde renames on `AutomationScope`.
/// This match restates it for a message an operator reads, and the test
/// below walks [`AutomationScope::ALL`] to assert the two agree, so a
/// variant added to the enum stops this file compiling and a variant
/// spelled differently here fails that test. The other restatements are
/// named in the comment above the enum.
fn scope_str(scope: AutomationScope) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

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
        use axum::body::Body;
        use axum::routing::get;
        use axum::{Extension, Router};
        use http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route(path, get(|| async { "reached" }))
            .layer(axum::middleware::from_fn(authorize_scope))
            .layer(Extension(principal));

        app.oneshot(
            Request::builder()
                .method(Method::GET)
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
            // verb the router does not mount must inherit nothing from
            // a rule written about a read.
            for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
                assert_eq!(required_scope(&method, path), None, "{method} {path}");
            }
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
