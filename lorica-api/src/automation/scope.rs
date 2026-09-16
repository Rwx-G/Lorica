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

/// The scope a request needs, or `None` when no scope has been
/// declared for it.
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
/// use lorica_api::automation::required_scope;
/// use lorica_config::models::AutomationScope;
///
/// assert_eq!(
///     required_scope(&http::Method::GET, "/automation/v1/whoami"),
///     Some(AutomationScope::EnvironmentsRead)
/// );
/// // An undeclared path is reachable by nobody, not by the most
/// // privileged token.
/// assert_eq!(
///     required_scope(&http::Method::GET, "/automation/v1/not-a-route"),
///     None
/// );
/// ```
pub fn required_scope(method: &http::Method, path: &str) -> Option<AutomationScope> {
    // `whoami` reports the token back to its own holder and reaches
    // nothing else, so it sits on the narrowest scope any automation
    // token that talks to this plane at all will carry.
    if path == "/automation/v1/whoami" {
        return Some(AutomationScope::EnvironmentsRead);
    }

    // The environment resource (Story 10.4): the collection, and one
    // environment by name. Exactly one path segment after the
    // collection, so a deeper path stays undeclared and refused.
    if let Some(rest) = path.strip_prefix(ENVIRONMENTS_PATH) {
        let is_collection = rest.is_empty();
        let is_one = rest
            .strip_prefix('/')
            .is_some_and(|name| !name.is_empty() && !name.contains('/'));
        if is_collection || is_one {
            return match *method {
                http::Method::GET => Some(AutomationScope::EnvironmentsRead),
                http::Method::PUT | http::Method::DELETE if is_one => {
                    Some(AutomationScope::EnvironmentsWrite)
                }
                _ => None,
            };
        }
    }

    None
}

/// The environment collection path; single environments hang under it.
const ENVIRONMENTS_PATH: &str = "/automation/v1/environments";

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
    let Some(needed) = required_scope(req.method(), &path) else {
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
    if !principal.has_scope(needed) {
        // The message names the missing scope. That is not a
        // disclosure: the caller already holds the token and can read
        // its own scopes from `whoami`; what they cannot do is guess
        // which one this path wanted.
        return Err(ApiError::Forbidden(format!(
            "this token does not carry the {} scope",
            scope_str(needed)
        )));
    }

    Ok(next.run(req).await)
}

/// The wire spelling of a scope, matching its serde rename so an
/// operator reads the same string in the error and in the token.
fn scope_str(scope: AutomationScope) -> &'static str {
    match scope {
        AutomationScope::EnvironmentsWrite => "environments:write",
        AutomationScope::EnvironmentsRead => "environments:read",
        AutomationScope::RoutesRead => "routes:read",
        AutomationScope::CertificatesRead => "certificates:read",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn whoami_needs_only_the_read_scope() {
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/whoami"),
            Some(AutomationScope::EnvironmentsRead)
        );
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
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/environments"),
            Some(AutomationScope::EnvironmentsRead)
        );
        assert_eq!(
            required_scope(&Method::GET, "/automation/v1/environments/pr-42"),
            Some(AutomationScope::EnvironmentsRead)
        );
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/environments/pr-42"),
            Some(AutomationScope::EnvironmentsWrite)
        );
        assert_eq!(
            required_scope(&Method::DELETE, "/automation/v1/environments/pr-42"),
            Some(AutomationScope::EnvironmentsWrite)
        );
        // The OpenAPI gate asks with the parameter normalised away.
        assert_eq!(
            required_scope(&Method::PUT, "/automation/v1/environments/{}"),
            Some(AutomationScope::EnvironmentsWrite)
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

    #[test]
    fn every_scope_spells_itself_the_way_the_wire_does() {
        for (scope, expected) in [
            (AutomationScope::EnvironmentsWrite, "environments:write"),
            (AutomationScope::EnvironmentsRead, "environments:read"),
            (AutomationScope::RoutesRead, "routes:read"),
            (AutomationScope::CertificatesRead, "certificates:read"),
        ] {
            assert_eq!(scope_str(scope), expected);
            assert_eq!(
                serde_json::to_string(&scope).expect("scope serialises"),
                format!("\"{expected}\"")
            );
        }
    }
}
