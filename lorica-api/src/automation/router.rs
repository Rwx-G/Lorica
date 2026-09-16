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

//! The automation router and its one endpoint.
//!
//! `GET /automation/v1/whoami` exists so the whole chain - source
//! filter, TLS, bearer verification, scope gate, audit - is testable
//! now instead of after the environment resource lands. It reports the
//! token back to its own holder and reaches nothing else, so it stays
//! useful afterwards as the call an automation makes to check that its
//! credential is still live and still carries what it expects.

use axum::routing::get;
use axum::Router;
use lorica_config::models::AutomationScope;
use serde::Serialize;

use super::auth::AutomationPrincipal;
use crate::error::json_data;
use crate::server::AppState;

/// Body cap for the automation plane.
///
/// Story 10.3 ships one GET. The ceiling is deliberately far below the
/// management plane's 1 MiB: an environment declaration is a small
/// JSON document, and the cap is easier to raise for one endpoint that
/// needs it than to notice once it is wide.
const AUTOMATION_BODY_CAP: usize = 64 * 1024;

/// What `whoami` reports.
#[derive(Debug, Serialize)]
pub struct WhoAmI {
    /// The token's operator-facing label.
    pub name: String,
    /// The token's lookup half, which is the id an operator revokes.
    pub public_id: String,
    /// Everything this token may do.
    pub scopes: Vec<AutomationScope>,
}

/// `GET /automation/v1/whoami` - the token behind this request.
///
/// Never reports the secret half, which the node does not hold: the
/// store keeps only its HMAC.
pub async fn whoami(principal: AutomationPrincipal) -> axum::Json<serde_json::Value> {
    json_data(WhoAmI {
        name: principal.token.name.clone(),
        public_id: principal.token.public_id.clone(),
        scopes: principal.token.scopes.clone(),
    })
}

/// Build the automation-plane router.
///
/// Layer order, outermost first:
///
/// 1. [`super::audit::audit_automation_request`] - outermost, so a
///    request refused by the bearer gate still lands a row.
/// 2. [`super::auth::require_automation_auth`] - the bearer check.
/// 3. [`super::scope::authorize_scope`] - the scope floor.
///
/// There is deliberately NO cookie layer, NO CSRF layer and NO session
/// store here. The two management planes share no credential, and the
/// cheapest way to keep that true is for this router to have no way to
/// read one.
pub fn build_automation_router(state: AppState) -> Router {
    Router::new()
        .route("/automation/v1/whoami", get(whoami))
        .layer(axum::middleware::from_fn(super::scope::authorize_scope))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::require_automation_auth,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(AUTOMATION_BODY_CAP))
        .layer(axum::Extension(state.clone()))
        // `from_fn_with_state` rather than the `Extension` above: the
        // audit layer is outermost, so it runs BEFORE that extension is
        // inserted into the request on the way down.
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::audit::audit_automation_request,
        ))
}
