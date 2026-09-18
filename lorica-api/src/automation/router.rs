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

//! The automation router: `whoami` and the environment resource.
//!
//! `GET /automation/v1/whoami` exists so the whole chain - source
//! filter, TLS, bearer verification, scope gate, audit - is testable
//! on its own. It reports the token back to its own holder and reaches
//! nothing else, so it stays useful as the call an automation makes to
//! check that its credential is still live and still carries what it
//! expects. The environment paths (Story 10.4) live in
//! [`super::environments`]; they are mounted here, and only here, so
//! the OpenAPI drift gate in `tests/openapi_contract.rs` sees every
//! automation route in one file.

use axum::routing::get;
use axum::Router;
use lorica_config::models::{AutomationScope, OwnerKind, PipelineIdentity};
use serde::Serialize;

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
/// notice once it is wide.
const AUTOMATION_BODY_CAP: usize = 64 * 1024;

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
/// else, so it covers the bearer gate and the scope gate as well as the
/// handlers, and so the audit layer itself is never the thing being
/// caught.
///
/// The test router in [`super::audit`] is built through this same
/// function, which is the only way a test can assert the order the
/// production listener actually runs.
pub(super) fn with_audit_and_panic_net(router: Router, state: AppState) -> Router {
    router
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        // `from_fn_with_state` rather than an `Extension`: the audit
        // layer is outermost, so it runs BEFORE any extension a layer
        // below inserts into the request on the way down.
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::audit::audit_automation_request,
        ))
}

/// Build the automation-plane router.
///
/// Layer order, outermost first:
///
/// 1. [`super::audit::audit_automation_request`] - outermost, so a
///    request refused by the bearer gate still lands a row.
/// 2. `CatchPanicLayer` - see [`with_audit_and_panic_net`].
/// 3. [`super::auth::require_automation_auth`] - the bearer check.
/// 4. [`super::scope::authorize_scope`] - the scope floor.
///
/// There is deliberately NO cookie layer, NO CSRF layer and NO session
/// store here. The two management planes share no credential, and the
/// cheapest way to keep that true is for this router to have no way to
/// read one.
pub fn build_automation_router(state: AppState) -> Router {
    let routed = Router::new()
        .route("/automation/v1/whoami", get(whoami))
        .route("/automation/v1/environments", get(list_environments))
        .route(
            "/automation/v1/environments/{name}",
            get(get_environment)
                .put(put_environment)
                .delete(delete_environment),
        )
        .layer(axum::middleware::from_fn(super::scope::authorize_scope))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::require_automation_auth,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(AUTOMATION_BODY_CAP))
        .layer(axum::Extension(state.clone()));
    with_audit_and_panic_net(routed, state)
}
