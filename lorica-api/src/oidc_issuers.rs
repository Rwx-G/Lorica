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

//! Administration of OIDC issuer entries (Story 10.5 AC #1): register,
//! list and remove the trust configuration behind a GitLab ID token.
//!
//! # Why these handlers live on the MANAGEMENT plane
//!
//! The same reason token administration does: an entry decides which
//! identity provider's signed statements this node acts on and which
//! claims unlock it. A credential able to widen that is a credential
//! able to admit its own successor, so the automation listener serves
//! none of these paths, and [`crate::automation::required_scope`]
//! refuses them for every token.
//!
//! # Removal takes effect on the next request
//!
//! The bearer gate reads the entries for a token's audience from the
//! store on every request and caches nothing, so `DELETE` refuses the
//! very next ID token the entry would have accepted (AC #5). The JWKS
//! cache and the replay set are per process and per URL, not per
//! entry, and neither can admit a token an entry no longer vouches
//! for. `removing_an_issuer_refuses_the_next_id_token_immediately`
//! pins this through the real gate.
//!
//! # Validation
//!
//! [`lorica_config::models::OidcIssuer::validate`] is the only
//! validator: the `https` rule, the closed claim set, the one glob and
//! the grant caps all belong to the model. This module only fills in
//! the defaults an operator may omit.

use std::collections::BTreeMap;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

use lorica_config::models::{
    AutomationScope, OidcIssuer, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// `target_type` of every issuer-entry audit row.
const OIDC_ISSUER_TARGET_TYPE: &str = "oidc_issuer";

/// JSON body for `POST /api/v1/automation/oidc-issuers`.
///
/// `deny_unknown_fields`, so the server-owned facts (`id`,
/// `created_by`, `created_at`) are refused on input rather than
/// quietly ignored. `jwks_url` defaults to
/// `<issuer>/oauth/discovery/keys`, `bound_claims` and
/// `allowed_backend_cidrs` to empty, and `max_ttl_seconds` to the
/// static-token default.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOidcIssuerRequest {
    /// The GitLab instance URL, which is the token's `iss`. `https`.
    pub issuer: String,
    /// The value the job puts in `id_tokens.<NAME>.aud`.
    pub audience: String,
    /// Where the signing keys are fetched from; defaults to the GitLab
    /// discovery path under `issuer`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Claims that must match exactly; a `*` glob on `project_path`
    /// only.
    #[serde(default)]
    pub bound_claims: BTreeMap<String, String>,
    /// Hostname patterns a token from this entry may claim.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs a token from this entry may point a hostname at.
    #[serde(default)]
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment a token from this entry
    /// creates may request, in seconds.
    #[serde(default)]
    pub max_ttl_seconds: Option<u32>,
    /// What a token from this entry may do. At least one.
    pub scopes: Vec<AutomationScope>,
}

/// The audit payload for one entry: everything it says, because an
/// entry is policy and the audit trail is where policy changes are
/// answered for. There is no secret in it.
fn audit_payload(issuer: &OidcIssuer) -> serde_json::Value {
    serde_json::to_value(issuer).unwrap_or(serde_json::Value::Null)
}

/// Record one issuer-entry mutation.
async fn audit_mutation(
    state: &AppState,
    session: &Session,
    connect_info: &crate::audit::ClientConnectInfo,
    headers: &http::HeaderMap,
    action: &str,
    issuer: &OidcIssuer,
    before: bool,
) {
    let audit_ctx = crate::audit::AuditContext::new(session, connect_info.as_ref(), headers);
    let payload = audit_payload(issuer);
    let (before, after) = if before {
        (Some(&payload), None)
    } else {
        (None, Some(&payload))
    };
    crate::audit::record(
        state,
        &audit_ctx,
        action,
        (OIDC_ISSUER_TARGET_TYPE, &issuer.id),
        before,
        after,
    )
    .await;
}

/// GET /api/v1/automation/oidc-issuers - every issuer entry on this
/// node (SuperAdmin).
pub async fn list_oidc_issuers(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let issuers = db_blocking(&state.store, move |store| store.list_oidc_issuers()).await?;
    Ok(json_data(serde_json::json!({ "issuers": issuers })))
}

/// POST /api/v1/automation/oidc-issuers - register an issuer entry
/// (SuperAdmin).
pub async fn create_oidc_issuer(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateOidcIssuerRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let CreateOidcIssuerRequest {
        issuer,
        audience,
        jwks_url,
        bound_claims,
        allowed_hostnames,
        allowed_backend_cidrs,
        max_ttl_seconds,
        scopes,
    } = body;
    let jwks_url = jwks_url
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| OidcIssuer::default_jwks_url(&issuer));
    let entry = OidcIssuer {
        id: uuid::Uuid::new_v4().to_string(),
        issuer,
        audience,
        jwks_url,
        bound_claims,
        allowed_hostnames,
        allowed_backend_cidrs,
        max_ttl_seconds: max_ttl_seconds.unwrap_or(AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS),
        scopes,
        created_by: session.username.clone(),
        created_at: Utc::now(),
    };
    entry.validate().map_err(ApiError::Unprocessable)?;

    let stored = entry.clone();
    db_blocking(&state.store, move |store| store.create_oidc_issuer(&stored)).await?;

    tracing::info!(
        id = %entry.id,
        issuer = %entry.issuer,
        audience = %entry.audience,
        "oidc issuer entry registered"
    );
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "automation.oidc_issuer.create",
        &entry,
        false,
    )
    .await;

    Ok(json_data_with_status(StatusCode::CREATED, entry))
}

/// DELETE /api/v1/automation/oidc-issuers/{id} - remove an issuer
/// entry (SuperAdmin).
///
/// A real delete, unlike a token revocation: the row holds no
/// credential whose history matters after the fact, and the audit row
/// keeps everything the entry said. An unknown id is a 404, so a typo
/// cannot read as a removal.
pub async fn delete_oidc_issuer(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let lookup = id.clone();
    let removed = db_blocking(&state.store, move |store| {
        let entry = store
            .get_oidc_issuer(&lookup)?
            .ok_or_else(|| ApiError::NotFound(format!("oidc issuer {lookup}")))?;
        store.delete_oidc_issuer(&lookup)?;
        Ok::<_, ApiError>(entry)
    })
    .await?;

    tracing::info!(id = %removed.id, issuer = %removed.issuer, "oidc issuer entry removed");
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "automation.oidc_issuer.delete",
        &removed,
        true,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
