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
//! [`lorica_config::models::OidcIssuer::validate`] is the validator for
//! every field the model can judge on its own: the `https` rule, the
//! closed claim set, the one glob and the grant caps. `ca_pem` is the
//! exception and is judged here, by [`validate_ca_pem`], because
//! deciding whether a blob is a certificate needs an X.509 parser and
//! `lorica-config` has none. It is still a write-time rule: this
//! handler is the only path that writes a row.
//!
//! # `ca_pem` goes in and never comes back
//!
//! The certificate an entry pins is not a secret, but it is node-local
//! material an operator supplied, and a listing is the wrong place for
//! a few kilobytes of PEM. `GET` answers with a `ca_fingerprint`, the
//! SHA-256 of the first certificate's DER in lowercase hex, which is
//! what an operator compares against `openssl x509 -fingerprint
//! -sha256` to confirm the right CA is pinned.

use std::collections::BTreeMap;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::CertificateDer;

use lorica_config::models::{
    AutomationScope, OidcIssuer, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// `target_type` of every issuer-entry audit row.
const OIDC_ISSUER_TARGET_TYPE: &str = "oidc_issuer";

/// Most bytes accepted in a `ca_pem`. A root plus an intermediate is
/// around four kilobytes; the cap is sixteen times that, and it exists
/// so a SuperAdmin typo cannot park a megabyte in a row every JWKS
/// fetch reads.
const CA_PEM_MAX_LEN: usize = 64 * 1024;

/// JSON body for `POST /api/v1/automation/oidc-issuers`.
///
/// `deny_unknown_fields`, so the server-owned facts (`id`,
/// `created_by`, `created_at`) are refused on input rather than
/// quietly ignored. `jwks_url` defaults to
/// `<issuer>/oauth/discovery/keys` and `max_ttl_seconds` to the
/// static-token default. `bound_claims` and `allowed_backend_cidrs`
/// have no usable default: an entry binding neither `project_path`
/// nor `namespace_path` accepts every project on the instance, and an
/// empty CIDR list is read as every address, so the model refuses
/// both.
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
    /// CIDRs a token from this entry may point a hostname at. At
    /// least one.
    #[serde(default)]
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment a token from this entry
    /// creates may request, in seconds.
    #[serde(default)]
    pub max_ttl_seconds: Option<u32>,
    /// What a token from this entry may do. At least one.
    pub scopes: Vec<AutomationScope>,
    /// PEM certificates that become the only trust anchors for this
    /// entry's JWKS fetch. Omit it on a public GitLab, or on a
    /// self-hosted one whose CA the node already trusts.
    #[serde(default)]
    pub ca_pem: Option<String>,
}

/// One entry as the API answers it: the stored row, whose `ca_pem` is
/// never serialised, plus the fingerprint of the CA it pins.
#[derive(Serialize)]
struct OidcIssuerView {
    #[serde(flatten)]
    entry: OidcIssuer,
    /// Lowercase-hex SHA-256 of the first pinned certificate's DER, or
    /// `null` when the entry fetches on the node's trust roots.
    ca_fingerprint: Option<String>,
}

impl OidcIssuerView {
    fn of(entry: &OidcIssuer) -> Self {
        Self {
            entry: entry.clone(),
            ca_fingerprint: entry.ca_pem.as_deref().and_then(ca_fingerprint),
        }
    }
}

/// The certificates a `ca_pem` holds, in order.
///
/// The same rustls PEM reader the management-TLS loader and the
/// syslog sink use, so a certificate this node accepts here is one its
/// TLS stack can actually anchor on.
fn certificates_of(ca_pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(ca_pem.as_bytes())
        .filter_map(Result::ok)
        .map(CertificateDer::into_owned)
        .collect()
}

/// SHA-256 of the first certificate's DER, lowercase hex.
///
/// DER and not the PEM text, so the value matches what
/// `openssl x509 -fingerprint -sha256` prints and does not move when
/// the file is rewrapped or a trailing newline changes.
fn ca_fingerprint(ca_pem: &str) -> Option<String> {
    let first = certificates_of(ca_pem).into_iter().next()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, first.as_ref());
    Some(
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// A `ca_pem` an operator supplied: bounded, and at least one
/// certificate the TLS stack can parse.
///
/// # Errors
///
/// A message naming `ca_pem`, suitable for a `422` body.
fn validate_ca_pem(ca_pem: &str) -> Result<(), String> {
    if ca_pem.len() > CA_PEM_MAX_LEN {
        return Err(format!("ca_pem exceeds {CA_PEM_MAX_LEN} bytes"));
    }
    if certificates_of(ca_pem).is_empty() {
        return Err(
            "ca_pem must hold at least one PEM certificate; nothing in it parsed as one"
                .to_string(),
        );
    }
    Ok(())
}

/// The audit payload for one entry: everything it says, because an
/// entry is policy and the audit trail is where policy changes are
/// answered for. The pinned certificate itself stays out, and its
/// fingerprint stands in, which is what identifies the trust decision
/// anyway.
fn audit_payload(issuer: &OidcIssuer) -> serde_json::Value {
    serde_json::to_value(OidcIssuerView::of(issuer)).unwrap_or(serde_json::Value::Null)
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
    let views: Vec<OidcIssuerView> = issuers.iter().map(OidcIssuerView::of).collect();
    Ok(json_data(serde_json::json!({ "issuers": views })))
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
        ca_pem,
    } = body;
    let jwks_url = jwks_url
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| OidcIssuer::default_jwks_url(&issuer));
    let ca_pem = ca_pem
        .map(|pem| pem.trim().to_string())
        .filter(|pem| !pem.is_empty());
    if let Some(pem) = ca_pem.as_deref() {
        validate_ca_pem(pem).map_err(ApiError::Unprocessable)?;
    }
    let entry = OidcIssuer {
        id: uuid::Uuid::new_v4().to_string(),
        issuer,
        audience,
        jwks_url,
        ca_pem,
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

    Ok(json_data_with_status(
        StatusCode::CREATED,
        OidcIssuerView::of(&entry),
    ))
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
