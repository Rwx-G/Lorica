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

//! Administration of automation tokens (Story 10.3 AC #6): mint, list
//! and revoke the credentials the automation plane authenticates.
//!
//! # Why these three handlers live on the MANAGEMENT plane
//!
//! The credential this module creates is the one
//! [`crate::automation`] accepts, and nothing else about the two
//! surfaces is shared. Mounting token administration on the automation
//! listener would mean a token that can mint tokens: a holder could
//! widen its own scopes, extend its own expiry, or mint a successor
//! before an operator revoked it, and the revocation an operator
//! reaches for would no longer be the end of the credential.
//!
//! Two things enforce the separation, not one:
//! [`crate::automation::build_automation_router`] declares no route
//! for these paths, and [`crate::automation::required_scope`] returns
//! `None` for any path it has not declared, so the scope gate refuses
//! them for every token including one carrying the whole enum. That is
//! what `the_admin_routes_are_not_reachable_through_the_automation_router`
//! pins, along with the absence of any write on the way.
//!
//! # The secret is returned EXACTLY ONCE
//!
//! [`create_automation_token`] is the only place the full
//! `<public_id>.<secret>` string ever exists on this node: the store
//! keeps HMAC-SHA256 of the secret half and nothing else, so no later
//! read can reconstruct it. Every other response here, the listing
//! included, carries [`AutomationTokenView`], which has no field for
//! either the secret or its HMAC. An operator who loses the string
//! mints a new token; there is no recovery path, and there should not
//! be one.
//!
//! Server-side logging follows the same rule: the `tracing` line and
//! the audit row both carry the `public_id`, which is what an operator
//! revokes, and never the token.
//!
//! # Validation
//!
//! [`lorica_config::models::AutomationToken::validate`] is the only
//! validator. Every cap, every hostname-pattern rule and the "at least
//! one scope" floor belong to the model, because the same rules have to
//! hold for a token that arrives any other way. This module restates
//! none of them; it only resolves the expiry an operator expressed as
//! a lifetime into the absolute instant the model stores.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use lorica_config::models::{
    mint_automation_token, AutomationScope, AutomationToken,
    AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// JSON body for `POST /api/v1/automation/tokens`.
///
/// `deny_unknown_fields`, so the server-owned facts (`public_id`,
/// `secret_hmac`, `created_at`, `created_by`, `last_used_at`,
/// `revoked_at`) are refused on input rather than quietly ignored.
///
/// The two omissible fields fall back to the model's own defaults:
/// `max_ttl_seconds` to [`AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS`]
/// and the expiry to [`AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS`] from
/// now. `allowed_backend_cidrs` has no default: there is no node-wide
/// backend policy to fall back on, and an empty list would be read as
/// every address, so the model refuses one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomationTokenRequest {
    /// Operator-facing label.
    pub name: String,
    /// What this token may do. At least one; the model says so.
    pub scopes: Vec<AutomationScope>,
    /// Hostname patterns this token may claim.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs this token may point a hostname at. At least one.
    #[serde(default)]
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment this token creates may
    /// request, in seconds.
    #[serde(default)]
    pub max_ttl_seconds: Option<u32>,
    /// The absolute instant the token stops being accepted.
    /// Mutually exclusive with `lifetime_days`.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// The token's lifetime from now, in days. Mutually exclusive with
    /// `expires_at`.
    #[serde(default)]
    pub lifetime_days: Option<i64>,
}

/// API view of one stored automation token.
///
/// There is deliberately no field for the secret and none for its
/// HMAC. The secret exists once, in the answer to the request that
/// minted it ([`MintedAutomationTokenResponse`]); the HMAC is the
/// node's private means of recognising that secret and discloses the
/// offline-guessing target if it leaves the database.
///
/// `last_used_at` and `revoked_at` are both present because they are
/// what an operator reads the listing for: a token nobody has
/// presented can be retired, and a revoked row is kept so the audit
/// trail survives.
#[derive(Serialize)]
pub struct AutomationTokenView {
    /// The lookup half, and the id every other endpoint takes.
    pub public_id: String,
    /// Operator-facing label.
    pub name: String,
    /// What this token may do.
    pub scopes: Vec<AutomationScope>,
    /// Hostname patterns this token may claim.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs this token may point a hostname at.
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling, in seconds, on the lifetime any environment this token
    /// creates may request.
    pub max_ttl_seconds: u32,
    /// Username of the operator who minted the token.
    pub created_by: String,
    /// RFC 3339 mint timestamp.
    pub created_at: String,
    /// RFC 3339 instant after which the token is refused.
    pub expires_at: String,
    /// RFC 3339 instant the token was last accepted, or `null`.
    pub last_used_at: Option<String>,
    /// RFC 3339 instant an operator withdrew the token, or `null`.
    pub revoked_at: Option<String>,
}

/// Payload of `POST /api/v1/automation/tokens`.
///
/// `token` is the full `<public_id>.<secret>` string and this is the
/// ONLY response in the product that carries it. It is never stored,
/// never logged and never returned again.
#[derive(Serialize)]
pub struct MintedAutomationTokenResponse {
    /// The full token. Shown once.
    pub token: String,
    /// The stored row, secret-free, so the caller can render the new
    /// token beside the others without a second request.
    #[serde(flatten)]
    pub view: AutomationTokenView,
}

/// Build the API view of a stored token.
fn token_to_view(token: &AutomationToken) -> AutomationTokenView {
    AutomationTokenView {
        public_id: token.public_id.clone(),
        name: token.name.clone(),
        scopes: token.scopes.clone(),
        allowed_hostnames: token.allowed_hostnames.clone(),
        allowed_backend_cidrs: token.allowed_backend_cidrs.clone(),
        max_ttl_seconds: token.max_ttl_seconds,
        created_by: token.created_by.clone(),
        created_at: token.created_at.to_rfc3339(),
        expires_at: token.expires_at.to_rfc3339(),
        last_used_at: token.last_used_at.map(|t| t.to_rfc3339()),
        revoked_at: token.revoked_at.map(|t| t.to_rfc3339()),
    }
}

/// The absolute instant the token stops being accepted.
///
/// An operator may state it either way: `expires_at` when a change
/// window fixes the date, `lifetime_days` when the token is minted
/// relative to now. Both at once describes two different instants, so
/// it is refused rather than silently resolved in one direction.
///
/// Nothing here caps the result. A lifetime the model refuses comes
/// back from [`AutomationToken::validate`] naming `expires_at`, which
/// is the one place that rule lives.
fn resolve_expiry(
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    lifetime_days: Option<i64>,
) -> Result<DateTime<Utc>, ApiError> {
    let days = match (expires_at, lifetime_days) {
        (Some(_), Some(_)) => {
            return Err(ApiError::Unprocessable(
                "expires_at and lifetime_days both set: they name two different instants, \
                 so send one or the other"
                    .to_string(),
            ))
        }
        (Some(at), None) => return Ok(at),
        (None, Some(days)) => days,
        (None, None) => AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS,
    };
    TimeDelta::try_days(days)
        .and_then(|delta| created_at.checked_add_signed(delta))
        .ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "lifetime_days `{days}` does not land on a representable instant"
            ))
        })
}

/// The audit payload for one token: who minted it, what it may do and
/// how far it reaches. Never the token, never its HMAC, because an
/// audit row outlives the credential and is read by more people.
fn audit_payload(token: &AutomationToken) -> serde_json::Value {
    serde_json::json!({
        "public_id": token.public_id,
        "name": token.name,
        "scopes": token.scopes,
        "allowed_hostnames": token.allowed_hostnames,
        "allowed_backend_cidrs": token.allowed_backend_cidrs,
        "max_ttl_seconds": token.max_ttl_seconds,
        "expires_at": token.expires_at.to_rfc3339(),
    })
}

/// Record one automation-token mutation.
async fn audit_mutation(
    state: &AppState,
    session: &Session,
    connect_info: &crate::audit::ClientConnectInfo,
    headers: &http::HeaderMap,
    action: &str,
    public_id: &str,
    payload: Option<&serde_json::Value>,
) {
    let audit_ctx = crate::audit::AuditContext::new(session, connect_info.as_ref(), headers);
    crate::audit::record(
        state,
        &audit_ctx,
        action,
        ("automation_token", public_id),
        None,
        payload,
    )
    .await;
}

/// GET /api/v1/automation/tokens - every automation token on this node
/// (SuperAdmin).
///
/// Safe to render: the rows carry no secret and no HMAC, and both
/// `last_used_at` and `revoked_at` are present so a stale or dead
/// credential is visible at a glance.
pub async fn list_automation_tokens(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tokens = db_blocking(&state.store, move |store| store.list_automation_tokens()).await?;
    let views: Vec<AutomationTokenView> = tokens.iter().map(token_to_view).collect();
    Ok(json_data(serde_json::json!({ "tokens": views })))
}

/// POST /api/v1/automation/tokens - mint an automation token
/// (SuperAdmin).
///
/// The answer carries the full token string, and it is the only time
/// it is ever returned: the store keeps the HMAC of the secret half,
/// so no later read can produce it again.
pub async fn create_automation_token(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateAutomationTokenRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let created_at = Utc::now();
    let expires_at = resolve_expiry(created_at, body.expires_at, body.lifetime_days)?;
    let created_by = session.username.clone();
    let CreateAutomationTokenRequest {
        name,
        scopes,
        allowed_hostnames,
        allowed_backend_cidrs,
        max_ttl_seconds,
        ..
    } = body;
    let max_ttl_seconds = max_ttl_seconds.unwrap_or(AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS);

    // The mint, the validation and the insert share one store visit:
    // the HMAC key is a store read, so splitting them would queue for
    // the store mutex twice and open a window where the key rotates
    // between hashing and writing.
    let (token_string, stored) = db_blocking(&state.store, move |store| {
        let key = store.automation_token_hmac_key()?;
        let minted = mint_automation_token(&key)
            .map_err(|e| ApiError::Internal(format!("automation token mint failed: {e}")))?;
        let token = AutomationToken {
            public_id: minted.public_id,
            name,
            secret_hmac: minted.secret_hmac,
            scopes,
            allowed_hostnames,
            allowed_backend_cidrs,
            max_ttl_seconds,
            created_by,
            created_at,
            expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        token.validate().map_err(ApiError::Unprocessable)?;
        store.create_automation_token(&token)?;
        Ok::<_, ApiError>((minted.token, token))
    })
    .await?;

    // The public half only. This line is the reason an operator can
    // grep for when a credential appeared; the token itself never
    // reaches a log, a metric or an audit row.
    tracing::info!(
        public_id = %stored.public_id,
        name = %stored.name,
        expires_at = %stored.expires_at.to_rfc3339(),
        "automation token minted"
    );
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "automation.token.create",
        &stored.public_id,
        Some(&audit_payload(&stored)),
    )
    .await;

    Ok(json_data_with_status(
        StatusCode::CREATED,
        MintedAutomationTokenResponse {
            token: token_string,
            view: token_to_view(&stored),
        },
    ))
}

/// DELETE /api/v1/automation/tokens/{public_id} - withdraw a token
/// (SuperAdmin).
///
/// This is revocation, not deletion. The row stays, with `revoked_at`
/// stamped, because after an incident the questions are "did this
/// credential exist", "who minted it" and "when was it last
/// presented", and a deleted row answers none of them.
///
/// Revoking twice is a 200, not a 404 or a 409. Revocation is
/// something an operator does under pressure, often from two places at
/// once; the second call finds exactly the state the caller wanted and
/// has nothing to report. What it must NOT do is move `revoked_at`
/// forward, which would rewrite when the credential actually stopped
/// working, and [`lorica_config::ConfigStore::revoke_automation_token`]
/// is what keeps the first stamp.
///
/// A `public_id` naming no row is still a 404: that is a different
/// mistake, and answering 200 would let a typo read as a successful
/// revocation.
pub async fn revoke_automation_token(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(public_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = public_id.clone();
    let token = db_blocking(&state.store, move |store| {
        store.revoke_automation_token(&id, Utc::now())?;
        store
            .get_automation_token(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("automation token {id}")))
    })
    .await?;

    tracing::info!(public_id = %token.public_id, "automation token revoked");
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "automation.token.revoke",
        &token.public_id,
        Some(&audit_payload(&token)),
    )
    .await;

    Ok(json_data(token_to_view(&token)))
}

#[cfg(test)]
mod tests;
