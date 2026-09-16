//! Traffic-capture rule management (Story 10.1).
//!
//! The six handlers behind `/api/v1/capture/rules`. They are a thin
//! shell on purpose: [`lorica_config::models::CaptureRule::validate`]
//! owns every cap and every predicate rule, and this module restates
//! none of them. A check that belongs to the model and is missing from
//! it is a model bug, not something to patch here, because the same
//! rule has to hold for a rule that arrives through configuration
//! import or fleet replication and never passes through a handler.
//!
//! Two facts are server-owned and refused on input by
//! `deny_unknown_fields`: `expires_at`, which is materialised from the
//! submitted `ttl_seconds`, and the two capture counters, which are
//! per-process runtime state rather than configuration.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use lorica_config::models::{
    CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
    CaptureScope,
};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

fn default_enabled() -> bool {
    true
}

/// JSON body for `POST /api/v1/capture/rules` and
/// `PUT /api/v1/capture/rules/{id}`.
///
/// One type for both verbs because a `PUT` is a full replace, not a
/// patch: a capture rule is a small document whose blocks interact
/// (`emit.always` against the other predicates, the body ceilings
/// against `limits`), and a per-field patch would let an operator
/// arrive at a combination no single request ever stated.
///
/// The nested blocks are the model's own types, so an operator writes
/// the same JSON the canonical configuration carries, and the model's
/// `deny_unknown_fields` applies inside each block as well as at the
/// top level.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRuleRequest {
    /// Operator-facing label.
    pub name: String,
    /// `Route.id` this rule records. Must name an existing route.
    pub route_id: String,
    /// Whether the rule records as soon as it lands. Defaults to `true`:
    /// an operator posting a capture rule during an incident wants it
    /// armed, and `POST .../disable` is the way back.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Which requests the rule considers.
    #[serde(rename = "match", default)]
    pub match_: CaptureMatch,
    /// Which of those are written out.
    #[serde(default)]
    pub emit: CaptureEmit,
    /// How much of each exchange is kept.
    #[serde(default)]
    pub capture: CaptureScope,
    /// What stops the rule, including the `ttl_seconds` that becomes
    /// `expires_at`.
    #[serde(default)]
    pub limits: CaptureLimits,
    /// Where captures land.
    #[serde(default)]
    pub output: CaptureOutput,
    /// Names redacted on top of the always-redacted set.
    #[serde(default)]
    pub redact: CaptureRedaction,
}

/// API view of one capture rule.
///
/// Timestamps are RFC 3339 strings, as every other response in this
/// crate renders them. The two counters are present and read-only: an
/// operator judging whether a rule has spent its budget needs them,
/// and [`CaptureRuleRequest`] has no field to send them back.
#[derive(Serialize)]
pub struct CaptureRuleResponse {
    /// Stable UUID of the rule.
    pub id: String,
    /// Operator-facing label.
    pub name: String,
    /// Route the rule records.
    pub route_id: String,
    /// Whether the rule is currently recording.
    pub enabled: bool,
    /// Which requests the rule considers.
    #[serde(rename = "match")]
    pub match_: CaptureMatch,
    /// Which of those are written out.
    pub emit: CaptureEmit,
    /// How much of each exchange is kept.
    pub capture: CaptureScope,
    /// What stops the rule.
    pub limits: CaptureLimits,
    /// Where captures land.
    pub output: CaptureOutput,
    /// Names redacted on top of the always-redacted set.
    pub redact: CaptureRedaction,
    /// Username of the operator who created the rule.
    pub created_by: String,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// RFC 3339 instant after which the rule records nothing.
    pub expires_at: String,
    /// Captures this node's process has emitted.
    pub captures_emitted: i64,
    /// Captures this node's process has dropped.
    pub captures_dropped: i64,
}

/// Build the API view of a stored rule.
fn rule_to_response(rule: &CaptureRule) -> CaptureRuleResponse {
    CaptureRuleResponse {
        id: rule.id.clone(),
        name: rule.name.clone(),
        route_id: rule.route_id.clone(),
        enabled: rule.enabled,
        match_: rule.match_.clone(),
        emit: rule.emit.clone(),
        capture: rule.capture.clone(),
        limits: rule.limits.clone(),
        output: rule.output.clone(),
        redact: rule.redact.clone(),
        created_by: rule.created_by.clone(),
        created_at: rule.created_at.to_rfc3339(),
        expires_at: rule.expires_at.to_rfc3339(),
        captures_emitted: rule.captures_emitted,
        captures_dropped: rule.captures_dropped,
    }
}

/// The absolute instant a rule stops recording: its creation plus the
/// submitted `ttl_seconds`.
///
/// Anchored to `created_at` rather than to the moment of the request,
/// so no sequence of edits can carry one rule past
/// [`lorica_config::models::CAPTURE_TTL_SECONDS_CAP`] from when it was
/// created. An absolute UTC instant rather than a duration is what
/// makes every node in a fleet stop the same rule at the same moment,
/// whenever its own copy of the configuration landed.
///
/// `ttl_seconds` is a `u32` and the cap is seven days, so the addition
/// cannot overflow a `TimeDelta`; the saturating add is there for the
/// year-262143 end of `DateTime<Utc>` and never fires in practice.
fn expiry_from_ttl(created_at: DateTime<Utc>, ttl_seconds: u32) -> DateTime<Utc> {
    let ttl = TimeDelta::seconds(i64::from(ttl_seconds));
    created_at
        .checked_add_signed(ttl)
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Run the model's validator and translate its message into a 422.
///
/// The message is the model's verbatim: it already names the offending
/// field (`limits.rate_per_minute`, `emit.always`, `route_id`), which
/// is what an operator needs to fix the submission.
fn validated(rule: CaptureRule) -> Result<CaptureRule, ApiError> {
    rule.validate().map_err(ApiError::Unprocessable)?;
    Ok(rule)
}

/// Assemble the stored model from a request plus the identity facts
/// the server owns.
fn rule_from_request(
    id: String,
    body: CaptureRuleRequest,
    created_by: String,
    created_at: DateTime<Utc>,
    captures_emitted: i64,
    captures_dropped: i64,
) -> CaptureRule {
    CaptureRule {
        id,
        expires_at: expiry_from_ttl(created_at, body.limits.ttl_seconds),
        name: body.name,
        route_id: body.route_id,
        enabled: body.enabled,
        match_: body.match_,
        emit: body.emit,
        capture: body.capture,
        limits: body.limits,
        output: body.output,
        redact: body.redact,
        created_by,
        created_at,
        captures_emitted,
        captures_dropped,
    }
}

/// Refuse a `route_id` that names no route.
///
/// Called inside the same store closure as the write so the check and
/// the insert see one snapshot. Without it the `capture_rules` foreign
/// key raises a driver error, which `ConfigError` reports as a database
/// fault and the API would surface as a 500 with no field named.
fn require_route(store: &mut lorica_config::ConfigStore, route_id: &str) -> Result<(), ApiError> {
    if store.get_route(route_id)?.is_none() {
        return Err(ApiError::Unprocessable(format!(
            "route_id `{route_id}` names no route"
        )));
    }
    Ok(())
}

/// Record one capture-rule mutation.
///
/// The payload carries the route and the effective predicates, so the
/// audit trail answers "what was this node told to record" and not only
/// "someone touched rule X".
async fn audit_mutation(
    state: &AppState,
    session: &Session,
    connect_info: &crate::audit::ClientConnectInfo,
    headers: &http::HeaderMap,
    action: &str,
    rule_id: &str,
    payload: Option<&serde_json::Value>,
) {
    let audit_ctx = crate::audit::AuditContext::new(session, connect_info.as_ref(), headers);
    crate::audit::record(
        state,
        &audit_ctx,
        action,
        ("capture_rule", rule_id),
        None,
        payload,
    )
    .await;
}

/// The audit payload for one rule: who it records and under what
/// conditions, which is the part of a capture rule that matters after
/// the fact.
fn audit_payload(rule: &CaptureRule) -> serde_json::Value {
    serde_json::json!({
        "route_id": rule.route_id,
        "name": rule.name,
        "enabled": rule.enabled,
        "match": rule.match_,
        "emit": rule.emit,
        "limits": rule.limits,
        "expires_at": rule.expires_at.to_rfc3339(),
    })
}

/// GET /api/v1/capture/rules - every capture rule on this node.
///
/// Operator floor: a capture rule names the paths and headers a node
/// records, which is closer to the traffic itself than to ordinary
/// configuration.
pub async fn list_capture_rules(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = db_blocking(&state.store, move |store| store.list_capture_rules()).await?;
    let responses: Vec<CaptureRuleResponse> = rules.iter().map(rule_to_response).collect();
    Ok(json_data(serde_json::json!({ "rules": responses })))
}

/// GET /api/v1/capture/rules/{id} - one capture rule.
pub async fn get_capture_rule(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = db_blocking(&state.store, move |store| {
        store
            .get_capture_rule(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("capture rule {id}")))
    })
    .await?;
    Ok(json_data(rule_to_response(&rule)))
}

/// POST /api/v1/capture/rules - arm a new capture rule.
pub async fn create_capture_rule(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CaptureRuleRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let rule = validated(rule_from_request(
        uuid::Uuid::new_v4().to_string(),
        body,
        session.username.clone(),
        Utc::now(),
        0,
        0,
    ))?;

    let rule = db_blocking(&state.store, move |store| {
        require_route(store, &rule.route_id)?;
        store.create_capture_rule(&rule)?;
        Ok::<_, ApiError>(rule)
    })
    .await?;

    state.notify_config_changed();
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "capture.create",
        &rule.id,
        Some(&audit_payload(&rule)),
    )
    .await;

    Ok(json_data_with_status(
        StatusCode::CREATED,
        rule_to_response(&rule),
    ))
}

/// PUT /api/v1/capture/rules/{id} - replace a capture rule.
///
/// `created_at`, `created_by` and the two counters come from the stored
/// row, never from the body. Resetting the counters on an edit would
/// make a rule that has already spent its budget look untouched, and
/// re-attributing `created_by` would erase who armed the recorder.
pub async fn update_capture_rule(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(body): Json<CaptureRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = db_blocking(&state.store, move |store| {
        let stored = store
            .get_capture_rule(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("capture rule {id}")))?;
        require_route(store, &body.route_id)?;
        let rule = validated(rule_from_request(
            stored.id,
            body,
            stored.created_by,
            stored.created_at,
            stored.captures_emitted,
            stored.captures_dropped,
        ))?;
        store.update_capture_rule(&rule)?;
        Ok::<_, ApiError>(rule)
    })
    .await?;

    state.notify_config_changed();
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "capture.update",
        &rule.id,
        Some(&audit_payload(&rule)),
    )
    .await;

    Ok(json_data(rule_to_response(&rule)))
}

/// DELETE /api/v1/capture/rules/{id} - remove a capture rule.
pub async fn delete_capture_rule(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule_id = id.clone();
    db_blocking(&state.store, move |store| store.delete_capture_rule(&id)).await?;

    state.notify_config_changed();
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "capture.delete",
        &rule_id,
        None,
    )
    .await;

    Ok(json_data(
        serde_json::json!({"message": "capture rule deleted"}),
    ))
}

/// POST /api/v1/capture/rules/{id}/disable - stop a capture rule.
///
/// This is the one mutation an Operator may perform, while creating or
/// editing a rule is SuperAdmin. It reads as an inconsistency and is
/// not: arming a recorder decides that production bodies get written to
/// disk, and stopping one only decides that they stop. An on-call
/// operator who finds a capture filling a disk, or recording more than
/// anyone intended, has to be able to end it at 3am without waking the
/// person who holds SuperAdmin.
pub async fn disable_capture_rule(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule = db_blocking(&state.store, move |store| {
        store.set_capture_rule_enabled(&id, false)?;
        store
            .get_capture_rule(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("capture rule {id}")))
    })
    .await?;

    state.notify_config_changed();
    audit_mutation(
        &state,
        &session,
        &connect_info,
        &headers,
        "capture.disable",
        &rule.id,
        Some(&audit_payload(&rule)),
    )
    .await;

    Ok(json_data(rule_to_response(&rule)))
}
