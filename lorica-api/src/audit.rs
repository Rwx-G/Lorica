//! Tamper-evident admin audit log (Story 8.9).
//!
//! Every state-mutating management-API handler records an audit entry.
//! Rows form a linear SHA-256 hash chain: each row stores the previous
//! row's `chain_hash` and its own `chain_hash` computed over ALL of the
//! row's content fields (timestamp, operator username + role, action,
//! target type + id, before/after payload hashes, ip, user_agent).
//! Editing any of those fields, or deleting a middle row, breaks
//! recomputation at the earliest affected row, which `verify` localises.
//! Retention truncation is chain-safe via a "retention seal" (the
//! earliest surviving row's `prev_chain_hash`) stored in
//! `audit_log_meta`.
//!
//! Threat model (honest scope): the chain is tamper-EVIDENT, not
//! tamper-PROOF. The hash is unkeyed and the seal is stored in-band, so
//! a principal with write access to `access-log.db` who recomputes every
//! `chain_hash` forward (the algorithm is public) can produce a
//! self-consistent forged history that `verify` accepts. `verify` proves
//! INTERNAL consistency, not authenticity against an external anchor. For
//! out-of-band detection, each successful `record` emits the row's
//! `chain_hash` on the `lorica::audit` tracing target (see [`record`]);
//! shipping that stream to a WORM / append-only sink lets an operator
//! catch a wholesale rewrite by comparing the persisted head against the
//! externally-captured one. An HMAC key was considered and rejected: on a
//! single-host deployment the key would live under the same owner as the
//! DB, so it stops no realistic on-host attacker while adding key
//! lifecycle complexity - the external anchor is the effective control.
//!
//! Storage lives in [`crate::log_store::LogStore`] (`access-log.db`),
//! which only exists in the process that serves the management API
//! (single-process or supervisor). Payloads (`before` / `after`) are
//! hashed, never stored: no secret material can land in the audit
//! table by construction.

use std::convert::Infallible;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Extension, FromRequestParts, Query};
use axum::http::request::Parts;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// `prev_chain_hash` of the very first row: 32 zero bytes, hex-encoded.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Row shape accepted by [`crate::log_store::LogStore::insert_audit`].
/// `prev_chain_hash` / `chain_hash` are computed at insert time inside
/// the store's connection lock (chain writes must be serialized).
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    /// RFC 3339 UTC timestamp of the mutation.
    pub timestamp: String,
    /// RBAC username of the operator (Story 8.3 session identity).
    pub operator_username: String,
    /// RBAC role of the operator at mutation time (snake_case).
    pub operator_role: String,
    /// Dotted action verb, e.g. `route.delete`.
    pub action: String,
    /// Entity kind the action touched, e.g. `route`.
    pub target_type: String,
    /// Identifier of the touched entity (empty when not applicable).
    pub target_id: String,
    /// SHA-256 hex of the pre-mutation payload, empty when absent.
    pub before_payload_hash: String,
    /// SHA-256 hex of the post-mutation payload, empty when absent.
    pub after_payload_hash: String,
    /// Client IP the mutation came from (empty when unknown).
    pub ip: String,
    /// Client `User-Agent` header (empty when absent).
    pub user_agent: String,
}

/// One stored audit row, as returned by `query_audit` / walked by
/// `verify_audit_chain`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// Monotonic row id (SQLite rowid).
    pub id: i64,
    /// RFC 3339 UTC timestamp of the mutation.
    pub timestamp: String,
    /// RBAC username of the operator.
    pub operator_username: String,
    /// RBAC role of the operator.
    pub operator_role: String,
    /// Dotted action verb.
    pub action: String,
    /// Entity kind.
    pub target_type: String,
    /// Entity id.
    pub target_id: String,
    /// SHA-256 hex of the pre-mutation payload ("" = absent).
    pub before_payload_hash: String,
    /// SHA-256 hex of the post-mutation payload ("" = absent).
    pub after_payload_hash: String,
    /// Source IP.
    pub ip: String,
    /// Client User-Agent.
    pub user_agent: String,
    /// `chain_hash` of the previous row (or genesis / retention seal).
    pub prev_chain_hash: String,
    /// This row's chain hash.
    pub chain_hash: String,
}

/// Filters for `GET /api/v1/audit`.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Exact operator-username match.
    pub operator: Option<String>,
    /// Action prefix match (`route.` matches `route.delete`).
    pub action_prefix: Option<String>,
    /// Inclusive RFC 3339 lower bound on `timestamp`.
    pub from: Option<String>,
    /// Inclusive RFC 3339 upper bound on `timestamp`.
    pub to: Option<String>,
    /// Maximum rows returned (newest first).
    pub limit: usize,
    /// Cursor: only rows with `id` strictly below this (pagination).
    pub before_id: Option<i64>,
}

/// Outcome of `GET /api/v1/audit/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    /// `true` when every row's chain recomputes.
    pub verified: bool,
    /// Number of rows walked.
    pub total_rows: u64,
    /// Earliest broken row id, when `verified == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_break_id: Option<i64>,
    /// `prev_hash_mismatch` or `chain_hash_mismatch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_break_reason: Option<String>,
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SHA-256 hex of a JSON payload's compact serialization; empty string
/// when the payload is absent (the chain input then carries the empty
/// field via its length prefix, so "absent" and "empty object" differ).
pub fn hash_payload(payload: Option<&serde_json::Value>) -> String {
    match payload {
        None => String::new(),
        Some(value) => {
            let compact = value.to_string();
            let digest = ring::digest::digest(&ring::digest::SHA256, compact.as_bytes());
            encode_hex(digest.as_ref())
        }
    }
}

/// Borrowed view of the chained fields of one row, fed into
/// [`compute_chain_hash`] alongside the previous row's hash.
#[derive(Debug, Clone, Copy)]
pub struct ChainInput<'a> {
    /// RFC 3339 timestamp.
    pub timestamp: &'a str,
    /// Operator username.
    pub operator_username: &'a str,
    /// Operator role at mutation time (snake_case).
    pub operator_role: &'a str,
    /// Dotted action verb.
    pub action: &'a str,
    /// Entity kind.
    pub target_type: &'a str,
    /// Entity id.
    pub target_id: &'a str,
    /// SHA-256 hex of the pre-mutation payload ("" = absent).
    pub before_payload_hash: &'a str,
    /// SHA-256 hex of the post-mutation payload ("" = absent).
    pub after_payload_hash: &'a str,
    /// Source IP ("" when unknown).
    pub ip: &'a str,
    /// Client User-Agent ("" when absent).
    pub user_agent: &'a str,
}

impl<'a> From<&'a NewAuditEntry> for ChainInput<'a> {
    fn from(entry: &'a NewAuditEntry) -> Self {
        Self {
            timestamp: &entry.timestamp,
            operator_username: &entry.operator_username,
            operator_role: &entry.operator_role,
            action: &entry.action,
            target_type: &entry.target_type,
            target_id: &entry.target_id,
            before_payload_hash: &entry.before_payload_hash,
            after_payload_hash: &entry.after_payload_hash,
            ip: &entry.ip,
            user_agent: &entry.user_agent,
        }
    }
}

impl<'a> From<&'a AuditRecord> for ChainInput<'a> {
    fn from(row: &'a AuditRecord) -> Self {
        Self {
            timestamp: &row.timestamp,
            operator_username: &row.operator_username,
            operator_role: &row.operator_role,
            action: &row.action,
            target_type: &row.target_type,
            target_id: &row.target_id,
            before_payload_hash: &row.before_payload_hash,
            after_payload_hash: &row.after_payload_hash,
            ip: &row.ip,
            user_agent: &row.user_agent,
        }
    }
}

/// Compute a row's `chain_hash`.
///
/// The PRD sketches raw concatenation of the fields; raw concatenation
/// is ambiguous at field boundaries (`ab` + `c` hashes like `a` + `bc`),
/// so each field is fed length-prefixed (u64 LE byte length, then the
/// UTF-8 bytes). Internal consistency is what matters: `insert_audit`
/// and `verify_audit_chain` both call this function.
pub fn compute_chain_hash(prev_chain_hash: &str, input: &ChainInput<'_>) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for field in [
        prev_chain_hash,
        input.timestamp,
        input.operator_username,
        input.operator_role,
        input.action,
        input.target_type,
        input.target_id,
        input.before_payload_hash,
        input.after_payload_hash,
        input.ip,
        input.user_agent,
    ] {
        ctx.update(&(field.len() as u64).to_le_bytes());
        ctx.update(field.as_bytes());
    }
    encode_hex(ctx.finish().as_ref())
}

/// Recompute the expected `chain_hash` for a stored row (verify path).
pub fn recompute_chain_hash(row: &AuditRecord) -> String {
    compute_chain_hash(&row.prev_chain_hash, &ChainInput::from(row))
}

/// Operator identity + request provenance for one audit emission,
/// captured once at the top of a handler.
#[derive(Debug, Clone)]
pub struct AuditContext {
    /// Session username (Story 8.3 RBAC identity).
    pub username: String,
    /// Session role (snake_case).
    pub role: String,
    /// Client IP ("" when unknown).
    pub ip: String,
    /// Client User-Agent ("" when absent).
    pub user_agent: String,
}

impl AuditContext {
    /// Build the context from the handler's extractors.
    pub fn new(
        session: &Session,
        connect_info: Option<&ConnectInfo<SocketAddr>>,
        headers: &http::HeaderMap,
    ) -> Self {
        Self {
            username: session.username.clone(),
            role: session.role.as_str().to_string(),
            ip: connect_info
                .map(|ci| ci.0.ip().to_string())
                .unwrap_or_default(),
            user_agent: headers
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        }
    }
}

/// Optional peer-address extractor for management-plane handlers.
///
/// Mirrors the axum 0.7 behavior of `Option<ConnectInfo<SocketAddr>>`:
/// yields the peer address when the server was started with
/// `into_make_service_with_connect_info` (production), and `None`
/// otherwise (unit tests driving the router via Tower `oneshot`, which
/// do not attach `ConnectInfo`). axum 0.8 dropped the blanket
/// `Option<T: FromRequestParts>` impl and `ConnectInfo` implements only
/// the fallible `FromRequestParts`, so this restores the never-rejecting
/// behavior without changing any call site.
#[derive(Debug, Clone)]
pub struct ClientConnectInfo(pub Option<ConnectInfo<SocketAddr>>);

impl ClientConnectInfo {
    /// Borrow the inner `ConnectInfo`, matching the shape
    /// [`AuditContext::new`] expects.
    pub fn as_ref(&self) -> Option<&ConnectInfo<SocketAddr>> {
        self.0.as_ref()
    }
}

impl<S> FromRequestParts<S> for ClientConnectInfo
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<ConnectInfo<SocketAddr>>().cloned()))
    }
}

/// Record one audit entry for a mutation that SUCCEEDED, and emit the
/// matching `lorica::audit` tracing event (picked up by stdout/JSON
/// logging and, when enabled, the OTel bridge - inside the current
/// `api_request` span).
///
/// `target` is `(target_type, target_id)`. `before` / `after` payloads
/// are SHA-256-hashed; the payloads themselves are never persisted. The
/// tracing event is emitted AFTER persistence so it carries the committed
/// `chain_hash` (the external-anchor control in the module threat model);
/// on the no-store / failure paths it is still emitted, with an empty
/// `chain_hash`. Failure policy: an insert failure is counted
/// (`lorica_audit_insert_failed_total`), logged, and swallowed -
/// availability beats auditability, the chain covers integrity, not
/// liveness. A `None` log store (worker mode, tests) skips persistence.
pub async fn record(
    state: &AppState,
    ctx: &AuditContext,
    action: &str,
    target: (&str, &str),
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) {
    record_with_store(state.log_store.clone(), ctx, action, target, before, after).await;
}

/// [`record`] for callers that hold the log store but no `AppState`:
/// the cluster plane's lifecycle hooks (enrollment, renewal, leave,
/// identity refusals), which run in the binary before and beside the
/// API. Same persistence, same sink copy, same failure policy.
pub async fn record_with_store(
    log_store: Option<std::sync::Arc<crate::log_store::LogStore>>,
    ctx: &AuditContext,
    action: &str,
    target: (&str, &str),
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) {
    let (target_type, target_id) = target;
    // One timestamp shared by the persisted row and the sink copy, so
    // the SIEM-side and DB-side records agree exactly (QA finding:
    // timestamp equality is the cheapest out-of-band join key).
    let timestamp = chrono::Utc::now().to_rfc3339();

    let Some(log_store) = log_store else {
        emit_audit_event(ctx, action, target_type, target_id, "", &timestamp);
        return;
    };

    let entry = NewAuditEntry {
        timestamp: timestamp.clone(),
        operator_username: ctx.username.clone(),
        operator_role: ctx.role.clone(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        before_payload_hash: hash_payload(before),
        after_payload_hash: hash_payload(after),
        ip: ctx.ip.clone(),
        user_agent: ctx.user_agent.clone(),
    };

    let result = tokio::task::spawn_blocking(move || log_store.insert_audit(&entry)).await;
    match result {
        Ok(Ok((_id, chain_hash))) => {
            emit_audit_event(ctx, action, target_type, target_id, &chain_hash, &timestamp);
        }
        Ok(Err(e)) => {
            crate::metrics::inc_audit_insert_failed();
            tracing::error!(error = %e, "audit log insert failed");
            emit_audit_event(ctx, action, target_type, target_id, "", &timestamp);
        }
        Err(e) => {
            crate::metrics::inc_audit_insert_failed();
            tracing::error!(error = %e, "audit log insert task failed");
            emit_audit_event(ctx, action, target_type, target_id, "", &timestamp);
        }
    }
}

/// Emit the `lorica::audit` tracing event for one mutation, and offer
/// the entry to the log-export sinks (Story 9.8). `chain_hash` is the
/// committed chain head (the out-of-band anchor), or `""` when
/// nothing was persisted (worker mode or an insert failure) - the
/// sink copy is best-effort either way.
fn emit_audit_event(
    ctx: &AuditContext,
    action: &str,
    target_type: &str,
    target_id: &str,
    chain_hash: &str,
    timestamp: &str,
) {
    tracing::info!(
        target: "lorica::audit",
        operator = %ctx.username,
        role = %ctx.role,
        action = %action,
        target_type = %target_type,
        target_id = %target_id,
        ip = %ctx.ip,
        chain_hash = %chain_hash,
        "audit"
    );
    // Gate before building the record so the seven allocations are
    // only paid when an audit-interested sink is installed (QA
    // finding; matches the publish_access / publish_waf pattern).
    if crate::log_sinks::wants(crate::log_sinks::SinkKind::Audit) {
        crate::log_sinks::publish_audit(crate::log_sinks::AuditSinkRecord {
            timestamp: timestamp.to_string(),
            operator_username: ctx.username.clone(),
            operator_role: ctx.role.clone(),
            action: action.to_string(),
            target_type: target_type.to_string(),
            target_id: target_id.to_string(),
            ip: ctx.ip.clone(),
            chain_hash: chain_hash.to_string(),
        });
    }
}

/// Query-string parameters of `GET /api/v1/audit`.
#[derive(Debug, Deserialize)]
pub struct AuditListParams {
    /// Exact operator-username filter.
    pub operator: Option<String>,
    /// Action prefix filter (`route.` matches `route.delete`).
    pub action: Option<String>,
    /// Inclusive RFC 3339 lower bound.
    pub from: Option<String>,
    /// Inclusive RFC 3339 upper bound.
    pub to: Option<String>,
    /// Page size (default 100, capped at 1000).
    pub limit: Option<usize>,
    /// Cursor: rows with `id` strictly below this value.
    pub before_id: Option<i64>,
}

/// GET /api/v1/audit - list audit entries, newest first (Operator+,
/// enforced by the authorize middleware). An absent log store (worker
/// mode, tests) reads as an empty log.
pub async fn list_audit(
    Extension(state): Extension<AppState>,
    Query(params): Query<AuditListParams>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(log_store) = state.log_store.clone() else {
        return Ok(json_data(serde_json::json!({ "entries": [], "total": 0 })));
    };

    let query = AuditQuery {
        operator: params.operator,
        action_prefix: params.action,
        from: params.from,
        to: params.to,
        limit: params.limit.unwrap_or(100).min(1000),
        before_id: params.before_id,
    };

    let (entries, total) = tokio::task::spawn_blocking(move || log_store.query_audit(&query))
        .await
        .map_err(|e| ApiError::Internal(format!("audit query task failed: {e}")))?
        .map_err(ApiError::Internal)?;

    Ok(json_data(serde_json::json!({
        "entries": entries,
        "total": total,
    })))
}

/// GET /api/v1/audit/verify - walk the whole chain and recompute every
/// hash (SuperAdmin only, enforced by the authorize middleware).
pub async fn verify_audit(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(log_store) = state.log_store.clone() else {
        return Ok(json_data(VerifyResult {
            verified: true,
            total_rows: 0,
            first_break_id: None,
            first_break_reason: None,
        }));
    };

    let result = tokio::task::spawn_blocking(move || log_store.verify_audit_chain())
        .await
        .map_err(|e| ApiError::Internal(format!("audit verify task failed: {e}")))?
        .map_err(ApiError::Internal)?;

    Ok(json_data(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_32_zero_bytes_hex() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn hash_payload_absent_is_empty() {
        assert_eq!(hash_payload(None), "");
    }

    #[test]
    fn hash_payload_is_deterministic_and_hex() {
        let v = serde_json::json!({"hostname": "a.example.com", "enabled": true});
        let h1 = hash_payload(Some(&v));
        let h2 = hash_payload(Some(&v));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn input<'a>(username: &'a str, action: &'a str, target_id: &'a str) -> ChainInput<'a> {
        ChainInput {
            timestamp: "t",
            operator_username: username,
            operator_role: "super_admin",
            action,
            target_type: "route",
            target_id,
            before_payload_hash: "",
            after_payload_hash: "",
            ip: "",
            user_agent: "",
        }
    }

    #[test]
    fn chain_hash_changes_with_any_field() {
        let base = compute_chain_hash(GENESIS_HASH, &input("alice", "route.delete", "5"));
        assert_ne!(
            base,
            compute_chain_hash(GENESIS_HASH, &input("alice", "route.delete", "6"))
        );
        assert_ne!(
            base,
            compute_chain_hash(GENESIS_HASH, &input("bob", "route.delete", "5"))
        );
    }

    #[test]
    fn chain_hash_is_boundary_unambiguous() {
        // With raw concatenation these two would collide.
        let a = compute_chain_hash(GENESIS_HASH, &input("ab", "c", "1"));
        let b = compute_chain_hash(GENESIS_HASH, &input("a", "bc", "1"));
        assert_ne!(a, b);
    }
}
