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
//!
//! # One queue, one writer, both planes
//!
//! [`record`] used to await a chained-hash SQLite commit before its
//! caller could answer, so every audited request paid one write and a
//! burst serialised there. It now hands the row to the bounded queue
//! that [`crate::log_store::LogStore`] owns
//! (`AUDIT_QUEUE_CAPACITY` deep) and returns.
//!
//! ONE queue for the management API and the automation plane
//! together, and one consumer behind it. Both write the same table and
//! the chain hash only means anything in write order, so a second
//! consumer would fork the chain and a second queue would give the two
//! planes different durability promises for the same rows. Ordering is
//! what the queue buys: rows chain in the order [`record`] was called,
//! whichever plane called it.
//!
//! What it costs is a window. A row is durable within the consumer's
//! next drain, not before the response, so a caller that must read the
//! row back (the `lorica cluster leave` CLI, which then exits; tests
//! that assert on the trail) flushes with
//! [`crate::log_store::LogStore::flush_audit`] first. And a full queue
//! DROPS the row, counted in `lorica_audit_rows_dropped_total` and
//! logged at ERROR: blocking a caller on a full audit queue would turn
//! a slow disk into a plane that stops answering, which is the outage
//! the log-writer stance already refuses.

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
    /// The node this row was recorded on (Story 9.9 AC #2).
    ///
    /// Empty means this node, on every install: a standalone node has
    /// no node id to stamp, and giving one to a clustered node's own
    /// rows would make the column change meaning the day it joins a
    /// fleet. Only fanned-in rows carry a value, stamped by the control
    /// plane from the mutual-TLS session and never from the payload.
    pub node_id: String,
    /// The row id the ORIGIN node assigned (Story 9.9 AC #2).
    ///
    /// Zero on a local row, where `id` already is that id. On a fanned-
    /// in row it is what reconstructs the origin's own order, which the
    /// aggregated `id` does not, and what lets an operator match an
    /// aggregated row against the node's own copy.
    pub origin_id: i64,
}

/// One audit row as another node published it (Story 9.9 AC #2).
///
/// Every field is the origin's, including both chain hashes, and the
/// control plane stores them verbatim. It deliberately carries no
/// `node_id`: the control plane stamps that from the mutual-TLS
/// session, never from the payload, which is the Story 9.5 D15 rule
/// and the reason a follower cannot write rows into another node's
/// history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FannedInAuditRow {
    /// The row id the origin node assigned.
    pub origin_id: i64,
    /// RFC 3339 UTC timestamp of the mutation.
    pub timestamp: String,
    /// RBAC username of the operator.
    pub operator_username: String,
    /// RBAC role at mutation time.
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
    /// The origin's `prev_chain_hash`, stored unchanged.
    pub prev_chain_hash: String,
    /// The origin's `chain_hash`, stored unchanged. Never recomputed:
    /// the aggregated copy is worth something only if it is identical
    /// to what the node published on its own anchor stream.
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
    /// Restrict to one node's rows (Story 9.9 AC #5).
    ///
    /// `Some("")` is meaningful and selects THIS node's own rows, which
    /// is why it is not folded into `None`.
    pub node_id: Option<String>,
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

    /// The context of an event no management session is behind: a
    /// budget running out, an environment expiring, a replication
    /// apply. `actor` names the background worker (`capture`,
    /// `reaper`, `cluster`).
    ///
    /// They share one shape on purpose. An operator scanning the audit
    /// log has to be able to tell a node-side event from an operator's
    /// at a glance, and that only works while every such event carries
    /// the same `node` role and the same empty provenance; a caller
    /// that spells the shape itself is one refactor away from drifting.
    /// A site with a real source address (the cluster plane's peer)
    /// overrides `ip` on top of this, which keeps the role and the
    /// missing user agent shared.
    pub fn node(actor: &str) -> Self {
        Self {
            username: actor.to_string(),
            role: "node".to_string(),
            ip: String::new(),
            user_agent: String::new(),
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
        Ok(Self(
            parts.extensions.get::<ConnectInfo<SocketAddr>>().cloned(),
        ))
    }
}

/// Record one audit entry for a mutation that SUCCEEDED, and emit the
/// matching `lorica::audit` tracing event (picked up by stdout/JSON
/// logging and, when enabled, the OTel bridge).
///
/// `target` is `(target_type, target_id)`. `before` / `after` payloads
/// are SHA-256-hashed; the payloads themselves are never persisted.
///
/// The row is HANDED TO THE QUEUE here, not written here: the caller
/// pays a `try_send`, and [`crate::log_store::LogStore`]'s single
/// audit writer commits it. See the module docs for what that costs
/// and what it buys. The tracing event is emitted by that writer,
/// AFTER persistence, so it carries the committed `chain_hash` (the
/// external-anchor control in the module threat model); on the
/// no-store, dropped and failure paths it is still emitted, with an
/// empty `chain_hash`. Failure policy: an insert failure is counted
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
/// API. Same queue, same sink copy, same failure policy.
///
/// Still `async` though nothing here awaits: every one of its ninety
/// call sites is in an async handler and reads as a call that records
/// something. Making it sync would churn all of them to say nothing
/// new.
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

    // Boxed from the start: the queue carries it boxed, so building it
    // on the stack would only move a dozen strings twice.
    let entry = Box::new(NewAuditEntry {
        timestamp,
        operator_username: ctx.username.clone(),
        operator_role: ctx.role.clone(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        before_payload_hash: hash_payload(before),
        after_payload_hash: hash_payload(after),
        ip: ctx.ip.clone(),
        user_agent: ctx.user_agent.clone(),
    });

    // The enqueue is what fixes the order: `try_send` returns in call
    // order, and a single consumer writes in receive order, so rows
    // chain in the order `record` was called across both planes.
    // Nothing may await between building the entry and offering it.
    if let Err(dropped) = log_store.enqueue_audit(entry) {
        // A full queue sheds the row rather than the request. Waiting
        // here would turn a slow disk into a management plane that
        // stops answering, which is the outage the log-writer stance
        // already refuses; the counter is how an operator learns the
        // trail has a hole.
        crate::metrics::inc_audit_rows_dropped();
        tracing::error!(
            action = %dropped.action,
            operator = %dropped.operator_username,
            "audit queue full; the row was dropped and the chain has a gap"
        );
        emit_stored_event(&dropped, "");
    }
}

/// The part of an action verb that follows the first `:`.
///
/// The automation plane spells the precise cause of a refusal there
/// (`automation.request.unauthenticated:wrong_alg`); the management
/// plane's verbs carry none and read as empty. Deriving the event
/// field from the verb rather than passing it down separately keeps
/// one source of truth: the stored row and the shipped event cannot
/// disagree about why a request was turned away.
fn action_reason(action: &str) -> &str {
    action.split_once(':').map_or("", |(_, reason)| reason)
}

/// [`emit_audit_event`] for a row that has already been built.
///
/// The audit writer thread calls this once the row is committed, so
/// the event carries the real `chain_hash`; `record_with_store` calls
/// it with an empty one when the queue dropped the row. The entry
/// already holds every field the event needs, which is why the writer
/// does not have to carry an [`AuditContext`] alongside it.
pub(crate) fn emit_stored_event(entry: &NewAuditEntry, chain_hash: &str) {
    let ctx = AuditContext {
        username: entry.operator_username.clone(),
        role: entry.operator_role.clone(),
        ip: entry.ip.clone(),
        user_agent: entry.user_agent.clone(),
    };
    emit_audit_event(
        &ctx,
        &entry.action,
        &entry.target_type,
        &entry.target_id,
        chain_hash,
        &entry.timestamp,
    );
}

/// Emit the `lorica::audit` tracing event for one mutation, and offer
/// the entry to the log-export sinks (Story 9.8). `chain_hash` is the
/// committed chain head (the out-of-band anchor), or `""` when
/// nothing was persisted (worker mode or an insert failure) - the
/// sink copy is best-effort either way.
///
/// `reason` rides as its OWN field as well as inside `action`, so a
/// syslog or OTLP consumer filters refusals on a field instead of
/// parsing a dotted verb. The payloads stay hashed (Story 9.9): the
/// reason vocabulary is a closed list of words with no caller-supplied
/// material in it, which is exactly why it can travel in clear when a
/// payload cannot.
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
        reason = %action_reason(action),
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
    /// Restrict to one node's rows (Story 9.9 AC #5).
    ///
    /// The empty string selects THIS node's own rows, which is a real
    /// filter and not the absence of one; omitting the parameter
    /// selects every node's.
    pub node: Option<String>,
}

/// GET /api/v1/audit - list audit entries, newest first (Operator+,
/// enforced by the authorize middleware). An absent log store (worker
/// mode, tests) reads as an empty log.
pub async fn list_audit(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Query(params): Query<AuditListParams>,
) -> Result<impl IntoResponse, ApiError> {
    // On a control plane the table aggregates every follower's
    // operators, roles, addresses and user agents (Story 9.9), and
    // the Operator floor was set when it held one node's rows. The
    // fleet's trail (`node` absent, or naming another node) is
    // SuperAdmin; `node=` with the empty string is this node's own
    // chain and keeps the single-node floor exactly (Epic 9 close,
    // backlog #73 decided). A standalone install or a follower holds
    // one chain, so nothing changes there.
    let aggregates = matches!(
        state.cluster,
        crate::cluster::ClusterRuntime::ControlPlane(_)
    );
    if aggregates
        && params.node.as_deref() != Some("")
        && session.role < lorica_config::models::Role::SuperAdmin
    {
        return Err(ApiError::Forbidden(
            "the fleet's audit trail is SuperAdmin; pass node= (empty) for this node's own".into(),
        ));
    }
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
        node_id: params.node,
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

/// Query string of `GET /api/v1/audit/verify`.
#[derive(Debug, Deserialize)]
pub struct AuditVerifyParams {
    /// Verify one node's chain. The empty string is this node's own.
    /// Omitted, every chain in the table is verified and reported
    /// separately.
    pub node: Option<String>,
}

/// One chain's verdict (Story 9.9 AC #3).
#[derive(Debug, Clone, Serialize)]
pub struct NodeVerifyResult {
    /// The chain's node id; empty is this node's own.
    pub node_id: String,
    /// That chain's verdict.
    #[serde(flatten)]
    pub result: VerifyResult,
}

/// GET /api/v1/audit/verify - recompute the hash chain (SuperAdmin
/// only, enforced by the authorize middleware).
///
/// Reports PER NODE. An aggregated table interleaves N chains, so one
/// verdict over the whole table would be meaningless: it would chain
/// one node's row to another's and break at the first interleave. The
/// top-level `verified` is the conjunction, so a caller that only reads
/// that field still gets a correct answer.
pub async fn verify_audit(
    Extension(state): Extension<AppState>,
    Query(params): Query<AuditVerifyParams>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(log_store) = state.log_store.clone() else {
        return Ok(json_data(serde_json::json!({
            "verified": true,
            "nodes": Vec::<NodeVerifyResult>::new(),
        })));
    };

    let requested = params.node;
    let nodes = tokio::task::spawn_blocking(move || {
        let ids = match requested {
            Some(node_id) => vec![node_id],
            None => {
                let mut ids = log_store.audit_node_ids()?;
                // A table with no rows at all still has a local chain
                // to report on, and reporting nothing reads as "not
                // checked" rather than "nothing to check".
                if ids.is_empty() {
                    ids.push(String::new());
                }
                ids
            }
        };
        ids.into_iter()
            .map(|node_id| {
                log_store
                    .verify_audit_chain_for(&node_id)
                    .map(|result| NodeVerifyResult { node_id, result })
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .await
    .map_err(|e| ApiError::Internal(format!("audit verify task failed: {e}")))?
    .map_err(ApiError::Internal)?;

    let verified = nodes.iter().all(|n| n.result.verified);
    Ok(json_data(serde_json::json!({
        "verified": verified,
        "nodes": nodes,
    })))
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
    fn the_event_reason_is_whatever_the_action_spells_after_the_first_colon() {
        assert_eq!(action_reason("route.delete"), "");
        assert_eq!(
            action_reason("automation.request.unauthenticated:wrong_alg"),
            "wrong_alg"
        );
        // A parametrised reason keeps its own colon: the split is on
        // the FIRST one, so the claim name travels with the stem.
        assert_eq!(
            action_reason("automation.request.unauthenticated:bound_claim_mismatch:project_path"),
            "bound_claim_mismatch:project_path"
        );
        assert_eq!(
            action_reason("automation.request.forbidden:environments:write"),
            "environments:write"
        );
    }

    #[test]
    fn chain_hash_is_boundary_unambiguous() {
        // With raw concatenation these two would collide.
        let a = compute_chain_hash(GENESIS_HASH, &input("ab", "c", "1"));
        let b = compute_chain_hash(GENESIS_HASH, &input("a", "bc", "1"));
        assert_ne!(a, b);
    }

    // ---- the write queue ----

    fn probe_ctx(username: &str, role: &str) -> AuditContext {
        AuditContext {
            username: username.to_string(),
            role: role.to_string(),
            ip: String::new(),
            user_agent: String::new(),
        }
    }

    /// The stored rows for one probe target type, oldest first.
    fn probe_rows(
        log_store: &crate::log_store::LogStore,
        target_type: &str,
    ) -> Vec<(String, String)> {
        let (mut rows, _) = log_store
            .query_audit(&AuditQuery {
                limit: 1000,
                ..AuditQuery::default()
            })
            .expect("the audit query runs");
        rows.retain(|row| row.target_type == target_type);
        // `query_audit` answers newest first; call order reads better
        // the other way round.
        rows.reverse();
        rows.into_iter()
            .map(|row| (row.operator_username, row.target_id))
            .collect()
    }

    #[tokio::test]
    async fn rows_chain_in_call_order_when_both_planes_interleave() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store = std::sync::Arc::new(
            crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"),
        );

        const ROUNDS: usize = 24;
        const TARGET_TYPE: &str = "queue_order_probe";

        // Two tasks stand in for the two planes, handing the turn back
        // and forth: call order is then a fact this test states, not a
        // race it hopes wins.
        let (to_automation, mut automation_turn) = tokio::sync::mpsc::channel::<()>(1);
        let (to_management, mut management_turn) = tokio::sync::mpsc::channel::<()>(1);

        let management_store = std::sync::Arc::clone(&log_store);
        let management = tokio::spawn(async move {
            let ctx = probe_ctx("operator", "super_admin");
            for round in 0..ROUNDS {
                let target_id = format!("management-{round:02}");
                record_with_store(
                    Some(std::sync::Arc::clone(&management_store)),
                    &ctx,
                    "queue.order",
                    (TARGET_TYPE, &target_id),
                    None,
                    None,
                )
                .await;
                if to_automation.send(()).await.is_err() {
                    break;
                }
                if management_turn.recv().await.is_none() {
                    break;
                }
            }
        });

        let automation_store = std::sync::Arc::clone(&log_store);
        let automation = tokio::spawn(async move {
            let ctx = probe_ctx("pipeline", "automation");
            for round in 0..ROUNDS {
                if automation_turn.recv().await.is_none() {
                    break;
                }
                let target_id = format!("automation-{round:02}");
                record_with_store(
                    Some(std::sync::Arc::clone(&automation_store)),
                    &ctx,
                    "queue.order",
                    (TARGET_TYPE, &target_id),
                    None,
                    None,
                )
                .await;
                if to_management.send(()).await.is_err() {
                    break;
                }
            }
        });

        management.await.expect("the management task finishes");
        automation.await.expect("the automation task finishes");
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");

        let expected: Vec<(String, String)> = (0..ROUNDS)
            .flat_map(|round| {
                [
                    ("operator".to_string(), format!("management-{round:02}")),
                    ("pipeline".to_string(), format!("automation-{round:02}")),
                ]
            })
            .collect();
        assert_eq!(
            probe_rows(&log_store, TARGET_TYPE),
            expected,
            "one consumer writes in arrival order, so the chain follows call order across planes"
        );
    }

    #[tokio::test]
    async fn a_full_audit_queue_drops_the_row_counts_it_and_never_blocks() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store = std::sync::Arc::new(
            crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"),
        );

        // A thread stalls the writer by holding the connection it
        // commits through. A thread rather than a guard in this
        // function because the lock must outlive an await and a future
        // has no business holding one across a yield point.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (stalled, is_stalled) = std::sync::mpsc::channel::<()>();
        let stalling_store = std::sync::Arc::clone(&log_store);
        let staller = std::thread::spawn(move || {
            let _connection = stalling_store.block_audit_writer_for_test();
            let _ = stalled.send(());
            let _ = released.recv();
        });
        is_stalled
            .recv()
            .expect("the stalling thread takes the connection");

        // The consumer may already hold one row, so capacity + 1 rows
        // can still be absorbed; the surplus has nowhere to go.
        const SURPLUS: usize = 64;
        let overflow = crate::log_store::AUDIT_QUEUE_CAPACITY + SURPLUS;
        let before = crate::metrics::audit_rows_dropped_total();
        let ctx = probe_ctx("pipeline", "automation");
        for row in 0..overflow {
            let target_id = format!("drop-{row}");
            // Reaching the end of this loop IS the no-block assertion:
            // a `send().await` here would never return.
            record_with_store(
                Some(std::sync::Arc::clone(&log_store)),
                &ctx,
                "queue.drop",
                ("queue_drop_probe", &target_id),
                None,
                None,
            )
            .await;
        }
        let dropped = crate::metrics::audit_rows_dropped_total() - before;

        let _ = release.send(());
        staller.join().expect("the stalling thread finishes");

        assert!(
            dropped >= (SURPLUS - 1) as u64,
            "a full queue sheds every row it cannot hold: {dropped} dropped of {overflow} offered"
        );
    }
}
