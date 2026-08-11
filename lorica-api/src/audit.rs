//! Tamper-evident admin audit log (Story 8.9).
//!
//! Every state-mutating management-API handler records an audit entry.
//! Rows form a linear SHA-256 hash chain: each row stores the previous
//! row's `chain_hash` and its own `chain_hash` computed over the
//! row's identifying fields. Tampering with any stored field (or
//! deleting a middle row) breaks recomputation at the earliest
//! affected row, which `verify` localises. Retention truncation is
//! chain-safe via a "retention seal" (the earliest surviving row's
//! `prev_chain_hash`) stored in `audit_log_meta`.
//!
//! Storage lives in [`crate::log_store::LogStore`] (`access-log.db`),
//! which only exists in the process that serves the management API
//! (single-process or supervisor). Payloads (`before` / `after`) are
//! hashed, never stored: no secret material can land in the audit
//! table by construction.

use serde::Serialize;

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
}

impl<'a> From<&'a NewAuditEntry> for ChainInput<'a> {
    fn from(entry: &'a NewAuditEntry) -> Self {
        Self {
            timestamp: &entry.timestamp,
            operator_username: &entry.operator_username,
            action: &entry.action,
            target_type: &entry.target_type,
            target_id: &entry.target_id,
            before_payload_hash: &entry.before_payload_hash,
            after_payload_hash: &entry.after_payload_hash,
        }
    }
}

impl<'a> From<&'a AuditRecord> for ChainInput<'a> {
    fn from(row: &'a AuditRecord) -> Self {
        Self {
            timestamp: &row.timestamp,
            operator_username: &row.operator_username,
            action: &row.action,
            target_type: &row.target_type,
            target_id: &row.target_id,
            before_payload_hash: &row.before_payload_hash,
            after_payload_hash: &row.after_payload_hash,
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
        input.action,
        input.target_type,
        input.target_id,
        input.before_payload_hash,
        input.after_payload_hash,
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
            action,
            target_type: "route",
            target_id,
            before_payload_hash: "",
            after_payload_hash: "",
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
