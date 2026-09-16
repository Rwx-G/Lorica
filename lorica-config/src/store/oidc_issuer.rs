//! OIDC issuer entries on `ConfigStore` (Story 10.5).
//!
//! # These rows do NOT replicate
//!
//! `oidc_issuers` is deliberately absent from [`CanonicalConfig`], from
//! `canonical.rs` and from `store/replica.rs`, for the same two reasons
//! `api_tokens` is, and neither weakens over time:
//!
//! 1. An entry is authority, not configuration. It names an identity
//!    provider whose signed statements this node will act on, and
//!    every replicated copy is another database in which that trust
//!    decision could be edited or read. A static token is a secret; an
//!    issuer entry is the thing that decides who needs no secret at
//!    all, which is not less sensitive.
//! 2. Nothing on a follower reads them. The automation listener runs
//!    on a standalone node or on a control plane; a follower has no
//!    automation surface to verify an ID token against.
//!
//! `oidc_issuers_stay_out_of_the_canonical_blob` asserts the absence
//! so a later slice cannot add it back by symmetry.
//!
//! [`CanonicalConfig`]: crate::canonical::CanonicalConfig

use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::OidcIssuer;

/// The column list every issuer read binds, in the order
/// [`row_to_oidc_issuer`] expects.
const OIDC_ISSUER_COLUMNS: &str = "id, issuer, audience, jwks_url, bound_claims_json, \
     scopes_json, allowed_hostnames_json, allowed_backend_cidrs_json, max_ttl_seconds, \
     created_by, created_at";

/// Decode one JSON column of an `oidc_issuers` row.
///
/// A malformed column is an error rather than a default, the same
/// stance as `api_tokens`: the bound claims and the grant lists ARE the
/// entry's authority, and degrading one to "empty" would either make a
/// policy that matches nothing or one that binds nothing.
fn json_column<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
    field: &str,
) -> Result<T> {
    let raw: String = row
        .get(index)
        .map_err(|e| ConfigError::Validation(format!("oidc issuer {field} unreadable: {e}")))?;
    serde_json::from_str(&raw)
        .map_err(|e| ConfigError::Validation(format!("invalid oidc issuer {field} JSON: {e}")))
}

/// Decode one `oidc_issuers` row.
fn row_to_oidc_issuer(row: &rusqlite::Row<'_>) -> Result<OidcIssuer> {
    let created_at: String = row.get(10)?;
    Ok(OidcIssuer {
        id: row.get(0)?,
        issuer: row.get(1)?,
        audience: row.get(2)?,
        jwks_url: row.get(3)?,
        bound_claims: json_column(row, 4, "bound_claims")?,
        scopes: json_column(row, 5, "scopes")?,
        allowed_hostnames: json_column(row, 6, "allowed_hostnames")?,
        allowed_backend_cidrs: json_column(row, 7, "allowed_backend_cidrs")?,
        max_ttl_seconds: row.get(8)?,
        created_by: row.get(9)?,
        created_at: parse_datetime(&created_at)?,
    })
}

impl ConfigStore {
    /// Every issuer entry, oldest first so a listing is stable and a
    /// verifier that tries entries in order tries them the way the
    /// operator registered them.
    pub fn list_oidc_issuers(&self) -> Result<Vec<OidcIssuer>> {
        self.oidc_issuers_where("1 = 1", &[])
    }

    /// Every issuer entry whose `audience` is exactly `audience`: the
    /// candidates for a presented token, before any signature is
    /// checked.
    pub fn list_oidc_issuers_for_audience(&self, audience: &str) -> Result<Vec<OidcIssuer>> {
        self.oidc_issuers_where("audience = ?1", &[&audience])
    }

    /// The two listings share one query; `predicate` is a compile-time
    /// constant from this module, never caller-supplied.
    fn oidc_issuers_where(
        &self,
        predicate: &'static str,
        binds: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<OidcIssuer>> {
        let sql = format!(
            "SELECT {OIDC_ISSUER_COLUMNS} FROM oidc_issuers WHERE {predicate} \
             ORDER BY created_at ASC, id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(binds, |row| Ok(row_to_oidc_issuer(row)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// One issuer entry by id, or `None` when no such row exists.
    pub fn get_oidc_issuer(&self, id: &str) -> Result<Option<OidcIssuer>> {
        let sql = format!("SELECT {OIDC_ISSUER_COLUMNS} FROM oidc_issuers WHERE id = ?1");
        self.conn
            .query_row(&sql, params![id], |row| Ok(row_to_oidc_issuer(row)))
            .optional()?
            .transpose()
    }

    /// Record a validated issuer entry.
    pub fn create_oidc_issuer(&self, issuer: &OidcIssuer) -> Result<()> {
        self.conn.execute(
            "INSERT INTO oidc_issuers (id, issuer, audience, jwks_url, bound_claims_json,
             scopes_json, allowed_hostnames_json, allowed_backend_cidrs_json, max_ttl_seconds,
             created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                issuer.id,
                issuer.issuer,
                issuer.audience,
                issuer.jwks_url,
                serialize_field("oidc issuer bound_claims", &issuer.bound_claims)?,
                serialize_field("oidc issuer scopes", &issuer.scopes)?,
                serialize_field("oidc issuer allowed_hostnames", &issuer.allowed_hostnames)?,
                serialize_field(
                    "oidc issuer allowed_backend_cidrs",
                    &issuer.allowed_backend_cidrs
                )?,
                issuer.max_ttl_seconds,
                issuer.created_by,
                issuer.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Delete one issuer entry by id.
    ///
    /// A real delete, unlike a token revocation: the row holds no
    /// credential whose history matters after the fact, and the audit
    /// row of the delete keeps what the entry said. The verifier reads
    /// the table on every presented token, so the next ID token this
    /// entry would have accepted is refused as soon as this returns.
    pub fn delete_oidc_issuer(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM oidc_issuers WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("oidc issuer {id}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};

    use crate::models::{AutomationScope, OidcIssuer, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS};
    use crate::store::ConfigStore;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn issuer(id: &str, audience: &str) -> OidcIssuer {
        let mut bound_claims = BTreeMap::new();
        bound_claims.insert("project_path".to_string(), "acme/*".to_string());
        bound_claims.insert("ref_protected".to_string(), "true".to_string());
        OidcIssuer {
            id: id.to_string(),
            issuer: "https://gitlab.example.com".to_string(),
            audience: audience.to_string(),
            jwks_url: "https://gitlab.example.com/oauth/discovery/keys".to_string(),
            bound_claims,
            allowed_hostnames: vec!["*.preview.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
            scopes: vec![
                AutomationScope::EnvironmentsRead,
                AutomationScope::EnvironmentsWrite,
            ],
            created_by: "admin".to_string(),
            created_at: fixed_now(),
        }
    }

    #[test]
    fn an_issuer_entry_round_trips_through_the_store() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        let written = issuer("issuer-1", "lorica-prod");
        store
            .create_oidc_issuer(&written)
            .expect("test setup: issuer insert");

        let read = store
            .get_oidc_issuer("issuer-1")
            .expect("test setup: issuer read")
            .expect("the entry exists");
        assert_eq!(read, written);
        assert_eq!(
            store
                .list_oidc_issuers()
                .expect("test setup: listing")
                .len(),
            1
        );
    }

    #[test]
    fn the_audience_listing_returns_only_exact_matches_in_registration_order() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        let mut later = issuer("issuer-b", "lorica-prod");
        later.created_at = fixed_now() + chrono::Duration::minutes(1);
        store
            .create_oidc_issuer(&later)
            .expect("test setup: issuer insert");
        store
            .create_oidc_issuer(&issuer("issuer-a", "lorica-prod"))
            .expect("test setup: issuer insert");
        store
            .create_oidc_issuer(&issuer("issuer-c", "lorica-staging"))
            .expect("test setup: issuer insert");

        let ids: Vec<String> = store
            .list_oidc_issuers_for_audience("lorica-prod")
            .expect("audience read")
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(ids, vec!["issuer-a".to_string(), "issuer-b".to_string()]);
        assert!(store
            .list_oidc_issuers_for_audience("LORICA-PROD")
            .expect("audience read")
            .is_empty());
        assert!(store
            .list_oidc_issuers_for_audience("lorica")
            .expect("audience read")
            .is_empty());
    }

    #[test]
    fn deleting_an_entry_removes_it_and_an_unknown_id_is_not_found() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_oidc_issuer(&issuer("issuer-1", "lorica-prod"))
            .expect("test setup: issuer insert");
        store
            .delete_oidc_issuer("issuer-1")
            .expect("test setup: delete");
        assert!(store
            .get_oidc_issuer("issuer-1")
            .expect("test setup: issuer read")
            .is_none());
        assert!(store.delete_oidc_issuer("issuer-1").is_err());
    }

    #[test]
    fn a_duplicate_id_is_refused_by_the_primary_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_oidc_issuer(&issuer("issuer-1", "lorica-prod"))
            .expect("test setup: issuer insert");
        assert!(store
            .create_oidc_issuer(&issuer("issuer-1", "lorica-prod"))
            .is_err());
    }

    #[test]
    fn oidc_issuers_stay_out_of_the_canonical_blob() {
        // An issuer entry decides who needs no secret at all to act on
        // this node. That decision belongs on the node that verifies,
        // and nothing on a follower does. This asserts the absence so a
        // later slice cannot add it back by symmetry with the other
        // tables without a test failing.
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_oidc_issuer(&issuer("issuer-1", "lorica-prod-sentinel"))
            .expect("test setup: issuer insert");
        let blob = crate::canonical::canonical_config(&store).expect("test setup: canonical blob");
        let json = serde_json::to_string(&blob).expect("test setup: blob serialises");
        assert!(!json.contains("lorica-prod-sentinel"), "{json}");
        assert!(!json.contains("oidc_issuers"), "{json}");
        assert!(!json.contains("gitlab.example.com"), "{json}");
    }
}
