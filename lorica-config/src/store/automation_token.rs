//! Scoped automation tokens on `ConfigStore` (Story 10.3), and the
//! server-side key their secrets are hashed under.
//!
//! Only the HMAC of the secret half is stored, indexed by the public
//! half, so presenting a token is one lookup and one verification.
//!
//! # These rows do NOT replicate
//!
//! `api_tokens` is deliberately absent from [`CanonicalConfig`], from
//! `store/canonical.rs` and from `store/replica.rs`, and it must stay
//! absent. Two reasons, and neither weakens over time:
//!
//! 1. A credential that reaches a follower is a credential in more
//!    places than it needs to be. Every replicated copy is another
//!    database whose theft hands over the ability to recognise a token,
//!    and another machine an operator has to think about when they
//!    revoke one.
//! 2. Nothing on a follower reads them. The automation listener runs on
//!    a standalone node or on a control plane; a follower has no
//!    automation surface to authenticate against.
//!
//! The pull to add them is symmetry with the other tables, which is not
//! a reason. If a future slice needs a follower to accept an automation
//! token, that is a design decision about where the automation surface
//! lives, and it gets made explicitly rather than by extending a list.
//!
//! [`CanonicalConfig`]: crate::canonical::CanonicalConfig

use chrono::{DateTime, Utc};
use ring::rand::SecureRandom;
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{json_column, parse_datetime, parse_optional_datetime};
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::{AutomationToken, AUTOMATION_TOKEN_HMAC_KEY_LEN};

/// The `cluster_secrets` row holding the automation token HMAC key.
///
/// A row of its own beside `token_hmac_key`, never a reuse of it:
/// rotating or burning one credential family must not silently
/// invalidate the other. Both are encrypted under the node master key,
/// so a master-key rotation still covers this one.
const AUTOMATION_TOKEN_HMAC_KEY_ID: &str = "automation_token_hmac_key";

/// The column list every automation-token read binds, in the order
/// [`row_to_automation_token`] expects.
const AUTOMATION_TOKEN_COLUMNS: &str = "public_id, name, secret_hmac, scopes_json, \
     allowed_hostnames_json, allowed_backend_cidrs_json, max_ttl_seconds, created_by, \
     created_at, expires_at, last_used_at, revoked_at";

/// Decode one `api_tokens` row.
fn row_to_automation_token(row: &rusqlite::Row<'_>) -> Result<AutomationToken> {
    let created_at: String = row.get(8)?;
    let expires_at: String = row.get(9)?;
    Ok(AutomationToken {
        public_id: row.get(0)?,
        name: row.get(1)?,
        secret_hmac: row.get(2)?,
        scopes: json_column(row, 3, "automation token", "scopes")?,
        allowed_hostnames: json_column(row, 4, "automation token", "allowed_hostnames")?,
        allowed_backend_cidrs: json_column(row, 5, "automation token", "allowed_backend_cidrs")?,
        max_ttl_seconds: row.get(6)?,
        created_by: row.get(7)?,
        created_at: parse_datetime(&created_at)?,
        expires_at: parse_datetime(&expires_at)?,
        last_used_at: parse_optional_datetime(row.get(10)?)?,
        revoked_at: parse_optional_datetime(row.get(11)?)?,
    })
}

impl ConfigStore {
    /// This node's automation token HMAC key, generated on first use
    /// and persisted encrypted under the master key.
    pub fn automation_token_hmac_key(&self) -> Result<[u8; AUTOMATION_TOKEN_HMAC_KEY_LEN]> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM cluster_secrets WHERE id = ?1",
                params![AUTOMATION_TOKEN_HMAC_KEY_ID],
                |row| row.get(0),
            )
            .optional()?;
        let raw: Vec<u8> = match stored {
            Some(ciphertext) => self.decrypt_bytes(&ciphertext)?,
            None => {
                let mut fresh = [0u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
                ring::rand::SystemRandom::new()
                    .fill(&mut fresh)
                    .map_err(|_| {
                        ConfigError::Validation("automation token key generation failed".into())
                    })?;
                let ciphertext = self.encrypt_bytes(&fresh)?;
                self.conn.execute(
                    "INSERT INTO cluster_secrets (id, value, created_at) VALUES (?1, ?2, ?3)",
                    params![
                        AUTOMATION_TOKEN_HMAC_KEY_ID,
                        ciphertext,
                        Utc::now().to_rfc3339()
                    ],
                )?;
                fresh.to_vec()
            }
        };
        raw.try_into().map_err(|_| {
            ConfigError::Corrupt("stored automation token key has the wrong length".into())
        })
    }

    /// Every automation token, newest first.
    pub fn list_automation_tokens(&self) -> Result<Vec<AutomationToken>> {
        let sql = format!(
            "SELECT {AUTOMATION_TOKEN_COLUMNS} FROM api_tokens \
             ORDER BY created_at DESC, public_id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_automation_token(row)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// One automation token by its public half, or `None` when no such
    /// row exists.
    pub fn get_automation_token(&self, public_id: &str) -> Result<Option<AutomationToken>> {
        let sql = format!("SELECT {AUTOMATION_TOKEN_COLUMNS} FROM api_tokens WHERE public_id = ?1");
        self.conn
            .query_row(&sql, params![public_id], |row| {
                Ok(row_to_automation_token(row))
            })
            .optional()?
            .transpose()
    }

    /// Record a freshly minted token (its secret is already hashed).
    pub fn create_automation_token(&self, token: &AutomationToken) -> Result<()> {
        self.conn.execute(
            "INSERT INTO api_tokens (public_id, name, secret_hmac, scopes_json,
             allowed_hostnames_json, allowed_backend_cidrs_json, max_ttl_seconds, created_by,
             created_at, expires_at, last_used_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                token.public_id,
                token.name,
                token.secret_hmac,
                serialize_field("automation token scopes", &token.scopes)?,
                serialize_field(
                    "automation token allowed_hostnames",
                    &token.allowed_hostnames
                )?,
                serialize_field(
                    "automation token allowed_backend_cidrs",
                    &token.allowed_backend_cidrs
                )?,
                token.max_ttl_seconds,
                token.created_by,
                token.created_at.to_rfc3339(),
                token.expires_at.to_rfc3339(),
                token.last_used_at.map(|t| t.to_rfc3339()),
                token.revoked_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Withdraw a token, leaving the row in place.
    ///
    /// The row stays so an operator can still see that the credential
    /// existed, who minted it and when it was last used; a deleted row
    /// answers none of those questions after an incident. `true` iff the
    /// token was standing, so a second revoke reports honestly rather
    /// than moving `revoked_at` forward.
    pub fn revoke_automation_token(&self, public_id: &str, now: DateTime<Utc>) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE api_tokens SET revoked_at = ?2 WHERE public_id = ?1 AND revoked_at IS NULL",
            params![public_id, now.to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    /// Stamp `last_used_at` after a token has been accepted.
    ///
    /// A vanished row is not an error: the stamp follows a successful
    /// verification, so the only way to miss is a revoke or a delete
    /// landing in between, and failing the caller's request over that
    /// race would punish the operator for good timing.
    pub fn touch_automation_token_last_used(
        &self,
        public_id: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE api_tokens SET last_used_at = ?2 WHERE public_id = ?1",
            params![public_id, now.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Delete one automation token by its public half.
    pub fn delete_automation_token(&self, public_id: &str) -> Result<()> {
        let affected = self.conn.execute(
            "DELETE FROM api_tokens WHERE public_id = ?1",
            params![public_id],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!(
                "automation token {public_id}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use crate::models::{
        AutomationScope, AutomationToken, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
    };
    use crate::store::ConfigStore;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn token(public_id: &str) -> AutomationToken {
        AutomationToken {
            public_id: public_id.to_string(),
            name: format!("token {public_id}"),
            secret_hmac: "a".repeat(64),
            scopes: vec![
                AutomationScope::EnvironmentsWrite,
                AutomationScope::CertificatesRead,
            ],
            allowed_hostnames: vec!["*.preview.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
            created_by: "admin".to_string(),
            created_at: fixed_now(),
            expires_at: fixed_now() + chrono::Duration::days(365),
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn an_automation_token_round_trips_through_the_store() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        let written = token("0123456789abcdef01234567");
        store
            .create_automation_token(&written)
            .expect("test setup: token insert");

        let read = store
            .get_automation_token("0123456789abcdef01234567")
            .expect("test setup: token read")
            .expect("the token exists");
        assert_eq!(read, written);
        assert_eq!(
            store
                .list_automation_tokens()
                .expect("test setup: listing")
                .len(),
            1
        );
    }

    #[test]
    fn an_unknown_public_id_reads_as_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store
            .get_automation_token("ffffffffffffffffffffffff")
            .expect("test setup: token read")
            .is_none());
    }

    #[test]
    fn revoking_stamps_the_row_and_leaves_it_in_place() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");

        assert!(store
            .revoke_automation_token("0123456789abcdef01234567", fixed_now())
            .expect("test setup: revoke"));

        let read = store
            .get_automation_token("0123456789abcdef01234567")
            .expect("test setup: token read")
            .expect("the row survives the revoke");
        assert_eq!(read.revoked_at, Some(fixed_now()));
        assert!(!read.is_live(fixed_now()));
        assert_eq!(read.name, "token 0123456789abcdef01234567");
    }

    #[test]
    fn a_second_revoke_reports_false_and_keeps_the_first_timestamp() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");
        store
            .revoke_automation_token("0123456789abcdef01234567", fixed_now())
            .expect("test setup: revoke");

        let later = fixed_now() + chrono::Duration::days(1);
        assert!(!store
            .revoke_automation_token("0123456789abcdef01234567", later)
            .expect("test setup: second revoke"));
        let read = store
            .get_automation_token("0123456789abcdef01234567")
            .expect("test setup: token read")
            .expect("the token exists");
        assert_eq!(read.revoked_at, Some(fixed_now()));
    }

    #[test]
    fn revoking_an_unknown_token_reports_false() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(!store
            .revoke_automation_token("ffffffffffffffffffffffff", fixed_now())
            .expect("test setup: revoke"));
    }

    #[test]
    fn touching_last_used_records_the_moment_and_nothing_else() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");

        let used = fixed_now() + chrono::Duration::hours(3);
        store
            .touch_automation_token_last_used("0123456789abcdef01234567", used)
            .expect("test setup: touch");

        let read = store
            .get_automation_token("0123456789abcdef01234567")
            .expect("test setup: token read")
            .expect("the token exists");
        assert_eq!(read.last_used_at, Some(used));
        assert!(read.is_live(used));
    }

    #[test]
    fn touching_a_token_that_raced_a_delete_is_not_an_error() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store
            .touch_automation_token_last_used("ffffffffffffffffffffffff", fixed_now())
            .is_ok());
    }

    #[test]
    fn deleting_a_token_removes_it_and_an_unknown_id_is_not_found() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");
        store
            .delete_automation_token("0123456789abcdef01234567")
            .expect("test setup: delete");
        assert!(store
            .get_automation_token("0123456789abcdef01234567")
            .expect("test setup: token read")
            .is_none());
        assert!(store
            .delete_automation_token("0123456789abcdef01234567")
            .is_err());
    }

    #[test]
    fn a_duplicate_public_id_is_refused_by_the_primary_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");
        assert!(store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .is_err());
    }

    #[test]
    fn the_automation_key_is_generated_once_and_is_not_the_join_token_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        let first = store
            .automation_token_hmac_key()
            .expect("test setup: key generates");
        let second = store
            .automation_token_hmac_key()
            .expect("test setup: key reads back");
        assert_eq!(first, second);
        // Separate rows, separate keys: compromising one credential
        // family must not hand over the other.
        let join_key = store.token_hmac_key().expect("test setup: join key");
        assert_ne!(first, join_key);
    }

    #[test]
    fn automation_tokens_stay_out_of_the_canonical_blob() {
        // A credential that reaches a follower is a credential in more
        // places than it needs to be, and nothing on a follower reads
        // one. This asserts the absence so a later slice cannot add it
        // back by symmetry with the other tables without a test
        // failing.
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .create_automation_token(&token("0123456789abcdef01234567"))
            .expect("test setup: token insert");
        let blob = crate::canonical::canonical_config(&store).expect("test setup: canonical blob");
        let json = serde_json::to_string(&blob).expect("test setup: blob serialises");
        assert!(!json.contains("0123456789abcdef01234567"), "{json}");
        assert!(!json.contains("api_tokens"), "{json}");
    }
}
