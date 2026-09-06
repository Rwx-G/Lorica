//! Join tokens on `ConfigStore` (Story 9.3 AC #1/#4/#5).
//!
//! Only the HMAC of the secret half is stored, indexed by the public
//! half, so a redemption is one lookup and one verification. The burn
//! is a single conditional UPDATE that must report exactly one row
//! BEFORE any certificate is signed (AC #4): N concurrent redemptions
//! of one token race on the row lock and exactly one wins.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{parse_datetime, parse_optional_datetime};
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::{JoinToken, TokenState};

const TOKEN_COLUMNS: &str = "public_id, secret_hmac, state, created_at, expires_at, created_by, \
     bound_node_name, bound_source_cidr, burned_at, burned_by_node_id";

fn row_to_token(row: &rusqlite::Row<'_>) -> Result<JoinToken> {
    let state: String = row.get(2)?;
    Ok(JoinToken {
        public_id: row.get(0)?,
        secret_hmac: row.get(1)?,
        state: state
            .parse()
            .map_err(|e: String| ConfigError::Validation(e))?,
        created_at: parse_datetime(&row.get::<_, String>(3)?)?,
        expires_at: parse_datetime(&row.get::<_, String>(4)?)?,
        created_by: row.get(5)?,
        bound_node_name: row.get(6)?,
        bound_source_cidr: row.get(7)?,
        burned_at: parse_optional_datetime(row.get(8)?)?,
        burned_by_node_id: row.get(9)?,
    })
}

impl ConfigStore {
    /// Record a freshly minted token (its secret is already hashed).
    pub fn create_join_token(&self, token: &JoinToken) -> Result<()> {
        self.conn.execute(
            "INSERT INTO cluster_join_tokens (public_id, secret_hmac, state, created_at, \
             expires_at, created_by, bound_node_name, bound_source_cidr, burned_at, \
             burned_by_node_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                token.public_id,
                token.secret_hmac,
                token.state.as_str(),
                token.created_at.to_rfc3339(),
                token.expires_at.to_rfc3339(),
                token.created_by,
                token.bound_node_name,
                token.bound_source_cidr,
                token.burned_at.map(|t| t.to_rfc3339()),
                token.burned_by_node_id,
            ],
        )?;
        Ok(())
    }

    /// Fetch a token by its public half.
    pub fn get_join_token(&self, public_id: &str) -> Result<Option<JoinToken>> {
        self.conn
            .query_row(
                &format!("SELECT {TOKEN_COLUMNS} FROM cluster_join_tokens WHERE public_id = ?1"),
                params![public_id],
                |row| Ok(row_to_token(row)),
            )
            .optional()?
            .transpose()
    }

    /// Every token, newest first.
    pub fn list_join_tokens(&self) -> Result<Vec<JoinToken>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {TOKEN_COLUMNS} FROM cluster_join_tokens ORDER BY created_at DESC, public_id"
        ))?;
        let rows = stmt.query_map([], |row| Ok(row_to_token(row)))?;
        let mut tokens = Vec::new();
        for r in rows {
            tokens.push(r??);
        }
        Ok(tokens)
    }

    /// The atomic burn (AC #4): `unused` and unexpired -> `burned`, in
    /// one conditional UPDATE. `true` iff exactly one row changed; the
    /// caller signs a certificate only on `true`.
    pub fn burn_join_token(
        &self,
        public_id: &str,
        node_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE cluster_join_tokens SET state = 'burned', burned_at = ?3, \
             burned_by_node_id = ?2 WHERE public_id = ?1 AND state = 'unused' AND expires_at > ?3",
            params![public_id, node_id, now.to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    /// Withdraw an unused token. `true` iff it was unused.
    pub fn revoke_join_token(&self, public_id: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE cluster_join_tokens SET state = 'revoked' WHERE public_id = ?1 AND state = 'unused'",
            params![public_id],
        )?;
        Ok(changed == 1)
    }

    /// Tokens that can still be redeemed at `now`: the enrollment
    /// listener's liveness input.
    pub fn count_live_join_tokens(&self, now: DateTime<Utc>) -> Result<u32> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM cluster_join_tokens WHERE state = ?1 AND expires_at > ?2",
            params![TokenState::Unused.as_str(), now.to_rfc3339()],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// The earliest expiry among live tokens, so the liveness
    /// publisher can wake exactly when the window would close.
    pub fn next_join_token_expiry(&self, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
        let earliest: Option<String> = self
            .conn
            .query_row(
                "SELECT MIN(expires_at) FROM cluster_join_tokens WHERE state = ?1 AND expires_at > ?2",
                params![TokenState::Unused.as_str(), now.to_rfc3339()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        earliest.map(|s| parse_datetime(&s)).transpose()
    }
}
