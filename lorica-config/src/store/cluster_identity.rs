//! A follower's own fleet identity and the control plane's token key
//! on `ConfigStore` (Story 9.3).
//!
//! `cluster_identity` holds the single row a follower gets at
//! enrollment (leaf key encrypted at rest, registered for rotation).
//! `cluster_secrets` holds the control plane's token HMAC key
//! (encrypted at rest, registered for rotation): rotating the master
//! key therefore rotates the token key too, which invalidates every
//! outstanding join token - the right outcome for a key event.

use chrono::Utc;
use ring::rand::SecureRandom;
use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::ClusterIdentity;

/// The fixed primary key of the identity row.
const IDENTITY_ROW_ID: &str = "self";

/// The `cluster_secrets` row holding the token HMAC key.
const TOKEN_HMAC_KEY_ID: &str = "token_hmac_key";

/// Length of the token HMAC key.
pub const TOKEN_HMAC_KEY_LEN: usize = 32;

/// The raw identity row: node_id, node_name, cert_pem, key_pem
/// (ciphertext), ca_pem, control_plane, server_name, enrolled_at,
/// cert_not_after.
type IdentityRow = (
    String,
    String,
    String,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
);

impl ConfigStore {
    /// Persist (or replace) this node's fleet identity.
    pub fn set_cluster_identity(&self, identity: &ClusterIdentity) -> Result<()> {
        let encrypted_key = self.encrypt_key_pem(&identity.key_pem)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO cluster_identity (id, node_id, node_name, cert_pem, key_pem, \
             ca_pem, control_plane, server_name, enrolled_at, cert_not_after) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                IDENTITY_ROW_ID,
                identity.node_id,
                identity.node_name,
                identity.cert_pem,
                encrypted_key,
                identity.ca_pem,
                identity.control_plane,
                identity.server_name,
                identity.enrolled_at.to_rfc3339(),
                identity.cert_not_after.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// This node's fleet identity, key decrypted. `None` on a node
    /// that never joined (or left).
    pub fn get_cluster_identity(&self) -> Result<Option<ClusterIdentity>> {
        let row: Option<IdentityRow> = self
            .conn
            .query_row(
                "SELECT node_id, node_name, cert_pem, key_pem, ca_pem, control_plane, \
                 server_name, enrolled_at, cert_not_after FROM cluster_identity WHERE id = ?1",
                params![IDENTITY_ROW_ID],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            node_id,
            node_name,
            cert_pem,
            stored_key,
            ca_pem,
            control_plane,
            server_name,
            enrolled_at,
            cert_not_after,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(ClusterIdentity {
            node_id,
            node_name,
            cert_pem,
            key_pem: self.decrypt_key_pem(&stored_key)?,
            ca_pem,
            control_plane,
            server_name,
            enrolled_at: parse_datetime(&enrolled_at)?,
            cert_not_after: parse_datetime(&cert_not_after)?,
        }))
    }

    /// Wipe this node's fleet identity (`lorica cluster leave`).
    /// `true` iff a row existed.
    pub fn delete_cluster_identity(&self) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM cluster_identity WHERE id = ?1",
            params![IDENTITY_ROW_ID],
        )?;
        Ok(changed == 1)
    }

    /// The control plane's token HMAC key, generated on first use and
    /// persisted encrypted.
    pub fn token_hmac_key(&self) -> Result<[u8; TOKEN_HMAC_KEY_LEN]> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM cluster_secrets WHERE id = ?1",
                params![TOKEN_HMAC_KEY_ID],
                |row| row.get(0),
            )
            .optional()?;
        let raw: Vec<u8> = match stored {
            Some(ciphertext) => self.decrypt_bytes(&ciphertext)?,
            None => {
                let mut fresh = [0u8; TOKEN_HMAC_KEY_LEN];
                ring::rand::SystemRandom::new()
                    .fill(&mut fresh)
                    .map_err(|_| ConfigError::Validation("token key generation failed".into()))?;
                let ciphertext = self.encrypt_bytes(&fresh)?;
                self.conn.execute(
                    "INSERT INTO cluster_secrets (id, value, created_at) VALUES (?1, ?2, ?3)",
                    params![TOKEN_HMAC_KEY_ID, ciphertext, Utc::now().to_rfc3339()],
                )?;
                fresh.to_vec()
            }
        };
        let key: [u8; TOKEN_HMAC_KEY_LEN] = raw.try_into().map_err(|_| {
            ConfigError::Validation("stored token key has the wrong length".into())
        })?;
        Ok(key)
    }
}
