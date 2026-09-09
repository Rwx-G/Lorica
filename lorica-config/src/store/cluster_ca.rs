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

//! Cluster CA persistence on `ConfigStore` (Story 9.2 AC #8).
//!
//! Two rows in `cluster_ca`: the CA itself (`id = 'ca'`) and the
//! control plane's own leaf keypair (`id = 'control-plane-leaf'`).
//! Private keys are encrypted at rest via the same AES-256-GCM
//! helpers as certificate leaf keys, and the column is registered in
//! `ENCRYPTED_COLUMNS`, so key rotation covers the fleet identity root
//! from day one.
//!
//! The control-plane leaf KEYPAIR is persisted (its certificate is
//! re-issued at every boot with a short validity) because Story 9.3
//! pins the leaf's SPKI digest inside join tokens: a keypair minted
//! per boot would invalidate every outstanding token on restart.

use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use super::ConfigStore;
use crate::error::Result;

/// The fixed primary key of the single cluster CA row.
const CA_ROW_ID: &str = "ca";

/// The fixed primary key of the control-plane leaf keypair row.
const CONTROL_PLANE_LEAF_ROW_ID: &str = "control-plane-leaf";

impl ConfigStore {
    /// Persist (or replace) the control plane's leaf keypair. The
    /// certificate is stored for reference only; boot re-issues it
    /// from the stable key.
    pub fn set_control_plane_leaf(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let encrypted_key = self.encrypt_key_pem(key_pem)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO cluster_ca (id, cert_pem, key_pem, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                CONTROL_PLANE_LEAF_ROW_ID,
                cert_pem,
                encrypted_key,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Load the control plane's leaf as `(cert_pem, key_pem)`,
    /// decrypting the key. `None` before the first control-plane boot.
    pub fn get_control_plane_leaf(&self) -> Result<Option<(String, String)>> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT cert_pem, key_pem FROM cluster_ca WHERE id = ?1",
                params![CONTROL_PLANE_LEAF_ROW_ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((cert_pem, stored_key)) => {
                let key_pem = self.decrypt_key_pem(&stored_key)?;
                Ok(Some((cert_pem, key_pem)))
            }
            None => Ok(None),
        }
    }

    /// Persist (or replace) the cluster CA. `key_pem` is encrypted at
    /// rest when an encryption key is configured.
    pub fn set_cluster_ca(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let encrypted_key = self.encrypt_key_pem(key_pem)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO cluster_ca (id, cert_pem, key_pem, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![CA_ROW_ID, cert_pem, encrypted_key, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Load the cluster CA as `(cert_pem, key_pem)`, decrypting the
    /// key. `None` when `lorica cluster init` has never run.
    pub fn get_cluster_ca(&self) -> Result<Option<(String, String)>> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT cert_pem, key_pem FROM cluster_ca WHERE id = ?1",
                params![CA_ROW_ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((cert_pem, stored_key)) => {
                let key_pem = self.decrypt_key_pem(&stored_key)?;
                Ok(Some((cert_pem, key_pem)))
            }
            None => Ok(None),
        }
    }
}
