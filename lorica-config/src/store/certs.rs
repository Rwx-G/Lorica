//! Certificate CRUD methods on `ConfigStore`.
//!
//! Certificate private keys (`key_pem`) are encrypted at rest using the
//! encryption helpers in `super` when an encryption key is configured.

use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Insert a new certificate. The `key_pem` field is encrypted at rest if an encryption key is configured.
    pub fn create_certificate(&self, cert: &Certificate) -> Result<()> {
        let san_json = serde_json::to_string(&cert.san_domains)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_key = self.encrypt_key_pem(&cert.key_pem)?;
        self.conn.execute(
            "INSERT INTO certificates (id, domain, san_domains, fingerprint, cert_pem, key_pem,
             issuer, not_before, not_after, is_acme, acme_auto_renew, created_at,
             acme_method, acme_dns_provider_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                cert.id,
                cert.domain,
                san_json,
                cert.fingerprint,
                cert.cert_pem,
                encrypted_key,
                cert.issuer,
                cert.not_before.to_rfc3339(),
                cert.not_after.to_rfc3339(),
                cert.is_acme,
                cert.acme_auto_renew,
                cert.created_at.to_rfc3339(),
                cert.acme_method,
                cert.acme_dns_provider_id,
            ],
        )?;
        Ok(())
    }

    /// Fetch a certificate by ID, or `None` if not found. Decrypts `key_pem` transparently.
    pub fn get_certificate(&self, id: &str) -> Result<Option<Certificate>> {
        self.conn
            .query_row(
                "SELECT id, domain, san_domains, fingerprint, cert_pem, key_pem,
                 issuer, not_before, not_after, is_acme, acme_auto_renew, created_at,
                 acme_method, acme_dns_provider_id
                 FROM certificates WHERE id = ?1",
                params![id],
                |row| Ok(self.row_to_certificate(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all certificates, ordered by domain. Decrypts `key_pem` transparently.
    pub fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, domain, san_domains, fingerprint, cert_pem, key_pem,
             issuer, not_before, not_after, is_acme, acme_auto_renew, created_at,
             acme_method, acme_dns_provider_id
             FROM certificates ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| Ok(self.row_to_certificate(row)))?;
        let mut certs = Vec::new();
        for r in rows {
            certs.push(r??);
        }
        Ok(certs)
    }

    /// Update an existing certificate. Re-encrypts `key_pem` at rest.
    pub fn update_certificate(&self, cert: &Certificate) -> Result<()> {
        let san_json = serde_json::to_string(&cert.san_domains)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_key = self.encrypt_key_pem(&cert.key_pem)?;
        let changed = self.conn.execute(
            "UPDATE certificates SET domain=?2, san_domains=?3, fingerprint=?4,
             cert_pem=?5, key_pem=?6, issuer=?7, not_before=?8, not_after=?9,
             is_acme=?10, acme_auto_renew=?11, acme_method=?12,
             acme_dns_provider_id=?13
             WHERE id=?1",
            params![
                cert.id,
                cert.domain,
                san_json,
                cert.fingerprint,
                cert.cert_pem,
                encrypted_key,
                cert.issuer,
                cert.not_before.to_rfc3339(),
                cert.not_after.to_rfc3339(),
                cert.is_acme,
                cert.acme_auto_renew,
                cert.acme_method,
                cert.acme_dns_provider_id,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("certificate {}", cert.id)));
        }
        Ok(())
    }

    /// Reassign all routes referencing `old_cert_id` to `new_cert_id`.
    /// Returns the number of routes updated.
    ///
    /// The `updated_at` timestamp is produced from Rust as an RFC3339
    /// string rather than delegating to SQLite's `datetime('now')`:
    /// SQLite would write the SQL-plain format `2026-04-17 19:13:17`
    /// which is NOT RFC3339 (no `T` separator, no timezone), and the
    /// next config reload would fail to deserialise the row, crash-
    /// looping every worker. Seen in the wild during an ACME renewal
    /// on 2026-04-17 - see `docs/backlog.md` entry #7.
    pub fn reassign_certificate(&self, old_cert_id: &str, new_cert_id: &str) -> Result<usize> {
        let now_rfc3339 = Utc::now().to_rfc3339();
        let updated = self.conn.execute(
            "UPDATE routes SET certificate_id = ?1, updated_at = ?2 WHERE certificate_id = ?3",
            params![new_cert_id, now_rfc3339, old_cert_id],
        )?;
        Ok(updated)
    }

    /// Delete a certificate by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_certificate(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM certificates WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("certificate {id}")));
        }
        Ok(())
    }

    /// Convert a certificate row into a `Certificate`, decrypting `key_pem`.
    /// This depends on `self` for access to the encryption helpers, so it
    /// stays as a method rather than a free function in `row_helpers`.
    pub(super) fn row_to_certificate(&self, row: &rusqlite::Row<'_>) -> Result<Certificate> {
        let san_json: String = row.get(2)?;
        let san_domains: Vec<String> = serde_json::from_str(&san_json)
            .map_err(|e| ConfigError::Validation(format!("invalid san_domains JSON: {e}")))?;
        let key_pem_raw: Vec<u8> = row.get(5)?;
        let key_pem = self.decrypt_key_pem(&key_pem_raw)?;
        let acme_method: Option<String> = row.get(12)?;
        let acme_dns_provider_id: Option<String> = row.get(13)?;
        Ok(Certificate {
            id: row.get(0)?,
            domain: row.get(1)?,
            san_domains,
            fingerprint: row.get(3)?,
            cert_pem: row.get(4)?,
            key_pem,
            issuer: row.get(6)?,
            not_before: parse_datetime(&row.get::<_, String>(7)?)?,
            not_after: parse_datetime(&row.get::<_, String>(8)?)?,
            is_acme: row.get(9)?,
            acme_auto_renew: row.get(10)?,
            created_at: parse_datetime(&row.get::<_, String>(11)?)?,
            acme_method,
            acme_dns_provider_id,
        })
    }
}
