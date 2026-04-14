//! DNS provider CRUD methods on `ConfigStore`.
//!
//! The `config` column contains provider-specific credentials and is
//! encrypted at rest via the shared helpers in `super`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Insert a new DNS provider. The `config` field is encrypted at rest.
    pub fn create_dns_provider(&self, provider: &DnsProvider) -> Result<()> {
        let encrypted_config = self.encrypt_config(&provider.config)?;
        self.conn.execute(
            "INSERT INTO dns_providers (id, name, provider_type, config, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                provider.id,
                provider.name,
                provider.provider_type,
                encrypted_config,
                provider.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a DNS provider by ID, or `None` if not found. Decrypts `config` transparently.
    pub fn get_dns_provider(&self, id: &str) -> Result<Option<DnsProvider>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, name, provider_type, config, created_at
                 FROM dns_providers WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        match result {
            Some((id, name, provider_type, encrypted_config, created_at)) => {
                let config = self.decrypt_config(&encrypted_config)?;
                Ok(Some(DnsProvider {
                    id,
                    name,
                    provider_type,
                    config,
                    created_at: parse_datetime(&created_at)?,
                }))
            }
            None => Ok(None),
        }
    }

    /// List all DNS providers, ordered by name. Decrypts `config` transparently.
    pub fn list_dns_providers(&self) -> Result<Vec<DnsProvider>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, provider_type, config, created_at
             FROM dns_providers ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut providers = Vec::new();
        for r in rows {
            let (id, name, provider_type, encrypted_config, created_at) = r?;
            let config = self.decrypt_config(&encrypted_config)?;
            providers.push(DnsProvider {
                id,
                name,
                provider_type,
                config,
                created_at: parse_datetime(&created_at)?,
            });
        }
        Ok(providers)
    }

    /// Update an existing DNS provider. Re-encrypts `config` at rest.
    pub fn update_dns_provider(&self, provider: &DnsProvider) -> Result<()> {
        let encrypted_config = self.encrypt_config(&provider.config)?;
        let changed = self.conn.execute(
            "UPDATE dns_providers SET name=?2, provider_type=?3, config=?4
             WHERE id=?1",
            params![
                provider.id,
                provider.name,
                provider.provider_type,
                encrypted_config,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "dns_provider {}",
                provider.id
            )));
        }
        Ok(())
    }

    /// Delete a DNS provider by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_dns_provider(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM dns_providers WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("dns_provider {id}")));
        }
        Ok(())
    }

    /// Check if any certificates reference the given DNS provider.
    pub fn dns_provider_in_use(&self, provider_id: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM certificates WHERE acme_dns_provider_id = ?1",
            params![provider_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}
