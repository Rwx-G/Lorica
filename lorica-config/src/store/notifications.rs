//! Notification configuration CRUD methods on `ConfigStore`.
//!
//! The `config` field is encrypted at rest via the shared helpers in
//! `super` when an encryption key is configured.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_notification_config;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Insert a new notification configuration.
    pub fn create_notification_config(&self, nc: &NotificationConfig) -> Result<()> {
        let alert_json = serde_json::to_string(&nc.alert_types)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_config = self.encrypt_config(&nc.config)?;
        self.conn.execute(
            "INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nc.id,
                nc.channel.as_str(),
                nc.enabled,
                encrypted_config,
                alert_json,
            ],
        )?;
        Ok(())
    }

    /// Fetch a notification config by ID, or `None` if not found.
    pub fn get_notification_config(&self, id: &str) -> Result<Option<NotificationConfig>> {
        let nc = self
            .conn
            .query_row(
                "SELECT id, channel, enabled, config, alert_types
                 FROM notification_configs WHERE id = ?1",
                params![id],
                |row| Ok(row_to_notification_config(row)),
            )
            .optional()?
            .transpose()?;
        match nc {
            Some(mut nc) => {
                nc.config = self.decrypt_config(&nc.config)?;
                Ok(Some(nc))
            }
            None => Ok(None),
        }
    }

    /// List all notification configs, ordered by channel.
    pub fn list_notification_configs(&self) -> Result<Vec<NotificationConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, enabled, config, alert_types
             FROM notification_configs ORDER BY channel",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_notification_config(row)))?;
        let mut configs = Vec::new();
        for r in rows {
            let mut nc = r??;
            nc.config = self.decrypt_config(&nc.config)?;
            configs.push(nc);
        }
        Ok(configs)
    }

    /// Update an existing notification config. Returns `NotFound` if the ID does not exist.
    pub fn update_notification_config(&self, nc: &NotificationConfig) -> Result<()> {
        let alert_json = serde_json::to_string(&nc.alert_types)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_config = self.encrypt_config(&nc.config)?;
        let changed = self.conn.execute(
            "UPDATE notification_configs SET channel=?2, enabled=?3, config=?4, alert_types=?5
             WHERE id=?1",
            params![
                nc.id,
                nc.channel.as_str(),
                nc.enabled,
                encrypted_config,
                alert_json
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "notification_config {}",
                nc.id
            )));
        }
        Ok(())
    }

    /// Delete a notification config by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_notification_config(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM notification_configs WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("notification_config {id}")));
        }
        Ok(())
    }
}
