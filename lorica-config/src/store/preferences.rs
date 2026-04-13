//! User preference CRUD methods on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_user_preference;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Insert a new user preference.
    pub fn create_user_preference(&self, pref: &UserPreference) -> Result<()> {
        self.conn.execute(
            "INSERT INTO user_preferences (id, preference_key, value, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pref.id,
                pref.preference_key,
                pref.value.as_str(),
                pref.created_at.to_rfc3339(),
                pref.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a user preference by ID, or `None` if not found.
    pub fn get_user_preference(&self, id: &str) -> Result<Option<UserPreference>> {
        self.conn
            .query_row(
                "SELECT id, preference_key, value, created_at, updated_at
                 FROM user_preferences WHERE id = ?1",
                params![id],
                |row| Ok(row_to_user_preference(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch a user preference by its unique key, or `None` if not found.
    pub fn get_user_preference_by_key(&self, key: &str) -> Result<Option<UserPreference>> {
        self.conn
            .query_row(
                "SELECT id, preference_key, value, created_at, updated_at
                 FROM user_preferences WHERE preference_key = ?1",
                params![key],
                |row| Ok(row_to_user_preference(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all user preferences, ordered by key.
    pub fn list_user_preferences(&self) -> Result<Vec<UserPreference>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, preference_key, value, created_at, updated_at
             FROM user_preferences ORDER BY preference_key",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_user_preference(row)))?;
        let mut prefs = Vec::new();
        for r in rows {
            prefs.push(r??);
        }
        Ok(prefs)
    }

    /// Update an existing user preference. Returns `NotFound` if the ID does not exist.
    pub fn update_user_preference(&self, pref: &UserPreference) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE user_preferences SET preference_key=?2, value=?3, updated_at=?4
             WHERE id=?1",
            params![
                pref.id,
                pref.preference_key,
                pref.value.as_str(),
                pref.updated_at.to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "user_preference {}",
                pref.id
            )));
        }
        Ok(())
    }

    /// Delete a user preference by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_user_preference(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM user_preferences WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("user_preference {id}")));
        }
        Ok(())
    }
}
