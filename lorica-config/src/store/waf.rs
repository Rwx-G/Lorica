//! WAF persistence helpers (disabled rule list and custom rules) on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::ConfigStore;
use crate::error::{ConfigError, Result};

impl ConfigStore {
    /// Save the list of disabled WAF rule IDs as a JSON array in global settings.
    pub fn save_waf_disabled_rules(&self, rule_ids: &[u32]) -> Result<()> {
        let json = serde_json::to_string(rule_ids).map_err(|e| {
            ConfigError::Validation(format!("failed to serialize disabled rules: {e}"))
        })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('waf_disabled_rules', ?1)",
            params![json],
        )?;
        Ok(())
    }

    /// Load the list of disabled WAF rule IDs from global settings.
    pub fn load_waf_disabled_rules(&self) -> Result<Vec<u32>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM global_settings WHERE key = 'waf_disabled_rules'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match json {
            Some(s) => serde_json::from_str(&s).map_err(|e| {
                ConfigError::Validation(format!("invalid waf_disabled_rules JSON: {e}"))
            }),
            None => Ok(Vec::new()),
        }
    }

    /// Save a WAF custom rule to the database.
    pub fn save_waf_custom_rule(
        &self,
        id: u32,
        description: &str,
        category: &str,
        pattern: &str,
        severity: u8,
        enabled: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO waf_custom_rules (id, description, category, pattern, severity, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, description, category, pattern, severity as i32, enabled],
        )?;
        Ok(())
    }

    /// Delete a WAF custom rule from the database.
    pub fn delete_waf_custom_rule(&self, id: u32) -> Result<()> {
        self.conn
            .execute("DELETE FROM waf_custom_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Load all WAF custom rules from the database.
    #[allow(clippy::type_complexity)]
    pub fn load_waf_custom_rules(&self) -> Result<Vec<(u32, String, String, String, u8, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, description, category, pattern, severity, enabled FROM waf_custom_rules ORDER BY id"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i32>(4)? as u8,
                row.get::<_, bool>(5)?,
            ))
        })?;
        let mut rules = Vec::new();
        for r in rows {
            rules.push(r?);
        }
        Ok(rules)
    }
}
