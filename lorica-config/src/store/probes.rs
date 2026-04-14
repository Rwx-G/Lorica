//! Probe configuration and result persistence on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_probe_config;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    // ---- Probe Configuration ----

    /// Create a new probe configuration.
    pub fn create_probe_config(&self, probe: &ProbeConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO probe_configs (id, route_id, method, path, expected_status,
             interval_s, timeout_ms, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                probe.id,
                probe.route_id,
                probe.method,
                probe.path,
                probe.expected_status,
                probe.interval_s,
                probe.timeout_ms,
                probe.enabled,
                probe.created_at.to_rfc3339(),
                probe.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all probe configurations.
    pub fn list_probe_configs(&self) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at FROM probe_configs",
        )?;
        let rows = stmt.query_map([], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    /// List probe configurations for a specific route.
    pub fn list_probes_for_route(&self, route_id: &str) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at
             FROM probe_configs WHERE route_id = ?1",
        )?;
        let rows = stmt.query_map(params![route_id], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    /// Get a single probe configuration by ID.
    pub fn get_probe_config(&self, id: &str) -> Result<Option<ProbeConfig>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, route_id, method, path, expected_status, interval_s,
                 timeout_ms, enabled, created_at, updated_at
                 FROM probe_configs WHERE id = ?1",
                params![id],
                row_to_probe_config,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Update a probe configuration.
    pub fn update_probe_config(&self, probe: &ProbeConfig) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE probe_configs SET method = ?1, path = ?2, expected_status = ?3,
             interval_s = ?4, timeout_ms = ?5, enabled = ?6, updated_at = ?7
             WHERE id = ?8",
            params![
                probe.method,
                probe.path,
                probe.expected_status,
                probe.interval_s,
                probe.timeout_ms,
                probe.enabled,
                probe.updated_at.to_rfc3339(),
                probe.id,
            ],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("probe config {}", probe.id)));
        }
        Ok(())
    }

    /// Delete a probe configuration.
    pub fn delete_probe_config(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM probe_configs WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("probe config {id}")));
        }
        Ok(())
    }

    /// List all enabled probes (for the scheduler).
    pub fn list_enabled_probes(&self) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at
             FROM probe_configs WHERE enabled = 1",
        )?;
        let rows = stmt.query_map([], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    // ---- Probe Results ----

    /// Insert a probe execution result.
    pub fn insert_probe_result(
        &self,
        probe_id: &str,
        route_id: &str,
        status_code: u16,
        latency_ms: u64,
        success: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO probe_results (probe_id, route_id, status_code, latency_ms, success, error, executed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![probe_id, route_id, status_code as i64, latency_ms as i64, success, error, now],
        )?;
        Ok(())
    }

    /// Query probe execution history for a specific probe, newest first.
    pub fn list_probe_results(&self, probe_id: &str, limit: usize) -> Result<Vec<ProbeResultRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, probe_id, route_id, status_code, latency_ms, success, error, executed_at
             FROM probe_results WHERE probe_id = ?1
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![probe_id, limit as i64], |row| {
            Ok(ProbeResultRow {
                id: row.get(0)?,
                probe_id: row.get(1)?,
                route_id: row.get(2)?,
                status_code: row.get::<_, i64>(3)? as u16,
                latency_ms: row.get::<_, i64>(4)? as u64,
                success: row.get(5)?,
                error: row.get(6)?,
                executed_at: row.get(7)?,
            })
        })?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    /// Purge old probe results, keeping at most `max_per_probe` entries per probe.
    pub fn purge_probe_results(&self, max_per_probe: u64) -> Result<u64> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT probe_id FROM probe_results")?;
        let probe_ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        let mut total_deleted = 0u64;
        for pid in &probe_ids {
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM probe_results WHERE probe_id = ?1",
                params![pid],
                |row| row.get(0),
            )?;
            if count > max_per_probe as i64 {
                let to_delete = count - max_per_probe as i64;
                self.conn.execute(
                    "DELETE FROM probe_results WHERE probe_id = ?1 AND id IN (
                        SELECT id FROM probe_results WHERE probe_id = ?1 ORDER BY id ASC LIMIT ?2
                    )",
                    params![pid, to_delete],
                )?;
                total_deleted += to_delete as u64;
            }
        }
        Ok(total_deleted)
    }
}
