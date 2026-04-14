//! Load test configuration and result persistence on `ConfigStore`.

use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{row_to_load_test_config, row_to_load_test_result};
use super::{new_id, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    // ---- Load Test Configuration ----

    /// Create a new load test configuration.
    pub fn create_load_test_config(&self, config: &LoadTestConfig) -> Result<()> {
        let headers_json = serde_json::to_string(&config.headers)
            .map_err(|e| ConfigError::Validation(format!("invalid headers: {e}")))?;
        self.conn.execute(
            "INSERT INTO load_test_configs (id, name, target_url, method, headers, body,
             concurrency, requests_per_second, duration_s, error_threshold_pct,
             schedule_cron, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                config.id,
                config.name,
                config.target_url,
                config.method,
                headers_json,
                config.body,
                config.concurrency,
                config.requests_per_second,
                config.duration_s,
                config.error_threshold_pct,
                config.schedule_cron,
                config.enabled,
                config.created_at.to_rfc3339(),
                config.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all load test configurations.
    pub fn list_load_test_configs(&self) -> Result<Vec<LoadTestConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, target_url, method, headers, body, concurrency,
             requests_per_second, duration_s, error_threshold_pct, schedule_cron,
             enabled, created_at, updated_at FROM load_test_configs ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_load_test_config)?;
        let mut configs = Vec::new();
        for row in rows {
            configs.push(row??);
        }
        Ok(configs)
    }

    /// Get a single load test configuration by ID.
    pub fn get_load_test_config(&self, id: &str) -> Result<Option<LoadTestConfig>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, name, target_url, method, headers, body, concurrency,
                 requests_per_second, duration_s, error_threshold_pct, schedule_cron,
                 enabled, created_at, updated_at FROM load_test_configs WHERE id = ?1",
                params![id],
                row_to_load_test_config,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Update a load test configuration.
    pub fn update_load_test_config(&self, config: &LoadTestConfig) -> Result<()> {
        let headers_json = serde_json::to_string(&config.headers)
            .map_err(|e| ConfigError::Validation(format!("invalid headers: {e}")))?;
        let affected = self.conn.execute(
            "UPDATE load_test_configs SET name = ?1, target_url = ?2, method = ?3,
             headers = ?4, body = ?5, concurrency = ?6, requests_per_second = ?7,
             duration_s = ?8, error_threshold_pct = ?9, schedule_cron = ?10,
             enabled = ?11, updated_at = ?12 WHERE id = ?13",
            params![
                config.name,
                config.target_url,
                config.method,
                headers_json,
                config.body,
                config.concurrency,
                config.requests_per_second,
                config.duration_s,
                config.error_threshold_pct,
                config.schedule_cron,
                config.enabled,
                config.updated_at.to_rfc3339(),
                config.id,
            ],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!(
                "load test config {}",
                config.id
            )));
        }
        Ok(())
    }

    /// Delete a load test configuration.
    pub fn delete_load_test_config(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM load_test_configs WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("load test config {id}")));
        }
        Ok(())
    }

    /// Clone a load test configuration with a new ID and name suffix.
    pub fn clone_load_test_config(
        &self,
        source_id: &str,
        new_name: &str,
    ) -> Result<LoadTestConfig> {
        let source = self
            .get_load_test_config(source_id)?
            .ok_or_else(|| ConfigError::NotFound(format!("load test config {source_id}")))?;
        let now = Utc::now();
        let cloned = LoadTestConfig {
            id: new_id(),
            name: new_name.to_string(),
            created_at: now,
            updated_at: now,
            schedule_cron: None,
            ..source
        };
        self.create_load_test_config(&cloned)?;
        Ok(cloned)
    }

    // ---- Load Test Results ----

    /// Insert a load test result.
    pub fn insert_load_test_result(&self, result: &LoadTestResult) -> Result<()> {
        self.conn.execute(
            "INSERT INTO load_test_results (id, config_id, started_at, finished_at,
             total_requests, successful_requests, failed_requests, avg_latency_ms,
             p50_latency_ms, p95_latency_ms, p99_latency_ms, min_latency_ms,
             max_latency_ms, throughput_rps, aborted, abort_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                result.id,
                result.config_id,
                result.started_at.to_rfc3339(),
                result.finished_at.to_rfc3339(),
                result.total_requests,
                result.successful_requests,
                result.failed_requests,
                result.avg_latency_ms,
                result.p50_latency_ms,
                result.p95_latency_ms,
                result.p99_latency_ms,
                result.min_latency_ms,
                result.max_latency_ms,
                result.throughput_rps,
                result.aborted,
                result.abort_reason,
            ],
        )?;
        Ok(())
    }

    /// List results for a load test config, most recent first.
    pub fn list_load_test_results(&self, config_id: &str) -> Result<Vec<LoadTestResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, config_id, started_at, finished_at, total_requests,
             successful_requests, failed_requests, avg_latency_ms, p50_latency_ms,
             p95_latency_ms, p99_latency_ms, min_latency_ms, max_latency_ms,
             throughput_rps, aborted, abort_reason
             FROM load_test_results WHERE config_id = ?1 ORDER BY started_at DESC",
        )?;
        let rows = stmt.query_map(params![config_id], row_to_load_test_result)?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    /// Get the most recent result for a load test config.
    pub fn get_latest_load_test_result(&self, config_id: &str) -> Result<Option<LoadTestResult>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, config_id, started_at, finished_at, total_requests,
                 successful_requests, failed_requests, avg_latency_ms, p50_latency_ms,
                 p95_latency_ms, p99_latency_ms, min_latency_ms, max_latency_ms,
                 throughput_rps, aborted, abort_reason
                 FROM load_test_results WHERE config_id = ?1
                 ORDER BY started_at DESC LIMIT 1",
                params![config_id],
                row_to_load_test_result,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }
}
