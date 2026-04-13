//! SLA configuration and aggregated bucket persistence on `ConfigStore`.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{parse_datetime, row_to_sla_bucket};
use super::ConfigStore;
use crate::error::Result;
use crate::models::*;

impl ConfigStore {
    // ---- SLA Configuration ----

    /// Get SLA configuration for a route. Returns default if none configured.
    pub fn get_sla_config(&self, route_id: &str) -> Result<SlaConfig> {
        let result = self
            .conn
            .query_row(
                "SELECT route_id, target_pct, max_latency_ms, success_status_min,
                 success_status_max, created_at, updated_at
                 FROM sla_configs WHERE route_id = ?1",
                params![route_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                route_id,
                target_pct,
                max_latency_ms,
                min_status,
                max_status,
                created,
                updated,
            )) => Ok(SlaConfig {
                route_id,
                target_pct,
                max_latency_ms,
                success_status_min: min_status,
                success_status_max: max_status,
                created_at: parse_datetime(&created)?,
                updated_at: parse_datetime(&updated)?,
            }),
            None => Ok(SlaConfig::default_for_route(route_id)),
        }
    }

    /// Upsert SLA configuration for a route.
    pub fn upsert_sla_config(&self, config: &SlaConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sla_configs (route_id, target_pct, max_latency_ms,
             success_status_min, success_status_max, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(route_id) DO UPDATE SET
                target_pct = excluded.target_pct,
                max_latency_ms = excluded.max_latency_ms,
                success_status_min = excluded.success_status_min,
                success_status_max = excluded.success_status_max,
                updated_at = excluded.updated_at",
            params![
                config.route_id,
                config.target_pct,
                config.max_latency_ms,
                config.success_status_min,
                config.success_status_max,
                config.created_at.to_rfc3339(),
                config.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all SLA configurations.
    pub fn list_sla_configs(&self) -> Result<Vec<SlaConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT route_id, target_pct, max_latency_ms, success_status_min,
             success_status_max, created_at, updated_at FROM sla_configs",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, i32>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut configs = Vec::new();
        for row in rows {
            let (route_id, target_pct, max_latency_ms, min_s, max_s, created, updated) = row?;
            configs.push(SlaConfig {
                route_id,
                target_pct,
                max_latency_ms,
                success_status_min: min_s,
                success_status_max: max_s,
                created_at: parse_datetime(&created)?,
                updated_at: parse_datetime(&updated)?,
            });
        }
        Ok(configs)
    }

    // ---- SLA Buckets ----

    /// Insert an aggregated SLA bucket.
    pub fn insert_sla_bucket(&self, bucket: &SlaBucket) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sla_buckets
             (route_id, bucket_start, request_count, success_count, error_count,
              latency_sum_ms, latency_min_ms, latency_max_ms,
              latency_p50_ms, latency_p95_ms, latency_p99_ms, source,
              cfg_max_latency_ms, cfg_status_min, cfg_status_max, cfg_target_pct)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                bucket.route_id,
                bucket.bucket_start.to_rfc3339(),
                bucket.request_count,
                bucket.success_count,
                bucket.error_count,
                bucket.latency_sum_ms,
                bucket.latency_min_ms,
                bucket.latency_max_ms,
                bucket.latency_p50_ms,
                bucket.latency_p95_ms,
                bucket.latency_p99_ms,
                bucket.source,
                bucket.cfg_max_latency_ms,
                bucket.cfg_status_min,
                bucket.cfg_status_max,
                bucket.cfg_target_pct,
            ],
        )?;
        Ok(())
    }

    /// Query SLA buckets for a route within a time range.
    pub fn query_sla_buckets(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        source: &str,
    ) -> Result<Vec<SlaBucket>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, bucket_start, request_count, success_count, error_count,
             latency_sum_ms, latency_min_ms, latency_max_ms,
             latency_p50_ms, latency_p95_ms, latency_p99_ms, source,
             cfg_max_latency_ms, cfg_status_min, cfg_status_max, cfg_target_pct
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
             ORDER BY bucket_start ASC",
        )?;
        let rows = stmt.query_map(
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            row_to_sla_bucket,
        )?;
        let mut buckets = Vec::new();
        for row in rows {
            buckets.push(row??);
        }
        Ok(buckets)
    }

    /// Compute an SLA summary for a route over a time window.
    pub fn compute_sla_summary(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        window_label: &str,
        source: &str,
    ) -> Result<SlaSummary> {
        let row = self.conn.query_row(
            "SELECT COALESCE(SUM(request_count), 0),
                    COALESCE(SUM(success_count), 0),
                    COALESCE(SUM(latency_sum_ms), 0)
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4",
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        let (total, success, latency_sum) = row;

        // Weighted percentiles: pick the median bucket values weighted by request count
        let percentiles = self.conn.query_row(
            "SELECT COALESCE(MAX(latency_p50_ms), 0),
                    COALESCE(MAX(latency_p95_ms), 0),
                    COALESCE(MAX(latency_p99_ms), 0)
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4",
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;

        let sla_pct = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let avg_latency = if total > 0 {
            latency_sum as f64 / total as f64
        } else {
            0.0
        };

        // Use the snapshot target_pct from the most recent bucket in the window,
        // so historical queries reflect the config active at recording time.
        // Fall back to live config if no buckets exist yet.
        let snapshot_target: f64 = self
            .conn
            .query_row(
                "SELECT cfg_target_pct FROM sla_buckets
                 WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
                 ORDER BY bucket_start DESC LIMIT 1",
                params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| {
                self.get_sla_config(route_id)
                    .map(|c| c.target_pct)
                    .unwrap_or(99.9)
            });

        Ok(SlaSummary {
            route_id: route_id.to_string(),
            window: window_label.to_string(),
            total_requests: total,
            successful_requests: success,
            sla_pct,
            avg_latency_ms: avg_latency,
            p50_latency_ms: percentiles.0,
            p95_latency_ms: percentiles.1,
            p99_latency_ms: percentiles.2,
            target_pct: snapshot_target,
            meets_target: sla_pct >= snapshot_target,
        })
    }

    /// Delete SLA buckets older than a given timestamp (for data retention).
    pub fn prune_sla_buckets(&self, before: &DateTime<Utc>) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM sla_buckets WHERE bucket_start < ?1",
            params![before.to_rfc3339()],
        )?;
        Ok(count)
    }

    /// Delete all SLA buckets for a specific route.
    pub fn delete_sla_buckets_for_route(&self, route_id: &str) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM sla_buckets WHERE route_id = ?1",
            params![route_id],
        )?;
        Ok(count)
    }

    /// Export SLA data as JSON for a route over a time range.
    pub fn export_sla_data(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
    ) -> Result<serde_json::Value> {
        let buckets = self.query_sla_buckets(route_id, from, to, "passive")?;
        let config = self.get_sla_config(route_id)?;
        Ok(serde_json::json!({
            "route_id": route_id,
            "from": from.to_rfc3339(),
            "to": to.to_rfc3339(),
            "config": config,
            "buckets": buckets,
        }))
    }
}
