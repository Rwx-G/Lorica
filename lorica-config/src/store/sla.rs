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

    /// Merge one slice of a minute into its SLA bucket.
    ///
    /// A bucket is keyed by `(route_id, bucket_start, source)` and several
    /// writers reach the same key: in worker mode every forked worker flushes
    /// its own slice of the same minute into this one database, and an active
    /// probe writes the currently open minute once per probe. This used to be
    /// `INSERT OR REPLACE`, so the stored row was whichever writer wrote last:
    /// an N-worker node under-reported its request volume by roughly N, and an
    /// active bucket held a single probe instead of the minute (backlog #68).
    ///
    /// The counters and the latency sum add up, the minimum and the maximum
    /// take the extreme of the two slices, and the configuration snapshot
    /// follows the newest writer. **The three percentiles take the maximum**:
    /// a percentile cannot be recomputed from per-slice percentiles without
    /// the samples behind them, and a tail figure that can be averaged away by
    /// a quiet worker is worse than one that reads slightly high. That is also
    /// what [`Self::compute_sla_summary`] already does when it collapses a
    /// window of buckets.
    pub fn merge_sla_bucket(&self, bucket: &SlaBucket) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sla_buckets
             (route_id, bucket_start, request_count, success_count, error_count,
              latency_sum_ms, latency_min_ms, latency_max_ms,
              latency_p50_ms, latency_p95_ms, latency_p99_ms, source,
              cfg_max_latency_ms, cfg_status_min, cfg_status_max, cfg_target_pct)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(route_id, bucket_start, source) DO UPDATE SET
              request_count  = sla_buckets.request_count  + excluded.request_count,
              success_count  = sla_buckets.success_count  + excluded.success_count,
              error_count    = sla_buckets.error_count    + excluded.error_count,
              latency_sum_ms = sla_buckets.latency_sum_ms + excluded.latency_sum_ms,
              latency_min_ms = MIN(sla_buckets.latency_min_ms, excluded.latency_min_ms),
              latency_max_ms = MAX(sla_buckets.latency_max_ms, excluded.latency_max_ms),
              latency_p50_ms = MAX(sla_buckets.latency_p50_ms, excluded.latency_p50_ms),
              latency_p95_ms = MAX(sla_buckets.latency_p95_ms, excluded.latency_p95_ms),
              latency_p99_ms = MAX(sla_buckets.latency_p99_ms, excluded.latency_p99_ms),
              cfg_max_latency_ms = excluded.cfg_max_latency_ms,
              cfg_status_min     = excluded.cfg_status_min,
              cfg_status_max     = excluded.cfg_status_max,
              cfg_target_pct     = excluded.cfg_target_pct",
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

    /// Delete route and stream SLA buckets older than a given timestamp
    /// (for data retention). One pass for both tables, so the
    /// `sla_purge_*` settings govern stream history too (Story 12.9).
    /// Returns the rows removed from both.
    pub fn prune_sla_buckets(&self, before: &DateTime<Utc>) -> Result<usize> {
        let cutoff = before.to_rfc3339();
        let routes = self.conn.execute(
            "DELETE FROM sla_buckets WHERE bucket_start < ?1",
            params![cutoff],
        )?;
        let streams = self.conn.execute(
            "DELETE FROM stream_sla_buckets WHERE bucket_start < ?1",
            params![cutoff],
        )?;
        Ok(routes + streams)
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

    // ---- Stream SLA Configuration (Story 12.9) ----

    /// Get the SLA target of a stream. Returns the default when none is
    /// configured.
    pub fn get_stream_sla_config(&self, stream_id: &str) -> Result<StreamSlaConfig> {
        let row = self
            .conn
            .query_row(
                &format!("SELECT {STREAM_SLA_CONFIG_COLUMNS} FROM stream_sla_configs WHERE stream_id = ?1"),
                params![stream_id],
                row_to_stream_sla_config,
            )
            .optional()?;
        match row {
            Some(config) => config,
            None => Ok(StreamSlaConfig::default_for_stream(stream_id)),
        }
    }

    /// Upsert the SLA target of a stream. On conflict the stored
    /// `created_at` is kept. A stream the store does not hold is refused
    /// by the foreign key.
    pub fn upsert_stream_sla_config(&self, config: &StreamSlaConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO stream_sla_configs (stream_id, target_pct, max_connect_latency_ms,
             created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(stream_id) DO UPDATE SET
                target_pct = excluded.target_pct,
                max_connect_latency_ms = excluded.max_connect_latency_ms,
                updated_at = excluded.updated_at",
            params![
                config.stream_id,
                config.target_pct,
                config.max_connect_latency_ms,
                config.created_at.to_rfc3339(),
                config.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List every stored stream SLA target, by stream id.
    pub fn list_stream_sla_configs(&self) -> Result<Vec<StreamSlaConfig>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {STREAM_SLA_CONFIG_COLUMNS} FROM stream_sla_configs ORDER BY stream_id"
        ))?;
        let rows = stmt.query_map([], row_to_stream_sla_config)?;
        let mut configs = Vec::new();
        for row in rows {
            configs.push(row??);
        }
        Ok(configs)
    }

    // ---- Stream SLA Buckets (Story 12.9) ----

    /// The ids of the streams holding at least one SLA bucket of
    /// `source`. The bucket table has no foreign key, so an id here may
    /// name a stream the store no longer holds.
    pub fn list_stream_ids_with_sla_buckets(
        &self,
        source: &str,
    ) -> Result<std::collections::BTreeSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT stream_id FROM stream_sla_buckets WHERE source = ?1")?;
        let rows = stmt.query_map(params![source], |row| row.get::<_, String>(0))?;
        let mut ids = std::collections::BTreeSet::new();
        for row in rows {
            ids.insert(row?);
        }
        Ok(ids)
    }

    /// Merge one slice of a minute into its stream SLA bucket, keyed by
    /// `(stream_id, bucket_start, source)`, on the rules
    /// [`Self::merge_sla_bucket`] gives for routes: the counters and the
    /// latency sum add up, the minimum and the maximum take the extreme
    /// of the two slices, the percentiles take the maximum, and the
    /// configuration snapshot follows the newest writer.
    ///
    /// The latency columns are NULL where nothing connected, and a NULL
    /// is "no sample", never 0: a slice with no sample leaves the
    /// other's value as it is. SQLite's scalar `MIN` and `MAX` answer
    /// NULL when either argument is NULL, hence the `COALESCE` around
    /// each.
    pub fn merge_stream_sla_bucket(&self, bucket: &StreamSlaBucket) -> Result<()> {
        self.conn.execute(
            "INSERT INTO stream_sla_buckets
             (stream_id, bucket_start, source, judged_count, success_count, failure_count,
              connected_count, connect_latency_sum_ms, connect_latency_min_ms,
              connect_latency_max_ms, connect_latency_p50_ms, connect_latency_p95_ms,
              connect_latency_p99_ms, cfg_target_pct, cfg_max_connect_latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(stream_id, bucket_start, source) DO UPDATE SET
              judged_count    = stream_sla_buckets.judged_count    + excluded.judged_count,
              success_count   = stream_sla_buckets.success_count   + excluded.success_count,
              failure_count   = stream_sla_buckets.failure_count   + excluded.failure_count,
              connected_count = stream_sla_buckets.connected_count + excluded.connected_count,
              connect_latency_sum_ms = COALESCE(
                  stream_sla_buckets.connect_latency_sum_ms + excluded.connect_latency_sum_ms,
                  stream_sla_buckets.connect_latency_sum_ms, excluded.connect_latency_sum_ms),
              connect_latency_min_ms = COALESCE(
                  MIN(stream_sla_buckets.connect_latency_min_ms, excluded.connect_latency_min_ms),
                  stream_sla_buckets.connect_latency_min_ms, excluded.connect_latency_min_ms),
              connect_latency_max_ms = COALESCE(
                  MAX(stream_sla_buckets.connect_latency_max_ms, excluded.connect_latency_max_ms),
                  stream_sla_buckets.connect_latency_max_ms, excluded.connect_latency_max_ms),
              connect_latency_p50_ms = COALESCE(
                  MAX(stream_sla_buckets.connect_latency_p50_ms, excluded.connect_latency_p50_ms),
                  stream_sla_buckets.connect_latency_p50_ms, excluded.connect_latency_p50_ms),
              connect_latency_p95_ms = COALESCE(
                  MAX(stream_sla_buckets.connect_latency_p95_ms, excluded.connect_latency_p95_ms),
                  stream_sla_buckets.connect_latency_p95_ms, excluded.connect_latency_p95_ms),
              connect_latency_p99_ms = COALESCE(
                  MAX(stream_sla_buckets.connect_latency_p99_ms, excluded.connect_latency_p99_ms),
                  stream_sla_buckets.connect_latency_p99_ms, excluded.connect_latency_p99_ms),
              cfg_target_pct             = excluded.cfg_target_pct,
              cfg_max_connect_latency_ms = excluded.cfg_max_connect_latency_ms",
            params![
                bucket.stream_id,
                bucket.bucket_start.to_rfc3339(),
                bucket.source,
                bucket.judged_count,
                bucket.success_count,
                bucket.failure_count,
                bucket.connected_count,
                bucket.connect_latency_sum_ms,
                bucket.connect_latency_min_ms,
                bucket.connect_latency_max_ms,
                bucket.connect_latency_p50_ms,
                bucket.connect_latency_p95_ms,
                bucket.connect_latency_p99_ms,
                bucket.cfg_target_pct,
                bucket.cfg_max_connect_latency_ms,
            ],
        )?;
        Ok(())
    }

    /// Query the SLA buckets of a stream within `[from, to)`, oldest
    /// first.
    pub fn query_stream_sla_buckets(
        &self,
        stream_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        source: &str,
    ) -> Result<Vec<StreamSlaBucket>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {STREAM_SLA_BUCKET_COLUMNS} FROM stream_sla_buckets
             WHERE stream_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
             ORDER BY bucket_start ASC"
        ))?;
        let rows = stmt.query_map(
            params![stream_id, from.to_rfc3339(), to.to_rfc3339(), source],
            row_to_stream_sla_bucket,
        )?;
        let mut buckets = Vec::new();
        for row in rows {
            buckets.push(row??);
        }
        Ok(buckets)
    }

    /// Compute the SLA summary of a stream over `[from, to)`.
    ///
    /// The mean connect latency divides by the connections that
    /// connected, not by the judged ones; the percentiles are the
    /// highest of the window's buckets, as for routes.
    pub fn compute_stream_sla_summary(
        &self,
        stream_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        window_label: &str,
        source: &str,
    ) -> Result<StreamSlaSummary> {
        let (from, to) = (from.to_rfc3339(), to.to_rfc3339());
        let window = params![stream_id, from, to, source];
        let (judged, success, failure, connected, latency_sum, p50, p95, p99) =
            self.conn.query_row(
                "SELECT COALESCE(SUM(judged_count), 0),
                        COALESCE(SUM(success_count), 0),
                        COALESCE(SUM(failure_count), 0),
                        COALESCE(SUM(connected_count), 0),
                        SUM(connect_latency_sum_ms),
                        MAX(connect_latency_p50_ms),
                        MAX(connect_latency_p95_ms),
                        MAX(connect_latency_p99_ms)
                 FROM stream_sla_buckets
                 WHERE stream_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4",
                window,
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                },
            )?;

        let snapshot_target: Option<f64> = self
            .conn
            .query_row(
                "SELECT cfg_target_pct FROM stream_sla_buckets
                 WHERE stream_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
                 ORDER BY bucket_start DESC LIMIT 1",
                window,
                |row| row.get(0),
            )
            .optional()?;
        let target_pct = match snapshot_target {
            Some(target) => target,
            None => self.get_stream_sla_config(stream_id)?.target_pct,
        };

        let sla_pct = if judged > 0 {
            (success as f64 / judged as f64) * 100.0
        } else {
            0.0
        };
        let avg_connect_latency_ms = match latency_sum {
            Some(sum) if connected > 0 => Some(sum as f64 / connected as f64),
            _ => None,
        };
        Ok(StreamSlaSummary {
            stream_id: stream_id.to_string(),
            window: window_label.to_string(),
            judged_count: judged,
            success_count: success,
            failure_count: failure,
            sla_pct,
            avg_connect_latency_ms,
            p50_connect_latency_ms: p50,
            p95_connect_latency_ms: p95,
            p99_connect_latency_ms: p99,
            target_pct,
            meets_target: sla_pct >= target_pct,
        })
    }

    /// Delete every SLA bucket of a stream.
    pub fn delete_stream_sla_buckets(&self, stream_id: &str) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM stream_sla_buckets WHERE stream_id = ?1",
            params![stream_id],
        )?;
        Ok(count)
    }

    /// Export the passive SLA data of a stream over `[from, to)` as JSON,
    /// in the shape [`Self::export_sla_data`] gives a route.
    pub fn export_stream_sla_data(
        &self,
        stream_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
    ) -> Result<serde_json::Value> {
        let buckets = self.query_stream_sla_buckets(stream_id, from, to, "passive")?;
        let config = self.get_stream_sla_config(stream_id)?;
        Ok(serde_json::json!({
            "stream_id": stream_id,
            "from": from.to_rfc3339(),
            "to": to.to_rfc3339(),
            "config": config,
            "buckets": buckets,
        }))
    }
}

/// The `stream_sla_configs` columns, in the order
/// [`row_to_stream_sla_config`] reads them.
const STREAM_SLA_CONFIG_COLUMNS: &str =
    "stream_id, target_pct, max_connect_latency_ms, created_at, updated_at";

/// The `stream_sla_buckets` columns, in the order
/// [`row_to_stream_sla_bucket`] reads them.
const STREAM_SLA_BUCKET_COLUMNS: &str = "id, stream_id, bucket_start, source, judged_count, \
     success_count, failure_count, connected_count, connect_latency_sum_ms, \
     connect_latency_min_ms, connect_latency_max_ms, connect_latency_p50_ms, \
     connect_latency_p95_ms, connect_latency_p99_ms, cfg_target_pct, cfg_max_connect_latency_ms";

fn row_to_stream_sla_config(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<StreamSlaConfig>> {
    let created: String = row.get(3)?;
    let updated: String = row.get(4)?;
    let stream_id: String = row.get(0)?;
    let target_pct: f64 = row.get(1)?;
    let max_connect_latency_ms: i64 = row.get(2)?;
    Ok(parse_datetime(&created).and_then(|created_at| {
        Ok(StreamSlaConfig {
            stream_id,
            target_pct,
            max_connect_latency_ms,
            created_at,
            updated_at: parse_datetime(&updated)?,
        })
    }))
}

fn row_to_stream_sla_bucket(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<StreamSlaBucket>> {
    let bucket_start = match parse_datetime(&row.get::<_, String>(2)?) {
        Ok(at) => at,
        Err(e) => return Ok(Err(e)),
    };
    Ok(Ok(StreamSlaBucket {
        id: row.get(0)?,
        stream_id: row.get(1)?,
        bucket_start,
        source: row.get(3)?,
        judged_count: row.get(4)?,
        success_count: row.get(5)?,
        failure_count: row.get(6)?,
        connected_count: row.get(7)?,
        connect_latency_sum_ms: row.get(8)?,
        connect_latency_min_ms: row.get(9)?,
        connect_latency_max_ms: row.get(10)?,
        connect_latency_p50_ms: row.get(11)?,
        connect_latency_p95_ms: row.get(12)?,
        connect_latency_p99_ms: row.get(13)?,
        cfg_target_pct: row.get(14)?,
        cfg_max_connect_latency_ms: row.get(15)?,
    }))
}
