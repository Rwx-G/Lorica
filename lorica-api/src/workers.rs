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

//! Worker process metrics for the management API.

use std::collections::HashMap;
use std::time::Instant;

use axum::extract::Extension;
use axum::Json;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// Per-worker health metrics, updated by the supervisor heartbeat loop.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerStatus {
    pub worker_id: u32,
    pub pid: i32,
    pub last_heartbeat_ms: u64,
    pub last_heartbeat_ago_s: u64,
    pub healthy: bool,
}

/// Thread-safe store for worker metrics.
#[derive(Debug)]
pub struct WorkerMetrics {
    inner: RwLock<HashMap<u32, WorkerMetricEntry>>,
}

#[derive(Debug, Clone)]
struct WorkerMetricEntry {
    pid: i32,
    last_heartbeat_latency_ms: u64,
    last_heartbeat_at: Instant,
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerMetrics {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Record a heartbeat response from a worker.
    pub async fn record_heartbeat(&self, worker_id: u32, pid: i32, latency_ms: u64) {
        let mut map = self.inner.write().await;
        map.insert(
            worker_id,
            WorkerMetricEntry {
                pid,
                last_heartbeat_latency_ms: latency_ms,
                last_heartbeat_at: Instant::now(),
            },
        );
    }

    /// Remove a worker (e.g. on crash before restart).
    pub async fn remove_worker(&self, worker_id: u32) {
        self.inner.write().await.remove(&worker_id);
    }

    /// Snapshot of all worker statuses.
    pub async fn snapshot(&self) -> Vec<WorkerStatus> {
        let map = self.inner.read().await;
        let mut statuses: Vec<WorkerStatus> = map
            .iter()
            .map(|(&id, entry)| {
                let ago = entry.last_heartbeat_at.elapsed().as_secs();
                WorkerStatus {
                    worker_id: id,
                    pid: entry.pid,
                    last_heartbeat_ms: entry.last_heartbeat_latency_ms,
                    last_heartbeat_ago_s: ago,
                    healthy: ago < 15, // unhealthy if no heartbeat in 15s
                }
            })
            .collect();
        statuses.sort_by_key(|s| s.worker_id);
        statuses
    }
}

#[derive(Serialize)]
struct WorkersResponse {
    workers: Vec<WorkerStatus>,
    total: usize,
}

/// Aggregated proxy metrics from all worker processes.
///
/// Each worker periodically sends a MetricsReport via the command channel.
/// The supervisor stores per-worker snapshots and computes aggregations on read.
#[derive(Debug)]
pub struct AggregatedMetrics {
    inner: RwLock<HashMap<u32, WorkerSnapshot>>,
}

#[derive(Debug, Clone)]
struct WorkerSnapshot {
    cache_hits: u64,
    cache_misses: u64,
    active_connections: u64,
    /// (ip, remaining_seconds, ban_duration_seconds)
    ban_entries: Vec<(String, u64, u64)>,
    /// backend_address -> score_us
    ewma_scores: HashMap<String, f64>,
    /// backend_address -> active connections
    backend_connections: HashMap<String, u64>,
    /// (route_id, status_code) -> cumulative count
    request_counts: Vec<(String, u32, u64)>,
    /// (category, action) -> cumulative count
    waf_counts: Vec<(String, String, u64)>,
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregatedMetrics {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Update metrics snapshot for a worker from its MetricsReport.
    pub async fn update_worker(
        &self,
        worker_id: u32,
        cache_hits: u64,
        cache_misses: u64,
        active_connections: u64,
        ban_entries: Vec<(String, u64, u64)>,
        ewma_scores: HashMap<String, f64>,
        backend_connections: HashMap<String, u64>,
        request_counts: Vec<(String, u32, u64)>,
        waf_counts: Vec<(String, String, u64)>,
    ) {
        let mut map = self.inner.write().await;
        map.insert(
            worker_id,
            WorkerSnapshot {
                cache_hits,
                cache_misses,
                active_connections,
                ban_entries,
                ewma_scores,
                backend_connections,
                request_counts,
                waf_counts,
            },
        );
    }

    /// Remove a worker's metrics (e.g. on crash).
    pub async fn remove_worker(&self, worker_id: u32) {
        self.inner.write().await.remove(&worker_id);
    }

    /// Sum of cache hits across all workers.
    pub async fn total_cache_hits(&self) -> u64 {
        self.inner.read().await.values().map(|w| w.cache_hits).sum()
    }

    /// Sum of cache misses across all workers.
    pub async fn total_cache_misses(&self) -> u64 {
        self.inner
            .read()
            .await
            .values()
            .map(|w| w.cache_misses)
            .sum()
    }

    /// Sum of active connections across all workers.
    pub async fn total_active_connections(&self) -> u64 {
        self.inner
            .read()
            .await
            .values()
            .map(|w| w.active_connections)
            .sum()
    }

    /// Union of ban lists from all workers. For duplicate IPs, keep the longest remaining ban.
    pub async fn merged_ban_list(&self) -> Vec<(String, u64, u64)> {
        let map = self.inner.read().await;
        let mut merged: HashMap<String, (u64, u64)> = HashMap::new();
        for w in map.values() {
            for (ip, remaining, duration) in &w.ban_entries {
                let entry = merged.entry(ip.clone()).or_insert((0, 0));
                if *remaining > entry.0 {
                    *entry = (*remaining, *duration);
                }
            }
        }
        merged
            .into_iter()
            .map(|(ip, (remaining, duration))| (ip, remaining, duration))
            .collect()
    }

    /// Sum of active connections per backend across all workers.
    pub async fn merged_backend_connections(&self) -> HashMap<String, u64> {
        let map = self.inner.read().await;
        let mut merged: HashMap<String, u64> = HashMap::new();
        for w in map.values() {
            for (addr, count) in &w.backend_connections {
                *merged.entry(addr.clone()).or_insert(0) += count;
            }
        }
        merged
    }

    /// Minimum EWMA score per backend across all workers (best latency wins).
    pub async fn merged_ewma_scores(&self) -> HashMap<String, f64> {
        let map = self.inner.read().await;
        let mut merged: HashMap<String, f64> = HashMap::new();
        for w in map.values() {
            for (addr, score) in &w.ewma_scores {
                let entry = merged.entry(addr.clone()).or_insert(f64::MAX);
                if *score < *entry {
                    *entry = *score;
                }
            }
        }
        merged
    }

    /// Sum of HTTP request counts across all workers, grouped by (route_id, status_code).
    pub async fn merged_request_counts(&self) -> HashMap<(String, u32), u64> {
        let map = self.inner.read().await;
        let mut merged: HashMap<(String, u32), u64> = HashMap::new();
        for w in map.values() {
            for (route_id, status, count) in &w.request_counts {
                *merged.entry((route_id.clone(), *status)).or_insert(0) += count;
            }
        }
        merged
    }

    /// Sum of WAF event counts across all workers, grouped by (category, action).
    pub async fn merged_waf_counts(&self) -> HashMap<(String, String), u64> {
        let map = self.inner.read().await;
        let mut merged: HashMap<(String, String), u64> = HashMap::new();
        for w in map.values() {
            for (category, action, count) in &w.waf_counts {
                *merged.entry((category.clone(), action.clone())).or_insert(0) += count;
            }
        }
        merged
    }
}

/// GET /api/v1/workers
pub async fn get_workers(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let workers = if let Some(ref metrics) = state.worker_metrics {
        metrics.snapshot().await
    } else {
        vec![]
    };
    let total = workers.len();
    Ok(json_data(WorkersResponse { workers, total }))
}
