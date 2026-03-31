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
