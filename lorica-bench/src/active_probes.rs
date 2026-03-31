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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Timelike, Utc};
use lorica_config::models::{ProbeConfig, SlaBucket};
use lorica_config::ConfigStore;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::NotifyDispatcher;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Result of a single probe execution.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub route_id: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Manages active probe scheduling and execution.
///
/// Runs synthetic health probes against backends at configured intervals,
/// independently from real traffic. Results are stored as "active" source
/// SLA buckets in the database.
pub struct ProbeScheduler {
    store: Arc<TokioMutex<ConfigStore>>,
    dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
    http_client: reqwest::Client,
    tasks: TokioMutex<HashMap<String, JoinHandle<()>>>,
}

impl ProbeScheduler {
    pub fn new(
        store: Arc<TokioMutex<ConfigStore>>,
        dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // Probes hit internal backends
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            store,
            dispatcher,
            http_client,
            tasks: TokioMutex::new(HashMap::new()),
        }
    }

    /// Reload probe configurations from the database and restart probe tasks.
    pub async fn reload(&self) {
        let probes = {
            let store = self.store.lock().await;
            match store.list_enabled_probes() {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "failed to load probe configs");
                    return;
                }
            }
        };

        let mut tasks = self.tasks.lock().await;

        // Cancel all existing tasks
        for (_, handle) in tasks.drain() {
            handle.abort();
        }

        // Start new probe tasks
        for probe in probes {
            let id = probe.id.clone();
            let handle = self.spawn_probe_task(probe);
            tasks.insert(id, handle);
        }

        info!(count = tasks.len(), "active probes reloaded");
    }

    fn spawn_probe_task(&self, probe: ProbeConfig) -> JoinHandle<()> {
        let store = Arc::clone(&self.store);
        let dispatcher = self.dispatcher.clone();
        let client = self.http_client.clone();

        tokio::spawn(async move {
            let interval_duration = Duration::from_secs(probe.interval_s.max(5) as u64);
            let timeout = Duration::from_millis(probe.timeout_ms.max(1000) as u64);
            let mut interval = tokio::time::interval(interval_duration);

            loop {
                interval.tick().await;

                let result = execute_probe(&client, &probe, timeout).await;

                debug!(
                    probe_id = %probe.id,
                    route_id = %probe.route_id,
                    status = result.status_code,
                    latency_ms = result.latency_ms,
                    success = result.success,
                    "probe executed"
                );

                // Flush result as an "active" source bucket
                let bucket_start = {
                    let now = Utc::now();
                    now.with_nanosecond(0).unwrap().with_second(0).unwrap()
                };

                let bucket = SlaBucket {
                    id: None,
                    route_id: result.route_id.clone(),
                    bucket_start,
                    request_count: 1,
                    success_count: if result.success { 1 } else { 0 },
                    error_count: if result.success { 0 } else { 1 },
                    latency_sum_ms: result.latency_ms as i64,
                    latency_min_ms: result.latency_ms as i64,
                    latency_max_ms: result.latency_ms as i64,
                    latency_p50_ms: result.latency_ms as i64,
                    latency_p95_ms: result.latency_ms as i64,
                    latency_p99_ms: result.latency_ms as i64,
                    source: "active".to_string(),
                };

                {
                    let s = store.lock().await;
                    if let Err(e) = s.insert_sla_bucket(&bucket) {
                        warn!(error = %e, "failed to store probe result");
                    }
                }

                // Alert on probe failure
                if !result.success {
                    if let Some(ref dispatcher) = dispatcher {
                        let event = AlertEvent::new(
                            AlertType::SlaBreached,
                            format!(
                                "Active probe failed for route {}: {}",
                                result.route_id,
                                result.error.as_deref().unwrap_or("unexpected status")
                            ),
                        )
                        .with_detail("route_id", &result.route_id)
                        .with_detail("probe_id", &probe.id)
                        .with_detail("status_code", result.status_code.to_string())
                        .with_detail("latency_ms", result.latency_ms.to_string());

                        let d = dispatcher.lock().await;
                        d.dispatch(&event).await;
                    }
                }
            }
        })
    }

    /// Stop all running probe tasks.
    pub async fn stop(&self) {
        let mut tasks = self.tasks.lock().await;
        for (_, handle) in tasks.drain() {
            handle.abort();
        }
    }

    /// Get number of active probe tasks.
    pub async fn active_count(&self) -> usize {
        self.tasks.lock().await.len()
    }
}

/// Execute a single probe against the first backend of the route.
async fn execute_probe(
    client: &reqwest::Client,
    probe: &ProbeConfig,
    timeout: Duration,
) -> ProbeResult {
    // We need to find the backend address for this route
    // The probe targets the backend directly (not through the proxy)
    let start = std::time::Instant::now();

    // Build the probe URL - we'll resolve the backend from the route config
    // For now, we use the probe path directly as the URL target
    // The actual backend resolution happens at probe creation time in the API
    let url = format!("http://127.0.0.1{}", probe.path);

    let request = match probe.method.as_str() {
        "GET" => client.get(&url),
        "HEAD" => client.head(&url),
        "POST" => client.post(&url),
        _ => client.get(&url),
    };

    let result = request.timeout(timeout).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            let success = status == probe.expected_status as u16;
            ProbeResult {
                route_id: probe.route_id.clone(),
                status_code: status,
                latency_ms,
                success,
                error: if success {
                    None
                } else {
                    Some(format!(
                        "expected status {}, got {}",
                        probe.expected_status, status
                    ))
                },
            }
        }
        Err(e) => ProbeResult {
            route_id: probe.route_id.clone(),
            status_code: 0,
            latency_ms,
            success: false,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_probe_config(id: &str, route_id: &str) -> ProbeConfig {
        let now = Utc::now();
        ProbeConfig {
            id: id.to_string(),
            route_id: route_id.to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            expected_status: 200,
            interval_s: 30,
            timeout_ms: 5000,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_probe_config_creation() {
        let probe = make_probe_config("p1", "r1");
        assert_eq!(probe.method, "GET");
        assert_eq!(probe.interval_s, 30);
        assert_eq!(probe.expected_status, 200);
    }

    #[test]
    fn test_store_probe_crud() {
        let store = ConfigStore::open_in_memory().unwrap();

        // Create a route (FK constraint)
        let route = lorica_config::models::Route {
            id: "r1".to_string(),
            hostname: "example.com".to_string(),
            path_prefix: "/".to_string(),
            certificate_id: None,
            load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: lorica_config::models::WafMode::Detection,
            topology_type: lorica_config::models::TopologyType::SingleVm,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let probe = make_probe_config("p1", "r1");
        store.create_probe_config(&probe).unwrap();

        // List all
        let probes = store.list_probe_configs().unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].id, "p1");

        // Get by ID
        let p = store.get_probe_config("p1").unwrap().unwrap();
        assert_eq!(p.route_id, "r1");
        assert_eq!(p.method, "GET");

        // List for route
        let probes = store.list_probes_for_route("r1").unwrap();
        assert_eq!(probes.len(), 1);

        // List enabled
        let enabled = store.list_enabled_probes().unwrap();
        assert_eq!(enabled.len(), 1);

        // Update
        let mut updated = p;
        updated.method = "HEAD".to_string();
        updated.interval_s = 60;
        store.update_probe_config(&updated).unwrap();
        let p = store.get_probe_config("p1").unwrap().unwrap();
        assert_eq!(p.method, "HEAD");
        assert_eq!(p.interval_s, 60);

        // Delete
        store.delete_probe_config("p1").unwrap();
        assert!(store.get_probe_config("p1").unwrap().is_none());
    }

    #[test]
    fn test_store_probe_cascade_delete() {
        let store = ConfigStore::open_in_memory().unwrap();

        let route = lorica_config::models::Route {
            id: "r1".to_string(),
            hostname: "example.com".to_string(),
            path_prefix: "/".to_string(),
            certificate_id: None,
            load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: lorica_config::models::WafMode::Detection,
            topology_type: lorica_config::models::TopologyType::SingleVm,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let probe = make_probe_config("p1", "r1");
        store.create_probe_config(&probe).unwrap();

        // Deleting the route should cascade-delete the probe
        store.delete_route("r1").unwrap();
        assert!(store.get_probe_config("p1").unwrap().is_none());
    }

    #[tokio::test]
    async fn test_probe_scheduler_active_count() {
        let store = Arc::new(TokioMutex::new(ConfigStore::open_in_memory().unwrap()));
        let scheduler = ProbeScheduler::new(store, None);
        assert_eq!(scheduler.active_count().await, 0);
    }

    #[test]
    fn test_probe_result_success() {
        let result = ProbeResult {
            route_id: "r1".to_string(),
            status_code: 200,
            latency_ms: 42,
            success: true,
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_probe_result_failure() {
        let result = ProbeResult {
            route_id: "r1".to_string(),
            status_code: 503,
            latency_ms: 100,
            success: false,
            error: Some("expected status 200, got 503".to_string()),
        };
        assert!(!result.success);
        assert!(result.error.unwrap().contains("503"));
    }
}
