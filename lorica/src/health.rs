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
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use lorica_config::models::{HealthStatus, LifecycleState};
use lorica_config::ConfigStore;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use lorica::proxy_wiring::{BackendConnections, ProxyConfig};
use lorica::reload::reload_proxy_config;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default drain timeout before force-closing a Closing backend.
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Latency threshold above which a backend is considered degraded (ms).
const DEGRADED_THRESHOLD_MS: u128 = 2000;

/// Result of a single TCP health check probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Connection succeeded within the degraded threshold.
    Healthy,
    /// Connection succeeded but took longer than the degraded threshold.
    Degraded,
    /// Connection failed or timed out.
    Down,
}

impl ProbeResult {
    pub fn to_health_status(&self) -> HealthStatus {
        match self {
            ProbeResult::Healthy => HealthStatus::Healthy,
            ProbeResult::Degraded => HealthStatus::Degraded,
            ProbeResult::Down => HealthStatus::Down,
        }
    }
}

/// Run TCP health checks and backend drain monitoring in a loop.
///
/// - Health checks: probe each backend, update status (Healthy/Degraded/Down)
/// - Drain checks: transition Closing backends to Closed when connections reach 0 or timeout expires
pub async fn health_check_loop(
    store: Arc<Mutex<ConfigStore>>,
    proxy_config: Arc<ArcSwap<ProxyConfig>>,
    default_interval_s: u64,
    backend_connections: Option<Arc<BackendConnections>>,
    alert_sender: Option<lorica_notify::AlertSender>,
    config_reload_tx: Option<tokio::sync::broadcast::Sender<u64>>,
) {
    let interval = Duration::from_secs(default_interval_s.max(5));
    // Track when each backend entered Closing state for drain timeout
    let mut drain_start: HashMap<String, Instant> = HashMap::new();

    loop {
        tokio::time::sleep(interval).await;

        let backends = {
            let store = store.lock().await;
            match store.list_backends() {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "failed to list backends for health check");
                    continue;
                }
            }
        };

        let mut changed = false;

        for backend in &backends {
            // --- Drain monitoring for Closing backends ---
            if backend.lifecycle_state == LifecycleState::Closing {
                let start = drain_start
                    .entry(backend.id.clone())
                    .or_insert_with(Instant::now);

                let active = backend_connections
                    .as_ref()
                    .map(|bc| bc.get(&backend.address))
                    .unwrap_or(0);

                let timed_out = start.elapsed() >= DEFAULT_DRAIN_TIMEOUT;

                if active == 0 || timed_out {
                    let reason = if active == 0 {
                        "all connections drained"
                    } else {
                        "drain timeout expired"
                    };
                    info!(
                        backend = %backend.address,
                        active_connections = active,
                        reason = reason,
                        "transitioning backend to Closed"
                    );

                    let mut updated = backend.clone();
                    updated.lifecycle_state = LifecycleState::Closed;
                    updated.updated_at = chrono::Utc::now();

                    let store = store.lock().await;
                    if let Err(e) = store.update_backend(&updated) {
                        warn!(
                            backend = %backend.address,
                            error = %e,
                            "failed to transition backend to Closed"
                        );
                    } else {
                        changed = true;
                        drain_start.remove(&backend.id);
                    }
                }
                continue;
            }

            // Clean up drain tracking for non-Closing backends
            drain_start.remove(&backend.id);

            // --- Health checks for Normal backends ---
            if !backend.health_check_enabled {
                continue;
            }

            // Run active probes (HTTP if path set, else TCP)
            let probe = if let Some(ref path) = backend.health_check_path {
                let scheme = if backend.tls_upstream {
                    "https"
                } else {
                    "http"
                };
                let url = format!("{scheme}://{}{path}", backend.address);
                http_probe(&url).await
            } else {
                tcp_probe(&backend.address).await
            };
            let new_status = probe.to_health_status();

            if new_status != backend.health_status {
                debug!(
                    backend = %backend.address,
                    old = backend.health_status.as_str(),
                    new = new_status.as_str(),
                    "backend health status changed"
                );

                let mut updated = backend.clone();
                updated.health_status = new_status.clone();

                // Dispatch backend_down notification on transition to Down
                if new_status == HealthStatus::Down {
                    if let Some(ref sender) = alert_sender {
                        sender.send(
                            lorica_notify::AlertEvent::new(
                                lorica_notify::events::AlertType::BackendDown,
                                format!("Backend {} is down", backend.address),
                            )
                            .with_detail("backend_id", backend.id.clone())
                            .with_detail("address", backend.address.clone())
                            .with_detail("name", backend.name.clone()),
                        );
                    }
                }

                let store = store.lock().await;
                if let Err(e) = store.update_backend(&updated) {
                    warn!(
                        backend = %backend.address,
                        error = %e,
                        "failed to update backend health status"
                    );
                } else {
                    changed = true;
                }
            }
        }

        if changed {
            if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
                warn!(error = %e, "failed to reload proxy config after health check");
            }
            // Notify workers to reload their proxy config with updated health statuses
            if let Some(ref tx) = config_reload_tx {
                let _ = tx.send(0);
            }
        }
    }
}

/// Attempt a TCP connection and measure latency.
/// Returns Healthy if connect < DEGRADED_THRESHOLD_MS, Degraded if slower, Down on failure.
async fn tcp_probe(address: &str) -> ProbeResult {
    let start = Instant::now();
    match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => {
            let elapsed_ms = start.elapsed().as_millis();
            if elapsed_ms > DEGRADED_THRESHOLD_MS {
                debug!(
                    address = %address,
                    latency_ms = elapsed_ms as u64,
                    threshold_ms = DEGRADED_THRESHOLD_MS as u64,
                    "TCP health check slow - marking degraded"
                );
                ProbeResult::Degraded
            } else {
                ProbeResult::Healthy
            }
        }
        Ok(Err(e)) => {
            debug!(address = %address, error = %e, "TCP health check failed");
            ProbeResult::Down
        }
        Err(_) => {
            debug!(address = %address, "TCP health check timed out");
            ProbeResult::Down
        }
    }
}

/// Attempt an HTTP GET and check for a 2xx response.
/// Returns Healthy if response is 2xx within the degraded threshold, Degraded if slow, Down on failure.
async fn http_probe(url: &str) -> ProbeResult {
    let start = Instant::now();

    let client = match reqwest::Client::builder()
        .timeout(TCP_CONNECT_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug!(url = %url, error = %e, "HTTP health check client build failed");
            return ProbeResult::Down;
        }
    };

    match client.get(url).send().await {
        Ok(resp) => {
            let elapsed_ms = start.elapsed().as_millis();
            if !resp.status().is_success() {
                debug!(
                    url = %url,
                    status = resp.status().as_u16(),
                    "HTTP health check non-2xx response"
                );
                return ProbeResult::Down;
            }
            if elapsed_ms > DEGRADED_THRESHOLD_MS {
                debug!(
                    url = %url,
                    latency_ms = elapsed_ms as u64,
                    "HTTP health check slow - marking degraded"
                );
                ProbeResult::Degraded
            } else {
                ProbeResult::Healthy
            }
        }
        Err(e) => {
            debug!(url = %url, error = %e, "HTTP health check failed");
            ProbeResult::Down
        }
    }
}

/// Determine probe result from a latency value (for testing).
#[cfg(test)]
fn classify_latency(connected: bool, latency_ms: u128) -> ProbeResult {
    if !connected {
        ProbeResult::Down
    } else if latency_ms > DEGRADED_THRESHOLD_MS {
        ProbeResult::Degraded
    } else {
        ProbeResult::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Latency classification ----

    #[test]
    fn test_classify_latency_healthy() {
        assert_eq!(classify_latency(true, 50), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 0), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 1999), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 2000), ProbeResult::Healthy);
    }

    #[test]
    fn test_classify_latency_degraded() {
        assert_eq!(classify_latency(true, 2001), ProbeResult::Degraded);
        assert_eq!(classify_latency(true, 5000), ProbeResult::Degraded);
    }

    #[test]
    fn test_classify_latency_down() {
        assert_eq!(classify_latency(false, 0), ProbeResult::Down);
        assert_eq!(classify_latency(false, 3000), ProbeResult::Down);
    }

    #[test]
    fn test_probe_result_to_health_status() {
        assert_eq!(
            ProbeResult::Healthy.to_health_status(),
            HealthStatus::Healthy
        );
        assert_eq!(
            ProbeResult::Degraded.to_health_status(),
            HealthStatus::Degraded
        );
        assert_eq!(ProbeResult::Down.to_health_status(), HealthStatus::Down);
    }

    #[tokio::test]
    async fn test_tcp_probe_unreachable_address() {
        // Use a non-routable address to guarantee failure
        let result = tcp_probe("192.0.2.1:1").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_tcp_probe_invalid_address() {
        let result = tcp_probe("not-a-valid-address").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_tcp_probe_refused() {
        // Localhost on a port nothing is listening on
        let result = tcp_probe("127.0.0.1:1").await;
        assert_eq!(result, ProbeResult::Down);
    }

    // ---- HTTP probe ----

    #[tokio::test]
    async fn test_http_probe_unreachable() {
        let result = http_probe("http://192.0.2.1:1/healthz").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_http_probe_invalid_url() {
        let result = http_probe("not-a-url").await;
        assert_eq!(result, ProbeResult::Down);
    }
}
