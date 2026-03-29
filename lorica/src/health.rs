// Copyright 2026 Romain G. (Lorica)
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

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use lorica_config::models::HealthStatus;
use lorica_config::ConfigStore;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, warn};

use lorica::proxy_wiring::ProxyConfig;
use lorica::reload::reload_proxy_config;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Run TCP health checks in a loop, updating backend health status in the database
/// and triggering a config reload when status changes.
pub async fn health_check_loop(
    store: Arc<Mutex<ConfigStore>>,
    proxy_config: Arc<ArcSwap<ProxyConfig>>,
    default_interval_s: u64,
) {
    let interval = Duration::from_secs(default_interval_s.max(5));
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
            if !backend.health_check_enabled {
                continue;
            }

            let new_status = match tcp_check(&backend.address).await {
                true => HealthStatus::Healthy,
                false => HealthStatus::Down,
            };

            if new_status != backend.health_status {
                debug!(
                    backend = %backend.address,
                    old = backend.health_status.as_str(),
                    new = new_status.as_str(),
                    "backend health status changed"
                );

                let mut updated = backend.clone();
                updated.health_status = new_status;

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
        }
    }
}

/// Attempt a TCP connection to the given address. Returns true if successful.
async fn tcp_check(address: &str) -> bool {
    match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!(address = %address, error = %e, "TCP health check failed");
            false
        }
        Err(_) => {
            debug!(address = %address, "TCP health check timed out");
            false
        }
    }
}
