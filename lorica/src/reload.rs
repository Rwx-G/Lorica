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

use std::sync::Arc;

use arc_swap::ArcSwap;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::info;

use crate::proxy_wiring::ProxyConfig;

/// Load all routes, backends, certificates and route-backend links from the store
/// and build a new ProxyConfig, then atomically swap it in.
pub async fn reload_proxy_config(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let store = store.lock().await;

    let routes = store.list_routes()?;
    let backends = store.list_backends()?;
    let certificates = store.list_certificates()?;
    let route_backends = store.list_route_backends()?;

    let links: Vec<(String, String)> = route_backends
        .into_iter()
        .map(|rb| (rb.route_id, rb.backend_id))
        .collect();

    let new_config = ProxyConfig::from_store(routes, backends, certificates, links);

    let route_count: usize = new_config.routes_by_host.values().map(|v| v.len()).sum();
    info!(routes = route_count, "proxy configuration reloaded");

    proxy_config.store(Arc::new(new_config));
    Ok(())
}
