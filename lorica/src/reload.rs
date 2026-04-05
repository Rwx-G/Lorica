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
use lorica_tls::cert_resolver::{CertData, CertResolver};
use tokio::sync::Mutex;
use tracing::{info, warn};

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
    let settings = store.get_global_settings().ok();
    let custom_presets = settings
        .as_ref()
        .map(|s| s.custom_security_presets.clone())
        .unwrap_or_default();
    let max_global_connections = settings
        .as_ref()
        .map(|s| s.max_global_connections.max(0) as u32)
        .unwrap_or(0);
    let flood_threshold_rps = settings
        .as_ref()
        .map(|s| s.flood_threshold_rps.max(0) as u32)
        .unwrap_or(0);

    let links: Vec<(String, String)> = route_backends
        .into_iter()
        .map(|rb| (rb.route_id, rb.backend_id))
        .collect();

    let new_config = ProxyConfig::from_store(
        routes,
        backends,
        certificates,
        links,
        custom_presets,
        max_global_connections,
        flood_threshold_rps,
    );

    let route_count: usize = new_config.routes_by_host.values().map(|v| v.len()).sum();
    info!(routes = route_count, "proxy configuration reloaded");

    proxy_config.store(Arc::new(new_config));
    Ok(())
}

/// Reload the TLS certificate resolver from the database.
/// Called alongside `reload_proxy_config` when certificates change.
pub async fn reload_cert_resolver(
    store: &Arc<Mutex<ConfigStore>>,
    cert_resolver: &Arc<CertResolver>,
) {
    let s = store.lock().await;
    let db_certs = match s.list_certificates() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to list certificates for resolver reload");
            return;
        }
    };

    let cert_data: Vec<CertData> = db_certs
        .iter()
        .map(|c| CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
        })
        .collect();

    match cert_resolver.reload(cert_data) {
        Ok(()) => info!(
            domains = cert_resolver.domain_count(),
            "TLS certificate resolver reloaded"
        ),
        Err(e) => warn!(error = %e, "failed to reload TLS certificate resolver"),
    }
}
