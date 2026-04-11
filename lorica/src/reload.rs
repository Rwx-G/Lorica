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
    let waf_ban_threshold = settings
        .as_ref()
        .map(|s| s.waf_ban_threshold.max(0) as u32)
        .unwrap_or(5);
    let waf_ban_duration_s = settings
        .as_ref()
        .map(|s| s.waf_ban_duration_s.max(0) as u32)
        .unwrap_or(3600);
    let trusted_proxies = settings
        .as_ref()
        .map(|s| s.trusted_proxies.clone())
        .unwrap_or_default();
    let waf_whitelist_ips = settings
        .as_ref()
        .map(|s| s.waf_whitelist_ips.clone())
        .unwrap_or_default();

    let links: Vec<(String, String)> = route_backends
        .into_iter()
        .map(|rb| (rb.route_id, rb.backend_id))
        .collect();

    let mut new_config = ProxyConfig::from_store(
        routes,
        backends,
        certificates,
        links,
        crate::proxy_wiring::ProxyConfigGlobals {
            custom_security_presets: custom_presets,
            max_global_connections,
            flood_threshold_rps,
            waf_ban_threshold,
            waf_ban_duration_s,
            trusted_proxy_cidrs: trusted_proxies,
            waf_whitelist_cidrs: waf_whitelist_ips,
        },
    );

    // Preserve round-robin counters from the old config to avoid resetting
    // load distribution on every config reload
    let old_config = proxy_config.load();
    for entries in new_config.routes_by_host.values_mut() {
        for entry in entries.iter_mut() {
            if let Some(old_entries) = old_config.routes_by_host.get(&entry.route.hostname) {
                if let Some(old_entry) = old_entries.iter().find(|e| e.route.id == entry.route.id) {
                    entry.wrr_state = Arc::clone(&old_entry.wrr_state);
                }
            }
        }
    }

    let route_count: usize = new_config.routes_by_host.values().map(|v| v.len()).sum();
    info!(routes = route_count, "proxy configuration reloaded");

    proxy_config.store(Arc::new(new_config));
    Ok(())
}

/// Reload the TLS certificate resolver from the database.
/// Only loads certificates that are actively referenced by at least one route.
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

    // Only load certificates referenced by at least one route
    let active_cert_ids: std::collections::HashSet<String> = match s.list_routes() {
        Ok(routes) => routes
            .iter()
            .filter_map(|r| r.certificate_id.clone())
            .collect(),
        Err(e) => {
            warn!(error = %e, "failed to list routes for resolver reload");
            return;
        }
    };

    let cert_data: Vec<CertData> = db_certs
        .iter()
        .filter(|c| active_cert_ids.contains(&c.id))
        .map(|c| CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
            ocsp_response: None,
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
