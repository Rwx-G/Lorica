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

use crate::connection_filter::{ConnectionFilterPolicy, GlobalConnectionFilter};
use crate::proxy_wiring::ProxyConfig;

/// Load all routes, backends, certificates and route-backend links from the store
/// and build a new ProxyConfig, then atomically swap it in.
///
/// When `connection_filter` is provided, its CIDR policy is refreshed in the
/// same transaction as the ProxyConfig swap, so listener-level filtering
/// stays coherent with route/backend state after a settings change.
pub async fn reload_proxy_config(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    connection_filter: Option<&Arc<GlobalConnectionFilter>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    reload_proxy_config_with_mtls(store, proxy_config, connection_filter, None).await
}

/// Variant of [`reload_proxy_config`] that also compares the current
/// CA fingerprint against the one installed on the listener at startup
/// and logs a warning when they differ. Kept as a separate entry
/// point so existing callers (tests, internal call sites that never
/// see a fingerprint) don't need to track a new argument.
pub async fn reload_proxy_config_with_mtls(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    connection_filter: Option<&Arc<GlobalConnectionFilter>>,
    installed_mtls_fingerprint: Option<&parking_lot::Mutex<Option<String>>>,
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
    let connection_allow_cidrs = settings
        .as_ref()
        .map(|s| s.connection_allow_cidrs.clone())
        .unwrap_or_default();
    let connection_deny_cidrs = settings
        .as_ref()
        .map(|s| s.connection_deny_cidrs.clone())
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

    // Preserve round-robin counters from the old config to avoid
    // resetting load distribution on every config reload. Entries are
    // now stored as `Arc<RouteEntry>` (shared across hostname +
    // aliases), so we rebuild the inner struct with the preserved
    // wrr_state once per route_id and then replace every Arc slot
    // pointing at that route.
    let old_config = proxy_config.load();
    let mut rebuilt: std::collections::HashMap<String, Arc<crate::proxy_wiring::RouteEntry>> =
        std::collections::HashMap::new();
    for entries in new_config.routes_by_host.values() {
        for entry in entries {
            if rebuilt.contains_key(&entry.route.id) {
                continue;
            }
            if let Some(old_entries) = old_config.routes_by_host.get(&entry.route.hostname) {
                if let Some(old_entry) = old_entries.iter().find(|e| e.route.id == entry.route.id) {
                    let mut new_inner = (**entry).clone();
                    new_inner.wrr_state = Arc::clone(&old_entry.wrr_state);
                    rebuilt.insert(entry.route.id.clone(), Arc::new(new_inner));
                }
            }
        }
    }
    for entries in new_config.routes_by_host.values_mut() {
        for slot in entries.iter_mut() {
            if let Some(new_arc) = rebuilt.get(&slot.route.id) {
                *slot = Arc::clone(new_arc);
            }
        }
    }

    let route_count: usize = new_config.routes_by_host.values().map(|v| v.len()).sum();
    info!(routes = route_count, "proxy configuration reloaded");

    // mTLS CA bundle drift detection: rustls `ServerConfig` is
    // immutable after the listener is built, so any edit to a
    // route's `mtls.ca_cert_pem` at runtime won't take effect until
    // the process is restarted. Surface that as a warn log so
    // operators don't debug a "bundle update didn't apply" bug.
    // Toggling `required` or editing `allowed_organizations` hot-
    // reloads via the snapshot we just published, so those aren't
    // flagged here.
    if let Some(slot) = installed_mtls_fingerprint {
        // Re-read routes from the snapshot we just built so we
        // compare against the same Route instances the proxy is
        // actually serving.
        let current_routes: Vec<lorica_config::models::Route> = new_config
            .routes_by_host
            .values()
            .flat_map(|v| v.iter().map(|e| (*e.route).clone()))
            .collect();
        let current_fp = crate::mtls::compute_ca_fingerprint(&current_routes);
        let installed_fp = slot.lock().clone();
        if installed_fp != current_fp {
            warn!(
                installed = ?installed_fp,
                current = ?current_fp,
                "mtls CA bundle changed since startup; restart Lorica to apply (rustls ServerConfig is immutable). Toggling mtls.required or editing allowed_organizations takes effect live."
            );
        }
    }

    proxy_config.store(Arc::new(new_config));

    if let Some(filter) = connection_filter {
        let policy =
            ConnectionFilterPolicy::from_cidrs(&connection_allow_cidrs, &connection_deny_cidrs);
        let allow_count = policy.allow.len();
        let deny_count = policy.deny.len();
        filter.reload(policy);
        info!(
            allow_cidrs = allow_count,
            deny_cidrs = deny_count,
            "connection filter reloaded"
        );
    }

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

    // Build CertData with OCSP staple responses fetched in parallel.
    // Drop the store lock before doing network I/O.
    let active_certs: Vec<_> = db_certs
        .iter()
        .filter(|c| active_cert_ids.contains(&c.id))
        .cloned()
        .collect();
    drop(s);

    let ocsp_futures: Vec<_> = active_certs
        .iter()
        .map(|c| lorica_tls::ocsp::try_fetch_ocsp(&c.cert_pem))
        .collect();
    let ocsp_responses = futures_util::future::join_all(ocsp_futures).await;

    let cert_data: Vec<CertData> = active_certs
        .iter()
        .zip(ocsp_responses)
        .map(|(c, ocsp)| CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
            ocsp_response: ocsp,
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
