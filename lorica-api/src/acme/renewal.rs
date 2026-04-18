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

//! Background renewal task and manual renewal endpoint.

use axum::extract::{Extension, Path};
use axum::Json;
use tracing::{error, info, warn};

use crate::error::ApiError;
use crate::server::AppState;

use super::config::AcmeConfig;
use super::dns01::provision_with_acme_dns;
use super::dns_challengers::{build_dns_challenger, DnsChallengeConfig};
use super::http01::provision_with_acme;

/// Spawn a background task that checks ACME certificates for renewal.
///
/// Runs every `check_interval` and renews certificates where:
/// - `is_acme == true` and `acme_auto_renew == true`
/// - Days until expiry <= `renewal_threshold_days`
pub fn spawn_renewal_task(
    state: AppState,
    check_interval: std::time::Duration,
    renewal_threshold_days: i64,
    alert_sender: Option<lorica_notify::AlertSender>,
) -> tokio::task::JoinHandle<()> {
    let tracker = state.task_tracker.clone();
    tracker.spawn(async move {
        loop {
            tokio::time::sleep(check_interval).await;

            let certs = {
                let store = state.store.lock().await;
                match store.list_certificates() {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "ACME renewal: failed to list certificates");
                        continue;
                    }
                }
            };

            let now = chrono::Utc::now();
            for cert in &certs {
                if !cert.is_acme || !cert.acme_auto_renew {
                    continue;
                }

                let days_remaining = (cert.not_after - now).num_days();
                if days_remaining > renewal_threshold_days {
                    continue;
                }

                info!(
                    domain = %cert.domain,
                    days_remaining = days_remaining,
                    threshold = renewal_threshold_days,
                    "ACME certificate approaching expiry, attempting renewal"
                );

                // Dispatch cert_expiring notification
                if let Some(ref sender) = alert_sender {
                    sender.send(
                        lorica_notify::AlertEvent::new(
                            lorica_notify::events::AlertType::CertExpiring,
                            format!(
                                "Certificate for {} expires in {} days",
                                cert.domain, days_remaining
                            ),
                        )
                        .with_detail("domain", cert.domain.clone())
                        .with_detail("days_remaining", days_remaining.to_string())
                        .with_detail("cert_id", cert.id.clone()),
                    );
                }

                // Skip dns01-manual certs in auto-renewal
                if cert.acme_method.as_deref() == Some("dns01-manual") {
                    info!(
                        domain = %cert.domain,
                        "skipping auto-renewal for manual DNS-01 certificate"
                    );
                    continue;
                }

                let config = AcmeConfig {
                    staging: cert.issuer.contains("STAGING"),
                    contact_email: None,
                };

                // Renew with all domains (primary + SANs), deduplicated
                let mut all_domains = vec![cert.domain.clone()];
                for d in &cert.san_domains {
                    if !all_domains.contains(d) {
                        all_domains.push(d.clone());
                    }
                }
                match renew_with_method(&state, cert, &config, &all_domains).await {
                    Ok(new_cert_id) => {
                        // Reassign routes from old cert to new cert
                        let store = state.store.lock().await;
                        if let Ok(reassigned) = store.reassign_certificate(&cert.id, &new_cert_id) {
                            if reassigned > 0 {
                                info!(old_id = %cert.id, new_id = %new_cert_id, routes = reassigned, "routes reassigned to renewed certificate");
                            }
                        }
                        // Delete old certificate
                        if let Err(e) = store.delete_certificate(&cert.id) {
                            warn!(old_id = %cert.id, error = %e, "failed to delete old certificate after renewal");
                        }
                        drop(store);
                        state.rotate_bot_hmac_on_cert_event().await;
                        state.notify_config_changed();
                        info!(
                            domain = %cert.domain,
                            old_cert_id = %cert.id,
                            new_cert_id = %new_cert_id,
                            acme_method = ?cert.acme_method,
                            "ACME certificate renewed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            domain = %cert.domain,
                            error = %e,
                            days_remaining = days_remaining,
                            acme_method = ?cert.acme_method,
                            "ACME renewal failed - existing cert still active"
                        );
                    }
                }
            }
        }
    })
}

/// POST /api/v1/certificates/:id/renew - manually trigger ACME renewal for a certificate
pub async fn renew_certificate(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cert = {
        let store = state.store.lock().await;
        store
            .get_certificate(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?
    };

    if !cert.is_acme {
        return Err(ApiError::BadRequest(
            "only ACME certificates can be renewed (use upload for manual certs)".into(),
        ));
    }

    let config = AcmeConfig {
        staging: cert.issuer.contains("STAGING") || cert.issuer.contains("(staging)"),
        contact_email: None,
    };

    // Renew with all domains (primary + SANs), deduplicated
    let mut all_domains = vec![cert.domain.clone()];
    for d in &cert.san_domains {
        if !all_domains.contains(d) {
            all_domains.push(d.clone());
        }
    }

    let new_cert_id = renew_with_method(&state, &cert, &config, &all_domains)
        .await
        .map_err(|e| ApiError::Internal(format!("ACME renewal failed: {e}")))?;

    // Reassign routes and delete old cert
    {
        let store = state.store.lock().await;
        if let Ok(reassigned) = store.reassign_certificate(&cert.id, &new_cert_id) {
            if reassigned > 0 {
                tracing::info!(old_id = %cert.id, new_id = %new_cert_id, routes = reassigned, "routes reassigned to renewed certificate");
            }
        }
        if let Err(e) = store.delete_certificate(&cert.id) {
            tracing::warn!(old_id = %cert.id, error = %e, "failed to delete old certificate after renewal");
        }
    }
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    tracing::info!(
        domain = %cert.domain,
        old_cert_id = %cert.id,
        new_cert_id = %new_cert_id,
        "certificate manually renewed"
    );

    Ok(crate::error::json_data(serde_json::json!({
        "renewed": true,
        "old_cert_id": cert.id,
        "new_cert_id": new_cert_id,
        "domain": cert.domain,
    })))
}

/// Renew a certificate using the appropriate method based on `acme_method`.
///
/// - `"http01"` or `None` -> HTTP-01 (original behavior)
/// - `"dns01-cloudflare"` / `"dns01-route53"` / `"dns01-ovh"` -> decrypt config, build challenger
/// - `"dns01-manual"` -> error (requires manual renewal)
async fn renew_with_method(
    state: &AppState,
    cert: &lorica_config::models::Certificate,
    config: &AcmeConfig,
    domains: &[String],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let method = cert.acme_method.as_deref().unwrap_or("http01");

    match method {
        "http01" => provision_with_acme(state, config, domains).await,
        "dns01-manual" => Err("manual DNS-01 certificates require manual renewal - \
             use the provision-dns-manual endpoint"
            .into()),
        m if m.starts_with("dns01-") => {
            // Extract provider name from "dns01-provider"
            let provider = &m[6..];

            // Try new approach first: global DNS provider reference
            let (dns_config, dns_provider_id) = if let Some(ref pid) = cert.acme_dns_provider_id {
                let store = state.store.lock().await;
                let dp = store
                    .get_dns_provider(pid)
                    .map_err(|e| format!("failed to fetch DNS provider '{pid}': {e}"))?;
                drop(store);
                let dp = dp.ok_or_else(|| {
                    format!(
                        "certificate references DNS provider '{pid}' which no longer exists - \
                         cannot auto-renew"
                    )
                })?;
                let cfg: DnsChallengeConfig = serde_json::from_str(&dp.config)
                    .map_err(|e| format!("failed to parse DNS provider config: {e}"))?;
                (cfg, Some(pid.clone()))
            } else {
                return Err(format!(
                    "certificate has method '{m}' but no DNS provider configured - \
                     cannot auto-renew"
                )
                .into());
            };

            // Verify provider matches
            if dns_config.provider != provider {
                return Err(format!(
                    "DNS config provider '{}' does not match method '{m}'",
                    dns_config.provider
                )
                .into());
            }

            let challenger = build_dns_challenger(&dns_config)
                .await
                .map_err(|e| format!("failed to build DNS challenger for renewal: {e}"))?;

            provision_with_acme_dns(
                state,
                config,
                domains,
                challenger.as_ref(),
                m,
                dns_provider_id,
            )
            .await
        }
        other => Err(format!("unknown ACME method: {other}").into()),
    }
}
