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

//! Automated DNS-01 challenge provisioning: endpoint and internal flow.

use axum::extract::{Extension};
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use lorica_acme::{build_dns_challenger, AcmeConfig, DnsChallengeConfig, DnsChallenger};

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

use super::types::{default_true, AcmeProvisionResponse};

/// Request body for DNS-01 ACME certificate provisioning.
#[derive(Debug, Deserialize)]
pub struct AcmeDnsProvisionRequest {
    /// Domain to provision certificate for.
    pub domain: String,
    /// Whether to use staging environment.
    #[serde(default = "default_true")]
    pub staging: bool,
    /// Contact email for Let's Encrypt.
    pub contact_email: Option<String>,
    /// DNS provider configuration (inline credentials - legacy).
    #[serde(default)]
    pub dns: Option<DnsChallengeConfig>,
    /// Reference to a global DNS provider (new approach).
    #[serde(default)]
    pub dns_provider_id: Option<String>,
}

/// POST /api/v1/acme/provision-dns - Initiate ACME certificate provisioning via DNS-01.
///
/// This is a long-running operation. It creates an ACME order, responds to
/// the DNS-01 challenge by creating a TXT record via the configured DNS provider,
/// and waits for certificate issuance.
pub async fn provision_certificate_dns(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<AcmeDnsProvisionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Support multi-domain: "example.com, *.example.com" or "a.com,b.com"
    let domains: Vec<String> = body
        .domain
        .split(',')
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if domains.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }
    let primary_domain = domains[0].clone();

    // Resolve DNS config: either from a global provider or inline credentials
    let (dns_config, dns_provider_id) = if let Some(ref provider_id) = body.dns_provider_id {
        // New approach: look up global DNS provider
        let pid = provider_id.clone();
        let provider = db_blocking(&state.store, move |store| {
            store
                .get_dns_provider(&pid)
                .map_err(|e| ApiError::Internal(format!("failed to fetch DNS provider: {e}")))?
                .ok_or_else(|| ApiError::NotFound(format!("dns_provider {pid}")))
        })
        .await?;
        let config: DnsChallengeConfig = serde_json::from_str(&provider.config)
            .map_err(|e| ApiError::Internal(format!("invalid DNS provider config: {e}")))?;
        (config, Some(provider_id.clone()))
    } else if let Some(ref dns) = body.dns {
        // Legacy approach: inline credentials
        (dns.clone(), None)
    } else {
        return Err(ApiError::BadRequest(
            "either dns_provider_id or dns config is required".into(),
        ));
    };

    if let Err(e) = dns_config.validate() {
        return Err(ApiError::BadRequest(format!("invalid DNS config: {e}")));
    }

    let challenger = build_dns_challenger(&dns_config)
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to build DNS challenger: {e}")))?;

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    let acme_method = format!("dns01-{}", dns_config.provider);

    info!(
        domains = ?domains,
        staging = config.staging,
        provider = %dns_config.provider,
        directory = config.directory_url(),
        dns_provider_id = ?dns_provider_id,
        "starting ACME DNS-01 certificate provisioning"
    );

    let result = provision_with_acme_dns(
        &state,
        &config,
        &domains,
        challenger.as_ref(),
        &acme_method,
        dns_provider_id,
        None,
    )
    .await;

    match result {
        Ok(cert_id) => {
            info!(domains = ?domains, cert_id = %cert_id, "ACME DNS-01 certificate provisioned");
            let response = AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: primary_domain,
                staging: config.staging,
                message: format!(
                    "Certificate provisioned via DNS-01 for {} domain(s) (id: {cert_id})",
                    domains.len()
                ),
            };

            // `after` uses the credential-free response view; the
            // request body may carry inline DNS credentials.
            let audit_ctx =
                crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
            let after = serde_json::to_value(&response).ok();
            crate::audit::record(
                &state,
                &audit_ctx,
                "acme.provision_dns01",
                ("certificate", &cert_id),
                None,
                after.as_ref(),
            )
            .await;

            Ok(json_data(response))
        }
        Err(e) => {
            warn!(domains = ?domains, error = %e, "ACME DNS-01 provisioning failed");
            Err(ApiError::Internal(format!(
                "ACME DNS-01 provisioning failed: {e}"
            )))
        }
    }
}

/// Internal ACME provisioning logic using DNS-01 challenge.
/// Supports multi-domain and wildcard certificates.
///
/// `acme_method` is stored on the certificate (e.g. "dns01-cloudflare").
/// `encrypted_dns_config` is the encrypted JSON of the DNS credentials (legacy).
/// `dns_provider_id` references a global DNS provider (new approach).
///
/// When `existing_cert_id` is `Some`, the freshly issued leaf is
/// persisted in place on that row via `update_certificate` (same id,
/// route bindings untouched); when `None`, a new row is inserted with
/// a fresh UUID. The returned id is the id that now carries the leaf.
pub(super) async fn provision_with_acme_dns(
    state: &AppState,
    config: &AcmeConfig,
    domains: &[String],
    challenger: &dyn DnsChallenger,
    acme_method: &str,
    dns_provider_id: Option<String>,
    existing_cert_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let primary_domain = &domains[0];

    // Drive the pure ACME protocol via `lorica-acme`; the challenger creates
    // the `_acme-challenge.<host>` TXT records, waits for propagation, and
    // deletes them once the order resolves.
    let issued = lorica_acme::issue_dns01(config, domains, challenger).await?;
    let cert_pem = issued.cert_pem;
    let key_pem = issued.key_pem;

    // Store certificate in database. On renewal (`existing_cert_id`
    // is `Some`) update the row in place so the id and every route
    // binding survive ; on first issuance insert a fresh row.
    let now = chrono::Utc::now();
    let is_renewal = existing_cert_id.is_some();
    let cert_id = existing_cert_id
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), ToString::to_string);
    let fingerprint = format!("acme-dns:{}", domains.join(","));

    let cert = lorica_config::models::Certificate {
        id: cert_id.clone(),
        domain: primary_domain.clone(),
        san_domains: domains.to_vec(),
        fingerprint,
        cert_pem,
        key_pem,
        issuer: if config.staging {
            "(STAGING) Let's Encrypt".to_string()
        } else {
            "Let's Encrypt".to_string()
        },
        not_before: now,
        not_after: now + chrono::Duration::days(90),
        is_acme: true,
        acme_auto_renew: true,
        // `update_certificate` does not touch `created_at`, so the
        // original insert timestamp is preserved on a renewal.
        created_at: now,
        acme_method: Some(acme_method.to_string()),

        acme_dns_provider_id: dns_provider_id,
    };

    let (cert, export_snapshot) = db_blocking(&state.store, move |store| {
        if is_renewal {
            store.update_certificate(&cert)?;
        } else {
            store.create_certificate(&cert)?;
        }
        let snapshot = crate::cert_export::snapshot_export_inputs(store);
        Ok::<_, ApiError>((cert, snapshot))
    })
    .await?;
    // v1.5.1 audit M-9 : run the disk export in `spawn_blocking`
    // AFTER releasing the store mutex so concurrent API handlers
    // do not block on the cross-mount EXDEV `copy + fsync + rename`
    // path while waiting for the same lock.
    if let Some((settings, acls)) = export_snapshot {
        crate::cert_export::export_after_release(settings, acls, cert).await;
    }
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(cert_id)
}
