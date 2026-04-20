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

use axum::extract::Extension;
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

use super::config::AcmeConfig;
use super::dns_challengers::{build_dns_challenger, DnsChallengeConfig, DnsChallenger};
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
    Extension(state): Extension<AppState>,
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
        let store = state.store.lock().await;
        let provider = store
            .get_dns_provider(provider_id)
            .map_err(|e| ApiError::Internal(format!("failed to fetch DNS provider: {e}")))?
            .ok_or_else(|| ApiError::NotFound(format!("dns_provider {provider_id}")))?;
        drop(store);
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
    )
    .await;

    match result {
        Ok(cert_id) => {
            info!(domains = ?domains, cert_id = %cert_id, "ACME DNS-01 certificate provisioned");
            Ok(json_data(AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: primary_domain,
                staging: config.staging,
                message: format!(
                    "Certificate provisioned via DNS-01 for {} domain(s) (id: {cert_id})",
                    domains.len()
                ),
            }))
        }
        Err(e) => {
            warn!(domains = ?domains, error = %e, "ACME DNS-01 provisioning failed");
            Err(ApiError::Internal(format!(
                "ACME DNS-01 provisioning failed: {e}"
            )))
        }
    }
}

/// Strip the `*.` prefix from a wildcard domain to get the base domain
/// for the `_acme-challenge` TXT record.
pub(super) fn acme_dns_base_domain(domain: &str) -> &str {
    domain.strip_prefix("*.").unwrap_or(domain)
}

/// Internal ACME provisioning logic using DNS-01 challenge.
/// Supports multi-domain and wildcard certificates.
///
/// `acme_method` is stored on the certificate (e.g. "dns01-cloudflare").
/// `encrypted_dns_config` is the encrypted JSON of the DNS credentials (legacy).
/// `dns_provider_id` references a global DNS provider (new approach).
pub(super) async fn provision_with_acme_dns(
    state: &AppState,
    config: &AcmeConfig,
    domains: &[String],
    challenger: &dyn DnsChallenger,
    acme_method: &str,
    dns_provider_id: Option<String>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

    let primary_domain = &domains[0];

    // Create or load ACME account
    let contact = config.contact_email.as_ref().map(|e| format!("mailto:{e}"));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

    let (account, _) = Account::create(
        &NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        config.directory_url(),
        None,
    )
    .await?;

    // Create order with all domains as identifiers
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    // Get authorizations (one per domain)
    let authorizations = order.authorizations().await?;

    // Phase 1: Create all TXT records before signaling readiness
    // Track (base_domain, challenge_url) for cleanup and signaling
    let mut challenge_info: Vec<(String, String)> = Vec::new(); // (base_domain, challenge_url)

    for auth in &authorizations {
        if matches!(auth.status, AuthorizationStatus::Valid) {
            continue;
        }

        // Find DNS-01 challenge
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or("no DNS-01 challenge available")?;

        let key_authorization = order.key_authorization(challenge);

        // For DNS-01, the TXT record value is the base64url-encoded SHA-256 digest
        // of the key authorization.
        use base64::Engine;
        use ring::digest;
        let digest_val = digest::digest(&digest::SHA256, key_authorization.as_str().as_bytes());
        let txt_value =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest_val.as_ref());

        // For wildcards, strip the `*.` prefix for the TXT record domain
        let auth_domain = match &auth.identifier {
            Identifier::Dns(d) => d.clone(),
        };
        let base_domain = acme_dns_base_domain(&auth_domain).to_string();

        // Create TXT record via DNS provider
        challenger
            .create_txt_record(&base_domain, &txt_value)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

        challenge_info.push((base_domain, challenge.url.clone()));
    }

    // Wait for DNS propagation
    info!(domains = ?domains, "waiting for DNS propagation (30s)");
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    // Phase 2: Signal readiness for all challenges
    for (_, url) in &challenge_info {
        order.set_challenge_ready(url).await?;
    }

    // Phase 3: Wait for all authorizations to become valid
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let fresh_auths = order.authorizations().await?;

        let all_valid = fresh_auths
            .iter()
            .all(|a| matches!(a.status, AuthorizationStatus::Valid));
        if all_valid {
            break;
        }

        let any_invalid = fresh_auths
            .iter()
            .any(|a| matches!(a.status, AuthorizationStatus::Invalid));
        if any_invalid {
            // Clean up all TXT records before returning error
            for (base_domain, _) in &challenge_info {
                let _ = challenger.delete_txt_record(base_domain).await;
            }
            let failed: Vec<String> = fresh_auths
                .iter()
                .filter(|a| matches!(a.status, AuthorizationStatus::Invalid))
                .map(|a| format!("{:?}", a.identifier))
                .collect();
            return Err(format!(
                "DNS-01 challenge validation failed for: {}",
                failed.join(", ")
            )
            .into());
        }

        attempts += 1;
        if attempts > 24 {
            // Clean up all TXT records before returning error
            for (base_domain, _) in &challenge_info {
                let _ = challenger.delete_txt_record(base_domain).await;
            }
            return Err("DNS-01 challenge validation timed out after 120s".into());
        }
    }

    // Clean up all TXT records
    for (base_domain, _) in &challenge_info {
        if let Err(e) = challenger.delete_txt_record(base_domain).await {
            warn!(domain = %base_domain, error = %e, "failed to clean up DNS TXT record");
        }
    }

    // Generate CSR with all domains as SANs and finalize order
    let mut params = rcgen::CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let private_key = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;

    order.finalize(csr.der()).await?;

    // Wait for certificate issuance
    let mut attempts = 0;
    let cert_pem = loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let order_state = order.state();
        match order_state.status {
            OrderStatus::Valid => {
                let cert = order.certificate().await?;
                break cert.ok_or("no certificate returned")?;
            }
            OrderStatus::Processing => {
                attempts += 1;
                if attempts > 30 {
                    return Err("certificate issuance timed out".into());
                }
                order.refresh().await?;
            }
            status => {
                return Err(format!("unexpected order status: {status:?}").into());
            }
        }
    };

    let key_pem = private_key.serialize_pem();

    // Store certificate in database
    let now = chrono::Utc::now();
    let cert_id = uuid::Uuid::new_v4().to_string();
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
        created_at: now,
        acme_method: Some(acme_method.to_string()),

        acme_dns_provider_id: dns_provider_id,
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;
    crate::cert_export::export_from_store(&store, &cert);
    drop(store);
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(cert_id)
}
