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
        RetryPolicy,
    };

    let primary_domain = &domains[0];

    // Create or load ACME account
    let contact = config.contact_email.as_ref().map(|e| format!("mailto:{e}"));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

    // instant-acme 0.8 (audit L-15) : `Account::create` moved to
    // a builder-mediated path. The builder owns the HTTP client
    // (default `hyper-rustls` feature) ; `directory_url` is now
    // an owned `String` ; the rest of the shape is preserved.
    let (account, _) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url().to_string(),
            None,
        )
        .await?;

    // Create order with all domains as identifiers. instant-acme
    // 0.8 made `NewOrder`'s extra fields (`replaces`, `profile`)
    // private and exposes a `NewOrder::new(&identifiers)`
    // constructor as the public entry point.
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // instant-acme 0.8 (audit L-15) : authorizations is a
    // stream-style iterator and ChallengeHandle borrows the
    // order, so we cannot keep all challenge handles alive
    // across two phases. Strategy : (1) walk the iterator once
    // to collect challenge metadata (token + key_authorization
    // + identifier) AND create the TXT records ; (2) sleep for
    // DNS propagation ; (3) walk the iterator a SECOND time to
    // call set_ready on each challenge ; (4) poll_ready for
    // global readiness. Cleanup of TXT records always runs in
    // both happy and error paths so the DNS provider does not
    // accumulate stale `_acme-challenge.<host>` rows.
    let mut created_records: Vec<String> = Vec::new(); // base_domains we created TXT for

    // Phase 1 : create TXT records.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if matches!(authz.status, AuthorizationStatus::Valid) {
                continue;
            }
            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or("no DNS-01 challenge available")?;
            let key_authorization = challenge.key_authorization();

            // For DNS-01, the TXT record value is the
            // base64url-encoded SHA-256 digest of the key
            // authorization.
            use base64::Engine;
            use ring::digest;
            let digest_val = digest::digest(&digest::SHA256, key_authorization.as_str().as_bytes());
            let txt_value =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest_val.as_ref());

            // For wildcards, strip the `*.` prefix for the TXT
            // record domain. `challenge.identifier()` gives an
            // `AuthorizedIdentifier` whose Display is the
            // hostname (matching the legacy
            // `Identifier::Dns(d).clone()` extraction).
            let auth_domain = challenge.identifier().to_string();
            let base_domain = acme_dns_base_domain(&auth_domain).to_string();

            challenger
                .create_txt_record(&base_domain, &txt_value)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

            created_records.push(base_domain);
        }
    }

    // Wait for DNS propagation
    info!(domains = ?domains, "waiting for DNS propagation (30s)");
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    // Phase 2 : signal readiness for all challenges by walking
    // the authorizations again. The second walk re-fetches
    // server state so set_ready transitions the now-pending
    // challenge into PROCESSING.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if matches!(authz.status, AuthorizationStatus::Valid) {
                continue;
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or("no DNS-01 challenge available")?;
            challenge.set_ready().await?;
        }
    }

    // Phase 3 : wait for all authorizations to become valid (or
    // hit a terminal failure). `poll_ready` exponentially backs
    // off and returns the final OrderStatus.
    let ready_status = order.poll_ready(&RetryPolicy::default()).await;

    // Cleanup TXT records regardless of poll outcome.
    for base_domain in &created_records {
        let _ = challenger.delete_txt_record(base_domain).await;
    }

    let ready_status = ready_status?;
    if ready_status != OrderStatus::Ready {
        return Err(format!(
            "DNS-01 challenge validation did not reach Ready: {ready_status:?}"
        )
        .into());
    }

    // (TXT-record cleanup already happened just before the
    // poll_ready check above ; no second pass needed.)

    // Generate CSR with all domains as SANs and finalize order.
    // `finalize_csr` is the explicit-CSR variant in 0.8 ; the
    // sibling `finalize()` would use a fresh rcgen key generated
    // by the crate (requires the `rcgen` feature, which we do
    // not enable - see `Cargo.toml`).
    let mut params = rcgen::CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let private_key = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;

    order.finalize_csr(csr.der()).await?;

    // Poll for issuance with exponential backoff. Returns the
    // PEM-encoded certificate chain on success.
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("certificate poll failed: {e}"))?;

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
    let export_snapshot = crate::cert_export::snapshot_export_inputs(&store);
    drop(store);
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
