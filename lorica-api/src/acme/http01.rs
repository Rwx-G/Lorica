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

//! HTTP-01 challenge provisioning: axum endpoints and the internal flow.

use axum::extract::{Extension, Path};
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

use super::config::AcmeConfig;
use super::types::{default_true, AcmeProvisionResponse};

/// Request body for ACME certificate provisioning.
#[derive(Debug, Deserialize)]
pub struct AcmeProvisionRequest {
    /// Domain to provision certificate for.
    pub domain: String,
    /// Whether to use staging environment.
    #[serde(default = "default_true")]
    pub staging: bool,
    /// Contact email for Let's Encrypt.
    pub contact_email: Option<String>,
}

/// POST /api/v1/acme/provision - Initiate ACME certificate provisioning.
///
/// This is a long-running operation. It creates an ACME order, responds to
/// the HTTP-01 challenge, and waits for certificate issuance.
///
/// **Requires**: port 80 reachable from the Internet for HTTP-01 challenge.
pub async fn provision_certificate(
    Extension(state): Extension<AppState>,
    Json(body): Json<AcmeProvisionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Support multi-domain: "www.rwx-g.fr, rwx-g.fr" or "www.rwx-g.fr,rwx-g.fr"
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

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    info!(
        domains = ?domains,
        staging = config.staging,
        directory = config.directory_url(),
        "starting ACME certificate provisioning"
    );

    let result = provision_with_acme(&state, &config, &domains).await;

    match result {
        Ok(cert_id) => {
            info!(domains = ?domains, cert_id = %cert_id, "ACME certificate provisioned");
            Ok(json_data(AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: primary_domain,
                staging: config.staging,
                message: format!(
                    "Certificate provisioned for {} domain(s) (id: {cert_id})",
                    domains.len()
                ),
            }))
        }
        Err(e) => {
            warn!(domains = ?domains, error = %e, "ACME provisioning failed");
            Err(ApiError::Internal(format!("ACME provisioning failed: {e}")))
        }
    }
}

/// GET /api/v1/acme/challenge/{token} - Serve HTTP-01 challenge response.
///
/// This endpoint is also served on the proxy port (80) for Let's Encrypt
/// validation. The proxy must forward /.well-known/acme-challenge/* here.
pub async fn serve_challenge(
    Extension(state): Extension<AppState>,
    Path(token): Path<String>,
) -> Result<String, ApiError> {
    let challenge_store = state
        .acme_challenge_store
        .as_ref()
        .ok_or_else(|| ApiError::NotFound("ACME not initialized".into()))?;

    challenge_store
        .get(&token)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("challenge token {token} not found")))
}

/// Internal ACME provisioning logic using instant-acme.
/// Supports multi-domain SAN certificates (one order, N challenges).
pub(super) async fn provision_with_acme(
    state: &AppState,
    config: &AcmeConfig,
    domains: &[String],
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

    // Phase 1: Store all challenge tokens before signaling readiness
    let mut challenge_info: Vec<(String, String)> = Vec::new(); // (token, challenge_url)
    for auth in &authorizations {
        if matches!(auth.status, AuthorizationStatus::Valid) {
            continue;
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or("no HTTP-01 challenge available")?;

        let key_authorization = order.key_authorization(challenge);

        // Store challenge response for the proxy to serve
        if let Some(ref store) = state.acme_challenge_store {
            store
                .set(
                    challenge.token.clone(),
                    key_authorization.as_str().to_string(),
                )
                .await;
        }

        challenge_info.push((challenge.token.clone(), challenge.url.clone()));
    }

    // Phase 2: Signal readiness for all challenges
    for (_, url) in &challenge_info {
        order.set_challenge_ready(url).await?;
    }

    // Phase 3: Wait for all authorizations to become valid
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
            // Find which domain failed
            let failed: Vec<String> = fresh_auths
                .iter()
                .filter(|a| matches!(a.status, AuthorizationStatus::Invalid))
                .map(|a| format!("{:?}", a.identifier))
                .collect();
            return Err(format!("challenge validation failed for: {}", failed.join(", ")).into());
        }

        attempts += 1;
        if attempts > 15 {
            return Err("challenge validation timed out after 30s".into());
        }
    }

    // Clean up all challenge tokens
    if let Some(ref store) = state.acme_challenge_store {
        for (token, _) in &challenge_info {
            store.remove(token).await;
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
        let state = order.state();
        match state.status {
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
    let san_domains: Vec<String> = domains.to_vec();
    let fingerprint = format!("acme:{}", domains.join(","));

    let cert = lorica_config::models::Certificate {
        id: cert_id.clone(),
        domain: primary_domain.clone(),
        san_domains,
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
        acme_method: Some("http01".into()),

        acme_dns_provider_id: None,
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;
    drop(store);
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(cert_id)
}
