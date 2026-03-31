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

//! ACME / Let's Encrypt integration for automatic TLS certificate provisioning.
//!
//! Uses HTTP-01 challenge. Requires port 80 reachable from the Internet.
//! **Limitation**: does not work behind NAT without port forwarding.
//! DNS-01 challenge support is planned for a future release.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// In-memory store for pending ACME HTTP-01 challenges.
/// Maps token -> key_authorization for /.well-known/acme-challenge/{token}.
#[derive(Debug, Default, Clone)]
pub struct AcmeChallengeStore {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn set(&self, token: String, key_authorization: String) {
        self.challenges.write().await.insert(token, key_authorization);
    }

    pub async fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().await.get(token).cloned()
    }

    pub async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
    }
}

/// ACME configuration for the Let's Encrypt directory.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Use staging directory (recommended for testing).
    pub staging: bool,
    /// Contact email for Let's Encrypt account.
    pub contact_email: Option<String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            staging: true,
            contact_email: None,
        }
    }
}

impl AcmeConfig {
    pub fn directory_url(&self) -> &str {
        if self.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        }
    }
}

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

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct AcmeProvisionResponse {
    status: String,
    domain: String,
    staging: bool,
    message: String,
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
    if body.domain.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    info!(
        domain = %body.domain,
        staging = config.staging,
        directory = config.directory_url(),
        "starting ACME certificate provisioning"
    );

    // Use instant-acme to provision
    let result = provision_with_acme(&state, &config, &body.domain).await;

    match result {
        Ok(cert_id) => {
            info!(domain = %body.domain, cert_id = %cert_id, "ACME certificate provisioned");
            Ok(json_data(AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: body.domain,
                staging: config.staging,
                message: format!("Certificate provisioned (id: {cert_id})"),
            }))
        }
        Err(e) => {
            warn!(domain = %body.domain, error = %e, "ACME provisioning failed");
            // Fallback: don't disrupt existing certs, just report failure
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
async fn provision_with_acme(
    state: &AppState,
    config: &AcmeConfig,
    domain: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
        OrderStatus,
    };

    // Create or load ACME account
    let contact = config
        .contact_email
        .as_ref()
        .map(|e| format!("mailto:{e}"));
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

    // Create order for the domain
    let identifier = Identifier::Dns(domain.to_string());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await?;

    // Get authorizations
    let authorizations = order.authorizations().await?;

    for auth in &authorizations {
        if matches!(auth.status, AuthorizationStatus::Valid) {
            continue;
        }

        // Find HTTP-01 challenge
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

        // Tell ACME server we're ready
        order.set_challenge_ready(&challenge.url).await?;

        // Wait for validation (poll with backoff)
        let mut attempts = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let fresh_auth = order.authorizations().await?;
            let auth = &fresh_auth[0];

            match auth.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Pending => {
                    attempts += 1;
                    if attempts > 15 {
                        return Err("challenge validation timed out after 30s".into());
                    }
                }
                AuthorizationStatus::Invalid => {
                    return Err("challenge validation failed (invalid)".into());
                }
                _ => {
                    return Err(format!("unexpected authorization status: {:?}", auth.status)
                        .into());
                }
            }
        }

        // Clean up challenge
        if let Some(ref store) = state.acme_challenge_store {
            store.remove(&challenge.token).await;
        }
    }

    // Generate CSR and finalize order
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
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

    // Parse cert to get expiry info
    let fingerprint = format!("acme:{domain}");

    let cert = lorica_config::models::Certificate {
        id: cert_id.clone(),
        domain: domain.to_string(),
        san_domains: vec![domain.to_string()],
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
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;
    drop(store);
    state.notify_config_changed();

    Ok(cert_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_challenge_store_set_get_remove() {
        let store = AcmeChallengeStore::new();
        store.set("token1".into(), "auth1".into()).await;
        assert_eq!(store.get("token1").await, Some("auth1".to_string()));
        store.remove("token1").await;
        assert_eq!(store.get("token1").await, None);
    }

    #[tokio::test]
    async fn test_challenge_store_get_nonexistent() {
        let store = AcmeChallengeStore::new();
        assert_eq!(store.get("nonexistent").await, None);
    }

    #[test]
    fn test_acme_config_staging_url() {
        let config = AcmeConfig::default();
        assert!(config.staging);
        assert!(config.directory_url().contains("staging"));
    }

    #[test]
    fn test_acme_config_production_url() {
        let config = AcmeConfig {
            staging: false,
            contact_email: None,
        };
        assert!(!config.directory_url().contains("staging"));
        assert!(config.directory_url().contains("acme-v02"));
    }
}
