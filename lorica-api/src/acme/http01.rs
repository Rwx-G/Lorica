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
        RetryPolicy,
    };

    let primary_domain = &domains[0];

    // Create or load ACME account
    let contact = config.contact_email.as_ref().map(|e| format!("mailto:{e}"));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

    // instant-acme 0.8 (audit L-15) : Account creation goes
    // through a builder, NewOrder needs the public constructor.
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

    // Create order with all domains as identifiers
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    // instant-acme 0.8 (audit L-15) : authorizations is now a
    // stream-style iterator yielding `AuthorizationHandle`s ;
    // we iterate once, store each token + signal readiness on
    // the same handle, then poll the order for "all auths
    // valid" via the new `poll_ready` helper. Cleanup of stored
    // tokens happens in both the success and failure paths so
    // the proxy never serves a stale challenge after the order
    // resolves.
    let mut authorizations = order.authorizations();
    let mut stored_tokens: Vec<String> = Vec::new();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        if matches!(authz.status, AuthorizationStatus::Valid) {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or("no HTTP-01 challenge available")?;
        let key_authorization = challenge.key_authorization();
        let token = challenge.token.clone();
        if let Some(ref store) = state.acme_challenge_store {
            store
                .set(token.clone(), key_authorization.as_str().to_string())
                .await;
        }
        stored_tokens.push(token);
        challenge.set_ready().await?;
    }
    // `authorizations` borrows `order` ; let NLL release the borrow
    // here so the next `order.poll_ready()` call can re-borrow mut.
    let _ = authorizations;

    // Wait for all authorizations to become valid (or hit a
    // terminal failure). `poll_ready` exponentially backs off
    // and returns the final OrderStatus.
    let ready_status = order.poll_ready(&RetryPolicy::default()).await?;

    // Clean up all challenge tokens regardless of outcome - the
    // proxy must not serve a stale token after the order
    // resolves either way.
    if let Some(ref store) = state.acme_challenge_store {
        for token in &stored_tokens {
            store.remove(token).await;
        }
    }

    if ready_status != OrderStatus::Ready {
        return Err(format!(
            "ACME challenge validation did not reach Ready: {ready_status:?}"
        )
        .into());
    }

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
    // PEM-encoded certificate chain on success ; the helper
    // handles `Processing` -> `Valid` transitions internally
    // and replaces the v0.7-era manual sleep-and-refresh loop.
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("certificate poll failed: {e}"))?;

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
    let export_snapshot = crate::cert_export::snapshot_export_inputs(&store);
    drop(store);
    // v1.5.1 audit M-9 : disk export off-loaded to spawn_blocking
    // and dispatched AFTER the store mutex is released.
    if let Some((settings, acls)) = export_snapshot {
        crate::cert_export::export_after_release(settings, acls, cert).await;
    }
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(cert_id)
}
