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
//! Supports three challenge modes:
//! - **HTTP-01**: Requires port 80 reachable from the Internet.
//! - **DNS-01 (automated)**: Creates a `_acme-challenge.{domain}` TXT record via DNS
//!   provider API. Supports Cloudflare and AWS Route53.
//! - **DNS-01 (manual)**: Returns the TXT record info for the user to create manually,
//!   then confirms the challenge in a second step.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Path};
use axum::Json;
use dashmap::DashMap;
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
        self.challenges
            .write()
            .await
            .insert(token, key_authorization);
    }

    pub async fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().await.get(token).cloned()
    }

    pub async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
    }
}

/// In-memory store for pending manual DNS-01 challenges.
///
/// Maps domain name to the pending challenge state. Entries are created by
/// `provision_dns_manual` (step 1) and consumed by `provision_dns_manual_confirm`
/// (step 2). Entries older than 10 minutes are considered expired.
pub type PendingDnsChallenges = Arc<DashMap<String, PendingDnsChallenge>>;

/// State for a pending manual DNS-01 challenge between the two-step flow.
pub struct PendingDnsChallenge {
    /// The order URL so we can restore the order from the ACME account.
    pub order_url: String,
    /// The challenge URL to mark as ready.
    pub challenge_url: String,
    /// The TXT record value the user must create.
    pub txt_value: String,
    /// Serialized account credentials (JSON) to restore the ACME account.
    pub account_credentials_json: String,
    /// Whether this was issued against the staging directory.
    pub staging: bool,
    /// Contact email used for the ACME account.
    pub contact_email: Option<String>,
    /// When this pending challenge was created (for expiry).
    pub created_at: Instant,
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
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

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
                    return Err(
                        format!("unexpected authorization status: {:?}", auth.status).into(),
                    );
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
    tokio::spawn(async move {
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

                let config = AcmeConfig {
                    staging: cert.issuer.contains("STAGING"),
                    contact_email: None,
                };

                match provision_with_acme(&state, &config, &cert.domain).await {
                    Ok(new_cert_id) => {
                        info!(
                            domain = %cert.domain,
                            old_cert_id = %cert.id,
                            new_cert_id = %new_cert_id,
                            "ACME certificate renewed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            domain = %cert.domain,
                            error = %e,
                            days_remaining = days_remaining,
                            "ACME renewal failed - existing cert still active"
                        );
                    }
                }
            }
        }
    })
}

/// Check all certificates for upcoming expiration and dispatch alerts.
///
/// This is a pure logic function (no loop, no sleep) so it can be unit-tested.
/// It reads `cert_warning_days` and `cert_critical_days` from `GlobalSettings`
/// and sends `CertExpiring` alerts for every certificate within those thresholds.
pub async fn check_cert_expiry(
    state: &AppState,
    alert_sender: &lorica_notify::AlertSender,
) {
    let (certs, settings) = {
        let store = state.store.lock().await;
        let certs = match store.list_certificates() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "cert expiry check: failed to list certificates");
                return;
            }
        };
        let settings = match store.get_global_settings() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "cert expiry check: failed to load global settings");
                return;
            }
        };
        (certs, settings)
    };

    let warning_days = i64::from(settings.cert_warning_days);
    let critical_days = i64::from(settings.cert_critical_days);
    let now = chrono::Utc::now();

    for cert in &certs {
        let days_remaining = (cert.not_after - now).num_days();

        if days_remaining > warning_days {
            continue;
        }

        let summary = if days_remaining <= critical_days {
            format!(
                "CRITICAL: Certificate for {} expires in {} days",
                cert.domain, days_remaining
            )
        } else {
            format!(
                "Certificate for {} expires in {} days",
                cert.domain, days_remaining
            )
        };

        info!(
            domain = %cert.domain,
            days_remaining = days_remaining,
            is_acme = cert.is_acme,
            "cert expiry check: certificate approaching expiry"
        );

        alert_sender.send(
            lorica_notify::AlertEvent::new(
                lorica_notify::events::AlertType::CertExpiring,
                summary,
            )
            .with_detail("domain", cert.domain.clone())
            .with_detail("days_remaining", days_remaining.to_string())
            .with_detail("cert_id", cert.id.clone())
            .with_detail("is_acme", cert.is_acme.to_string()),
        );
    }
}

/// Spawn a background task that periodically checks ALL certificates for expiration.
///
/// Unlike `spawn_renewal_task` which only handles ACME auto-renew certs, this task
/// alerts on every certificate (ACME or manual) that is within the warning/critical
/// thresholds defined in `GlobalSettings`.
pub fn spawn_cert_expiry_check_task(
    state: AppState,
    check_interval: std::time::Duration,
    alert_sender: lorica_notify::AlertSender,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        check_cert_expiry(&state, &alert_sender).await;
        loop {
            tokio::time::sleep(check_interval).await;
            check_cert_expiry(&state, &alert_sender).await;
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

    let new_cert_id = provision_with_acme(&state, &config, &cert.domain)
        .await
        .map_err(|e| ApiError::Internal(format!("ACME renewal failed: {e}")))?;

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

// ---------------------------------------------------------------------------
// DNS-01 challenge support
// ---------------------------------------------------------------------------

/// Configuration for DNS-01 ACME challenges.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsChallengeConfig {
    /// DNS provider: `"cloudflare"` or `"route53"`.
    pub provider: String,
    /// Zone identifier (Cloudflare zone ID or Route53 hosted zone ID).
    pub zone_id: String,
    /// API token (Cloudflare API token or AWS access key ID).
    pub api_token: String,
    /// Optional secret (AWS secret access key). Not used for Cloudflare.
    pub api_secret: Option<String>,
}

impl DnsChallengeConfig {
    /// Validate the configuration and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.provider != "cloudflare" && self.provider != "route53" {
            return Err(format!(
                "unsupported DNS provider '{}': expected 'cloudflare' or 'route53'",
                self.provider
            ));
        }
        if self.zone_id.is_empty() {
            return Err("zone_id is required".into());
        }
        if self.api_token.is_empty() {
            return Err("api_token is required".into());
        }
        if self.provider == "route53" && self.api_secret.as_ref().is_none_or(|s| s.is_empty()) {
            return Err("api_secret is required for route53 provider".into());
        }
        Ok(())
    }
}

/// Trait for DNS providers that can create and delete ACME challenge TXT records.
#[async_trait::async_trait]
pub trait DnsChallenger: Send + Sync {
    /// Create a TXT record at `_acme-challenge.{domain}` with the given value.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String>;
    /// Delete the TXT record at `_acme-challenge.{domain}`.
    async fn delete_txt_record(&self, domain: &str) -> Result<(), String>;
}

/// Cloudflare DNS-01 challenger using the Cloudflare API v4.
pub struct CloudflareDnsChallenger {
    zone_id: String,
    api_token: String,
    client: reqwest::Client,
}

impl CloudflareDnsChallenger {
    pub fn new(zone_id: String, api_token: String) -> Self {
        Self {
            zone_id,
            api_token,
            client: reqwest::Client::new(),
        }
    }

    /// Find the record ID for a given TXT record name.
    async fn find_record_id(&self, name: &str) -> Result<Option<String>, String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            self.zone_id, name
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| format!("Cloudflare API request failed: {e}"))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Cloudflare API response parse error: {e}"))?;

        if let Some(results) = body.get("result").and_then(|r| r.as_array()) {
            if let Some(record) = results.first() {
                if let Some(id) = record.get("id").and_then(|v| v.as_str()) {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl DnsChallenger for CloudflareDnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let record_name = format!("_acme-challenge.{domain}");
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let payload = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Cloudflare create TXT record failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API returned {status}: {body}"));
        }

        info!(domain = %domain, record = %record_name, "Cloudflare DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let record_name = format!("_acme-challenge.{domain}");
        let record_id = self
            .find_record_id(&record_name)
            .await?
            .ok_or_else(|| format!("TXT record '{record_name}' not found for deletion"))?;

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{record_id}",
            self.zone_id
        );

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| format!("Cloudflare delete TXT record failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API delete returned {status}: {body}"));
        }

        info!(domain = %domain, record = %record_name, "Cloudflare DNS TXT record deleted");
        Ok(())
    }
}

/// AWS Route53 DNS-01 challenger using the official AWS SDK.
#[cfg(feature = "route53")]
pub struct Route53DnsChallenger {
    hosted_zone_id: String,
    client: aws_sdk_route53::Client,
    /// Track created TXT values so DELETE can provide the exact value.
    created_values: parking_lot::Mutex<std::collections::HashMap<String, String>>,
}

#[cfg(feature = "route53")]
impl Route53DnsChallenger {
    pub async fn new(hosted_zone_id: String, access_key: String, secret_key: String) -> Self {
        let creds = aws_sdk_route53::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "lorica-acme",
        );
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .load()
            .await;
        let client = aws_sdk_route53::Client::new(&config);
        Self {
            hosted_zone_id,
            client,
            created_values: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn change_record(
        &self,
        action: aws_sdk_route53::types::ChangeAction,
        domain: &str,
        value: &str,
    ) -> Result<(), String> {
        use aws_sdk_route53::types::{
            Change, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
        };

        let record_name = format!("_acme-challenge.{domain}.");
        let txt_value = format!("\"{value}\"");

        let record_set = ResourceRecordSet::builder()
            .name(&record_name)
            .r#type(RrType::Txt)
            .ttl(120)
            .resource_records(
                ResourceRecord::builder()
                    .value(&txt_value)
                    .build()
                    .map_err(|e| format!("Route53 record build error: {e}"))?,
            )
            .build()
            .map_err(|e| format!("Route53 record set build error: {e}"))?;

        let change = Change::builder()
            .action(action)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| format!("Route53 change build error: {e}"))?;

        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| format!("Route53 batch build error: {e}"))?;

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| format!("Route53 API error: {e}"))?;

        Ok(())
    }
}

#[cfg(feature = "route53")]
#[async_trait::async_trait]
impl DnsChallenger for Route53DnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        self.change_record(aws_sdk_route53::types::ChangeAction::Upsert, domain, value)
            .await?;
        self.created_values
            .lock()
            .insert(domain.to_string(), value.to_string());
        info!(domain = %domain, "Route53 DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let value = self
            .created_values
            .lock()
            .remove(domain)
            .unwrap_or_default();
        if value.is_empty() {
            warn!(domain = %domain, "Route53 delete: no tracked value, skipping");
            return Ok(());
        }
        self.change_record(aws_sdk_route53::types::ChangeAction::Delete, domain, &value)
            .await?;
        info!(domain = %domain, "Route53 DNS TXT record deleted");
        Ok(())
    }
}

/// Build a `DnsChallenger` from a `DnsChallengeConfig`.
pub async fn build_dns_challenger(
    config: &DnsChallengeConfig,
) -> Result<Box<dyn DnsChallenger>, String> {
    config.validate()?;
    match config.provider.as_str() {
        "cloudflare" => Ok(Box::new(CloudflareDnsChallenger::new(
            config.zone_id.clone(),
            config.api_token.clone(),
        ))),
        #[cfg(feature = "route53")]
        "route53" => Ok(Box::new(
            Route53DnsChallenger::new(
                config.zone_id.clone(),
                config.api_token.clone(),
                config.api_secret.clone().unwrap_or_default(),
            )
            .await,
        )),
        #[cfg(not(feature = "route53"))]
        "route53" => Err("route53 provider requires the 'route53' feature flag".into()),
        other => Err(format!("unsupported DNS provider: {other}")),
    }
}

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
    /// DNS provider configuration.
    pub dns: DnsChallengeConfig,
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
    if body.domain.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }

    if let Err(e) = body.dns.validate() {
        return Err(ApiError::BadRequest(format!("invalid DNS config: {e}")));
    }

    let challenger = build_dns_challenger(&body.dns)
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to build DNS challenger: {e}")))?;

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    info!(
        domain = %body.domain,
        staging = config.staging,
        provider = %body.dns.provider,
        directory = config.directory_url(),
        "starting ACME DNS-01 certificate provisioning"
    );

    let result = provision_with_acme_dns(&state, &config, &body.domain, challenger.as_ref()).await;

    match result {
        Ok(cert_id) => {
            info!(domain = %body.domain, cert_id = %cert_id, "ACME DNS-01 certificate provisioned");
            Ok(json_data(AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: body.domain,
                staging: config.staging,
                message: format!("Certificate provisioned via DNS-01 (id: {cert_id})"),
            }))
        }
        Err(e) => {
            warn!(domain = %body.domain, error = %e, "ACME DNS-01 provisioning failed");
            Err(ApiError::Internal(format!(
                "ACME DNS-01 provisioning failed: {e}"
            )))
        }
    }
}

/// Internal ACME provisioning logic using DNS-01 challenge.
async fn provision_with_acme_dns(
    state: &AppState,
    config: &AcmeConfig,
    domain: &str,
    challenger: &dyn DnsChallenger,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

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
        let digest = digest::digest(&digest::SHA256, key_authorization.as_str().as_bytes());
        let txt_value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

        // Create TXT record via DNS provider
        challenger
            .create_txt_record(domain, &txt_value)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

        // Wait for DNS propagation
        info!(domain = %domain, "waiting for DNS propagation (30s)");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        // Tell ACME server we're ready
        order.set_challenge_ready(&challenge.url).await?;

        // Wait for validation (poll with backoff)
        let mut attempts = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let fresh_auth = order.authorizations().await?;
            let auth = &fresh_auth[0];

            match auth.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Pending => {
                    attempts += 1;
                    if attempts > 24 {
                        // Clean up TXT record before returning error
                        let _ = challenger.delete_txt_record(domain).await;
                        return Err("DNS-01 challenge validation timed out after 120s".into());
                    }
                }
                AuthorizationStatus::Invalid => {
                    let _ = challenger.delete_txt_record(domain).await;
                    return Err("DNS-01 challenge validation failed (invalid)".into());
                }
                _ => {
                    let _ = challenger.delete_txt_record(domain).await;
                    return Err(
                        format!("unexpected authorization status: {:?}", auth.status).into(),
                    );
                }
            }
        }

        // Clean up TXT record
        if let Err(e) = challenger.delete_txt_record(domain).await {
            warn!(domain = %domain, error = %e, "failed to clean up DNS TXT record");
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
    let fingerprint = format!("acme-dns:{domain}");

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

// ---------------------------------------------------------------------------
// DNS-01 manual (two-step) challenge support
// ---------------------------------------------------------------------------

/// Maximum age for a pending manual DNS challenge before it is considered expired.
const PENDING_DNS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600); // 10 min

/// Request body for step 1: initiate a manual DNS-01 challenge.
#[derive(Debug, Deserialize)]
pub struct AcmeDnsManualRequest {
    /// Domain to provision a certificate for.
    pub domain: String,
    /// Whether to use the staging environment.
    #[serde(default = "default_true")]
    pub staging: bool,
    /// Contact email for the Let's Encrypt account.
    pub contact_email: Option<String>,
}

/// Response for step 1: the TXT record the user must create.
#[derive(Debug, Serialize)]
struct AcmeDnsManualResponse {
    status: String,
    domain: String,
    txt_record_name: String,
    txt_record_value: String,
    message: String,
}

/// Request body for step 2: confirm that the TXT record has been created.
#[derive(Debug, Deserialize)]
pub struct AcmeDnsManualConfirmRequest {
    /// The domain whose pending challenge should be confirmed.
    pub domain: String,
}

/// POST /api/v1/acme/provision-dns-manual - Step 1 of manual DNS-01 flow.
///
/// Creates an ACME order and extracts the DNS-01 challenge, but does NOT create
/// the TXT record. Instead it returns the record name and value so the user can
/// create it manually. The pending challenge is stored in memory.
pub async fn provision_dns_manual(
    Extension(state): Extension<AppState>,
    Json(body): Json<AcmeDnsManualRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    };

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
        "starting manual DNS-01 challenge (step 1)"
    );

    // Create ACME account
    let contact = config.contact_email.as_ref().map(|e| format!("mailto:{e}"));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        config.directory_url(),
        None,
    )
    .await
    .map_err(|e| ApiError::Internal(format!("ACME account creation failed: {e}")))?;

    // Create order
    let identifier = Identifier::Dns(body.domain.clone());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .map_err(|e| ApiError::Internal(format!("ACME order creation failed: {e}")))?;

    // Get authorizations and find DNS-01 challenge
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to get authorizations: {e}")))?;

    let auth = authorizations
        .first()
        .ok_or_else(|| ApiError::Internal("no authorizations returned".into()))?;

    if matches!(auth.status, AuthorizationStatus::Valid) {
        return Err(ApiError::BadRequest(
            "authorization already valid - no challenge needed".into(),
        ));
    }

    let challenge = auth
        .challenges
        .iter()
        .find(|c| c.r#type == ChallengeType::Dns01)
        .ok_or_else(|| ApiError::Internal("no DNS-01 challenge available".into()))?;

    let key_authorization = order.key_authorization(challenge);
    let txt_value = key_authorization.dns_value();
    let txt_record_name = format!("_acme-challenge.{}", body.domain);

    // Serialize account credentials for later restoration
    let credentials_json = serde_json::to_string(&credentials)
        .map_err(|e| ApiError::Internal(format!("failed to serialize credentials: {e}")))?;

    // Store the pending challenge
    let pending = PendingDnsChallenge {
        order_url: order.url().to_string(),
        challenge_url: challenge.url.clone(),
        txt_value: txt_value.clone(),
        account_credentials_json: credentials_json,
        staging: body.staging,
        contact_email: body.contact_email.clone(),
        created_at: Instant::now(),
    };

    state
        .pending_dns_challenges
        .insert(body.domain.clone(), pending);

    info!(
        domain = %body.domain,
        txt_record = %txt_record_name,
        "manual DNS-01 challenge created, waiting for user to set TXT record"
    );

    Ok(json_data(AcmeDnsManualResponse {
        status: "pending_dns".into(),
        domain: body.domain,
        txt_record_name,
        txt_record_value: txt_value,
        message: "Create a DNS TXT record with the above name and value, then call confirm.".into(),
    }))
}

/// POST /api/v1/acme/provision-dns-manual/confirm - Step 2 of manual DNS-01 flow.
///
/// The user calls this after creating the TXT record. Lorica tells Let's Encrypt
/// to verify the challenge, waits for validation, downloads the certificate, and
/// stores it in the database.
pub async fn provision_dns_manual_confirm(
    Extension(state): Extension<AppState>,
    Json(body): Json<AcmeDnsManualConfirmRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use instant_acme::{Account, AccountCredentials, AuthorizationStatus, OrderStatus};

    if body.domain.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }

    // Look up and remove the pending challenge
    let (_, pending) = state
        .pending_dns_challenges
        .remove(&body.domain)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "no pending DNS challenge for domain '{}'",
                body.domain
            ))
        })?;

    // Check expiry
    if pending.created_at.elapsed() > PENDING_DNS_MAX_AGE {
        return Err(ApiError::BadRequest(
            "pending DNS challenge has expired (>10 min) - please start over".into(),
        ));
    }

    info!(
        domain = %body.domain,
        "confirming manual DNS-01 challenge (step 2)"
    );

    // Restore ACME account from saved credentials
    let credentials: AccountCredentials =
        serde_json::from_str(&pending.account_credentials_json)
            .map_err(|e| ApiError::Internal(format!("failed to deserialize credentials: {e}")))?;

    let account = Account::from_credentials(credentials)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to restore ACME account: {e}")))?;

    // Restore the order
    let mut order = account
        .order(pending.order_url.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("failed to restore ACME order: {e}")))?;

    // Tell ACME server the challenge is ready
    order
        .set_challenge_ready(&pending.challenge_url)
        .await
        .map_err(|e| ApiError::Internal(format!("set_challenge_ready failed: {e}")))?;

    // Wait for validation (poll with backoff)
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let fresh_auth = order
            .authorizations()
            .await
            .map_err(|e| ApiError::Internal(format!("failed to poll authorizations: {e}")))?;
        let auth = &fresh_auth[0];

        match auth.status {
            AuthorizationStatus::Valid => break,
            AuthorizationStatus::Pending => {
                attempts += 1;
                if attempts > 24 {
                    return Err(ApiError::Internal(
                        "DNS-01 challenge validation timed out after 120s".into(),
                    ));
                }
            }
            AuthorizationStatus::Invalid => {
                return Err(ApiError::Internal(
                    "DNS-01 challenge validation failed (invalid) - check your TXT record".into(),
                ));
            }
            _ => {
                return Err(ApiError::Internal(format!(
                    "unexpected authorization status: {:?}",
                    auth.status
                )));
            }
        }
    }

    // Generate CSR and finalize order
    let mut params = rcgen::CertificateParams::new(vec![body.domain.clone()])
        .map_err(|e| ApiError::Internal(format!("CSR params error: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let private_key =
        rcgen::KeyPair::generate().map_err(|e| ApiError::Internal(format!("keygen error: {e}")))?;
    let csr = params
        .serialize_request(&private_key)
        .map_err(|e| ApiError::Internal(format!("CSR serialize error: {e}")))?;

    order
        .finalize(csr.der())
        .await
        .map_err(|e| ApiError::Internal(format!("order finalize failed: {e}")))?;

    // Wait for certificate issuance
    let mut attempts = 0;
    let cert_pem = loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let order_state = order.state();
        match order_state.status {
            OrderStatus::Valid => {
                let cert = order
                    .certificate()
                    .await
                    .map_err(|e| ApiError::Internal(format!("certificate download failed: {e}")))?;
                break cert.ok_or_else(|| ApiError::Internal("no certificate returned".into()))?;
            }
            OrderStatus::Processing => {
                attempts += 1;
                if attempts > 30 {
                    return Err(ApiError::Internal("certificate issuance timed out".into()));
                }
                order
                    .refresh()
                    .await
                    .map_err(|e| ApiError::Internal(format!("order refresh failed: {e}")))?;
            }
            status => {
                return Err(ApiError::Internal(format!(
                    "unexpected order status: {status:?}"
                )));
            }
        }
    };

    let key_pem = private_key.serialize_pem();

    // Store certificate in database
    let now = chrono::Utc::now();
    let cert_id = uuid::Uuid::new_v4().to_string();
    let fingerprint = format!("acme-dns-manual:{}", body.domain);

    let cert = lorica_config::models::Certificate {
        id: cert_id.clone(),
        domain: body.domain.clone(),
        san_domains: vec![body.domain.clone()],
        fingerprint,
        cert_pem,
        key_pem,
        issuer: if pending.staging {
            "(STAGING) Let's Encrypt".to_string()
        } else {
            "Let's Encrypt".to_string()
        },
        not_before: now,
        not_after: now + chrono::Duration::days(90),
        is_acme: true,
        acme_auto_renew: false, // manual mode cannot auto-renew
        created_at: now,
    };

    let store = state.store.lock().await;
    store
        .create_certificate(&cert)
        .map_err(|e| ApiError::Internal(format!("failed to store certificate: {e}")))?;
    drop(store);
    state.notify_config_changed();

    info!(
        domain = %body.domain,
        cert_id = %cert_id,
        "manual DNS-01 certificate provisioned"
    );

    Ok(json_data(AcmeProvisionResponse {
        status: "provisioned".into(),
        domain: body.domain,
        staging: pending.staging,
        message: format!("Certificate provisioned via manual DNS-01 (id: {cert_id})"),
    }))
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

    #[test]
    fn test_dns_config_valid_cloudflare() {
        let config = DnsChallengeConfig {
            provider: "cloudflare".into(),
            zone_id: "zone123".into(),
            api_token: "token456".into(),
            api_secret: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_dns_config_valid_route53() {
        let config = DnsChallengeConfig {
            provider: "route53".into(),
            zone_id: "Z1234567890".into(),
            api_token: "AKIAIOSFODNN7EXAMPLE".into(),
            api_secret: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_dns_config_invalid_provider() {
        let config = DnsChallengeConfig {
            provider: "godaddy".into(),
            zone_id: "zone123".into(),
            api_token: "token456".into(),
            api_secret: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("unsupported DNS provider"));
        assert!(err.contains("godaddy"));
    }

    #[test]
    fn test_dns_config_empty_zone_id() {
        let config = DnsChallengeConfig {
            provider: "cloudflare".into(),
            zone_id: "".into(),
            api_token: "token456".into(),
            api_secret: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("zone_id"));
    }

    #[test]
    fn test_dns_config_empty_api_token() {
        let config = DnsChallengeConfig {
            provider: "cloudflare".into(),
            zone_id: "zone123".into(),
            api_token: "".into(),
            api_secret: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("api_token"));
    }

    #[test]
    fn test_dns_config_route53_missing_secret() {
        let config = DnsChallengeConfig {
            provider: "route53".into(),
            zone_id: "Z1234567890".into(),
            api_token: "AKIAIOSFODNN7EXAMPLE".into(),
            api_secret: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("api_secret"));
    }

    #[test]
    fn test_dns_config_route53_empty_secret() {
        let config = DnsChallengeConfig {
            provider: "route53".into(),
            zone_id: "Z1234567890".into(),
            api_token: "AKIAIOSFODNN7EXAMPLE".into(),
            api_secret: Some("".into()),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("api_secret"));
    }

    #[tokio::test]
    async fn test_build_dns_challenger_cloudflare() {
        let config = DnsChallengeConfig {
            provider: "cloudflare".into(),
            zone_id: "zone123".into(),
            api_token: "token456".into(),
            api_secret: None,
        };
        assert!(build_dns_challenger(&config).await.is_ok());
    }

    #[tokio::test]
    async fn test_build_dns_challenger_route53() {
        let config = DnsChallengeConfig {
            provider: "route53".into(),
            zone_id: "Z1234567890".into(),
            api_token: "AKIAIOSFODNN7EXAMPLE".into(),
            api_secret: Some("secret".into()),
        };
        assert!(build_dns_challenger(&config).await.is_ok());
    }

    #[tokio::test]
    async fn test_build_dns_challenger_invalid() {
        let config = DnsChallengeConfig {
            provider: "invalid".into(),
            zone_id: "zone".into(),
            api_token: "token".into(),
            api_secret: None,
        };
        assert!(build_dns_challenger(&config).await.is_err());
    }

    #[test]
    fn test_pending_dns_challenges_store_and_retrieve() {
        let store: PendingDnsChallenges = Arc::new(DashMap::new());
        store.insert(
            "example.com".to_string(),
            PendingDnsChallenge {
                order_url: "https://acme.example/order/1".into(),
                challenge_url: "https://acme.example/chall/1".into(),
                txt_value: "abc123".into(),
                account_credentials_json: "{}".into(),
                staging: true,
                contact_email: Some("test@example.com".into()),
                created_at: Instant::now(),
            },
        );

        assert!(store.contains_key("example.com"));
        assert!(!store.contains_key("other.com"));

        let (_, pending) = store.remove("example.com").unwrap();
        assert_eq!(pending.txt_value, "abc123");
        assert_eq!(pending.challenge_url, "https://acme.example/chall/1");
        assert!(pending.staging);
        assert!(!store.contains_key("example.com"));
    }

    #[test]
    fn test_pending_dns_challenge_expiry_check() {
        let pending = PendingDnsChallenge {
            order_url: String::new(),
            challenge_url: String::new(),
            txt_value: String::new(),
            account_credentials_json: String::new(),
            staging: false,
            contact_email: None,
            created_at: Instant::now() - std::time::Duration::from_secs(700),
        };
        assert!(pending.created_at.elapsed() > PENDING_DNS_MAX_AGE);
    }

    #[test]
    fn test_pending_dns_challenge_not_expired() {
        let pending = PendingDnsChallenge {
            order_url: String::new(),
            challenge_url: String::new(),
            txt_value: String::new(),
            account_credentials_json: String::new(),
            staging: false,
            contact_email: None,
            created_at: Instant::now(),
        };
        assert!(pending.created_at.elapsed() < PENDING_DNS_MAX_AGE);
    }

    #[tokio::test]
    async fn test_check_cert_expiry_dispatches_alerts() {
        use lorica_config::models::{Certificate, GlobalSettings};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let store = lorica_config::ConfigStore::open_in_memory().unwrap();

        // Set warning=14, critical=3
        let mut settings = GlobalSettings::default();
        settings.cert_warning_days = 14;
        settings.cert_critical_days = 3;
        store.update_global_settings(&settings).unwrap();

        let now = chrono::Utc::now();

        // Cert expiring in 10 days (warning level)
        let warning_cert = Certificate {
            id: "cert-warn".into(),
            domain: "warn.example.com".into(),
            san_domains: vec![],
            fingerprint: "aaa".into(),
            cert_pem: "---CERT---".into(),
            key_pem: "---KEY---".into(),
            issuer: "manual".into(),
            not_before: now - chrono::Duration::days(80),
            not_after: now + chrono::Duration::days(10),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now - chrono::Duration::days(80),
        };

        // Cert expiring in 2 days (critical level)
        let critical_cert = Certificate {
            id: "cert-crit".into(),
            domain: "crit.example.com".into(),
            san_domains: vec![],
            fingerprint: "bbb".into(),
            cert_pem: "---CERT---".into(),
            key_pem: "---KEY---".into(),
            issuer: "manual".into(),
            not_before: now - chrono::Duration::days(88),
            not_after: now + chrono::Duration::days(2),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now - chrono::Duration::days(88),
        };

        // Cert expiring in 30 days (no alert)
        let safe_cert = Certificate {
            id: "cert-safe".into(),
            domain: "safe.example.com".into(),
            san_domains: vec![],
            fingerprint: "ccc".into(),
            cert_pem: "---CERT---".into(),
            key_pem: "---KEY---".into(),
            issuer: "Let's Encrypt".into(),
            not_before: now - chrono::Duration::days(60),
            not_after: now + chrono::Duration::days(30),
            is_acme: true,
            acme_auto_renew: true,
            created_at: now - chrono::Duration::days(60),
        };

        store.create_certificate(&warning_cert).unwrap();
        store.create_certificate(&critical_cert).unwrap();
        store.create_certificate(&safe_cert).unwrap();

        let state = crate::server::AppState {
            store: Arc::new(Mutex::new(store)),
            log_buffer: Arc::new(crate::logs::LogBuffer::new(100)),
            system_cache: Arc::new(Mutex::new(crate::system::SystemCache::new())),
            active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Instant::now(),
            http_port: 8080,
            https_port: 8443,
            config_reload_tx: None,
            worker_metrics: None,
            waf_event_buffer: None,
            waf_engine: None,
            waf_rule_count: None,
            acme_challenge_store: None,
            pending_dns_challenges: Arc::new(DashMap::new()),
            sla_collector: None,
            load_test_engine: None,
            cache_hits: None,
            cache_misses: None,
            ban_list: None,
            cache_backend: None,
            ewma_scores: None,
            backend_connections: None,
            notification_history: None,
            log_store: None,
            aggregated_metrics: None,
        };

        let alert_sender = lorica_notify::AlertSender::new(64);
        let mut rx = alert_sender.subscribe();

        check_cert_expiry(&state, &alert_sender).await;

        // Collect all alerts
        let mut alerts = Vec::new();
        while let Ok(event) = rx.try_recv() {
            alerts.push(event);
        }

        // Should have exactly 2 alerts (warning + critical), not 3 (safe cert is >14 days)
        assert_eq!(alerts.len(), 2, "expected 2 alerts, got {}", alerts.len());

        // Find the critical alert
        let crit = alerts
            .iter()
            .find(|a| a.summary.contains("CRITICAL"))
            .expect("should have a CRITICAL alert");
        assert!(crit.summary.contains("crit.example.com"));
        assert_eq!(
            crit.details.get("cert_id").unwrap(),
            "cert-crit"
        );

        // Find the warning alert
        let warn = alerts
            .iter()
            .find(|a| !a.summary.contains("CRITICAL"))
            .expect("should have a warning alert");
        assert!(warn.summary.contains("warn.example.com"));
        assert_eq!(
            warn.details.get("cert_id").unwrap(),
            "cert-warn"
        );
    }
}
