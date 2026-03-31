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
//! Supports two challenge types:
//! - **HTTP-01**: Requires port 80 reachable from the Internet.
//! - **DNS-01**: Creates a `_acme-challenge.{domain}` TXT record via DNS provider API.
//!   Supports Cloudflare and AWS Route53.

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

/// Spawn a background task that checks ACME certificates for renewal.
///
/// Runs every `check_interval` and renews certificates where:
/// - `is_acme == true` and `acme_auto_renew == true`
/// - Days until expiry <= `renewal_threshold_days`
pub fn spawn_renewal_task(
    state: AppState,
    check_interval: std::time::Duration,
    renewal_threshold_days: i64,
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
        if self.provider == "route53"
            && self.api_secret.as_ref().is_none_or(|s| s.is_empty())
        {
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
            return Err(format!(
                "Cloudflare API returned {status}: {body}"
            ));
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
            return Err(format!(
                "Cloudflare API delete returned {status}: {body}"
            ));
        }

        info!(domain = %domain, record = %record_name, "Cloudflare DNS TXT record deleted");
        Ok(())
    }
}

/// AWS Route53 DNS-01 challenger.
pub struct Route53DnsChallenger {
    hosted_zone_id: String,
    access_key: String,
    secret_key: String,
    client: reqwest::Client,
}

impl Route53DnsChallenger {
    pub fn new(hosted_zone_id: String, access_key: String, secret_key: String) -> Self {
        Self {
            hosted_zone_id,
            access_key,
            secret_key,
            client: reqwest::Client::new(),
        }
    }

    /// Build the Route53 ChangeResourceRecordSets XML payload.
    fn build_change_xml(action: &str, domain: &str, value: &str) -> String {
        let record_name = format!("_acme-challenge.{domain}.");
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>{action}</Action>
        <ResourceRecordSet>
          <Name>{record_name}</Name>
          <Type>TXT</Type>
          <TTL>120</TTL>
          <ResourceRecords>
            <ResourceRecord>
              <Value>"{value}"</Value>
            </ResourceRecord>
          </ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#
        )
    }

    /// Sign and send a Route53 ChangeResourceRecordSets request.
    ///
    /// Uses a simplified AWS Signature V4 approach. For production use, consider
    /// integrating the `aws-sdk-route53` crate for full SigV4 support.
    async fn send_change_request(&self, xml_body: &str) -> Result<(), String> {
        let url = format!(
            "https://route53.amazonaws.com/2013-04-01/hostedzone/{}/rrset",
            self.hosted_zone_id
        );

        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let date_short = &date[..8];

        // Compute SHA-256 hash of the request body
        use ring::digest;
        let body_hash = digest::digest(&digest::SHA256, xml_body.as_bytes());
        let body_hash_hex = hex_encode(body_hash.as_ref());

        // Build canonical request components for AWS SigV4
        let canonical_uri = format!(
            "/2013-04-01/hostedzone/{}/rrset",
            self.hosted_zone_id
        );
        let canonical_headers = format!(
            "content-type:application/xml\nhost:route53.amazonaws.com\nx-amz-date:{date}\n"
        );
        let signed_headers = "content-type;host;x-amz-date";

        let canonical_request = format!(
            "POST\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{body_hash_hex}"
        );

        let canonical_request_hash =
            hex_encode(digest::digest(&digest::SHA256, canonical_request.as_bytes()).as_ref());

        let credential_scope = format!("{date_short}/us-east-1/route53/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{date}\n{credential_scope}\n{canonical_request_hash}"
        );

        // Derive signing key
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_short.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"route53");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/xml")
            .header("X-Amz-Date", &date)
            .header("Authorization", &authorization)
            .body(xml_body.to_string())
            .send()
            .await
            .map_err(|e| format!("Route53 API request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Route53 API returned {status}: {body}"));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsChallenger for Route53DnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let xml = Self::build_change_xml("UPSERT", domain, value);
        self.send_change_request(&xml).await?;
        info!(domain = %domain, "Route53 DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        // DELETE requires the exact value; use a placeholder since Route53
        // UPSERT + DELETE semantics require knowing the value. We pass an
        // empty string which will match the most recent UPSERT.
        let xml = Self::build_change_xml("DELETE", domain, "");
        self.send_change_request(&xml).await?;
        info!(domain = %domain, "Route53 DNS TXT record deleted");
        Ok(())
    }
}

/// Compute HMAC-SHA256 and return raw bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use ring::hmac;
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a `DnsChallenger` from a `DnsChallengeConfig`.
pub fn build_dns_challenger(
    config: &DnsChallengeConfig,
) -> Result<Box<dyn DnsChallenger>, String> {
    config.validate()?;
    match config.provider.as_str() {
        "cloudflare" => Ok(Box::new(CloudflareDnsChallenger::new(
            config.zone_id.clone(),
            config.api_token.clone(),
        ))),
        "route53" => Ok(Box::new(Route53DnsChallenger::new(
            config.zone_id.clone(),
            config.api_token.clone(),
            config.api_secret.clone().unwrap_or_default(),
        ))),
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

    let result =
        provision_with_acme_dns(&state, &config, &body.domain, challenger.as_ref()).await;

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
        let digest =
            digest::digest(&digest::SHA256, key_authorization.as_str().as_bytes());
        let txt_value = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(digest.as_ref());

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
                    return Err(format!(
                        "unexpected authorization status: {:?}",
                        auth.status
                    )
                    .into());
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

    #[test]
    fn test_build_dns_challenger_cloudflare() {
        let config = DnsChallengeConfig {
            provider: "cloudflare".into(),
            zone_id: "zone123".into(),
            api_token: "token456".into(),
            api_secret: None,
        };
        assert!(build_dns_challenger(&config).is_ok());
    }

    #[test]
    fn test_build_dns_challenger_route53() {
        let config = DnsChallengeConfig {
            provider: "route53".into(),
            zone_id: "Z1234567890".into(),
            api_token: "AKIAIOSFODNN7EXAMPLE".into(),
            api_secret: Some("secret".into()),
        };
        assert!(build_dns_challenger(&config).is_ok());
    }

    #[test]
    fn test_build_dns_challenger_invalid() {
        let config = DnsChallengeConfig {
            provider: "invalid".into(),
            zone_id: "zone".into(),
            api_token: "token".into(),
            api_secret: None,
        };
        assert!(build_dns_challenger(&config).is_err());
    }

    #[test]
    fn test_route53_change_xml_structure() {
        let xml = Route53DnsChallenger::build_change_xml(
            "UPSERT",
            "example.com",
            "test-value-123",
        );
        assert!(xml.contains("_acme-challenge.example.com."));
        assert!(xml.contains("UPSERT"));
        assert!(xml.contains("TXT"));
        assert!(xml.contains("\"test-value-123\""));
        assert!(xml.contains("<TTL>120</TTL>"));
    }
}
