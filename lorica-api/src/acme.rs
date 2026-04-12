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

/// SQLite-backed store for pending ACME HTTP-01 challenges.
/// Maps token -> key_authorization for /.well-known/acme-challenge/{token}.
/// Uses SQLite so challenges are accessible across forked worker processes
/// (workers share the same database file).
#[derive(Debug, Clone)]
pub struct AcmeChallengeStore {
    /// In-memory cache for fast lookups in the supervisor process.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    /// Path to the SQLite database for cross-process sharing.
    db_path: std::path::PathBuf,
}

impl Default for AcmeChallengeStore {
    fn default() -> Self {
        Self::with_db_path(std::path::PathBuf::from("/var/lib/lorica/lorica.db"))
    }
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_db_path(path: std::path::PathBuf) -> Self {
        // Ensure the acme_challenges table exists and WAL mode is enabled
        if let Ok(conn) = rusqlite::Connection::open(&path) {
            let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS acme_challenges (token TEXT PRIMARY KEY, key_auth TEXT NOT NULL)",
                [],
            );
        }
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            db_path: path,
        }
    }

    pub async fn set(&self, token: String, key_authorization: String) {
        self.challenges
            .write()
            .await
            .insert(token.clone(), key_authorization.clone());
        // Persist to SQLite for cross-process access (workers)
        match rusqlite::Connection::open(&self.db_path) {
            Ok(conn) => {
                let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
                match conn.execute(
                    "INSERT OR REPLACE INTO acme_challenges (token, key_auth) VALUES (?1, ?2)",
                    rusqlite::params![token, key_authorization],
                ) {
                    Ok(_) => {
                        tracing::info!(token = %token, db = %self.db_path.display(), "ACME challenge persisted to SQLite")
                    }
                    Err(e) => {
                        tracing::warn!(token = %token, error = %e, "failed to persist ACME challenge to SQLite")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, db = %self.db_path.display(), "failed to open SQLite for ACME challenge")
            }
        }
    }

    pub async fn get(&self, token: &str) -> Option<String> {
        // Try in-memory first (supervisor process)
        if let Some(val) = self.challenges.read().await.get(token).cloned() {
            tracing::info!(token = token, "ACME challenge found in memory");
            return Some(val);
        }
        // Fall back to SQLite (worker processes)
        let db_path = self.db_path.clone();
        let token_owned = token.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&db_path).ok()?;
            let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
            conn.query_row(
                "SELECT key_auth FROM acme_challenges WHERE token = ?1",
                rusqlite::params![token_owned],
                |row| row.get::<_, String>(0),
            )
            .ok()
        })
        .await
        .ok()
        .flatten();
        if result.is_some() {
            tracing::info!(token = token, "ACME challenge found in SQLite");
        } else {
            tracing::info!(token = token, db = %self.db_path.display(), "ACME challenge not found in memory or SQLite");
        }
        result
    }

    pub async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
        if let Ok(conn) = rusqlite::Connection::open(&self.db_path) {
            let _ = conn.execute(
                "DELETE FROM acme_challenges WHERE token = ?1",
                rusqlite::params![token],
            );
        }
    }
}

/// In-memory store for pending manual DNS-01 challenges.
///
/// Maps domain name to the pending challenge state. Entries are created by
/// `provision_dns_manual` (step 1) and consumed by `provision_dns_manual_confirm`
/// (step 2). Entries older than 10 minutes are considered expired.
pub type PendingDnsChallenges = Arc<DashMap<String, PendingDnsChallenge>>;

/// State for a pending manual DNS-01 challenge between the two-step flow.
#[derive(Clone)]
pub struct PendingDnsChallenge {
    /// The order URL so we can restore the order from the ACME account.
    pub order_url: String,
    /// The challenge URLs to mark as ready (one per domain).
    pub challenge_urls: Vec<String>,
    /// The TXT record entries the user must create: (record_name, txt_value, domain).
    pub txt_records: Vec<(String, String, String)>,
    /// All domains in this order.
    pub domains: Vec<String>,
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
async fn provision_with_acme(
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

/// Check all certificates for upcoming expiration and dispatch alerts.
///
/// This is a pure logic function (no loop, no sleep) so it can be unit-tested.
/// It reads `cert_warning_days` and `cert_critical_days` from `GlobalSettings`
/// and sends `CertExpiring` alerts for every certificate within those thresholds.
pub async fn check_cert_expiry(state: &AppState, alert_sender: &lorica_notify::AlertSender) {
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
            lorica_notify::AlertEvent::new(lorica_notify::events::AlertType::CertExpiring, summary)
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

// ---------------------------------------------------------------------------
// DNS-01 challenge support
// ---------------------------------------------------------------------------

/// Configuration for DNS-01 ACME challenges.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsChallengeConfig {
    /// DNS provider: `"cloudflare"`, `"route53"`, or `"ovh"`.
    pub provider: String,
    /// Zone identifier (Cloudflare zone ID or Route53 hosted zone ID).
    /// Not used for OVH (zone is extracted from domain).
    #[serde(default)]
    pub zone_id: String,
    /// API token (Cloudflare API token or AWS access key ID).
    /// For OVH: the application_key.
    #[serde(default)]
    pub api_token: String,
    /// Optional secret (AWS secret access key, OVH application_secret).
    pub api_secret: Option<String>,
    /// OVH endpoint (default: "eu.api.ovh.com"). Only used for OVH.
    #[serde(default)]
    pub ovh_endpoint: Option<String>,
    /// OVH consumer key. Only used for OVH.
    #[serde(default)]
    pub ovh_consumer_key: Option<String>,
}

impl DnsChallengeConfig {
    /// Validate the configuration and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        match self.provider.as_str() {
            "cloudflare" => {
                if self.zone_id.is_empty() {
                    return Err("zone_id is required".into());
                }
                if self.api_token.is_empty() {
                    return Err("api_token is required".into());
                }
            }
            "route53" => {
                if self.zone_id.is_empty() {
                    return Err("zone_id is required".into());
                }
                if self.api_token.is_empty() {
                    return Err("api_token is required".into());
                }
                if self.api_secret.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("api_secret is required for route53 provider".into());
                }
            }
            "ovh" => {
                if self.api_token.is_empty() {
                    return Err("api_token (application_key) is required for OVH".into());
                }
                if self.api_secret.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("api_secret (application_secret) is required for OVH".into());
                }
                if self.ovh_consumer_key.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("ovh_consumer_key is required for OVH".into());
                }
            }
            other => {
                return Err(format!(
                    "unsupported DNS provider '{}': expected 'cloudflare', 'route53', or 'ovh'",
                    other
                ));
            }
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

/// OVH DNS-01 challenger using the OVH API.
///
/// OVH authentication uses application_key, application_secret and consumer_key.
/// Each request is signed with a SHA1 hash of the concatenation:
/// `application_secret+consumer_key+METHOD+URL+BODY+timestamp`.
pub struct OvhDnsChallenger {
    endpoint: String,
    application_key: String,
    application_secret: String,
    consumer_key: String,
    client: reqwest::Client,
    /// Track created record IDs for cleanup (domain -> record_id).
    created_records: parking_lot::Mutex<std::collections::HashMap<String, u64>>,
}

impl OvhDnsChallenger {
    pub fn new(
        endpoint: String,
        application_key: String,
        application_secret: String,
        consumer_key: String,
    ) -> Self {
        Self {
            endpoint,
            application_key,
            application_secret,
            consumer_key,
            client: reqwest::Client::new(),
            created_records: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Extract zone and subdomain from a domain name.
    /// e.g. "bastion.rwx-g.fr" -> zone="rwx-g.fr", subdomain="_acme-challenge.bastion"
    /// e.g. "rwx-g.fr" -> zone="rwx-g.fr", subdomain="_acme-challenge"
    fn extract_zone_and_subdomain(domain: &str) -> (String, String) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 2 {
            // domain is the zone itself (e.g. "rwx-g.fr")
            (domain.to_string(), "_acme-challenge".to_string())
        } else {
            // zone is the last 2 parts, subdomain is the rest prefixed with _acme-challenge
            let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            let sub_parts = &parts[..parts.len() - 2];
            let subdomain = format!("_acme-challenge.{}", sub_parts.join("."));
            (zone, subdomain)
        }
    }

    /// Get the OVH server timestamp for request signing.
    async fn get_server_time(&self) -> Result<i64, String> {
        let url = format!("https://{}/1.0/auth/time", self.endpoint);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OVH get server time failed: {e}"))?;
        let time: i64 = resp
            .json()
            .await
            .map_err(|e| format!("OVH server time parse failed: {e}"))?;
        Ok(time)
    }

    /// Compute the OVH API signature.
    /// Format: "$1$" + SHA1(application_secret+"+"+consumer_key+"+"+method+"+"+url+"+"+body+"+"+timestamp)
    fn sign(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        let to_sign = format!(
            "{}+{}+{}+{}+{}+{}",
            self.application_secret, self.consumer_key, method, url, body, timestamp
        );
        let digest =
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, to_sign.as_bytes());
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        format!("$1${hex}")
    }

    /// Make a signed request to the OVH API.
    async fn ovh_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response, String> {
        let url = format!("https://{}/1.0{}", self.endpoint, path);
        let body_str = body
            .map(|b| serde_json::to_string(b).unwrap_or_default())
            .unwrap_or_default();
        let timestamp = self.get_server_time().await?;
        let signature = self.sign(method.as_str(), &url, &body_str, timestamp);

        let mut req = self
            .client
            .request(method, &url)
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Signature", &signature)
            .header("Content-Type", "application/json");

        if !body_str.is_empty() {
            req = req.body(body_str);
        }

        req.send()
            .await
            .map_err(|e| format!("OVH API request failed: {e}"))
    }

    /// Refresh the DNS zone to apply changes.
    async fn refresh_zone(&self, zone: &str) -> Result<(), String> {
        let path = format!("/domain/zone/{zone}/refresh");
        let resp = self.ovh_request(reqwest::Method::POST, &path, None).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("OVH zone refresh returned {status}: {body}"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsChallenger for OvhDnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let (zone, subdomain) = Self::extract_zone_and_subdomain(domain);

        let payload = serde_json::json!({
            "fieldType": "TXT",
            "subDomain": subdomain,
            "target": value,
            "ttl": 60
        });

        let path = format!("/domain/zone/{zone}/record");
        let resp = self
            .ovh_request(reqwest::Method::POST, &path, Some(&payload))
            .await?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OVH create TXT response parse error: {e}"))?;

        if !status.is_success() {
            return Err(format!("OVH create TXT returned {status}: {body}"));
        }

        // Store record ID for later deletion
        if let Some(id) = body.get("id").and_then(|v| v.as_u64()) {
            self.created_records.lock().insert(domain.to_string(), id);
        }

        // Refresh zone to apply changes
        self.refresh_zone(&zone).await?;

        info!(domain = %domain, zone = %zone, subdomain = %subdomain, "OVH DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let (zone, _subdomain) = Self::extract_zone_and_subdomain(domain);

        let record_id = self
            .created_records
            .lock()
            .remove(domain)
            .ok_or_else(|| format!("no tracked OVH record ID for domain '{domain}'"))?;

        let path = format!("/domain/zone/{zone}/record/{record_id}");
        let resp = self
            .ovh_request(reqwest::Method::DELETE, &path, None)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("OVH delete TXT returned {status}: {body}"));
        }

        // Refresh zone to apply changes
        self.refresh_zone(&zone).await?;

        info!(domain = %domain, "OVH DNS TXT record deleted");
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
        "ovh" => Ok(Box::new(OvhDnsChallenger::new(
            config
                .ovh_endpoint
                .clone()
                .unwrap_or_else(|| "eu.api.ovh.com".to_string()),
            config.api_token.clone(),
            config.api_secret.clone().unwrap_or_default(),
            config.ovh_consumer_key.clone().unwrap_or_default(),
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
fn acme_dns_base_domain(domain: &str) -> &str {
    domain.strip_prefix("*.").unwrap_or(domain)
}

/// Internal ACME provisioning logic using DNS-01 challenge.
/// Supports multi-domain and wildcard certificates.
///
/// `acme_method` is stored on the certificate (e.g. "dns01-cloudflare").
/// `encrypted_dns_config` is the encrypted JSON of the DNS credentials (legacy).
/// `dns_provider_id` references a global DNS provider (new approach).
async fn provision_with_acme_dns(
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

/// A single TXT record entry for the manual DNS-01 response.
#[derive(Debug, Serialize)]
struct DnsManualTxtRecord {
    /// The domain this TXT record is for.
    domain: String,
    /// The TXT record name (e.g. `_acme-challenge.example.com`).
    name: String,
    /// The TXT record value to set.
    value: String,
}

/// Response for step 1: the TXT record(s) the user must create.
#[derive(Debug, Serialize)]
struct AcmeDnsManualResponse {
    status: String,
    /// Primary domain (first in the list).
    domain: String,
    /// For backwards compatibility with single-domain usage.
    txt_record_name: String,
    /// For backwards compatibility with single-domain usage.
    txt_record_value: String,
    /// All TXT records to create (for multi-domain / wildcard).
    txt_records: Vec<DnsManualTxtRecord>,
    message: String,
}

/// Request body for step 2 (check/confirm): verify or confirm TXT record.
#[derive(Debug, Deserialize)]
pub struct AcmeDnsManualConfirmRequest {
    /// The primary domain whose pending challenge should be checked/confirmed.
    pub domain: String,
    /// Optional DNS server to query (e.g. ns1.provider.com) instead of system DNS.
    pub dns_server: Option<String>,
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

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    info!(
        domains = ?domains,
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

    // Create order with all domains as identifiers
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .map_err(|e| ApiError::Internal(format!("ACME order creation failed: {e}")))?;

    // Get authorizations and extract DNS-01 challenge for each domain
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| ApiError::Internal(format!("failed to get authorizations: {e}")))?;

    let mut challenge_urls: Vec<String> = Vec::new();
    let mut txt_records_out: Vec<DnsManualTxtRecord> = Vec::new();
    let mut txt_records_pending: Vec<(String, String, String)> = Vec::new(); // (record_name, txt_value, domain)

    for auth in &authorizations {
        if matches!(auth.status, AuthorizationStatus::Valid) {
            continue;
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| ApiError::Internal("no DNS-01 challenge available".into()))?;

        let key_authorization = order.key_authorization(challenge);
        let txt_value = key_authorization.dns_value();

        let auth_domain = match &auth.identifier {
            Identifier::Dns(d) => d.clone(),
        };
        let base_domain = acme_dns_base_domain(&auth_domain);
        let txt_record_name = format!("_acme-challenge.{base_domain}");

        challenge_urls.push(challenge.url.clone());
        txt_records_out.push(DnsManualTxtRecord {
            domain: auth_domain.clone(),
            name: txt_record_name.clone(),
            value: txt_value.clone(),
        });
        txt_records_pending.push((txt_record_name, txt_value, auth_domain));
    }

    if txt_records_out.is_empty() {
        return Err(ApiError::BadRequest(
            "all authorizations already valid - no challenge needed".into(),
        ));
    }

    // Serialize account credentials for later restoration
    let credentials_json = serde_json::to_string(&credentials)
        .map_err(|e| ApiError::Internal(format!("failed to serialize credentials: {e}")))?;

    // Store the pending challenge (keyed by primary domain)
    let pending = PendingDnsChallenge {
        order_url: order.url().to_string(),
        challenge_urls,
        txt_records: txt_records_pending,
        domains: domains.clone(),
        account_credentials_json: credentials_json,
        staging: body.staging,
        contact_email: body.contact_email.clone(),
        created_at: Instant::now(),
    };

    state
        .pending_dns_challenges
        .insert(primary_domain.clone(), pending);

    // Backwards-compatible fields use the first TXT record
    let first_name = txt_records_out[0].name.clone();
    let first_value = txt_records_out[0].value.clone();

    let message = if txt_records_out.len() == 1 {
        "Create a DNS TXT record with the above name and value, then call confirm.".to_string()
    } else {
        format!(
            "Create {} DNS TXT records as listed in txt_records, then call confirm.",
            txt_records_out.len()
        )
    };

    info!(
        domains = ?domains,
        record_count = txt_records_out.len(),
        "manual DNS-01 challenge created, waiting for user to set TXT record(s)"
    );

    Ok(json_data(AcmeDnsManualResponse {
        status: "pending_dns".into(),
        domain: primary_domain,
        txt_record_name: first_name,
        txt_record_value: first_value,
        txt_records: txt_records_out,
        message,
    }))
}

/// POST /api/v1/acme/provision-dns-manual/check - Check TXT record propagation.
///
/// Verifies that the TXT records are resolvable before confirming.
/// Returns which records are found and which are still missing.
pub async fn check_dns_manual(
    Extension(state): Extension<AppState>,
    Json(body): Json<AcmeDnsManualConfirmRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pending = state
        .pending_dns_challenges
        .get(&body.domain)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "no pending DNS challenge for domain '{}'",
                body.domain
            ))
        })?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut all_found = true;

    let dns_server = body.dns_server.as_deref();
    for (record_name, expected_value, domain) in &pending.txt_records {
        let found = check_txt_record(record_name, expected_value, dns_server).await;
        results.push(serde_json::json!({
            "domain": domain,
            "record_name": record_name,
            "expected_value": expected_value,
            "found": found,
        }));
        if !found {
            all_found = false;
        }
    }

    Ok(Json(serde_json::json!({
        "data": {
            "all_found": all_found,
            "records": results,
        }
    })))
}

/// Validate that a DNS server string is a safe IP address or hostname.
/// Rejects values containing shell metacharacters, spaces, semicolons, etc.
fn is_valid_dns_server(server: &str) -> bool {
    if server.is_empty() || server.len() > 253 {
        return false;
    }
    // Allow only alphanumeric, dots, hyphens, colons (for IPv6), and square brackets
    server
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Check if a TXT record contains the expected value.
/// If dns_server is provided, queries that specific server (e.g. the authoritative NS).
async fn check_txt_record(
    record_name: &str,
    expected_value: &str,
    dns_server: Option<&str>,
) -> bool {
    let mut args = vec![
        "+short".to_string(),
        "TXT".to_string(),
        record_name.to_string(),
    ];
    if let Some(server) = dns_server {
        if !is_valid_dns_server(server) {
            tracing::warn!(server, "rejecting invalid DNS server parameter");
            return false;
        }
        args.push(format!("@{server}"));
    }
    let expected = expected_value.to_string();
    let result = tokio::task::spawn_blocking(move || {
        match std::process::Command::new("dig").args(&args).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(&expected)
            }
            Err(_) => false,
        }
    })
    .await;
    result.unwrap_or(false)
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

    // Look up the pending challenge (keyed by primary domain) - keep it for retry
    let pending_ref = state
        .pending_dns_challenges
        .get(&body.domain)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "no pending DNS challenge for domain '{}'",
                body.domain
            ))
        })?;
    let pending = pending_ref.clone();
    drop(pending_ref);

    // Check expiry
    if pending.created_at.elapsed() > PENDING_DNS_MAX_AGE {
        return Err(ApiError::BadRequest(
            "pending DNS challenge has expired (>10 min) - please start over".into(),
        ));
    }

    let domains = &pending.domains;
    let primary_domain = domains[0].clone();

    info!(
        domains = ?domains,
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

    // Tell ACME server all challenges are ready
    for challenge_url in &pending.challenge_urls {
        order
            .set_challenge_ready(challenge_url)
            .await
            .map_err(|e| ApiError::Internal(format!("set_challenge_ready failed: {e}")))?;
    }

    // Wait for all authorizations to become valid
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let fresh_auths = order
            .authorizations()
            .await
            .map_err(|e| ApiError::Internal(format!("failed to poll authorizations: {e}")))?;

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
            let failed: Vec<String> = fresh_auths
                .iter()
                .filter(|a| matches!(a.status, AuthorizationStatus::Invalid))
                .map(|a| format!("{:?}", a.identifier))
                .collect();
            return Err(ApiError::Internal(format!(
                "DNS-01 challenge validation failed for: {} - check your TXT records",
                failed.join(", ")
            )));
        }

        attempts += 1;
        if attempts > 24 {
            return Err(ApiError::Internal(
                "DNS-01 challenge validation timed out after 120s".into(),
            ));
        }
    }

    // Generate CSR with all domains and finalize order
    let mut params = rcgen::CertificateParams::new(domains.clone())
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
    let fingerprint = format!("acme-dns-manual:{}", domains.join(","));

    let cert = lorica_config::models::Certificate {
        id: cert_id.clone(),
        domain: primary_domain.clone(),
        san_domains: domains.clone(),
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
        acme_method: Some("dns01-manual".into()),

        acme_dns_provider_id: None,
    };

    let store = state.store.lock().await;
    store
        .create_certificate(&cert)
        .map_err(|e| ApiError::Internal(format!("failed to store certificate: {e}")))?;
    drop(store);
    state.notify_config_changed();

    // Only remove the pending challenge after successful provisioning
    state.pending_dns_challenges.remove(&body.domain);

    info!(
        domains = ?domains,
        cert_id = %cert_id,
        "manual DNS-01 certificate provisioned"
    );

    Ok(json_data(AcmeProvisionResponse {
        status: "provisioned".into(),
        domain: primary_domain,
        staging: pending.staging,
        message: format!(
            "Certificate provisioned via manual DNS-01 for {} domain(s) (id: {cert_id})",
            domains.len()
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_challenge_store() -> AcmeChallengeStore {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.into_path().join("test-acme.db");
        AcmeChallengeStore::with_db_path(db_path)
    }

    #[tokio::test]
    async fn test_challenge_store_set_get_remove() {
        let store = temp_challenge_store();
        store.set("token1".into(), "auth1".into()).await;
        assert_eq!(store.get("token1").await, Some("auth1".to_string()));
        store.remove("token1").await;
        assert_eq!(store.get("token1").await, None);
    }

    #[tokio::test]
    async fn test_challenge_store_get_nonexistent() {
        let store = temp_challenge_store();
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_dns_config_valid_ovh() {
        let config = DnsChallengeConfig {
            provider: "ovh".into(),
            zone_id: String::new(),
            api_token: "app-key-123".into(),
            api_secret: Some("app-secret-456".into()),
            ovh_endpoint: Some("eu.api.ovh.com".into()),
            ovh_consumer_key: Some("consumer-key-789".into()),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_dns_config_ovh_missing_consumer_key() {
        let config = DnsChallengeConfig {
            provider: "ovh".into(),
            zone_id: String::new(),
            api_token: "app-key-123".into(),
            api_secret: Some("app-secret-456".into()),
            ovh_endpoint: None,
            ovh_consumer_key: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("ovh_consumer_key"));
    }

    #[test]
    fn test_dns_config_ovh_missing_secret() {
        let config = DnsChallengeConfig {
            provider: "ovh".into(),
            zone_id: String::new(),
            api_token: "app-key-123".into(),
            api_secret: None,
            ovh_endpoint: None,
            ovh_consumer_key: Some("consumer-key-789".into()),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("api_secret"));
    }

    #[test]
    fn test_dns_config_invalid_provider() {
        let config = DnsChallengeConfig {
            provider: "godaddy".into(),
            zone_id: "zone123".into(),
            api_token: "token456".into(),
            api_secret: None,
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
        };
        assert!(build_dns_challenger(&config).await.is_ok());
    }

    #[tokio::test]
    async fn test_build_dns_challenger_ovh() {
        let config = DnsChallengeConfig {
            provider: "ovh".into(),
            zone_id: String::new(),
            api_token: "app-key".into(),
            api_secret: Some("app-secret".into()),
            ovh_endpoint: Some("eu.api.ovh.com".into()),
            ovh_consumer_key: Some("consumer-key".into()),
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
            ovh_endpoint: None,
            ovh_consumer_key: None,
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
                challenge_urls: vec!["https://acme.example/chall/1".into()],
                txt_records: vec![(
                    "_acme-challenge.example.com".into(),
                    "abc123".into(),
                    "example.com".into(),
                )],
                domains: vec!["example.com".into()],
                account_credentials_json: "{}".into(),
                staging: true,
                contact_email: Some("test@example.com".into()),
                created_at: Instant::now(),
            },
        );

        assert!(store.contains_key("example.com"));
        assert!(!store.contains_key("other.com"));

        let (_, pending) = store.remove("example.com").unwrap();
        assert_eq!(pending.txt_records[0].1, "abc123");
        assert_eq!(pending.challenge_urls[0], "https://acme.example/chall/1");
        assert!(pending.staging);
        assert!(!store.contains_key("example.com"));
    }

    #[test]
    fn test_pending_dns_challenges_multi_domain() {
        let store: PendingDnsChallenges = Arc::new(DashMap::new());
        store.insert(
            "example.com".to_string(),
            PendingDnsChallenge {
                order_url: "https://acme.example/order/2".into(),
                challenge_urls: vec![
                    "https://acme.example/chall/1".into(),
                    "https://acme.example/chall/2".into(),
                ],
                txt_records: vec![
                    (
                        "_acme-challenge.example.com".into(),
                        "val1".into(),
                        "example.com".into(),
                    ),
                    (
                        "_acme-challenge.example.com".into(),
                        "val2".into(),
                        "*.example.com".into(),
                    ),
                ],
                domains: vec!["example.com".into(), "*.example.com".into()],
                account_credentials_json: "{}".into(),
                staging: false,
                contact_email: None,
                created_at: Instant::now(),
            },
        );

        let (_, pending) = store.remove("example.com").unwrap();
        assert_eq!(pending.domains.len(), 2);
        assert_eq!(pending.challenge_urls.len(), 2);
        assert_eq!(pending.txt_records.len(), 2);
        // Both TXT records should target the same _acme-challenge name
        assert_eq!(pending.txt_records[0].0, pending.txt_records[1].0);
    }

    #[test]
    fn test_acme_dns_base_domain() {
        assert_eq!(acme_dns_base_domain("example.com"), "example.com");
        assert_eq!(acme_dns_base_domain("*.example.com"), "example.com");
        assert_eq!(acme_dns_base_domain("*.sub.example.com"), "sub.example.com");
        assert_eq!(acme_dns_base_domain("www.example.com"), "www.example.com");
    }

    #[test]
    fn test_pending_dns_challenge_expiry_check() {
        let pending = PendingDnsChallenge {
            order_url: String::new(),
            challenge_urls: vec![],
            txt_records: vec![],
            domains: vec![],
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
            challenge_urls: vec![],
            txt_records: vec![],
            domains: vec![],
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
        let settings = GlobalSettings {
            cert_warning_days: 14,
            cert_critical_days: 3,
            ..GlobalSettings::default()
        };
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
            acme_method: None,

            acme_dns_provider_id: None,
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
            acme_method: None,

            acme_dns_provider_id: None,
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
            acme_method: Some("http01".into()),

            acme_dns_provider_id: None,
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
        assert_eq!(crit.details.get("cert_id").unwrap(), "cert-crit");

        // Find the warning alert
        let warn = alerts
            .iter()
            .find(|a| !a.summary.contains("CRITICAL"))
            .expect("should have a warning alert");
        assert!(warn.summary.contains("warn.example.com"));
        assert_eq!(warn.details.get("cert_id").unwrap(), "cert-warn");
    }

    #[test]
    fn test_ovh_zone_extraction_simple() {
        let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("rwx-g.fr");
        assert_eq!(zone, "rwx-g.fr");
        assert_eq!(sub, "_acme-challenge");
    }

    #[test]
    fn test_ovh_zone_extraction_subdomain() {
        let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("bastion.rwx-g.fr");
        assert_eq!(zone, "rwx-g.fr");
        assert_eq!(sub, "_acme-challenge.bastion");
    }

    #[test]
    fn test_ovh_zone_extraction_deep_subdomain() {
        let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("a.b.rwx-g.fr");
        assert_eq!(zone, "rwx-g.fr");
        assert_eq!(sub, "_acme-challenge.a.b");
    }
}
