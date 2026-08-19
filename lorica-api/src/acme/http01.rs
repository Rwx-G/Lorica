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

use lorica_acme::{AcmeConfig, Http01ChallengeSolver};

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

use super::types::{default_true, AcmeProvisionResponse};

/// No-op HTTP-01 solver used when the process has no challenge store
/// (`state.acme_challenge_store` is `None`). It publishes nowhere, matching
/// the pre-extraction behaviour where a missing store simply skipped the
/// token set/remove calls.
struct NoopHttp01Solver;

#[async_trait::async_trait]
impl Http01ChallengeSolver for NoopHttp01Solver {
    async fn present(&self, _token: String, _key_authorization: String) {}
    async fn cleanup(&self, _token: &str) {}
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

/// POST /api/v1/acme/provision - Initiate ACME certificate provisioning.
///
/// This is a long-running operation. It creates an ACME order, responds to
/// the HTTP-01 challenge, and waits for certificate issuance.
///
/// **Requires**: port 80 reachable from the Internet for HTTP-01 challenge.
pub async fn provision_certificate(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
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

    let result = provision_with_acme(&state, &config, &domains, None).await;

    match result {
        Ok(cert_id) => {
            info!(domains = ?domains, cert_id = %cert_id, "ACME certificate provisioned");
            let response = AcmeProvisionResponse {
                status: "provisioned".into(),
                domain: primary_domain,
                staging: config.staging,
                message: format!(
                    "Certificate provisioned for {} domain(s) (id: {cert_id})",
                    domains.len()
                ),
            };

            let audit_ctx =
                crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
            let after = serde_json::to_value(&response).ok();
            crate::audit::record(
                &state,
                &audit_ctx,
                "acme.provision_http01",
                ("certificate", &cert_id),
                None,
                after.as_ref(),
            )
            .await;

            Ok(json_data(response))
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

/// Internal ACME provisioning: drives issuance via `lorica_acme::issue_http01`
/// then persists the result. Supports multi-domain SAN certificates.
///
/// When `existing_cert_id` is `Some`, the freshly issued leaf is
/// persisted in place on that row via `update_certificate` (same id,
/// route bindings untouched); when `None`, a new row is inserted with
/// a fresh UUID. The returned id is the id that now carries the leaf:
/// the existing id on renewal, the fresh UUID on first issuance.
pub(super) async fn provision_with_acme(
    state: &AppState,
    config: &AcmeConfig,
    domains: &[String],
    existing_cert_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let primary_domain = &domains[0];

    // Drive the pure ACME protocol via `lorica-acme`. The challenge tokens
    // are published through `AcmeChallengeStore` (the `Http01ChallengeSolver`
    // impl); a process without a store falls back to a no-op solver, matching
    // the pre-extraction behaviour.
    let issued = match &state.acme_challenge_store {
        Some(store) => lorica_acme::issue_http01(config, domains, store).await?,
        None => lorica_acme::issue_http01(config, domains, &NoopHttp01Solver).await?,
    };
    let cert_pem = issued.cert_pem;
    let key_pem = issued.key_pem;

    // Store certificate in database. On renewal (`existing_cert_id`
    // is `Some`) update the row in place so the id and every route
    // binding survive ; on first issuance insert a fresh row.
    let now = chrono::Utc::now();
    let is_renewal = existing_cert_id.is_some();
    let cert_id = existing_cert_id
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), ToString::to_string);
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
        // `update_certificate` does not touch `created_at`, so the
        // original insert timestamp is preserved on a renewal.
        created_at: now,
        acme_method: Some("http01".into()),

        acme_dns_provider_id: None,
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
    // v1.5.1 audit M-9 : disk export off-loaded to spawn_blocking
    // and dispatched AFTER the store mutex is released.
    if let Some((settings, acls)) = export_snapshot {
        crate::cert_export::export_after_release(settings, acls, cert).await;
    }
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(cert_id)
}
