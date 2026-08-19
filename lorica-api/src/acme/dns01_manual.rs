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

//! Two-step manual DNS-01 challenge flow (init, check, confirm).

use std::time::Instant;

use axum::extract::{Extension};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::info;

use lorica_acme::AcmeConfig;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

use super::types::{default_true, AcmeProvisionResponse, PendingDnsChallenge};

/// Maximum age for a pending manual DNS challenge before it is considered expired.
pub(super) const PENDING_DNS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600); // 10 min

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
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<AcmeDnsManualRequest>,
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

    let config = AcmeConfig {
        staging: body.staging,
        contact_email: body.contact_email.clone(),
    };

    info!(
        domains = ?domains,
        staging = config.staging,
        "starting manual DNS-01 challenge (step 1)"
    );

    // Drive the pure ACME core: create the account + order and extract the
    // DNS-01 challenge metadata WITHOUT creating any TXT record. The operator
    // publishes the returned records, then calls confirm.
    let manual_order = lorica_acme::begin_manual_dns01(&config, &domains).await?;

    if manual_order.challenges.is_empty() {
        return Err(ApiError::BadRequest(
            "all authorizations already valid - no challenge needed".into(),
        ));
    }

    let txt_records_out: Vec<DnsManualTxtRecord> = manual_order
        .challenges
        .iter()
        .map(|c| DnsManualTxtRecord {
            domain: c.domain.clone(),
            name: c.record_name.clone(),
            value: c.txt_value.clone(),
        })
        .collect();
    let challenge_urls: Vec<String> = manual_order
        .challenges
        .iter()
        .map(|c| c.challenge_url.clone())
        .collect();
    let txt_records_pending: Vec<(String, String, String)> = manual_order
        .challenges
        .iter()
        .map(|c| (c.record_name.clone(), c.txt_value.clone(), c.domain.clone()))
        .collect();

    // Store the pending challenge (keyed by primary domain)
    let pending = PendingDnsChallenge {
        order_url: manual_order.order_url,
        challenge_urls,
        txt_records: txt_records_pending,
        domains: domains.clone(),
        account_credentials_json: manual_order.account_credentials_json,
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

    // The pending challenge (order + account credentials) is state
    // this handler just created; the audit payload stays None so the
    // key authorization values never reach the audit hash input.
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "acme.provision_dns01_manual",
        ("certificate", &primary_domain),
        None,
        None,
    )
    .await;

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
///
/// `pub(super)` so `acme::tests` can unit-test the full alphabet
/// without going through the `check_txt_record` wrapper (which
/// spawns `dig` and is integration-only).
pub(super) fn is_valid_dns_server(server: &str) -> bool {
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
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<AcmeDnsManualConfirmRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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

    // Drive the pure ACME core: restore the account + order from the pending
    // credentials, signal readiness for the operator-published challenges,
    // and poll to issuance.
    let issued = lorica_acme::finalize_manual_dns01(
        &pending.account_credentials_json,
        &pending.order_url,
        &pending.challenge_urls,
        domains,
    )
    .await?;
    let cert_pem = issued.cert_pem;
    let key_pem = issued.key_pem;

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

    let (cert, export_snapshot) = db_blocking(&state.store, move |store| {
        store
            .create_certificate(&cert)
            .map_err(|e| ApiError::Internal(format!("failed to store certificate: {e}")))?;
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

    // Only remove the pending challenge after successful provisioning
    state.pending_dns_challenges.remove(&body.domain);

    info!(
        domains = ?domains,
        cert_id = %cert_id,
        "manual DNS-01 certificate provisioned"
    );

    let response = AcmeProvisionResponse {
        status: "provisioned".into(),
        domain: primary_domain,
        staging: pending.staging,
        message: format!(
            "Certificate provisioned via manual DNS-01 for {} domain(s) (id: {cert_id})",
            domains.len()
        ),
    };

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    let after = serde_json::to_value(&response).ok();
    crate::audit::record(
        &state,
        &audit_ctx,
        "acme.dns01_manual_confirm",
        ("certificate", &cert_id),
        None,
        after.as_ref(),
    )
    .await;

    Ok(json_data(response))
}
