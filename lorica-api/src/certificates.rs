use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

#[derive(Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_acme: bool,
    pub acme_auto_renew: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateCertificateRequest {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Deserialize)]
pub struct GenerateSelfSignedRequest {
    pub domain: String,
}

#[derive(Deserialize)]
pub struct UpdateCertificateRequest {
    pub domain: Option<String>,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
}

#[derive(Serialize)]
pub struct CertificateDetailResponse {
    pub id: String,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub cert_pem: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_acme: bool,
    pub acme_auto_renew: bool,
    pub created_at: String,
    pub associated_routes: Vec<String>,
}

fn cert_to_response(c: &lorica_config::models::Certificate) -> CertificateResponse {
    CertificateResponse {
        id: c.id.clone(),
        domain: c.domain.clone(),
        san_domains: c.san_domains.clone(),
        fingerprint: c.fingerprint.clone(),
        issuer: c.issuer.clone(),
        not_before: c.not_before.to_rfc3339(),
        not_after: c.not_after.to_rfc3339(),
        is_acme: c.is_acme,
        acme_auto_renew: c.acme_auto_renew,
        created_at: c.created_at.to_rfc3339(),
    }
}

/// Compute a SHA-256 fingerprint from PEM cert data using ring.
/// Parsed X.509 metadata from a PEM certificate.
struct ParsedCertInfo {
    issuer: String,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
    san_domains: Vec<String>,
    fingerprint: String,
}

/// Parse X.509 metadata from a PEM certificate string.
/// Falls back to defaults if parsing fails (so uploads always succeed).
fn parse_cert_pem(cert_pem: &str) -> ParsedCertInfo {
    let defaults = || ParsedCertInfo {
        issuer: "unknown".to_string(),
        not_before: chrono::Utc::now(),
        not_after: chrono::Utc::now() + chrono::Duration::days(365),
        san_domains: Vec::new(),
        fingerprint: compute_fingerprint_from_pem(cert_pem),
    };

    let pem_block = match pem::parse(cert_pem) {
        Ok(p) => p,
        Err(_) => {
            // Try parsing first block from multi-block PEM (cert chain)
            match pem::parse_many(cert_pem) {
                Ok(blocks) if !blocks.is_empty() => blocks.into_iter().next().unwrap(),
                _ => return defaults(),
            }
        }
    };

    let der = pem_block.contents();
    let cert = match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => cert,
        Err(_) => return defaults(),
    };

    // Issuer: extract Organization + Common Name
    let issuer = {
        let mut parts = Vec::new();
        for attr in cert.issuer().iter_organization() {
            if let Ok(s) = attr.as_str() {
                parts.push(s.to_string());
            }
        }
        for attr in cert.issuer().iter_common_name() {
            if let Ok(s) = attr.as_str() {
                parts.push(s.to_string());
            }
        }
        if parts.is_empty() {
            "unknown".to_string()
        } else {
            parts.join(" - ")
        }
    };

    // Validity dates
    let not_before = asn1_to_chrono(cert.validity().not_before);
    let not_after = asn1_to_chrono(cert.validity().not_after);

    // SAN domains
    let mut san_domains = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let x509_parser::prelude::GeneralName::DNSName(dns) = name {
                san_domains.push(dns.to_string());
            }
        }
    }

    // Fingerprint from DER bytes (matches browser display)
    let fingerprint = compute_fingerprint_from_der(der);

    ParsedCertInfo {
        issuer,
        not_before,
        not_after,
        san_domains,
        fingerprint,
    }
}

fn asn1_to_chrono(t: x509_parser::prelude::ASN1Time) -> chrono::DateTime<chrono::Utc> {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(t.timestamp(), 0)
        .single()
        .unwrap_or_else(chrono::Utc::now)
}

fn compute_fingerprint_from_der(der: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(digest.as_ref().len() * 3);
    for (i, byte) in digest.as_ref().iter().enumerate() {
        if i > 0 {
            hex.push(':');
        }
        write!(hex, "{byte:02X}").unwrap();
    }
    hex
}

fn compute_fingerprint_from_pem(cert_pem: &str) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_pem.as_bytes());
    let mut hex = String::with_capacity(digest.as_ref().len() * 3);
    for (i, byte) in digest.as_ref().iter().enumerate() {
        if i > 0 {
            hex.push(':');
        }
        write!(hex, "{byte:02X}").unwrap();
    }
    hex
}

/// GET /api/v1/certificates
pub async fn list_certificates(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let certs = store.list_certificates()?;
    let responses: Vec<_> = certs.iter().map(cert_to_response).collect();
    Ok(json_data(serde_json::json!({ "certificates": responses })))
}

/// POST /api/v1/certificates
pub async fn create_certificate(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateCertificateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.domain.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }
    if body.cert_pem.is_empty() || body.key_pem.is_empty() {
        return Err(ApiError::BadRequest(
            "cert_pem and key_pem are required".into(),
        ));
    }

    let parsed = parse_cert_pem(&body.cert_pem);
    let now = Utc::now();

    let cert = lorica_config::models::Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        domain: body.domain,
        san_domains: parsed.san_domains,
        fingerprint: parsed.fingerprint,
        cert_pem: body.cert_pem,
        key_pem: body.key_pem,
        issuer: parsed.issuer,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
        is_acme: false,
        acme_auto_renew: false,
        created_at: now,
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;
    drop(store);
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        cert_to_response(&cert),
    ))
}

/// GET /api/v1/certificates/:id
pub async fn get_certificate(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let cert = store
        .get_certificate(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;

    // Find routes that reference this certificate
    let routes = store.list_routes()?;
    let associated_routes: Vec<String> = routes
        .iter()
        .filter(|r| r.certificate_id.as_deref() == Some(&id))
        .map(|r| r.id.clone())
        .collect();

    let response = CertificateDetailResponse {
        id: cert.id.clone(),
        domain: cert.domain.clone(),
        san_domains: cert.san_domains.clone(),
        fingerprint: cert.fingerprint.clone(),
        cert_pem: cert.cert_pem.clone(),
        issuer: cert.issuer.clone(),
        not_before: cert.not_before.to_rfc3339(),
        not_after: cert.not_after.to_rfc3339(),
        is_acme: cert.is_acme,
        acme_auto_renew: cert.acme_auto_renew,
        created_at: cert.created_at.to_rfc3339(),
        associated_routes,
    };

    Ok(json_data(response))
}

/// PUT /api/v1/certificates/:id
pub async fn update_certificate(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateCertificateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut cert = store
        .get_certificate(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;

    if let Some(domain) = body.domain {
        cert.domain = domain;
    }
    if let Some(cert_pem) = body.cert_pem {
        let parsed = parse_cert_pem(&cert_pem);
        cert.fingerprint = parsed.fingerprint;
        cert.issuer = parsed.issuer;
        cert.not_before = parsed.not_before;
        cert.not_after = parsed.not_after;
        cert.san_domains = parsed.san_domains;
        cert.cert_pem = cert_pem;
    }
    if let Some(key_pem) = body.key_pem {
        cert.key_pem = key_pem;
    }

    store.update_certificate(&cert)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(cert_to_response(&cert)))
}

/// DELETE /api/v1/certificates/:id
pub async fn delete_certificate(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    // Check if any routes reference this certificate
    let routes = store.list_routes()?;
    let referencing: Vec<&str> = routes
        .iter()
        .filter(|r| r.certificate_id.as_deref() == Some(id.as_str()))
        .map(|r| r.id.as_str())
        .collect();

    if !referencing.is_empty() {
        return Err(ApiError::Conflict(format!(
            "certificate is referenced by routes: {}",
            referencing.join(", ")
        )));
    }

    store.delete_certificate(&id)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(
        serde_json::json!({"message": "certificate deleted"}),
    ))
}

/// POST /api/v1/certificates/self-signed
pub async fn generate_self_signed(
    Extension(state): Extension<AppState>,
    Json(body): Json<GenerateSelfSignedRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.domain.is_empty() {
        return Err(ApiError::BadRequest("domain is required".into()));
    }

    let mut params = rcgen::CertificateParams::new(vec![body.domain.clone()])
        .map_err(|e| ApiError::Internal(format!("failed to create cert params: {e}")))?;
    params.is_ca = rcgen::IsCa::NoCa;

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| ApiError::Internal(format!("failed to generate key pair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ApiError::Internal(format!("failed to generate self-signed cert: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let parsed = parse_cert_pem(&cert_pem);
    let now = Utc::now();

    let certificate = lorica_config::models::Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        domain: body.domain,
        san_domains: parsed.san_domains,
        fingerprint: parsed.fingerprint,
        cert_pem: cert_pem.clone(),
        key_pem,
        issuer: parsed.issuer,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
        is_acme: false,
        acme_auto_renew: false,
        created_at: now,
    };

    let store = state.store.lock().await;
    store.create_certificate(&certificate)?;
    drop(store);
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        cert_to_response(&certificate),
    ))
}
