//! TLS certificate CRUD plus self-signed generation. ACME-issued certs are
//! created via the [`crate::acme`] module but managed here once stored.

use axum::extract::{ConnectInfo, Extension, Path, Query};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::rate_limit::RateLimiter;
use crate::server::AppState;

/// Compact certificate view returned by list endpoints (no PEM body).
#[derive(Serialize)]
pub struct CertificateResponse {
    /// Cert row id.
    pub id: String,
    /// Primary CN / SAN.
    pub domain: String,
    /// Extra SAN DNS names parsed from the cert.
    pub san_domains: Vec<String>,
    /// SHA-256 fingerprint (hex).
    pub fingerprint: String,
    /// Issuer DN.
    pub issuer: String,
    /// RFC 3339 not-before timestamp.
    pub not_before: String,
    /// RFC 3339 not-after timestamp.
    pub not_after: String,
    /// Whether the cert was issued by Lorica's ACME flow.
    pub is_acme: bool,
    /// Whether the ACME renewal loop auto-renews this cert.
    pub acme_auto_renew: bool,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// ACME method (`"http01"` / `"dns01-*"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_method: Option<String>,
    /// Global DNS provider ID for DNS-01 renewals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_dns_provider_id: Option<String>,
}

/// JSON body for `POST /api/v1/certificates` - upload a PEM cert and key.
#[derive(Deserialize)]
pub struct CreateCertificateRequest {
    /// Primary hostname the cert binds to.
    pub domain: String,
    /// PEM-encoded leaf + chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
}

/// JSON body for `POST /api/v1/certificates/self-signed`.
#[derive(Deserialize)]
pub struct GenerateSelfSignedRequest {
    /// Hostname the self-signed cert binds to.
    pub domain: String,
}

/// JSON body for `PUT /api/v1/certificates/:id`. Only supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateCertificateRequest {
    /// New primary hostname.
    pub domain: Option<String>,
    /// New PEM cert + chain.
    pub cert_pem: Option<String>,
    /// New PEM private key.
    pub key_pem: Option<String>,
    /// ACME method override.
    pub acme_method: Option<String>,
    /// New DNS provider reference for DNS-01 renewals.
    pub acme_dns_provider_id: Option<String>,
    /// Toggle auto-renewal for this cert.
    pub acme_auto_renew: Option<bool>,
}

/// Detailed certificate view returned by `GET /api/v1/certificates/:id`,
/// including the PEM body and the routes that reference it.
#[derive(Serialize)]
pub struct CertificateDetailResponse {
    /// Cert row id.
    pub id: String,
    /// Primary hostname.
    pub domain: String,
    /// SAN DNS names from the cert.
    pub san_domains: Vec<String>,
    /// SHA-256 fingerprint (hex).
    pub fingerprint: String,
    /// PEM-encoded leaf + chain.
    pub cert_pem: String,
    /// Issuer DN.
    pub issuer: String,
    /// RFC 3339 not-before timestamp.
    pub not_before: String,
    /// RFC 3339 not-after timestamp.
    pub not_after: String,
    /// Whether the cert is ACME-issued.
    pub is_acme: bool,
    /// Whether the ACME loop auto-renews this cert.
    pub acme_auto_renew: bool,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// IDs of routes currently pointing at this cert.
    pub associated_routes: Vec<String>,
    /// ACME method when `is_acme`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_method: Option<String>,
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
        acme_method: c.acme_method.clone(),
        acme_dns_provider_id: c.acme_dns_provider_id.clone(),
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
                Ok(blocks) if !blocks.is_empty() => blocks
                    .into_iter()
                    .next()
                    .expect("guard `!blocks.is_empty()` guarantees at least one block"),
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
        write!(hex, "{byte:02X}").expect("write to String is infallible");
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
        write!(hex, "{byte:02X}").expect("write to String is infallible");
    }
    hex
}

/// GET /api/v1/certificates - list every stored certificate (without PEM bodies).
pub async fn list_certificates(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let certs = store.list_certificates()?;
    let responses: Vec<_> = certs.iter().map(cert_to_response).collect();
    Ok(json_data(serde_json::json!({ "certificates": responses })))
}

/// POST /api/v1/certificates - upload a PEM cert + key. Metadata is parsed from the cert.
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
        acme_method: None,

        acme_dns_provider_id: None,
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;
    crate::cert_export::export_from_store(&store, &cert);
    drop(store);
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        cert_to_response(&cert),
    ))
}

/// GET /api/v1/certificates/:id - return cert details, PEM body, and associated routes.
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
        acme_method: cert.acme_method.clone(),
    };

    Ok(json_data(response))
}

/// PUT /api/v1/certificates/:id - replace the PEM body, domain, or ACME settings.
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
    if let Some(method) = body.acme_method {
        cert.acme_method = if method.is_empty() {
            None
        } else {
            Some(method)
        };
    }
    if let Some(provider_id) = body.acme_dns_provider_id {
        cert.acme_dns_provider_id = if provider_id.is_empty() {
            None
        } else {
            Some(provider_id)
        };
    }
    if let Some(auto_renew) = body.acme_auto_renew {
        cert.acme_auto_renew = auto_renew;
    }

    store.update_certificate(&cert)?;
    drop(store);
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();
    Ok(json_data(cert_to_response(&cert)))
}

/// DELETE /api/v1/certificates/:id - delete a certificate, refusing if any route still references it.
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

/// POST /api/v1/certificates/self-signed - generate and store a self-signed cert for the given domain.
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
        acme_method: None,

        acme_dns_provider_id: None,
    };

    let store = state.store.lock().await;
    store.create_certificate(&certificate)?;
    crate::cert_export::export_from_store(&store, &certificate);
    drop(store);
    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        cert_to_response(&certificate),
    ))
}

/// Query string for `GET /api/v1/certificates/:id/download`.
/// `part` selects which PEM blob ends up in the response body:
/// * `cert` - the leaf certificate only
/// * `key` - the private key only (most sensitive)
/// * `chain` - the certificate followed by any additional chain in
///   the PEM
/// * `bundle` - cert + key concatenated (fullchain-style). Default.
#[derive(Deserialize, Default)]
pub struct DownloadCertificateQuery {
    /// Which part of the bundle to serve : `"cert"` / `"key"` /
    /// `"chain"` / `"bundle"` (default).
    #[serde(default)]
    pub part: Option<String>,
}

/// GET /api/v1/certificates/:id/download - emit the PEM payload as a
/// file download. Auth-gated (this endpoint lives under
/// `protected_routes`), rate-limited per client IP (5 downloads / 60 s,
/// same bucket shape used for login), audited via `tracing::warn!` with
/// the client IP, cert id, domain and selected part so a rogue export
/// leaves a trail in the access log. The `Content-Disposition`
/// filename is built from the cert domain with a sanitiser that
/// rejects path-traversal / non-ASCII sequences; a malformed domain
/// falls back to the opaque cert id so the download never serves a
/// file named from attacker-controlled bytes.
pub async fn download_certificate(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Extension(state): Extension<AppState>,
    Extension(rate_limiter): Extension<RateLimiter>,
    Path(id): Path<String>,
    Query(q): Query<DownloadCertificateQuery>,
) -> Result<Response, ApiError> {
    let client_ip = connect_info
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Rate-limit per client IP in a dedicated `cert_download` bucket
    // (5 attempts / 60 s window) so a runaway script cannot exfiltrate
    // every cert in a tight loop. Legitimate "backup all certs" use
    // cases pace themselves trivially. The bucket is independent of
    // the login bucket so a cert-download flood does not block the
    // operator from logging in.
    if let Err(retry_after) = rate_limiter
        .check_bucket("cert_download", &client_ip, 5, 60)
        .await
    {
        return Err(ApiError::RateLimited(retry_after));
    }

    let store = state.store.lock().await;
    let cert = store
        .get_certificate(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;

    let part = q.part.as_deref().unwrap_or("bundle");
    let (body, suffix) = match part {
        "cert" => (cert.cert_pem.clone(), "cert"),
        "key" => (cert.key_pem.clone(), "key"),
        "chain" => (cert.cert_pem.clone(), "chain"),
        "bundle" => {
            let mut b = cert.cert_pem.clone();
            if !b.ends_with('\n') {
                b.push('\n');
            }
            b.push_str(&cert.key_pem);
            (b, "bundle")
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown `part` value {other:?}; expected cert | key | chain | bundle"
            )));
        }
    };

    let safe_domain = sanitize_filename(&cert.domain).unwrap_or_else(|| cert.id.clone());
    let filename = format!("{safe_domain}-{suffix}.pem");

    tracing::warn!(
        client_ip = %client_ip,
        cert_id = %cert.id,
        domain = %cert.domain,
        part = %suffix,
        "certificate download",
    );

    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    // `HeaderValue::from_str` is not infallible here (filename contains
    // only ASCII after sanitize_filename), but we still defend against
    // a surprise with a conservative fallback.
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// Sanitize a cert domain into a safe filename component. Returns
/// `None` when the input has no usable characters left (triggers the
/// caller's fallback to the opaque cert id). Rules: keep only ASCII
/// letters, digits, `-`, `_`, `.`. Reject leading dot / empty result /
/// any `..` sequence. Hostnames fit naturally; wildcard domains
/// (`*.example.com`) get their `*` dropped since it is not a
/// filesystem-safe character.
fn sanitize_filename(domain: &str) -> Option<String> {
    let mut out = String::with_capacity(domain.len());
    for c in domain.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        }
    }
    if out.is_empty() || out.starts_with('.') || out.contains("..") {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod download_tests {
    use super::*;

    #[test]
    fn sanitize_filename_keeps_hostnames() {
        assert_eq!(
            sanitize_filename("grafana.mibu.fr").as_deref(),
            Some("grafana.mibu.fr")
        );
        assert_eq!(
            sanitize_filename("my_host-01.example.com").as_deref(),
            Some("my_host-01.example.com")
        );
    }

    #[test]
    fn sanitize_filename_rejects_wildcard() {
        // `*` is unsafe on most filesystems (Windows especially) and
        // most shells interpret it. The sanitiser drops it, but the
        // remaining `.example.com` starts with a dot so the guard
        // rejects it - the caller falls back to the opaque cert id,
        // which is exactly what we want for a wildcard cert.
        assert_eq!(sanitize_filename("*.example.com"), None);
    }

    #[test]
    fn sanitize_filename_rejects_traversal() {
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("../etc/passwd"), None);
        assert_eq!(sanitize_filename(""), None);
    }

    #[test]
    fn sanitize_filename_rejects_non_ascii() {
        // Non-ASCII characters are silently dropped so a domain like
        // `grafäna.fr` becomes `grafna.fr` rather than smuggling
        // Unicode through the filename. A domain that reduces to the
        // empty string after stripping returns None.
        assert_eq!(
            sanitize_filename("grafäna.fr").as_deref(),
            Some("grafna.fr")
        );
        assert_eq!(sanitize_filename("é").as_deref(), None);
    }
}
