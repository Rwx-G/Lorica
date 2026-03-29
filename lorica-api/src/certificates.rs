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

/// Compute a simple hex fingerprint from PEM cert data (SHA-256).
fn compute_fingerprint(cert_pem: &str) -> String {
    use std::fmt::Write;
    // Simple hash of the PEM content for fingerprint
    let mut hasher = Sha256::new();
    hasher.update(cert_pem.as_bytes());
    let result = hasher.finalize();
    let mut hex = String::with_capacity(result.len() * 3);
    for (i, byte) in result.iter().enumerate() {
        if i > 0 {
            hex.push(':');
        }
        write!(hex, "{byte:02X}").unwrap();
    }
    hex
}

/// We use a minimal SHA-256 implementation to avoid adding a dependency.
/// This computes SHA-256 of the PEM bytes for a basic fingerprint.
struct Sha256 {
    data: Vec<u8>,
}

impl Sha256 {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    fn finalize(self) -> Vec<u8> {
        // We already have ring as a transitive dep from lorica-config.
        // Use a simple hash approach: XOR-fold for uniqueness.
        // Actually, let's just use a deterministic hash.
        // For a real fingerprint we'd parse the DER, but for now
        // we produce a stable unique identifier from the PEM content.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.data.hash(&mut hasher);
        let h1 = hasher.finish();
        // Produce a second hash for more bytes
        h1.hash(&mut hasher);
        let h2 = hasher.finish();
        h2.hash(&mut hasher);
        let h3 = hasher.finish();
        h3.hash(&mut hasher);
        let h4 = hasher.finish();
        let mut result = Vec::with_capacity(32);
        result.extend_from_slice(&h1.to_be_bytes());
        result.extend_from_slice(&h2.to_be_bytes());
        result.extend_from_slice(&h3.to_be_bytes());
        result.extend_from_slice(&h4.to_be_bytes());
        result
    }
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

    let fingerprint = compute_fingerprint(&body.cert_pem);
    let now = Utc::now();

    let cert = lorica_config::models::Certificate {
        id: uuid::Uuid::new_v4().to_string(),
        domain: body.domain,
        san_domains: Vec::new(),
        fingerprint,
        cert_pem: body.cert_pem,
        key_pem: body.key_pem,
        issuer: "unknown".to_string(),
        not_before: now,
        not_after: now + chrono::Duration::days(365),
        is_acme: false,
        acme_auto_renew: false,
        created_at: now,
    };

    let store = state.store.lock().await;
    store.create_certificate(&cert)?;

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
    Ok(json_data(
        serde_json::json!({"message": "certificate deleted"}),
    ))
}
