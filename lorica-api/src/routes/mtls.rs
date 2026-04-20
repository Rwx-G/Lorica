//! Per-route mTLS configuration types, validator, and the
//! `POST /api/v1/validate/mtls-pem` dashboard endpoint.

use axum::extract::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// Per-route mTLS configuration: trusted CA bundle and optional org allowlist.
#[derive(Serialize, Deserialize, Clone)]
pub struct MtlsConfigRequest {
    pub ca_cert_pem: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub allowed_organizations: Vec<String>,
}

/// Validate and convert a `MtlsConfigRequest` to the stored model.
/// Catches PEM that doesn't decode or carries zero CERTIFICATE blocks
/// (operator pasted junk) before a reload applies it to the listener,
/// and rejects oversized bundles that would bloat the shared root
/// store. The allowed-organizations list is trimmed and deduplicated;
/// empty entries are rejected because they would silently widen the
/// allowlist in unexpected ways.
pub(super) fn build_mtls_config(
    body: &MtlsConfigRequest,
) -> Result<lorica_config::models::MtlsConfig, ApiError> {
    let pem_text = body.ca_cert_pem.trim();
    if pem_text.is_empty() {
        return Err(ApiError::BadRequest(
            "mtls.ca_cert_pem must not be empty (use null/missing to disable)".into(),
        ));
    }
    // 1 MiB covers a deep CA bundle; well above normal single-CA use.
    const MTLS_PEM_CEILING: usize = 1_048_576;
    if pem_text.len() > MTLS_PEM_CEILING {
        return Err(ApiError::BadRequest(format!(
            "mtls.ca_cert_pem must be <= {MTLS_PEM_CEILING} bytes ({} MiB); trim the bundle to just the issuing CAs",
            MTLS_PEM_CEILING / 1_048_576
        )));
    }
    // Parse once to catch malformed PEM before a reload. We also
    // require at least one CERTIFICATE block; keys or other labels
    // alone are not a CA bundle.
    let parsed = pem::parse_many(pem_text.as_bytes())
        .map_err(|e| ApiError::BadRequest(format!("mtls.ca_cert_pem could not be parsed: {e}")))?;
    let mut cert_count = 0usize;
    for block in &parsed {
        if block.tag() == "CERTIFICATE" {
            cert_count += 1;
            // X.509 sanity - rejects CERTIFICATE blocks whose bytes are
            // not actually DER-encoded certs.
            x509_parser::parse_x509_certificate(block.contents()).map_err(|e| {
                ApiError::BadRequest(format!(
                    "mtls.ca_cert_pem contains a CERTIFICATE block that is not a valid X.509 cert: {e}"
                ))
            })?;
        }
    }
    if cert_count == 0 {
        return Err(ApiError::BadRequest(
            "mtls.ca_cert_pem must contain at least one CERTIFICATE block".into(),
        ));
    }

    const ORG_MAX_LEN: usize = 256;
    const ORGS_CAP: usize = 100;
    if body.allowed_organizations.len() > ORGS_CAP {
        return Err(ApiError::BadRequest(format!(
            "mtls.allowed_organizations: at most {ORGS_CAP} entries allowed"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    let mut orgs = Vec::with_capacity(body.allowed_organizations.len());
    for (i, org) in body.allowed_organizations.iter().enumerate() {
        let t = org.trim();
        if t.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "mtls.allowed_organizations[{i}] must not be empty"
            )));
        }
        if t.len() > ORG_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "mtls.allowed_organizations[{i}] is longer than {ORG_MAX_LEN} characters"
            )));
        }
        // The X.509 subject/issuer O= RDN is a utf8String or printableString
        // per RFC 5280; control characters (CR / LF / NUL / <0x20 except
        // space / DEL) never appear in a legitimate CA bundle. Reject them
        // so a pasted binary blob does not slip through.
        if t.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
            return Err(ApiError::BadRequest(format!(
                "mtls.allowed_organizations[{i}] contains a control character"
            )));
        }
        if seen.insert(t.to_string()) {
            orgs.push(t.to_string());
        }
    }

    Ok(lorica_config::models::MtlsConfig {
        ca_cert_pem: pem_text.to_string(),
        required: body.required,
        allowed_organizations: orgs,
    })
}

/// JSON body for `POST /api/v1/validate/mtls-pem`.
#[derive(Deserialize)]
pub struct ValidateMtlsPemRequest {
    pub ca_cert_pem: String,
}

/// Response describing a validated mTLS CA bundle (count + per-cert subject summaries).
#[derive(Serialize)]
pub struct ValidateMtlsPemResponse {
    pub ca_count: usize,
    /// Subject summaries for each CERTIFICATE block found. One entry
    /// per cert so the operator can cross-check their bundle ("yes,
    /// these are the two CAs I expected").
    pub subjects: Vec<String>,
}

/// POST /api/v1/validate/mtls-pem - run the same validator used on
/// route save, return a human-readable summary of what's in the
/// bundle so the operator can confirm BEFORE committing the route.
pub async fn validate_mtls_pem(
    Extension(_state): Extension<AppState>,
    Json(body): Json<ValidateMtlsPemRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let req = MtlsConfigRequest {
        ca_cert_pem: body.ca_cert_pem,
        required: false,
        allowed_organizations: Vec::new(),
    };
    // Shape check: hits all the same failure paths (empty, garbage
    // PEM, non-X.509 block, oversize).
    let _cfg = build_mtls_config(&req)?;

    // Re-parse to extract the per-cert summary. The validator above
    // already confirmed every block is a valid X.509 DER so this
    // shouldn't fail; if it does we surface a 400 rather than 500.
    let parsed = pem::parse_many(req.ca_cert_pem.trim().as_bytes())
        .map_err(|e| ApiError::BadRequest(format!("PEM parse: {e}")))?;
    let mut subjects = Vec::new();
    for block in &parsed {
        if block.tag() != "CERTIFICATE" {
            continue;
        }
        match x509_parser::parse_x509_certificate(block.contents()) {
            Ok((_, cert)) => {
                subjects.push(cert.subject().to_string());
            }
            Err(_) => {
                subjects.push("<unparseable subject>".into());
            }
        }
    }

    Ok(json_data(ValidateMtlsPemResponse {
        ca_count: subjects.len(),
        subjects,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_ca_pem() -> String {
        // Build a self-signed CA with rcgen so parsers have something
        // real to chew on. Generated per-test so we never leak key bytes
        // into the repo.
        let mut params =
            rcgen::CertificateParams::new(vec!["Test CA".to_string()]).expect("test setup");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("test setup");
        let cert = params.self_signed(&key).expect("test setup");
        cert.pem()
    }

    fn mtls_req(pem: &str, required: bool, orgs: Vec<&str>) -> MtlsConfigRequest {
        MtlsConfigRequest {
            ca_cert_pem: pem.to_string(),
            required,
            allowed_organizations: orgs.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn build_mtls_accepts_well_formed_bundle() {
        let pem = gen_ca_pem();
        let built = build_mtls_config(&mtls_req(&pem, true, vec!["Acme"])).expect("test setup");
        assert!(built.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(built.required);
        assert_eq!(built.allowed_organizations, vec!["Acme".to_string()]);
    }

    #[test]
    fn build_mtls_rejects_empty_pem() {
        let err = build_mtls_config(&mtls_req("", false, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_whitespace_pem() {
        let err = build_mtls_config(&mtls_req("    \n  ", false, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_garbage_pem() {
        let err = build_mtls_config(&mtls_req("not a pem file at all", false, vec![]))
            .expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_non_certificate_blocks() {
        // PEM with only a PRIVATE KEY block - no CERTIFICATE = not a
        // CA bundle. Operator probably pasted the wrong file.
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==\n-----END PRIVATE KEY-----\n";
        let err = build_mtls_config(&mtls_req(pem, false, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_bad_der_inside_certificate_block() {
        // Well-formed PEM wrapper, but the bytes inside are not a
        // valid X.509 DER encoding. Catches an operator who base64'd
        // random junk between BEGIN/END markers.
        use base64::Engine as _;
        let junk = base64::engine::general_purpose::STANDARD.encode(b"not-x509-der-bytes");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{junk}\n-----END CERTIFICATE-----\n");
        let err = build_mtls_config(&mtls_req(&pem, false, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_oversize_pem() {
        // Pad above the 1 MiB cap by repeating the PEM itself, since
        // the validator trims outer whitespace before measuring.
        let single = gen_ca_pem();
        let copies = (1_048_577 / single.len()) + 1;
        let pem = single.repeat(copies);
        assert!(
            pem.trim().len() > 1_048_576,
            "test did not actually exceed cap"
        );
        let err = build_mtls_config(&mtls_req(&pem, false, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_dedup_and_trims_organizations() {
        let pem = gen_ca_pem();
        let built = build_mtls_config(&mtls_req(&pem, false, vec!["  Acme  ", "Beta", "Acme"]))
            .expect("test setup");
        assert_eq!(
            built.allowed_organizations,
            vec!["Acme".to_string(), "Beta".to_string()]
        );
    }

    #[test]
    fn build_mtls_rejects_empty_organization_entry() {
        let pem = gen_ca_pem();
        let err =
            build_mtls_config(&mtls_req(&pem, false, vec!["Acme", "   "])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_mtls_rejects_organization_too_long() {
        let pem = gen_ca_pem();
        let long = "a".repeat(300);
        let err = build_mtls_config(&mtls_req(&pem, false, vec![&long])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("256")));
    }

    #[test]
    fn build_mtls_rejects_organization_with_control_char() {
        let pem = gen_ca_pem();
        let err = build_mtls_config(&mtls_req(&pem, false, vec!["Acme\nInc"]))
            .expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("control character")));
    }

    #[test]
    fn build_mtls_rejects_too_many_organizations() {
        let pem = gen_ca_pem();
        let many: Vec<String> = (0..101).map(|i| format!("Org{i}")).collect();
        let req = MtlsConfigRequest {
            ca_cert_pem: pem,
            required: false,
            allowed_organizations: many,
        };
        let err = build_mtls_config(&req).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("100")));
    }
}
