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
    /// Concatenated PEM CA bundle trusted to issue client certs.
    pub ca_cert_pem: String,
    /// Whether a missing / untrusted client cert is rejected with
    /// HTTP 496 (`true`) or the request continues without a cert
    /// (`false`).
    #[serde(default)]
    pub required: bool,
    /// Optional subject-organization allowlist ; empty accepts any
    /// cert that chains to `ca_cert_pem`.
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

/// What a bundle trusts beyond the certificates it lists, one sentence
/// per finding, for the operator to read before saving.
///
/// Every certificate of a route's bundle is a trust anchor, the X.509
/// semantics every TLS stack shares. A bundle that carries a root
/// therefore trusts every CA the root signed, and one that carries a CA
/// with a certificate it issued trusts every other CA that one signed:
/// a "full chain" export of one issuing CA silently admits its
/// siblings. Such bundles stay valid, since refusing them would break
/// routes saved before this check; this names the certificates that
/// widen the trust. Issuance is read from the names (an issuer name
/// equal to another certificate's subject), without checking the
/// signature, which is enough for a warning.
pub(super) fn mtls_bundle_trust_warnings(pem_text: &str) -> Vec<String> {
    let Ok(blocks) = pem::parse_many(pem_text.trim().as_bytes()) else {
        return Vec::new();
    };
    let certificates: Vec<x509_parser::certificate::X509Certificate<'_>> = blocks
        .iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .filter_map(|block| x509_parser::parse_x509_certificate(block.contents()).ok())
        .map(|(_, certificate)| certificate)
        .collect();
    fn self_issued(certificate: &x509_parser::certificate::X509Certificate<'_>) -> bool {
        certificate.subject().as_raw() == certificate.issuer().as_raw()
    }
    const ADVICE: &str =
        "Keep only the issuing CAs this route trusts in the bundle, not the CA above them.";

    let mut warnings = Vec::new();
    if certificates.len() > 1 {
        for root in certificates.iter().filter(|c| self_issued(c)) {
            warnings.push(format!(
                "{} is a self-signed root: every CA it signed is trusted on this route, not only the other certificates of this bundle. {ADVICE}",
                root.subject()
            ));
        }
    }
    for issuer in certificates.iter().filter(|c| !self_issued(c)) {
        let issued: Vec<String> = certificates
            .iter()
            .filter(|other| {
                !self_issued(other) && other.issuer().as_raw() == issuer.subject().as_raw()
            })
            .map(|other| other.subject().to_string())
            .collect();
        if !issued.is_empty() {
            warnings.push(format!(
                "{} issued {} of this bundle: every CA it signed is trusted on this route, not only those. {ADVICE}",
                issuer.subject(),
                issued.join(", ")
            ));
        }
    }
    warnings
}

/// The save-time side of [`mtls_bundle_trust_warnings`]. A route write
/// answers with the route alone, so the warnings go to the log, where an
/// operator who saved through the API without validating first still
/// finds them.
pub(super) fn log_mtls_bundle_trust_warnings(config: &lorica_config::models::MtlsConfig) {
    for warning in mtls_bundle_trust_warnings(&config.ca_cert_pem) {
        tracing::warn!(%warning, "mtls: the CA bundle trusts more than the CAs it lists");
    }
}

/// JSON body for `POST /api/v1/validate/mtls-pem`.
#[derive(Deserialize)]
pub struct ValidateMtlsPemRequest {
    /// Concatenated PEM CA bundle to validate.
    pub ca_cert_pem: String,
}

/// Response describing a validated mTLS CA bundle (count + per-cert subject summaries).
#[derive(Serialize)]
pub struct ValidateMtlsPemResponse {
    /// Number of valid CERTIFICATE blocks parsed from the bundle.
    pub ca_count: usize,
    /// Subject summaries for each CERTIFICATE block found. One entry
    /// per cert so the operator can cross-check their bundle ("yes,
    /// these are the two CAs I expected").
    pub subjects: Vec<String>,
    /// What the bundle trusts beyond the certificates it lists (a root,
    /// or a CA next to a certificate it issued), one sentence each.
    /// Empty when the bundle holds only CAs that issued none of the
    /// others. The bundle is valid either way.
    pub warnings: Vec<String>,
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
        warnings: mtls_bundle_trust_warnings(&req.ca_cert_pem),
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
        let err =
            build_mtls_config(&mtls_req(&pem, false, vec!["Acme\nInc"])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("control character")));
    }

    /// A CA named `cn`, self-signed or signed by `parent`.
    fn ca(
        cn: &str,
        parent: Option<&rcgen::Issuer<'static, rcgen::KeyPair>>,
    ) -> (String, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("test setup");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().expect("test setup");
        let cert = match parent {
            Some(parent) => params.signed_by(&key, parent),
            None => params.self_signed(&key),
        }
        .expect("test setup");
        (cert.pem(), rcgen::Issuer::new(params, key))
    }

    #[test]
    fn a_bundle_of_unrelated_issuing_cas_carries_no_trust_warning() {
        let (_, root) = ca("Root", None);
        let (issuing_a, _) = ca("Issuing A", Some(&root));
        let (issuing_b, _) = ca("Issuing B", Some(&root));
        assert!(mtls_bundle_trust_warnings(&format!("{issuing_a}{issuing_b}")).is_empty());
        let (lone_root, _) = ca("Lone Root", None);
        assert!(mtls_bundle_trust_warnings(&lone_root).is_empty());
    }

    #[test]
    fn a_bundle_carrying_a_root_beside_other_certificates_is_warned_about() {
        let (root_pem, root) = ca("Root", None);
        let (issuing_a, _) = ca("Issuing A", Some(&root));
        let warnings = mtls_bundle_trust_warnings(&format!("{issuing_a}{root_pem}"));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("CN=Root"), "{warnings:?}");
        assert!(warnings[0].contains("self-signed root"), "{warnings:?}");
        assert!(warnings[0].contains("every CA it signed"), "{warnings:?}");
    }

    #[test]
    fn a_bundle_carrying_a_ca_and_a_certificate_it_issued_is_warned_about() {
        let (_, root) = ca("Root", None);
        let (policy_pem, policy) = ca("Policy CA", Some(&root));
        let (issuing_pem, _) = ca("Issuing A", Some(&policy));
        let warnings = mtls_bundle_trust_warnings(&format!("{issuing_pem}{policy_pem}"));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("CN=Policy CA issued CN=Issuing A"),
            "{warnings:?}"
        );
    }

    #[test]
    fn build_mtls_accepts_a_bundle_it_warns_about() {
        // Backward compatibility: the warning never refuses a bundle.
        let (root_pem, root) = ca("Root", None);
        let (issuing_a, _) = ca("Issuing A", Some(&root));
        let pem = format!("{issuing_a}{root_pem}");
        assert!(!mtls_bundle_trust_warnings(&pem).is_empty());
        assert!(build_mtls_config(&mtls_req(&pem, true, vec![])).is_ok());
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
