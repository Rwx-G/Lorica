// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! OCSP stapling support.
//!
//! Fetches OCSP responses from the CA's OCSP responder and caches them
//! alongside the certificate so rustls can include them in TLS handshakes.
//! This avoids clients having to contact the CA themselves, reducing latency
//! and improving privacy.

use log::warn;

/// Extract the OCSP responder URL from a PEM-encoded certificate chain.
///
/// Parses the end-entity certificate's Authority Information Access (AIA)
/// extension and returns the first OCSP responder URI found.
pub fn extract_ocsp_responder_url(cert_pem: &str) -> Option<String> {
    use x509_parser::pem::parse_x509_pem;

    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;

    // OID for OCSP access method: 1.3.6.1.5.5.7.48.1
    let ocsp_oid = x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP;

    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) =
            ext.parsed_extension()
        {
            for desc in aia.accessdescs.iter() {
                if desc.access_method == ocsp_oid {
                    if let x509_parser::extensions::GeneralName::URI(uri) = desc.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Fetch an OCSP response from the given responder URL for the provided
/// certificate (DER-encoded end-entity cert and issuer cert).
///
/// Builds a minimal OCSP request containing the certificate serial number,
/// issuer name hash and issuer key hash, then POSTs it to the responder.
/// Returns the raw OCSP response bytes on success.
pub async fn fetch_ocsp_response(
    cert_pem: &str,
    responder_url: &str,
) -> Result<Vec<u8>, String> {
    use x509_parser::pem::parse_x509_pem;

    // Parse end-entity cert
    let (rem, pem_ee) =
        parse_x509_pem(cert_pem.as_bytes()).map_err(|e| format!("parse EE PEM: {e}"))?;
    let (_, ee_cert) = x509_parser::parse_x509_certificate(&pem_ee.contents)
        .map_err(|e| format!("parse EE cert: {e}"))?;

    // Parse issuer cert (second cert in chain)
    let issuer_der = if !rem.is_empty() {
        let (_, pem_issuer) =
            parse_x509_pem(rem).map_err(|e| format!("parse issuer PEM: {e}"))?;
        pem_issuer.contents
    } else {
        return Err("no issuer certificate in chain - cannot build OCSP request".to_string());
    };

    let (_, issuer_cert) = x509_parser::parse_x509_certificate(&issuer_der)
        .map_err(|e| format!("parse issuer cert: {e}"))?;

    // Build OCSP request (minimal: SHA-1 hash of issuer name + key + serial)
    use ring::digest;

    let issuer_name_hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, ee_cert.issuer().as_raw());
    let issuer_key_hash = digest::digest(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        issuer_cert
            .public_key()
            .subject_public_key
            .as_ref(),
    );
    let serial = ee_cert.raw_serial();

    // ASN.1 DER encode the OCSP request manually (RFC 6960)
    let cert_id = build_cert_id(
        issuer_name_hash.as_ref(),
        issuer_key_hash.as_ref(),
        serial,
    );
    let ocsp_request = build_ocsp_request(&cert_id);

    // POST to OCSP responder
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .post(responder_url)
        .header("Content-Type", "application/ocsp-request")
        .body(ocsp_request)
        .send()
        .await
        .map_err(|e| format!("OCSP request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("OCSP responder returned {}", resp.status()));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read OCSP response: {e}"))?;

    // Basic validation: OCSP response must start with a SEQUENCE tag (0x30)
    if bytes.first() != Some(&0x30) {
        return Err("invalid OCSP response (not a DER SEQUENCE)".to_string());
    }

    Ok(bytes.to_vec())
}

/// Fetch OCSP response for a certificate, returning None on any error.
/// Logs warnings but does not fail - OCSP stapling is best-effort.
pub async fn try_fetch_ocsp(cert_pem: &str) -> Option<Vec<u8>> {
    let url = extract_ocsp_responder_url(cert_pem)?;
    match fetch_ocsp_response(cert_pem, &url).await {
        Ok(resp) => {
            log::info!("OCSP response fetched ({} bytes) from {url}", resp.len());
            Some(resp)
        }
        Err(e) => {
            warn!("OCSP fetch failed for {url}: {e}");
            None
        }
    }
}

// --- ASN.1 DER encoding helpers (minimal OCSP request) ---

/// Encode a TLV (tag-length-value) in DER.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    debug_assert!(len <= 0xFFFF, "DER TLV content exceeds 2-byte length encoding");
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

/// Build a CertID (RFC 6960 section 4.1.1):
/// CertID ::= SEQUENCE {
///   hashAlgorithm  AlgorithmIdentifier (SHA-1),
///   issuerNameHash OCTET STRING,
///   issuerKeyHash  OCTET STRING,
///   serialNumber   CertificateSerialNumber (INTEGER)
/// }
fn build_cert_id(issuer_name_hash: &[u8], issuer_key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    // SHA-1 AlgorithmIdentifier: SEQUENCE { OID 1.3.14.3.2.26, NULL }
    let sha1_oid = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
    let null = [0x05, 0x00];
    let mut algo_id = sha1_oid.to_vec();
    algo_id.extend_from_slice(&null);
    let algo_seq = der_tlv(0x30, &algo_id);

    let name_hash = der_tlv(0x04, issuer_name_hash);
    let key_hash = der_tlv(0x04, issuer_key_hash);
    let serial_int = der_tlv(0x02, serial);

    let mut cert_id_content = Vec::new();
    cert_id_content.extend_from_slice(&algo_seq);
    cert_id_content.extend_from_slice(&name_hash);
    cert_id_content.extend_from_slice(&key_hash);
    cert_id_content.extend_from_slice(&serial_int);

    der_tlv(0x30, &cert_id_content)
}

/// Build a minimal OCSPRequest (RFC 6960 section 4.1.1):
/// OCSPRequest ::= SEQUENCE {
///   tbsRequest TBSRequest ::= SEQUENCE {
///     requestList SEQUENCE OF Request ::= SEQUENCE {
///       reqCert CertID
///     }
///   }
/// }
fn build_ocsp_request(cert_id: &[u8]) -> Vec<u8> {
    let request = der_tlv(0x30, cert_id); // Request
    let request_list = der_tlv(0x30, &request); // SEQUENCE OF Request
    let tbs_request = der_tlv(0x30, &request_list); // TBSRequest
    der_tlv(0x30, &tbs_request) // OCSPRequest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ocsp_url_no_aia() {
        // Self-signed cert without AIA extension
        let self_signed = "-----BEGIN CERTIFICATE-----
MIIBkTCB+wIUXKoZlpMNDRaJD+tbp3S4dLhWIhQwDQYJKoZIhvcNAQELBQAwFDES
MBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAw
MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
AL7ebONT52KKwGBR4gNc6gMC2RqGzNU0I63RqKwtiRCFcG/sBTMlo/3aEH3/smn8
kJVNZVTO+LSyQgSZfBBOYAkCAwEAAaMhMB8wHQYDVR0OBBYEFNuT1B6D5CmPOhYb
DJx2E3oFHiWJMA0GCSqGSIb3DQEBCwUAA0EAJqIj5+MYtXm5M2JaANzFNoHh1evB
LJagjH4BgO+sTf0qoGih6SSTt0rBLHmSrtYxHOFGNwPDR1WxKaHmg0c3w==
-----END CERTIFICATE-----";
        assert!(extract_ocsp_responder_url(self_signed).is_none());
    }

    #[test]
    fn test_der_tlv_short_length() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = der_tlv(0x04, &data);
        assert_eq!(encoded, vec![0x04, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_build_cert_id_structure() {
        let name_hash = vec![0u8; 20]; // SHA-1 produces 20 bytes
        let key_hash = vec![1u8; 20];
        let serial = vec![0x01, 0x00, 0x01];

        let cert_id = build_cert_id(&name_hash, &key_hash, &serial);
        // Must be a SEQUENCE (tag 0x30)
        assert_eq!(cert_id[0], 0x30);
    }

    #[test]
    fn test_build_ocsp_request_structure() {
        let cert_id = vec![0x30, 0x03, 0x01, 0x02, 0x03]; // dummy CertID
        let request = build_ocsp_request(&cert_id);
        // Nested SEQUENCEs: OCSPRequest > TBSRequest > RequestList > Request
        assert_eq!(request[0], 0x30); // OCSPRequest SEQUENCE
    }
}
