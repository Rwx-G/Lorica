// Copyright 2026 Cloudflare, Inc.
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

//! This module contains all the rustls specific lorica integration for things
//! like loading certificates and private keys

#![warn(clippy::all)]

pub mod cert_resolver;
pub mod no_debug;
pub mod ocsp;

use std::fs;
use std::path::Path;

use log::warn;
use lorica_error::{Error, ErrorType, OrErr, Result};
// Was `pub use no_debug::{Ellipses, NoDebug, WithTypeInfo};` against the
// upstream `no_debug = "3.1.0"` crate. Now re-exports our inlined copy
// (see src/no_debug.rs) so every downstream `use lorica_tls::NoDebug`
// keeps working unchanged (audit SC-L-3).
pub use crate::no_debug::{Ellipses, NoDebug, WithTypeInfo};

pub use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
pub use rustls::{
    client::WebPkiServerVerifier, version, CertificateError, ClientConfig, DigitallySignedStruct,
    Error as RusTlsError, KeyLogFile, RootCertStore, ServerConfig, SignatureScheme, Stream,
};
pub use rustls_native_certs::load_native_certs;
// v1.5.1 audit L-16 : the `rustls-pemfile` crate (RUSTSEC-2025-0134,
// unmaintained) was the last hop on Lorica's outstanding RUSTSEC
// chain. PEM parsing now goes through `rustls_pki_types::pem`'s
// `PemObject` trait (`pem_slice_iter` + `from_pem_slice`), which
// is the rustls team's actively-maintained replacement. Iterators
// only yield the section type they were called on (other PEM
// blocks are skipped silently), so the previous "match on Item
// variant" pattern collapses into a typed iterator per call site.
use rustls_pki_types::pem::PemObject;
pub use rustls_pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;
pub use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};

// This allows to skip certificate verification. Be highly cautious.
pub use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

/// Read the entire file into memory as a byte buffer and use the
/// lorica Error type instead of the std::io version. The PEM
/// parsers in `rustls_pki_types::pem` consume `&[u8]` slices, so
/// we materialise the file once rather than streaming.
fn read_file<P>(path: P) -> Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    fs::read(path).or_err(ErrorType::FileReadError, "Failed to load file")
}

/// Load the certificates from the given pem file path into the given
/// certificate store
pub fn load_ca_file_into_store<P>(path: P, cert_store: &mut RootCertStore) -> Result<()>
where
    P: AsRef<Path>,
{
    let bytes = read_file(path)?;
    let mut added = 0usize;
    for cert_result in CertificateDer::pem_slice_iter(&bytes) {
        let cert = cert_result.or_err(
            ErrorType::InvalidCert,
            "Certificate in pem file could not be read",
        )?;
        cert_store.add(cert).or_err(
            ErrorType::InvalidCert,
            "Failed to load X509 certificate into root store",
        )?;
        added += 1;
    }
    if added == 0 {
        return Error::e_explain(
            ErrorType::InvalidCert,
            "Pem file contains no loadable X509 certificate",
        );
    }
    Ok(())
}

/// Attempt to load the native cas into the given root-certificate store
pub fn load_platform_certs_incl_env_into_store(ca_certs: &mut RootCertStore) -> Result<()> {
    // this includes handling of ENV vars SSL_CERT_FILE & SSL_CERT_DIR
    for cert in load_native_certs()
        .or_err(ErrorType::InvalidCert, "Failed to load native certificates")?
        .into_iter()
    {
        ca_certs.add(cert).or_err(
            ErrorType::InvalidCert,
            "Failed to load native certificate into root store",
        )?;
    }

    Ok(())
}

/// Verify that a PEM-encoded certificate chain and private key form a
/// matching pair *and* are in a shape the worker can serve from. Both
/// must parse, the leaf certificate's `SubjectPublicKeyInfo` must match
/// the public key derived from the private key (rustls'
/// `CertifiedKey::keys_match`), and the resulting key must be acceptable
/// to the rustls signing stack.
///
/// The API uses this on every cert upload so a bundle whose cert and
/// key come from two different key pairs is rejected at the boundary
/// rather than landing in the database and surfacing later as a
/// `DecryptError` TLS alert during the handshake : the leaf cert
/// presents one public key while the worker signs `CertificateVerify`
/// with another, and clients refuse the signature with no further
/// diagnostic on the server side.
pub fn validate_certificate_bundle(cert_pem: &str, key_pem: &str) -> Result<()> {
    let ck = crate::cert_resolver::build_certified_key(cert_pem, key_pem, None)?;
    ck.keys_match()
        .or_err(ErrorType::InvalidCert, "certificate and private key do not form a matching pair (SubjectPublicKeyInfo mismatch)")?;
    Ok(())
}

/// Parse the first PEM-encoded private key from `pem` accepting
/// PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1
/// (`-----BEGIN RSA PRIVATE KEY-----`), and SEC1
/// (`-----BEGIN EC PRIVATE KEY-----`).
///
/// `PrivateKeyDer::from_pem_slice` already accepts all three on
/// well-formed input ; this wrapper falls back to the per-format
/// filters when the enum dispatch fails, so an operator-supplied
/// bundle with an unusual ordering, a stray non-key block, or a
/// minor encoding artefact still loads. The fallback is also a
/// belt-and-braces against any future regression in upstream's
/// section-kind matching.
///
/// The returned diagnostic includes the first PEM `BEGIN` line
/// found in the input so the operator can tell at a glance
/// whether the file claims to be a key and which format.
pub fn load_first_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    use rustls_pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    if let Ok(key) = PrivateKeyDer::from_pem_slice(pem) {
        return Ok(key);
    }
    if let Ok(k) = PrivatePkcs8KeyDer::from_pem_slice(pem) {
        return Ok(PrivateKeyDer::from(k));
    }
    if let Ok(k) = PrivatePkcs1KeyDer::from_pem_slice(pem) {
        return Ok(PrivateKeyDer::from(k));
    }
    if let Ok(k) = PrivateSec1KeyDer::from_pem_slice(pem) {
        return Ok(PrivateKeyDer::from(k));
    }

    let header = pem
        .split(|&b| b == b'\n')
        .find(|line| line.starts_with(b"-----BEGIN"))
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_else(|| "<no PEM BEGIN line>".to_string());
    Error::e_explain(
        ErrorType::InvalidCert,
        format!(
            "no supported private key found in PEM (expected PKCS#8, PKCS#1 or SEC1 ; first BEGIN line was {header:?})"
        ),
    )
}

/// Load the certificates and private key files
pub fn load_certs_and_key_files(
    cert: &str,
    key: &str,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let cert_bytes = read_file(cert)?;
    let key_bytes = read_file(key)?;

    // `CertificateDer::pem_slice_iter` skips non-certificate
    // sections silently, so a bundle PEM with intermediate roots
    // round-trips cleanly. `.into_owned()` detaches the borrow
    // from `cert_bytes` so the caller does not need to keep the
    // input slice alive.
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .filter_map(|r| r.ok())
        .map(|c| c.into_owned())
        .collect();

    let private_key_opt = load_first_private_key(&key_bytes).ok();

    if let (Some(private_key), false) = (private_key_opt, certs.is_empty()) {
        Ok(Some((certs, private_key)))
    } else {
        Ok(None)
    }
}

/// Load the certificate
pub fn load_pem_file_ca(path: &String) -> Result<Vec<u8>> {
    let bytes = read_file(path)?;
    Ok(CertificateDer::pem_slice_iter(&bytes)
        .filter_map(|r| r.ok())
        .next()
        .map(|cert| cert.as_ref().to_vec())
        .unwrap_or_default())
}

pub fn load_pem_file_private_key(path: &String) -> Result<Vec<u8>> {
    let bytes = read_file(path)?;
    // Mirror the previous behaviour : a missing / unsupported
    // key returns an empty Vec rather than an error so the
    // caller can decide what "no key here" means in context.
    Ok(load_first_private_key(&bytes)
        .map(|k| k.secret_der().to_vec())
        .unwrap_or_default())
}

/// Load CRLs from a PEM or DER file. Supports files containing multiple CRLs.
pub fn load_crls_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let bytes = read_file(&path)?;
    let crls: Vec<CertificateRevocationListDer<'static>> =
        CertificateRevocationListDer::pem_slice_iter(&bytes)
            .map(|item_res| {
                item_res.or_err(ErrorType::InvalidCert, "Failed to load CRL from file")
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|crl| crl.to_owned())
            .collect();

    if crls.is_empty() {
        // No PEM-encoded CRL section found - treat the file as raw
        // DER (single CRL) and pass it through unchanged.
        return Ok(vec![CertificateRevocationListDer::from(bytes)]);
    }

    Ok(crls)
}

pub fn hash_certificate(cert: &CertificateDer) -> Vec<u8> {
    let hash = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
    hash.as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Valid PEM-encoded CRL (generated by openssl, empty revocation list, signed by TestCA)
    const TEST_CRL_PEM: &str = "-----BEGIN X509 CRL-----\n\
MIIBaTBTAgEBMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRlc3RDQRcNMjYw\n\
NDA1MDc0ODMyWhcNMjcwNDA1MDc0ODMyWqAOMAwwCgYDVR0UBAMCAQEwDQYJKoZI\n\
hvcNAQELBQADggEBAJLdsh2csL6q60ZQLEGVkSMcQBJgJBc5okYM75+iSBkgt2CZ\n\
Cb0hIiH5XILelvuUv9+Mm+Z7zEYEwgQRGUGpC818IpV19X1Kpfp0xCsgaQ6pcNRI\n\
2GLupm7QQZ4B824OWzyKhx2nK5Ms7HIQNK3a/LfBbe4fnGpeSrkj57dQ/YcSQaW6\n\
kpxGxLCTf4YLnK+nSYjWX507QTXGrROVKiszEt295AKqVaP/w/+L5TLdzoEJxNIj\n\
xZCgYNcZiv7Z4hGNX0WmlLtdTjHue4o1opJqA2GZZwHdrPUVVTQRBFKHoiGAjB5j\n\
MBFHMbCjYvz3MFZd10rdBXJn0gnJEnA/UeCub7A=\n\
-----END X509 CRL-----\n";

    #[test]
    fn test_load_crls_from_pem_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_lorica_crl_{}.pem", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(TEST_CRL_PEM.as_bytes()).unwrap();
        }
        let crls = load_crls_from_file(&path).unwrap();
        assert_eq!(crls.len(), 1);
        assert!(!crls[0].as_ref().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_crls_from_nonexistent_file() {
        let result = load_crls_from_file("/nonexistent/crl.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_crls_from_der_fallback() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_lorica_crl_{}.der", std::process::id()));
        {
            // Write raw bytes (not valid CRL, but tests the DER fallback path)
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"\x30\x82\x00\x05\x00\x00\x00\x00\x00")
                .unwrap();
        }
        let crls = load_crls_from_file(&path).unwrap();
        assert_eq!(crls.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crl_verifier_construction() {
        // Verify that WebPkiServerVerifier can be built with CRLs.
        // Requires platform CA certificates (skipped in minimal containers).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "test_lorica_crl_verifier_{}.pem",
            std::process::id()
        ));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(TEST_CRL_PEM.as_bytes()).unwrap();
        }
        let crls = load_crls_from_file(&path).unwrap();

        let mut root_store = RootCertStore::empty();
        let _ = load_platform_certs_incl_env_into_store(&mut root_store);
        if root_store.is_empty() {
            // Skip in environments without CA certificates (e.g. minimal Docker)
            std::fs::remove_file(&path).ok();
            return;
        }

        let result = WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
            .with_crls(crls)
            .build();

        assert!(result.is_ok());
        std::fs::remove_file(&path).ok();
    }
}
