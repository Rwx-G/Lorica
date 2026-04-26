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

    // `PrivateKeyDer::from_pem_slice` returns the first supported
    // key block (PKCS1 / PKCS8 / SEC1) and is `Err` on malformed
    // PEM. We treat "no key" / "unsupported key" as None to match
    // the previous Option semantics.
    let private_key_opt = PrivateKeyDer::from_pem_slice(&key_bytes)
        .ok()
        .map(|k| k.clone_key());

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
    match PrivateKeyDer::from_pem_slice(&bytes) {
        Ok(key) => Ok(key.secret_der().to_vec()),
        // Mirror the previous behaviour : a missing / unsupported
        // key returns an empty Vec rather than an error so the
        // caller can decide what "no key here" means in context.
        Err(_) => Ok(Vec::new()),
    }
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
