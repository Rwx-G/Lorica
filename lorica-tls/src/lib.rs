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

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use log::warn;
pub use no_debug::{Ellipses, NoDebug, WithTypeInfo};
use lorica_error::{Error, ErrorType, OrErr, Result};

pub use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
pub use rustls::server::ResolvesServerCert;
pub use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
pub use rustls::{
    client::WebPkiServerVerifier, version, CertificateError, ClientConfig, DigitallySignedStruct,
    Error as RusTlsError, KeyLogFile, RootCertStore, ServerConfig, SignatureScheme, Stream,
};
pub use rustls_native_certs::load_native_certs;
use rustls_pemfile::Item;
pub use rustls_pki_types::{
    CertificateRevocationListDer, CertificateDer, PrivateKeyDer, ServerName, UnixTime,
};
pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;
pub use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};

// This allows to skip certificate verification. Be highly cautious.
pub use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

/// Load the given file from disk as a buffered reader and use the lorica Error
/// type instead of the std::io version
fn load_file<P>(path: P) -> Result<BufReader<File>>
where
    P: AsRef<Path>,
{
    File::open(path)
        .or_err(ErrorType::FileReadError, "Failed to load file")
        .map(BufReader::new)
}

/// Read the pem file at the given path from disk
fn load_pem_file<P>(path: P) -> Result<Vec<Item>>
where
    P: AsRef<Path>,
{
    rustls_pemfile::read_all(&mut load_file(path)?)
        .map(|item_res| {
            item_res.or_err(
                ErrorType::InvalidCert,
                "Certificate in pem file could not be read",
            )
        })
        .collect()
}

/// Load the certificates from the given pem file path into the given
/// certificate store
pub fn load_ca_file_into_store<P>(path: P, cert_store: &mut RootCertStore) -> Result<()>
where
    P: AsRef<Path>,
{
    for pem_item in load_pem_file(path)? {
        // only loading certificates, handling a CA file
        let Item::X509Certificate(content) = pem_item else {
            return Error::e_explain(
                ErrorType::InvalidCert,
                "Pem file contains un-loadable certificate type",
            );
        };
        cert_store.add(content).or_err(
            ErrorType::InvalidCert,
            "Failed to load X509 certificate into root store",
        )?;
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
pub fn load_certs_and_key_files<'a>(
    cert: &str,
    key: &str,
) -> Result<Option<(Vec<CertificateDer<'a>>, PrivateKeyDer<'a>)>> {
    let certs_file = load_pem_file(cert)?;
    let key_file = load_pem_file(key)?;

    let certs = certs_file
        .into_iter()
        .filter_map(|item| {
            if let Item::X509Certificate(cert) = item {
                Some(cert)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    // These are the currently supported pk types -
    // [https://doc.servo.org/rustls/key/struct.PrivateKey.html]
    let private_key_opt = key_file
        .into_iter()
        .filter_map(|key_item| match key_item {
            Item::Pkcs1Key(key) => Some(PrivateKeyDer::from(key)),
            Item::Pkcs8Key(key) => Some(PrivateKeyDer::from(key)),
            Item::Sec1Key(key) => Some(PrivateKeyDer::from(key)),
            _ => None,
        })
        .next();

    if let (Some(private_key), false) = (private_key_opt, certs.is_empty()) {
        Ok(Some((certs, private_key)))
    } else {
        Ok(None)
    }
}

/// Load the certificate
pub fn load_pem_file_ca(path: &String) -> Result<Vec<u8>> {
    let mut reader = load_file(path)?;
    let cas_file_items = rustls_pemfile::certs(&mut reader)
        .map(|item_res| {
            item_res.or_err(
                ErrorType::InvalidCert,
                "Failed to load certificate from file",
            )
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(cas_file_items
        .first()
        .map(|ca| ca.to_vec())
        .unwrap_or_default())
}

pub fn load_pem_file_private_key(path: &String) -> Result<Vec<u8>> {
    Ok(rustls_pemfile::private_key(&mut load_file(path)?)
        .or_err(
            ErrorType::InvalidCert,
            "Failed to load private key from file",
        )?
        .map(|key| key.secret_der().to_vec())
        .unwrap_or_default())
}

/// Load CRLs from a PEM or DER file. Supports files containing multiple CRLs.
pub fn load_crls_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let mut reader = load_file(&path)?;
    let crls: Vec<CertificateRevocationListDer<'static>> = rustls_pemfile::crls(&mut reader)
        .map(|item_res| {
            item_res.or_err(
                ErrorType::InvalidCert,
                "Failed to load CRL from file",
            )
        })
        .collect::<Result<Vec<_>>>()?;

    if crls.is_empty() {
        // Try DER format as fallback
        let raw = std::fs::read(path.as_ref())
            .or_err(ErrorType::FileReadError, "Failed to read CRL file")?;
        return Ok(vec![CertificateRevocationListDer::from(raw)]);
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
            f.write_all(b"\x30\x82\x00\x05\x00\x00\x00\x00\x00").unwrap();
        }
        let crls = load_crls_from_file(&path).unwrap();
        assert_eq!(crls.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_crl_verifier_construction() {
        // Verify that WebPkiServerVerifier can be built with CRLs.
        // Requires platform CA certificates (skipped in minimal containers).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_lorica_crl_verifier_{}.pem", std::process::id()));
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
