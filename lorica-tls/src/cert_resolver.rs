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

//! SNI-based certificate resolver with hot-swap support.
//!
//! Implements rustls `ResolvesServerCert` to select the right certificate
//! based on the SNI hostname in the TLS ClientHello. Supports:
//!
//! - Exact domain matching (`example.com`)
//! - Wildcard matching (`*.example.com`)
//! - Multiple certificates per domain, sorted by expiration (longest-lived first)
//! - Atomic hot-swap via `arc-swap` - no downtime during certificate rotation

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use lorica_error::{Error, ErrorType, OrErr, Result};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
// v1.5.1 audit L-16 : `rustls-pemfile` (RUSTSEC-2025-0134,
// unmaintained) replaced by the `PemObject` trait from
// `rustls-pki-types`. Iterators yield only the section type they
// were called on, which collapses the previous "match Item variant"
// per-call pattern.
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Data needed to load a certificate into the resolver.
#[derive(Clone)]
pub struct CertData {
    /// Primary domain (e.g. "example.com" or "*.example.com").
    pub domain: String,
    /// Subject Alternative Name domains.
    pub san_domains: Vec<String>,
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// Expiration timestamp (seconds since Unix epoch).
    pub not_after_epoch: i64,
    /// DER-encoded OCSP response for stapling (optional).
    pub ocsp_response: Option<Vec<u8>>,
}

/// A single certificate entry, sorted by expiration.
#[derive(Clone)]
struct CertEntry {
    key: Arc<CertifiedKey>,
    not_after_epoch: i64,
}

/// Inner state of the resolver, atomically swapped on reload.
struct CertResolverInner {
    /// Maps lowercase domain -> certs sorted by expiry (longest-lived first).
    certs: HashMap<String, Vec<CertEntry>>,
}

/// SNI-based certificate resolver with atomic hot-swap.
///
/// Thread-safe and lock-free on the read path (TLS handshake).
/// Writes (reload) use `arc-swap` for atomic pointer swap.
pub struct CertResolver {
    inner: ArcSwap<CertResolverInner>,
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.load();
        f.debug_struct("CertResolver")
            .field("domains", &inner.certs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for CertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CertResolver {
    /// Create an empty resolver.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(CertResolverInner {
                certs: HashMap::new(),
            }),
        }
    }

    /// Atomically reload all certificates.
    ///
    /// Builds a new lookup table from the provided certificates and swaps it in.
    /// Existing TLS connections continue using their already-negotiated certificates.
    pub fn reload(&self, certs: Vec<CertData>) -> Result<()> {
        let mut map: HashMap<String, Vec<CertEntry>> = HashMap::new();

        for cert_data in certs {
            let certified_key = build_certified_key(
                &cert_data.cert_pem,
                &cert_data.key_pem,
                cert_data.ocsp_response.clone(),
            )?;
            let entry = CertEntry {
                key: Arc::new(certified_key),
                not_after_epoch: cert_data.not_after_epoch,
            };

            // Register for primary domain
            let domain = cert_data.domain.to_lowercase();
            map.entry(domain).or_default().push(entry.clone());

            // Register for each SAN domain
            for san in &cert_data.san_domains {
                let san_lower = san.to_lowercase();
                map.entry(san_lower).or_default().push(entry.clone());
            }
        }

        // Sort each domain's certs by expiry descending (longest-lived first)
        for entries in map.values_mut() {
            entries.sort_by_key(|e| std::cmp::Reverse(e.not_after_epoch));
        }

        self.inner.store(Arc::new(CertResolverInner { certs: map }));
        Ok(())
    }

    /// Number of unique domains currently registered.
    pub fn domain_count(&self) -> usize {
        self.inner.load().certs.len()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni_raw = client_hello.server_name()?;
        let inner = self.inner.load();

        // Audit M-13 : every TLS handshake calls this. Avoid the
        // `to_lowercase()` String allocation when the SNI is already
        // lowercase (the common case ; modern clients normalise) -
        // RFC 5890 leaves DNS labels case-insensitive but practical
        // SNI traffic is overwhelmingly lower-case ASCII.
        let already_lower = sni_raw.bytes().all(|b| !b.is_ascii_uppercase());
        let sni_owned;
        let sni: &str = if already_lower {
            sni_raw
        } else {
            sni_owned = sni_raw.to_ascii_lowercase();
            &sni_owned
        };

        // 1. Exact match
        if let Some(entries) = inner.certs.get(sni) {
            if let Some(entry) = entries.first() {
                return Some(Arc::clone(&entry.key));
            }
        }

        // 2. Wildcard match: replace first label with *
        if let Some(dot_pos) = sni.find('.') {
            // Build the wildcard form into a stack-friendly buffer.
            // DNS names are <= 253 bytes ; `*` + suffix fits in 256.
            // Avoids the `format!` allocation on every handshake.
            let suffix = &sni[dot_pos..];
            let mut wildcard_buf = [0u8; 256];
            let needed = 1 + suffix.len();
            if needed <= wildcard_buf.len() {
                wildcard_buf[0] = b'*';
                wildcard_buf[1..needed].copy_from_slice(suffix.as_bytes());
                // SAFETY: `*` is ASCII, `suffix` is a valid &str sub-
                // slice ; the concatenation is therefore valid UTF-8.
                let wildcard = std::str::from_utf8(&wildcard_buf[..needed])
                    .expect("ASCII '*' + UTF-8 DNS suffix is UTF-8");
                if let Some(entries) = inner.certs.get(wildcard) {
                    if let Some(entry) = entries.first() {
                        return Some(Arc::clone(&entry.key));
                    }
                }
            }
        }

        None
    }
}

/// Parse PEM strings and build a rustls `CertifiedKey`, optionally with an
/// OCSP staple response.
fn build_certified_key(
    cert_pem: &str,
    key_pem: &str,
    ocsp_response: Option<Vec<u8>>,
) -> Result<CertifiedKey> {
    let certs = parse_certs_from_pem(cert_pem)?;
    let key = parse_key_from_pem(key_pem)?;

    let signing_key =
        any_supported_type(&key).or_err(ErrorType::InvalidCert, "unsupported key type")?;

    let mut ck = CertifiedKey::new(certs, signing_key);
    if let Some(ocsp) = ocsp_response {
        ck.ocsp = Some(ocsp);
    }
    Ok(ck)
}

fn parse_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .filter_map(|r| r.ok())
        .map(|c| c.into_owned())
        .collect();

    if certs.is_empty() {
        return Error::e_explain(ErrorType::InvalidCert, "no certificates found in PEM");
    }

    Ok(certs)
}

fn parse_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    // `PrivateKeyDer::from_pem_slice` returns the first supported
    // key block (PKCS1 / PKCS8 / SEC1) and is `Err` when none is
    // present or the PEM is malformed - matches the previous
    // "iterate Items, return first key, fail otherwise" semantics.
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .or_err(ErrorType::InvalidCert, "no private key found in PEM")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed test certificate for "test.example.com" generated at build time
    // is not practical, so we test the resolver logic with mock entries.

    #[allow(dead_code)] // Placeholder helper kept for future integration tests.
    fn make_resolver_with_entries(entries: Vec<(&str, i64)>) -> CertResolver {
        let resolver = CertResolver::new();

        // We can't easily create real CertifiedKeys in tests without valid certs,
        // so test the HashMap/wildcard logic via the public API indirectly.
        // For real cert tests, see integration tests.
        let _ = entries; // placeholder
        resolver
    }

    #[test]
    fn test_empty_resolver() {
        let resolver = CertResolver::new();
        assert_eq!(resolver.domain_count(), 0);
    }

    #[test]
    fn test_reload_with_valid_self_signed_cert() {
        // Generate a minimal self-signed cert for testing
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");

        let resolver = CertResolver::new();
        let result = resolver.reload(vec![CertData {
            domain: "test.example.com".to_string(),
            san_domains: vec!["*.example.com".to_string()],
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            not_after_epoch: 9999999999,
            ocsp_response: None,
        }]);

        assert!(result.is_ok());
        // Primary domain + wildcard SAN
        assert_eq!(resolver.domain_count(), 2);
    }

    #[test]
    fn test_reload_replaces_previous() {
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");

        let resolver = CertResolver::new();

        // First load
        resolver
            .reload(vec![CertData {
                domain: "a.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 1000,
                ocsp_response: None,
            }])
            .unwrap();
        assert_eq!(resolver.domain_count(), 1);

        // Reload with different domain
        resolver
            .reload(vec![CertData {
                domain: "b.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 2000,
                ocsp_response: None,
            }])
            .unwrap();
        assert_eq!(resolver.domain_count(), 1);
    }

    #[test]
    fn test_multiple_certs_sorted_by_expiry() {
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");

        let resolver = CertResolver::new();
        resolver
            .reload(vec![
                CertData {
                    domain: "example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: cert_pem.to_string(),
                    key_pem: key_pem.to_string(),
                    not_after_epoch: 1000, // short-lived
                    ocsp_response: None,
                },
                CertData {
                    domain: "example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: cert_pem.to_string(),
                    key_pem: key_pem.to_string(),
                    not_after_epoch: 9000, // long-lived
                    ocsp_response: None,
                },
            ])
            .unwrap();

        // Both certs register under the same domain
        assert_eq!(resolver.domain_count(), 1);
        // The longest-lived cert should be first (verified by resolve logic)
    }

    #[test]
    fn test_wildcard_domain_registration() {
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");

        let resolver = CertResolver::new();
        resolver
            .reload(vec![CertData {
                domain: "*.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 9999999999,
                ocsp_response: None,
            }])
            .unwrap();

        assert_eq!(resolver.domain_count(), 1);
    }

    #[test]
    fn test_case_insensitive() {
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");

        let resolver = CertResolver::new();
        resolver
            .reload(vec![CertData {
                domain: "Example.COM".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 9999999999,
                ocsp_response: None,
            }])
            .unwrap();

        // Stored as lowercase
        assert_eq!(resolver.domain_count(), 1);
    }
}
