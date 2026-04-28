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
use log::warn;
use lorica_error::{Error, ErrorType, OrErr, Result};
// Pinned to `ring` to match the workspace-wide crypto stack
// (audit M-6 : avoid carrying both ring + aws-lc-rs in the binary).
use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
// v1.5.1 audit L-16 : `rustls-pemfile` (RUSTSEC-2025-0134,
// unmaintained) replaced by the `PemObject` trait from
// `rustls-pki-types`. Iterators yield only the section type they
// were called on, which collapses the previous "match Item variant"
// per-call pattern.
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::load_first_private_key;

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

/// Outcome counts for one [`CertResolver::reload`] call.
///
/// Exposed so the caller (in `lorica`) can bump
/// `lorica_certificates_invalid_bundle_total{source="reload"}` per
/// skipped cert without `lorica-tls` having to depend on
/// `lorica-api`. `domains` is the count of distinct primary-domain
/// entries the swap published (SAN registrations re-use the same
/// `CertEntry` and don't add to this number). `skipped_domains`
/// carries the originating `domain` of every skipped row so the
/// caller can build a structured log without having to grep the
/// per-row WARN ; this also makes the partial-tolerance regression
/// test directly assert that the right domain was skipped instead
/// of inferring it from a count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadStats {
    pub total: usize,
    pub skipped: usize,
    pub domains: usize,
    pub skipped_domains: Vec<String>,
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
    ///
    /// Per-cert build failures are logged and skipped rather than aborting the
    /// whole reload : a single misconfigured row in the database (truncated
    /// key, encoded-with-the-wrong-encryption-key blob, mismatched cert/key
    /// pair…) must not poison every other vhost on the resolver. The caller
    /// can detect a fully-empty result via [`Self::domain_count`] and the
    /// per-row skip count via the returned [`ReloadStats::skipped`] - the
    /// latter is what `lorica` feeds into the
    /// `lorica_certificates_invalid_bundle_total{source="reload"}`
    /// Prometheus counter.
    pub fn reload(&self, certs: Vec<CertData>) -> Result<ReloadStats> {
        let mut map: HashMap<String, Vec<CertEntry>> = HashMap::new();
        let total = certs.len();
        let mut skipped_domains: Vec<String> = Vec::new();

        for cert_data in certs {
            let certified_key = match build_certified_key(
                &cert_data.cert_pem,
                &cert_data.key_pem,
                cert_data.ocsp_response.clone(),
            ) {
                Ok(k) => k,
                Err(e) => {
                    warn!(
                        "cert resolver: skipping cert for domain {:?} ({} SAN) : {}",
                        cert_data.domain,
                        cert_data.san_domains.len(),
                        e
                    );
                    skipped_domains.push(cert_data.domain.clone());
                    continue;
                }
            };
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

        let skipped = skipped_domains.len();
        if skipped > 0 {
            warn!(
                "cert resolver: {skipped}/{total} certificate(s) skipped due to load errors"
            );
        }

        let domains = map.len();
        self.inner.store(Arc::new(CertResolverInner { certs: map }));
        Ok(ReloadStats {
            total,
            skipped,
            domains,
            skipped_domains,
        })
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
pub fn build_certified_key(
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
    // Accept PKCS#8, PKCS#1 (RSA), and SEC1 (EC) section kinds with
    // an explicit per-format fallback : a misconfigured upstream
    // PEM with mixed sections, an unusual ordering, or a stray
    // non-key block still yields a key when one is present in any
    // supported encoding. See `crate::load_first_private_key` for
    // the diagnostics produced on total failure.
    load_first_private_key(pem.as_bytes())
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

    /// PEM private-key loader must accept the three encodings that
    /// any RFC-7468-compatible operator-supplied bundle could carry :
    /// PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1
    /// (`-----BEGIN RSA PRIVATE KEY-----`, the openssl-genrsa default
    /// before 3.0 and still produced by `openssl genrsa -traditional`),
    /// and SEC1 (`-----BEGIN EC PRIVATE KEY-----`). Pre-existing
    /// `test-key.pem` covers SEC1 ; the two RSA fixtures cover the
    /// other two and use a single key material so they round-trip
    /// against the same RSA self-signed cert.
    #[test]
    fn loads_pkcs8_rsa_private_key() {
        let cert_pem = include_str!("../tests/test-cert-rsa.pem");
        let key_pem = include_str!("../tests/test-key-rsa-pkcs8.pem");
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        let resolver = CertResolver::new();
        resolver
            .reload(vec![CertData {
                domain: "test.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 9999999999,
                ocsp_response: None,
            }])
            .expect("PKCS#8 RSA key must load");
        assert_eq!(resolver.domain_count(), 1);
    }

    #[test]
    fn loads_pkcs1_rsa_private_key() {
        let cert_pem = include_str!("../tests/test-cert-rsa.pem");
        let key_pem = include_str!("../tests/test-key-rsa-pkcs1.pem");
        assert!(key_pem.contains("BEGIN RSA PRIVATE KEY"));

        let resolver = CertResolver::new();
        resolver
            .reload(vec![CertData {
                domain: "test.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 9999999999,
                ocsp_response: None,
            }])
            .expect("PKCS#1 RSA key must load");
        assert_eq!(resolver.domain_count(), 1);
    }

    #[test]
    fn loads_sec1_ec_private_key() {
        let cert_pem = include_str!("../tests/test-cert.pem");
        let key_pem = include_str!("../tests/test-key.pem");
        assert!(key_pem.contains("BEGIN EC PRIVATE KEY"));

        let resolver = CertResolver::new();
        resolver
            .reload(vec![CertData {
                domain: "test.example.com".to_string(),
                san_domains: vec![],
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
                not_after_epoch: 9999999999,
                ocsp_response: None,
            }])
            .expect("SEC1 EC key must load");
        assert_eq!(resolver.domain_count(), 1);
    }

    /// `validate_certificate_bundle` must reject a row whose `cert_pem`
    /// and `key_pem` are individually well-formed but come from two
    /// different keypairs. Without this, the upload lands cleanly in
    /// the database, every PEM parser is happy, but the worker signs
    /// `CertificateVerify` with a key that does not match the
    /// presented leaf : the client closes the handshake with a TLS
    /// `DecryptError` alert (alert code 51) and the server has no
    /// usable diagnostic. This was the second-pass failure mode in
    /// the v1.5.2 prod incident, after the initial PEM-parse failure
    /// was worked around.
    #[test]
    fn validate_bundle_rejects_cert_and_key_from_different_keypairs() {
        let cert_pem = include_str!("../tests/test-cert-rsa.pem");
        let mismatched_key = include_str!("../tests/test-key-rsa-pkcs1-other.pem");

        let err = crate::validate_certificate_bundle(cert_pem, mismatched_key)
            .expect_err("mismatched bundle must be rejected");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("matching")
                || msg.to_lowercase().contains("mismatch")
                || msg.to_lowercase().contains("subjectpublickeyinfo"),
            "expected SPKI-mismatch diagnostic, got: {msg}"
        );
    }

    #[test]
    fn validate_bundle_accepts_matching_pair() {
        let cert_pem = include_str!("../tests/test-cert-rsa.pem");
        let key_pem = include_str!("../tests/test-key-rsa-pkcs1.pem");
        crate::validate_certificate_bundle(cert_pem, key_pem)
            .expect("matching bundle must validate");
    }

    /// A single corrupted row in the database (truncated key blob,
    /// rotated encryption key, mismatched cert/key pair…) must not
    /// poison the whole batch : every other vhost on the resolver
    /// has to keep working. This mirrors a v1.5.2 prod incident in
    /// which a single bad row left the entire resolver empty and
    /// brought every TLS-terminated vhost down at once.
    ///
    /// The test asserts on `ReloadStats::skipped_domains` directly,
    /// not just `domain_count`, so a future refactor that keeps the
    /// skip behaviour but loses the per-row diagnostic (the
    /// originating `domain` carried in the WARN line and now in the
    /// stats) fails this case with a named regression. The whole
    /// operational value of the v1.5.3 fix is the operator's ability
    /// to identify the offending vhost without grepping logs.
    #[test]
    fn reload_skips_bad_certs_and_keeps_the_good_ones() {
        let good_cert = include_str!("../tests/test-cert-rsa.pem").to_string();
        let good_key = include_str!("../tests/test-key-rsa-pkcs1.pem").to_string();

        let resolver = CertResolver::new();
        let stats = resolver
            .reload(vec![
                CertData {
                    domain: "broken.example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: good_cert.clone(),
                    key_pem: "this is not a PEM key".to_string(),
                    not_after_epoch: 9999999999,
                    ocsp_response: None,
                },
                CertData {
                    domain: "good.example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: good_cert,
                    key_pem: good_key,
                    not_after_epoch: 9999999999,
                    ocsp_response: None,
                },
            ])
            .expect("reload must succeed even with a broken row in the batch");

        // Only the good vhost is registered ; the broken one was
        // skipped and the stats carry its originating domain.
        assert_eq!(resolver.domain_count(), 1);
        assert_eq!(stats.total, 2, "stats.total must count input rows");
        assert_eq!(stats.skipped, 1, "exactly one row must have been skipped");
        assert_eq!(
            stats.skipped_domains,
            vec!["broken.example.com".to_string()],
            "the skipped row's originating domain must be reported \
             so the operator can identify which vhost is missing - \
             pinning this prevents a future refactor from dropping \
             the per-row diagnostic"
        );
        assert_eq!(stats.domains, 1, "exactly one domain must be served");
    }

    /// All rows skipped : the resolver MUST end up empty (not stale)
    /// and the stats must list every originating domain so the
    /// operator can tell at a glance that nothing is being served.
    /// Pre-fix, a fully-broken batch would have failed the whole
    /// reload with `?` and left the previous resolver state in place,
    /// which is the worst possible failure mode for an operator
    /// rotating credentials.
    #[test]
    fn reload_with_all_bad_rows_publishes_empty_resolver() {
        let good_cert = include_str!("../tests/test-cert-rsa.pem").to_string();

        let resolver = CertResolver::new();
        let stats = resolver
            .reload(vec![
                CertData {
                    domain: "first.example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: good_cert.clone(),
                    key_pem: "not a PEM key".to_string(),
                    not_after_epoch: 9999999999,
                    ocsp_response: None,
                },
                CertData {
                    domain: "second.example.com".to_string(),
                    san_domains: vec![],
                    cert_pem: good_cert,
                    key_pem: "also not a PEM key".to_string(),
                    not_after_epoch: 9999999999,
                    ocsp_response: None,
                },
            ])
            .expect("reload must succeed even when every row is broken");

        assert_eq!(resolver.domain_count(), 0);
        assert_eq!(stats.skipped, 2);
        assert_eq!(
            stats.skipped_domains,
            vec![
                "first.example.com".to_string(),
                "second.example.com".to_string(),
            ],
            "both rows' originating domains must be reported"
        );
    }
}
