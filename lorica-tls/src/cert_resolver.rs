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
//! - A ClientHello without SNI, answered by the `iPAddress` SAN matching the
//!   local address the connection arrived on (see [`ResolvesServerCertByLocalIp`])

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
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
use x509_parser::extensions::GeneralName;

use crate::load_first_private_key;

/// The identity of a certificate: the SHA-256 of its leaf's DER.
///
/// An OCSP response is about one certificate (its CertID names the
/// leaf's serial and issuer), so [`CertResolver::refresh_staples`] takes
/// staples by this identity rather than by a name. Two certificates may
/// share a name, and each must keep its own staple whatever name or
/// address it is reached by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeafFingerprint([u8; 32]);

impl LeafFingerprint {
    /// The fingerprint of the leaf whose DER encoding is `der`.
    pub fn of_der(der: &[u8]) -> LeafFingerprint {
        let mut out: [u8; 32] = [0; 32];
        out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, der).as_ref());
        LeafFingerprint(out)
    }

    /// The fingerprint of the leaf of `cert_pem`, read as
    /// [`CertResolver::reload`] reads it (the first certificate block);
    /// `None` when the PEM holds no certificate.
    pub fn of_pem(cert_pem: &str) -> Option<LeafFingerprint> {
        parse_certs_from_pem(cert_pem)
            .ok()?
            .first()
            .map(|leaf: &CertificateDer<'static>| LeafFingerprint::of_der(leaf.as_ref()))
    }
}

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
///
/// Every name and address of one certificate holds a clone of the same
/// entry, so its `key` is one `Arc` shared by all of them.
#[derive(Clone)]
struct CertEntry {
    key: Arc<CertifiedKey>,
    not_after_epoch: i64,
    /// Which certificate this is, for [`CertResolver::refresh_staples`].
    leaf: LeafFingerprint,
}

/// Inner state of the resolver, atomically swapped on reload.
struct CertResolverInner {
    /// Maps lowercase domain -> certs sorted by expiry (longest-lived first).
    certs: HashMap<String, Vec<CertEntry>>,
    /// Maps an address carried as an `iPAddress` SAN of a leaf, in the
    /// family the SAN is written in (see [`ip_sans_of_leaf`]) -> certs
    /// sorted like `certs`. Read only for a ClientHello without SNI,
    /// never as a fallback for an SNI the domain map does not know.
    certs_by_ip: HashMap<IpAddr, Vec<CertEntry>>,
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
            .field("ips", &inner.certs_by_ip.keys().collect::<Vec<_>>())
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
                certs_by_ip: HashMap::new(),
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
    ///
    /// The IP index is derived from each leaf's own `iPAddress` SAN
    /// entries, never from [`CertData::san_domains`], so a certificate
    /// stored before the index existed is served by IP without a
    /// re-upload.
    pub fn reload(&self, certs: Vec<CertData>) -> Result<ReloadStats> {
        let mut map: HashMap<String, Vec<CertEntry>> = HashMap::new();
        let mut by_ip: HashMap<IpAddr, Vec<CertEntry>> = HashMap::new();
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
            let ip_sans: Vec<IpAddr> = leaf_ip_sans(&certified_key.cert);
            let domain = cert_data.domain.to_lowercase();
            // `build_certified_key` refuses a PEM without a certificate.
            let leaf = LeafFingerprint::of_der(certified_key.cert[0].as_ref());
            let entry = CertEntry {
                key: Arc::new(certified_key),
                not_after_epoch: cert_data.not_after_epoch,
                leaf,
            };

            // Register for primary domain
            map.entry(domain).or_default().push(entry.clone());

            // Register for each SAN domain
            for san in &cert_data.san_domains {
                let san_lower = san.to_lowercase();
                map.entry(san_lower).or_default().push(entry.clone());
            }

            for ip in ip_sans {
                by_ip.entry(ip).or_default().push(entry.clone());
            }
        }

        // Sort each domain's (and each address's) certs by expiry
        // descending (longest-lived first)
        for entries in map.values_mut().chain(by_ip.values_mut()) {
            entries.sort_by_key(|e| std::cmp::Reverse(e.not_after_epoch));
        }

        let skipped = skipped_domains.len();
        if skipped > 0 {
            warn!("cert resolver: {skipped}/{total} certificate(s) skipped due to load errors");
        }

        let domains = map.len();
        self.inner.store(Arc::new(CertResolverInner {
            certs: map,
            certs_by_ip: by_ip,
        }));
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

    /// The certificate for a connection accepted on `local_ip` whose
    /// ClientHello carries no SNI: the longest-lived certificate whose
    /// leaf lists `local_ip` as an `iPAddress` SAN, or `None`.
    ///
    /// RFC 6066 forbids an IP literal in SNI, so a client dialing
    /// `https://192.0.2.10` sends none, and the local address is the only
    /// name left to choose by. `local_ip` is canonicalised first: a
    /// dual-stack `[::]` listener reports an IPv4 client's local address
    /// as `::ffff:a.b.c.d`.
    pub fn resolve_by_local_ip(&self, local_ip: IpAddr) -> Option<Arc<CertifiedKey>> {
        self.inner
            .load()
            .certs_by_ip
            .get(&local_ip.to_canonical())
            .and_then(|entries| entries.first())
            .map(|entry| Arc::clone(&entry.key))
    }

    /// Whether any loaded certificate carries an `iPAddress` SAN, read
    /// from the current hot-swapped table. When it is `false`,
    /// [`Self::resolve_by_local_ip`] answers `None` for every address, so
    /// a listener can skip learning the local address of a connection.
    pub fn has_local_ip_certs(&self) -> bool {
        !self.inner.load().certs_by_ip.is_empty()
    }

    /// Atomically replace the OCSP staple bytes on already-loaded
    /// certificates without re-parsing PEM or re-deriving signing keys.
    ///
    /// `staples` maps a certificate, by [`LeafFingerprint`], to a fresh
    /// DER-encoded OCSP response. Each loaded certificate present in the
    /// map gets one new `CertifiedKey` carrying its staple (the parsed
    /// chain is cloned once, the signing key is `Arc`-shared), and every
    /// name and address that certificate is registered under shares that
    /// one key. A certificate is therefore served with its own staple
    /// whatever name or address it is reached by, even when another
    /// certificate shares one of its names. Certificates absent from the
    /// map keep their current key untouched. The whole rebuilt table is
    /// published with a single `arc-swap`, so in-flight TLS handshakes
    /// keep serving their already-negotiated `CertifiedKey` (Story 8.5
    /// AC #2 / AC #6). This is the OCSP-only counterpart to
    /// [`Self::reload`]: reload swaps cert bodies, this swaps staples,
    /// and the two never block each other on the network.
    pub fn refresh_staples(&self, staples: &HashMap<LeafFingerprint, Vec<u8>>) -> RefreshStats {
        let current = self.inner.load();
        let mut restapled: HashMap<LeafFingerprint, Arc<CertifiedKey>> = HashMap::new();
        let mut unchanged: HashSet<LeafFingerprint> = HashSet::new();
        let mut restaple = |entry: &CertEntry| -> CertEntry {
            let Some(ocsp) = staples.get(&entry.leaf) else {
                unchanged.insert(entry.leaf);
                return entry.clone();
            };
            let key: &Arc<CertifiedKey> = restapled.entry(entry.leaf).or_insert_with(|| {
                let mut ck = CertifiedKey::new(entry.key.cert.clone(), Arc::clone(&entry.key.key));
                ck.ocsp = Some(ocsp.clone());
                Arc::new(ck)
            });
            CertEntry {
                key: Arc::clone(key),
                not_after_epoch: entry.not_after_epoch,
                leaf: entry.leaf,
            }
        };

        let certs: HashMap<String, Vec<CertEntry>> = current
            .certs
            .iter()
            .map(|(domain, entries)| (domain.clone(), entries.iter().map(&mut restaple).collect()))
            .collect();
        let certs_by_ip: HashMap<IpAddr, Vec<CertEntry>> = current
            .certs_by_ip
            .iter()
            .map(|(ip, entries)| (*ip, entries.iter().map(&mut restaple).collect()))
            .collect();

        self.inner
            .store(Arc::new(CertResolverInner { certs, certs_by_ip }));
        RefreshStats {
            refreshed: restapled.len(),
            unchanged: unchanged.len(),
        }
    }

    /// Snapshot of every registered domain key, lowercased, in no
    /// particular order. The OCSP refresh loop uses it only for logging
    /// and gauge cardinality; staple fetching is driven from the cert
    /// store (which retains the PEM), not from this list.
    pub fn domains(&self) -> Vec<String> {
        self.inner.load().certs.keys().cloned().collect()
    }

    /// The OCSP staple currently attached to the first (longest-lived)
    /// cert registered for `domain`, if any. Test-only accessor used to
    /// assert that [`Self::refresh_staples`] published the fresh bytes.
    #[cfg(test)]
    fn staple_for(&self, domain: &str) -> Option<Vec<u8>> {
        self.inner
            .load()
            .certs
            .get(domain)
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.key.ocsp.clone())
    }

    /// [`Self::staple_for`] on the IP index.
    #[cfg(test)]
    fn ip_staple_for(&self, ip: IpAddr) -> Option<Vec<u8>> {
        self.resolve_by_local_ip(ip)
            .and_then(|key: Arc<CertifiedKey>| key.ocsp.clone())
    }

    /// Every key registered under `domain`, in serving order.
    #[cfg(test)]
    fn keys_for(&self, domain: &str) -> Vec<Arc<CertifiedKey>> {
        self.inner
            .load()
            .certs
            .get(domain)
            .map(|entries: &Vec<CertEntry>| {
                entries
                    .iter()
                    .map(|entry: &CertEntry| Arc::clone(&entry.key))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The canonical `iPAddress` entries of the subjectAltName of `chain`'s
/// leaf, without duplicates; empty when the leaf cannot be parsed or
/// lists none. An entry of any length but 4 or 16 octets is not an
/// address (RFC 5280 section 4.2.1.6) and is skipped.
fn leaf_ip_sans(chain: &[CertificateDer<'_>]) -> Vec<IpAddr> {
    let Some(leaf) = chain.first() else {
        return Vec::new();
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = san
        .value
        .general_names
        .iter()
        .filter_map(|name: &GeneralName<'_>| match name {
            GeneralName::IPAddress(octets) => ip_from_san_octets(octets),
            _ => None,
        })
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn ip_from_san_octets(octets: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(octets) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(octets)
        .ok()
        .map(|v6: [u8; 16]| IpAddr::from(v6).to_canonical())
}

/// A certificate resolver that can also answer a ClientHello carrying no
/// SNI, by the local IP address the connection was accepted on.
///
/// rustls hands [`ResolvesServerCert::resolve`] the ClientHello alone, so
/// a listener that serves this path learns the local address before the
/// handshake and gives that connection a [`LocalIpResolver`].
pub trait ResolvesServerCertByLocalIp: ResolvesServerCert {
    /// The certificate for a connection accepted on `local_ip` whose
    /// ClientHello names no server, `None` when none carries that address.
    fn resolve_by_local_ip(&self, local_ip: IpAddr) -> Option<Arc<CertifiedKey>>;

    /// Whether [`Self::resolve_by_local_ip`] can answer anything at all
    /// right now. A listener asks this on every accept before it reads the
    /// connection's local address, which costs a `getsockname` syscall, so
    /// it must be cheap and must never answer `false` while some address
    /// would resolve.
    fn has_local_ip_certs(&self) -> bool;
}

impl ResolvesServerCertByLocalIp for CertResolver {
    fn resolve_by_local_ip(&self, local_ip: IpAddr) -> Option<Arc<CertifiedKey>> {
        CertResolver::resolve_by_local_ip(self, local_ip)
    }

    fn has_local_ip_certs(&self) -> bool {
        CertResolver::has_local_ip_certs(self)
    }
}

/// The resolver of the connections accepted on one local address.
///
/// A ClientHello with SNI goes to the shared resolver's SNI lookup,
/// exactly as on a listener without IP certificates: an SNI the resolver
/// does not know fails the handshake rather than falling back to the
/// address. A ClientHello without SNI (rustls also reports none for an
/// IP literal sent as SNI) gets the certificate for the address. Both
/// lookups go to the shared resolver on every handshake, so a reload or
/// a staple refresh is seen at once.
#[derive(Debug)]
pub struct LocalIpResolver {
    shared: Arc<dyn ResolvesServerCertByLocalIp>,
    local_ip: IpAddr,
}

impl LocalIpResolver {
    /// The resolver for connections accepted on `local_ip`, backed by
    /// `shared`.
    pub fn new(shared: Arc<dyn ResolvesServerCertByLocalIp>, local_ip: IpAddr) -> LocalIpResolver {
        LocalIpResolver { shared, local_ip }
    }
}

impl ResolvesServerCert for LocalIpResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if client_hello.server_name().is_some() {
            self.shared.resolve(client_hello)
        } else {
            self.shared.resolve_by_local_ip(self.local_ip)
        }
    }
}

/// Outcome counts for one [`CertResolver::refresh_staples`] call, in
/// loaded certificates (distinct [`LeafFingerprint`]s), not in the names
/// or addresses they are registered under. The OCSP refresh loop in
/// `lorica` logs them; its `lorica_ocsp_refresh_total` counter counts
/// responder fetches instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshStats {
    /// Certificates whose staple was replaced.
    pub refreshed: usize,
    /// Certificates absent from the staple map, whose existing staple,
    /// if any, is kept.
    pub unchanged: usize,
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

    /// `refresh_staples` must replace the OCSP bytes on a loaded cert
    /// without changing the served domain set, and report the count of
    /// refreshed vs untouched domains. This is the background-loop swap
    /// (Story 8.5) : reload puts the cert body in with no staple, the
    /// loop attaches the staple later without a PEM re-parse.
    #[test]
    fn refresh_staples_replaces_ocsp_bytes_and_counts() {
        let cert: IpCert = ip_cert(
            "stapled.example.com",
            &["alt.example.com"],
            &[],
            9_999_999_999,
        );
        let resolver = CertResolver::new();
        resolver.reload(vec![cert.data.clone()]).unwrap();

        // No staple after a body-only reload.
        assert_eq!(resolver.staple_for("stapled.example.com"), None);

        let fresh: Vec<u8> = vec![0x30, 0x03, 0x0A, 0x01, 0x00];
        let stats: RefreshStats = resolver.refresh_staples(&staples_of(&[(&cert, fresh.clone())]));

        assert_eq!(stats.refreshed, 1, "one certificate, whatever its names");
        assert_eq!(stats.unchanged, 0);
        assert_eq!(resolver.domain_count(), 2, "domain set is unchanged");
        assert_eq!(
            resolver.staple_for("stapled.example.com"),
            Some(fresh.clone())
        );
        assert_eq!(resolver.staple_for("alt.example.com"), Some(fresh));
        assert!(
            Arc::ptr_eq(
                &resolver.keys_for("stapled.example.com")[0],
                &resolver.keys_for("alt.example.com")[0]
            ),
            "the names of one certificate share one restapled key"
        );
    }

    /// A staple map that misses a loaded certificate must leave that
    /// certificate's existing key untouched and count it as `unchanged`,
    /// so a transient OCSP-fetch failure for one vhost never drops the
    /// staple (or the cert) of the others.
    #[test]
    fn refresh_staples_leaves_unlisted_certificates_untouched() {
        let a: IpCert = ip_cert("a.example.com", &[], &[], 9_999_999_999);
        let mut b: IpCert = ip_cert("b.example.com", &[], &[], 9_999_999_999);
        b.data.ocsp_response = Some(vec![0xBB]);
        let resolver = CertResolver::new();
        resolver.reload(vec![a.data.clone(), b.data]).unwrap();

        let stats: RefreshStats = resolver.refresh_staples(&staples_of(&[(&a, vec![0xCC])]));

        assert_eq!(stats.refreshed, 1);
        assert_eq!(stats.unchanged, 1);
        assert_eq!(resolver.staple_for("a.example.com"), Some(vec![0xCC]));
        assert_eq!(
            resolver.staple_for("b.example.com"),
            Some(vec![0xBB]),
            "an unlisted certificate keeps its prior staple"
        );
    }

    /// Two certificates sharing a name each keep their own staple, under
    /// that name, under their other names and on the IP path. Keyed by
    /// name, the last certificate written won the shared name and its
    /// response was stapled to the other.
    #[test]
    fn two_certificates_sharing_a_name_each_keep_their_own_staple() {
        let first: IpCert = ip_cert("shared.example.com", &[], &[ip("192.0.2.10")], 9_000);
        let second: IpCert = ip_cert(
            "other.example.com",
            &["shared.example.com"],
            &[ip("192.0.2.20")],
            9_999,
        );
        let resolver = CertResolver::new();
        resolver
            .reload(vec![first.data.clone(), second.data.clone()])
            .unwrap();

        let stats: RefreshStats =
            resolver.refresh_staples(&staples_of(&[(&first, vec![0x01]), (&second, vec![0x02])]));

        assert_eq!(stats.refreshed, 2);
        let under_shared: Vec<(Vec<u8>, Option<Vec<u8>>)> = resolver
            .keys_for("shared.example.com")
            .iter()
            .map(|key: &Arc<CertifiedKey>| (key.cert[0].to_vec(), key.ocsp.clone()))
            .collect();
        assert_eq!(
            under_shared,
            vec![
                (second.der.clone(), Some(vec![0x02])),
                (first.der.clone(), Some(vec![0x01])),
            ],
            "each certificate under the shared name carries its own staple"
        );
        assert_eq!(resolver.staple_for("other.example.com"), Some(vec![0x02]));
        assert_eq!(resolver.ip_staple_for(ip("192.0.2.10")), Some(vec![0x01]));
        assert_eq!(resolver.ip_staple_for(ip("192.0.2.20")), Some(vec![0x02]));
        assert!(
            Arc::ptr_eq(
                &resolver.keys_for("shared.example.com")[1],
                &resolver.resolve_by_local_ip(ip("192.0.2.10")).unwrap()
            ),
            "a certificate's name and address share one restapled key"
        );
    }

    #[test]
    fn a_leaf_fingerprint_is_the_same_from_the_pem_and_from_the_loaded_chain() {
        let cert: IpCert = ip_cert("a.example.com", &[], &[], 9_999_999_999);
        assert_eq!(
            LeafFingerprint::of_pem(&cert.data.cert_pem),
            Some(LeafFingerprint::of_der(&cert.der))
        );
        assert_eq!(LeafFingerprint::of_pem("not a certificate"), None);
    }

    /// A self-signed certificate, its key, and the leaf's DER, for the
    /// IP index tests: `dns` and `ips` as its SAN entries.
    struct IpCert {
        data: CertData,
        der: Vec<u8>,
    }

    fn ip_cert(domain: &str, dns: &[&str], ips: &[IpAddr], not_after_epoch: i64) -> IpCert {
        let key: rcgen::KeyPair = rcgen::KeyPair::generate().expect("test setup: key");
        let mut params: rcgen::CertificateParams = rcgen::CertificateParams::new(
            dns.iter()
                .map(|d: &&str| d.to_string())
                .collect::<Vec<String>>(),
        )
        .expect("test setup: params");
        params
            .subject_alt_names
            .extend(ips.iter().map(|ip: &IpAddr| rcgen::SanType::IpAddress(*ip)));
        let cert: rcgen::Certificate = params.self_signed(&key).expect("test setup: certificate");
        IpCert {
            der: cert.der().to_vec(),
            data: CertData {
                domain: domain.to_string(),
                san_domains: dns.iter().map(|d: &&str| d.to_string()).collect(),
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
                not_after_epoch,
                ocsp_response: None,
            },
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test setup: address")
    }

    /// A staple map as the OCSP loop builds it, from each certificate's
    /// stored PEM.
    fn staples_of(staples: &[(&IpCert, Vec<u8>)]) -> HashMap<LeafFingerprint, Vec<u8>> {
        staples
            .iter()
            .map(|(cert, ocsp): &(&IpCert, Vec<u8>)| {
                (
                    LeafFingerprint::of_pem(&cert.data.cert_pem).expect("test setup: PEM"),
                    ocsp.clone(),
                )
            })
            .collect()
    }

    fn served_der(resolver: &CertResolver, local_ip: IpAddr) -> Option<Vec<u8>> {
        resolver
            .resolve_by_local_ip(local_ip)
            .map(|key: Arc<CertifiedKey>| key.cert[0].to_vec())
    }

    #[test]
    fn an_ipv4_san_is_served_on_that_local_address_only() {
        let cert: IpCert = ip_cert(
            "localhost",
            &["localhost"],
            &[ip("192.0.2.10")],
            9_999_999_999,
        );
        let resolver = CertResolver::new();
        resolver.reload(vec![cert.data.clone()]).unwrap();

        assert_eq!(served_der(&resolver, ip("192.0.2.10")), Some(cert.der));
        assert_eq!(served_der(&resolver, ip("192.0.2.11")), None);
        assert_eq!(
            resolver.domain_count(),
            1,
            "an IP SAN never enters the domain map"
        );
    }

    #[test]
    fn an_ipv6_san_is_served_on_that_local_address() {
        let cert: IpCert = ip_cert("localhost", &[], &[ip("2001:db8::1")], 9_999_999_999);
        let resolver = CertResolver::new();
        resolver.reload(vec![cert.data.clone()]).unwrap();

        assert_eq!(served_der(&resolver, ip("2001:db8::1")), Some(cert.der));
        assert_eq!(served_der(&resolver, ip("2001:db8::2")), None);
    }

    /// A dual-stack `[::]` listener reports an IPv4 client's local
    /// address as `::ffff:a.b.c.d`; it must find the IPv4 SAN.
    #[test]
    fn an_ipv4_mapped_local_address_finds_the_ipv4_san() {
        let cert: IpCert = ip_cert("localhost", &[], &[ip("192.0.2.10")], 9_999_999_999);
        let resolver = CertResolver::new();
        resolver.reload(vec![cert.data.clone()]).unwrap();

        assert_eq!(
            served_der(&resolver, ip("::ffff:192.0.2.10")),
            Some(cert.der)
        );
    }

    #[test]
    fn has_local_ip_certs_follows_the_loaded_table() {
        let resolver = CertResolver::new();
        assert!(!resolver.has_local_ip_certs(), "an empty resolver");

        let dns_only: IpCert = ip_cert("example.com", &["example.com"], &[], 9_999_999_999);
        resolver.reload(vec![dns_only.data.clone()]).unwrap();
        assert!(!resolver.has_local_ip_certs(), "DNS SANs only");

        let with_ip: IpCert = ip_cert("localhost", &[], &[ip("192.0.2.10")], 9_999_999_999);
        resolver
            .reload(vec![dns_only.data.clone(), with_ip.data])
            .unwrap();
        assert!(
            resolver.has_local_ip_certs(),
            "a certificate with an IP SAN"
        );

        resolver.reload(vec![dns_only.data]).unwrap();
        assert!(
            !resolver.has_local_ip_certs(),
            "a reload that drops the IP certificate"
        );
    }

    #[test]
    fn no_certificate_for_an_address_no_certificate_carries() {
        let dns_only: IpCert = ip_cert("example.com", &["example.com"], &[], 9_999_999_999);
        let resolver = CertResolver::new();
        resolver.reload(vec![dns_only.data]).unwrap();

        assert_eq!(served_der(&resolver, ip("127.0.0.1")), None);
        assert_eq!(served_der(&resolver, ip("::1")), None);
    }

    /// The IP index comes from the leaf, not from `san_domains`: an
    /// address string in `san_domains` (which no part of Lorica writes
    /// there) does not make a certificate servable by IP.
    #[test]
    fn the_ip_index_is_derived_from_the_certificate_not_from_san_domains() {
        let mut cert: IpCert = ip_cert("localhost", &["localhost"], &[], 9_999_999_999);
        cert.data.san_domains.push("192.0.2.99".to_string());
        let resolver = CertResolver::new();
        resolver.reload(vec![cert.data]).unwrap();

        assert_eq!(served_der(&resolver, ip("192.0.2.99")), None);
    }

    #[test]
    fn the_longest_lived_certificate_for_an_address_is_served_first() {
        let address: IpAddr = ip("192.0.2.10");
        let short: IpCert = ip_cert("short.example", &[], &[address], 1_000);
        let long: IpCert = ip_cert("long.example", &[], &[address], 9_000);
        let resolver = CertResolver::new();
        resolver
            .reload(vec![short.data.clone(), long.data.clone()])
            .unwrap();
        assert_eq!(served_der(&resolver, address), Some(long.der.clone()));

        resolver.reload(vec![long.data, short.data]).unwrap();
        assert_eq!(
            served_der(&resolver, address),
            Some(long.der),
            "the order of the rows does not decide"
        );
    }

    /// A certificate served by IP must carry the same fresh staple as
    /// when its name is sent as SNI, and a certificate whose staple is
    /// missing keeps the one it had.
    #[test]
    fn a_staple_refresh_reaches_the_ip_index() {
        let stapled: IpCert = ip_cert(
            "stapled.example.com",
            &[],
            &[ip("192.0.2.10")],
            9_999_999_999,
        );
        let mut kept: IpCert =
            ip_cert("kept.example.com", &[], &[ip("2001:db8::1")], 9_999_999_999);
        kept.data.ocsp_response = Some(vec![0xBB]);
        let resolver = CertResolver::new();
        resolver
            .reload(vec![stapled.data.clone(), kept.data])
            .unwrap();
        assert_eq!(resolver.ip_staple_for(ip("192.0.2.10")), None);

        let fresh: Vec<u8> = vec![0x30, 0x03, 0x0A, 0x01, 0x00];
        let stats: RefreshStats =
            resolver.refresh_staples(&staples_of(&[(&stapled, fresh.clone())]));

        assert_eq!(stats.refreshed, 1);
        assert_eq!(stats.unchanged, 1);
        assert_eq!(
            resolver.ip_staple_for(ip("192.0.2.10")),
            Some(fresh.clone())
        );
        assert_eq!(
            resolver.ip_staple_for(ip("192.0.2.10")),
            resolver.staple_for("stapled.example.com"),
            "the IP path and the SNI path serve the same staple"
        );
        assert_eq!(resolver.ip_staple_for(ip("2001:db8::1")), Some(vec![0xBB]));
    }
}
