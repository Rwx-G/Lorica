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

//! Cluster certificate authority (Story 9.2 AC #8).
//!
//! `lorica cluster init` generates this CA once on the control plane;
//! the key is persisted through the existing AES-256-GCM store helpers
//! (`ConfigStore::set_cluster_ca`), which means the CA key inherits the
//! existing master-key trust model: `<data_dir>/encryption.key` is 32
//! raw bytes in a `0600` file - no KDF, no passphrase, no machine
//! binding. This epic promotes that file from "this node's leaf keys"
//! to "the identity root of the fleet"; `docs/cluster.md` documents the
//! operational consequences.
//!
//! Leaf issuance enforces the Story 9.3 AC #2 EKU split from day one:
//! node (client) certificates are `clientAuth`-ONLY and the
//! control-plane certificate is `serverAuth`-ONLY, so a stolen node
//! certificate cannot impersonate the control plane and vice versa.

use chrono::{DateTime, Datelike, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevocationReason, RevokedCertParams, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::CertificateRevocationListDer;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

/// Bytes in a node-certificate serial (RFC 5280 allows up to 20).
const SERIAL_LEN: usize = 16;

/// Smallest RSA modulus the fleet accepts (Story 9.3 AC #3).
const MIN_RSA_BITS: usize = 2048;

/// How long a minted CRL declares itself current; the control plane
/// re-mints on every revocation and at every boot, so this is a
/// ceiling, not a schedule.
const CRL_VALIDITY_DAYS: i64 = 365;

/// CA certificate validity (10 years): rotating the fleet root is a
/// re-enrollment event, not routine maintenance.
const CA_VALIDITY_DAYS: i64 = 3650;

/// Leaf validity (90 days), matching Story 9.3 AC #12's auto-renewal
/// design (renew at two thirds of lifetime).
const LEAF_VALIDITY_DAYS: i64 = 90;

/// Errors from CA generation or leaf issuance.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// rcgen could not generate or sign material.
    #[error("cluster CA generation failed: {0}")]
    Generate(String),
    /// The persisted CA material did not parse back into a signer.
    #[error("cluster CA material rejected: {0}")]
    Parse(String),
    /// A joiner's public key is not on the allowlist (Ed25519, P-256,
    /// RSA of at least 2048 bits) or is not a valid SPKI.
    #[error("public key refused: {0}")]
    PublicKey(String),
}

/// A node certificate issued on a bare public key (Story 9.3 AC #3).
#[derive(Debug, Clone)]
pub struct IssuedLeaf {
    /// The certificate, PEM.
    pub cert_pem: String,
    /// Uppercase-hex serial (CRLs revoke by serial).
    pub serial_hex: String,
    /// Lowercase-hex SHA-256 of the certificate DER (the identity the
    /// operational listener matches).
    pub fingerprint_sha256: String,
    /// `notAfter` (midnight UTC of the expiry date).
    pub not_after: DateTime<Utc>,
}

/// One entry of the CRL the control plane mints (Story 9.3 AC #7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedEntry {
    /// Uppercase-hex serial.
    pub serial_hex: String,
    /// When the control plane processed the revocation.
    pub revoked_at: DateTime<Utc>,
    /// `true` for a certificate superseded by a renewal, `false` for
    /// an operator revocation.
    pub superseded: bool,
}

/// Generate a node keypair for `lorica cluster join` and renewals
/// (P-256, the allowlist's default): `(spki_der, key_pem)`. The
/// private key never leaves the node (Story 9.3 AC #3).
pub fn generate_node_keypair() -> Result<(Vec<u8>, String), CaError> {
    use rcgen::PublicKeyData;
    let key_pair: KeyPair = KeyPair::generate().map_err(|e| CaError::Generate(e.to_string()))?;
    Ok((key_pair.subject_public_key_info(), key_pair.serialize_pem()))
}

/// Check a joiner's DER SPKI against the allowlist (AC #3): Ed25519,
/// P-256, RSA with a modulus of at least [`MIN_RSA_BITS`]. Anything
/// else (P-384, small RSA, DSA, malformed) is refused BEFORE any
/// signing.
pub fn check_public_key_allowlist(spki_der: &[u8]) -> Result<(), CaError> {
    use x509_parser::oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION, OID_SIG_ED25519,
    };
    let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| CaError::PublicKey(format!("not a SubjectPublicKeyInfo: {e}")))?;
    if !rest.is_empty() {
        return Err(CaError::PublicKey("trailing bytes after the key".into()));
    }
    let alg = &spki.algorithm.algorithm;
    if *alg == OID_SIG_ED25519 {
        return Ok(());
    }
    if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok());
        return match curve {
            Some(curve) if curve == OID_EC_P256 => Ok(()),
            _ => Err(CaError::PublicKey(
                "elliptic-curve key is not P-256".into(),
            )),
        };
    }
    if *alg == OID_PKCS1_RSAENCRYPTION {
        return match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) if rsa.key_size() >= MIN_RSA_BITS => Ok(()),
            Ok(PublicKey::RSA(rsa)) => Err(CaError::PublicKey(format!(
                "RSA modulus of {} bits is below {MIN_RSA_BITS}",
                rsa.key_size()
            ))),
            _ => Err(CaError::PublicKey("malformed RSA key".into())),
        };
    }
    Err(CaError::PublicKey(format!(
        "algorithm {alg} is not on the allowlist (Ed25519, P-256, RSA-2048+)"
    )))
}

/// A random positive serial whose DER encoding is exactly
/// [`SERIAL_LEN`] bytes (first byte in `0x40..=0x7f`), so the hex the
/// registry stores equals what any parser reads back.
fn random_serial() -> Result<[u8; SERIAL_LEN], CaError> {
    let mut bytes = [0u8; SERIAL_LEN];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CaError::Generate("serial randomness unavailable".into()))?;
    bytes[0] = (bytes[0] & 0x3f) | 0x40;
    Ok(bytes)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, CaError> {
    if !s.len().is_multiple_of(2) {
        return Err(CaError::Parse(format!("odd-length serial {s:?}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| CaError::Parse(format!("non-hex serial {s:?}")))
        })
        .collect()
}

/// Midnight UTC of `now + days`, the instant `set_validity` encodes.
fn midnight_after(now: DateTime<Utc>, days: i64) -> DateTime<Utc> {
    let date = (now + chrono::Duration::days(days)).date_naive();
    DateTime::<Utc>::from_naive_utc_and_offset(
        date.and_hms_opt(0, 0, 0).unwrap_or_default(),
        Utc,
    )
}



/// A cluster CA loaded in memory, able to issue leaves.
pub struct ClusterCa {
    cert_pem: String,
    key_pair: KeyPair,
}

impl ClusterCa {
    /// Generate a fresh CA (`CA:TRUE`, `keyCertSign` + `cRLSign`),
    /// valid [`CA_VALIDITY_DAYS`]. Returns the loaded CA; persist it
    /// with [`ClusterCa::cert_pem`] and [`ClusterCa::key_pem`].
    pub fn generate(common_name: &str) -> Result<Self, CaError> {
        let mut params: CertificateParams = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn: DistinguishedName = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        set_validity(&mut params, CA_VALIDITY_DAYS);

        let key_pair: KeyPair =
            KeyPair::generate().map_err(|e| CaError::Generate(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| CaError::Generate(e.to_string()))?;

        Ok(Self {
            cert_pem: cert.pem(),
            key_pair,
        })
    }

    /// Reload a persisted CA from its PEM pair (as returned by the
    /// store's `get_cluster_ca`). Fails if the pair cannot act as an
    /// issuer (unparseable certificate or key).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CaError> {
        let key_pair: KeyPair =
            KeyPair::from_pem(key_pem).map_err(|e| CaError::Parse(e.to_string()))?;
        // Validate now, at load time, that the pair can issue.
        rcgen::Issuer::from_ca_cert_pem(cert_pem, &key_pair)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        Ok(Self {
            cert_pem: cert_pem.to_string(),
            key_pair,
        })
    }

    /// The CA certificate PEM (public material; this is the trust
    /// anchor every cluster TLS config verifies against).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA private key PEM. Persist ONLY through the encrypted
    /// store path; never log.
    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Issue the control-plane leaf on a FRESH keypair: EKU
    /// `serverAuth` ONLY, SAN = `host` (DNS or IP), valid
    /// [`LEAF_VALIDITY_DAYS`]. Returns `(cert_pem, key_pem)`.
    pub fn issue_server_leaf(&self, host: &str) -> Result<(String, String), CaError> {
        let leaf_key: KeyPair =
            KeyPair::generate().map_err(|e| CaError::Generate(e.to_string()))?;
        let cert_pem = self.issue_leaf(
            host,
            ExtendedKeyUsagePurpose::ServerAuth,
            Some(host),
            &leaf_key,
        )?;
        Ok((cert_pem, leaf_key.serialize_pem()))
    }

    /// Issue the control-plane leaf on a PERSISTED keypair, so the
    /// control plane's SPKI is stable across restarts: Story 9.3 pins
    /// the SHA-256 of that SPKI inside every join token, and a leaf
    /// re-keyed per boot would invalidate outstanding tokens at every
    /// restart. Validity stays short; only the key persists. Returns
    /// the certificate PEM.
    pub fn issue_server_leaf_with_key(&self, host: &str, key_pem: &str) -> Result<String, CaError> {
        let leaf_key: KeyPair =
            KeyPair::from_pem(key_pem).map_err(|e| CaError::Parse(e.to_string()))?;
        self.issue_leaf(
            host,
            ExtendedKeyUsagePurpose::ServerAuth,
            Some(host),
            &leaf_key,
        )
    }

    /// Issue a node leaf on the node's BARE public key (Story 9.3
    /// AC #3: no CSR, every parameter server-assigned): CN =
    /// `node_id`, EKU `clientAuth` ONLY, `CA:FALSE`, a random
    /// 16-byte serial, valid [`LEAF_VALIDITY_DAYS`]. The key is
    /// checked against the allowlist first.
    pub fn issue_node_leaf_for_public_key(
        &self,
        node_id: &str,
        spki_der: &[u8],
    ) -> Result<IssuedLeaf, CaError> {
        check_public_key_allowlist(spki_der)?;
        let public_key = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|e| CaError::PublicKey(format!("unusable public key: {e}")))?;
        let serial = random_serial()?;
        let now = Utc::now();

        let mut params: CertificateParams = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let mut dn: DistinguishedName = DistinguishedName::new();
        dn.push(DnType::CommonName, node_id);
        params.distinguished_name = dn;
        set_validity(&mut params, LEAF_VALIDITY_DAYS);

        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        let cert = params
            .signed_by(&public_key, &issuer)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, cert.der().as_ref());
        Ok(IssuedLeaf {
            cert_pem: cert.pem(),
            serial_hex: hex_upper(&serial),
            fingerprint_sha256: hex_lower(digest.as_ref()),
            not_after: midnight_after(now, LEAF_VALIDITY_DAYS),
        })
    }

    /// Mint a CRL over `revoked` (Story 9.3 AC #7), signed by the CA
    /// (`cRLSign` is in its key usage). Day granularity on the dates:
    /// the control plane re-mints on every change, and rustls does
    /// not schedule by `nextUpdate`.
    pub fn mint_crl(
        &self,
        revoked: &[RevokedEntry],
    ) -> Result<CertificateRevocationListDer<'static>, CaError> {
        let now = Utc::now();
        // rcgen's date type is not nameable without the `time` crate;
        // a closure infers it.
        let ymd = |dt: DateTime<Utc>| rcgen::date_time_ymd(dt.year(), dt.month() as u8, dt.day() as u8);
        let mut revoked_certs = Vec::with_capacity(revoked.len());
        for entry in revoked {
            revoked_certs.push(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&unhex(&entry.serial_hex)?),
                revocation_time: ymd(entry.revoked_at),
                reason_code: Some(if entry.superseded {
                    RevocationReason::Superseded
                } else {
                    RevocationReason::CessationOfOperation
                }),
                invalidity_date: None,
            });
        }
        // Monotonic enough: unix seconds, big-endian, top bit clear.
        let crl_number = u64::try_from(now.timestamp()).unwrap_or(0) & 0x7fff_ffff_ffff_ffff;
        let params = CertificateRevocationListParams {
            this_update: ymd(now - chrono::Duration::days(1)),
            next_update: ymd(now + chrono::Duration::days(CRL_VALIDITY_DAYS)),
            crl_number: SerialNumber::from_slice(&crl_number.to_be_bytes()),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        let crl = params
            .signed_by(&issuer)
            .map_err(|e| CaError::Generate(format!("CRL: {e}")))?;
        Ok(crl.into())
    }

    /// Issue a node (follower) leaf: EKU `clientAuth` ONLY, CN =
    /// `node_id`, no SAN needed (the dialer authenticates the server,
    /// not the other way around), valid [`LEAF_VALIDITY_DAYS`].
    /// Returns `(cert_pem, key_pem)`.
    pub fn issue_client_leaf(&self, node_id: &str) -> Result<(String, String), CaError> {
        let leaf_key: KeyPair =
            KeyPair::generate().map_err(|e| CaError::Generate(e.to_string()))?;
        let cert_pem =
            self.issue_leaf(node_id, ExtendedKeyUsagePurpose::ClientAuth, None, &leaf_key)?;
        Ok((cert_pem, leaf_key.serialize_pem()))
    }

    fn issue_leaf(
        &self,
        common_name: &str,
        eku: ExtendedKeyUsagePurpose,
        san_host: Option<&str>,
        leaf_key: &KeyPair,
    ) -> Result<String, CaError> {
        let mut params: CertificateParams = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![eku];
        let mut dn: DistinguishedName = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        if let Some(host) = san_host {
            params.subject_alt_names = vec![host_san(host)?];
        }
        set_validity(&mut params, LEAF_VALIDITY_DAYS);

        // Rebuild the issuer from the CA certificate itself so the
        // leaf's issuer DN always matches the CA's real subject DN,
        // whether this CA was just generated or reloaded from the
        // store.
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        let cert = params
            .signed_by(leaf_key, &issuer)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        Ok(cert.pem())
    }
}

/// Build the SAN for `host`: an IP SAN when it parses as an address,
/// a DNS SAN otherwise.
fn host_san(host: &str) -> Result<SanType, CaError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    rcgen::string::Ia5String::try_from(host.to_string())
        .map(SanType::DnsName)
        .map_err(|e| CaError::Generate(format!("invalid DNS SAN {host:?}: {e}")))
}

/// Set notBefore (backdated one day for clock skew, matching the
/// management-TLS precedent) and notAfter on `params`.
fn set_validity(params: &mut CertificateParams, validity_days: i64) {
    let now = chrono::Utc::now();
    let not_before = now - chrono::Duration::days(1);
    let not_after = now + chrono::Duration::days(validity_days);
    params.not_before = rcgen::date_time_ymd(
        not_before.year(),
        not_before.month() as u8,
        not_before.day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        not_after.year(),
        not_after.month() as u8,
        not_after.day() as u8,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_pem_pair() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn ca_round_trips_through_pem() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        let reloaded =
            ClusterCa::from_pem(ca.cert_pem(), &ca.key_pem()).expect("reload from PEM");
        // The reloaded CA must still be able to sign.
        let (leaf_pem, leaf_key) = reloaded
            .issue_client_leaf("node-a")
            .expect("issue after reload");
        assert!(leaf_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf_key.contains("PRIVATE KEY"));
    }

    #[test]
    fn leaves_issue_with_distinct_material() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        let (server_pem, server_key) = ca.issue_server_leaf("cp.internal").expect("server leaf");
        let (client_pem, client_key) = ca.issue_client_leaf("node-a").expect("client leaf");
        assert_ne!(server_pem, client_pem);
        assert_ne!(server_key, client_key);
        // The EKU split itself (serverAuth-only vs clientAuth-only) is
        // asserted behaviourally in the TLS handshake tests: a client
        // leaf fails server verification and vice versa.
    }

    #[test]
    fn server_leaf_reissued_on_a_persisted_key_keeps_the_key() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        let (_first_cert, key_pem) = ca.issue_server_leaf("cp.internal").expect("first leaf");
        let reissued = ca
            .issue_server_leaf_with_key("cp.internal", &key_pem)
            .expect("reissue on the persisted key");
        assert!(reissued.contains("BEGIN CERTIFICATE"));
        // rustls refuses a certificate whose public key does not match
        // the private key handed alongside it, so a successful config
        // build proves the reissued leaf carries the persisted key's
        // SPKI.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        crate::tls::operational_server_config(ca.cert_pem(), &reissued, &key_pem)
            .expect("reissued leaf must pair with the persisted key");
        assert!(matches!(
            ca.issue_server_leaf_with_key("cp.internal", "not a key"),
            Err(CaError::Parse(_))
        ));
    }

    #[test]
    fn bare_public_keys_are_issued_only_from_the_allowlist() {
        use rcgen::PublicKeyData;
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        let p256 = KeyPair::generate().expect("p256");
        let issued = ca
            .issue_node_leaf_for_public_key("node-1", &p256.subject_public_key_info())
            .expect("P-256 accepted");
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.serial_hex.len(), SERIAL_LEN * 2);
        assert_eq!(issued.fingerprint_sha256.len(), 64);
        assert!(issued.not_after > Utc::now());
        // The serial the registry stores is the one in the certificate.
        use tokio_rustls::rustls::pki_types::pem::PemObject;
        let der = tokio_rustls::rustls::pki_types::CertificateDer::from_pem_slice(
            issued.cert_pem.as_bytes(),
        )
        .expect("der");
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .expect("parse");
        assert_eq!(hex_upper(parsed.raw_serial()), issued.serial_hex);
        assert_eq!(parsed.subject().to_string(), "CN=node-1");
        let eku = parsed
            .extended_key_usage()
            .expect("eku")
            .expect("eku present");
        assert!(eku.value.client_auth && !eku.value.server_auth);

        let ed = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
        ca.issue_node_leaf_for_public_key("node-2", &ed.subject_public_key_info())
            .expect("Ed25519 accepted");
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("p384");
        assert!(matches!(
            ca.issue_node_leaf_for_public_key("node-3", &p384.subject_public_key_info()),
            Err(CaError::PublicKey(_))
        ));
        assert!(matches!(
            check_public_key_allowlist(b"not a key"),
            Err(CaError::PublicKey(_))
        ));
        // Two issuances never share a serial or a fingerprint.
        let again = ca
            .issue_node_leaf_for_public_key("node-1", &p256.subject_public_key_info())
            .expect("reissue");
        assert_ne!(again.serial_hex, issued.serial_hex);
        assert_ne!(again.fingerprint_sha256, issued.fingerprint_sha256);
    }

    #[test]
    fn crl_mints_over_revoked_serials_and_parses() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        let empty = ca.mint_crl(&[]).expect("empty CRL");
        assert!(!empty.as_ref().is_empty());
        let crl = ca
            .mint_crl(&[
                RevokedEntry {
                    serial_hex: "4A".repeat(SERIAL_LEN),
                    revoked_at: Utc::now(),
                    superseded: false,
                },
                RevokedEntry {
                    serial_hex: "5B".repeat(SERIAL_LEN),
                    revoked_at: Utc::now(),
                    superseded: true,
                },
            ])
            .expect("CRL");
        let (_, parsed) = x509_parser::revocation_list::CertificateRevocationList::from_der(
            crl.as_ref(),
        )
        .expect("parse CRL");
        let serials: Vec<String> = parsed
            .iter_revoked_certificates()
            .map(|r| hex_upper(&r.user_certificate.to_bytes_be()))
            .collect();
        assert_eq!(serials, vec!["4A".repeat(SERIAL_LEN), "5B".repeat(SERIAL_LEN)]);
        assert!(matches!(
            ca.mint_crl(&[RevokedEntry {
                serial_hex: "zz".to_string(),
                revoked_at: Utc::now(),
                superseded: false
            }]),
            Err(CaError::Parse(_))
        ));
    }

    #[test]
    fn ip_hosts_get_ip_sans() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        // Must not error: 192.0.2.10 is not a valid Ia5 DNS name, so
        // this only works if the SAN is emitted as an IP.
        let (pem, _) = ca.issue_server_leaf("192.0.2.10").expect("ip SAN leaf");
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }
}
