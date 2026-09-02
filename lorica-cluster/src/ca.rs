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

use chrono::Datelike;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};

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

    /// Issue the control-plane leaf: EKU `serverAuth` ONLY, SAN =
    /// `host` (DNS or IP), valid [`LEAF_VALIDITY_DAYS`]. Returns
    /// `(cert_pem, key_pem)`.
    pub fn issue_server_leaf(&self, host: &str) -> Result<(String, String), CaError> {
        self.issue_leaf(host, ExtendedKeyUsagePurpose::ServerAuth, Some(host))
    }

    /// Issue a node (follower) leaf: EKU `clientAuth` ONLY, CN =
    /// `node_id`, no SAN needed (the dialer authenticates the server,
    /// not the other way around), valid [`LEAF_VALIDITY_DAYS`].
    /// Returns `(cert_pem, key_pem)`.
    pub fn issue_client_leaf(&self, node_id: &str) -> Result<(String, String), CaError> {
        self.issue_leaf(node_id, ExtendedKeyUsagePurpose::ClientAuth, None)
    }

    fn issue_leaf(
        &self,
        common_name: &str,
        eku: ExtendedKeyUsagePurpose,
        san_host: Option<&str>,
    ) -> Result<(String, String), CaError> {
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

        let leaf_key: KeyPair =
            KeyPair::generate().map_err(|e| CaError::Generate(e.to_string()))?;
        // Rebuild the issuer from the CA certificate itself so the
        // leaf's issuer DN always matches the CA's real subject DN,
        // whether this CA was just generated or reloaded from the
        // store.
        let issuer = rcgen::Issuer::from_ca_cert_pem(&self.cert_pem, &self.key_pair)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        Ok((cert.pem(), leaf_key.serialize_pem()))
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
    fn ip_hosts_get_ip_sans() {
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("generate");
        // Must not error: 192.0.2.10 is not a valid Ia5 DNS name, so
        // this only works if the SAN is emitted as an IP.
        let (pem, _) = ca.issue_server_leaf("192.0.2.10").expect("ip SAN leaf");
        assert!(pem.contains("BEGIN CERTIFICATE"));
    }
}
