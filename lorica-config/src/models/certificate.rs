use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// X.509 certificate + private key used to terminate TLS for one or
/// more routes. `key_pem` is encrypted at rest by the store when an
/// [`EncryptionKey`](crate::EncryptionKey) is configured. `is_acme` /
/// `acme_*` fields drive the ACME renewal loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Stable UUID; primary key of the `certificates` table.
    pub id: String,
    /// Primary CN / SAN DNS name the cert binds to.
    pub domain: String,
    /// Additional Subject Alternative Names present in the cert.
    pub san_domains: Vec<String>,
    /// SHA-256 fingerprint of the leaf certificate, hex-encoded.
    pub fingerprint: String,
    /// PEM-encoded leaf + chain.
    pub cert_pem: String,
    /// PEM-encoded private key (AES-GCM encrypted at rest when a key
    /// is configured).
    pub key_pem: String,
    /// Issuer subject DN.
    pub issuer: String,
    /// Not-before validity timestamp from the X.509 body.
    pub not_before: DateTime<Utc>,
    /// Not-after validity timestamp from the X.509 body.
    pub not_after: DateTime<Utc>,
    /// Whether the cert was issued by Lorica's ACME flow.
    pub is_acme: bool,
    /// Whether the ACME renewal loop is allowed to renew this cert
    /// without operator confirmation.
    pub acme_auto_renew: bool,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// ACME provisioning method: "http01", "dns01-ovh", "dns01-cloudflare",
    /// "dns01-route53", "dns01-manual". None for non-ACME certificates.
    #[serde(default)]
    pub acme_method: Option<String>,
    /// Reference to a global DNS provider (dns_providers.id).
    #[serde(default)]
    pub acme_dns_provider_id: Option<String>,
}

/// A global DNS provider with encrypted credentials.
///
/// Instead of storing DNS credentials on each certificate, providers are
/// configured once and referenced by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProvider {
    /// Stable UUID; primary key of the `dns_providers` table.
    pub id: String,
    /// User-friendly name (e.g. "OVH rwx-g.fr").
    pub name: String,
    /// Provider type: "ovh", "cloudflare", "route53".
    pub provider_type: String,
    /// Encrypted JSON with provider credentials.
    pub config: String,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
}
