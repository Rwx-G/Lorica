use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// X.509 certificate + private key used to terminate TLS for one or
/// more routes. `key_pem` is encrypted at rest by the store when an
/// [`EncryptionKey`](crate::EncryptionKey) is configured. `is_acme` /
/// `acme_*` fields drive the ACME renewal loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_acme: bool,
    pub acme_auto_renew: bool,
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
    pub id: String,
    /// User-friendly name (e.g. "OVH rwx-g.fr").
    pub name: String,
    /// Provider type: "ovh", "cloudflare", "route53".
    pub provider_type: String,
    /// Encrypted JSON with provider credentials.
    pub config: String,
    pub created_at: DateTime<Utc>,
}
