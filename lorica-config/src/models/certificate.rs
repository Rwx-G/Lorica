use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::hostname_pattern::matches_one_label;

/// X.509 certificate + private key used to terminate TLS for one or
/// more routes. `key_pem` is encrypted at rest by the store when an
/// [`EncryptionKey`](crate::EncryptionKey) is configured. `is_acme` /
/// `acme_*` fields drive the ACME renewal loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// How closely a certificate name matched a hostname. Ordered so that
/// `max_by_key` prefers an exact name over a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CoverageKind {
    Wildcard,
    Exact,
}

/// The best way one certificate covers `hostname`, or `None` when
/// neither its `domain` nor any `san_domains` entry does.
fn coverage(cert: &Certificate, hostname: &str) -> Option<CoverageKind> {
    std::iter::once(cert.domain.as_str())
        .chain(cert.san_domains.iter().map(String::as_str))
        .filter(|name| matches_one_label(name, hostname))
        .map(|name| {
            if name.starts_with("*.") {
                CoverageKind::Wildcard
            } else {
                CoverageKind::Exact
            }
        })
        .max()
}

/// Pick the certificate that covers `hostname` (Story 10.4 AC #4).
///
/// A certificate covers the hostname when its `domain` or one of its
/// `san_domains` matches under [`matches_one_label`]: an exact name,
/// or a wildcard standing for exactly one label, so `*.example.com`
/// covers `a.example.com` and not `a.b.example.com`. Among the
/// candidates an exact name beats a wildcard, then the latest
/// `not_after` wins, then the lowest `id` so two nodes holding the
/// same rows pick the same certificate.
///
/// An expired certificate still resolves. Expiry is the renewal path's
/// business: the certificate row is the binding an environment asks
/// for, and the ACME loop replaces its body in place. Refusing here
/// would strand every environment the moment a certificate lapsed,
/// which is exactly when a renewal is already under way, and a valid
/// certificate for the same name wins anyway through `not_after`.
///
/// ```
/// use lorica_config::models::{resolve_certificate_for_hostname, Certificate};
/// # fn demo(certs: &[Certificate]) {
/// let picked = resolve_certificate_for_hostname(certs, "pr-42.review.example.com");
/// assert!(picked.map_or(true, |c| !c.id.is_empty()));
/// # }
/// ```
pub fn resolve_certificate_for_hostname<'a>(
    certs: &'a [Certificate],
    hostname: &str,
) -> Option<&'a Certificate> {
    certs
        .iter()
        .filter_map(|cert| coverage(cert, hostname).map(|kind| (kind, cert)))
        .max_by(|(kind_a, a), (kind_b, b)| {
            kind_a
                .cmp(kind_b)
                .then(a.not_after.cmp(&b.not_after))
                // Reversed: among equals the LOWEST id wins, and
                // `max_by` keeps the greatest.
                .then_with(|| b.id.cmp(&a.id))
        })
        .map(|(_, cert)| cert)
}

/// The single-label wildcard pattern an operator could provision to
/// cover `hostname`, for the `no_certificate_covers_hostname` message.
///
/// `pr-42.review.example.com` yields `*.review.example.com`. A name
/// with fewer than three labels yields nothing: `*.com` is not a
/// certificate a public CA issues, so suggesting it would send the
/// operator down a path that ends in a refusal.
///
/// ```
/// use lorica_config::models::wildcard_patterns_an_operator_could_provision;
/// assert_eq!(
///     wildcard_patterns_an_operator_could_provision("pr-42.review.example.com"),
///     vec!["*.review.example.com".to_string()]
/// );
/// assert!(wildcard_patterns_an_operator_could_provision("example.com").is_empty());
/// ```
pub fn wildcard_patterns_an_operator_could_provision(hostname: &str) -> Vec<String> {
    let name = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let Some((_, parent)) = name.split_once('.') else {
        return Vec::new();
    };
    if parent.split('.').filter(|label| !label.is_empty()).count() < 2 {
        return Vec::new();
    }
    vec![format!("*.{parent}")]
}

/// A global DNS provider with encrypted credentials.
///
/// Instead of storing DNS credentials on each certificate, providers are
/// configured once and referenced by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn cert(id: &str, domain: &str, sans: &[&str], not_after: &str) -> Certificate {
        Certificate {
            id: id.to_string(),
            domain: domain.to_string(),
            san_domains: sans.iter().map(|s| (*s).to_string()).collect(),
            fingerprint: format!("fp-{id}"),
            cert_pem: String::new(),
            key_pem: String::new(),
            issuer: "test".to_string(),
            not_before: at("2026-01-01T00:00:00Z"),
            not_after: at(not_after),
            is_acme: false,
            acme_auto_renew: false,
            created_at: at("2026-01-01T00:00:00Z"),
            acme_method: None,
            acme_dns_provider_id: None,
        }
    }

    fn picked_id(certs: &[Certificate], hostname: &str) -> Option<String> {
        resolve_certificate_for_hostname(certs, hostname).map(|c| c.id.clone())
    }

    #[test]
    fn an_exact_name_beats_a_wildcard_whatever_the_expiry() {
        let certs = vec![
            cert("wild", "*.review.example.com", &[], "2027-12-31T00:00:00Z"),
            cert(
                "exact",
                "pr-42.review.example.com",
                &[],
                "2026-06-01T00:00:00Z",
            ),
        ];
        assert_eq!(
            picked_id(&certs, "pr-42.review.example.com").as_deref(),
            Some("exact")
        );
    }

    #[test]
    fn the_latest_not_after_wins_among_equals() {
        let certs = vec![
            cert("older", "*.review.example.com", &[], "2026-06-01T00:00:00Z"),
            cert("newer", "*.review.example.com", &[], "2026-09-01T00:00:00Z"),
        ];
        assert_eq!(
            picked_id(&certs, "pr-42.review.example.com").as_deref(),
            Some("newer")
        );
    }

    #[test]
    fn a_san_entry_covers_as_well_as_the_primary_domain() {
        let certs = vec![cert(
            "san",
            "example.com",
            &["*.review.example.com"],
            "2026-06-01T00:00:00Z",
        )];
        assert_eq!(
            picked_id(&certs, "pr-42.review.example.com").as_deref(),
            Some("san")
        );
    }

    #[test]
    fn a_wildcard_does_not_cover_a_deeper_subdomain() {
        let certs = vec![cert("wild", "*.example.com", &[], "2027-01-01T00:00:00Z")];
        assert_eq!(picked_id(&certs, "a.b.example.com"), None);
        assert_eq!(picked_id(&certs, "a.example.com").as_deref(), Some("wild"));
    }

    #[test]
    fn an_expired_certificate_still_resolves() {
        // Expiry is the renewal path's business: the binding is the
        // row, and the ACME loop replaces its body in place. A valid
        // sibling would win through `not_after`; alone, the expired
        // one is still the certificate this hostname is bound to.
        let certs = vec![cert(
            "expired",
            "*.review.example.com",
            &[],
            "2020-01-01T00:00:00Z",
        )];
        assert_eq!(
            picked_id(&certs, "pr-42.review.example.com").as_deref(),
            Some("expired")
        );
    }

    #[test]
    fn a_tie_breaks_on_the_lowest_id_so_every_node_agrees() {
        let certs = vec![
            cert("b", "*.review.example.com", &[], "2026-06-01T00:00:00Z"),
            cert("a", "*.review.example.com", &[], "2026-06-01T00:00:00Z"),
        ];
        assert_eq!(
            picked_id(&certs, "pr-42.review.example.com").as_deref(),
            Some("a")
        );
    }

    #[test]
    fn no_covering_certificate_is_none() {
        let certs = vec![cert(
            "other",
            "*.prod.example.com",
            &[],
            "2027-01-01T00:00:00Z",
        )];
        assert_eq!(picked_id(&certs, "pr-42.review.example.com"), None);
        assert_eq!(picked_id(&[], "pr-42.review.example.com"), None);
    }

    #[test]
    fn the_suggested_wildcard_is_the_single_label_parent() {
        assert_eq!(
            wildcard_patterns_an_operator_could_provision("pr-42.review.example.com"),
            vec!["*.review.example.com".to_string()]
        );
        assert_eq!(
            wildcard_patterns_an_operator_could_provision("PR-42.Review.Example.COM."),
            vec!["*.review.example.com".to_string()]
        );
        // `*.com` is not a certificate anyone issues.
        assert!(wildcard_patterns_an_operator_could_provision("example.com").is_empty());
        assert!(wildcard_patterns_an_operator_could_provision("localhost").is_empty());
    }
}
