//! The AD CS authority (Story 13.2, Epic 13 PRD D3, D5, D10, D12, D15).
//!
//! One row in v1.10.0 (D10), referenced from certificates through
//! `Certificate::adcs_authority_id`. The service account password is
//! deliberately NOT a field of [`AdcsAuthority`]: the struct is what an
//! API response or a log line may carry, and the password only ever
//! travels through `ConfigStore::get_adcs_password` and
//! `ConfigStore::set_adcs_password`, so serialising the model can never
//! leak it.
//!
//! The realm and KDC grammar is validated at the API boundary with
//! `lorica_adcs::Realm` and `lorica_adcs::KdcAddress`, the types the
//! `krb5.conf` renderer consumes. This crate does not depend on
//! `lorica-adcs` (it links the system GSS-API library, which every
//! consumer of the configuration store would then inherit), so it
//! stores those values as the strings the API already accepted.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};

/// RFC 1035 section 2.3.4: a full name fits in 253 octets of text.
const DNS_NAME_MAX_LEN: usize = 253;

/// RFC 1035 section 2.3.4: one label is at most 63 octets.
const DNS_LABEL_MAX_LEN: usize = 63;

/// The key the CSR is generated with (PRD D4).
///
/// RSA 2048 is the default because a template duplicated from *Web
/// Server* at schema version 2 uses a legacy CSP that only handles RSA.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdcsKeyType {
    /// RSA, 2048-bit modulus.
    #[default]
    Rsa2048,
    /// RSA, 3072-bit modulus.
    Rsa3072,
    /// ECDSA on NIST P-256; needs a schema version 3 template with a
    /// key storage provider.
    EcdsaP256,
}

impl AdcsKeyType {
    /// Every variant, for callers that enumerate the choices.
    pub const ALL: [AdcsKeyType; 3] = [Self::Rsa2048, Self::Rsa3072, Self::EcdsaP256];

    /// The stored and serialised spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048",
            Self::Rsa3072 => "rsa3072",
            Self::EcdsaP256 => "ecdsa_p256",
        }
    }
}

impl fmt::Display for AdcsKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AdcsKeyType {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == s)
            .ok_or_else(|| ConfigError::Validation(format!("unknown AD CS key type: {s}")))
    }
}

/// The fixed part of the subject every CSR carries (PRD D5). The `CN`
/// is not here: it is the certificate's first SAN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsSubjectDefaults {
    /// `C`, the two-letter country code.
    #[serde(default)]
    pub country: Option<String>,
    /// `ST`, state or province.
    #[serde(default)]
    pub state: Option<String>,
    /// `L`, locality.
    #[serde(default)]
    pub locality: Option<String>,
    /// `O`, organisation.
    #[serde(default)]
    pub organization: Option<String>,
    /// `OU`, organisational unit.
    #[serde(default)]
    pub organizational_unit: Option<String>,
    /// The optional `emailAddress` attribute.
    #[serde(default)]
    pub email: Option<String>,
}

/// One entry of the authority's DNS-suffix allowlist (PRD D5).
///
/// Built only through [`AllowedSuffix::new`], so a value of this type is
/// a lowercase DNS name of at least two LDH labels with no wildcard, and
/// [`AllowedSuffix::permits`] never has to reason about a malformed
/// suffix. Deserialisation goes through the same constructor, so a
/// stored list that no longer validates is refused rather than widened.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AllowedSuffix(String);

impl AllowedSuffix {
    /// Validate and normalise a suffix.
    ///
    /// Lowercased; one trailing root dot is dropped, since
    /// `corp.example.org.` and `corp.example.org` name the same zone.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Validation`] for an empty value, a wildcard, a
    /// leading dot, an empty label, a label outside RFC 1123 (LDH, 1 to
    /// 63 characters, no hyphen at either end), a name over 253
    /// characters, or a single label: a bare TLD as an allowlist entry
    /// would let Lorica request any name under it.
    ///
    /// ```
    /// use lorica_config::models::AllowedSuffix;
    /// let suffix = AllowedSuffix::new("Corp.Example.ORG").expect("valid suffix");
    /// assert_eq!(suffix.as_str(), "corp.example.org");
    /// assert!(AllowedSuffix::new("*.corp.example.org").is_err());
    /// ```
    pub fn new(raw: &str) -> Result<Self> {
        if raw.contains('*') {
            return Err(ConfigError::Validation(format!(
                "allowed suffix {raw:?}: wildcards are refused; an entry already covers \
                 every name under it"
            )));
        }
        if raw.starts_with('.') {
            return Err(ConfigError::Validation(format!(
                "allowed suffix {raw:?}: write the zone without a leading dot"
            )));
        }
        let name = normalize_dns_name(raw).ok_or_else(|| {
            ConfigError::Validation(format!(
                "allowed suffix {raw:?} is not a DNS name (RFC 1123 labels, at most 253 \
                 characters)"
            ))
        })?;
        if !name.contains('.') {
            return Err(ConfigError::Validation(format!(
                "allowed suffix {raw:?}: at least two labels are required"
            )));
        }
        Ok(Self(name))
    }

    /// The normalised suffix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `name` is this suffix or a name under it at any depth.
    ///
    /// Matching is on whole labels and case-insensitive, never on a
    /// string suffix, so `corp.example.org` does not permit
    /// `evilcorp.example.org`. A wildcard name is never permitted
    /// (wildcard SANs are refused in v1.10.0), nor is anything that is
    /// not itself a well-formed DNS name. One trailing root dot is
    /// ignored.
    ///
    /// ```
    /// use lorica_config::models::AllowedSuffix;
    /// let suffix = AllowedSuffix::new("corp.example.org").expect("valid suffix");
    /// assert!(suffix.permits("corp.example.org"));
    /// assert!(suffix.permits("a.b.corp.example.org"));
    /// assert!(!suffix.permits("evilcorp.example.org"));
    /// assert!(!suffix.permits("*.corp.example.org"));
    /// ```
    pub fn permits(&self, name: &str) -> bool {
        if name.contains('*') {
            return false;
        }
        let Some(name) = normalize_dns_name(name) else {
            return false;
        };
        if name == self.0 {
            return true;
        }
        // Every label of a normalised name is non-empty, so a `.`
        // immediately before the suffix is a label boundary and the
        // part before it is at least one whole label.
        name.strip_suffix(self.0.as_str())
            .is_some_and(|head| head.len() > 1 && head.ends_with('.'))
    }
}

impl TryFrom<String> for AllowedSuffix {
    type Error = ConfigError;

    fn try_from(raw: String) -> Result<Self> {
        Self::new(&raw)
    }
}

impl From<AllowedSuffix> for String {
    fn from(suffix: AllowedSuffix) -> Self {
        suffix.0
    }
}

impl fmt::Display for AllowedSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `raw` lowercased with one root dot dropped, when every label is an
/// RFC 1123 LDH label and the whole fits RFC 1035's length; `None`
/// otherwise. Non-ASCII input is refused: an internationalised name is
/// written in its punycode (`xn--`) form, which is LDH.
fn normalize_dns_name(raw: &str) -> Option<String> {
    let lowered = raw.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    if name.is_empty() || name.len() > DNS_NAME_MAX_LEN {
        return None;
    }
    let every_label_is_ldh = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= DNS_LABEL_MAX_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    every_label_is_ldh.then(|| name.to_string())
}

/// The organisation's AD CS authority, reached through its Certificate
/// Enrollment Web Service (PRD D1, D10).
///
/// A control-plane object: it is absent from the canonical blob, from
/// every follower payload and from the configuration export (D13, D14).
/// The service account password lives in its own encrypted column and
/// is not a field here (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsAuthority {
    /// Stable id; primary key of the `adcs_authority` table and the
    /// value certificates carry in `adcs_authority_id`.
    pub id: String,
    /// The CES endpoint URL; `https://` only.
    pub endpoint: String,
    /// The Kerberos realm, uppercase (validated at the API).
    pub realm: String,
    /// Explicit KDCs as `host[:port]`; empty means DNS SRV discovery.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// The service account principal Lorica authenticates as.
    pub principal: String,
    /// PEM bundle trusted, alone, for the CES endpoint's TLS
    /// certificate (D12). `None` uses the default roots.
    #[serde(default)]
    pub endpoint_ca_pem: Option<String>,
    /// The issuing CA certificate, used for adoption and display
    /// (D12); learned from the first issuance or pasted.
    #[serde(default)]
    pub issuing_ca_pem: Option<String>,
    /// The template's common name (`cn`), never its display name.
    pub default_template: String,
    /// The key type a new certificate gets unless the request says
    /// otherwise.
    #[serde(default)]
    pub default_key_type: AdcsKeyType,
    /// The fixed part of every CSR's subject.
    #[serde(default)]
    pub subject: AdcsSubjectDefaults,
    /// Names Lorica may request; at least one (D5).
    pub allowed_suffixes: Vec<AllowedSuffix>,
    /// The `acme_auto_renew` value a newly issued certificate starts
    /// with.
    pub auto_renew_default: bool,
    /// When the authority entered the failed state (D15); `None` when
    /// it is not failed.
    #[serde(default)]
    pub failed_since: Option<DateTime<Utc>>,
    /// The step that failed, as named by the client (Story 13.1 AC #8).
    #[serde(default)]
    pub failed_step: Option<String>,
    /// The KDC error code that put the authority in the failed state.
    #[serde(default)]
    pub failed_kdc_code: Option<i32>,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last configuration change.
    pub updated_at: DateTime<Utc>,
}

impl AdcsAuthority {
    /// Whether the D15 breaker is open: no attempt may be made against
    /// this authority until a password write clears it.
    pub fn is_failed(&self) -> bool {
        self.failed_since.is_some()
    }

    /// Whether `name` falls under at least one allowed suffix.
    pub fn permits(&self, name: &str) -> bool {
        self.allowed_suffixes.iter().any(|s| s.permits(name))
    }

    /// The invariants the store refuses to persist without: an
    /// `https://` endpoint with a host, a principal, a template, and at
    /// least one allowed suffix. The realm and KDC grammar is the API's
    /// (see the module doc).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Validation`] naming the first field that fails.
    pub fn validate(&self) -> Result<()> {
        let has_https_scheme = self
            .endpoint
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
        if !has_https_scheme || self.endpoint.len() == 8 {
            return Err(ConfigError::Validation(
                "AD CS endpoint must be an https:// URL".to_string(),
            ));
        }
        if self.realm.trim().is_empty() {
            return Err(ConfigError::Validation(
                "AD CS realm is required".to_string(),
            ));
        }
        if self.principal.trim().is_empty() {
            return Err(ConfigError::Validation(
                "AD CS principal is required".to_string(),
            ));
        }
        if self.default_template.trim().is_empty() {
            return Err(ConfigError::Validation(
                "AD CS default template is required".to_string(),
            ));
        }
        if self.allowed_suffixes.is_empty() {
            return Err(ConfigError::Validation(
                "AD CS authority needs at least one allowed DNS suffix".to_string(),
            ));
        }
        Ok(())
    }
}

/// Every text this fixture carries contains [`ADCS_FIXTURE_SENTINEL`],
/// so a test proving the authority never left the control plane can
/// look for that one marker in a payload instead of listing fields.
#[cfg(test)]
pub(crate) const ADCS_FIXTURE_SENTINEL: &str = "adcssentinel";

/// A valid authority for tests across the crate.
#[cfg(test)]
pub(crate) fn sample_adcs_authority(id: &str) -> AdcsAuthority {
    let at = DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
        .expect("test setup: valid timestamp")
        .with_timezone(&Utc);
    let s = ADCS_FIXTURE_SENTINEL;
    AdcsAuthority {
        id: id.to_string(),
        endpoint: format!("https://ces-{s}.corp.example.org/CA_CES_Kerberos/service.svc/CES"),
        realm: format!("{}.CORP.EXAMPLE.ORG", s.to_ascii_uppercase()),
        kdcs: vec![format!("kdc-{s}.corp.example.org:88")],
        principal: format!("svc-{s}@CORP.EXAMPLE.ORG"),
        endpoint_ca_pem: Some(format!(
            "-----BEGIN CERTIFICATE-----\nendpoint-ca-{s}\n-----END CERTIFICATE-----"
        )),
        issuing_ca_pem: Some(format!(
            "-----BEGIN CERTIFICATE-----\nissuing-ca-{s}\n-----END CERTIFICATE-----"
        )),
        default_template: format!("Template{s}"),
        default_key_type: AdcsKeyType::Rsa3072,
        subject: AdcsSubjectDefaults {
            country: Some("FR".to_string()),
            state: Some(format!("State {s}")),
            locality: Some(format!("City {s}")),
            organization: Some(format!("Org {s}")),
            organizational_unit: Some(format!("Unit {s}")),
            email: Some(format!("pki-{s}@corp.example.org")),
        },
        allowed_suffixes: vec![
            AllowedSuffix::new(&format!("{s}.corp.example.org")).expect("test setup: valid suffix")
        ],
        auto_renew_default: true,
        failed_since: None,
        failed_step: None,
        failed_kdc_code: None,
        created_at: at,
        updated_at: at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(raw: &str) -> AllowedSuffix {
        AllowedSuffix::new(raw).expect("test setup: valid suffix")
    }

    #[test]
    fn a_suffix_is_normalised_on_construction() {
        let cases: &[(&str, &str)] = &[
            ("corp.example.org", "corp.example.org"),
            ("Corp.Example.ORG", "corp.example.org"),
            ("corp.example.org.", "corp.example.org"),
            ("xn--bcher-kva.example.org", "xn--bcher-kva.example.org"),
            ("a-1.example.org", "a-1.example.org"),
        ];
        for (raw, expected) in cases {
            assert_eq!(suffix(raw).as_str(), *expected, "input {raw:?}");
        }
    }

    #[test]
    fn a_malformed_suffix_is_refused() {
        let too_long_label = format!("{}.example.org", "a".repeat(64));
        let too_long_name = format!("{}.org", vec!["a".repeat(60); 5].join("."));
        let refused: Vec<&str> = vec![
            "",
            ".",
            "*.corp.example.org",
            "*",
            "corp.*.org",
            ".corp.example.org",
            "corp..example.org",
            "corp.example.org..",
            "org",
            "-corp.example.org",
            "corp-.example.org",
            "corp_x.example.org",
            "corp example.org",
            "bücher.example.org",
            "corp.example.org/x",
            &too_long_label,
            &too_long_name,
        ];
        for raw in refused {
            assert!(
                AllowedSuffix::new(raw).is_err(),
                "{raw:?} must not be an allowed suffix"
            );
        }
    }

    #[test]
    fn permits_follows_label_semantics() {
        let corp = suffix("corp.example.org");
        let cases: &[(&str, bool)] = &[
            ("corp.example.org", true),
            ("web.corp.example.org", true),
            ("a.b.c.corp.example.org", true),
            ("WEB.Corp.Example.ORG", true),
            ("web.corp.example.org.", true),
            ("corp.example.org.", true),
            ("xn--bcher-kva.corp.example.org", true),
            // The lookalike: a string suffix, not a label suffix.
            ("evilcorp.example.org", false),
            ("web.evilcorp.example.org", false),
            ("example.org", false),
            ("corp.example.org.evil.test", false),
            ("corp.example.com", false),
            // Wildcards are never permitted, even under the suffix.
            ("*.corp.example.org", false),
            ("a.*.corp.example.org", false),
            // Malformed names never match.
            ("", false),
            (".", false),
            (".corp.example.org", false),
            ("web..corp.example.org", false),
            ("web.corp.example.org..", false),
            ("we b.corp.example.org", false),
            ("bücher.corp.example.org", false),
        ];
        for (name, expected) in cases {
            assert_eq!(corp.permits(name), *expected, "name {name:?}");
        }
    }

    #[test]
    fn a_suffix_round_trips_through_serde_and_refuses_a_bad_stored_value() {
        let json = serde_json::to_string(&vec![suffix("Corp.Example.org")])
            .expect("test setup: serialise");
        assert_eq!(json, r#"["corp.example.org"]"#);
        let back: Vec<AllowedSuffix> = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back, vec![suffix("corp.example.org")]);
        assert!(serde_json::from_str::<Vec<AllowedSuffix>>(r#"["*.corp.example.org"]"#).is_err());
    }

    #[test]
    fn the_key_type_spellings_round_trip() {
        for kind in AdcsKeyType::ALL {
            assert_eq!(kind.as_str().parse::<AdcsKeyType>().ok(), Some(kind));
            let json = serde_json::to_string(&kind).expect("test setup: serialise");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
        }
        assert_eq!(AdcsKeyType::default(), AdcsKeyType::Rsa2048);
        assert!("rsa4096".parse::<AdcsKeyType>().is_err());
    }

    fn authority() -> AdcsAuthority {
        let mut authority = sample_adcs_authority("adcs-1");
        authority.allowed_suffixes = vec![suffix("corp.example.org")];
        authority
    }

    #[test]
    fn validate_refuses_each_missing_invariant() {
        assert!(authority().validate().is_ok());

        let mut plain_http = authority();
        plain_http.endpoint = "http://ces.corp.example.org/".to_string();
        let mut no_host = authority();
        no_host.endpoint = "https://".to_string();
        let mut no_realm = authority();
        no_realm.realm = String::new();
        let mut no_principal = authority();
        no_principal.principal = " ".to_string();
        let mut no_template = authority();
        no_template.default_template = String::new();
        let mut no_suffix = authority();
        no_suffix.allowed_suffixes.clear();
        for broken in [
            plain_http,
            no_host,
            no_realm,
            no_principal,
            no_template,
            no_suffix,
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }

        let mut upper_scheme = authority();
        upper_scheme.endpoint = "HTTPS://ces.corp.example.org/".to_string();
        assert!(upper_scheme.validate().is_ok());
    }

    #[test]
    fn the_authority_permits_a_name_under_any_of_its_suffixes() {
        let mut two = authority();
        two.allowed_suffixes.push(suffix("lab.example.net"));
        assert!(two.permits("web.corp.example.org"));
        assert!(two.permits("x.lab.example.net"));
        assert!(!two.permits("example.net"));
    }

    #[test]
    fn the_serialised_authority_carries_no_password_field() {
        let json = serde_json::to_value(authority()).expect("test setup: serialise");
        let object = json.as_object().expect("an object");
        assert!(
            object.keys().all(|key| !key.contains("password")),
            "{object:?}"
        );
    }
}
