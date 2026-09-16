//! OIDC issuer entries (Story 10.5): the trust configuration behind a
//! GitLab ID token on the automation listener.
//!
//! One entry is one authorisation policy: which issuer signs, which
//! audience the job must name, which claims must match exactly, and
//! the same grant a static token carries (scopes, hostnames, backend
//! CIDRs, TTL ceiling). Several entries may share an issuer and an
//! audience with different bound claims; the verifier tries every
//! entry whose audience matches and accepts the first whose bound
//! claims all hold.
//!
//! # Why globs are allowed on one claim and refused on the others
//!
//! `project_path` takes a glob because a group of projects is a real
//! authorisation unit (`acme/*` is "everything the acme group owns").
//! `ref_protected` and `environment_protected` are booleans and
//! `deployment_tier` is an enum; their whole value is being exact, and
//! a glob there would silently widen a decision an operator believed
//! they had narrowed. [`OidcIssuer::validate`] refuses a `*` anywhere
//! but in `project_path`, so the widening cannot be expressed at all.
//!
//! # Why the URLs must be `https`
//!
//! The issuer URL is operator-supplied and reached from the control
//! plane. Over plain HTTP the JWKS it serves could be replaced on the
//! path, which is a signing key for every automation this entry
//! grants; `https` with the node's trust roots is the floor.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::automation_token::{validate_hostname_pattern, AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP};
use super::hostname_pattern::matches_one_label;
use super::AutomationScope;
use crate::connection_filter::validate_cidr;

/// The closed set of claims an entry may bind. Anything else is refused
/// at validation: a claim GitLab does not put in the token can never
/// match, and an entry that can never match is a misconfiguration, not
/// a policy.
pub const OIDC_BOUND_CLAIM_NAMES: &[&str] = &[
    "project_path",
    "namespace_path",
    "ref_protected",
    "environment_protected",
    "deployment_tier",
];

/// The ONE bound claim whose value may carry a `*` glob.
pub const OIDC_BOUND_CLAIM_WITH_GLOB: &str = "project_path";

/// The two bound claims whose value must be exactly `true` or `false`.
pub const OIDC_BOOLEAN_BOUND_CLAIMS: &[&str] = &["ref_protected", "environment_protected"];

/// The path GitLab serves its signing keys on, appended to the issuer
/// URL when the entry names no `jwks_url`.
pub const OIDC_ISSUER_DEFAULT_JWKS_PATH: &str = "/oauth/discovery/keys";

/// Longest issuer or JWKS URL accepted.
pub const OIDC_ISSUER_URL_MAX_LEN: usize = 2048;

/// Longest audience accepted.
pub const OIDC_AUDIENCE_MAX_LEN: usize = 255;

/// Longest bound-claim value accepted.
pub const OIDC_BOUND_CLAIM_VALUE_MAX_LEN: usize = 255;

/// One OIDC issuer entry: a trust anchor plus the grant a token it
/// signs receives.
///
/// The row is node-local and never replicates, for the reasons the
/// store module gives. There is no secret in it, but there is
/// authority: whoever can add a row can make an identity provider of
/// their choosing mint credentials for this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcIssuer {
    /// Stable UUID; primary key of the `oidc_issuers` table and the id
    /// a `DELETE` names.
    pub id: String,
    /// The `iss` claim the token must carry, which is the GitLab
    /// instance URL. Must be `https`.
    pub issuer: String,
    /// The `aud` claim the token must carry: the value the job puts in
    /// `id_tokens.<NAME>.aud`. It identifies THIS Lorica instance, so a
    /// token minted for another consumer is refused here.
    pub audience: String,
    /// Where the issuer's signing keys are fetched from. Defaults to
    /// `<issuer>/oauth/discovery/keys`. Must be `https`.
    pub jwks_url: String,
    /// Claims that must match exactly, keyed by name from
    /// [`OIDC_BOUND_CLAIM_NAMES`]. A `*` glob is accepted in
    /// [`OIDC_BOUND_CLAIM_WITH_GLOB`] only. A `BTreeMap` so the row
    /// serialises the same way every time.
    pub bound_claims: BTreeMap<String, String>,
    /// Hostname patterns a token from this entry may claim. At least
    /// one, the same rule as a static token.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs a token from this entry may point a hostname at. Empty
    /// means the node's default backend policy applies.
    #[serde(default)]
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment a token from this entry
    /// creates may request, in seconds.
    pub max_ttl_seconds: u32,
    /// What a token from this entry may do. At least one.
    pub scopes: Vec<AutomationScope>,
    /// Username of the operator who registered the entry.
    pub created_by: String,
    /// Registration timestamp.
    pub created_at: DateTime<Utc>,
}

impl OidcIssuer {
    /// The JWKS URL an entry gets when the operator names none:
    /// `<issuer>/oauth/discovery/keys`, with one trailing slash on the
    /// issuer folded away so the path is not doubled.
    ///
    /// ```
    /// use lorica_config::models::OidcIssuer;
    /// assert_eq!(
    ///     OidcIssuer::default_jwks_url("https://gitlab.example.com/"),
    ///     "https://gitlab.example.com/oauth/discovery/keys"
    /// );
    /// ```
    pub fn default_jwks_url(issuer: &str) -> String {
        format!(
            "{}{OIDC_ISSUER_DEFAULT_JWKS_PATH}",
            issuer.trim_end_matches('/')
        )
    }

    /// Whether this entry grants `scope`.
    pub fn has_scope(&self, scope: AutomationScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether any of the entry's patterns covers `hostname`, under the
    /// same one-label wildcard rule a static token uses.
    pub fn allows_hostname(&self, hostname: &str) -> bool {
        self.allowed_hostnames
            .iter()
            .any(|pattern| matches_one_label(pattern, hostname))
    }

    /// Whether this entry binds `environment_protected = true`, which
    /// is what ties an environment's name to the job's `environment`
    /// claim (AC #3).
    pub fn binds_protected_environment(&self) -> bool {
        self.bound_claims
            .get("environment_protected")
            .is_some_and(|value| value == "true")
    }

    /// Check every bound claim against the token's claims.
    ///
    /// A claim the token does not carry never matches. The first
    /// mismatch, in claim-name order, is returned by name so the audit
    /// row can say which one.
    ///
    /// # Errors
    ///
    /// The name of the first bound claim that does not hold.
    pub fn bound_claims_match(&self, claims: &BTreeMap<String, String>) -> Result<(), String> {
        for (name, expected) in &self.bound_claims {
            let holds = claims
                .get(name)
                .is_some_and(|actual| bound_claim_matches(name, expected, actual));
            if !holds {
                return Err(name.clone());
            }
        }
        Ok(())
    }

    /// Validate every operator-supplied field.
    ///
    /// Returns a human-readable message describing the first violated
    /// rule, suitable for a `422` body, the same shape as
    /// [`super::AutomationToken::validate`].
    ///
    /// # Errors
    ///
    /// Returns `Err` when a URL is not `https` or is malformed, when
    /// the audience is blank, when a bound claim is outside
    /// [`OIDC_BOUND_CLAIM_NAMES`], carries a glob outside
    /// [`OIDC_BOUND_CLAIM_WITH_GLOB`], or is not `true`/`false` for a
    /// boolean claim, when the entry grants no scope or matches no
    /// hostname, when a hostname pattern or a CIDR is malformed, or
    /// when `max_ttl_seconds` is zero or over the static-token cap.
    ///
    /// ```
    /// use lorica_config::models::OidcIssuer;
    /// # fn demo(mut issuer: OidcIssuer) {
    /// issuer.bound_claims.insert("ref_protected".to_string(), "*".to_string());
    /// // A glob on a boolean claim would widen a decision silently.
    /// assert!(issuer.validate().is_err());
    /// # }
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("oidc issuer entry must have an id".to_string());
        }
        validate_https_url("issuer", &self.issuer)?;
        if self.issuer.contains('?') || self.issuer.contains('#') {
            return Err("issuer must not carry a query string or a fragment".to_string());
        }
        validate_https_url("jwks_url", &self.jwks_url)?;
        let audience = self.audience.trim();
        if audience.is_empty() || audience != self.audience {
            return Err("audience must not be blank or carry surrounding whitespace".to_string());
        }
        if audience.len() > OIDC_AUDIENCE_MAX_LEN {
            return Err(format!("audience exceeds {OIDC_AUDIENCE_MAX_LEN} bytes"));
        }
        for (name, value) in &self.bound_claims {
            validate_bound_claim(name, value)?;
        }
        if self.scopes.is_empty() {
            return Err("oidc issuer entry must grant at least one scope".to_string());
        }
        if self.allowed_hostnames.is_empty() {
            return Err(
                "oidc issuer entry must allow at least one hostname; an entry that matches no \
                 hostname can do nothing, and does so silently"
                    .to_string(),
            );
        }
        for pattern in &self.allowed_hostnames {
            validate_hostname_pattern(pattern)?;
        }
        for cidr in &self.allowed_backend_cidrs {
            validate_cidr(cidr, "allowed_backend_cidrs")?;
        }
        if self.max_ttl_seconds == 0 {
            return Err("max_ttl_seconds must be greater than zero".to_string());
        }
        if self.max_ttl_seconds > AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP {
            return Err(format!(
                "max_ttl_seconds may not exceed {AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP}"
            ));
        }
        if self.created_by.trim().is_empty() {
            return Err("oidc issuer entry must name who registered it".to_string());
        }
        Ok(())
    }
}

/// Whether a token's `actual` value satisfies the bound value
/// `expected` for claim `name`: a glob match on
/// [`OIDC_BOUND_CLAIM_WITH_GLOB`], an exact byte comparison everywhere
/// else.
///
/// ```
/// use lorica_config::models::bound_claim_matches;
/// assert!(bound_claim_matches("project_path", "acme/*", "acme/web"));
/// assert!(!bound_claim_matches("namespace_path", "acme/*", "acme/web"));
/// assert!(bound_claim_matches("ref_protected", "true", "true"));
/// ```
pub fn bound_claim_matches(name: &str, expected: &str, actual: &str) -> bool {
    if name == OIDC_BOUND_CLAIM_WITH_GLOB {
        glob_matches(expected, actual)
    } else {
        expected == actual
    }
}

/// One bound claim: a known name, a non-empty bounded value, a glob
/// only where one is allowed, and an exact boolean where one is
/// required.
fn validate_bound_claim(name: &str, value: &str) -> Result<(), String> {
    if !OIDC_BOUND_CLAIM_NAMES.contains(&name) {
        return Err(format!(
            "bound claim `{name}` is not one of {}",
            OIDC_BOUND_CLAIM_NAMES.join(", ")
        ));
    }
    if value.is_empty() {
        return Err(format!("bound claim `{name}` must not be empty"));
    }
    if value.len() > OIDC_BOUND_CLAIM_VALUE_MAX_LEN {
        return Err(format!(
            "bound claim `{name}` exceeds {OIDC_BOUND_CLAIM_VALUE_MAX_LEN} bytes"
        ));
    }
    if value.contains('*') && name != OIDC_BOUND_CLAIM_WITH_GLOB {
        return Err(format!(
            "bound claim `{name}` must match exactly; a glob is only accepted on \
             `{OIDC_BOUND_CLAIM_WITH_GLOB}`"
        ));
    }
    if OIDC_BOOLEAN_BOUND_CLAIMS.contains(&name) && value != "true" && value != "false" {
        return Err(format!(
            "bound claim `{name}` must be exactly `true` or `false`"
        ));
    }
    Ok(())
}

/// An absolute `https` URL with a host, no userinfo and no whitespace.
///
/// Deliberately not a full URL parser: the operator is a SuperAdmin
/// and the fetch client parses the URL again; what this refuses is the
/// one thing the fetch client would happily accept and must not, a
/// plain-HTTP issuer.
fn validate_https_url(field: &str, raw: &str) -> Result<(), String> {
    if raw.len() > OIDC_ISSUER_URL_MAX_LEN {
        return Err(format!("{field} exceeds {OIDC_ISSUER_URL_MAX_LEN} bytes"));
    }
    let Some(rest) = raw.strip_prefix("https://") else {
        return Err(format!("{field} must be an https:// URL"));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(format!("{field} must name a host"));
    }
    if authority.contains('@') {
        return Err(format!("{field} must not carry credentials in the URL"));
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{field} must not contain whitespace"));
    }
    Ok(())
}

/// Wildcard match where `*` stands for any run of characters, `/`
/// included, so `acme/*` covers `acme/web` and `acme/team/web`.
///
/// Iterative two-pointer matching with backtracking to the last `*`,
/// so a pattern with several stars still runs in linear time on the
/// value length for each star.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while v < value.len() {
        if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, v));
            p += 1;
        } else if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if let Some((star_p, star_v)) = star {
            p = star_p + 1;
            v = star_v + 1;
            star = Some((star_p, star_v + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn claims(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// An entry that validates, so each test below changes exactly one
    /// thing and the failure it asserts is the thing it changed.
    fn valid_issuer() -> OidcIssuer {
        OidcIssuer {
            id: "issuer-1".to_string(),
            issuer: "https://gitlab.example.com".to_string(),
            audience: "lorica-prod".to_string(),
            jwks_url: OidcIssuer::default_jwks_url("https://gitlab.example.com"),
            bound_claims: claims(&[("project_path", "acme/*"), ("ref_protected", "true")]),
            allowed_hostnames: vec!["*.preview.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
            scopes: vec![
                AutomationScope::EnvironmentsRead,
                AutomationScope::EnvironmentsWrite,
            ],
            created_by: "admin".to_string(),
            created_at: fixed_now(),
        }
    }

    // ---- Validation ----

    #[test]
    fn a_well_formed_entry_validates() {
        assert_eq!(valid_issuer().validate(), Ok(()));
    }

    #[test]
    fn the_issuer_and_the_jwks_url_must_be_https() {
        for bad in [
            "http://gitlab.example.com",
            "gitlab.example.com",
            "https://",
            "https://user:pw@gitlab.example.com",
            "https://gitlab.example.com/ path",
            "",
        ] {
            let mut issuer = valid_issuer();
            issuer.issuer = bad.to_string();
            assert!(issuer.validate().is_err(), "issuer {bad:?} must be refused");
            let mut issuer = valid_issuer();
            issuer.jwks_url = bad.to_string();
            assert!(
                issuer.validate().is_err(),
                "jwks_url {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn the_issuer_carries_no_query_or_fragment() {
        let mut issuer = valid_issuer();
        issuer.issuer = "https://gitlab.example.com/?x=1".to_string();
        assert!(issuer.validate().is_err());
        let mut issuer = valid_issuer();
        issuer.issuer = "https://gitlab.example.com/#frag".to_string();
        assert!(issuer.validate().is_err());
    }

    #[test]
    fn the_default_jwks_url_is_the_gitlab_discovery_path() {
        assert_eq!(
            OidcIssuer::default_jwks_url("https://gitlab.example.com"),
            "https://gitlab.example.com/oauth/discovery/keys"
        );
        assert_eq!(
            OidcIssuer::default_jwks_url("https://gitlab.example.com///"),
            "https://gitlab.example.com/oauth/discovery/keys"
        );
    }

    #[test]
    fn a_blank_or_padded_audience_is_refused() {
        for bad in ["", "   ", " lorica", "lorica "] {
            let mut issuer = valid_issuer();
            issuer.audience = bad.to_string();
            let err = issuer.validate().expect_err("refused");
            assert!(err.contains("audience"), "{err}");
        }
    }

    #[test]
    fn an_unknown_bound_claim_is_refused() {
        let mut issuer = valid_issuer();
        issuer
            .bound_claims
            .insert("sub".to_string(), "project_path:acme/web".to_string());
        let err = issuer.validate().expect_err("refused");
        assert!(err.contains("`sub`"), "{err}");
    }

    #[test]
    fn a_glob_is_accepted_on_project_path_and_nowhere_else() {
        let mut issuer = valid_issuer();
        issuer.bound_claims = claims(&[("project_path", "acme/*")]);
        assert_eq!(issuer.validate(), Ok(()));

        for name in [
            "namespace_path",
            "ref_protected",
            "environment_protected",
            "deployment_tier",
        ] {
            let mut issuer = valid_issuer();
            issuer.bound_claims = claims(&[(name, "*")]);
            let err = issuer
                .validate()
                .expect_err("a glob outside project_path is refused");
            assert!(err.contains(name), "{err}");
        }
    }

    #[test]
    fn the_boolean_claims_take_exactly_true_or_false() {
        for name in ["ref_protected", "environment_protected"] {
            for value in ["true", "false"] {
                let mut issuer = valid_issuer();
                issuer.bound_claims = claims(&[(name, value)]);
                assert_eq!(issuer.validate(), Ok(()), "{name}={value}");
            }
            for value in ["True", "yes", "1", ""] {
                let mut issuer = valid_issuer();
                issuer.bound_claims = claims(&[(name, value)]);
                assert!(
                    issuer.validate().is_err(),
                    "{name}={value:?} must be refused"
                );
            }
        }
    }

    #[test]
    fn the_grant_rules_mirror_a_static_token() {
        let mut issuer = valid_issuer();
        issuer.scopes.clear();
        assert!(issuer.validate().is_err());

        let mut issuer = valid_issuer();
        issuer.allowed_hostnames.clear();
        assert!(issuer.validate().is_err());

        let mut issuer = valid_issuer();
        issuer.allowed_hostnames = vec!["*".to_string()];
        assert!(issuer.validate().is_err());

        let mut issuer = valid_issuer();
        issuer.allowed_backend_cidrs = vec!["10.0.0.0/33".to_string()];
        assert!(issuer.validate().is_err());

        let mut issuer = valid_issuer();
        issuer.max_ttl_seconds = 0;
        assert!(issuer.validate().is_err());

        let mut issuer = valid_issuer();
        issuer.max_ttl_seconds = AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP + 1;
        assert!(issuer.validate().is_err());
    }

    // ---- Bound-claim matching ----

    #[test]
    fn every_bound_claim_must_hold_and_the_first_miss_is_named() {
        let issuer = valid_issuer();
        assert_eq!(
            issuer.bound_claims_match(&claims(&[
                ("project_path", "acme/web"),
                ("ref_protected", "true"),
                ("job_id", "42"),
            ])),
            Ok(())
        );
        assert_eq!(
            issuer.bound_claims_match(&claims(&[
                ("project_path", "globex/web"),
                ("ref_protected", "true"),
            ])),
            Err("project_path".to_string())
        );
        assert_eq!(
            issuer.bound_claims_match(&claims(&[
                ("project_path", "acme/web"),
                ("ref_protected", "false"),
            ])),
            Err("ref_protected".to_string())
        );
        // A claim the token does not carry never matches.
        assert_eq!(
            issuer.bound_claims_match(&claims(&[("project_path", "acme/web")])),
            Err("ref_protected".to_string())
        );
    }

    #[test]
    fn the_project_path_glob_spans_slashes_and_the_others_compare_bytes() {
        assert!(bound_claim_matches("project_path", "acme/*", "acme/web"));
        assert!(bound_claim_matches(
            "project_path",
            "acme/*",
            "acme/team/web"
        ));
        assert!(bound_claim_matches("project_path", "*/web", "acme/web"));
        assert!(bound_claim_matches(
            "project_path",
            "acme/*/web",
            "acme/team/web"
        ));
        assert!(!bound_claim_matches(
            "project_path",
            "acme/*",
            "acmecorp/web"
        ));
        assert!(!bound_claim_matches("project_path", "acme/*", "acme"));
        assert!(bound_claim_matches("project_path", "acme/web", "acme/web"));
        assert!(!bound_claim_matches("project_path", "acme/web", "acme/Web"));
        // Elsewhere a star is a literal star, which no real claim holds.
        assert!(!bound_claim_matches("namespace_path", "acme/*", "acme/web"));
        assert!(bound_claim_matches(
            "deployment_tier",
            "production",
            "production"
        ));
        assert!(!bound_claim_matches(
            "deployment_tier",
            "production",
            "staging"
        ));
    }

    #[test]
    fn the_protected_environment_binding_is_the_exact_true_value() {
        let mut issuer = valid_issuer();
        assert!(!issuer.binds_protected_environment());
        issuer
            .bound_claims
            .insert("environment_protected".to_string(), "true".to_string());
        assert!(issuer.binds_protected_environment());
        issuer
            .bound_claims
            .insert("environment_protected".to_string(), "false".to_string());
        assert!(!issuer.binds_protected_environment());
    }
}
