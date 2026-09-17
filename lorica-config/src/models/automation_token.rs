//! Scoped automation tokens (Story 10.3): the credential an external
//! automation presents, the narrow surface it is allowed to touch, and
//! the keyed verification of its secret half.
//!
//! # Why this is a sibling of the cluster join token, not a reuse
//!
//! `lorica_cluster::token` mints `<public_id>.<payload>` where the
//! payload carries a 32-byte pin of the control plane's leaf key, so a
//! joining node can authenticate the control plane before it has any
//! CA. An automation token is presented over an already-authenticated
//! TLS connection to a listener whose certificate the automation
//! already trusts, so there is nothing to pin. Bending one type to
//! serve both would mean a field that is meaningless in half its uses,
//! and every reader would have to work out which half they are in.
//!
//! # Shape
//!
//! `<public_id>.<secret>` where `public_id` is
//! [`AUTOMATION_TOKEN_PUBLIC_ID_LEN`] random bytes as lowercase hex
//! (the indexed lookup key, so a presentation is ONE lookup and ONE
//! verification) and `secret` is
//! [`AUTOMATION_TOKEN_SECRET_LEN`] random bytes as URL-safe base64
//! without padding.
//!
//! # Verification
//!
//! The database stores HMAC-SHA256(server_key, secret) as hex. The
//! secret is 256 bits of machine entropy, not a human password, so a
//! memory-hard KDF buys nothing and would turn an unauthenticated
//! endpoint into a memory-exhaustion primitive.
//! [`verify_automation_secret`] is constant-time
//! (`ring::hmac::verify`), and a caller whose `public_id` is unknown
//! runs it against [`dummy_automation_secret_hmac_hex`] so the unknown
//! and known paths cost the same.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::hostname_pattern::matches_one_label;
use crate::connection_filter::validate_cidr;

/// Bytes in the public (lookup) half of an automation token.
pub const AUTOMATION_TOKEN_PUBLIC_ID_LEN: usize = 12;

/// Bytes in the secret half of an automation token.
pub const AUTOMATION_TOKEN_SECRET_LEN: usize = 32;

/// Bytes in the server-side key that hashes an automation token's
/// secret. A dedicated key, never the cluster join-token key: rotating
/// or burning one credential family must not touch the other.
pub const AUTOMATION_TOKEN_HMAC_KEY_LEN: usize = 32;

/// Default [`AutomationToken::max_ttl_seconds`]: seven days.
pub const AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS: u32 = 7 * 24 * 60 * 60;

/// Hard cap on [`AutomationToken::max_ttl_seconds`]: thirty days. The
/// field is the ceiling on the lifetime any environment this token
/// creates may request, so it is what bounds how long an automation
/// failure can leave resources standing after everyone stopped looking
/// at them.
pub const AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP: u32 = 30 * 24 * 60 * 60;

/// Default number of days between an automation token's creation and
/// its mandatory [`AutomationToken::expires_at`].
pub const AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS: i64 = 365;

/// Longest hostname pattern accepted, matching the DNS name limit.
const HOSTNAME_PATTERN_MAX_LEN: usize = 253;

/// Longest single label inside a hostname pattern (RFC 1035).
const HOSTNAME_LABEL_MAX_LEN: usize = 63;

fn default_max_ttl_seconds() -> u32 {
    AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS
}

/// What an automation token is allowed to do.
///
/// The enum is closed and these four variants are the whole surface for
/// 1.8.0. The absence of `routes:write`, `certificates:write` and
/// `settings:*` is deliberate: the automation surface is the
/// environment resource, not the management API behind a different
/// door. An automation that needs to reshape routing or issue a
/// certificate is asking for an operator's credential, and it should
/// have to say so rather than find the capability already attached to
/// the token it uses for ephemeral environments.
///
/// An unknown scope string fails to deserialise rather than being
/// dropped, so a token minted against a newer Lorica is refused here
/// instead of silently losing the grant an operator wrote down.
///
/// ```
/// use lorica_config::models::AutomationScope;
/// let scope: AutomationScope =
///     serde_json::from_str("\"environments:write\"").expect("known scope");
/// assert_eq!(scope, AutomationScope::EnvironmentsWrite);
/// assert!(serde_json::from_str::<AutomationScope>("\"settings:write\"").is_err());
/// ```
// The wire spelling below lives in three places and a rename has to
// touch all three: these renames, `scope_str` in
// `lorica-api/src/automation/scope.rs` (the string an operator reads in
// a 403), and
// `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.fixture.ts`
// (what the mint form offers). Two of the three agreeing is a token
// minted with a scope the gate never matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutomationScope {
    /// Create, update and tear down environments.
    #[serde(rename = "environments:write")]
    EnvironmentsWrite,
    /// Read environments and their state.
    #[serde(rename = "environments:read")]
    EnvironmentsRead,
    /// Read the routes an environment resolves to.
    #[serde(rename = "routes:read")]
    RoutesRead,
    /// Read certificate metadata (never private key material).
    #[serde(rename = "certificates:read")]
    CertificatesRead,
}

/// One scoped automation credential.
///
/// The row stores [`AutomationToken::secret_hmac`] and never the
/// secret, so a database read gives an attacker the ability to
/// recognise a token they already hold and nothing more.
///
/// `allowed_hostnames` and `allowed_backend_cidrs` are the token's
/// blast radius: what names it may claim and what it may point them at.
/// Both are enforced at use time, not at mint time, so tightening a
/// token narrows what it can already have created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationToken {
    /// The lookup half of the token, stored in clear; primary key of
    /// the `api_tokens` table.
    pub public_id: String,
    /// Operator-facing label.
    pub name: String,
    /// Lowercase-hex HMAC-SHA256 of the secret half under the node's
    /// automation token key.
    pub secret_hmac: String,
    /// What this token may do. At least one.
    pub scopes: Vec<AutomationScope>,
    /// Hostname patterns this token may claim: an exact hostname
    /// (`api.example.com`) or a wildcard (`*.preview.example.com`).
    /// At least one.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs (or bare addresses) this token may point a hostname at.
    /// At least one: there is no node-wide default backend policy to
    /// fall back on, and the filter reads an empty allow list as
    /// allow-every-address, which would let a token aim a public
    /// hostname at loopback or at a cloud metadata service.
    #[serde(default)]
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment this token creates may
    /// request, in seconds. Capped by
    /// [`AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP`].
    #[serde(default = "default_max_ttl_seconds")]
    pub max_ttl_seconds: u32,
    /// Username of the operator who minted the token.
    pub created_by: String,
    /// Mint timestamp.
    pub created_at: DateTime<Utc>,
    /// Absolute UTC instant after which the token is refused.
    /// Mandatory: a credential handed to a machine outlives the memory
    /// of who asked for it, so there is no "never expires" option.
    pub expires_at: DateTime<Utc>,
    /// When the token was last accepted, or `None` if never used. The
    /// signal an operator needs to retire a token nobody presents.
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When an operator withdrew the token, or `None` while it stands.
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AutomationToken {
    /// Whether the token is neither revoked nor expired at `now`.
    ///
    /// `now` is a parameter rather than a `Utc::now()` call inside, so
    /// the caller's single notion of "now" decides the whole request
    /// (liveness, TTL ceiling, `last_used_at`) and a test can place a
    /// token on either side of its expiry without waiting for a clock.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    /// Whether the token carries `scope`.
    pub fn has_scope(&self, scope: AutomationScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether any of the token's patterns covers `hostname`.
    ///
    /// The matcher is [`super::matches_one_label`], TLS wildcard
    /// semantics: `*.review.example.com` covers
    /// `mr-42.review.example.com` and refuses `a.b.review.example.com`.
    /// An operator reads a wildcard here the way they read one in a
    /// certificate, which is the only reading this product uses for a
    /// name it hands authority over.
    ///
    /// It is NOT [`super::matches_any_depth`], the certificate export
    /// ACL matcher, which covers a parent at any depth. That one grants
    /// a uid and a gid over files an operator already owns; this one
    /// grants the right to claim a name, and the extra depth would be
    /// authority nobody wrote down.
    pub fn allows_hostname(&self, hostname: &str) -> bool {
        self.allowed_hostnames
            .iter()
            .any(|pattern| matches_one_label(pattern, hostname))
    }

    /// Validate every operator-supplied field.
    ///
    /// Returns a human-readable message describing the first violated
    /// rule, suitable for a `400 Bad Request` body, the same shape as
    /// [`super::CaptureRule::validate`].
    ///
    /// # Errors
    ///
    /// Returns `Err` when the name is blank, when the token grants no
    /// scope, when it matches no hostname, when it names no backend
    /// CIDR, when a hostname pattern or a backend CIDR is malformed,
    /// when `max_ttl_seconds` is zero or over
    /// [`AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP`], or when `expires_at`
    /// is not after `created_at`.
    ///
    /// ```
    /// use lorica_config::models::AutomationToken;
    /// # fn demo(mut token: AutomationToken) {
    /// token.allowed_hostnames.clear();
    /// // A token that may write environments but matches no hostname
    /// // can do nothing, and would fail silently at every call.
    /// assert!(token.validate().is_err());
    /// # }
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("automation token must have a name".to_string());
        }
        if self.scopes.is_empty() {
            return Err("automation token must grant at least one scope".to_string());
        }
        if self.allowed_hostnames.is_empty() {
            return Err(
                "automation token must allow at least one hostname; a token that matches no \
                 hostname can do nothing, and does so silently"
                    .to_string(),
            );
        }
        for pattern in &self.allowed_hostnames {
            validate_hostname_pattern(pattern)?;
        }
        if self.allowed_backend_cidrs.is_empty() {
            return Err(
                "automation token must allow at least one backend CIDR; an empty                  allowed_backend_cidrs is read as every address, which would let this token                  point a public hostname at loopback or at a metadata service"
                    .to_string(),
            );
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
        if self.expires_at <= self.created_at {
            return Err("expires_at must be after created_at".to_string());
        }
        Ok(())
    }
}

/// One hostname pattern: an exact name, or a single leading `*.`
/// wildcard over a well-formed parent.
///
/// A bare `*` is refused. It would make the "at least one hostname"
/// rule vacuous, and an operator who wants a token over everything a
/// node serves is describing an operator credential, not an automation
/// one.
///
/// Shared with the OIDC issuer entry (Story 10.5), which grants the
/// same kind of authority over a name and must read a pattern the same
/// way.
pub(super) fn validate_hostname_pattern(pattern: &str) -> Result<(), String> {
    let invalid = |why: &str| format!("`{pattern}` is not a valid hostname pattern: {why}");
    if pattern == "*" {
        return Err(invalid(
            "a bare `*` grants every hostname; name the parent instead (`*.example.com`)",
        ));
    }
    if pattern.is_empty() || pattern.len() > HOSTNAME_PATTERN_MAX_LEN {
        return Err(invalid("empty, or longer than a DNS name may be"));
    }
    let parent = pattern.strip_prefix("*.").unwrap_or(pattern);
    if parent.contains('*') {
        return Err(invalid(
            "a wildcard is only allowed as a single leading `*.`",
        ));
    }
    if parent.is_empty() {
        return Err(invalid("the wildcard names no parent"));
    }
    for label in parent.split('.') {
        validate_hostname_label(label).map_err(|why| invalid(&why))?;
    }
    Ok(())
}

/// One DNS label: ASCII alphanumerics and inner hyphens.
fn validate_hostname_label(label: &str) -> Result<(), String> {
    if label.is_empty() || label.len() > HOSTNAME_LABEL_MAX_LEN {
        return Err(format!("`{label}` is not a usable DNS label"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(format!("`{label}` starts or ends with a hyphen"));
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("`{label}` holds a character DNS does not carry"));
    }
    Ok(())
}

/// Why an automation token string could not be parsed. Deliberately
/// shapeless (one variant): a caller with a mistyped token learns that
/// it is not a token, and nothing about which half was wrong.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed automation token")]
pub struct AutomationTokenFormatError;

/// Why an automation token could not be minted.
#[derive(Debug, thiserror::Error)]
pub enum AutomationMintError {
    /// The system RNG failed.
    #[error("token randomness unavailable")]
    Randomness,
}

/// A freshly minted automation token: what the operator copies ONCE,
/// and what the store keeps.
#[derive(Debug)]
pub struct MintedAutomationToken {
    /// The full `<public_id>.<secret>` string; shown once, never
    /// stored, never logged.
    pub token: String,
    /// The lookup half, stored in clear.
    pub public_id: String,
    /// Lowercase-hex HMAC-SHA256 of the secret half; the only trace of
    /// the secret the store holds.
    pub secret_hmac: String,
}

/// A presented automation token, split into its lookup and secret
/// halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAutomationToken {
    /// The lookup half.
    pub public_id: String,
    /// The secret half.
    pub secret: [u8; AUTOMATION_TOKEN_SECRET_LEN],
}

/// Whether `public_id` has the exact shape a minted token's lookup half
/// has: [`AUTOMATION_TOKEN_PUBLIC_ID_LEN`] bytes as lowercase hex.
///
/// [`parse_automation_token`] applies it before the caller reaches the
/// store, so a malformed id costs no lookup.
pub fn automation_public_id_is_valid(public_id: &str) -> bool {
    public_id.len() == AUTOMATION_TOKEN_PUBLIC_ID_LEN * 2
        && public_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Mint a token and hash its secret half under `hmac_key`.
///
/// # Errors
///
/// Returns `Err` when the system RNG refuses to fill either half.
pub fn mint_automation_token(
    hmac_key: &[u8],
) -> Result<MintedAutomationToken, AutomationMintError> {
    let rng = SystemRandom::new();
    let mut public = [0u8; AUTOMATION_TOKEN_PUBLIC_ID_LEN];
    let mut secret = [0u8; AUTOMATION_TOKEN_SECRET_LEN];
    rng.fill(&mut public)
        .map_err(|_| AutomationMintError::Randomness)?;
    rng.fill(&mut secret)
        .map_err(|_| AutomationMintError::Randomness)?;
    let public_id = hex(&public);
    let token = format!("{public_id}.{}", base64url_encode(&secret));
    Ok(MintedAutomationToken {
        token,
        public_id,
        secret_hmac: automation_secret_hmac_hex(hmac_key, &secret),
    })
}

/// Split a presented token into its halves, rejecting anything that
/// does not have a minted token's shape.
///
/// Surrounding whitespace is tolerated: tokens arrive through headers,
/// files and environment variables.
///
/// # Errors
///
/// Returns [`AutomationTokenFormatError`] when the string has no
/// separator, when the lookup half is not
/// [`AUTOMATION_TOKEN_PUBLIC_ID_LEN`] bytes of lowercase hex, or when
/// the secret half is not [`AUTOMATION_TOKEN_SECRET_LEN`] bytes of
/// URL-safe base64.
pub fn parse_automation_token(
    token: &str,
) -> Result<ParsedAutomationToken, AutomationTokenFormatError> {
    let token = token.trim();
    let (public_id, encoded) = token.split_once('.').ok_or(AutomationTokenFormatError)?;
    if !automation_public_id_is_valid(public_id) {
        return Err(AutomationTokenFormatError);
    }
    let bytes = base64url_decode(encoded).ok_or(AutomationTokenFormatError)?;
    let secret: [u8; AUTOMATION_TOKEN_SECRET_LEN] =
        bytes.try_into().map_err(|_| AutomationTokenFormatError)?;
    Ok(ParsedAutomationToken {
        public_id: public_id.to_string(),
        secret,
    })
}

/// Lowercase-hex HMAC-SHA256 of `secret` under `hmac_key`.
pub fn automation_secret_hmac_hex(hmac_key: &[u8], secret: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    hex(hmac::sign(&key, secret).as_ref())
}

/// Constant-time check of `secret` against a stored hex digest. A
/// digest that is not valid hex verifies as false in the same time.
pub fn verify_automation_secret(hmac_key: &[u8], secret: &[u8], stored_hmac_hex: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    let expected = unhex(stored_hmac_hex).unwrap_or_else(|| vec![0u8; 32]);
    hmac::verify(&key, secret, &expected).is_ok()
}

/// A stored digest to verify against when the `public_id` is unknown,
/// so the unknown-id path costs exactly one verification like the
/// known-id path and answers in the same time.
pub fn dummy_automation_secret_hmac_hex() -> String {
    hex(&[0u8; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn base64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    /// A token that validates, so each test below changes exactly one
    /// thing and the failure it asserts is the thing it changed.
    fn valid_token() -> AutomationToken {
        AutomationToken {
            public_id: "0123456789abcdef01234567".to_string(),
            name: "ci pipeline".to_string(),
            secret_hmac: dummy_automation_secret_hmac_hex(),
            scopes: vec![
                AutomationScope::EnvironmentsWrite,
                AutomationScope::RoutesRead,
            ],
            allowed_hostnames: vec!["*.preview.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
            created_by: "admin".to_string(),
            created_at: fixed_now(),
            expires_at: fixed_now()
                + chrono::Duration::days(AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS),
            last_used_at: None,
            revoked_at: None,
        }
    }

    // ---- The scope enum ----

    #[test]
    fn every_scope_round_trips_through_its_exact_wire_string() {
        for (scope, wire) in [
            (AutomationScope::EnvironmentsWrite, "environments:write"),
            (AutomationScope::EnvironmentsRead, "environments:read"),
            (AutomationScope::RoutesRead, "routes:read"),
            (AutomationScope::CertificatesRead, "certificates:read"),
        ] {
            let json = serde_json::to_string(&scope).expect("test setup: scope serialises");
            assert_eq!(json, format!("\"{wire}\""));
            let back: AutomationScope =
                serde_json::from_str(&json).expect("test setup: scope deserialises");
            assert_eq!(back, scope);
        }
    }

    #[test]
    fn an_unknown_scope_string_fails_to_deserialise_rather_than_being_ignored() {
        // The enum is the whole grant surface for 1.8.0. Dropping an
        // unknown entry would mint a token narrower than the operator
        // wrote, and they would find out at the first call.
        for unknown in [
            "\"settings:write\"",
            "\"routes:write\"",
            "\"certificates:write\"",
            "\"environments\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<AutomationScope>(unknown).is_err(),
                "{unknown} must be refused"
            );
        }
    }

    #[test]
    fn a_token_with_no_backend_cidr_is_refused() {
        // An empty allow list is default-allow in the connection
        // filter, so "no CIDR named" would be the widest grant the
        // token can carry rather than the narrowest.
        let mut token = valid_token();
        token.allowed_backend_cidrs.clear();
        let err = token
            .validate()
            .expect_err("an empty backend grant is refused");
        assert!(err.contains("allowed_backend_cidrs"), "{err}");
    }

    // ---- Liveness ----

    #[test]
    fn a_fresh_token_is_live() {
        assert!(valid_token().is_live(fixed_now()));
    }

    #[test]
    fn a_revoked_token_is_not_live() {
        let mut token = valid_token();
        token.revoked_at = Some(fixed_now());
        assert!(!token.is_live(fixed_now()));
    }

    #[test]
    fn an_expired_token_is_not_live() {
        let mut token = valid_token();
        token.expires_at = fixed_now();
        assert!(!token.is_live(fixed_now() + chrono::Duration::seconds(1)));
    }

    // ---- Hostname matching ----

    #[test]
    fn an_exact_hostname_matches_only_itself() {
        let mut token = valid_token();
        token.allowed_hostnames = vec!["api.example.com".to_string()];
        assert!(token.allows_hostname("api.example.com"));
        assert!(token.allows_hostname("API.Example.COM"));
        assert!(!token.allows_hostname("other.example.com"));
    }

    #[test]
    fn a_wildcard_covers_a_label_but_never_the_bare_parent() {
        let token = valid_token();
        assert!(token.allows_hostname("pr-42.preview.example.com"));
        assert!(!token.allows_hostname("preview.example.com"));
        assert!(!token.allows_hostname("pr-42.preview.example.org"));
    }

    #[test]
    fn a_wildcard_does_not_cover_a_deeper_subdomain() {
        // The grant is deliberately narrower than the certificate
        // export ACL, which would cover this name: a wildcard here
        // means what it means in a certificate, exactly one label, so
        // an operator who writes `*.preview.example.com` does not
        // discover later that they also handed out everything below it.
        let token = valid_token();
        assert!(!token.allows_hostname("a.b.preview.example.com"));
    }

    #[test]
    fn a_hostname_outside_every_pattern_does_not_match() {
        let token = valid_token();
        assert!(!token.allows_hostname("example.com"));
        assert!(!token.allows_hostname("preview.example.com.evil.test"));
    }

    // ---- Validation ----

    #[test]
    fn a_well_formed_token_validates() {
        assert!(valid_token().validate().is_ok());
    }

    #[test]
    fn a_token_with_no_name_is_refused() {
        let mut token = valid_token();
        token.name = "   ".to_string();
        let err = token.validate().expect_err("a blank name is refused");
        assert!(err.contains("name"), "{err}");
    }

    #[test]
    fn a_token_with_no_scope_is_refused() {
        let mut token = valid_token();
        token.scopes.clear();
        let err = token.validate().expect_err("no scope is refused");
        assert!(err.contains("scope"), "{err}");
    }

    #[test]
    fn a_token_with_no_hostname_is_refused() {
        let mut token = valid_token();
        token.allowed_hostnames.clear();
        let err = token.validate().expect_err("no hostname is refused");
        assert!(err.contains("hostname"), "{err}");
    }

    #[test]
    fn a_bare_wildcard_hostname_is_refused() {
        let mut token = valid_token();
        token.allowed_hostnames = vec!["*".to_string()];
        let err = token.validate().expect_err("a bare `*` is refused");
        assert!(err.contains("example.com"), "{err}");
    }

    #[test]
    fn a_malformed_hostname_pattern_is_refused() {
        for bad in [
            "",
            "*.",
            "exa*mple.com",
            "*.*.example.com",
            "-lead.example.com",
            "trail-.example.com",
            "under_score.example.com",
            "double..dot",
        ] {
            let mut token = valid_token();
            token.allowed_hostnames = vec![bad.to_string()];
            assert!(token.validate().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_hostname_shapes_an_operator_writes_are_accepted() {
        let mut token = valid_token();
        token.allowed_hostnames = vec![
            "api.example.com".to_string(),
            "*.preview.example.com".to_string(),
            "localhost".to_string(),
            "pr-42.example.com".to_string(),
        ];
        assert!(token.validate().is_ok());
    }

    #[test]
    fn a_backend_cidr_that_does_not_parse_is_refused() {
        let mut token = valid_token();
        token.allowed_backend_cidrs = vec!["10.0.0.0/33".to_string()];
        let err = token.validate().expect_err("a /33 is not a v4 prefix");
        assert!(err.contains("allowed_backend_cidrs"), "{err}");
    }

    #[test]
    fn a_zero_max_ttl_is_refused() {
        let mut token = valid_token();
        token.max_ttl_seconds = 0;
        let err = token.validate().expect_err("a zero ceiling is refused");
        assert!(err.contains("max_ttl_seconds"), "{err}");
    }

    #[test]
    fn a_max_ttl_over_the_hard_cap_is_refused() {
        let mut token = valid_token();
        token.max_ttl_seconds = AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP + 1;
        let err = token.validate().expect_err("over the cap");
        assert!(err.contains("max_ttl_seconds"), "{err}");
    }

    #[test]
    fn an_expiry_before_creation_is_refused() {
        let mut token = valid_token();
        token.expires_at = token.created_at - chrono::Duration::seconds(1);
        let err = token.validate().expect_err("expiry precedes creation");
        assert!(err.contains("expires_at"), "{err}");
    }

    // ---- Mint, parse, verify ----

    #[test]
    fn mint_then_parse_then_verify_round_trips() {
        let key = [7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let minted = mint_automation_token(&key).expect("test setup: mint");
        let parsed =
            parse_automation_token(&format!("  {}\n", minted.token)).expect("test setup: parse");
        assert_eq!(parsed.public_id, minted.public_id);
        assert!(verify_automation_secret(
            &key,
            &parsed.secret,
            &minted.secret_hmac
        ));
        // The token carries the secret, never its digest, and never
        // base64 padding.
        assert!(!minted.token.contains(&minted.secret_hmac));
        assert!(!minted.token.contains('='));
    }

    #[test]
    fn a_wrong_secret_fails_verification() {
        let key = [7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let minted = mint_automation_token(&key).expect("test setup: mint");
        let other = mint_automation_token(&key).expect("test setup: mint");
        let wrong = parse_automation_token(&other.token).expect("test setup: parse");
        assert!(!verify_automation_secret(
            &key,
            &wrong.secret,
            &minted.secret_hmac
        ));
        assert!(!verify_automation_secret(
            &key,
            &[0u8; AUTOMATION_TOKEN_SECRET_LEN],
            &minted.secret_hmac
        ));
    }

    #[test]
    fn a_secret_hashed_under_another_key_fails_verification() {
        let minted =
            mint_automation_token(&[7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN]).expect("test setup: mint");
        let parsed = parse_automation_token(&minted.token).expect("test setup: parse");
        assert!(!verify_automation_secret(
            &[8u8; AUTOMATION_TOKEN_HMAC_KEY_LEN],
            &parsed.secret,
            &minted.secret_hmac
        ));
    }

    #[test]
    fn a_tampered_public_id_fails_the_shape_guard_before_any_lookup() {
        let key = [7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let minted = mint_automation_token(&key).expect("test setup: mint");
        let secret = minted
            .token
            .split_once('.')
            .expect("test setup: minted tokens carry a separator")
            .1;
        for bad_id in [
            "",
            "0123456789ABCDEF01234567",
            "0123456789abcdef0123456",
            "0123456789abcdef012345678",
            "0123456789abcdefgggggggg",
        ] {
            assert_eq!(
                parse_automation_token(&format!("{bad_id}.{secret}")),
                Err(AutomationTokenFormatError),
                "{bad_id:?}"
            );
        }
    }

    #[test]
    fn a_malformed_token_is_refused_with_one_shapeless_error() {
        let valid_id = "0123456789abcdef01234567";
        let short_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16]);
        for bad in [
            String::new(),
            "nodot".to_string(),
            valid_id.to_string(),
            format!("{valid_id}.{short_secret}"),
            format!("{valid_id}.***"),
            format!("{valid_id}."),
        ] {
            assert_eq!(
                parse_automation_token(&bad),
                Err(AutomationTokenFormatError),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn two_mints_never_collide() {
        let key = [1u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let a = mint_automation_token(&key).expect("test setup: mint");
        let b = mint_automation_token(&key).expect("test setup: mint");
        assert_ne!(a.public_id, b.public_id);
        assert_ne!(a.secret_hmac, b.secret_hmac);
        assert_ne!(a.token, b.token);
    }

    #[test]
    fn the_dummy_digest_refuses_every_secret_so_the_unknown_id_path_matches() {
        // An unknown public_id has no stored digest, so the caller
        // verifies against this one instead of returning early. Both
        // paths must therefore run one verification and both must say
        // no.
        let key = [7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let minted = mint_automation_token(&key).expect("test setup: mint");
        let parsed = parse_automation_token(&minted.token).expect("test setup: parse");
        assert!(!verify_automation_secret(
            &key,
            &parsed.secret,
            &dummy_automation_secret_hmac_hex()
        ));
        assert!(!verify_automation_secret(
            &key,
            &[0u8; AUTOMATION_TOKEN_SECRET_LEN],
            &dummy_automation_secret_hmac_hex()
        ));
    }

    #[test]
    fn a_stored_digest_that_is_not_hex_verifies_as_false() {
        let key = [7u8; AUTOMATION_TOKEN_HMAC_KEY_LEN];
        let minted = mint_automation_token(&key).expect("test setup: mint");
        let parsed = parse_automation_token(&minted.token).expect("test setup: parse");
        assert!(!verify_automation_secret(&key, &parsed.secret, "not hex"));
        assert!(!verify_automation_secret(&key, &parsed.secret, ""));
    }
}
