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

/// The longest lifetime, in days, of an automation token carrying
/// `settings:write` (maintainer decision, 2026-09-30).
///
/// That scope is the MCP admin tier's: it changes fleet-wide
/// operational settings and is minted for the one task that needs it.
/// A short lifetime was advice until this constant;
/// [`AutomationToken::validate`] now refuses a longer one, so the
/// dashboard, the management API and both CLI commands are held to it
/// by the one validator they share. The per-tier default
/// `lorica mcp token create` uses is pinned at or beneath it by a test
/// in `lorica-mcp`, which cannot otherwise see it.
pub const AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS: i64 = 7;

/// How every refusal about an automation token names its subject.
pub const AUTOMATION_TOKEN_SUBJECT: &str = "automation token";

/// Longest hostname pattern accepted, matching the DNS name limit.
const HOSTNAME_PATTERN_MAX_LEN: usize = 253;

/// Longest single label inside a hostname pattern (RFC 1035).
const HOSTNAME_LABEL_MAX_LEN: usize = 63;

fn default_max_ttl_seconds() -> u32 {
    AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS
}

/// What an automation token is allowed to do.
///
/// The enum is closed and [`AutomationScope::ALL`] is the whole surface.
/// What is absent from it is absent deliberately: there is no
/// `certificates:upload`, no `users:*` and no `cluster:write`, because
/// key material, identity and fleet membership enter through the
/// management API, by a human, and never through a token.
///
/// The read grants beyond `routes:read` and `certificates:read` arrived
/// with the management MCP server (Epic 11). Its read tier is what
/// consumes them: a session that can only read has nothing an injected
/// instruction can usefully reach.
///
/// The three write grants, `routes:write`, `backends:write` and
/// `certificates:write`, arrived with that server's config tier (Story
/// 11.2) and reverse the Story 10.3 decision that the automation
/// surface is the environment resource and never the management API
/// behind a different door. The reversal is recorded beside that
/// decision in the Epic 10 PRD. A token carrying one of them reaches
/// the management plane's own handler and validators for that
/// resource, bounded by the token's hostname and backend grants; it is
/// a different credential from the one a CI pipeline uses for
/// ephemeral environments, and an operator mints it as such.
///
/// `settings:write` arrived with that server's admin tier (Story 11.3)
/// and reverses the rest of the same Story 10.3 decision for node-wide
/// settings, bounded: it reaches one path, and that path accepts only
/// the keys `SETTINGS_ALLOWLIST` in `lorica-api` names, each with the
/// reason it is there. Every other setting, and every identity and
/// cluster operation, stays out of reach of any token.
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
/// assert!(serde_json::from_str::<AutomationScope>("\"users:write\"").is_err());
/// ```
// The serde renames below are this vocabulary's source of truth. The
// surfaces named here carry the same strings and none of them is
// maintained from memory: `AutomationScope::as_str` below (the string
// an operator reads in a 403 and in an audit row, which
// `lorica-api`'s `scope_str` returns) is asserted against these
// renames by a test that walks `ALL`;
// `AUTOMATION_AUDIT_REASONS` publishes them as refusal reasons under
// the same walk; the two OpenAPI documents restate the enum and are
// read by `lorica-api/tests/openapi_contract.rs`; and
// `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`,
// what the mint form offers, is diffed against `ALL` by
// `lorica-api/tests/automation_scope_fixture.rs`. Add a variant here
// alone and each of those turns red.
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
    /// Read access-log rows.
    #[serde(rename = "logs:read")]
    LogsRead,
    /// Read WAF events and their aggregate counts.
    #[serde(rename = "waf:read")]
    WafRead,
    /// Read SLA windows per route.
    #[serde(rename = "sla:read")]
    SlaRead,
    /// Read cluster and node status.
    #[serde(rename = "cluster:read")]
    ClusterRead,
    /// Read the backends a route resolves to.
    #[serde(rename = "backends:read")]
    BackendsRead,
    /// Create, update and delete routes, one by id, and bind a
    /// certificate to one.
    #[serde(rename = "routes:write")]
    RoutesWrite,
    /// Create, update and delete backends, one by id.
    #[serde(rename = "backends:write")]
    BackendsWrite,
    /// Bind a stored certificate to a route and renew an ACME one.
    /// Never an upload: key material is not an argument anywhere on
    /// the automation plane.
    #[serde(rename = "certificates:write")]
    CertificatesWrite,
    /// Change the operational global settings the admin tier's
    /// allowlist names, and nothing else: never an identity, a
    /// credential, a listener or the fleet.
    #[serde(rename = "settings:write")]
    SettingsWrite,
}

impl AutomationScope {
    /// Every variant, in declaration order.
    ///
    /// The one place anything that has to walk the vocabulary reads it
    /// from, so that the surfaces restating the spellings (the
    /// [`AutomationScope::as_str`] match, the published audit
    /// reasons, the dashboard's generated fixture) are each checked
    /// against the enum instead of against somebody's memory of it. A
    /// variant added above and not here fails
    /// `all_carries_every_variant_the_enum_declares`.
    pub const ALL: &'static [AutomationScope] = &[
        AutomationScope::EnvironmentsWrite,
        AutomationScope::EnvironmentsRead,
        AutomationScope::RoutesRead,
        AutomationScope::CertificatesRead,
        AutomationScope::LogsRead,
        AutomationScope::WafRead,
        AutomationScope::SlaRead,
        AutomationScope::ClusterRead,
        AutomationScope::BackendsRead,
        AutomationScope::RoutesWrite,
        AutomationScope::BackendsWrite,
        AutomationScope::CertificatesWrite,
        AutomationScope::SettingsWrite,
    ];

    /// Whether a path this scope reaches consults the credential's
    /// hostname and backend grants.
    ///
    /// The one place the set is decided, and it is decided by what the
    /// automation plane's handlers read, verified on the code: the
    /// environment write checks every hostname and backend address it
    /// claims; the route, backend and certificate writes run the grant
    /// guards on the body and on the stored row they name. No read and
    /// not the settings write consults either grant, so on a credential
    /// carrying none of these the grants bound nothing, and
    /// `validate_automation_grants` refuses them there.
    ///
    /// An exhaustive `match` and not a list, so a scope added to the
    /// enum is a compile error here until somebody decides.
    ///
    /// ```
    /// use lorica_config::models::AutomationScope;
    /// assert!(AutomationScope::RoutesWrite.is_grant_bounded());
    /// assert!(!AutomationScope::SettingsWrite.is_grant_bounded());
    /// assert!(!AutomationScope::LogsRead.is_grant_bounded());
    /// ```
    pub fn is_grant_bounded(self) -> bool {
        match self {
            AutomationScope::EnvironmentsWrite
            | AutomationScope::RoutesWrite
            | AutomationScope::BackendsWrite
            | AutomationScope::CertificatesWrite => true,
            AutomationScope::EnvironmentsRead
            | AutomationScope::RoutesRead
            | AutomationScope::CertificatesRead
            | AutomationScope::LogsRead
            | AutomationScope::WafRead
            | AutomationScope::SlaRead
            | AutomationScope::ClusterRead
            | AutomationScope::BackendsRead
            | AutomationScope::SettingsWrite => false,
        }
    }

    /// The scope as the wire spells it: the serde rename, which a test
    /// walking [`Self::ALL`] holds this match to.
    ///
    /// ```
    /// use lorica_config::models::AutomationScope;
    /// assert_eq!(AutomationScope::SettingsWrite.as_str(), "settings:write");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            AutomationScope::EnvironmentsWrite => "environments:write",
            AutomationScope::EnvironmentsRead => "environments:read",
            AutomationScope::RoutesRead => "routes:read",
            AutomationScope::CertificatesRead => "certificates:read",
            AutomationScope::LogsRead => "logs:read",
            AutomationScope::WafRead => "waf:read",
            AutomationScope::SlaRead => "sla:read",
            AutomationScope::ClusterRead => "cluster:read",
            AutomationScope::BackendsRead => "backends:read",
            AutomationScope::RoutesWrite => "routes:write",
            AutomationScope::BackendsWrite => "backends:write",
            AutomationScope::CertificatesWrite => "certificates:write",
            AutomationScope::SettingsWrite => "settings:write",
        }
    }

    /// The scope a wire spelling names, or `None` for one this build
    /// does not know.
    ///
    /// ```
    /// use lorica_config::models::AutomationScope;
    /// assert_eq!(
    ///     AutomationScope::from_wire("routes:write"),
    ///     Some(AutomationScope::RoutesWrite)
    /// );
    /// assert_eq!(AutomationScope::from_wire("dns:write"), None);
    /// ```
    pub fn from_wire(spelling: &str) -> Option<AutomationScope> {
        AutomationScope::ALL
            .iter()
            .copied()
            .find(|scope| scope.as_str() == spelling)
    }
}

/// The hostname and backend grants of a credential carrying `scopes`,
/// held to typed absence (maintainer decision, 2026-09-30).
///
/// Required, non-empty and well-formed, when any scope is
/// [`AutomationScope::is_grant_bounded`]. Refused, both empty, when none
/// is: a grant on a credential whose every path ignores it is a blast
/// radius the operator reads and the node never applies. An empty list
/// means "nothing" everywhere it is read (`allows_hostname` matches no
/// pattern; the backend check refuses before it builds a filter), so a
/// credential that carries a bounded scope and an empty grant could do
/// nothing, silently, which is why it is refused here rather than
/// discovered at the first call.
///
/// Shared by the static token and the OIDC issuer entry, which grant
/// the same two things. `subject` names the credential in the message.
///
/// # Errors
///
/// A message naming the field and the rule, for a `422` body.
pub fn validate_automation_grants(
    subject: &str,
    scopes: &[AutomationScope],
    allowed_hostnames: &[String],
    allowed_backend_cidrs: &[String],
) -> Result<(), String> {
    if !scopes.iter().any(|scope| scope.is_grant_bounded()) {
        for (field, grant) in [
            ("allowed_hostnames", allowed_hostnames),
            ("allowed_backend_cidrs", allowed_backend_cidrs),
        ] {
            if !grant.is_empty() {
                let bounded: Vec<&str> = AutomationScope::ALL
                    .iter()
                    .filter(|scope| scope.is_grant_bounded())
                    .map(|scope| scope.as_str())
                    .collect();
                return Err(format!(
                    "{subject} carries no scope a hostname or backend grant bounds ({}), so \
                     {field} must be empty: here it would bound nothing and still read as the \
                     {subject}'s blast radius",
                    bounded.join(", ")
                ));
            }
        }
        return Ok(());
    }
    if allowed_hostnames.is_empty() {
        return Err(format!(
            "{subject} carries a scope the hostname grant bounds, so it must allow at least one \
             hostname; one that matches no hostname can do nothing, and does so silently"
        ));
    }
    for pattern in allowed_hostnames {
        validate_hostname_pattern(pattern)?;
    }
    if allowed_backend_cidrs.is_empty() {
        return Err(format!(
            "{subject} carries a scope the backend grant bounds, so it must allow at least one \
             backend CIDR in allowed_backend_cidrs; an empty list admits no address, and there \
             is no node-wide default backend policy to fall back on"
        ));
    }
    for cidr in allowed_backend_cidrs {
        validate_cidr(cidr, "allowed_backend_cidrs")?;
    }
    Ok(())
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
    /// At least one when the token carries a grant-bounded scope
    /// ([`AutomationScope::is_grant_bounded`]), none otherwise: an
    /// empty list is the typed absence of a grant, and it admits no
    /// host.
    #[serde(default)]
    pub allowed_hostnames: Vec<String>,
    /// CIDRs (or bare addresses) this token may point a hostname at.
    /// Same rule as [`Self::allowed_hostnames`]. An empty list admits
    /// no address: the backend check refuses on it before it builds
    /// the connection filter, whose own empty allow list would read as
    /// every address.
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
    /// scope, when it carries a grant-bounded scope and matches no
    /// hostname or names no backend CIDR, when it carries none and
    /// names either grant anyway, when a hostname pattern or a backend
    /// CIDR is malformed,
    /// when `max_ttl_seconds` is zero or over
    /// [`AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP`], when `expires_at`
    /// is not after `created_at`, or when a token carrying
    /// `settings:write` would live longer than
    /// [`AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS`].
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
            return Err(format!("{AUTOMATION_TOKEN_SUBJECT} must have a name"));
        }
        if self.scopes.is_empty() {
            return Err(format!(
                "{AUTOMATION_TOKEN_SUBJECT} must grant at least one scope"
            ));
        }
        validate_automation_grants(
            AUTOMATION_TOKEN_SUBJECT,
            &self.scopes,
            &self.allowed_hostnames,
            &self.allowed_backend_cidrs,
        )?;
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
        let ceiling = chrono::Duration::days(AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS);
        if self.has_scope(AutomationScope::SettingsWrite)
            && self.expires_at - self.created_at > ceiling
        {
            return Err(format!(
                "{AUTOMATION_TOKEN_SUBJECT} carrying {} lives at most \
                 {AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS} days: it changes operational \
                 settings and is minted for the task that needs them; pass lifetime_days \
                 {AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS} or less, or an expires_at inside \
                 that window",
                AutomationScope::SettingsWrite.as_str()
            ));
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
/// Shared with the OIDC issuer entry (Story 10.5) through
/// [`validate_automation_grants`]: it grants the same kind of authority over a
/// name and must read a pattern the same way.
fn validate_hostname_pattern(pattern: &str) -> Result<(), String> {
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

    /// The wire spellings this file's enum declares, read back out of
    /// its own source.
    ///
    /// Nothing else in the process can see a serde rename, so the only
    /// way to assert that [`AutomationScope::ALL`] is complete is to
    /// look at what the enum wrote. A hand-written expectation would
    /// need remembering on exactly the day it matters.
    fn renames_declared_by_the_enum() -> Vec<&'static str> {
        const MARKER: &str = "#[serde(rename = \"";
        let body: &'static str = include_str!("automation_token.rs")
            .split_once("pub enum AutomationScope {")
            .expect("the enum is declared in this file")
            .1
            .split_once("\n}")
            .expect("the enum body ends at a closing brace in column zero")
            .0;
        body.match_indices(MARKER)
            .filter_map(|(at, marker)| body[at + marker.len()..].split_once('"'))
            .map(|(spelling, _)| spelling)
            .collect()
    }

    /// The wire spelling of every entry in [`AutomationScope::ALL`].
    fn spellings_of_all() -> Vec<String> {
        AutomationScope::ALL
            .iter()
            .map(|scope| {
                serde_json::to_value(scope)
                    .expect("test setup: a scope serialises")
                    .as_str()
                    .expect("test setup: a scope serialises to a string")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn all_carries_every_variant_the_enum_declares() {
        let declared: Vec<&str> = renames_declared_by_the_enum();
        assert!(
            !declared.is_empty(),
            "the rename scan found nothing: the enum was reshaped and this guard went blind"
        );
        assert_eq!(
            spellings_of_all(),
            declared,
            "AutomationScope::ALL and the enum's serde renames disagree. \
             ALL is what every other surface walks, so a variant missing \
             from it is a grant the 403 cannot name and the mint form \
             cannot offer."
        );
    }

    #[test]
    fn every_scope_round_trips_through_its_exact_wire_string() {
        for scope in AutomationScope::ALL {
            let json = serde_json::to_string(scope).expect("test setup: scope serialises");
            let back: AutomationScope =
                serde_json::from_str(&json).expect("test setup: scope deserialises");
            assert_eq!(back, *scope);
        }
    }

    #[test]
    fn an_unknown_scope_string_fails_to_deserialise_rather_than_being_ignored() {
        // [`AutomationScope::ALL`] is the whole grant surface. Dropping
        // an unknown entry would mint a token narrower than the
        // operator wrote, and they would find out at the first call.
        for unknown in [
            "\"users:write\"",
            "\"certificates:upload\"",
            "\"waf:write\"",
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

    #[test]
    fn a_token_carrying_no_bounded_scope_carries_no_grant() {
        // Typed absence (2026-09-30). A read or a settings token carries
        // grants that no path it reaches consults, and a grant that
        // bounds nothing still reads as a blast radius in the listing.
        for scope in AutomationScope::ALL
            .iter()
            .copied()
            .filter(|scope| !scope.is_grant_bounded())
        {
            let mut token = valid_token();
            token.scopes = vec![scope];
            // Inside every scope's lifetime ceiling, so the only thing
            // wrong with the token is the grant under test.
            token.expires_at = token.created_at + chrono::Duration::days(1);
            let refused = token
                .validate()
                .expect_err("grants on a token they cannot bound");
            assert!(
                refused.contains("allowed_hostnames"),
                "{scope:?}: {refused}"
            );
            token.allowed_hostnames.clear();
            let refused = token
                .validate()
                .expect_err("the CIDR grant bounds nothing either");
            assert!(
                refused.contains("allowed_backend_cidrs"),
                "{scope:?}: {refused}"
            );
            token.allowed_backend_cidrs.clear();
            assert_eq!(token.validate(), Ok(()), "{scope:?}");
        }
    }

    #[test]
    fn a_token_carrying_one_bounded_scope_needs_both_grants_whatever_else_it_carries() {
        for scope in AutomationScope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.is_grant_bounded())
        {
            let mut token = valid_token();
            token.scopes = vec![AutomationScope::LogsRead, scope];
            assert_eq!(token.validate(), Ok(()), "{scope:?}");
            let mut no_host = token.clone();
            no_host.allowed_hostnames.clear();
            assert!(no_host.validate().is_err(), "{scope:?}");
            let mut no_cidr = token;
            no_cidr.allowed_backend_cidrs.clear();
            assert!(no_cidr.validate().is_err(), "{scope:?}");
        }
    }

    #[test]
    fn the_grant_bounded_scopes_are_writes_and_the_settings_write_is_not_one() {
        // The admin tier's scope reaches the settings path, which no
        // grant bounds; every other write is bounded.
        let mut bounded = 0usize;
        for scope in AutomationScope::ALL {
            let spelled = serde_json::to_value(scope)
                .expect("test setup: a scope serialises")
                .as_str()
                .expect("test setup: a string")
                .to_string();
            if scope.is_grant_bounded() {
                bounded += 1;
                assert!(spelled.ends_with(":write"), "{spelled}");
            }
        }
        assert!(bounded > 0);
        assert!(!AutomationScope::SettingsWrite.is_grant_bounded());
    }

    #[test]
    fn an_empty_hostname_grant_admits_no_host() {
        // Empty means nothing, never everything: a row stored before
        // typed absence, or a read token, can claim no name.
        let mut token = valid_token();
        token.allowed_hostnames.clear();
        for host in [
            "pr-42.preview.example.com",
            "preview.example.com",
            "localhost",
            "*",
            "",
        ] {
            assert!(!token.allows_hostname(host), "{host:?}");
        }
    }

    #[test]
    fn no_refusal_carries_a_run_of_spaces_from_a_broken_line_continuation() {
        // The backend CIDR message once lost its trailing backslash and
        // carried two runs of source indentation to every operator.
        let mut no_cidr = valid_token();
        no_cidr.allowed_backend_cidrs.clear();
        let mut no_host = valid_token();
        no_host.allowed_hostnames.clear();
        let mut unbounded = valid_token();
        unbounded.scopes = vec![AutomationScope::LogsRead];
        for token in [no_cidr, no_host, unbounded] {
            let refused = token.validate().expect_err("refused");
            assert!(!refused.contains("  "), "{refused}");
        }
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
    fn a_settings_write_token_lives_at_most_the_ceiling_and_no_other_scope_is_held_to_it() {
        let ceiling = chrono::Duration::days(AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS);
        let mut admin = valid_token();
        admin.scopes = vec![AutomationScope::SettingsWrite];
        admin.allowed_hostnames.clear();
        admin.allowed_backend_cidrs.clear();

        admin.expires_at = admin.created_at + ceiling;
        admin.validate().expect("exactly the ceiling is allowed");

        admin.expires_at = admin.created_at + ceiling + chrono::Duration::seconds(1);
        let err = admin.validate().expect_err("past the ceiling is refused");
        assert!(
            err.contains(&format!(
                "{AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS} days"
            )),
            "the refusal names the ceiling: {err}"
        );
        assert!(err.contains("settings:write"), "{err}");
        assert!(!err.contains("  "), "a line continuation was lost: {err}");

        // The node's own default lifetime is past the ceiling, so a
        // settings:write mint that names no lifetime is refused rather
        // than silently shortened.
        admin.expires_at =
            admin.created_at + chrono::Duration::days(AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS);
        assert!(admin.validate().is_err());

        // Beside other scopes the rule still holds: it follows the
        // scope, not the scope set.
        let mut mixed = valid_token();
        mixed.scopes.push(AutomationScope::SettingsWrite);
        assert!(mixed.validate().is_err());

        // Without settings:write, the default lifetime stands.
        valid_token()
            .validate()
            .expect("a token without settings:write keeps the default lifetime");
    }

    #[test]
    fn a_scope_spells_itself_the_way_serde_does_and_reads_back() {
        assert!(!AutomationScope::ALL.is_empty());
        for scope in AutomationScope::ALL {
            let serde_spelling = serde_json::to_value(scope)
                .expect("a scope serialises")
                .as_str()
                .map(str::to_string)
                .expect("to a string");
            assert_eq!(scope.as_str(), serde_spelling);
            assert_eq!(AutomationScope::from_wire(scope.as_str()), Some(*scope));
        }
        assert_eq!(AutomationScope::from_wire("users:write"), None);
        assert_eq!(AutomationScope::from_wire(""), None);
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
