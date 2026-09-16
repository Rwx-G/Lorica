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

//! GitLab OIDC ID tokens as a second credential on the automation
//! listener (Story 10.5).
//!
//! A job presents the JWT GitLab minted for it instead of a shared
//! secret. The token lives for minutes, says which project, ref and
//! environment the job runs for, and is signed by the instance. This
//! module decides whether to believe it.
//!
//! # The algorithm never comes from the token
//!
//! [`OidcVerifier::verify`] pins RS256 twice: the header's `alg` is
//! compared to the literal before any key is looked up, and the
//! [`jsonwebtoken::Validation`] handed to the library lists RS256
//! alone. A token whose header says `HS256`, signed with the issuer's
//! public key as the MAC secret, is the oldest defect in this family
//! and is refused as `wrong_alg` without touching the key set; the
//! test suite presents exactly that token, and one with `alg: none`.
//!
//! # What a caller learns
//!
//! Nothing. Every failure is a [`RefusalReason`], and the bearer gate
//! turns every one of them into the same 401 the static-token path
//! answers. The precise reason goes to the audit row alone, where an
//! operator can read it and an attacker cannot.
//!
//! # Layout
//!
//! - [`jwks`] - the key cache, its two refresh triggers and the
//!   HTTPS fetcher.
//! - [`replay`] - the bounded `jti` set.
//! - this file - the verification itself, the claims that become the
//!   identity, and the GitLab environment-slug rule.

pub mod jwks;
pub mod replay;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Validation};
use lorica_config::models::{OidcIssuer, PipelineIdentity, OIDC_BOUND_CLAIM_NAMES};

pub use jwks::{HttpJwksFetcher, JwksCache, JwksFetcher, JwksLookupError};
pub use replay::{ReplaySet, OIDC_REPLAY_SET_CAP};

/// Clock skew tolerated on `exp`, `nbf` and `iat`, in seconds.
pub const OIDC_CLOCK_SKEW_SECONDS: u64 = 60;

/// The one signing algorithm accepted, as the header spells it.
const PINNED_ALGORITHM_NAME: &str = "RS256";

/// The one signing algorithm accepted, as the library spells it.
const PINNED_ALGORITHM: Algorithm = Algorithm::RS256;

/// Why an ID token was refused. Never on the wire; the audit row's
/// `reason` field is [`RefusalReason::audit_reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// Not three base64url segments carrying a JSON header and payload.
    Malformed,
    /// The header names an algorithm other than RS256, `none` included.
    WrongAlg,
    /// No registered issuer entry names the token's audience.
    NoIssuer,
    /// The header's `kid` is absent, or the issuer's current key set
    /// does not carry it.
    UnknownKid,
    /// The issuer's key set could not be fetched and no cached set is
    /// still within its refresh interval.
    JwksUnavailable,
    /// The key set carries the `kid` but the key could not be used.
    InvalidKey,
    /// The signature does not verify under the named key.
    BadSignature,
    /// `exp` is in the past, beyond the skew.
    Expired,
    /// `nbf` or `iat` is in the future, beyond the skew.
    NotYetValid,
    /// `aud` does not name the entry's audience.
    WrongAud,
    /// `iss` does not name the entry's issuer.
    WrongIss,
    /// A claim the verifier needs is absent.
    MissingClaim(String),
    /// A bound claim does not hold; carries the claim name.
    BoundClaimMismatch(String),
    /// The `jti` was already accepted and has not expired.
    Replayed,
}

impl RefusalReason {
    /// The `reason` value written to the audit row.
    ///
    /// ```
    /// use lorica_api::automation::RefusalReason;
    /// assert_eq!(
    ///     RefusalReason::BoundClaimMismatch("project_path".into()).audit_reason(),
    ///     "bound_claim_mismatch:project_path"
    /// );
    /// assert_eq!(RefusalReason::WrongAlg.audit_reason(), "wrong_alg");
    /// ```
    pub fn audit_reason(&self) -> String {
        match self {
            Self::Malformed => "malformed".to_string(),
            Self::WrongAlg => "wrong_alg".to_string(),
            Self::NoIssuer => "no_issuer".to_string(),
            Self::UnknownKid => "unknown_kid".to_string(),
            Self::JwksUnavailable => "jwks_unavailable".to_string(),
            Self::InvalidKey => "invalid_key".to_string(),
            Self::BadSignature => "bad_signature".to_string(),
            Self::Expired => "expired".to_string(),
            Self::NotYetValid => "not_yet_valid".to_string(),
            Self::WrongAud => "wrong_aud".to_string(),
            Self::WrongIss => "wrong_iss".to_string(),
            Self::MissingClaim(claim) => format!("missing_claim:{claim}"),
            Self::BoundClaimMismatch(claim) => format!("bound_claim_mismatch:{claim}"),
            Self::Replayed => "replayed".to_string(),
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.audit_reason())
    }
}

/// The claims of an accepted token that the rest of the plane reads.
///
/// Every string here was signed by the issuer. `bound` carries the
/// five bindable claims as strings, booleans and numbers included,
/// because GitLab spells `ref_protected` as the string `"true"` and an
/// operator writes bound values as strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// The `iss` claim.
    pub issuer: String,
    /// The `sub` claim, when present.
    pub subject: Option<String>,
    /// The `jti` claim, the replay key.
    pub jti: String,
    /// The `exp` claim: how long the replay set remembers `jti`.
    pub expires_at: DateTime<Utc>,
    /// The `project_path` claim, which is the ownership principal.
    pub project_path: String,
    /// The `environment` claim: the environment NAME as GitLab spells
    /// it, not its slug.
    pub environment: Option<String>,
    /// The job identity recorded on an environment row.
    pub pipeline: PipelineIdentity,
    /// The bindable claims the token carries, stringified.
    pub bound: BTreeMap<String, String>,
}

/// An accepted ID token: the entry that accepted it and its claims.
#[derive(Debug, Clone)]
pub struct VerifiedIdToken {
    /// The issuer entry whose bound claims held. Its grant (scopes,
    /// hostnames, CIDRs, TTL ceiling) is the principal's grant.
    pub issuer: OidcIssuer,
    /// What the token said.
    pub claims: IdTokenClaims,
}

/// The verifier: one per process, holding the key cache and the
/// replay set. Issuer entries are NOT held here; the bearer gate reads
/// them from the store on every request, so removing one refuses the
/// very next token with no invalidation step to get wrong.
#[derive(Debug)]
pub struct OidcVerifier {
    jwks: JwksCache,
    replay: ReplaySet,
}

impl OidcVerifier {
    /// A verifier fetching key sets through `fetcher`.
    pub fn new(fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            jwks: JwksCache::new(fetcher),
            replay: ReplaySet::default(),
        }
    }

    /// A verifier with a replay set of `cap` entries, for tests that
    /// exercise the eviction.
    pub fn with_replay_cap(fetcher: Arc<dyn JwksFetcher>, cap: usize) -> Self {
        Self {
            jwks: JwksCache::new(fetcher),
            replay: ReplaySet::with_cap(cap),
        }
    }

    /// The production verifier, fetching over HTTPS on the node's
    /// trust roots.
    ///
    /// # Errors
    ///
    /// The `reqwest` build error, which is a broken TLS backend.
    pub fn with_http_fetcher() -> Result<Self, reqwest::Error> {
        Ok(Self::new(Arc::new(HttpJwksFetcher::new()?)))
    }

    /// The replay set, for tests and gauges.
    pub fn replay_set(&self) -> &ReplaySet {
        &self.replay
    }

    /// Verify `token` against `candidates`, the issuer entries whose
    /// audience the token named, at `now`.
    ///
    /// The entries are tried in order; the first whose issuer signed
    /// the token and whose bound claims all hold accepts it. The
    /// `jti` is then remembered until `exp`.
    ///
    /// # Errors
    ///
    /// The [`RefusalReason`] of the last entry tried, or of the check
    /// that failed before any entry was consulted.
    pub async fn verify(
        &self,
        token: &str,
        candidates: &[OidcIssuer],
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdToken, RefusalReason> {
        // The header is read for two things only: to refuse any
        // algorithm but the pinned one, and to know which key to look
        // up. Nothing in it is trusted beyond that, and it is read
        // BEFORE the key set is consulted so a forgery costs no fetch.
        let kid = pinned_header_kid(token)?;
        if candidates.is_empty() {
            return Err(RefusalReason::NoIssuer);
        }

        let mut last = RefusalReason::NoIssuer;
        for (issuer_url, jwks_url, entries) in group_by_key_source(candidates) {
            let key = match self.jwks.decoding_key(jwks_url, &kid, now).await {
                Ok(key) => key,
                Err(JwksLookupError::UnknownKid) => {
                    last = RefusalReason::UnknownKid;
                    continue;
                }
                Err(JwksLookupError::Unavailable) => {
                    last = RefusalReason::JwksUnavailable;
                    continue;
                }
            };

            // One signature verification per key source, shared by
            // every entry on it; the audience and the bound claims are
            // then judged per entry.
            let validation = validation_for_issuer(issuer_url);
            let decoded = match jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
                token,
                &key,
                &validation,
            ) {
                Ok(decoded) => decoded,
                Err(error) => {
                    last = reason_for(&error);
                    continue;
                }
            };
            let claims = match claims_from(&decoded.claims, now) {
                Ok(claims) => claims,
                Err(reason) => {
                    last = reason;
                    continue;
                }
            };
            let audiences = audiences_of(&decoded.claims);

            for entry in entries {
                if !audiences.iter().any(|aud| aud == &entry.audience) {
                    last = RefusalReason::WrongAud;
                    continue;
                }
                if let Err(claim) = entry.bound_claims_match(&claims.bound) {
                    last = RefusalReason::BoundClaimMismatch(claim);
                    continue;
                }
                // Only an accepted token consumes its `jti`: a mismatch
                // on one entry must not turn a later request on another
                // entry into a replay.
                let replay_key = format!("{}|{}", claims.issuer, claims.jti);
                if !self.replay.remember(&replay_key, claims.expires_at, now) {
                    return Err(RefusalReason::Replayed);
                }
                return Ok(VerifiedIdToken {
                    issuer: entry.clone(),
                    claims,
                });
            }
        }
        Err(last)
    }
}

/// The `kid` of a token whose header names the pinned algorithm.
///
/// Refuses `alg: none`, every HMAC and ECDSA algorithm, and every RSA
/// algorithm but RS256, by string comparison on the header before any
/// library code runs: the library's own algorithm list is the second
/// pin, not the first.
fn pinned_header_kid(token: &str) -> Result<String, RefusalReason> {
    let mut segments = token.split('.');
    let (Some(header), Some(_payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(RefusalReason::Malformed);
    };
    let header = decode_segment(header).ok_or(RefusalReason::Malformed)?;
    match header.get("alg").and_then(serde_json::Value::as_str) {
        Some(alg) if alg == PINNED_ALGORITHM_NAME => {}
        _ => return Err(RefusalReason::WrongAlg),
    }
    header
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .filter(|kid| !kid.is_empty())
        .map(str::to_string)
        .ok_or(RefusalReason::UnknownKid)
}

/// The candidate entries grouped by `(issuer, jwks_url)` in first-seen
/// order, so one key lookup and one signature check serve every entry
/// that shares a key source.
fn group_by_key_source(candidates: &[OidcIssuer]) -> Vec<(&str, &str, Vec<&OidcIssuer>)> {
    let mut groups: Vec<(&str, &str, Vec<&OidcIssuer>)> = Vec::new();
    for entry in candidates {
        match groups
            .iter_mut()
            .find(|(issuer, jwks, _)| *issuer == entry.issuer && *jwks == entry.jwks_url)
        {
            Some((_, _, members)) => members.push(entry),
            None => groups.push((&entry.issuer, &entry.jwks_url, vec![entry])),
        }
    }
    groups
}

/// The `aud` values of a verified payload, a string or a list.
fn audiences_of(claims: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    match claims.get("aud") {
        Some(serde_json::Value::String(one)) => vec![one.clone()],
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether a bearer value has the three-segment shape of a JWT: three
/// non-empty runs of base64url characters separated by dots.
///
/// A shape test, not a parse: the bearer gate uses it to pick the OIDC
/// path over the static-token path, and anything that passes it and
/// then fails to decode is refused as malformed on that path.
///
/// ```
/// use lorica_api::automation::oidc::looks_like_jwt;
/// assert!(looks_like_jwt("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"));
/// assert!(!looks_like_jwt("0123456789abcdef01234567.c2VjcmV0"));
/// assert!(!looks_like_jwt("a..b"));
/// ```
pub fn looks_like_jwt(value: &str) -> bool {
    let mut segments = 0usize;
    for segment in value.split('.') {
        segments += 1;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
    }
    segments == 3
}

/// The `aud` values a token names, read WITHOUT verification.
///
/// This is the only thing the bearer gate reads before verification,
/// and only to pick which issuer entries to try; a forged `aud` selects
/// entries whose keys then refuse the forgery. Returns an empty list
/// for anything that does not decode.
pub fn peek_audiences(token: &str) -> Vec<String> {
    let Some(payload) = token.split('.').nth(1) else {
        return Vec::new();
    };
    decode_segment(payload)
        .map(|claims| audiences_of(&claims))
        .unwrap_or_default()
}

/// The slug GitLab derives from an environment name
/// (`CI_ENVIRONMENT_SLUG`), so an environment created for a job bound
/// to `environment_protected = true` can be required to carry the
/// job's own environment.
///
/// Mirrors `Gitlab::Slug::Environment`: lowercase, every character
/// outside `a-z0-9` becomes `-`, a leading `env-` when the result does
/// not start with a letter, runs of `-` squeezed, and when the result
/// is longer than 24 characters OR differs from the name at all, the
/// first 17 characters plus `-` plus a six-character suffix derived
/// from the SHA-256 of the name; a trailing `-` is dropped last.
///
/// ```
/// use lorica_api::automation::oidc::gitlab_environment_slug;
/// assert_eq!(gitlab_environment_slug("production"), "production");
/// let review = gitlab_environment_slug("review/mr-42");
/// assert!(review.starts_with("review-mr-42-"));
/// assert_eq!(review.len(), 19);
/// ```
pub fn gitlab_environment_slug(name: &str) -> String {
    let mut slugified: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    if !slugified.starts_with(|c: char| c.is_ascii_lowercase()) {
        slugified = format!("env-{slugified}");
    }
    let mut squeezed = String::with_capacity(slugified.len());
    for c in slugified.chars() {
        if c == '-' && squeezed.ends_with('-') {
            continue;
        }
        squeezed.push(c);
    }
    let mut slug = if squeezed.len() > 24 || squeezed != name {
        let head: String = squeezed.chars().take(17).collect();
        format!("{head}-{}", gitlab_slug_suffix(name))
    } else {
        squeezed
    };
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

/// GitLab's slug suffix: the SHA-256 of the name as a big integer,
/// written in base 36, last six digits. The last six base-36 digits
/// are the integer modulo 36^6, computed byte by byte so no big-integer
/// arithmetic is needed.
fn gitlab_slug_suffix(name: &str) -> String {
    const BASE36: u64 = 36;
    const MODULUS: u64 = BASE36 * BASE36 * BASE36 * BASE36 * BASE36 * BASE36;
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let digest = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
    let mut remainder: u64 = 0;
    for byte in digest.as_ref() {
        remainder = (remainder * 256 + u64::from(*byte)) % MODULUS;
    }
    let mut out = [b'0'; 6];
    for slot in out.iter_mut().rev() {
        *slot = DIGITS[usize::try_from(remainder % BASE36).unwrap_or(0)];
        remainder /= BASE36;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode one base64url JWT segment into a JSON object.
fn decode_segment(segment: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    }
}

/// A claim as a string, whichever JSON scalar GitLab used for it.
fn scalar_claim(claims: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<String> {
    match claims.get(name)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A numeric date claim (`exp`, `nbf`, `iat`) as seconds since the
/// epoch. RFC 7519 allows a fraction; GitLab writes integers.
fn numeric_date(claims: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<i64> {
    match claims.get(name)? {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        _ => None,
    }
}

/// The [`RefusalReason`] a library error maps to.
fn reason_for(error: &jsonwebtoken::errors::Error) -> RefusalReason {
    match error.kind() {
        ErrorKind::InvalidSignature => RefusalReason::BadSignature,
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::MissingAlgorithm => RefusalReason::WrongAlg,
        ErrorKind::ExpiredSignature => RefusalReason::Expired,
        ErrorKind::ImmatureSignature => RefusalReason::NotYetValid,
        ErrorKind::InvalidAudience => RefusalReason::WrongAud,
        ErrorKind::InvalidIssuer => RefusalReason::WrongIss,
        ErrorKind::MissingRequiredClaim(claim) => RefusalReason::MissingClaim(claim.clone()),
        ErrorKind::InvalidRsaKey(_) | ErrorKind::InvalidKeyFormat => RefusalReason::InvalidKey,
        _ => RefusalReason::Malformed,
    }
}

/// The validation handed to the library for one key source: RS256
/// alone, `iss` pinned, `exp` and `nbf` checked with the skew.
///
/// `aud` is deliberately NOT checked here. Several entries can share a
/// key source with different audiences, and the audience is judged per
/// entry by the caller so one signature verification serves them all.
fn validation_for_issuer(issuer_url: &str) -> Validation {
    let mut validation = Validation::new(PINNED_ALGORITHM);
    validation.algorithms = vec![PINNED_ALGORITHM];
    validation.leeway = OIDC_CLOCK_SKEW_SECONDS;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.set_issuer(&[issuer_url]);
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation
}

/// The skew as a `chrono` delta.
fn skew() -> TimeDelta {
    TimeDelta::seconds(i64::try_from(OIDC_CLOCK_SKEW_SECONDS).unwrap_or(60))
}

/// Read the claims the plane keeps from a verified payload.
fn claims_from(
    claims: &serde_json::Map<String, serde_json::Value>,
    now: DateTime<Utc>,
) -> Result<IdTokenClaims, RefusalReason> {
    let issuer =
        scalar_claim(claims, "iss").ok_or_else(|| RefusalReason::MissingClaim("iss".into()))?;
    let jti =
        scalar_claim(claims, "jti").ok_or_else(|| RefusalReason::MissingClaim("jti".into()))?;
    let exp =
        numeric_date(claims, "exp").ok_or_else(|| RefusalReason::MissingClaim("exp".into()))?;
    let iat =
        numeric_date(claims, "iat").ok_or_else(|| RefusalReason::MissingClaim("iat".into()))?;
    // The library checks `exp` and `nbf`; `iat` is ours. A token
    // issued in the future is not one the issuer could have minted.
    if DateTime::from_timestamp(iat, 0).is_none_or(|issued| issued > now + skew()) {
        return Err(RefusalReason::NotYetValid);
    }
    let expires_at = DateTime::from_timestamp(exp, 0).ok_or(RefusalReason::Malformed)?;
    let project_path = scalar_claim(claims, "project_path")
        .ok_or_else(|| RefusalReason::MissingClaim("project_path".into()))?;
    let bound: BTreeMap<String, String> = OIDC_BOUND_CLAIM_NAMES
        .iter()
        .filter_map(|name| scalar_claim(claims, name).map(|value| ((*name).to_string(), value)))
        .collect();
    Ok(IdTokenClaims {
        issuer,
        subject: scalar_claim(claims, "sub"),
        jti,
        expires_at,
        project_path: project_path.clone(),
        environment: scalar_claim(claims, "environment"),
        pipeline: PipelineIdentity {
            project_path,
            git_ref: scalar_claim(claims, "ref"),
            pipeline_id: scalar_claim(claims, "pipeline_id"),
            job_id: scalar_claim(claims, "job_id"),
            user_login: scalar_claim(claims, "user_login"),
        },
        bound,
    })
}
