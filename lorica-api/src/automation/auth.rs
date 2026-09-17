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

//! Bearer authentication for the automation plane.
//!
//! `Authorization: Bearer <value>` is the ONLY credential this layer
//! looks at. The cookie header is never read, so a browser that happens
//! to hold a dashboard session gains nothing by pointing at this
//! listener.
//!
//! # Two credentials, picked by shape
//!
//! The value is either a static token, `<public_id>.<secret>`
//! (Story 10.3), or a GitLab ID token, a three-segment JWT
//! (Story 10.5). The mode is chosen by the SHAPE of the value and by
//! nothing the caller can state separately: a value with a minted
//! token's shape takes the static path, a value with a JWT's shape
//! takes the OIDC path, and anything else is refused without touching
//! the store. The two shapes cannot collide, because a static token's
//! secret half is base64url with no dot in it and a JWT has exactly
//! two.
//!
//! # The static path, in order
//!
//! 1. [`lorica_config::models::parse_automation_token`] rejects
//!    anything without a minted token's shape. A mistyped token
//!    therefore costs no store access at all, which keeps an
//!    unauthenticated caller from using this endpoint as a way to
//!    queue behind the store mutex.
//! 2. One indexed lookup by `public_id`.
//! 3. One constant-time HMAC verification. When the lookup found
//!    nothing, the verification still runs, against
//!    [`lorica_config::models::dummy_automation_secret_hmac_hex`], so
//!    an unknown id and a known id with a wrong secret cost the same
//!    work and answer in the same time. This is the property the
//!    cluster join-token path already has, and it has to hold on any
//!    surface where an attacker can enumerate identifiers.
//! 4. [`lorica_config::models::AutomationToken::is_live`] at the
//!    caller's single "now". Nothing is cached, so a revoke or an
//!    expiry takes effect on the very next request with no
//!    invalidation step to get wrong.
//!
//! # What an unauthenticated caller may cost before any store access
//!
//! Both paths refuse a bearer longer than
//! [`AUTOMATION_BEARER_MAX_BYTES`] before looking at its shape, and
//! the OIDC path refuses a token naming more than
//! [`OIDC_MAX_AUDIENCES`] audiences before its first store read. The
//! audience list is attacker-chosen and each entry used to be one
//! indexed read inside the single `db_blocking` closure that holds
//! the store mutex, plus one audit row per attempt, so an unsigned
//! JWT carrying a thousand audiences was a thousand reads under the
//! lock every node's control plane shares.
//!
//! # The OIDC path, in order
//!
//! 1. The token's `aud` is read WITHOUT verification, only to select
//!    the issuer entries to try; a forged `aud` selects entries whose
//!    keys then refuse the forgery.
//! 2. One store read: the entries registered for that audience. Read
//!    per request and never cached, for the same reason the static
//!    path caches nothing: removing an entry refuses the very next
//!    token.
//! 3. [`super::oidc::OidcVerifier::verify`], which pins the algorithm,
//!    checks the signature and the standard claims, judges the bound
//!    claims per entry and consumes the `jti`.
//!
//! # Every refusal answers the same 401
//!
//! Missing, malformed, unknown, wrong, revoked, expired, unsigned,
//! mis-signed and replayed all read alike on the wire, and the body
//! does not say which mode was tried. Telling a caller that their
//! token is known but revoked confirms the id; telling them that their
//! JWT reached the verifier confirms that an audience is registered.
//! The precise reason is written to the audit row, which an operator
//! can read and an attacker cannot.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use axum::extract::FromRequestParts;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use lorica_config::models::{
    dummy_automation_secret_hmac_hex, parse_automation_token, verify_automation_secret,
    AutomationScope, AutomationToken, EnvironmentOwner, OidcIssuer, OwnerKind, PipelineIdentity,
    AUTOMATION_TOKEN_HMAC_KEY_LEN,
};

use super::oidc::{gitlab_environment_slug, looks_like_jwt, peek_audiences, VerifiedIdToken};
use crate::db::db_blocking;
use crate::error::ApiError;
use crate::server::AppState;

/// Realm advertised in the `WWW-Authenticate` challenge on a 401.
pub const AUTOMATION_REALM: &str = "lorica-automation";

/// The single message every authentication refusal carries.
///
/// Missing, malformed, unknown, wrong, revoked and expired all read
/// alike on the wire, on both credential paths. An automation that
/// cannot reach the plane has to look at the audit log, which an
/// operator can read and an attacker cannot.
const UNAUTHORIZED_MESSAGE: &str = "a valid automation bearer credential is required";

/// Most bytes accepted in a bearer value, before its shape is even
/// looked at.
///
/// A minted static token is under a hundred bytes and a GitLab ID
/// token a couple of kilobytes; eight kibibytes is room for an issuer
/// with an unusually long claim set and a hard stop well below what a
/// caller could otherwise hand the base64 decoder and the JSON parser
/// on an unauthenticated endpoint.
pub const AUTOMATION_BEARER_MAX_BYTES: usize = 8 * 1024;

/// Most `aud` entries an ID token may name.
///
/// The audience list decides how many issuer-entry lookups one
/// unauthenticated request costs, and the caller writes it. A job
/// names exactly one audience; eight is room for a migration between
/// two Lorica instances and a ceiling on the fan-out.
pub const OIDC_MAX_AUDIENCES: usize = 8;

/// Least time between two `last_used_at` writes for one credential.
///
/// The stamp is a reporting field an operator reads to retire a token
/// nobody presents, and it was costing one SQLite write on the single
/// store mutex per authenticated request. A minute of resolution
/// answers the question it exists for.
pub const AUTOMATION_LAST_USED_WRITE_INTERVAL: Duration = Duration::from_secs(60);

/// Most credentials the stamp throttle remembers at once.
///
/// Bounded for the same reason the replay set is: the entries are
/// keyed by a value a caller supplies, so an attacker presenting many
/// distinct public ids must not be able to grow a process-local map
/// without limit. A key is a 24-character id beside an `Instant`, so
/// the cap holds the map near a megabyte.
const LAST_USED_THROTTLE_CAP: usize = 10_000;

/// When each `public_id` last had its `last_used_at` written.
///
/// Process-local and deliberately not replicated: the stamp is a
/// local reporting field, and a node that restarts simply writes one
/// stamp per credential again.
static LAST_USED_STAMPS: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether `public_id` is due a `last_used_at` write at `now`.
///
/// Entries older than the interval are dropped before the cap is
/// measured, the way the replay set purges before it evicts: an entry
/// past its interval suppresses nothing, so keeping it costs memory
/// and buys nothing. A map full of live entries answers `true` without
/// remembering the id, which is the un-throttled behaviour for that
/// credential until the pressure passes and never unbounded memory.
fn last_used_write_due(public_id: &str, now: Instant) -> bool {
    let mut stamps = LAST_USED_STAMPS.lock();
    if stamps
        .get(public_id)
        .is_some_and(|previous| now.duration_since(*previous) < AUTOMATION_LAST_USED_WRITE_INTERVAL)
    {
        return false;
    }
    stamps.retain(|_, stamp| now.duration_since(*stamp) < AUTOMATION_LAST_USED_WRITE_INTERVAL);
    if stamps.len() >= LAST_USED_THROTTLE_CAP {
        return true;
    }
    stamps.insert(public_id.to_string(), now);
    true
}

/// The authenticated automation behind a request, installed in the
/// request extensions by [`require_automation_auth`].
///
/// One shape for both credentials, so the scope gate and the
/// environment handlers never ask which kind of caller they are looking
/// at: the grant fields carry what the static token row or the issuer
/// entry said, and the ownership fields carry the token name or the
/// project path. What differs is what the audit row names and what an
/// environment row records about the job.
#[derive(Debug, Clone)]
pub struct AutomationPrincipal {
    /// Which authority stands behind the request, and therefore which
    /// ownership namespace the principal lives in.
    pub kind: OwnerKind,
    /// The ownership principal: the token's name, or the project path.
    pub principal: String,
    /// The id an operator withdraws: the token's `public_id`, or the
    /// issuer entry's id.
    pub grant_id: String,
    /// What the credential may do.
    pub scopes: Vec<AutomationScope>,
    /// Hostname patterns the credential may claim.
    pub allowed_hostnames: Vec<String>,
    /// CIDRs the credential may point a hostname at.
    pub allowed_backend_cidrs: Vec<String>,
    /// Ceiling on the lifetime any environment this credential creates
    /// may request, in seconds.
    pub max_ttl_seconds: u32,
    /// The CI job behind an ID token; `None` for a static token.
    pub pipeline: Option<PipelineIdentity>,
    /// When the issuer entry binds `environment_protected = true`: the
    /// GitLab slug of the job's `environment` claim, which every
    /// environment this principal writes must be named after (AC #3).
    /// An empty string means the entry binds it but the token carries
    /// no `environment` claim, which no name can satisfy.
    pub required_environment_slug: Option<String>,
}

impl AutomationPrincipal {
    /// The principal a verified static token row yields.
    pub fn from_static_token(token: AutomationToken) -> Self {
        Self {
            kind: OwnerKind::StaticToken,
            principal: token.name,
            grant_id: token.public_id,
            scopes: token.scopes,
            allowed_hostnames: token.allowed_hostnames,
            allowed_backend_cidrs: token.allowed_backend_cidrs,
            max_ttl_seconds: token.max_ttl_seconds,
            pipeline: None,
            required_environment_slug: None,
        }
    }

    /// The principal a verified ID token yields: the accepting entry's
    /// grant, and the token's claims as the identity.
    pub fn from_id_token(verified: VerifiedIdToken) -> Self {
        let VerifiedIdToken { issuer, claims } = verified;
        let required_environment_slug = issuer.binds_protected_environment().then(|| {
            claims
                .environment
                .as_deref()
                .map(gitlab_environment_slug)
                .unwrap_or_default()
        });
        Self {
            kind: OwnerKind::OidcProject,
            principal: claims.project_path,
            grant_id: issuer.id,
            scopes: issuer.scopes,
            allowed_hostnames: issuer.allowed_hostnames,
            allowed_backend_cidrs: issuer.allowed_backend_cidrs,
            max_ttl_seconds: issuer.max_ttl_seconds,
            pipeline: Some(claims.pipeline),
            required_environment_slug,
        }
    }

    /// The operator-facing label: the token name, or the project path.
    pub fn name(&self) -> &str {
        &self.principal
    }

    /// The id an operator withdraws: the token's `public_id`, or the
    /// issuer entry's id.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// The principal as the owner an environment row records.
    pub fn as_owner(&self) -> EnvironmentOwner {
        EnvironmentOwner {
            kind: self.kind,
            principal: self.principal.clone(),
        }
    }

    /// The one string the audit rows name this principal by: the label
    /// and the id an operator revokes, in one column, because the audit
    /// row has one principal field and an automation principal has two
    /// identities. An ID token is marked `oidc:` so the id reads as an
    /// issuer entry and not as a token.
    pub fn audit_identity(&self) -> String {
        match self.kind {
            OwnerKind::StaticToken => format!("{} ({})", self.principal, self.grant_id),
            OwnerKind::OidcProject => format!("{} (oidc:{})", self.principal, self.grant_id),
        }
    }

    /// Whether this principal carries `scope`.
    pub fn has_scope(&self, scope: AutomationScope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Whether any of the principal's patterns covers `hostname`, under
    /// the one-label wildcard rule both credentials share.
    pub fn allows_hostname(&self, hostname: &str) -> bool {
        self.allowed_hostnames
            .iter()
            .any(|pattern| lorica_config::models::matches_one_label(pattern, hostname))
    }
}

impl<S> FromRequestParts<S> for AutomationPrincipal
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Fails closed. The extension is installed by
        // `require_automation_auth`, which every automation route runs
        // behind; a handler mounted outside that layer must break
        // loudly rather than serve an unauthenticated caller.
        parts
            .extensions
            .get::<AutomationPrincipal>()
            .cloned()
            .ok_or_else(|| {
                ApiError::Internal(
                    "automation principal missing: route mounted outside the bearer gate".into(),
                )
            })
    }
}

/// Axum middleware authenticating the bearer credential and installing
/// the [`AutomationPrincipal`] extension.
///
/// Answers `401` with `WWW-Authenticate: Bearer realm="lorica-automation"`
/// on every refusal, and tells the audit layer the precise reason
/// through the slot it installed on the way down.
pub async fn require_automation_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let slot = req
        .extensions()
        .get::<super::audit::PrincipalSlot>()
        .cloned();

    let Some(presented) = bearer_value(&req) else {
        if let Some(slot) = &slot {
            slot.refuse("no_bearer");
        }
        return unauthorized();
    };

    let principal = match authenticate(&state, &presented, Utc::now()).await {
        Ok(principal) => principal,
        Err(reason) => {
            if let Some(slot) = &slot {
                slot.refuse(&reason);
            }
            return unauthorized();
        }
    };

    // The audit layer wraps this one, so it cannot see the request
    // extensions any more once the response comes back. The slot it
    // installed on the way down is how the principal reaches it.
    if let Some(slot) = &slot {
        slot.accept(&principal);
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// The `Authorization: Bearer <value>` payload, or `None` when the
/// header is absent, unparseable, or carries another scheme.
///
/// The scheme match is case-insensitive per RFC 7235; the token itself
/// is not touched here.
fn bearer_value(req: &Request) -> Option<String> {
    let raw = req
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Verify `presented` against the store at `now`, on whichever path
/// its shape selects.
///
/// `Err` carries the audit reason and nothing else: the caller has one
/// answer to give on the wire and must not be able to accidentally
/// spell the reason into it.
async fn authenticate(
    state: &AppState,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<AutomationPrincipal, String> {
    // Before the shape test, so nothing downstream ever decodes or
    // parses an attacker-sized value.
    if presented.len() > AUTOMATION_BEARER_MAX_BYTES {
        return Err("bearer_too_long".to_string());
    }
    if let Ok(parsed) = parse_automation_token(presented) {
        return authenticate_static_token(state, parsed.public_id, parsed.secret, now).await;
    }
    if looks_like_jwt(presented) {
        return authenticate_id_token(state, presented, now).await;
    }
    Err("not_a_credential".to_string())
}

/// The static-token path: lookup, constant-time verification,
/// liveness, `last_used_at`.
async fn authenticate_static_token(
    state: &AppState,
    public_id: String,
    secret: [u8; lorica_config::models::AUTOMATION_TOKEN_SECRET_LEN],
    now: DateTime<Utc>,
) -> Result<AutomationPrincipal, String> {
    // The lookup and the key read share one store visit so they do not
    // queue for the mutex twice.
    let lookup_id = public_id.clone();
    let looked_up: Result<
        ([u8; AUTOMATION_TOKEN_HMAC_KEY_LEN], Option<AutomationToken>),
        ApiError,
    > = db_blocking(&state.store, move |store| {
        let key = store.automation_token_hmac_key()?;
        let token = store.get_automation_token(&lookup_id)?;
        Ok::<_, lorica_config::ConfigError>((key, token))
    })
    .await;
    let (hmac_key, found) = looked_up.map_err(|e| {
        tracing::error!(error = %e, "automation token lookup failed");
        "store_error".to_string()
    })?;

    let stored_hmac: String = found
        .as_ref()
        .map(|token| token.secret_hmac.clone())
        .unwrap_or_else(dummy_automation_secret_hmac_hex);
    let secret_ok: bool = verify_automation_secret(&hmac_key, &secret, &stored_hmac);

    // `secret_ok` is computed before this branch and for both paths, so
    // an unknown id runs exactly the work a known one does. The reason
    // below is written after that work, to the audit row only.
    let (Some(token), true) = (found, secret_ok) else {
        return Err("token_unknown_or_wrong_secret".to_string());
    };

    if token.revoked_at.is_some() {
        return Err("token_revoked".to_string());
    }
    if !token.is_live(now) {
        return Err("token_expired".to_string());
    }

    // Best effort, and at most once per
    // [`AUTOMATION_LAST_USED_WRITE_INTERVAL`] per credential: a token
    // that was just accepted is a token in use, and failing the
    // request because the stamp did not land would trade a working
    // automation for a reporting field.
    if last_used_write_due(&public_id, Instant::now()) {
        if let Err(e) = db_blocking(&state.store, move |store| {
            store.touch_automation_token_last_used(&public_id, now)
        })
        .await
        {
            tracing::warn!(error = %e, "automation token last_used stamp failed");
        }
    }

    Ok(AutomationPrincipal::from_static_token(token))
}

/// The OIDC path: the audience peek, the per-request store read of the
/// matching issuer entries, and the verifier.
async fn authenticate_id_token(
    state: &AppState,
    token: &str,
    now: DateTime<Utc>,
) -> Result<AutomationPrincipal, String> {
    let audiences = peek_audiences(token);
    if audiences.is_empty() {
        return Err("malformed".to_string());
    }
    // Before the store read below, which is one indexed lookup per
    // audience inside one closure holding the store mutex, and one
    // audit row per attempt. The list is unverified and the caller
    // writes it.
    if audiences.len() > OIDC_MAX_AUDIENCES {
        return Err("too_many_audiences".to_string());
    }

    // Read from the store on every request, never cached: an entry an
    // operator removes must refuse the very next token, and a cache
    // would be one more thing to invalidate on that path.
    let candidates: Vec<OidcIssuer> = db_blocking(&state.store, move |store| {
        let mut entries = Vec::new();
        for audience in &audiences {
            entries.extend(store.list_oidc_issuers_for_audience(audience)?);
        }
        Ok::<_, lorica_config::ConfigError>(entries)
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "oidc issuer lookup failed");
        "store_error".to_string()
    })?;

    state
        .oidc
        .verify(token, &candidates, now)
        .await
        .map(AutomationPrincipal::from_id_token)
        .map_err(|reason| reason.audit_reason())
}

/// The `401` every refusal answers, challenge header included.
fn unauthorized() -> Response {
    let mut response = ApiError::Unauthorized(UNAUTHORIZED_MESSAGE.to_string()).into_response();
    debug_assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    if let Ok(value) = HeaderValue::from_str(&format!("Bearer realm=\"{AUTOMATION_REALM}\"")) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(header_value: Option<&str>) -> Request {
        let mut builder = Request::builder();
        if let Some(value) = header_value {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder
            .body(axum::body::Body::empty())
            .expect("test request")
    }

    #[test]
    fn only_a_bearer_header_is_read() {
        assert_eq!(bearer_value(&req_with(None)), None);
        assert_eq!(bearer_value(&req_with(Some("Basic abc"))), None);
        assert_eq!(bearer_value(&req_with(Some("Bearer "))), None);
        assert_eq!(
            bearer_value(&req_with(Some("Bearer abc.def"))).as_deref(),
            Some("abc.def")
        );
        // RFC 7235 makes the scheme case-insensitive; a client that
        // spells it `bearer` is not malformed.
        assert_eq!(
            bearer_value(&req_with(Some("bearer abc.def"))).as_deref(),
            Some("abc.def")
        );
    }

    #[test]
    fn the_challenge_names_the_automation_realm() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer realm=\"lorica-automation\"")
        );
    }

    #[test]
    fn a_static_token_and_an_id_token_yield_one_principal_shape() {
        let now = Utc::now();
        let token = AutomationToken {
            public_id: "0123456789abcdef01234567".to_string(),
            name: "acme-ci".to_string(),
            secret_hmac: dummy_automation_secret_hmac_hex(),
            scopes: vec![AutomationScope::EnvironmentsRead],
            allowed_hostnames: vec!["*.review.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 600,
            created_by: "admin".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
            last_used_at: None,
            revoked_at: None,
        };
        let principal = AutomationPrincipal::from_static_token(token);
        assert_eq!(principal.kind, OwnerKind::StaticToken);
        assert_eq!(principal.name(), "acme-ci");
        assert_eq!(principal.grant_id(), "0123456789abcdef01234567");
        assert_eq!(
            principal.audit_identity(),
            "acme-ci (0123456789abcdef01234567)"
        );
        assert!(principal.allows_hostname("mr-1.review.example.com"));
        assert!(principal.pipeline.is_none());
        assert!(principal.required_environment_slug.is_none());
    }
}
