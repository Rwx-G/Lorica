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
//! `Authorization: Bearer <public_id>.<secret>` is the ONLY credential
//! this layer looks at. The cookie header is never read, so a browser
//! that happens to hold a dashboard session gains nothing by pointing
//! at this listener.
//!
//! # Order of work, and why
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
//! Every refusal answers `401` with the same body. Telling a caller
//! that their token is known but revoked confirms the id for them.

use axum::extract::FromRequestParts;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use lorica_config::models::{
    dummy_automation_secret_hmac_hex, parse_automation_token, verify_automation_secret,
    AutomationScope, AutomationToken, AUTOMATION_TOKEN_HMAC_KEY_LEN,
};

use crate::db::db_blocking;
use crate::error::ApiError;
use crate::server::AppState;

/// Realm advertised in the `WWW-Authenticate` challenge on a 401.
pub const AUTOMATION_REALM: &str = "lorica-automation";

/// The single message every authentication refusal carries.
///
/// Missing, malformed, unknown, wrong, revoked and expired all read
/// alike on the wire. An automation that cannot reach the plane has to
/// look at the audit log, which an operator can read and an attacker
/// cannot.
const UNAUTHORIZED_MESSAGE: &str = "a valid automation bearer token is required";

/// The authenticated automation behind a request, installed in the
/// request extensions by [`require_automation_auth`].
///
/// It carries the whole token row rather than a reduced view: the
/// scope gate needs the scopes, and the handlers Story 10.4 adds need
/// `allowed_hostnames`, `allowed_backend_cidrs` and `max_ttl_seconds`
/// on the same request.
#[derive(Debug, Clone)]
pub struct AutomationPrincipal {
    /// The verified token row, read at the start of this request.
    pub token: AutomationToken,
}

impl AutomationPrincipal {
    /// The token's lookup half, which is what an operator revokes.
    pub fn public_id(&self) -> &str {
        &self.token.public_id
    }

    /// The operator-facing label of the token.
    pub fn name(&self) -> &str {
        &self.token.name
    }

    /// Whether this principal carries `scope`.
    pub fn has_scope(&self, scope: AutomationScope) -> bool {
        self.token.has_scope(scope)
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

/// Axum middleware authenticating the bearer token and installing the
/// [`AutomationPrincipal`] extension.
///
/// Answers `401` with `WWW-Authenticate: Bearer realm="lorica-automation"`
/// on every refusal.
pub async fn require_automation_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(presented) = bearer_value(&req) else {
        return unauthorized();
    };

    let token = match authenticate(&state, &presented, Utc::now()).await {
        Ok(token) => token,
        Err(()) => return unauthorized(),
    };

    // The audit layer wraps this one, so it cannot see the request
    // extensions any more once the response comes back. The slot it
    // installed on the way down is how the principal reaches it.
    if let Some(slot) = req
        .extensions()
        .get::<super::audit::PrincipalSlot>()
        .cloned()
    {
        slot.fill(&token);
    }
    req.extensions_mut().insert(AutomationPrincipal { token });
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

/// Verify `presented` against the store at `now`.
///
/// `Err(())` is the whole error surface on purpose: the caller has one
/// answer to give and must not be able to accidentally spell which of
/// the refusals happened into the response.
async fn authenticate(
    state: &AppState,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<AutomationToken, ()> {
    // Step 1: the shape guard, before anything touches the store.
    let parsed = parse_automation_token(presented).map_err(|_| ())?;

    // Steps 2 and 3 share one store visit so the lookup and the key
    // read do not queue for the mutex twice.
    let public_id = parsed.public_id.clone();
    let looked_up: Result<
        ([u8; AUTOMATION_TOKEN_HMAC_KEY_LEN], Option<AutomationToken>),
        ApiError,
    > = db_blocking(&state.store, move |store| {
        let key = store.automation_token_hmac_key()?;
        let token = store.get_automation_token(&public_id)?;
        Ok::<_, lorica_config::ConfigError>((key, token))
    })
    .await;
    let (hmac_key, found) = looked_up.map_err(|e| {
        tracing::error!(error = %e, "automation token lookup failed");
    })?;

    let stored_hmac: String = found
        .as_ref()
        .map(|token| token.secret_hmac.clone())
        .unwrap_or_else(dummy_automation_secret_hmac_hex);
    let secret_ok: bool = verify_automation_secret(&hmac_key, &parsed.secret, &stored_hmac);

    // `secret_ok` is computed before this branch and for both paths, so
    // an unknown id runs exactly the work a known one does.
    let (Some(token), true) = (found, secret_ok) else {
        return Err(());
    };

    // Step 4: liveness at the caller's single notion of now.
    if !token.is_live(now) {
        return Err(());
    }

    // Best effort: a token that was just accepted is a token in use,
    // and failing the request because the stamp did not land would
    // trade a working automation for a reporting field.
    let public_id = token.public_id.clone();
    if let Err(e) = db_blocking(&state.store, move |store| {
        store.touch_automation_token_last_used(&public_id, now)
    })
    .await
    {
        tracing::warn!(error = %e, "automation token last_used stamp failed");
    }

    Ok(token)
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
}
