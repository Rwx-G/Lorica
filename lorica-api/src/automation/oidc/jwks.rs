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

//! The JWKS cache (Story 10.5 AC #2 and #5): the issuer's signing keys,
//! fetched over HTTPS, refreshed every six hours, and refetched on an
//! unknown `kid` at most once a minute.
//!
//! # An unknown `kid` is an outbound-fetch primitive
//!
//! Without a limit, a caller sending tokens with random `kid` values
//! drives one fetch each, from Lorica to the issuer, at request rate.
//! The refetch is capped at once per minute per JWKS URL regardless of
//! how many unknown kids arrive; the cap is on ATTEMPTS, so a failing
//! issuer is also asked once a minute and not once per request.
//!
//! # Failure is closed, after a grace
//!
//! A fetch failure keeps the cached keys until their refresh interval
//! elapses. A key that verified a minute ago still verifies; what a
//! dead JWKS endpoint must not do is take every pipeline down with it
//! for six hours. Once the interval has elapsed with no successful
//! fetch, there is no key the node can vouch for, and verification
//! fails closed until the endpoint answers again.
//!
//! # The fetch itself
//!
//! The client is the same shape the ACME and forward-auth clients use:
//! `reqwest` on the node's trust roots, `https` only, a connect and a
//! total timeout, and a redirect policy that follows a redirect ONLY
//! to the same scheme, host and port. A compromised or mistyped issuer
//! cannot therefore turn the control plane into a probe of its own
//! network, and the body is capped so a hostile issuer cannot make it
//! allocate without bound.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::DecodingKey;
use tokio::sync::Mutex;

/// How long a fetched key set is trusted before it is refetched.
pub const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Least time between two fetch attempts on one JWKS URL, whatever
/// triggers them.
pub const JWKS_REFETCH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Most bytes accepted in one JWKS document. A GitLab key set is a
/// few kilobytes; the cap is a hundred times that.
pub const JWKS_MAX_BODY_BYTES: usize = 256 * 1024;

/// Connect timeout of a JWKS fetch.
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total timeout of a JWKS fetch, headers and body included.
const JWKS_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Most redirects followed on one fetch, all on the original host.
const JWKS_MAX_REDIRECTS: usize = 3;

/// Where a key set comes from. The trait exists so the cache can be
/// tested against a counting mock without a socket; production uses
/// [`HttpJwksFetcher`].
#[async_trait]
pub trait JwksFetcher: Send + Sync {
    /// Fetch and parse the key set at `url`.
    ///
    /// # Errors
    ///
    /// A one-line reason suitable for a WARN log. The cache never
    /// shows it to a caller.
    async fn fetch(&self, url: &str) -> Result<JwkSet, String>;
}

/// The production fetcher: `reqwest` over the node's trust roots.
#[derive(Debug, Clone)]
pub struct HttpJwksFetcher {
    client: reqwest::Client,
}

impl HttpJwksFetcher {
    /// Build the client. Fails only when `reqwest` cannot initialise
    /// its TLS backend, which is a broken build rather than a runtime
    /// condition.
    ///
    /// # Errors
    ///
    /// The `reqwest` build error.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::custom(same_origin_redirects))
            .connect_timeout(JWKS_CONNECT_TIMEOUT)
            .timeout(JWKS_TOTAL_TIMEOUT)
            .build()?;
        Ok(Self { client })
    }
}

/// Follow a redirect only when it stays on the scheme, host and port
/// the fetch started on, and only [`JWKS_MAX_REDIRECTS`] times.
///
/// A JWKS URL is operator-supplied and `https`, but the response is
/// the issuer's, and an issuer that answers with a redirect to
/// `http://10.0.0.1/` must not have the control plane follow it.
fn same_origin_redirects(attempt: reqwest::redirect::Attempt) -> reqwest::redirect::Action {
    let Some(origin) = attempt.previous().first() else {
        return attempt.error("redirect with no origin");
    };
    if attempt.previous().len() > JWKS_MAX_REDIRECTS {
        return attempt.error("too many redirects");
    }
    let next = attempt.url();
    let same_origin = next.scheme() == origin.scheme()
        && next.host_str() == origin.host_str()
        && next.port_or_known_default() == origin.port_or_known_default();
    if same_origin {
        attempt.follow()
    } else {
        attempt.error("redirect to another origin refused")
    }
}

#[async_trait]
impl JwksFetcher for HttpJwksFetcher {
    async fn fetch(&self, url: &str) -> Result<JwkSet, String> {
        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("issuer answered an error status: {e}"))?;
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("body read failed: {e}"))?
        {
            if body.len() + chunk.len() > JWKS_MAX_BODY_BYTES {
                return Err(format!("JWKS body exceeds {JWKS_MAX_BODY_BYTES} bytes"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| format!("JWKS is not a valid key set: {e}"))
    }
}

/// One fetched key set, with the two timestamps the refresh rules
/// read. `last_attempt` moves on every fetch, successful or not;
/// `fetched_at` only on success.
#[derive(Debug, Clone)]
struct CachedKeys {
    keys: HashMap<String, Arc<DecodingKey>>,
    fetched_at: DateTime<Utc>,
    last_attempt: DateTime<Utc>,
}

impl CachedKeys {
    fn is_fresh(&self, now: DateTime<Utc>) -> bool {
        now < self.fetched_at + to_delta(JWKS_REFRESH_INTERVAL)
    }

    fn may_attempt(&self, now: DateTime<Utc>) -> bool {
        now >= self.last_attempt + to_delta(JWKS_REFETCH_MIN_INTERVAL)
    }
}

/// Why a key could not be produced for a `kid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksLookupError {
    /// The key set is current and does not carry this `kid`, or a
    /// refetch is throttled and the cached set does not carry it.
    UnknownKid,
    /// No current key set: the cache is empty or past its refresh
    /// interval, and the issuer could not be fetched.
    Unavailable,
}

/// The per-URL key cache. One instance per process, shared by every
/// verification; the lock is held across a fetch on purpose, so a burst
/// of requests on one issuer produces one fetch and not a herd.
#[derive(Debug)]
pub struct JwksCache {
    fetcher: Arc<dyn JwksFetcher>,
    entries: Mutex<HashMap<String, CachedKeys>>,
}

impl std::fmt::Debug for dyn JwksFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JwksFetcher")
    }
}

impl JwksCache {
    /// A cache backed by `fetcher`.
    pub fn new(fetcher: Arc<dyn JwksFetcher>) -> Self {
        Self {
            fetcher,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The RSA verification key `kid` names in the key set at
    /// `jwks_url`, as of `now`.
    ///
    /// Fetches when the cache has no current set for the URL or when
    /// the `kid` is unknown, subject to [`JWKS_REFETCH_MIN_INTERVAL`]
    /// between attempts.
    ///
    /// # Errors
    ///
    /// [`JwksLookupError::UnknownKid`] when a current set lacks the
    /// key, [`JwksLookupError::Unavailable`] when there is no current
    /// set at all.
    pub async fn decoding_key(
        &self,
        jwks_url: &str,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<DecodingKey>, JwksLookupError> {
        let mut entries = self.entries.lock().await;
        if let Some(cached) = entries.get(jwks_url) {
            if cached.is_fresh(now) {
                if let Some(key) = cached.keys.get(kid) {
                    return Ok(Arc::clone(key));
                }
            }
        }

        let may_attempt = entries
            .get(jwks_url)
            .is_none_or(|cached| cached.may_attempt(now));
        if may_attempt {
            match self.fetcher.fetch(jwks_url).await {
                Ok(set) => {
                    crate::metrics::inc_automation_oidc_jwks_fetch("ok");
                    entries.insert(
                        jwks_url.to_string(),
                        CachedKeys {
                            keys: rsa_keys_by_kid(&set),
                            fetched_at: now,
                            last_attempt: now,
                        },
                    );
                }
                Err(reason) => {
                    crate::metrics::inc_automation_oidc_jwks_fetch("error");
                    tracing::warn!(
                        jwks_url = %jwks_url,
                        reason = %reason,
                        "OIDC JWKS fetch failed; cached keys stay in use until their refresh \
                         interval elapses"
                    );
                    match entries.get_mut(jwks_url) {
                        Some(cached) => cached.last_attempt = now,
                        None => {
                            // An entry that is already stale, so the
                            // next lookup fails closed instead of
                            // trusting nothing as if it were fresh,
                            // and that carries the attempt stamp so
                            // the issuer is not asked again for a
                            // minute.
                            entries.insert(
                                jwks_url.to_string(),
                                CachedKeys {
                                    keys: HashMap::new(),
                                    fetched_at: now - to_delta(JWKS_REFRESH_INTERVAL),
                                    last_attempt: now,
                                },
                            );
                        }
                    }
                }
            }
        }

        match entries.get(jwks_url) {
            Some(cached) if cached.is_fresh(now) => cached
                .keys
                .get(kid)
                .map(Arc::clone)
                .ok_or(JwksLookupError::UnknownKid),
            _ => Err(JwksLookupError::Unavailable),
        }
    }
}

/// The RSA keys of a set, by `kid`. Keys of another family, and keys
/// without a `kid`, are left out: the verifier pins RS256, so nothing
/// else could ever verify a token, and a key nothing can name could
/// never be looked up.
fn rsa_keys_by_kid(set: &JwkSet) -> HashMap<String, Arc<DecodingKey>> {
    set.keys
        .iter()
        .filter_map(|jwk| {
            let kid = jwk.common.key_id.clone()?;
            let AlgorithmParameters::RSA(params) = &jwk.algorithm else {
                return None;
            };
            let key = DecodingKey::from_rsa_components(&params.n, &params.e).ok()?;
            Some((kid, Arc::new(key)))
        })
        .collect()
}

/// A `std::time::Duration` as the `chrono` delta the timestamps use.
fn to_delta(duration: Duration) -> TimeDelta {
    TimeDelta::from_std(duration).unwrap_or(TimeDelta::MAX)
}
