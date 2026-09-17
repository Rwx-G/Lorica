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
//!
//! # What "the node's trust roots" means
//!
//! `lorica-api` builds `reqwest` with both `rustls-tls-webpki-roots`
//! and `rustls-tls-native-roots`, so the default client anchors on
//! webpki's public bundle AND on the platform store, which is where a
//! distribution's CA bundle and `SSL_CERT_FILE` land. With webpki
//! alone, a self-hosted GitLab under a corporate PKI answered every ID
//! token with `jwks_unavailable` no matter how the host was set up.
//!
//! An entry may go further and pin its own CA
//! ([`lorica_config::models::OidcIssuer::ca_pem`]). That CA then
//! REPLACES the node's trust for that entry's fetch: an operator who
//! names an authority means that authority, and leaving the public
//! roots alongside it would let any commercial CA still vouch for the
//! issuer. Each pinned entry gets its own client, built once and kept
//! by entry id beside the key cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::DecodingKey;
use tokio::sync::Mutex;

use lorica_config::models::OidcIssuer;

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
    /// Fetch and parse the key set at `url`, on whatever trust the
    /// fetcher holds by default.
    ///
    /// # Errors
    ///
    /// A one-line reason suitable for a WARN log. The cache never
    /// shows it to a caller.
    async fn fetch(&self, url: &str) -> Result<JwkSet, String>;

    /// Fetch and parse the key set `entry` names, honouring the CA the
    /// entry pins when it pins one.
    ///
    /// The default implementation ignores the entry's trust material
    /// and calls [`JwksFetcher::fetch`], which is right for every
    /// fetcher whose trust does not vary per entry (the test mocks).
    /// [`HttpJwksFetcher`] overrides it.
    ///
    /// # Errors
    ///
    /// The same one-line reason [`JwksFetcher::fetch`] returns, or the
    /// reason the entry's pinned CA could not be turned into a client.
    async fn fetch_for(&self, entry: &OidcIssuer) -> Result<JwkSet, String> {
        self.fetch(&entry.jwks_url).await
    }
}

/// The production fetcher: `reqwest` over the node's trust roots, plus
/// one client per issuer entry that pins its own CA.
#[derive(Debug, Clone)]
pub struct HttpJwksFetcher {
    /// Used by every entry that pins no CA: webpki's public roots and
    /// the platform store together.
    default_client: reqwest::Client,
    /// Clients anchored on one entry's pinned CA, by entry id. Building
    /// one parses the PEM and seeds a fresh root store, so it is done
    /// once per entry and not once per fetch.
    pinned_clients: Arc<parking_lot::Mutex<HashMap<String, reqwest::Client>>>,
}

impl HttpJwksFetcher {
    /// Build the default client. Fails only when `reqwest` cannot
    /// initialise its TLS backend, which is a broken build rather than
    /// a runtime condition.
    ///
    /// # Errors
    ///
    /// The `reqwest` build error.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            default_client: build_client(None)?,
            pinned_clients: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        })
    }

    /// The client that fetches `entry`'s key set: the entry's own when
    /// it pins a CA, the node-trust one otherwise.
    ///
    /// # Errors
    ///
    /// The reason the pinned CA could not be turned into a client,
    /// which is a PEM the TLS stack refuses.
    fn client_for(&self, entry: &OidcIssuer) -> Result<reqwest::Client, String> {
        let Some(ca_pem) = entry.ca_pem.as_deref() else {
            return Ok(self.default_client.clone());
        };
        if let Some(client) = self.pinned_clients.lock().get(&entry.id) {
            return Ok(client.clone());
        }
        let client = build_client(Some(ca_pem))
            .map_err(|e| format!("the entry's pinned ca_pem is not a usable trust anchor: {e}"))?;
        self.pinned_clients
            .lock()
            .insert(entry.id.clone(), client.clone());
        Ok(client)
    }

    /// How many per-entry clients are held, so a test can tell an entry
    /// that took the default client from one that built its own without
    /// reaching the network.
    #[cfg(test)]
    fn pinned_client_count(&self) -> usize {
        self.pinned_clients.lock().len()
    }
}

/// One JWKS client: `https` only, same-origin redirects, both
/// timeouts.
///
/// With `ca_pem`, the built-in roots are switched OFF and the supplied
/// certificates become the whole trust store. That is the point of
/// pinning: an operator naming a CA is naming the only authority they
/// expect to have signed that endpoint, and adding it to the public
/// bundle would leave every commercial CA able to vouch for the issuer
/// as well.
fn build_client(ca_pem: Option<&str>) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::custom(same_origin_redirects))
        .connect_timeout(JWKS_CONNECT_TIMEOUT)
        .timeout(JWKS_TOTAL_TIMEOUT);
    if let Some(pem) = ca_pem {
        builder = builder.tls_built_in_root_certs(false);
        for certificate in reqwest::Certificate::from_pem_bundle(pem.as_bytes())? {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder.build()
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
        fetch_with(&self.default_client, url).await
    }

    async fn fetch_for(&self, entry: &OidcIssuer) -> Result<JwkSet, String> {
        let client = self.client_for(entry)?;
        fetch_with(&client, &entry.jwks_url).await
    }
}

/// One JWKS request on `client`, with the body cap applied as the
/// bytes arrive rather than after they are all in memory.
async fn fetch_with(client: &reqwest::Client, url: &str) -> Result<JwkSet, String> {
    let mut response = client
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

/// How a cache miss is filled: from a bare URL on the fetcher's own
/// trust, or from an issuer entry that may pin its own CA.
enum FetchSource<'a> {
    /// A URL with no entry behind it.
    Url(&'a str),
    /// An issuer entry, whose `ca_pem` the fetcher honours.
    Entry(&'a OidcIssuer),
}

impl FetchSource<'_> {
    /// The URL this source fetches, for the log line and the cache
    /// placeholder.
    fn url(&self) -> &str {
        match self {
            Self::Url(url) => url,
            Self::Entry(entry) => &entry.jwks_url,
        }
    }

    /// Ask `fetcher` for this source's key set.
    async fn fetch(&self, fetcher: &dyn JwksFetcher) -> Result<JwkSet, String> {
        match self {
            Self::Url(url) => fetcher.fetch(url).await,
            Self::Entry(entry) => fetcher.fetch_for(entry).await,
        }
    }
}

/// Where an entry's key set is cached.
///
/// An entry that pins no CA shares the URL's slot with every other
/// such entry, which is what makes one fetch serve a whole group of
/// entries on one GitLab. An entry that pins one gets a slot of its
/// own: the key set it fetched was vouched for by ITS anchor, and
/// handing that to an entry trusting something else would quietly
/// undo the pin.
fn cache_key_for(entry: &OidcIssuer) -> String {
    match entry.ca_pem {
        Some(_) => format!("{}#{}", entry.jwks_url, entry.id),
        None => entry.jwks_url.clone(),
    }
}

/// The per-URL key cache. One instance per process, shared by every
/// verification.
///
/// The map lock is NEVER held across a fetch. One entry's fetch can
/// take the client's full total timeout, and holding the map across
/// it made a single unreachable issuer stall every OIDC
/// authentication on the node for that long, including the ones whose
/// keys were cached and fresh. A burst on one issuer still produces
/// one fetch and not a herd, because the attempt stamp is claimed
/// under the lock BEFORE the lock is dropped: the second request
/// through sees the stamp, finds itself inside
/// [`JWKS_REFETCH_MIN_INTERVAL`], and answers from what the cache
/// holds rather than opening its own connection.
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
        self.lookup(jwks_url, &FetchSource::Url(jwks_url), kid, now)
            .await
    }

    /// The RSA verification key `kid` names in the key set `entry`
    /// points at, fetched on the trust `entry` carries.
    ///
    /// An entry pinning a CA gets its own cache slot as well as its own
    /// client: two entries on one URL with different trust anchors are
    /// two different questions, and one must not answer with the key
    /// set the other fetched.
    ///
    /// # Errors
    ///
    /// The same two reasons [`JwksCache::decoding_key`] returns.
    pub async fn decoding_key_for(
        &self,
        entry: &OidcIssuer,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<DecodingKey>, JwksLookupError> {
        let cache_key = cache_key_for(entry);
        self.lookup(&cache_key, &FetchSource::Entry(entry), kid, now)
            .await
    }

    /// The body both lookups share: `cache_key` addresses the cached
    /// key set, `source` says how a miss is filled.
    async fn lookup(
        &self,
        cache_key: &str,
        source: &FetchSource<'_>,
        kid: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<DecodingKey>, JwksLookupError> {
        let jwks_url = source.url();
        // Read the decision out of the map and drop the lock. Every
        // await below happens with the map free.
        let (hit, may_attempt) = {
            let mut entries = self.entries.lock().await;
            match entries.get_mut(cache_key) {
                Some(cached) => {
                    let hit = cached
                        .is_fresh(now)
                        .then(|| cached.keys.get(kid).map(Arc::clone))
                        .flatten();
                    let may_attempt = hit.is_none() && cached.may_attempt(now);
                    if may_attempt {
                        // Claim the attempt window here, so a burst on
                        // one issuer opens one connection and the rest
                        // answer from the cache.
                        cached.last_attempt = now;
                    }
                    (hit, may_attempt)
                }
                None => {
                    // The placeholder is already stale, so a lookup
                    // racing this fetch fails closed rather than
                    // trusting an empty key set as if it were fresh,
                    // and it carries the attempt stamp for the same
                    // reason the branch above sets one.
                    entries.insert(
                        cache_key.to_string(),
                        CachedKeys {
                            keys: HashMap::new(),
                            fetched_at: now - to_delta(JWKS_REFRESH_INTERVAL),
                            last_attempt: now,
                        },
                    );
                    (None, true)
                }
            }
        };
        if let Some(key) = hit {
            return Ok(key);
        }

        if may_attempt {
            match source.fetch(self.fetcher.as_ref()).await {
                Ok(set) => {
                    crate::metrics::inc_automation_oidc_jwks_fetch("ok");
                    self.entries.lock().await.insert(
                        cache_key.to_string(),
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
                }
            }
        }

        let entries = self.entries.lock().await;
        match entries.get(cache_key) {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use lorica_config::models::{AutomationScope, OidcIssuer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    /// A CA and the leaf it signs for `127.0.0.1`, minted per test so
    /// no key material lives in the tree. The leaf carries an IP SAN
    /// rather than a name, so the fetch never depends on how the test
    /// host resolves `localhost`.
    struct TestCa {
        ca_pem: String,
        leaf_cert_pem: String,
        leaf_key_pem: String,
    }

    fn mint_ca() -> TestCa {
        let mut ca_params =
            rcgen::CertificateParams::new(Vec::new()).expect("test setup: CA params");
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Lorica JWKS Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test setup: CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("test setup: CA self-signs");

        let mut leaf_params =
            rcgen::CertificateParams::new(Vec::new()).expect("test setup: leaf params");
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "jwks endpoint");
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.subject_alt_names = vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1,
        )))];
        let leaf_key = rcgen::KeyPair::generate().expect("test setup: leaf key");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), &ca_key)
            .expect("test setup: issuer from CA");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("test setup: CA signs the leaf");

        TestCa {
            ca_pem: ca_cert.pem(),
            leaf_cert_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    /// Serve one HTTPS request with an empty key set and stop. An empty
    /// set is enough: these tests are about which certificate the fetch
    /// accepts, not about which keys come back.
    async fn spawn_jwks_endpoint(ca: &TestCa) -> SocketAddr {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(ca.leaf_cert_pem.as_bytes())
                .filter_map(Result::ok)
                .map(CertificateDer::into_owned)
                .collect();
        let key = PrivateKeyDer::from_pem_slice(ca.leaf_key_pem.as_bytes())
            .expect("test setup: leaf key parses");
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("test setup: server config");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test setup: listener binds");
        let addr = listener.local_addr().expect("test setup: bound address");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let mut scratch = [0u8; 1024];
            let _ = tls.read(&mut scratch).await;
            let body = br#"{"keys":[]}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = tls.write_all(head.as_bytes()).await;
            let _ = tls.write_all(body).await;
            let _ = tls.shutdown().await;
        });
        addr
    }

    fn entry_at(addr: SocketAddr, ca_pem: Option<String>) -> OidcIssuer {
        let mut bound_claims = BTreeMap::new();
        bound_claims.insert("project_path".to_string(), "acme/*".to_string());
        OidcIssuer {
            id: "issuer-1".to_string(),
            issuer: "https://gitlab.example.com".to_string(),
            audience: "lorica-prod".to_string(),
            jwks_url: format!("https://{addr}/oauth/discovery/keys"),
            ca_pem,
            bound_claims,
            allowed_hostnames: vec!["*.review.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            scopes: vec![AutomationScope::EnvironmentsRead],
            created_by: "admin".to_string(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn a_pinned_ca_accepts_the_endpoint_it_signed() {
        let ca = mint_ca();
        let addr = spawn_jwks_endpoint(&ca).await;
        let fetcher = HttpJwksFetcher::new().expect("test setup: fetcher builds");
        let entry = entry_at(addr, Some(ca.ca_pem.clone()));

        fetcher
            .fetch_for(&entry)
            .await
            .expect("the pinned CA signed this endpoint, so the fetch succeeds");
        assert_eq!(
            fetcher.pinned_client_count(),
            1,
            "an entry that pins a CA fetches on its own client"
        );
    }

    #[tokio::test]
    async fn a_pinned_ca_refuses_an_endpoint_it_did_not_sign() {
        // The endpoint is served under one CA and the entry pins
        // another. Pinning REPLACES the node's trust, so neither the
        // platform roots nor the public bundle can rescue this.
        let serving = mint_ca();
        let pinned = mint_ca();
        let addr = spawn_jwks_endpoint(&serving).await;
        let fetcher = HttpJwksFetcher::new().expect("test setup: fetcher builds");
        let entry = entry_at(addr, Some(pinned.ca_pem.clone()));

        let error = fetcher
            .fetch_for(&entry)
            .await
            .expect_err("a certificate the pinned CA did not sign is refused");
        assert!(error.contains("request failed"), "{error}");
    }

    #[tokio::test]
    async fn an_entry_without_a_pinned_ca_uses_the_default_client() {
        // The fetch itself fails, because a throwaway CA is in no trust
        // store on earth. What this pins is that no per-entry client was
        // built for it: the entry went out on the node-trust client.
        let ca = mint_ca();
        let addr = spawn_jwks_endpoint(&ca).await;
        let fetcher = HttpJwksFetcher::new().expect("test setup: fetcher builds");
        let entry = entry_at(addr, None);

        let _ = fetcher.fetch_for(&entry).await;
        assert_eq!(
            fetcher.pinned_client_count(),
            0,
            "an entry pinning no CA must not build a client of its own"
        );
    }

    #[test]
    fn a_pinned_entry_gets_its_own_cache_slot() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let plain = entry_at(addr, None);
        let pinned = entry_at(addr, Some("pem".to_string()));
        assert_eq!(cache_key_for(&plain), plain.jwks_url);
        assert_ne!(cache_key_for(&pinned), pinned.jwks_url);
    }
}
