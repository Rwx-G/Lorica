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

//! A mock GitLab issuer for tests: a signing key generated in the
//! process, the JWKS it publishes, a counting fetcher, and the tokens
//! it mints.
//!
//! Shared by the verifier tests, the bearer-gate tests, the environment
//! tests and the issuer-administration tests, so every one of them
//! signs the way a real GitLab does and none checks a private key into
//! the repository. The key comes from `aws-lc-rs`, the backend
//! `jsonwebtoken` already builds.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
use base64::Engine as _;
use chrono::Utc;
use jsonwebtoken::jwk::JwkSet;
use parking_lot::Mutex;

use super::{JwksFetcher, OidcVerifier};

/// A verifier behind a mock issuer that publishes no key, for the test
/// harnesses whose `AppState` needs one and whose tests never present
/// an ID token.
pub(crate) fn verifier_without_issuer() -> Arc<OidcVerifier> {
    Arc::new(OidcVerifier::new(MockIssuer::serving(&[])))
}

/// The issuer URL every mock token carries as `iss`.
pub(crate) const ISSUER_URL: &str = "https://gitlab.example.com";

/// The JWKS URL an entry for the mock issuer names.
pub(crate) const JWKS_URL: &str = "https://gitlab.example.com/oauth/discovery/keys";

/// The audience every mock token carries as `aud`.
pub(crate) const AUDIENCE: &str = "lorica-prod";

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// One signing key of the mock issuer.
pub(crate) struct TestKey {
    pub(crate) kid: String,
    pair: KeyPair,
}

impl TestKey {
    /// A fresh RSA-2048 key named `kid`. Slow (about a hundred
    /// milliseconds), so a test generates as few as it needs.
    pub(crate) fn generate(kid: &str) -> Self {
        Self {
            kid: kid.to_string(),
            pair: KeyPair::generate(KeySize::Rsa2048).expect("test setup: RSA key generates"),
        }
    }

    /// The key as GitLab publishes it.
    pub(crate) fn jwk(&self) -> serde_json::Value {
        let components = PublicKeyComponents::<Vec<u8>>::from(self.pair.public_key());
        serde_json::json!({
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64(&components.n),
            "e": b64(&components.e),
        })
    }

    /// The SubjectPublicKeyInfo DER, which is what a confused verifier
    /// would use as an HMAC secret.
    pub(crate) fn public_key_der(&self) -> Vec<u8> {
        let der: PublicKeyX509Der<'static> = self
            .pair
            .public_key()
            .as_der()
            .expect("test setup: public key serialises");
        der.as_ref().to_vec()
    }

    /// An RS256 JWT over `claims`, with this key's `kid` in the header.
    pub(crate) fn sign(&self, claims: &serde_json::Value) -> String {
        self.sign_with_header(
            &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid }),
            claims,
        )
    }

    /// An RS256 JWT with an arbitrary header, for tests that lie in it.
    pub(crate) fn sign_with_header(
        &self,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let message = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let mut signature = vec![0u8; self.pair.public_modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .expect("test setup: RSA signature");
        format!("{message}.{}", b64(&signature))
    }
}

/// An HS256 JWT whose MAC secret is `secret`: the algorithm-confusion
/// forgery, when `secret` is the issuer's public key.
pub(crate) fn sign_hs256(secret: &[u8], kid: &str, claims: &serde_json::Value) -> String {
    let header = serde_json::json!({ "alg": "HS256", "typ": "JWT", "kid": kid });
    let message = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let tag = ring::hmac::sign(&key, message.as_bytes());
    format!("{message}.{}", b64(tag.as_ref()))
}

/// An unsigned JWT: `alg: none` with an empty signature segment, and
/// the variant with a garbage signature segment.
pub(crate) fn unsigned(kid: &str, claims: &serde_json::Value) -> (String, String) {
    let header = serde_json::json!({ "alg": "none", "typ": "JWT", "kid": kid });
    let message = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    (
        format!("{message}."),
        format!("{message}.{}", b64(b"not-a-signature")),
    )
}

/// The claims GitLab puts in an ID token, valid for five minutes from
/// the real clock, which is what the library's `exp` check reads.
pub(crate) fn gitlab_claims() -> serde_json::Value {
    let now = Utc::now().timestamp();
    serde_json::json!({
        "iss": ISSUER_URL,
        "aud": AUDIENCE,
        "sub": "project_path:acme/web:ref_type:branch:ref:main",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
        "project_path": "acme/web",
        "namespace_path": "acme",
        "ref": "main",
        "ref_protected": "true",
        "environment": "review/mr-42",
        "environment_protected": "false",
        "deployment_tier": "development",
        "pipeline_id": "1234",
        "job_id": "5678",
        "user_login": "dev",
    })
}

/// The issuer's key set, served by a counting fetcher.
pub(crate) struct MockIssuer {
    keys: Mutex<Vec<serde_json::Value>>,
    fetches: AtomicUsize,
    failing: AtomicBool,
}

impl MockIssuer {
    /// An issuer publishing `keys`.
    pub(crate) fn serving(keys: &[&TestKey]) -> Arc<Self> {
        Arc::new(Self {
            keys: Mutex::new(keys.iter().map(|key| key.jwk()).collect()),
            fetches: AtomicUsize::new(0),
            failing: AtomicBool::new(false),
        })
    }

    /// Replace the published key set.
    pub(crate) fn rotate_to(&self, keys: &[&TestKey]) {
        *self.keys.lock() = keys.iter().map(|key| key.jwk()).collect();
    }

    /// Make every fetch fail, or stop doing so.
    pub(crate) fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// How many fetches the verifier has made so far.
    pub(crate) fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl JwksFetcher for MockIssuer {
    async fn fetch(&self, url: &str) -> Result<JwkSet, String> {
        assert_eq!(
            url, JWKS_URL,
            "the verifier fetches the entry's jwks_url and nothing else"
        );
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err("mock issuer is down".to_string());
        }
        let keys = self.keys.lock().clone();
        serde_json::from_value(serde_json::json!({ "keys": keys })).map_err(|e| e.to_string())
    }
}
