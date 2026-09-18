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

//! Tests for the ID-token verifier, against a mock issuer that counts
//! its JWKS fetches.
//!
//! The two that matter most were written before the verifier existed
//! and failed against it: a token whose header says `HS256`, signed
//! with the issuer's public key as the MAC secret, and a token with
//! `alg: none`. Either one accepted is a complete authentication
//! bypass, and neither depends on anything but the verifier reading
//! the algorithm from its own configuration instead of the token.
//!
//! The mock signs with a key generated in the test through
//! `aws-lc-rs`, the backend `jsonwebtoken` already builds, so no
//! private key is checked into the repository.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use lorica_config::models::{
    AutomationScope, OidcIssuer, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
};

use super::jwks::{JWKS_REFETCH_MIN_INTERVAL, JWKS_REFRESH_INTERVAL};
use super::test_support::{
    gitlab_claims as claims, sign_hs256, unsigned, MockIssuer, TestKey, AUDIENCE, ISSUER_URL,
    JWKS_URL,
};
use super::{gitlab_environment_slug, looks_like_jwt, peek_audiences, OidcVerifier, RefusalReason};

fn bound(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// An entry that accepts the token [`claims`] mints.
fn issuer_entry(id: &str, bound_claims: BTreeMap<String, String>) -> OidcIssuer {
    OidcIssuer {
        id: id.to_string(),
        issuer: ISSUER_URL.to_string(),
        audience: AUDIENCE.to_string(),
        jwks_url: JWKS_URL.to_string(),
        ca_pem: None,
        bound_claims,
        allowed_hostnames: vec!["*.review.example.com".to_string()],
        allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
        max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
        scopes: vec![
            AutomationScope::EnvironmentsRead,
            AutomationScope::EnvironmentsWrite,
        ],
        created_by: "admin".to_string(),
        created_at: Utc::now(),
    }
}

fn entry() -> OidcIssuer {
    issuer_entry(
        "issuer-1",
        bound(&[("project_path", "acme/*"), ("ref_protected", "true")]),
    )
}

fn now() -> DateTime<Utc> {
    Utc::now()
}

async fn verify(
    verifier: &OidcVerifier,
    token: &str,
    entries: &[OidcIssuer],
    at: DateTime<Utc>,
) -> Result<super::VerifiedIdToken, RefusalReason> {
    verifier.verify(token, entries, at).await
}

// ---- IV4: the algorithm never comes from the token ----

#[tokio::test]
async fn an_hs256_token_signed_with_the_public_key_as_the_secret_is_refused_as_wrong_alg() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());

    // The classic confusion: a verifier that reads `alg` from the
    // header and holds an RSA public key would MAC the message with
    // that public key, which the attacker also holds.
    let forged = sign_hs256(&key.public_key_der(), "k1", &claims());
    let outcome = verify(&verifier, &forged, &[entry()], now()).await;
    assert_eq!(outcome.err(), Some(RefusalReason::WrongAlg));

    // Refused before any key is looked up, so no fetch happened either:
    // a forgery must not be an outbound-fetch primitive.
    assert_eq!(issuer.fetches(), 0);
}

#[tokio::test]
async fn a_token_with_alg_none_is_refused_as_wrong_alg() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());

    let (empty_signature, garbage_signature) = unsigned("k1", &claims());
    assert_eq!(
        verify(&verifier, &empty_signature, &[entry()], now())
            .await
            .err(),
        Some(RefusalReason::WrongAlg)
    );
    assert_eq!(
        verify(&verifier, &garbage_signature, &[entry()], now())
            .await
            .err(),
        Some(RefusalReason::WrongAlg)
    );
    assert_eq!(issuer.fetches(), 0);
}

// ---- Acceptance ----

#[tokio::test]
async fn a_well_formed_token_is_accepted_and_its_claims_become_the_identity() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());

    let verified = verify(&verifier, &key.sign(&claims()), &[entry()], now())
        .await
        .expect("a well-formed token is accepted");
    assert_eq!(verified.issuer.id, "issuer-1");
    assert_eq!(verified.claims.project_path, "acme/web");
    assert_eq!(verified.claims.pipeline.git_ref.as_deref(), Some("main"));
    assert_eq!(
        verified.claims.pipeline.pipeline_id.as_deref(),
        Some("1234")
    );
    assert_eq!(verified.claims.pipeline.job_id.as_deref(), Some("5678"));
    assert_eq!(verified.claims.pipeline.user_login.as_deref(), Some("dev"));
    assert_eq!(verified.claims.environment.as_deref(), Some("review/mr-42"));
    assert_eq!(
        verified
            .claims
            .bound
            .get("ref_protected")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(issuer.fetches(), 1, "one fetch fills the cache");
}

#[tokio::test]
async fn no_candidate_entry_is_refused_as_no_issuer_without_a_fetch() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    assert_eq!(
        verify(&verifier, &key.sign(&claims()), &[], now())
            .await
            .err(),
        Some(RefusalReason::NoIssuer)
    );
    assert_eq!(issuer.fetches(), 0);
}

// ---- Each claim failure has its own reason ----

#[tokio::test]
async fn each_claim_failure_is_refused_with_its_own_reason() {
    let key = TestKey::generate("k1");
    let other = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [entry()];
    let real_now = Utc::now().timestamp();

    let mut expired = claims();
    expired["exp"] = serde_json::json!(real_now - 120);
    assert_eq!(
        verify(&verifier, &key.sign(&expired), &entries, now())
            .await
            .err(),
        Some(RefusalReason::Expired)
    );

    let mut within_skew = claims();
    within_skew["exp"] = serde_json::json!(real_now - 30);
    assert!(
        verify(&verifier, &key.sign(&within_skew), &entries, now())
            .await
            .is_ok(),
        "sixty seconds of skew are tolerated on exp"
    );

    let mut not_yet = claims();
    not_yet["nbf"] = serde_json::json!(real_now + 300);
    assert_eq!(
        verify(&verifier, &key.sign(&not_yet), &entries, now())
            .await
            .err(),
        Some(RefusalReason::NotYetValid)
    );

    let mut issued_in_the_future = claims();
    issued_in_the_future["iat"] = serde_json::json!(real_now + 300);
    assert_eq!(
        verify(&verifier, &key.sign(&issued_in_the_future), &entries, now())
            .await
            .err(),
        Some(RefusalReason::NotYetValid)
    );

    let mut wrong_aud = claims();
    wrong_aud["aud"] = serde_json::json!("some-other-consumer");
    assert_eq!(
        verify(&verifier, &key.sign(&wrong_aud), &entries, now())
            .await
            .err(),
        Some(RefusalReason::WrongAud)
    );

    let mut wrong_iss = claims();
    wrong_iss["iss"] = serde_json::json!("https://evil.example.org");
    assert_eq!(
        verify(&verifier, &key.sign(&wrong_iss), &entries, now())
            .await
            .err(),
        Some(RefusalReason::WrongIss)
    );

    // Same kid, another private key: the JWKS key does not verify it.
    assert_eq!(
        verify(&verifier, &other.sign(&claims()), &entries, now())
            .await
            .err(),
        Some(RefusalReason::BadSignature)
    );

    let mut other_project = claims();
    other_project["project_path"] = serde_json::json!("globex/web");
    assert_eq!(
        verify(&verifier, &key.sign(&other_project), &entries, now())
            .await
            .err(),
        Some(RefusalReason::BoundClaimMismatch(
            "project_path".to_string()
        ))
    );

    let mut unprotected = claims();
    unprotected["ref_protected"] = serde_json::json!("false");
    assert_eq!(
        verify(&verifier, &key.sign(&unprotected), &entries, now())
            .await
            .err(),
        Some(RefusalReason::BoundClaimMismatch(
            "ref_protected".to_string()
        ))
    );

    let mut no_jti = claims();
    no_jti.as_object_mut().expect("object").remove("jti");
    assert_eq!(
        verify(&verifier, &key.sign(&no_jti), &entries, now())
            .await
            .err(),
        Some(RefusalReason::MissingClaim("jti".to_string()))
    );

    let mut no_project = claims();
    no_project
        .as_object_mut()
        .expect("object")
        .remove("project_path");
    assert_eq!(
        verify(&verifier, &key.sign(&no_project), &entries, now())
            .await
            .err(),
        Some(RefusalReason::MissingClaim("project_path".to_string()))
    );

    let rs512 = key.sign_with_header(
        &serde_json::json!({ "alg": "RS512", "typ": "JWT", "kid": "k1" }),
        &claims(),
    );
    assert_eq!(
        verify(&verifier, &rs512, &entries, now()).await.err(),
        Some(RefusalReason::WrongAlg),
        "another RSA algorithm is not RS256 either"
    );

    let no_kid = key.sign_with_header(&serde_json::json!({ "alg": "RS256" }), &claims());
    assert_eq!(
        verify(&verifier, &no_kid, &entries, now()).await.err(),
        Some(RefusalReason::UnknownKid)
    );

    for malformed in ["", "a.b", "not.a.jwt", "eyJ.eyJ.sig"] {
        assert_eq!(
            verify(&verifier, malformed, &entries, now()).await.err(),
            Some(RefusalReason::Malformed),
            "{malformed:?}"
        );
    }

    // Every reason spells itself distinctly in the audit row.
    let reasons: Vec<String> = [
        RefusalReason::Malformed,
        RefusalReason::WrongAlg,
        RefusalReason::NoIssuer,
        RefusalReason::UnknownKid,
        RefusalReason::JwksUnavailable,
        RefusalReason::InvalidKey,
        RefusalReason::BadSignature,
        RefusalReason::Expired,
        RefusalReason::NotYetValid,
        RefusalReason::WrongAud,
        RefusalReason::WrongIss,
        RefusalReason::MissingClaim("jti".to_string()),
        RefusalReason::BoundClaimMismatch("project_path".to_string()),
        RefusalReason::Replayed,
    ]
    .iter()
    .map(RefusalReason::audit_reason)
    .collect();
    let distinct: std::collections::BTreeSet<&String> = reasons.iter().collect();
    assert_eq!(distinct.len(), reasons.len());
    assert!(reasons.contains(&"bound_claim_mismatch:project_path".to_string()));
}

// ---- Replay (AC #4) ----

#[tokio::test]
async fn a_replayed_jti_is_refused_and_a_mismatch_does_not_consume_it() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    let token = key.sign(&claims());

    // A refusal on bound claims must not remember the jti: the token
    // may still be valid for another entry on a later request.
    let strict = issuer_entry("strict", bound(&[("project_path", "globex/*")]));
    assert_eq!(
        verify(&verifier, &token, &[strict], now()).await.err(),
        Some(RefusalReason::BoundClaimMismatch(
            "project_path".to_string()
        ))
    );

    assert!(verify(&verifier, &token, &[entry()], now()).await.is_ok());
    assert_eq!(
        verify(&verifier, &token, &[entry()], now()).await.err(),
        Some(RefusalReason::Replayed)
    );
    assert_eq!(verifier.replay_set().len(), 1);
}

#[tokio::test]
async fn a_full_replay_set_evicts_the_earliest_expiry_and_counts_it() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::with_replay_cap(issuer.clone(), 2);
    let before =
        crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[]);

    let real_now = Utc::now().timestamp();
    let mut soonest = claims();
    soonest["exp"] = serde_json::json!(real_now + 60);
    let soonest_token = key.sign(&soonest);
    assert!(verify(&verifier, &soonest_token, &[entry()], now())
        .await
        .is_ok());
    assert!(verify(&verifier, &key.sign(&claims()), &[entry()], now())
        .await
        .is_ok());
    assert!(verify(&verifier, &key.sign(&claims()), &[entry()], now())
        .await
        .is_ok());

    assert_eq!(verifier.replay_set().len(), 2, "the cap holds");
    assert_eq!(
        crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[])
            - before,
        1
    );
    // The evicted id is replayable again: that is the window the
    // counter reports, and why a silent eviction is not acceptable.
    assert!(verify(&verifier, &soonest_token, &[entry()], now())
        .await
        .is_ok());
}

// ---- The two refresh triggers (IV5, IV2) ----

#[tokio::test]
async fn a_thousand_unknown_kids_produce_at_most_one_fetch_in_a_minute() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [entry()];
    let start = now();

    // One key the issuer never published, presented under a thousand
    // different kids: the header names a key the cache does not hold,
    // and a kid is refused before the signature is ever checked.
    let stranger = TestKey::generate("unknown");
    for i in 0..1000 {
        let token = stranger.sign_with_header(
            &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": format!("unknown-{i}") }),
            &claims(),
        );
        let outcome = verify(
            &verifier,
            &token,
            &entries,
            start + Duration::milliseconds(i),
        )
        .await;
        assert_eq!(outcome.err(), Some(RefusalReason::UnknownKid));
    }
    assert_eq!(
        issuer.fetches(),
        1,
        "a thousand unknown kids within a minute are one fetch, not a thousand"
    );

    // A minute later the cap opens for exactly one more.
    let later = start + Duration::from_std(JWKS_REFETCH_MIN_INTERVAL).expect("delta");
    let stranger = TestKey::generate("unknown-late");
    assert_eq!(
        verify(&verifier, &stranger.sign(&claims()), &entries, later)
            .await
            .err(),
        Some(RefusalReason::UnknownKid)
    );
    assert_eq!(
        verify(
            &verifier,
            &stranger.sign(&claims()),
            &entries,
            later + Duration::seconds(1)
        )
        .await
        .err(),
        Some(RefusalReason::UnknownKid)
    );
    assert_eq!(issuer.fetches(), 2);
}

#[tokio::test]
async fn a_rotated_key_is_picked_up_on_the_next_unknown_kid_refresh() {
    let first = TestKey::generate("k1");
    let second = TestKey::generate("k2");
    let issuer = MockIssuer::serving(&[&first]);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [entry()];
    let start = now();

    assert!(verify(&verifier, &first.sign(&claims()), &entries, start)
        .await
        .is_ok());
    assert_eq!(issuer.fetches(), 1);

    // The issuer rotates. Within the minute the new kid is refused
    // without a fetch; once the minute has passed, one fetch picks the
    // new key up, and the old one is gone with it.
    issuer.rotate_to(&[&second]);
    assert_eq!(
        verify(
            &verifier,
            &second.sign(&claims()),
            &entries,
            start + Duration::seconds(30)
        )
        .await
        .err(),
        Some(RefusalReason::UnknownKid)
    );
    assert_eq!(issuer.fetches(), 1);

    let after_a_minute = start + Duration::from_std(JWKS_REFETCH_MIN_INTERVAL).expect("delta");
    assert!(
        verify(&verifier, &second.sign(&claims()), &entries, after_a_minute)
            .await
            .is_ok()
    );
    assert_eq!(issuer.fetches(), 2);
    assert_eq!(
        verify(
            &verifier,
            &first.sign(&claims()),
            &entries,
            after_a_minute + Duration::seconds(1)
        )
        .await
        .err(),
        Some(RefusalReason::UnknownKid),
        "the retired key no longer verifies, and the fetch cap holds"
    );
    assert_eq!(issuer.fetches(), 2);
}

#[tokio::test]
async fn a_jwks_outage_keeps_cached_keys_until_the_interval_elapses_then_refuses() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [entry()];
    let start = now();
    let refresh = Duration::from_std(JWKS_REFRESH_INTERVAL).expect("delta");
    let minute = Duration::from_std(JWKS_REFETCH_MIN_INTERVAL).expect("delta");

    assert!(verify(&verifier, &key.sign(&claims()), &entries, start)
        .await
        .is_ok());
    issuer.set_failing(true);

    // Five hours into the outage the cached key still verifies, and
    // no fetch is attempted for a known kid on a fresh set.
    assert!(verify(
        &verifier,
        &key.sign(&claims()),
        &entries,
        start + Duration::hours(5)
    )
    .await
    .is_ok());
    assert_eq!(issuer.fetches(), 1);

    // Past the interval the set is stale: one attempt, which fails,
    // and the verifier fails closed.
    let stale = start + refresh + Duration::seconds(1);
    assert_eq!(
        verify(&verifier, &key.sign(&claims()), &entries, stale)
            .await
            .err(),
        Some(RefusalReason::JwksUnavailable)
    );
    assert_eq!(issuer.fetches(), 2);

    // Still closed, and the dead issuer is not hammered.
    assert_eq!(
        verify(
            &verifier,
            &key.sign(&claims()),
            &entries,
            stale + Duration::seconds(10)
        )
        .await
        .err(),
        Some(RefusalReason::JwksUnavailable)
    );
    assert_eq!(issuer.fetches(), 2);

    // The issuer comes back; the next attempt after the minute
    // restores service.
    issuer.set_failing(false);
    assert!(
        verify(&verifier, &key.sign(&claims()), &entries, stale + minute)
            .await
            .is_ok()
    );
    assert_eq!(issuer.fetches(), 3);
}

#[tokio::test]
async fn an_outage_before_any_fetch_fails_closed_and_is_retried_once_a_minute() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    issuer.set_failing(true);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [entry()];
    let start = now();

    assert_eq!(
        verify(&verifier, &key.sign(&claims()), &entries, start)
            .await
            .err(),
        Some(RefusalReason::JwksUnavailable)
    );
    assert_eq!(
        verify(
            &verifier,
            &key.sign(&claims()),
            &entries,
            start + Duration::seconds(30)
        )
        .await
        .err(),
        Some(RefusalReason::JwksUnavailable)
    );
    assert_eq!(
        issuer.fetches(),
        1,
        "one attempt per minute on a dead issuer"
    );
}

// ---- Several entries, one issuer ----

#[tokio::test]
async fn a_later_entry_whose_bound_claims_hold_accepts_after_an_earlier_mismatch() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let verifier = OidcVerifier::new(issuer.clone());
    let entries = [
        issuer_entry("globex-only", bound(&[("project_path", "globex/*")])),
        issuer_entry("acme-only", bound(&[("project_path", "acme/*")])),
    ];
    let verified = verify(&verifier, &key.sign(&claims()), &entries, now())
        .await
        .expect("the second entry accepts");
    assert_eq!(verified.issuer.id, "acme-only");
    assert_eq!(
        issuer.fetches(),
        1,
        "one key set serves every entry on the URL"
    );
}

// ---- Shape helpers the bearer gate uses ----

#[test]
fn the_jwt_shape_test_separates_the_two_credentials() {
    let key = TestKey::generate("k1");
    assert!(looks_like_jwt(&key.sign(&claims())));
    assert!(!looks_like_jwt(
        "0123456789abcdef01234567.c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
    ));
    assert!(!looks_like_jwt(""));
    assert!(!looks_like_jwt("a.b"));
    assert!(!looks_like_jwt("a.b.c.d"));
    assert!(!looks_like_jwt("a..c"));
    assert!(!looks_like_jwt("a.b=.c"));
}

#[test]
fn the_audience_peek_reads_a_string_or_a_list_and_nothing_else() {
    let key = TestKey::generate("k1");
    assert_eq!(
        peek_audiences(&key.sign(&claims())),
        vec![AUDIENCE.to_string()]
    );
    let mut many = claims();
    many["aud"] = serde_json::json!(["a", "b", 3]);
    assert_eq!(
        peek_audiences(&key.sign(&many)),
        vec!["a".to_string(), "b".to_string()]
    );
    assert!(peek_audiences("not.a.jwt").is_empty());
    assert!(peek_audiences("").is_empty());
}

// ---- The GitLab environment slug ----

#[test]
fn the_environment_slug_follows_the_gitlab_rule() {
    // A short name of lowercase letters, digits and hyphens is its own
    // slug.
    assert_eq!(gitlab_environment_slug("production"), "production");
    assert_eq!(gitlab_environment_slug("review-42"), "review-42");
    assert_eq!(gitlab_environment_slug(&"a".repeat(24)), "a".repeat(24));
    // A name that is already a slug except for its trailing dash loses
    // the dash and nothing else.
    assert_eq!(gitlab_environment_slug("trailing-"), "trailing");

    // Anything else takes the hashed suffix, with the head cut to 17.
    for name in [
        "review/mr-42",
        "Staging",
        "review/feature branch",
        "9-lives",
        "a".repeat(25).as_str(),
        "prod.eu",
    ] {
        let slug = gitlab_environment_slug(name);
        assert!(slug.len() <= 24, "{name:?} -> {slug:?}");
        assert!(
            slug.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{name:?} -> {slug:?}"
        );
        assert!(
            slug.starts_with(|c: char| c.is_ascii_lowercase()),
            "{name:?} -> {slug:?}"
        );
        assert!(!slug.ends_with('-'), "{name:?} -> {slug:?}");
        assert!(!slug.contains("--"), "{name:?} -> {slug:?}");
        assert_eq!(slug, gitlab_environment_slug(name), "deterministic");
        let suffix = slug.rsplit('-').next().expect("a suffix");
        assert_eq!(suffix.len(), 6, "{name:?} -> {slug:?}");
    }
    assert!(gitlab_environment_slug("review/mr-42").starts_with("review-mr-42-"));
    assert!(gitlab_environment_slug("9-lives").starts_with("env-9-lives-"));
    assert_ne!(
        gitlab_environment_slug("review/mr-42"),
        gitlab_environment_slug("review/mr-43")
    );
}

// ---- The key cache holds no lock across a fetch ----

/// A fetcher that blocks on `gate` for one URL and answers at once for
/// every other, so a test can hold one issuer's fetch open and ask the
/// cache about another.
struct GatedFetcher {
    slow_url: String,
    keys: Vec<serde_json::Value>,
    entered: Arc<tokio::sync::Notify>,
    gate: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl super::JwksFetcher for GatedFetcher {
    async fn fetch(&self, url: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        if url == self.slow_url {
            self.entered.notify_waiters();
            self.gate.notified().await;
        }
        serde_json::from_value(serde_json::json!({ "keys": self.keys.clone() }))
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
async fn a_fetch_in_flight_for_one_issuer_does_not_block_another() {
    // The cache used to hold its map lock across the fetch, so one
    // unreachable issuer stalled every OIDC authentication on the node
    // for the client's full ten-second timeout.
    let key = TestKey::generate("k1");
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(tokio::sync::Notify::new());
    let cache = Arc::new(super::JwksCache::new(Arc::new(GatedFetcher {
        slow_url: SLOW_JWKS_URL.to_string(),
        keys: vec![key.jwk()],
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
    })));
    let now = Utc::now();

    // Prime the fast issuer, so the assertion below is a cache hit.
    cache
        .decoding_key(JWKS_URL, &key.kid, now)
        .await
        .expect("the fast issuer answers");

    let waiting = entered.notified();
    let slow = tokio::spawn({
        let cache = Arc::clone(&cache);
        let kid = key.kid.clone();
        async move { cache.decoding_key(SLOW_JWKS_URL, &kid, now).await }
    });
    waiting.await;

    // With the slow fetch in flight, the fast issuer still answers.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cache.decoding_key(JWKS_URL, &key.kid, now),
    )
    .await
    .expect("a cached issuer is not held behind another issuer's fetch")
    .expect("the fast issuer answers");

    gate.notify_waiters();
    slow.await
        .expect("the slow lookup finishes")
        .expect("the slow issuer answers once its fetch returns");
}

/// A second issuer's key URL, for the test above.
const SLOW_JWKS_URL: &str = "https://gitlab.slow.example.com/oauth/discovery/keys";
