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

//! Test suite for the pure ACME core: config, DNS-01 challenge config
//! validation, challenger construction, and the Cloudflare / OVH challenger
//! HTTP paths exercised against a `wiremock` mock server.

use crate::config::AcmeConfig;
use crate::dns_challengers::{
    build_dns_challenger, CloudflareDnsChallenger, DnsChallengeConfig, OvhDnsChallenger,
};

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

// --- DNS challenger HTTP coverage via wiremock ---
//
// These tests replace the provider's API with a local mock server,
// so the challenger code path (URL shape, auth header, JSON
// payload, 4xx error mapping) gets exercised without hitting the
// real Cloudflare / OVH endpoints. Each challenger carries a
// pub(crate) `with_base_url` constructor that points at the mock
// origin ; the production constructor plugs in the real base URL.

use crate::dns_challengers::DnsChallenger;
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
