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
//! validation, challenger construction, and the Cloudflare / OVH / Aliyun
//! challenger HTTP paths exercised against a `wiremock` mock server.

use crate::config::AcmeConfig;
use crate::dns_challengers::{
    aliyun::{canonical_query, percent_encode, sign},
    build_dns_challenger, AliyunDnsChallenger, CloudflareDnsChallenger, DnsChallengeConfig,
    OvhDnsChallenger,
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
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri())
            .expect("test setup: challenger");
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
        CloudflareDnsChallenger::with_base_url("zone123".into(), "bad-token".into(), server.uri())
            .expect("test setup: challenger");
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
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri())
            .expect("test setup: challenger");
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
        CloudflareDnsChallenger::with_base_url("zone123".into(), "token456".into(), server.uri())
            .expect("test setup: challenger");
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
    )
    .expect("test setup: challenger");
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
    )
    .expect("test setup: challenger");
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
    )
    .expect("test setup: challenger");
    let err = ovh
        .delete_txt_record("example.com")
        .await
        .expect_err("delete without a prior create must return Err");
    assert!(
        err.contains("no tracked"),
        "error should name the missing-id condition: {err}"
    );
}

// --- Aliyun (Alidns) challenger ---

#[test]
fn test_dns_config_valid_aliyun() {
    let config = DnsChallengeConfig {
        provider: "aliyun".into(),
        zone_id: String::new(),
        api_token: "LTAI5tExampleKeyId".into(),
        api_secret: Some("ExampleKeySecret".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_dns_config_aliyun_missing_token() {
    let config = DnsChallengeConfig {
        provider: "aliyun".into(),
        zone_id: String::new(),
        api_token: String::new(),
        api_secret: Some("ExampleKeySecret".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_token"));
}

#[test]
fn test_dns_config_aliyun_missing_secret() {
    let config = DnsChallengeConfig {
        provider: "aliyun".into(),
        zone_id: String::new(),
        api_token: "LTAI5tExampleKeyId".into(),
        api_secret: None,
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("api_secret"));
}

#[tokio::test]
async fn test_build_dns_challenger_aliyun() {
    let config = DnsChallengeConfig {
        provider: "aliyun".into(),
        zone_id: String::new(),
        api_token: "LTAI5tExampleKeyId".into(),
        api_secret: Some("ExampleKeySecret".into()),
        ovh_endpoint: None,
        ovh_consumer_key: None,
    };
    assert!(build_dns_challenger(&config).await.is_ok());
}

#[test]
fn test_aliyun_challenge_rr() {
    for (zone, name, expected) in [
        ("example.com", "example.com", "_acme-challenge"),
        ("example.com", "app.example.com", "_acme-challenge.app"),
        ("example.com", "a.b.example.com", "_acme-challenge.a.b"),
        ("b.example.com", "a.b.example.com", "_acme-challenge.a"),
    ] {
        assert_eq!(
            AliyunDnsChallenger::challenge_rr(zone, name),
            expected,
            "zone {zone}, name {name}"
        );
    }
}

#[test]
fn test_aliyun_percent_encode() {
    // The unreserved set survives verbatim; everything else is
    // upper-case-hex escaped. A space is `%20`, never `+`.
    assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
    assert_eq!(percent_encode("a b+c*d"), "a%20b%2Bc%2Ad");
    assert_eq!(
        percent_encode("2026-11-24T10:00:00Z"),
        "2026-11-24T10%3A00%3A00Z"
    );
    assert_eq!(percent_encode("/"), "%2F");
    assert_eq!(percent_encode("éxample"), "%C3%A9xample");
}

#[test]
fn test_aliyun_canonical_query_sorts_and_encodes() {
    let mut params = vec![
        ("Version".to_string(), "2015-01-09".to_string()),
        ("Action".to_string(), "AddDomainRecord".to_string()),
        ("RR".to_string(), "_acme-challenge.app".to_string()),
    ];
    assert_eq!(
        canonical_query(&mut params),
        "Action=AddDomainRecord&RR=_acme-challenge.app&Version=2015-01-09"
    );
}

/// Pinned signature vector: the canonicalised query and its HMAC-SHA1
/// signature were computed independently from the algorithm the Alidns
/// docs describe, so a regression in ordering, encoding or keying
/// fails here rather than against the live API.
#[test]
fn test_aliyun_sign_pinned_vector() {
    let mut params = vec![
        ("AccessKeyId".to_string(), "testid".to_string()),
        ("Action".to_string(), "DescribeDomainRecords".to_string()),
        ("DomainName".to_string(), "example.com".to_string()),
        ("Format".to_string(), "JSON".to_string()),
        ("PageNumber".to_string(), "1".to_string()),
        ("PageSize".to_string(), "1".to_string()),
        ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
        (
            "SignatureNonce".to_string(),
            "f59cb6d92202fdd8e2a3c84e0d6c3d1f".to_string(),
        ),
        ("SignatureVersion".to_string(), "1.0".to_string()),
        ("Timestamp".to_string(), "2026-11-24T10:00:00Z".to_string()),
        ("Version".to_string(), "2015-01-09".to_string()),
    ];
    let canonicalized = canonical_query(&mut params);
    assert_eq!(
        sign("testsecret", &canonicalized),
        "JbLIsf2WY9xFYU9mlnPonumTk7Y="
    );
}

/// The zone walk skips suffixes the account does not host and creates
/// the record under the first hosted one.
#[tokio::test]
async fn aliyun_create_txt_walks_to_hosted_zone() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .and(query_param("DomainName", "app.example.com"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "Code": "InvalidDomainName.NoExist",
            "Message": "The specified domain name does not exist.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .and(query_param("DomainName", "example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "TotalCount": 1,
            "PageNumber": 1,
            "PageSize": 1,
            "DomainRecords": {"Record": []},
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "AddDomainRecord"))
        .and(query_param("DomainName", "example.com"))
        .and(query_param("RR", "_acme-challenge.app"))
        .and(query_param("Type", "TXT"))
        .and(query_param("Value", "challenge-value"))
        .and(query_param("TTL", "600"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "RequestId": "536E9CAD-DB30-4647-AC87-AA5CC38C5382",
            "RecordId": "1001",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    challenger
        .create_txt_record("app.example.com", "challenge-value")
        .await
        .expect("create should succeed once the hosted zone is found");

    // Every request must carry the common RPC parameters. The signature
    // algorithm itself is pinned by `test_aliyun_sign_pinned_vector`.
    let requests = server
        .received_requests()
        .await
        .expect("test setup: recorded requests");
    let add = requests
        .iter()
        .find(|r| {
            r.url
                .query_pairs()
                .any(|(k, v)| k == "Action" && v == "AddDomainRecord")
        })
        .expect("test setup: AddDomainRecord request");
    let sent_params: Vec<(String, String)> = add
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    for required in [
        "Format",
        "Version",
        "AccessKeyId",
        "SignatureMethod",
        "SignatureVersion",
        "SignatureNonce",
        "Timestamp",
        "Signature",
    ] {
        assert!(
            sent_params.iter().any(|(k, _)| k == required),
            "signed request is missing {required}"
        );
    }
}

#[tokio::test]
async fn aliyun_create_txt_no_hosted_zone_is_err() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "Code": "InvalidDomainName.NoExist",
            "Message": "The specified domain name does not exist.",
        })))
        .expect(2)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("app.example.com", "val")
        .await
        .expect_err("no hosted zone must map to Err");
    assert!(
        err.contains("no hosted Alidns zone"),
        "error should name the missing zone: {err}"
    );
}

#[tokio::test]
async fn aliyun_create_txt_surfaces_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "TotalCount": 1,
            "PageNumber": 1,
            "PageSize": 1,
            "DomainRecords": {"Record": []},
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "AddDomainRecord"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "Code": "InvalidAccessKeyId.NotFound",
            "Message": "Specified access key is not found.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("bad-key-id".into(), "bad-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("example.com", "val")
        .await
        .expect_err("400 must map to Err");
    assert!(err.contains("400"), "error must carry the status: {err}");
    assert!(
        err.contains("InvalidAccessKeyId.NotFound"),
        "error must carry the API code: {err}"
    );
    assert!(
        err.contains("Specified access key is not found"),
        "error must carry the API message: {err}"
    );
}

/// One order carrying a name and its wildcard tracks two record ids
/// under the same TXT name. Cleanup retracts the successful id, keeps
/// the failed one, and retries only that id on the next call.
#[tokio::test]
async fn aliyun_delete_txt_retracts_and_retries_tracked_records() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "TotalCount": 1,
            "PageNumber": 1,
            "PageSize": 1,
            "DomainRecords": {"Record": []},
        })))
        .expect(2)
        .mount(&server)
        .await;

    for (record_id, value) in [("1001", "value-apex"), ("1002", "value-wildcard")] {
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("Action", "AddDomainRecord"))
            .and(query_param("Value", value))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "RecordId": record_id,
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DeleteDomainRecord"))
        .and(query_param("RecordId", "1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "RecordId": "1001",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DeleteDomainRecord"))
        .and(query_param("RecordId", "1002"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "Code": "Throttling",
            "Message": "Request was denied due to request throttling.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    challenger
        .create_txt_record("example.com", "value-apex")
        .await
        .expect("test setup: first create");
    challenger
        .create_txt_record("example.com", "value-wildcard")
        .await
        .expect("test setup: second create");
    let err = challenger
        .delete_txt_record("example.com")
        .await
        .expect_err("the failed deletion must be reported");
    assert!(
        err.contains("Throttling"),
        "error must carry the API code: {err}"
    );

    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DeleteDomainRecord"))
        .and(query_param("RecordId", "1001"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DeleteDomainRecord"))
        .and(query_param("RecordId", "1002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "RecordId": "1002",
        })))
        .expect(1)
        .mount(&server)
        .await;
    challenger
        .delete_txt_record("example.com")
        .await
        .expect("retry must delete only the id left by the failed call");

    let err = challenger
        .delete_txt_record("example.com")
        .await
        .expect_err("a later cleanup has nothing tracked");
    assert!(
        err.contains("no tracked"),
        "error should name the missing-id condition: {err}"
    );
}

/// A 200 response with a business `Code` must not be accepted as a
/// hosted zone or a successful record change.
#[tokio::test]
async fn aliyun_create_txt_rejects_business_error_in_200_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": "InvalidAccessKeyId.NotFound",
            "Message": "Specified access key is not found.",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "AddDomainRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "RecordId": "1001",
        })))
        .expect(0)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("bad-key".into(), "bad-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("example.com", "val")
        .await
        .expect_err("a 200 response with a Code must map to Err");
    assert!(
        err.contains("InvalidAccessKeyId.NotFound"),
        "error must carry the API code: {err}"
    );
}

/// A credential or throttling error during zone probing must surface
/// as itself, not be swallowed as "domain is not hosted".
#[tokio::test]
async fn aliyun_create_txt_surfaces_auth_error_during_zone_probe() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "Code": "Forbidden.RAM",
            "Message": "The RAM user is not authorized.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("app.example.com", "val")
        .await
        .expect_err("a RAM error must map to Err");
    assert!(
        err.contains("Forbidden.RAM"),
        "error must carry the original code: {err}"
    );
    assert!(
        !err.contains("no hosted"),
        "a RAM error must not be disguised as a missing zone: {err}"
    );
}

/// The client must not follow a redirect: doing so would send the
/// signed query, including the AccessKey id and signature, to a host
/// the configuration never named.
#[tokio::test]
async fn aliyun_client_follows_no_redirect() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stolen"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&target)
        .await;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/stolen", target.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("example.com", "val")
        .await
        .expect_err("a 302 is a failed RPC call, not a redirect to follow");
    assert!(err.contains("302"), "error must carry the status: {err}");
    assert!(
        !err.contains("Signature"),
        "error must not carry the signed query: {err}"
    );
}

/// `reqwest` renders the full request URL in transport errors. An
/// unreachable endpoint must not turn that URL, with its AccessKey id
/// and signature, into an ACME log line.
#[tokio::test]
async fn aliyun_transport_error_has_no_signed_url() {
    let challenger = AliyunDnsChallenger::with_base_url(
        "sensitive-key-id".into(),
        "sensitive-secret".into(),
        "http://127.0.0.1:1".into(),
    )
    .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("example.com", "val")
        .await
        .expect_err("an unreachable endpoint must fail");
    assert!(
        err.contains("request failed"),
        "error must name the failed call: {err}"
    );
    for secret in ["sensitive-key-id", "AccessKeyId", "Signature", "Timestamp"] {
        assert!(
            !err.contains(secret),
            "transport error must not carry the signed URL ({secret}): {err}"
        );
    }
}

/// An API error body that echoes the signed URL in either `Code` or
/// `Message` must be scrubbed end to end.
#[tokio::test]
async fn aliyun_api_error_body_is_scrubbed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(query_param("Action", "DescribeDomainRecords"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "Code": "GatewayError: Signature=code-secret&AccessKeyId=code-id",
            "Message": "GET /?AccessKeyId=sensitive-id&Signature=a%2Bb%3D&SignatureNonce=abc&Timestamp=2026-11-24T10%3A00%3A00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let challenger =
        AliyunDnsChallenger::with_base_url("key-id".into(), "key-secret".into(), server.uri())
            .expect("test setup: challenger");
    let err = challenger
        .create_txt_record("example.com", "val")
        .await
        .expect_err("a 400 error body must map to Err");
    for secret in [
        "code-secret",
        "code-id",
        "sensitive-id",
        "a%2Bb%3D",
        "SignatureNonce=abc",
        "2026-11-24T10%3A00%3A00Z",
    ] {
        assert!(
            !err.contains(secret),
            "error body leaked a signed query value ({secret}): {err}"
        );
    }
    assert!(
        err.contains("[REDACTED]"),
        "scrubbed values are marked: {err}"
    );
}
