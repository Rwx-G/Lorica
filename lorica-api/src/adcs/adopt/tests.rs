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

//! Tests for AD CS adoption and reversion (Story 13.5 Lot 1), through
//! the real router. The manual certificates are uploaded as an operator
//! would, signed by throwaway CAs: the authority's issuing CA, a sibling
//! issuing CA under the same root, and a CA of another chain carrying
//! the issuing CA's exact name.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lorica_config::models::{Certificate, CertificateSource, Role};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;

use super::observed_template;
use crate::adcs::issue::tests::{
    issue_v2, issuing, template_extension, StubAuthority, TemplateExtension, V2_TEMPLATE_OID,
};
use crate::adcs::tests::{body, fixture, Fixture, PASSWORD};
use crate::middleware::rate_limit::RateLimiter;
use crate::tests::body_json;

const CANDIDATES: &str = "/api/v1/adcs/adoption-candidates";
const ISSUING_CA_NAME: &str = "Example Issuing CA";

fn adopt_path(id: &str) -> String {
    format!("/api/v1/certificates/{id}/adcs/adopt")
}

fn revert_path(id: &str) -> String {
    format!("/api/v1/certificates/{id}/adcs/revert")
}

/// A throwaway CA: what signs, its certificate, and its key, so a
/// second signer with the same key can be built.
struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pem: String,
    key_pem: String,
}

fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("test setup: CA params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Example Corp");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
}

fn root(name: &str) -> Ca {
    let key = rcgen::KeyPair::generate().expect("test setup: root key");
    let params = ca_params(name);
    let cert = params.self_signed(&key).expect("test setup: root");
    Ca {
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
        issuer: rcgen::Issuer::new(params, key),
    }
}

fn intermediate(name: &str, parent: &Ca, algorithm: &'static rcgen::SignatureAlgorithm) -> Ca {
    let key = rcgen::KeyPair::generate_for(algorithm).expect("test setup: intermediate key");
    let params = ca_params(name);
    let cert = params
        .signed_by(&key, &parent.issuer)
        .expect("test setup: the parent signs");
    Ca {
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
        issuer: rcgen::Issuer::new(params, key),
    }
}

impl Ca {
    /// A signer with this CA's name and key that writes `key_id` as the
    /// authority key identifier of what it signs.
    fn with_key_identifier(
        &self,
        name: &str,
        key_id: Vec<u8>,
    ) -> rcgen::Issuer<'static, rcgen::KeyPair> {
        let mut params = ca_params(name);
        params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(key_id);
        rcgen::Issuer::new(
            params,
            rcgen::KeyPair::from_pem(&self.key_pem).expect("test setup: key"),
        )
    }
}

/// The three chains of IV1.
struct Pki {
    issuing: Ca,
    sibling: Ca,
    forged: Ca,
}

fn pki() -> Pki {
    let root_ca = root("Example Root CA");
    // AD CS issuing CAs are RSA in practice, so the signatures the
    // candidacy check verifies are RSA PKCS#1 ones; the sibling's are
    // ECDSA, the other family the check supports.
    let issuing = intermediate(ISSUING_CA_NAME, &root_ca, &rcgen::PKCS_RSA_SHA256);
    let sibling = intermediate(
        "Example Sibling Issuing CA",
        &root_ca,
        &rcgen::PKCS_ECDSA_P256_SHA256,
    );
    let other_root = root("Example Other Root CA");
    let forged = intermediate(ISSUING_CA_NAME, &other_root, &rcgen::PKCS_RSA_SHA256);
    Pki {
        issuing,
        sibling,
        forged,
    }
}

/// A leaf for `names` signed by `issuer`, as AD CS issues one: the
/// subject from the template's defaults, the authority key identifier,
/// the template extension. Returns the PEM and its key.
fn leaf(
    issuer: &rcgen::Issuer<'_, rcgen::KeyPair>,
    names: &[&str],
    template: TemplateExtension,
) -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("test setup: leaf key");
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<String>>(),
    )
    .expect("test setup: leaf params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "FR");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Example Corp");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, names[0]);
    params.use_authority_key_identifier_extension = true;
    if let Some(extension) = template_extension(template) {
        params.custom_extensions.push(extension);
    }
    let cert = params.signed_by(&key, issuer).expect("test setup: signed");
    (cert.pem(), key.serialize_pem())
}

/// An authority whose issuing CA certificate is `issuing_ca_pem`.
async fn with_authority(stub: &Arc<StubAuthority>, issuing_ca_pem: &str) -> Fixture {
    let f = fixture(Arc::clone(stub), None).await;
    let mut request = body(Some(PASSWORD));
    request["issuing_ca_pem"] = serde_json::json!(issuing_ca_pem);
    let resp = f
        .send(
            "PUT",
            crate::adcs::tests::AUTHORITY,
            &f.admin,
            Some(request),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    f
}

/// Upload a manual certificate as an operator would, leaf then chain.
async fn upload(
    f: &Fixture,
    domain: &str,
    (cert_pem, key_pem): (String, String),
    chain: &str,
) -> String {
    let resp = crate::tests::send(
        &f.state,
        &f.session_store,
        &RateLimiter::new(),
        "POST",
        "/api/v1/certificates",
        &f.admin,
        Some(serde_json::json!({
            "domain": domain,
            "cert_pem": format!("{cert_pem}{chain}"),
            "key_pem": key_pem,
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "upload {domain}");
    let json = body_json(resp).await;
    assert_eq!(json["data"]["source"], "manual");
    json["data"]["id"].as_str().expect("id").to_string()
}

/// A write to the adoption endpoints on a limiter of its own.
async fn post(
    f: &Fixture,
    uri: &str,
    cookie: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let resp = crate::tests::send(
        &f.state,
        &f.session_store,
        &RateLimiter::new(),
        "POST",
        uri,
        cookie,
        body,
    )
    .await;
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn candidates(f: &Fixture, cookie: &str) -> serde_json::Value {
    let resp = f.send("GET", CANDIDATES, cookie, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await["data"].clone()
}

fn candidate_ids(listing: &serde_json::Value) -> Vec<String> {
    listing["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|candidate| {
            candidate["certificate_id"]
                .as_str()
                .expect("id")
                .to_string()
        })
        .collect()
}

async fn stored(f: &Fixture, id: &str) -> Certificate {
    f.state
        .store
        .lock()
        .await
        .get_certificate(id)
        .expect("read")
        .expect("row")
}

/// IV1 and AC #1: of certificates signed by the issuing CA, by a
/// sibling issuing CA under the same root, by another chain's CA with
/// the issuing CA's exact name, and by the issuing CA's key under a
/// foreign authority key identifier, only the first is offered; one the
/// issuing CA signed for a name outside the allowlist, or for a
/// wildcard, is not either. Adoption refuses each of them server-side,
/// saying why.
#[tokio::test]
async fn iv1_only_a_certificate_the_issuing_ca_signed_is_offered() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let web = "web01.corp.example.org";

    let offered = upload(
        &f,
        web,
        leaf(
            &pki.issuing.issuer,
            &[web, "www.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let sibling = upload(
        &f,
        "sibling.corp.example.org",
        leaf(
            &pki.sibling.issuer,
            &["sibling.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.sibling.pem,
    )
    .await;
    let forged = upload(
        &f,
        "forged.corp.example.org",
        leaf(
            &pki.forged.issuer,
            &["forged.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.forged.pem,
    )
    .await;
    let foreign_key_id = upload(
        &f,
        "keyid.corp.example.org",
        leaf(
            &pki.issuing
                .with_key_identifier(ISSUING_CA_NAME, vec![0xAB; 20]),
            &["keyid.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let outside = upload(
        &f,
        "web.other.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web.other.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let wildcard = upload(
        &f,
        "apps.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["apps.corp.example.org", "*.apps.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;

    let viewer = f.user("viewer-adopt", Role::Viewer).await;
    let listing = candidates(&f, &viewer).await;
    assert!(listing["reason"].is_null(), "{listing}");
    assert_eq!(candidate_ids(&listing), vec![offered.clone()], "{listing}");
    let candidate = &listing["candidates"][0];
    assert_eq!(candidate["domain"], web);
    assert_eq!(
        candidate["san_domains"],
        serde_json::json!([web, "www.corp.example.org"])
    );
    assert_eq!(
        candidate["subject"],
        format!("CN={web},O=Example Corp,C=FR")
    );
    assert!(candidate["not_after"].is_string());
    assert_eq!(candidate["issued_template"], V2_TEMPLATE_OID);
    assert!(candidate["observed_template"].is_null());
    assert_eq!(candidate["template_mismatch"], false);

    for (id, says) in [
        (&sibling, "not signed by the authority's issuing CA"),
        (&forged, "not signed by the authority's issuing CA"),
        (&foreign_key_id, "not signed by the authority's issuing CA"),
        (&outside, "under an allowed suffix"),
        (&wildcard, "wildcard"),
    ] {
        let (status, json) = post(&f, &adopt_path(id), &f.admin, None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{id}: {json}");
        assert_eq!(json["error"]["code"], "adcs_not_candidate", "{json}");
        let message = json["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(says), "{id}: {message}");
        assert_eq!(stored(&f, id).await.source(), CertificateSource::Manual);
    }
    assert_eq!(stub.calls(), 0);
}

/// AC #1: with no authority, or no issuing CA certificate to verify
/// against, the listing is empty and says why; adoption is refused the
/// same way.
#[tokio::test]
async fn the_listing_says_why_nothing_can_be_offered() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = fixture(Arc::clone(&stub), None).await;
    let id = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;

    let listing = candidates(&f, &f.admin).await;
    assert_eq!(listing["reason"], "not_configured");
    assert_eq!(listing["candidates"], serde_json::json!([]));
    let (status, json) = post(&f, &adopt_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    assert_eq!(json["error"]["code"], "adcs_not_configured");

    f.create_authority().await;
    let listing = candidates(&f, &f.admin).await;
    assert_eq!(listing["reason"], "no_issuing_ca");
    assert_eq!(listing["candidates"], serde_json::json!([]));
    let (status, json) = post(&f, &adopt_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    assert_eq!(
        json["error"]["code"],
        crate::adcs::error::NO_ISSUING_CA.code
    );
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("issuing CA certificate"),
        "{json}"
    );

    let (status, _) = post(&f, &adopt_path("no-such-certificate"), &f.admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A follower holds no authority (D13): its listing says so without
/// reading anything, as its authority read does.
#[tokio::test]
async fn a_follower_lists_no_candidate_and_says_why() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let mut f = with_authority(&stub, &pki.issuing.pem).await;
    upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    f.state.cluster =
        crate::cluster::ClusterRuntime::Follower(crate::tests::test_follower_runtime());
    let listing = candidates(&f, &f.admin).await;
    assert_eq!(listing["reason"], "managed_on_control_plane");
    assert_eq!(listing["candidates"], serde_json::json!([]));
    assert_eq!(f.state.adcs.adoption.len(), 0, "nothing was verified");
}

/// The signature verdict of a certificate is computed once per pair of
/// certificates: a second listing verifies nothing new, a deleted
/// certificate's verdict is forgotten, and a new issuing CA certificate
/// is a pair not seen yet, never a stale verdict.
#[tokio::test]
async fn the_listing_remembers_each_verdict_by_the_certificates_bytes() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let offered = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let foreign = upload(
        &f,
        "sibling.corp.example.org",
        leaf(
            &pki.sibling.issuer,
            &["sibling.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.sibling.pem,
    )
    .await;

    let first = candidates(&f, &f.admin).await;
    assert_eq!(candidate_ids(&first), vec![offered.clone()]);
    assert_eq!(
        f.state.adcs.adoption.len(),
        2,
        "one verdict per manual certificate"
    );
    let second = candidates(&f, &f.admin).await;
    assert_eq!(second, first, "a remembered verdict answers the same");
    assert_eq!(f.state.adcs.adoption.len(), 2);

    f.state
        .store
        .lock()
        .await
        .delete_certificate(&foreign)
        .expect("test setup: delete");
    candidates(&f, &f.admin).await;
    assert_eq!(
        f.state.adcs.adoption.len(),
        1,
        "the deleted one is forgotten"
    );

    let mut request = body(None);
    request["issuing_ca_pem"] = serde_json::json!(pki.sibling.pem);
    let resp = f
        .send(
            "PUT",
            crate::adcs::tests::AUTHORITY,
            &f.admin,
            Some(request),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let listing = candidates(&f, &f.admin).await;
    assert_eq!(
        candidate_ids(&listing),
        Vec::<String>::new(),
        "under another issuing CA the certificate is verified again, and refused"
    );
    assert_eq!(f.state.adcs.adoption.len(), 1);
}

/// AC #3: the template a candidate was issued with is compared with the
/// one observed on what Lorica issued with the authority's template.
#[tokio::test]
async fn the_issued_template_is_compared_with_the_one_lorica_observed() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let same = upload(
        &f,
        "same.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["same.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let v1 = upload(
        &f,
        "v1.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["v1.corp.example.org"],
            TemplateExtension::V1Bmp,
        ),
        &pki.issuing.pem,
    )
    .await;
    let none = upload(
        &f,
        "none.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["none.corp.example.org"],
            TemplateExtension::None,
        ),
        &pki.issuing.pem,
    )
    .await;

    let listing = candidates(&f, &f.admin).await;
    assert_eq!(listing["candidates"].as_array().map(Vec::len), Some(3));
    for candidate in listing["candidates"].as_array().expect("candidates") {
        assert!(candidate["observed_template"].is_null(), "{candidate}");
        assert_eq!(candidate["template_mismatch"], false, "{candidate}");
    }

    let resp = f
        .issue(serde_json::json!({ "sans": ["lorica.corp.example.org"] }))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let listing = candidates(&f, &f.admin).await;
    let by_id = |id: &str| {
        listing["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .find(|candidate| candidate["certificate_id"] == id)
            .cloned()
            .expect("listed")
    };
    let same = by_id(&same);
    assert_eq!(same["observed_template"], V2_TEMPLATE_OID);
    assert_eq!(same["template_mismatch"], false);
    let v1 = by_id(&v1);
    assert_eq!(v1["issued_template"], "WebServer");
    assert_eq!(v1["observed_template"], V2_TEMPLATE_OID);
    assert_eq!(v1["template_mismatch"], true);
    let none = by_id(&none);
    assert!(none["issued_template"].is_null());
    assert_eq!(none["template_mismatch"], false);
}

fn adcs_row(
    id: &str,
    template: &str,
    oid: Option<&str>,
    request_id: Option<&str>,
    age_days: i64,
) -> Certificate {
    let now = Utc::now();
    Certificate {
        id: id.to_string(),
        domain: format!("{id}.corp.example.org"),
        san_domains: Vec::new(),
        fingerprint: format!("sha256:{id}"),
        cert_pem: String::new(),
        key_pem: String::new(),
        issuer: "CN=Example Issuing CA".to_string(),
        not_before: now - Duration::days(age_days),
        not_after: now + Duration::days(365),
        is_acme: false,
        acme_auto_renew: true,
        created_at: now,
        acme_method: None,
        acme_dns_provider_id: None,
        adcs_authority_id: Some("authority-1".to_string()),
        adcs_template: Some(template.to_string()),
        adcs_template_oid: oid.map(str::to_string),
        adcs_request_id: request_id.map(str::to_string),
    }
}

/// The observed template is the most recent leaf Lorica requested with
/// the authority's default template: another template, an adopted
/// certificate not yet renewed (no request identifier) and another
/// authority do not count.
#[tokio::test]
async fn the_observed_template_is_the_most_recent_lorica_issuance_with_the_default() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let mut authority = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("authority");
    authority.id = "authority-1".to_string();

    let mut elsewhere = adcs_row("elsewhere", "LoricaWebServer", Some("1.2.9"), Some("9"), 0);
    elsewhere.adcs_authority_id = Some("authority-2".to_string());
    let certs = vec![
        adcs_row("older", "LoricaWebServer", Some("1.2.1"), Some("1"), 20),
        adcs_row("newer", "LoricaWebServer", Some("1.2.2"), Some("2"), 10),
        adcs_row(
            "other-template",
            "OtherTemplate",
            Some("1.2.3"),
            Some("3"),
            1,
        ),
        adcs_row("adopted", "LoricaWebServer", Some("1.2.4"), None, 1),
        adcs_row("no-oid", "LoricaWebServer", None, Some("5"), 1),
        elsewhere,
    ];
    assert_eq!(
        observed_template(&authority, &certs).as_deref(),
        Some("1.2.2")
    );
    assert_eq!(observed_template(&authority, &certs[2..]), None);
}

/// AC #4, #6: adoption sets the references, takes the authority's
/// template and keeps the observed one, takes the auto-renew setting
/// from the request or the authority, issues nothing, leaves the
/// certificate in service as it was, and is audited naming it.
#[tokio::test]
async fn adoption_sets_the_references_and_issues_nothing() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let first = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V1Utf8,
        ),
        &pki.issuing.pem,
    )
    .await;
    let second = upload(
        &f,
        "web02.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web02.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let before = stored(&f, &first).await;
    let operator = f.user("operator-adopt", Role::Operator).await;

    let (status, json) = post(&f, &adopt_path(&first), &operator, None).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let data = &json["data"];
    assert_eq!(data["id"], first);
    assert_eq!(data["source"], "adcs");
    assert!(data["adcs_authority_id"].is_string());
    assert_eq!(data["adcs_template"], "LoricaWebServer");
    assert_eq!(data["adcs_template_oid"], "WebServer");
    assert!(data["adcs_request_id"].is_null());
    assert_eq!(data["acme_auto_renew"], true, "the authority's default");

    let (status, json) = post(
        &f,
        &adopt_path(&second),
        &operator,
        Some(serde_json::json!({ "auto_renew": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["acme_auto_renew"], false);
    assert_eq!(json["data"]["adcs_template_oid"], V2_TEMPLATE_OID);

    let after = stored(&f, &first).await;
    assert_eq!(after.fingerprint, before.fingerprint);
    assert_eq!(after.cert_pem, before.cert_pem);
    assert_eq!(after.key_pem, before.key_pem, "the key stays in service");
    assert_eq!(stub.calls(), 0, "adoption issues nothing");
    assert_eq!(
        candidate_ids(&candidates(&f, &f.admin).await),
        Vec::<String>::new()
    );

    let (status, json) = post(&f, &adopt_path(&first), &operator, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already managed by AD CS"),
        "{json}"
    );
    let (status, json) = post(
        &f,
        &adopt_path(&first),
        &operator,
        Some(serde_json::json!({ "template": "Other" })),
    )
    .await;
    assert!(status.is_client_error(), "{json}");
    let (status, _) = post(&f, &adopt_path("no-such-certificate"), &operator, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let actions = f.audit_actions().await;
    assert_eq!(
        actions,
        vec![
            "adcs.authority.create".to_string(),
            format!("adcs.certificate.adopt:{first}"),
            format!("adcs.certificate.adopt:{second}"),
        ]
    );
}

/// AC #5, #6: reverting clears the authority only, keeps the rest as
/// history and the certificate in service, makes it a candidate again,
/// is audited, and is refused on a certificate that is not AD CS, an
/// unknown one, or one whose renewal is in flight.
#[tokio::test]
async fn reverting_makes_the_certificate_manual_again() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let id = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let operator = f.user("operator-revert", Role::Operator).await;

    let (status, json) = post(&f, &revert_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "a manual certificate: {json}");

    let (status, _) = post(&f, &adopt_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::OK);

    let held = f.state.renewals.begin(&id).expect("free");
    let (status, json) = post(&f, &revert_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{json}");
    assert_eq!(stored(&f, &id).await.source(), CertificateSource::Adcs);
    drop(held);

    let (status, json) = post(&f, &revert_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["data"]["source"], "manual");
    assert!(json["data"]["adcs_authority_id"].is_null());
    assert_eq!(json["data"]["adcs_template"], "LoricaWebServer");
    assert_eq!(json["data"]["adcs_template_oid"], V2_TEMPLATE_OID);
    assert_eq!(
        candidate_ids(&candidates(&f, &f.admin).await),
        vec![id.clone()]
    );

    let (status, _) = post(&f, &revert_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = post(&f, &revert_path("no-such-certificate"), &operator, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // An issued certificate reverts too, and the authority can then go.
    let resp = f
        .issue(serde_json::json!({ "sans": ["lorica.corp.example.org"] }))
        .await;
    let issued = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let (status, _) = post(&f, &revert_path(&issued), &operator, None).await;
    assert_eq!(status, StatusCode::OK);
    let resp = f
        .send("DELETE", crate::adcs::tests::AUTHORITY, &f.admin, None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let actions = f.audit_actions().await;
    let mine: Vec<&String> = actions
        .iter()
        .filter(|action| {
            action.starts_with("adcs.certificate.adopt")
                || action.starts_with("adcs.certificate.revert")
        })
        .collect();
    assert_eq!(
        mine,
        vec![
            &format!("adcs.certificate.adopt:{id}"),
            &format!("adcs.certificate.revert:{id}"),
            &format!("adcs.certificate.revert:{issued}"),
        ]
    );
}

/// D11 and D13: the listing is a Viewer read, adopting and reverting
/// are Operator, and a follower refuses both.
#[tokio::test]
async fn adoption_is_operator_and_control_plane_only() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let mut f = with_authority(&stub, &pki.issuing.pem).await;
    let id = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let viewer = f.user("viewer-adopt", Role::Viewer).await;

    assert_eq!(
        candidate_ids(&candidates(&f, &viewer).await),
        vec![id.clone()]
    );
    let (status, _) = post(&f, &adopt_path(&id), &viewer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = post(&f, &adopt_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(&f, &revert_path(&id), &viewer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    f.state.cluster =
        crate::cluster::ClusterRuntime::Follower(crate::tests::test_follower_runtime());
    for path in [adopt_path(&id), revert_path(&id)] {
        let (status, json) = post(&f, &path, &f.admin, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}: {json}");
    }
    assert_eq!(stored(&f, &id).await.source(), CertificateSource::Adcs);
}

/// IV2: an adopted certificate bound to a route is renewed in place by
/// the loop at its window: same id, route kept, a new certificate
/// requested with the authority's template and the current key type
/// (ECDSA P-256 here, while the authority's default is RSA 2048).
#[tokio::test]
async fn iv2_an_adopted_bound_certificate_is_renewed_in_place_by_the_loop() {
    let stub = StubAuthority::new(issue_v2());
    let pki = pki();
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let name = "web01.corp.example.org";
    let id = upload(
        &f,
        name,
        leaf(&pki.issuing.issuer, &[name], TemplateExtension::V2),
        &pki.issuing.pem,
    )
    .await;
    let resp = f
        .send(
            "POST",
            "/api/v1/routes",
            &f.admin,
            Some(serde_json::json!({ "hostname": name, "certificate_id": id })),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let (status, _) = post(&f, &adopt_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let before = {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&id).expect("read").expect("row");
        cert.not_after = Utc::now() + Duration::days(10);
        store.update_certificate(&cert).expect("into the window");
        cert
    };

    crate::acme::renewal_tick(&f.state, 30, None).await;

    assert_eq!(stub.calls(), 1, "one renewal");
    let after = stored(&f, &id).await;
    assert_ne!(after.fingerprint, before.fingerprint);
    assert_ne!(after.key_pem, before.key_pem);
    assert_eq!(after.source(), CertificateSource::Adcs);
    assert_eq!(after.adcs_template.as_deref(), Some("LoricaWebServer"));
    assert_eq!(after.adcs_request_id.as_deref(), Some("4242"));
    let certificates = f
        .state
        .store
        .lock()
        .await
        .list_certificates()
        .expect("list");
    assert_eq!(certificates.len(), 1, "renewed in place");
    let routes = f.state.store.lock().await.list_routes().expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].certificate_id.as_deref(), Some(id.as_str()));

    let csr_der = stub.last_csr();
    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("csr");
    assert_eq!(
        crate::adcs::renew::generated_key_type(&csr.certification_request_info.subject_pki),
        Ok(lorica_config::models::AdcsKeyType::EcdsaP256)
    );
    let subject = csr.certification_request_info.subject.to_string();
    assert!(subject.contains("O=Example Corp"), "{subject}");
    assert!(subject.contains(&format!("CN={name}")), "{subject}");
}

/// A request on a limiter of its own: the download bucket admits five
/// per window, fewer than this test makes.
async fn unlimited(
    f: &Fixture,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let resp = crate::tests::send(
        &f.state,
        &f.session_store,
        &RateLimiter::new(),
        method,
        uri,
        cookie,
        body,
    )
    .await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Epic 13 D16: once a certificate is AD CS (adopted here), its private
/// key is downloadable by no role, through `key`, `bundle` or the
/// default part; its certificate and chain stay downloadable at the
/// usual floor.
#[tokio::test]
async fn the_key_of_an_adcs_certificate_is_downloaded_by_no_role() {
    let pki = pki();
    let stub = StubAuthority::new(issue_v2());
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let id = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let operator = f.user("operator-d16", Role::Operator).await;
    let viewer = f.user("viewer-d16", Role::Viewer).await;
    let download = |part: &str| format!("/api/v1/certificates/{id}/download{part}");

    let (status, text) = unlimited(&f, "GET", &download("?part=key"), &operator, None).await;
    assert_eq!(status, StatusCode::OK, "a manual key: {text}");
    assert!(text.contains("PRIVATE KEY"));

    let (status, _) = post(&f, &adopt_path(&id), &operator, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored(&f, &id).await.source(), CertificateSource::Adcs);

    for (role, cookie) in [
        ("viewer", viewer.as_str()),
        ("operator", operator.as_str()),
        ("superadmin", f.admin.as_str()),
    ] {
        for part in ["?part=key", "?part=bundle", ""] {
            let (status, text) = unlimited(&f, "GET", &download(part), cookie, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role} {part}: {text}");
            assert!(!text.contains("PRIVATE KEY"), "{role} {part}");
            if role != "viewer" {
                let json: serde_json::Value = serde_json::from_str(&text).expect("JSON error");
                assert_eq!(
                    json["error"]["code"],
                    crate::certificates::ADCS_KEY_NOT_EXPORTABLE,
                    "{role} {part}"
                );
            }
        }
        for part in ["?part=cert", "?part=chain"] {
            let (status, text) = unlimited(&f, "GET", &download(part), cookie, None).await;
            if role == "viewer" {
                assert_eq!(status, StatusCode::FORBIDDEN, "{role} {part}");
            } else {
                assert_eq!(status, StatusCode::OK, "{role} {part}: {text}");
                assert!(text.contains("BEGIN CERTIFICATE"), "{role} {part}");
                assert!(!text.contains("PRIVATE KEY"), "{role} {part}");
            }
        }
    }
}

/// Pen L2: the PEM, key and domain of an AD CS certificate cannot be
/// replaced through the generic update, which would bypass the
/// signature check adoption makes; its auto-renew setting can be
/// changed, and reverting it makes the replacement an ordinary update.
#[tokio::test]
async fn the_pem_of_an_adcs_certificate_is_not_replaced_through_the_update() {
    let pki = pki();
    let stub = StubAuthority::new(issue_v2());
    let f = with_authority(&stub, &pki.issuing.pem).await;
    let id = upload(
        &f,
        "web01.corp.example.org",
        leaf(
            &pki.issuing.issuer,
            &["web01.corp.example.org"],
            TemplateExtension::V2,
        ),
        &pki.issuing.pem,
    )
    .await;
    let (status, _) = post(&f, &adopt_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let before: Certificate = stored(&f, &id).await;
    let (foreign_pem, foreign_key) = leaf(
        &pki.forged.issuer,
        &["web01.corp.example.org"],
        TemplateExtension::V2,
    );
    let path = format!("/api/v1/certificates/{id}");

    for change in [
        serde_json::json!({ "cert_pem": foreign_pem, "key_pem": foreign_key }),
        serde_json::json!({ "domain": "dc01.corp.example.org" }),
        serde_json::json!({ "key_pem": crate::tests::TEST_KEY_RSA_PEM }),
    ] {
        let (status, text) = unlimited(&f, "PUT", &path, &f.admin, Some(change.clone())).await;
        assert_eq!(status, StatusCode::CONFLICT, "{change}: {text}");
        let json: serde_json::Value = serde_json::from_str(&text).expect("JSON error");
        assert_eq!(
            json["error"]["code"],
            crate::certificates::ADCS_CERTIFICATE_MANAGED
        );
    }
    let after: Certificate = stored(&f, &id).await;
    assert_eq!(after.fingerprint, before.fingerprint);
    assert_eq!(after.domain, before.domain);
    assert_eq!(after.source(), CertificateSource::Adcs);

    let (status, text) = unlimited(
        &f,
        "PUT",
        &path,
        &f.admin,
        Some(serde_json::json!({ "acme_auto_renew": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(!stored(&f, &id).await.acme_auto_renew);

    let (status, _) = post(&f, &revert_path(&id), &f.admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, text) = unlimited(
        &f,
        "PUT",
        &path,
        &f.admin,
        Some(serde_json::json!({ "cert_pem": foreign_pem, "key_pem": foreign_key })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a manual certificate: {text}");
}
