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

//! Tests for the AD CS authority endpoints (Story 13.2), driven
//! through the real router with the client behind [`AdcsClient`], so
//! no KDC is needed. What the client itself reports for a wrong
//! password, an unreachable KDC, an untrusted endpoint or a missing
//! binding is `lorica-adcs`'s and its harness's to prove; here the
//! handler is held to passing the step and the text through verbatim
//! and to opening the breaker on exactly one of them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use lorica_adcs::{AdcsError, CesParams, Secret, TicketFailure};
use lorica_config::models::{Certificate, Role};
use lorica_config::{ConfigStore, EncryptionKey};
use tokio::sync::Mutex;

use super::{AdcsClient, AdcsRuntime};
use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::AppState;
use crate::tests::{
    body_json, create_user_and_login, send, setup_admin_and_login, test_follower_runtime,
    test_state,
};

pub(in crate::adcs) const AUTHORITY: &str = "/api/v1/adcs/authority";
pub(in crate::adcs) const TEST: &str = "/api/v1/adcs/authority/test";
pub(in crate::adcs) const PASSWORD: &str = "example-only-password-1";
const NEW_PASSWORD: &str = "example-only-password-2";

/// A stand-in for the authority: answers every connection test with
/// what `answer` builds, and counts the calls.
struct StubClient {
    calls: AtomicUsize,
    /// How long the first call takes, as a KDC exchange outliving the
    /// operation timeout would; later calls answer at once.
    first_call_delay: Duration,
    answer: Box<dyn Fn() -> Result<(), AdcsError> + Send + Sync>,
}

impl StubClient {
    fn new(answer: impl Fn() -> Result<(), AdcsError> + Send + Sync + 'static) -> Arc<StubClient> {
        StubClient::slow_once(Duration::ZERO, answer)
    }

    fn slow_once(
        first_call_delay: Duration,
        answer: impl Fn() -> Result<(), AdcsError> + Send + Sync + 'static,
    ) -> Arc<StubClient> {
        Arc::new(StubClient {
            calls: AtomicUsize::new(0),
            first_call_delay,
            answer: Box::new(answer),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AdcsClient for StubClient {
    async fn test_connection(
        &self,
        params: &CesParams,
        password: &Secret,
    ) -> Result<(), AdcsError> {
        assert_eq!(params.realm.as_str(), "CORP.EXAMPLE.ORG");
        assert!(
            password.expose(|text: &str| !text.is_empty()),
            "the stored password reaches the client"
        );
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            tokio::time::sleep(self.first_call_delay).await;
        }
        (self.answer)()
    }

    async fn enroll(
        &self,
        _params: &CesParams,
        _password: &Secret,
        _csr_der: &[u8],
    ) -> Result<lorica_adcs::EnrollOutcome, AdcsError> {
        panic!("the connection-test stub is never asked to enroll");
    }
}

fn rejected_credential() -> AdcsError {
    AdcsError::Ticket {
        principal: "svc-lorica@CORP.EXAMPLE.ORG".to_string(),
        failure: TicketFailure::CredentialRejected,
        kdc_error_code: Some(24),
        minor_status: 0,
        message: "Preauthentication failed".to_string(),
    }
}

fn unreachable_kdc() -> AdcsError {
    AdcsError::Ticket {
        principal: "svc-lorica@CORP.EXAMPLE.ORG".to_string(),
        failure: TicketFailure::KdcUnreachable,
        kdc_error_code: None,
        minor_status: 0,
        message: "Cannot find KDC for realm \"CORP.EXAMPLE.ORG\"".to_string(),
    }
}

pub(in crate::adcs) struct Fixture {
    pub(in crate::adcs) state: AppState,
    pub(in crate::adcs) session_store: SessionStore,
    pub(in crate::adcs) rate_limiter: RateLimiter,
    pub(in crate::adcs) admin: String,
    // Held for the data directory's lifetime.
    _data_dir: tempfile::TempDir,
}

/// A state whose store holds an encryption key (the API's always does;
/// the shared test state's does not, and the store refuses to keep the
/// password in clear), with an audit log and a data directory of its
/// own.
pub(in crate::adcs) async fn fixture(
    client: Arc<impl AdcsClient + 'static>,
    alerts: Option<lorica_notify::AlertSender>,
) -> Fixture {
    let (mut state, _, rate_limiter) = test_state().await;
    let key: EncryptionKey = EncryptionKey::generate().expect("test setup: key");
    let store = Arc::new(Mutex::new(
        ConfigStore::open_in_memory_with_key(key).expect("test setup: keyed store"),
    ));
    state.store = Arc::clone(&store);
    let session_store: SessionStore = SessionStore::new(store).await;
    let data_dir: tempfile::TempDir = tempfile::tempdir().expect("test setup: tempdir");
    state.data_dir = data_dir.path().to_path_buf();
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    state.adcs = AdcsRuntime::with_client(client, alerts);
    let admin: String = setup_admin_and_login(&state, &session_store, &rate_limiter).await;
    Fixture {
        state,
        session_store,
        rate_limiter,
        admin,
        _data_dir: data_dir,
    }
}

impl Fixture {
    pub(in crate::adcs) async fn send(
        &self,
        method: &str,
        uri: &str,
        cookie: &str,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        send(
            &self.state,
            &self.session_store,
            &self.rate_limiter,
            method,
            uri,
            cookie,
            body,
        )
        .await
    }

    /// A connection test on a limiter of its own, for tests that run
    /// more of them than the `adcs_test` bucket admits.
    async fn test_unlimited(&self) -> axum::response::Response {
        send(
            &self.state,
            &self.session_store,
            &RateLimiter::new(),
            "POST",
            TEST,
            &self.admin,
            None,
        )
        .await
    }

    pub(in crate::adcs) async fn user(&self, name: &str, role: Role) -> String {
        create_user_and_login(
            &self.state,
            &self.session_store,
            &self.rate_limiter,
            name,
            role,
        )
        .await
    }

    pub(in crate::adcs) async fn create_authority(&self) -> serde_json::Value {
        let resp = self
            .send("PUT", AUTHORITY, &self.admin, Some(body(Some(PASSWORD))))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        body_json(resp).await
    }

    pub(in crate::adcs) async fn stored_password(&self) -> Option<String> {
        self.state
            .store
            .lock()
            .await
            .get_adcs_password()
            .expect("read the password")
    }

    pub(in crate::adcs) async fn audit_actions(&self) -> Vec<String> {
        let log_store = self.state.log_store.clone().expect("log store");
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");
        let (rows, _total) = log_store
            .query_audit(&crate::audit::AuditQuery {
                operator: None,
                action_prefix: Some("adcs.".to_string()),
                from: None,
                to: None,
                limit: 100,
                before_id: None,
                node_id: None,
            })
            .expect("audit query");
        let mut actions: Vec<String> = rows.into_iter().map(|row| row.action).collect();
        actions.reverse();
        actions
    }

    fn krb5_conf(&self) -> std::path::PathBuf {
        lorica_adcs::krb5_config_path(&self.state.data_dir)
    }

    /// Handlers answer 504 after `deadline` instead of the production
    /// one.
    pub(in crate::adcs) fn with_handler_deadline(mut self, deadline: Duration) -> Fixture {
        self.state.adcs = self.state.adcs.clone().with_handler_deadline(deadline);
        self
    }

    /// Waits until no AD CS operation holds the guard.
    pub(in crate::adcs) async fn wait_until_idle(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.state.adcs.guard().try_acquire().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the operation ends");
    }
}

pub(in crate::adcs) fn body(password: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "endpoint": "https://ces.corp.example.org/CA_CES_Kerberos/service.svc/CES",
        "realm": "CORP.EXAMPLE.ORG",
        "kdcs": ["kdc1.corp.example.org", "kdc2.corp.example.org:88"],
        "principal": "svc-lorica",
        "default_template": "LoricaWebServer",
        "default_key_type": "rsa2048",
        "subject": { "country": "fr", "organization": "Example Corp" },
        "allowed_suffixes": ["corp.example.org"],
        "auto_renew_default": true,
    });
    if let Some(password) = password {
        body["password"] = serde_json::json!(password);
    }
    body
}

fn always_ok() -> Arc<StubClient> {
    StubClient::new(|| Ok(()))
}

#[tokio::test]
async fn the_read_answers_null_until_an_authority_exists() {
    let f = fixture(always_ok(), None).await;
    let viewer = f.user("viewer-adcs", Role::Viewer).await;
    let resp = f.send("GET", AUTHORITY, &viewer, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["data"]["authority"].is_null(), "{json}");
    assert_eq!(json["data"]["managed_on_control_plane"], false);
}

#[tokio::test]
async fn creation_needs_a_password_which_is_stored_and_never_returned() {
    let f = fixture(always_ok(), None).await;

    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(body(None))).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .is_none());

    let created = f.create_authority().await;
    let text = created.to_string();
    assert!(!text.contains(PASSWORD), "{text}");
    assert!(created["data"].get("password").is_none(), "{text}");
    assert_eq!(created["data"]["password_set"], true);
    assert_eq!(created["data"]["realm"], "CORP.EXAMPLE.ORG");
    assert_eq!(created["data"]["subject"]["country"], "FR");
    assert_eq!(f.stored_password().await.as_deref(), Some(PASSWORD));

    let operator = f.user("operator-adcs", Role::Operator).await;
    let resp = f.send("GET", AUTHORITY, &operator, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let read = body_json(resp).await;
    let text = read.to_string();
    assert!(!text.contains(PASSWORD), "{text}");
    assert_eq!(read["data"]["authority"]["password_set"], true);
    assert_eq!(read["data"]["authority"]["id"], created["data"]["id"]);

    let conf = std::fs::read_to_string(f.krb5_conf()).expect("the krb5.conf is written");
    assert!(conf.contains("default_realm = CORP.EXAMPLE.ORG"), "{conf}");
    assert!(conf.contains("kdc = kdc2.corp.example.org:88"), "{conf}");
    assert!(
        conf.contains(&format!(
            "request_timeout = {}s",
            super::KDC_REQUEST_TIMEOUT_SECS
        )),
        "{conf}"
    );
    assert_eq!(f.audit_actions().await, vec!["adcs.authority.create"]);
}

/// IV1, second half, for every identity field of D11.
#[tokio::test]
async fn an_identity_change_without_a_password_is_refused_and_keeps_the_stored_one() {
    let f = fixture(always_ok(), None).await;
    f.create_authority().await;

    let changes: [(&str, serde_json::Value); 5] = [
        (
            "endpoint",
            serde_json::json!("https://ces2.corp.example.org/CA_CES_Kerberos/service.svc/CES"),
        ),
        ("realm", serde_json::json!("LAB.EXAMPLE.ORG")),
        ("kdcs", serde_json::json!(["kdc9.corp.example.org"])),
        ("principal", serde_json::json!("svc-other")),
        // The trust bundle decides which endpoint the tokens go to.
        (
            "endpoint_ca_pem",
            serde_json::json!(crate::tests::TEST_CERT_RSA_PEM),
        ),
    ];
    for (field, value) in &changes {
        let mut changed = body(None);
        changed[*field] = value.clone();
        let resp = f.send("PUT", AUTHORITY, &f.admin, Some(changed)).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        let message = body_json(resp).await["error"]["message"].to_string();
        assert!(message.contains("new one"), "{field}: {message}");
        assert_eq!(
            f.stored_password().await.as_deref(),
            Some(PASSWORD),
            "{field}"
        );
        let stored = f
            .state
            .store
            .lock()
            .await
            .get_adcs_authority()
            .expect("read")
            .expect("row");
        assert_eq!(stored.realm, "CORP.EXAMPLE.ORG", "{field}");
        assert_eq!(stored.principal, "svc-lorica", "{field}");
        assert_eq!(stored.endpoint_ca_pem, None, "{field}");
    }

    let mut changed = body(Some(NEW_PASSWORD));
    changed["realm"] = serde_json::json!("LAB.EXAMPLE.ORG");
    changed["principal"] = serde_json::json!("svc-lorica@LAB.EXAMPLE.ORG");
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(changed)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(f.stored_password().await.as_deref(), Some(NEW_PASSWORD));
    let conf = std::fs::read_to_string(f.krb5_conf()).expect("krb5.conf");
    assert!(conf.contains("default_realm = LAB.EXAMPLE.ORG"), "{conf}");
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.update:principal,realm,password",
        ]
    );
}

#[tokio::test]
async fn a_change_outside_the_identity_keeps_the_password_and_names_the_fields() {
    let f = fixture(always_ok(), None).await;
    f.create_authority().await;

    let mut changed = body(None);
    changed["allowed_suffixes"] = serde_json::json!(["corp.example.org", "lab.example.org"]);
    changed["default_template"] = serde_json::json!("OtherTemplate");
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(changed)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["allowed_suffixes"][1], "lab.example.org");
    assert_eq!(f.stored_password().await.as_deref(), Some(PASSWORD));

    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(body(None))).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "reverting both fields is an update too"
    );
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.update:allowed_suffixes,allowed_templates,default_template",
            "adcs.authority.update:allowed_suffixes,allowed_templates,default_template",
        ]
    );
}

#[tokio::test]
async fn every_invalid_field_is_refused_and_nothing_is_stored() {
    let f = fixture(always_ok(), None).await;
    let too_many_kdcs: Vec<String> = (0..=super::MAX_KDCS)
        .map(|n| format!("kdc{n}.corp.example.org"))
        .collect();
    let too_many_templates: Vec<String> = (0..lorica_config::models::ADCS_ALLOWED_TEMPLATES_MAX)
        .map(|n| format!("Template{n}"))
        .collect();
    let cases: [(&str, serde_json::Value); 17] = [
        (
            "endpoint",
            serde_json::json!("http://ces.corp.example.org/CES"),
        ),
        ("endpoint", serde_json::json!("https://192.0.2.10/CES")),
        (
            "endpoint",
            serde_json::json!("https://user:pw@ces.corp.example.org/CES"),
        ),
        ("realm", serde_json::json!("corp.example.org")),
        (
            "realm",
            serde_json::json!("CORP.EXAMPLE.ORG\n[libdefaults]"),
        ),
        (
            "kdcs",
            serde_json::json!(["kdc.corp.example.org }\n kdc = evil"]),
        ),
        ("kdcs", serde_json::json!(["kdc.corp.example.org:0"])),
        ("principal", serde_json::json!("svc lorica")),
        (
            "principal",
            serde_json::json!("svc-lorica@OTHER.EXAMPLE.ORG"),
        ),
        (
            "allowed_suffixes",
            serde_json::json!(["*.corp.example.org"]),
        ),
        ("allowed_suffixes", serde_json::json!([])),
        ("endpoint_ca_pem", serde_json::json!("not a certificate")),
        ("kdcs", serde_json::json!(too_many_kdcs)),
        ("allowed_templates", serde_json::json!(["Web\nServer"])),
        ("allowed_templates", serde_json::json!(["  "])),
        ("allowed_templates", serde_json::json!(too_many_templates)),
        ("default_template", serde_json::json!("Web\u{7}Server")),
    ];
    for (field, value) in &cases {
        let mut invalid = body(Some(PASSWORD));
        invalid[*field] = value.clone();
        let resp = f.send("PUT", AUTHORITY, &f.admin, Some(invalid)).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field} = {value}"
        );
    }
    let mut blank_template = body(Some(PASSWORD));
    blank_template["default_template"] = serde_json::json!("  ");
    let resp = f
        .send("PUT", AUTHORITY, &f.admin, Some(blank_template))
        .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .is_none());
    assert!(!f.krb5_conf().exists());

    let mut with_bundle = body(Some(PASSWORD));
    with_bundle["endpoint_ca_pem"] = serde_json::json!(crate::tests::TEST_CERT_RSA_PEM);
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(with_bundle)).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a real certificate is accepted"
    );
}

#[tokio::test]
async fn delete_is_refused_with_the_certificates_that_use_the_authority() {
    let f = fixture(always_ok(), None).await;
    let created = f.create_authority().await;
    let authority_id = created["data"]["id"].as_str().expect("id").to_string();
    let now = chrono::Utc::now();
    let certificate = Certificate {
        id: "issued-1".to_string(),
        domain: "web.corp.example.org".to_string(),
        san_domains: vec!["web.corp.example.org".to_string()],
        fingerprint: "sha256:issued-1".to_string(),
        cert_pem: crate::tests::TEST_CERT_RSA_PEM.to_string(),
        key_pem: crate::tests::TEST_KEY_RSA_PEM.to_string(),
        issuer: "CN=Issuing CA".to_string(),
        not_before: now,
        not_after: now + chrono::Duration::days(365),
        is_acme: false,
        acme_auto_renew: true,
        created_at: now,
        acme_method: None,
        acme_dns_provider_id: None,
        adcs_authority_id: Some(authority_id.clone()),
        adcs_template: Some("LoricaWebServer".to_string()),
        adcs_template_oid: None,
        adcs_request_id: Some("4242".to_string()),
    };
    f.state
        .store
        .lock()
        .await
        .create_certificate(&certificate)
        .expect("test setup: certificate");

    let resp = f.send("DELETE", AUTHORITY, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let message = body_json(resp).await["error"]["message"].to_string();
    assert!(message.contains("issued-1"), "{message}");
    assert!(f.krb5_conf().exists());

    {
        let store = f.state.store.lock().await;
        let mut manual = store
            .get_certificate("issued-1")
            .expect("read")
            .expect("row");
        manual.adcs_authority_id = None;
        store.update_certificate(&manual).expect("revert to manual");
    }
    let resp = f.send("DELETE", AUTHORITY, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .is_none());
    assert!(
        !f.krb5_conf().exists(),
        "the krb5.conf goes with the authority"
    );
    let resp = f.send("DELETE", AUTHORITY, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(resp).await["error"]["code"],
        super::error::NOT_CONFIGURED.code,
        "the same answer as every other endpoint without an authority"
    );
    assert_eq!(
        f.audit_actions().await,
        vec!["adcs.authority.create", "adcs.authority.delete"]
    );
}

/// IV1, first half: every write refused to an Operator, the suffix
/// list included, and the connection test admitted.
#[tokio::test]
async fn an_operator_tests_the_authority_and_writes_none_of_it() {
    let client = always_ok();
    let f = fixture(Arc::clone(&client), None).await;
    f.create_authority().await;
    let operator = f.user("operator-adcs", Role::Operator).await;
    let viewer = f.user("viewer-adcs", Role::Viewer).await;

    let mut suffixes_only = body(None);
    suffixes_only["allowed_suffixes"] = serde_json::json!(["example.org"]);
    for (method, payload) in [
        ("PUT", Some(suffixes_only)),
        ("PUT", Some(body(Some(NEW_PASSWORD)))),
        ("DELETE", None),
    ] {
        let resp = f.send(method, AUTHORITY, &operator, payload).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
    }
    let resp = f.send("POST", TEST, &viewer, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let stored = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row");
    assert_eq!(stored.allowed_suffixes[0].as_str(), "corp.example.org");
    assert_eq!(f.stored_password().await.as_deref(), Some(PASSWORD));

    let resp = f.send("POST", TEST, &operator, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["ok"], true);
    assert!(json["data"]["step"].is_null());
    assert_eq!(client.calls(), 1);
    assert_eq!(
        f.audit_actions().await,
        vec!["adcs.authority.create", "adcs.authority.test.ok"]
    );
}

#[tokio::test]
async fn the_connection_test_is_rate_limited_in_its_own_bucket() {
    let client = always_ok();
    let f = fixture(Arc::clone(&client), None).await;
    f.create_authority().await;
    for _ in 0..crate::server::RL_ACME_PROVISION {
        let resp = f.send("POST", TEST, &f.admin, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = f.send("POST", TEST, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        client.calls(),
        crate::server::RL_ACME_PROVISION as usize,
        "a refused test reaches no KDC"
    );
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(body(None))).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the writes do not share the test's bucket"
    );
}

#[tokio::test]
async fn a_second_operation_is_refused_while_one_runs() {
    let client = always_ok();
    let f = fixture(Arc::clone(&client), None).await;
    f.create_authority().await;

    let permit = f
        .state
        .adcs
        .guard()
        .try_acquire()
        .expect("nothing else runs");
    for (method, uri, payload) in [
        ("POST", TEST, None),
        ("PUT", AUTHORITY, Some(body(Some(NEW_PASSWORD)))),
        ("DELETE", AUTHORITY, None),
    ] {
        let resp = f.send(method, uri, &f.admin, payload).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "{method} {uri}");
        let error = body_json(resp).await["error"].clone();
        assert_eq!(error["code"], super::error::BUSY.code, "{method} {uri}");
        let message = error["message"].to_string();
        assert!(message.contains("already running"), "{message}");
    }
    assert_eq!(client.calls(), 0);
    assert_eq!(f.stored_password().await.as_deref(), Some(PASSWORD));

    drop(permit);
    let resp = f.send("POST", TEST, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(client.calls(), 1);
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.test.refused:busy",
            "adcs.authority.test.ok",
        ]
    );
}

const SLOW_OPERATION: Duration = Duration::from_millis(1500);
const SHORT_HANDLER_DEADLINE: Duration = Duration::from_millis(200);

/// D15: an operation that outlives the handler's deadline is answered
/// 504 and keeps the guard until it ends, so a request in the meantime
/// is refused rather than started beside it; its outcome is audited by
/// the task when it ends, and the next request runs normally.
#[tokio::test]
async fn an_operation_past_the_handler_deadline_keeps_the_guard_until_it_ends() {
    let client = StubClient::slow_once(SLOW_OPERATION, || Ok(()));
    let f = fixture(Arc::clone(&client), None)
        .await
        .with_handler_deadline(SHORT_HANDLER_DEADLINE);
    f.create_authority().await;

    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "gateway_timeout", "{json}");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("still finishing"),
        "{json}"
    );

    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let message = body_json(resp).await["error"]["message"].to_string();
    assert!(message.contains("already running"), "{message}");
    assert_eq!(client.calls(), 1, "the refused request reached no KDC");

    f.wait_until_idle().await;
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.test.refused:busy",
            "adcs.authority.test.ok",
        ],
        "the slow test's outcome is audited once it ends"
    );

    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["data"]["ok"], true);
    assert_eq!(client.calls(), 2);
}

/// The breaker is not lost with the 504: a slow operation that ends on
/// a rejected credential opens it from its own task.
#[tokio::test]
async fn a_rejected_credential_past_the_handler_deadline_still_opens_the_breaker() {
    let client = StubClient::slow_once(SLOW_OPERATION, || Err(rejected_credential()));
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = fixture(Arc::clone(&client), Some(alerts))
        .await
        .with_handler_deadline(SHORT_HANDLER_DEADLINE);
    f.create_authority().await;

    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    f.wait_until_idle().await;

    let stored = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row");
    assert!(stored.is_failed());
    assert_eq!(stored.failed_kdc_code, Some(24));
    let alert = received.try_recv().expect("the entry alert");
    assert_eq!(
        alert.alert_type,
        lorica_notify::events::AlertType::AdcsAuthorityFailed
    );
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.test.failed:ticket_acquisition",
            "adcs.authority.failed_state.enter:ticket_acquisition",
        ]
    );
    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(client.calls(), 1);
}

/// IV2's breaker half and AC #4: one rejected credential opens the
/// breaker, raises one alert, is persisted, refuses the next attempt
/// before it reaches the KDC, and only a password write closes it.
#[tokio::test]
async fn a_rejected_credential_opens_the_breaker_once_and_a_password_write_closes_it() {
    let client = StubClient::new(|| Err(rejected_credential()));
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = fixture(Arc::clone(&client), Some(alerts)).await;
    f.create_authority().await;

    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["ok"], false);
    assert_eq!(json["data"]["step"], "ticket_acquisition");
    assert_eq!(json["data"]["message"], rejected_credential().to_string());
    assert_eq!(json["data"]["authority_failed"], true);

    let resp = f.send("GET", AUTHORITY, &f.admin, None).await;
    let read = body_json(resp).await;
    assert!(
        read["data"]["authority"]["failed_since"].is_string(),
        "{read}"
    );
    assert_eq!(
        read["data"]["authority"]["failed_step"],
        "ticket_acquisition"
    );
    assert_eq!(read["data"]["authority"]["failed_kdc_code"], 24);

    for _ in 0..2 {
        let resp = f.test_unlimited().await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let error = body_json(resp).await["error"].clone();
        assert_eq!(error["code"], super::error::FAILED_STATE.code);
        let message = error["message"].as_str().unwrap_or_default().to_string();
        assert!(message.contains("failed state"), "{message}");
        assert!(
            !message.starts_with("conflict"),
            "the message is built from the condition, not another error's text: {message}"
        );
    }
    assert_eq!(client.calls(), 1, "the breaker spends no further attempt");

    let alert = received.try_recv().expect("one alert on entry");
    assert_eq!(
        alert.alert_type,
        lorica_notify::events::AlertType::AdcsAuthorityFailed
    );
    assert_eq!(
        alert.details.get("kdc_code").map(String::as_str),
        Some("24")
    );
    assert!(
        matches!(
            received.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "exactly one alert per entry"
    );

    let mut edit = body(None);
    edit["default_template"] = serde_json::json!("OtherTemplate");
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(edit)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let still_failed = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row");
    assert!(
        still_failed.is_failed(),
        "an edit without a password keeps it shut"
    );

    let resp = f
        .send("PUT", AUTHORITY, &f.admin, Some(body(Some(NEW_PASSWORD))))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["data"]["failed_since"].is_null(), "{json}");
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.authority.test.failed:ticket_acquisition",
            "adcs.authority.failed_state.enter:ticket_acquisition",
            "adcs.authority.test.refused:failed_state",
            "adcs.authority.test.refused:failed_state",
            "adcs.authority.update:allowed_templates,default_template",
            "adcs.authority.update:allowed_templates,default_template,password",
            "adcs.authority.failed_state.exit",
        ]
    );
}

#[tokio::test]
async fn other_failures_leave_the_breaker_shut() {
    let answers = std::sync::Mutex::new(vec![
        unreachable_kdc(),
        AdcsError::Tls {
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        },
    ]);
    let client = StubClient::new(move || {
        Err(answers
            .lock()
            .expect("test answers")
            .pop()
            .unwrap_or_else(unreachable_kdc))
    });
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = fixture(Arc::clone(&client), Some(alerts)).await;
    f.create_authority().await;

    for expected_step in ["tls", "kdc_discovery"] {
        let resp = f.test_unlimited().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["data"]["step"], expected_step);
        assert_eq!(json["data"]["authority_failed"], false);
    }
    assert_eq!(client.calls(), 2, "the second test was not refused");
    let stored = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row");
    assert!(!stored.is_failed());
    assert!(received.try_recv().is_err(), "no alert");
}

/// Story 13.1 AC #8 names the step; the test shows it as it is.
#[tokio::test]
async fn the_failing_step_and_text_reach_the_caller_verbatim() {
    let errors: Vec<fn() -> AdcsError> = vec![
        unreachable_kdc as fn() -> AdcsError,
        || AdcsError::Tls {
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        },
        || AdcsError::ChannelBindingAlgorithm {
            oid: "1.2.840.113549.1.1.10".to_string(),
        },
        || AdcsError::Spnego {
            reason: "the endpoint refused the token with 401".to_string(),
        },
        || AdcsError::MutualAuth {
            reason: "no response token".to_string(),
        },
        || AdcsError::Timeout {
            after: Duration::from_secs(120),
        },
    ];
    for make in errors {
        let f = fixture(StubClient::new(move || Err(make())), None).await;
        f.create_authority().await;
        let resp = f.test_unlimited().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let expected = make();
        assert_eq!(json["data"]["step"], expected.step().as_str());
        assert_eq!(json["data"]["message"], expected.to_string());
        assert_eq!(
            f.audit_actions().await.last().map(String::as_str),
            Some(format!("adcs.authority.test.failed:{}", expected.step().as_str()).as_str())
        );
    }
}

/// The connection test refuses a missing authority with the code every
/// AD CS endpoint answers it with.
#[tokio::test]
async fn a_test_without_an_authority_is_refused_as_not_configured_and_audited() {
    let client = always_ok();
    let f = fixture(Arc::clone(&client), None).await;
    let resp = f.send("POST", TEST, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(resp).await["error"]["code"],
        super::error::NOT_CONFIGURED.code
    );
    assert_eq!(client.calls(), 0);
    assert_eq!(
        f.audit_actions().await,
        vec!["adcs.authority.test.refused:not_configured"]
    );
}

/// D13: a follower holds no authority, so it shows none, and every
/// write and the test are refused before reaching a handler.
#[tokio::test]
async fn a_follower_says_the_authority_is_managed_on_the_control_plane() {
    let client = always_ok();
    let mut f = fixture(Arc::clone(&client), None).await;
    f.create_authority().await;
    f.state.cluster = crate::cluster::ClusterRuntime::Follower(test_follower_runtime());

    let resp = f.send("GET", AUTHORITY, &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["managed_on_control_plane"], true);
    assert!(json["data"]["authority"].is_null(), "{json}");

    for (method, uri, payload) in [
        ("PUT", AUTHORITY, Some(body(Some(NEW_PASSWORD)))),
        ("DELETE", AUTHORITY, None),
        ("POST", TEST, None),
    ] {
        let resp = f.send(method, uri, &f.admin, payload).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "{method} {uri}");
    }
    assert_eq!(client.calls(), 0);
    assert_eq!(f.stored_password().await.as_deref(), Some(PASSWORD));
}

#[tokio::test]
async fn the_import_response_carries_the_import_warnings() {
    let f = fixture(always_ok(), None).await;
    let now = chrono::Utc::now();
    let toml_content = {
        let source = ConfigStore::open_in_memory().expect("test setup: source store");
        source
            .create_certificate(&Certificate {
                id: "orphan".to_string(),
                domain: "web.corp.example.org".to_string(),
                san_domains: vec!["web.corp.example.org".to_string()],
                fingerprint: "sha256:orphan".to_string(),
                cert_pem: crate::tests::TEST_CERT_RSA_PEM.to_string(),
                key_pem: crate::tests::TEST_KEY_RSA_PEM.to_string(),
                issuer: "CN=Issuing CA".to_string(),
                not_before: now,
                not_after: now + chrono::Duration::days(365),
                is_acme: false,
                acme_auto_renew: true,
                created_at: now,
                acme_method: None,
                acme_dns_provider_id: None,
                adcs_authority_id: Some("adcs-elsewhere".to_string()),
                adcs_template: Some("LoricaWebServer".to_string()),
                adcs_template_oid: None,
                adcs_request_id: None,
            })
            .expect("test setup: certificate");
        // The export redacts private keys and the import refuses a
        // redacted one, so the key goes back in as an operator would
        // put it; a JSON string literal is a valid TOML basic string.
        let exported: String =
            lorica_config::export::export_to_toml(&source).expect("test setup: export");
        let redacted_key: &str = "key_pem = \"**REDACTED**\"";
        assert!(exported.contains(redacted_key), "{exported}");
        exported.replace(
            redacted_key,
            &format!(
                "key_pem = {}",
                serde_json::to_string(crate::tests::TEST_KEY_RSA_PEM).expect("test setup")
            ),
        )
    };

    let resp = f
        .send(
            "POST",
            "/api/v1/config/import",
            &f.admin,
            Some(serde_json::json!({ "toml_content": toml_content })),
        )
        .await;
    let status = resp.status();
    let json = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let warnings = json["data"]["warnings"].as_array().expect("warnings array");
    assert_eq!(warnings.len(), 1, "{json}");
    assert!(
        warnings[0]
            .as_str()
            .unwrap_or_default()
            .contains("adcs-elsewhere"),
        "{json}"
    );
}

/// A write that leaves `issuing_ca_pem` out keeps the stored one, which
/// an issuance may have learned since the form was loaded; a blank one
/// clears it.
#[tokio::test]
async fn a_write_without_the_issuing_ca_keeps_it_and_a_blank_one_clears_it() {
    let f = fixture(always_ok(), None).await;
    let mut with_ca = body(Some(PASSWORD));
    with_ca["issuing_ca_pem"] = serde_json::json!(crate::tests::TEST_CERT_RSA_PEM);
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(with_ca)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(stored_issuing_ca(&f).await.is_some());

    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(body(None))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        stored_issuing_ca(&f).await.is_some(),
        "an absent field keeps it"
    );

    let mut blank = body(None);
    blank["issuing_ca_pem"] = serde_json::json!("");
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(blank)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        stored_issuing_ca(&f).await.is_none(),
        "a blank field clears it"
    );
}

async fn stored_issuing_ca(f: &Fixture) -> Option<String> {
    f.state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row")
        .issuing_ca_pem
}

/// The `krb5.conf` an operation needs is written when it differs from
/// the rendering, and only then.
#[tokio::test]
async fn an_operation_rewrites_the_krb5_conf_only_when_it_changed() {
    let f = fixture(always_ok(), None).await;
    f.create_authority().await;
    let path = f.krb5_conf();
    std::fs::write(&path, b"stale").expect("test setup: stale file");
    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rendered = std::fs::read(&path).expect("read");
    assert_ne!(rendered, b"stale".to_vec(), "a stale file is rewritten");
    let modified = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .expect("mtime");
    std::thread::sleep(Duration::from_millis(20));
    let resp = f.test_unlimited().await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime"),
        modified,
        "an unchanged file is not written again"
    );
}

/// D18: every role learns that an authority exists, its suffixes and
/// its failed state; only Operators and SuperAdmins learn how it is
/// reached.
#[tokio::test]
async fn viewers_see_the_summary_and_operators_the_connection_details() {
    let f = fixture(always_ok(), None).await;
    let mut with_ca = body(Some(PASSWORD));
    with_ca["issuing_ca_pem"] = serde_json::json!(crate::tests::TEST_CERT_RSA_PEM);
    with_ca["allowed_templates"] = serde_json::json!(["LoricaWebServerEcdsa"]);
    let resp = f.send("PUT", AUTHORITY, &f.admin, Some(with_ca)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    f.state
        .store
        .lock()
        .await
        .set_adcs_failed("ticket_acquisition", Some(24))
        .expect("test setup: failed state");

    let viewer = f.user("viewer-d18", Role::Viewer).await;
    let operator = f.user("operator-d18", Role::Operator).await;
    let readers: [(&str, &str, bool); 3] = [
        ("viewer", viewer.as_str(), false),
        ("operator", operator.as_str(), true),
        ("superadmin", f.admin.as_str(), true),
    ];
    for (role, cookie, sees_details) in readers {
        let resp = f.send("GET", AUTHORITY, cookie, None).await;
        assert_eq!(resp.status(), StatusCode::OK, "{role}");
        let json = body_json(resp).await;
        let data = &json["data"];
        assert_eq!(data["configured"], true, "{role}");
        assert_eq!(data["managed_on_control_plane"], false, "{role}");
        let summary = &data["summary"];
        assert_eq!(summary["allowed_suffixes"][0], "corp.example.org", "{role}");
        assert_eq!(summary["failed_step"], "ticket_acquisition", "{role}");
        assert_eq!(summary["failed_kdc_code"], 24, "{role}");
        assert_eq!(
            summary["failed_reason"],
            lorica_adcs::kdc_error_meaning(24).expect("code 24 has a meaning"),
            "{role}"
        );
        assert!(summary["failed_since"].is_string(), "{role}");
        let text = json.to_string();
        for detail in [
            "ces.corp.example.org",
            "CORP.EXAMPLE.ORG",
            "kdc1.corp.example.org",
            "svc-lorica",
            "LoricaWebServer",
            "BEGIN CERTIFICATE",
        ] {
            assert_eq!(text.contains(detail), sees_details, "{role}: {detail}");
        }
        assert_eq!(data["authority"].is_null(), !sees_details, "{role}");
        assert!(!text.contains(PASSWORD), "{role}");
    }
}

/// D17: the allowed templates are stored with the default first, each
/// once whatever its case, and returned to Operators.
#[tokio::test]
async fn the_allowed_templates_are_stored_with_the_default_first() {
    let f = fixture(always_ok(), None).await;
    let mut with_templates = body(Some(PASSWORD));
    with_templates["allowed_templates"] = serde_json::json!([
        " LoricaWebServerEcdsa ",
        "loricawebserver",
        "LORICAWEBSERVERECDSA"
    ]);
    let resp = f
        .send("PUT", AUTHORITY, &f.admin, Some(with_templates))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(
        json["data"]["allowed_templates"],
        serde_json::json!(["LoricaWebServer", "LoricaWebServerEcdsa"])
    );
    let stored = f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row");
    assert!(stored.permits_template("LoricaWebServerEcdsa"));
    assert!(!stored.permits_template("User"));
}

/// The store's own endpoint check is coarser than `CesEndpoint` (the
/// config crate does not link `lorica-adcs`), and must never refuse an
/// endpoint the API accepted: every endpoint of these vectors that
/// `CesEndpoint` accepts, the model accepts too.
#[test]
fn the_store_never_refuses_an_endpoint_the_api_accepts() {
    let vectors: [&str; 8] = [
        "https://ces.corp.example.org/CA_CES_Kerberos/service.svc/CES",
        "https://ces.corp.example.org:8443/CES",
        "https://ces.corp.example.org",
        "HTTPS://ces.corp.example.org/CES",
        "https://xn--bcher-kva.corp.example.org/CES",
        "http://ces.corp.example.org/CES",
        "https://192.0.2.10/CES",
        "https://user:pw@ces.corp.example.org/CES",
    ];
    let mut accepted: usize = 0;
    for endpoint in vectors {
        if lorica_adcs::CesEndpoint::new(endpoint).is_err() {
            continue;
        }
        accepted += 1;
        let mut authority = lorica_config::models::AdcsAuthority {
            id: "adcs-1".to_string(),
            endpoint: endpoint.to_string(),
            realm: "CORP.EXAMPLE.ORG".to_string(),
            kdcs: Vec::new(),
            principal: "svc-lorica".to_string(),
            endpoint_ca_pem: None,
            issuing_ca_pem: None,
            default_template: "LoricaWebServer".to_string(),
            allowed_templates: Vec::new(),
            default_key_type: lorica_config::models::AdcsKeyType::Rsa2048,
            subject: lorica_config::models::AdcsSubjectDefaults::default(),
            allowed_suffixes: vec![
                lorica_config::models::AllowedSuffix::new("corp.example.org")
                    .expect("test setup: suffix"),
            ],
            auto_renew_default: true,
            failed_since: None,
            failed_step: None,
            failed_kdc_code: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(authority.validate().is_ok(), "{endpoint}");
        authority.allowed_templates = vec!["LoricaWebServer".to_string()];
        assert!(authority.validate().is_ok(), "{endpoint}");
    }
    assert!(
        accepted >= 4,
        "the vectors must exercise accepted endpoints"
    );
}
