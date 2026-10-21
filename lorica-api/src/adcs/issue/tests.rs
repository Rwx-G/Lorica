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

//! Tests for AD CS issuance (Story 13.3), through the real router with
//! the client behind [`AdcsClient`]. The stand-in authority signs the
//! CSR it is given with a throwaway two-level PKI, so what is stored is
//! a real certificate for the key Lorica generated.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use lorica_adcs::{AdcsError, CesParams, EnrollOutcome, FaultKind, Secret, TicketFailure};
use lorica_config::models::{AdcsSubjectDefaults, Certificate, Role};
use lorica_notify::events::AlertType;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;

use super::{issue, IssueError, IssueOutcome, IssueRequest, IssueSubject};
use crate::adcs::leaf::template_oid_of;
use crate::adcs::tests::{body, fixture, Fixture};
use crate::adcs::AdcsClient;
use crate::audit::AuditContext;
use crate::middleware::rate_limit::RateLimiter;
use crate::tests::body_json;

const ISSUE: &str = "/api/v1/certificates/adcs";
pub(in crate::adcs) const V2_TEMPLATE_OID: &str = "1.3.6.1.4.1.311.21.8.1234567.7654321.42";

/// The template extension the stand-in puts in what it issues.
#[derive(Clone, Copy)]
pub(in crate::adcs) enum TemplateExtension {
    None,
    V2,
    V1Bmp,
    V1Utf8,
}

/// A change to what the stand-in signs.
pub(in crate::adcs) type Tweak = fn(&mut rcgen::CertificateParams);

/// What the stand-in answers to the next enrollment.
#[derive(Clone)]
pub(in crate::adcs) enum Answer {
    /// Sign the CSR; with `sans`, issue those names instead of the
    /// requested ones.
    Issue {
        template: TemplateExtension,
        sans: Option<Vec<&'static str>>,
    },
    /// Sign the CSR as `Issue` with the v2 template does, then let
    /// `tweak` change what the certificate says before it is signed.
    Tweaked(Tweak),
    /// Sign the CSR, and answer with a chain whose first certificate is
    /// a CA of the same name that did not sign it.
    ForeignChain,
    Pending,
    Denied,
    Fault(FaultKind),
    Fail(fn() -> AdcsError),
}

pub(in crate::adcs) fn issue_v2() -> Answer {
    Answer::Issue {
        template: TemplateExtension::V2,
        sans: None,
    }
}

/// A stand-in authority: an issuing CA under a root, answering each
/// enrollment with `answer`, recording every CSR it is sent.
pub(in crate::adcs) struct StubAuthority {
    answer: Mutex<Answer>,
    calls: AtomicUsize,
    opens: AtomicUsize,
    csrs: Mutex<Vec<Vec<u8>>>,
    delay: Duration,
    issuing_ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    issuing_ca_der: Vec<u8>,
}

impl StubAuthority {
    pub(in crate::adcs) fn new(answer: Answer) -> Arc<StubAuthority> {
        StubAuthority::slow(answer, Duration::ZERO)
    }

    fn slow(answer: Answer, delay: Duration) -> Arc<StubAuthority> {
        let root_key = rcgen::KeyPair::generate().expect("test setup: root key");
        let root_params = ca_params("Example Root CA");
        let root = rcgen::Issuer::new(root_params, root_key);
        let issuing_key = rcgen::KeyPair::generate().expect("test setup: issuing key");
        let issuing_params = ca_params("Example Issuing CA");
        let issuing_cert = issuing_params
            .signed_by(&issuing_key, &root)
            .expect("test setup: the root signs the issuing CA");
        Arc::new(StubAuthority {
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            csrs: Mutex::new(Vec::new()),
            delay,
            issuing_ca: rcgen::Issuer::new(issuing_params, issuing_key),
            issuing_ca_der: issuing_cert.der().to_vec(),
        })
    }

    pub(in crate::adcs) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// How many sessions were opened, each one ticket in production.
    pub(in crate::adcs) fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    pub(in crate::adcs) fn set_answer(&self, answer: Answer) {
        *self.answer.lock().expect("answer") = answer;
    }

    pub(in crate::adcs) fn last_csr(&self) -> Vec<u8> {
        self.csrs
            .lock()
            .expect("csrs")
            .last()
            .cloned()
            .expect("a CSR was sent")
    }

    fn issuing_ca_pem(&self) -> String {
        super::pem_certificate(&self.issuing_ca_der)
    }

    fn sign(&self, csr_der: &[u8], template: TemplateExtension, sans: Option<&[&str]>) -> Vec<u8> {
        self.sign_tweaked(csr_der, template, sans, |_| {})
    }

    /// What a dedicated *Server Authentication* template issues, as
    /// changed by `tweak`.
    fn sign_tweaked(
        &self,
        csr_der: &[u8],
        template: TemplateExtension,
        sans: Option<&[&str]>,
        tweak: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> Vec<u8> {
        let mut request = rcgen::CertificateSigningRequestParams::from_der(&csr_der.into())
            .expect("the CSR parses and its signature verifies");
        request.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        if let Some(sans) = sans {
            request.params.subject_alt_names = sans
                .iter()
                .map(|name: &&str| {
                    rcgen::SanType::DnsName((*name).try_into().expect("test setup: DNS name"))
                })
                .collect();
        }
        if let Some(extension) = template_extension(template) {
            request.params.custom_extensions.push(extension);
        }
        tweak(&mut request.params);
        request
            .signed_by(&self.issuing_ca)
            .expect("the issuing CA signs")
            .der()
            .to_vec()
    }
}

fn ca_params(common_name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("test setup: CA params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
}

#[async_trait::async_trait]
impl AdcsClient for StubAuthority {
    async fn test_connection(
        &self,
        _params: &CesParams,
        _password: &Secret,
    ) -> Result<(), AdcsError> {
        Ok(())
    }

    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError> {
        assert_eq!(params.realm.as_str(), "CORP.EXAMPLE.ORG");
        assert!(password.expose(|text: &str| !text.is_empty()));
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.csrs.lock().expect("csrs").push(csr_der.to_vec());
        tokio::time::sleep(self.delay).await;
        let answer: Answer = self.answer.lock().expect("answer").clone();
        match answer {
            Answer::Issue { template, sans } => Ok(EnrollOutcome::Issued {
                leaf_der: self.sign(csr_der, template, sans.as_deref()),
                chain_der: vec![self.issuing_ca_der.clone()],
                request_id: Some("4242".to_string()),
                disposition_message: Some("Issued".to_string()),
            }),
            Answer::Tweaked(tweak) => Ok(EnrollOutcome::Issued {
                leaf_der: self.sign_tweaked(csr_der, TemplateExtension::V2, None, tweak),
                chain_der: vec![self.issuing_ca_der.clone()],
                request_id: Some("4242".to_string()),
                disposition_message: Some("Issued".to_string()),
            }),
            Answer::ForeignChain => {
                let impostor_key = rcgen::KeyPair::generate().expect("test setup: impostor key");
                let impostor = ca_params("Example Issuing CA")
                    .self_signed(&impostor_key)
                    .expect("test setup: impostor CA");
                Ok(EnrollOutcome::Issued {
                    leaf_der: self.sign(csr_der, TemplateExtension::V2, None),
                    chain_der: vec![impostor.der().to_vec()],
                    request_id: Some("4243".to_string()),
                    disposition_message: Some("Issued".to_string()),
                })
            }
            Answer::Pending => Ok(EnrollOutcome::Pending {
                request_id: "77".to_string(),
            }),
            Answer::Denied => Ok(EnrollOutcome::Denied {
                error_code: Some(0x8009_4012),
                request_id: Some("78".to_string()),
                message: "Denied by Policy Module".to_string(),
            }),
            Answer::Fault(kind) => Ok(EnrollOutcome::Error {
                kind,
                error_code: Some(0x8009_4800),
                message: "The requested certificate template is not supported".to_string(),
            }),
            Answer::Fail(make) => Err(make()),
        }
    }

    async fn open<'a>(
        &'a self,
        params: &CesParams,
        password: Secret,
    ) -> Result<Box<dyn crate::adcs::AdcsSession + 'a>, AdcsError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(crate::adcs::per_request_session(self, params, password))
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![tag];
    let len: usize = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("short length"));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b: &u8| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length of length"));
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn oid_content(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc: &str| arc.parse().expect("test setup: arc"))
        .collect();
    let mut out: Vec<u8> = vec![u8::try_from(arcs[0] * 40 + arcs[1]).expect("first arcs")];
    for &arc in &arcs[2..] {
        let mut groups: Vec<u8> = vec![u8::try_from(arc & 0x7F).expect("low group")];
        let mut rest: u64 = arc >> 7;
        while rest > 0 {
            groups.push(0x80 | u8::try_from(rest & 0x7F).expect("group"));
            rest >>= 7;
        }
        groups.reverse();
        out.extend(groups);
    }
    out
}

pub(in crate::adcs) fn template_extension(
    template: TemplateExtension,
) -> Option<rcgen::CustomExtension> {
    let (oid, value): (&[u64], Vec<u8>) = match template {
        TemplateExtension::None => return None,
        TemplateExtension::V2 => (
            &[1, 3, 6, 1, 4, 1, 311, 21, 7],
            tlv(
                0x30,
                &[
                    tlv(0x06, &oid_content(V2_TEMPLATE_OID)),
                    tlv(0x02, &[100]),
                    tlv(0x02, &[4]),
                ]
                .concat(),
            ),
        ),
        TemplateExtension::V1Bmp => (
            &[1, 3, 6, 1, 4, 1, 311, 20, 2],
            tlv(
                0x1E,
                &"WebServer"
                    .encode_utf16()
                    .flat_map(u16::to_be_bytes)
                    .collect::<Vec<u8>>(),
            ),
        ),
        TemplateExtension::V1Utf8 => (&[1, 3, 6, 1, 4, 1, 311, 20, 2], tlv(0x0C, b"WebServer")),
    };
    Some(rcgen::CustomExtension::from_oid_content(oid, value))
}

/// A fixture whose authority exists, with the stand-in answering.
/// The templates the fixture's authority allows besides its default,
/// the ones the renewal tests record on a certificate.
pub(in crate::adcs) const EXTRA_TEMPLATES: [&str; 2] = ["RenewalTemplate", "RecordedTemplate"];

pub(in crate::adcs) async fn issuing(
    stub: &Arc<StubAuthority>,
    alerts: Option<lorica_notify::AlertSender>,
) -> Fixture {
    let f = fixture(Arc::clone(stub), alerts).await;
    let mut with_templates = body(Some(super::super::tests::PASSWORD));
    with_templates["allowed_templates"] = serde_json::json!(EXTRA_TEMPLATES);
    let resp = f
        .send(
            "PUT",
            super::super::tests::AUTHORITY,
            &f.admin,
            Some(with_templates),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    f
}

impl Fixture {
    /// An issuance on a limiter of its own, for tests that issue more
    /// than the `adcs_issue` bucket admits.
    pub(in crate::adcs) async fn issue(
        &self,
        request: serde_json::Value,
    ) -> axum::response::Response {
        crate::tests::send(
            &self.state,
            &self.session_store,
            &RateLimiter::new(),
            "POST",
            ISSUE,
            &self.admin,
            Some(request),
        )
        .await
    }

    pub(in crate::adcs) async fn certificates(&self) -> Vec<Certificate> {
        self.state
            .store
            .lock()
            .await
            .list_certificates()
            .expect("list")
    }

    async fn authority_issuing_ca(&self) -> Option<String> {
        self.state
            .store
            .lock()
            .await
            .get_adcs_authority()
            .expect("read")
            .expect("authority")
            .issuing_ca_pem
    }
}

pub(in crate::adcs) fn web01() -> serde_json::Value {
    serde_json::json!({ "sans": ["web01.corp.example.org"], "key_type": "ecdsa_p256" })
}

async fn error_of(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status: StatusCode = resp.status();
    (status, body_json(resp).await["error"].clone())
}

pub(in crate::adcs) fn alerts_of(
    received: &mut tokio::sync::broadcast::Receiver<lorica_notify::AlertEvent>,
) -> Vec<lorica_notify::AlertEvent> {
    let mut alerts = Vec::new();
    while let Ok(alert) = received.try_recv() {
        alerts.push(alert);
    }
    alerts
}

/// AC #6 issued, AC #1: the row carries the chain, the key, the AD CS
/// fields and the observed template; the issuing CA is learned; the
/// CSR carried the merged subject and the deduplicated names.
#[tokio::test]
async fn an_issued_certificate_is_stored_with_its_chain_and_its_adcs_fields() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let operator = f.user("operator-issue", Role::Operator).await;

    let resp = f
        .send(
            "POST",
            ISSUE,
            &operator,
            Some(serde_json::json!({
                "sans": [" Web01.Corp.Example.ORG ", "web01.corp.example.org", "api.corp.example.org."],
                "key_type": "ecdsa_p256",
                "subject": { "organizational_unit": "IT" },
            })),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    let data = &json["data"];
    let text = json.to_string();
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    assert_eq!(data["source"], "adcs");
    assert_eq!(
        data["subject"], "CN=web01.corp.example.org,OU=IT,O=Example Corp,C=FR",
        "the subject as issued, RFC 4514"
    );
    assert_eq!(data["domain"], "web01.corp.example.org");
    assert_eq!(data["adcs_template"], "LoricaWebServer");
    assert_eq!(data["adcs_template_oid"], V2_TEMPLATE_OID);
    assert_eq!(data["adcs_request_id"], "4242");
    assert_eq!(data["acme_auto_renew"], true, "the authority's default");
    assert_eq!(data["is_acme"], false);
    assert!(data["issuer"]
        .as_str()
        .unwrap_or_default()
        .contains("Example Issuing CA"));
    let id = data["id"].as_str().expect("id").to_string();
    assert_eq!(stub.calls(), 1);

    let csr_der = stub.last_csr();
    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("csr");
    let subject = csr.certification_request_info.subject.to_string();
    assert!(subject.contains("C=FR"), "{subject}");
    assert!(subject.contains("O=Example Corp"), "{subject}");
    assert!(subject.contains("OU=IT"), "{subject}");
    assert!(subject.contains("CN=web01.corp.example.org"), "{subject}");

    let stored: Certificate = f
        .state
        .store
        .lock()
        .await
        .get_certificate(&id)
        .expect("read")
        .expect("row");
    assert_eq!(
        stored.san_domains,
        vec!["web01.corp.example.org", "api.corp.example.org"]
    );
    let blocks = pem::parse_many(&stored.cert_pem).expect("cert_pem parses");
    assert_eq!(blocks.len(), 2, "leaf then chain");
    assert_eq!(blocks[1].contents(), stub.issuing_ca_der.as_slice());
    lorica_tls::validate_certificate_bundle(&stored.cert_pem, &stored.key_pem)
        .expect("the stored key is the CSR's");
    assert_eq!(
        stored.adcs_authority_id.as_deref().map(str::is_empty),
        Some(false)
    );
    assert_eq!(f.authority_issuing_ca().await, Some(stub.issuing_ca_pem()));

    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create".to_string(),
            format!("adcs.certificate.issue.ok:{id}"),
            "adcs.authority.issuing_ca.learned".to_string(),
        ]
    );
}

/// D12: an issuing CA already known is never replaced by issuance.
#[tokio::test]
async fn a_known_issuing_ca_is_kept() {
    let stub = StubAuthority::new(issue_v2());
    let f = fixture(Arc::clone(&stub), None).await;
    let mut with_ca = body(Some(super::super::tests::PASSWORD));
    with_ca["issuing_ca_pem"] = serde_json::json!(crate::tests::TEST_CERT_RSA_PEM);
    let resp = f
        .send(
            "PUT",
            super::super::tests::AUTHORITY,
            &f.admin,
            Some(with_ca),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let before = f.authority_issuing_ca().await;

    let resp = f.issue(web01()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(f.authority_issuing_ca().await, before);
    assert!(!f
        .audit_actions()
        .await
        .iter()
        .any(|action| action.contains("issuing_ca")));
}

/// IV2 and AC #2: each refusal names the offending names and reaches
/// no authority.
#[tokio::test]
async fn names_outside_the_allowlist_are_refused_before_the_authority_is_contacted() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let too_many: Vec<String> = (0..=super::MAX_SANS)
        .map(|n: usize| format!("host{n}.corp.example.org"))
        .collect();
    let cases: Vec<(serde_json::Value, &str, Vec<&str>)> = vec![
        (
            serde_json::json!(["web01.corp.example.org", "web01.other.example.net"]),
            "san_outside_allowlist",
            vec!["web01.other.example.net"],
        ),
        (
            serde_json::json!(["*.corp.example.org"]),
            "san_wildcard",
            vec!["*.corp.example.org"],
        ),
        (
            serde_json::json!(["evilcorp.example.org"]),
            "san_outside_allowlist",
            vec!["evilcorp.example.org"],
        ),
        (serde_json::json!([]), "san_empty", vec![]),
        (serde_json::json!(too_many), "san_too_many", vec![]),
    ];
    let mut expected_audit: Vec<String> = vec!["adcs.authority.create".to_string()];
    for (sans, reason, named) in &cases {
        let resp = f.issue(serde_json::json!({ "sans": sans })).await;
        let (status, error) = error_of(resp).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{sans}");
        assert_eq!(error["code"], "adcs_san_refused", "{sans}");
        let message = error["message"].as_str().unwrap_or_default();
        for name in named {
            assert!(message.contains(name), "{message}");
        }
        expected_audit.push(format!("adcs.certificate.issue.refused:{reason}"));
    }
    assert_eq!(stub.calls(), 0, "no request reached the authority");
    assert!(f.certificates().await.is_empty());
    assert_eq!(f.audit_actions().await, expected_audit);
}

/// AC #6 pending, AC #7: nothing stored, the identifier shown, audited
/// and alerted.
#[tokio::test]
async fn a_pending_answer_stores_nothing_and_is_alerted() {
    let stub = StubAuthority::new(Answer::Pending);
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;

    let resp = f.issue(web01()).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let json = body_json(resp).await;
    assert_eq!(json["data"]["outcome"], "pending");
    assert_eq!(json["data"]["request_id"], "77");
    assert!(json["data"]["message"]
        .as_str()
        .unwrap_or_default()
        .contains("nothing was stored"));
    assert!(f.certificates().await.is_empty());
    assert_eq!(f.authority_issuing_ca().await, None);
    let alerts = alerts_of(&mut received);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, AlertType::CertIssuanceFailed);
    assert_eq!(
        alerts[0].details.get("step").map(String::as_str),
        Some("pending")
    );
    assert_eq!(
        alerts[0].details.get("request_id").map(String::as_str),
        Some("77")
    );
    assert_eq!(
        f.audit_actions().await.last().map(String::as_str),
        Some("adcs.certificate.issue.pending:77")
    );
}

/// AC #6 denied: the authority's message reaches the caller.
#[tokio::test]
async fn a_denial_stores_nothing_and_shows_the_authority_message() {
    let stub = StubAuthority::new(Answer::Denied);
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;

    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["code"], "adcs_denied");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(message.contains("Denied by Policy Module"), "{message}");
    assert!(message.contains("0x80094012"), "{message}");
    assert!(f.certificates().await.is_empty());
    let alerts = alerts_of(&mut received);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, AlertType::CertIssuanceFailed);
    assert_eq!(
        f.audit_actions().await.last().map(String::as_str),
        Some("adcs.certificate.issue.denied")
    );
}

/// AC #6 fault, and a client failure: 502 naming the step.
#[tokio::test]
async fn a_fault_or_a_client_failure_is_a_bad_gateway_naming_the_step() {
    let cases: Vec<(Answer, &str, Option<String>)> = vec![
        (Answer::Fault(FaultKind::Template), "fault_template", None),
        (
            Answer::Fault(FaultKind::Permission),
            "fault_permission",
            None,
        ),
        (
            Answer::Fail(|| AdcsError::Tls {
                reason: "invalid peer certificate: UnknownIssuer".to_string(),
            }),
            "tls",
            Some(
                AdcsError::Tls {
                    reason: "invalid peer certificate: UnknownIssuer".to_string(),
                }
                .to_string(),
            ),
        ),
    ];
    for (answer, step, exact_message) in cases {
        let stub = StubAuthority::new(answer);
        let alerts = lorica_notify::AlertSender::new(16);
        let mut received = alerts.subscribe();
        let f = issuing(&stub, Some(alerts)).await;
        let (status, error) = error_of(f.issue(web01()).await).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{step}");
        assert_eq!(error["code"], "adcs_error", "{step}");
        assert_eq!(error["step"], step);
        if let Some(message) = exact_message {
            assert_eq!(error["message"], message);
        }
        assert!(f.certificates().await.is_empty());
        let alerts = alerts_of(&mut received);
        assert_eq!(alerts.len(), 1, "{step}");
        assert_eq!(alerts[0].alert_type, AlertType::CertIssuanceFailed);
        assert_eq!(
            f.audit_actions().await.last().map(String::as_str),
            Some(format!("adcs.certificate.issue.error:{step}").as_str())
        );
        let stored = f
            .state
            .store
            .lock()
            .await
            .get_adcs_authority()
            .expect("read")
            .expect("row");
        assert!(!stored.is_failed(), "{step}");
    }
}

pub(in crate::adcs) fn rejected_credential() -> AdcsError {
    AdcsError::Ticket {
        principal: "svc-lorica@CORP.EXAMPLE.ORG".to_string(),
        failure: TicketFailure::CredentialRejected,
        kdc_error_code: Some(24),
        minor_status: 0,
        message: "Preauthentication failed".to_string(),
    }
}

/// D15: a rejected credential during issuance opens the breaker, as a
/// connection test does, and the next issuance reaches no KDC.
#[tokio::test]
async fn a_rejected_credential_opens_the_breaker_and_the_next_issuance_is_refused() {
    let stub = StubAuthority::new(Answer::Fail(rejected_credential));
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;

    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(error["step"], "ticket_acquisition");
    assert!(error["message"]
        .as_str()
        .unwrap_or_default()
        .contains("failed state"));
    let mut types: Vec<AlertType> = alerts_of(&mut received)
        .into_iter()
        .map(|alert| alert.alert_type)
        .collect();
    types.sort_by_key(|t| t.as_str());
    assert_eq!(
        types,
        vec![
            AlertType::AdcsAuthorityFailed,
            AlertType::CertIssuanceFailed
        ]
    );

    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "adcs_failed_state");
    assert_eq!(stub.calls(), 1, "the breaker spends no further attempt");
    assert_eq!(
        f.audit_actions().await,
        vec![
            "adcs.authority.create",
            "adcs.certificate.issue.error:ticket_acquisition",
            "adcs.authority.failed_state.enter:ticket_acquisition",
            "adcs.certificate.issue.refused:failed_state",
        ]
    );
}

/// An authority that issued other names than those requested is an
/// error: nothing stored, alerted.
#[tokio::test]
async fn a_certificate_that_does_not_cover_the_request_is_refused() {
    let stub = StubAuthority::new(Answer::Issue {
        template: TemplateExtension::V2,
        sans: Some(vec!["other.corp.example.org"]),
    });
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;

    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(error["step"], "san_coverage");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(message.contains("web01.corp.example.org"), "{message}");
    assert!(f.certificates().await.is_empty());
    assert_eq!(
        f.authority_issuing_ca().await,
        None,
        "nothing learned either"
    );
    assert_eq!(alerts_of(&mut received).len(), 1);
}

/// D15 single flight: an issuance during another operation is refused
/// and reaches no authority.
#[tokio::test]
async fn an_issuance_while_another_operation_runs_is_busy() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let permit = f.state.adcs.guard().try_acquire().expect("nothing runs");
    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "adcs_busy");
    assert_eq!(stub.calls(), 0);
    drop(permit);
    assert_eq!(f.issue(web01()).await.status(), StatusCode::CREATED);
    assert_eq!(
        f.audit_actions().await[1],
        "adcs.certificate.issue.refused:busy"
    );
}

/// An issuance that outlives the handler is answered 504 and is still
/// stored and audited by its own task.
#[tokio::test]
async fn an_issuance_past_the_handler_deadline_still_stores_its_certificate() {
    let stub = StubAuthority::slow(issue_v2(), Duration::from_millis(1500));
    let f = issuing(&stub, None)
        .await
        .with_handler_deadline(Duration::from_millis(200));
    let resp = f.issue(web01()).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    f.wait_until_idle().await;
    assert_eq!(f.certificates().await.len(), 1);
    assert!(f
        .audit_actions()
        .await
        .iter()
        .any(|action| action.starts_with("adcs.certificate.issue.ok:")));
}

#[tokio::test]
async fn an_issuance_without_an_authority_or_on_a_follower_is_a_conflict() {
    let stub = StubAuthority::new(issue_v2());
    let mut f = fixture(Arc::clone(&stub), None).await;
    let (status, error) = error_of(f.issue(web01()).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "adcs_not_configured");

    f.create_authority().await;
    f.state.cluster =
        crate::cluster::ClusterRuntime::Follower(crate::tests::test_follower_runtime());
    let resp = f.issue(web01()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(stub.calls(), 0);
}

/// D11: Operator and above, the certificate default.
#[tokio::test]
async fn a_viewer_cannot_issue() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let viewer = f.user("viewer-issue", Role::Viewer).await;
    let resp = f.send("POST", ISSUE, &viewer, Some(web01())).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(stub.calls(), 0);
}

#[tokio::test]
async fn issuance_is_rate_limited_in_its_own_bucket() {
    let stub = StubAuthority::new(Answer::Pending);
    let f = issuing(&stub, None).await;
    for _ in 0..crate::server::RL_ACME_PROVISION {
        let resp = f.send("POST", ISSUE, &f.admin, Some(web01())).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }
    let resp = f.send("POST", ISSUE, &f.admin, Some(web01())).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        stub.calls(),
        crate::server::RL_ACME_PROVISION as usize,
        "a refused issuance reaches no authority"
    );
    let resp = f
        .send("POST", super::super::tests::TEST, &f.admin, None)
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the test keeps its own bucket"
    );
}

/// The path Story 13.4's renewal takes: same id, a new key, the
/// subject given exactly, the template given, the auto-renew setting
/// and the creation time kept.
#[tokio::test]
async fn a_replacement_updates_the_certificate_in_place() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let before: Certificate = {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&id).expect("read").expect("row");
        cert.acme_auto_renew = false;
        store.update_certificate(&cert).expect("auto-renew off");
        cert
    };

    stub.set_answer(Answer::Issue {
        template: TemplateExtension::V1Bmp,
        sans: None,
    });
    let ctx = AuditContext::node("adcs-renewal");
    let request = IssueRequest {
        sans: before.san_domains.clone(),
        template: Some("RenewalTemplate".to_string()),
        key_type: None,
        subject: IssueSubject::Exact(AdcsSubjectDefaults {
            organizational_unit: Some("Web".to_string()),
            ..AdcsSubjectDefaults::default()
        }),
        auto_renew: None,
        replace: Some(id.clone()),
    };
    let outcome = issue(&f.state, &ctx, request).await;
    let renewed: Certificate = match outcome {
        Ok(IssueOutcome::Issued(cert)) => *cert,
        other => panic!("expected an issued certificate, got {other:?}"),
    };
    assert_eq!(renewed.id, id);
    let stored: Certificate = f
        .state
        .store
        .lock()
        .await
        .get_certificate(&id)
        .expect("read")
        .expect("row");
    assert_ne!(stored.fingerprint, before.fingerprint);
    assert_ne!(stored.key_pem, before.key_pem, "a new key every renewal");
    assert_eq!(stored.created_at, before.created_at);
    assert!(!stored.acme_auto_renew, "the current setting is kept");
    assert_eq!(stored.adcs_template.as_deref(), Some("RenewalTemplate"));
    assert_eq!(stored.adcs_template_oid.as_deref(), Some("WebServer"));
    assert_eq!(f.certificates().await.len(), 1);

    let csr_der = stub.last_csr();
    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("csr");
    let subject = csr.certification_request_info.subject.to_string();
    assert!(subject.contains("OU=Web"), "{subject}");
    assert!(
        !subject.contains("O=Example Corp"),
        "an exact subject ignores the defaults: {subject}"
    );
}

/// A replacement names a row that exists, checked before anything is
/// requested; a failed replacement's alert names the certificate.
#[tokio::test]
async fn a_replacement_of_a_missing_row_is_refused_and_a_failed_one_names_its_certificate() {
    let stub = StubAuthority::new(Answer::Pending);
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let ctx = AuditContext::node("adcs-renewal");
    let request = |replace: &str| IssueRequest {
        sans: vec!["web01.corp.example.org".to_string()],
        template: None,
        key_type: Some(lorica_config::models::AdcsKeyType::EcdsaP256),
        subject: IssueSubject::Exact(AdcsSubjectDefaults::default()),
        auto_renew: None,
        replace: Some(replace.to_string()),
    };
    match issue(&f.state, &ctx, request("missing")).await {
        Err(IssueError::Api(crate::error::ApiError::NotFound(_))) => {}
        other => panic!("expected not found, got {other:?}"),
    }
    assert_eq!(stub.calls(), 0);

    let now = chrono::Utc::now();
    f.state
        .store
        .lock()
        .await
        .create_certificate(&Certificate {
            id: "current".to_string(),
            domain: "web01.corp.example.org".to_string(),
            san_domains: vec!["web01.corp.example.org".to_string()],
            fingerprint: "sha256:current".to_string(),
            cert_pem: crate::tests::TEST_CERT_RSA_PEM.to_string(),
            key_pem: crate::tests::TEST_KEY_RSA_PEM.to_string(),
            issuer: "Example Issuing CA".to_string(),
            not_before: now,
            not_after: now + chrono::Duration::days(30),
            is_acme: false,
            acme_auto_renew: true,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
            adcs_authority_id: Some("any".to_string()),
            adcs_template: Some("LoricaWebServer".to_string()),
            adcs_template_oid: None,
            adcs_request_id: None,
        })
        .expect("test setup: certificate");
    match issue(&f.state, &ctx, request("current")).await {
        Ok(IssueOutcome::Pending { request_id, .. }) => assert_eq!(request_id, "77"),
        other => panic!("expected pending, got {other:?}"),
    }
    let alerts = alerts_of(&mut received);
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].details.get("cert_id").map(String::as_str),
        Some("current")
    );
    let unchanged: Certificate = f
        .state
        .store
        .lock()
        .await
        .get_certificate("current")
        .expect("read")
        .expect("row");
    assert_eq!(
        unchanged.fingerprint, "sha256:current",
        "pending keeps the current one"
    );
}

/// The template observed in an issued certificate, from each extension.
#[test]
fn the_template_is_read_from_either_extension() {
    let stub = StubAuthority::new(Answer::Pending);
    let csr = lorica_adcs::build_csr(
        &["web01.corp.example.org".to_string()],
        &lorica_adcs::SubjectFields::default(),
        "LoricaWebServer",
        lorica_adcs::KeyType::EcdsaP256,
    )
    .expect("csr");
    for (template, expected) in [
        (TemplateExtension::V2, Some(V2_TEMPLATE_OID)),
        (TemplateExtension::V1Bmp, Some("WebServer")),
        (TemplateExtension::V1Utf8, Some("WebServer")),
        (TemplateExtension::None, None),
    ] {
        let leaf_der = stub.sign(&csr.csr_der, template, None);
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).expect("leaf");
        assert_eq!(template_oid_of(&leaf).as_deref(), expected);
    }
}

/// AC #1: `source` and the AD CS fields on the list and on each
/// certificate, for the three sources.
#[tokio::test]
async fn every_certificate_view_carries_its_derived_source() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    let adcs_id = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let resp = f
        .send(
            "POST",
            "/api/v1/certificates",
            &f.admin,
            Some(serde_json::json!({
                "domain": "manual.corp.example.org",
                "cert_pem": crate::tests::TEST_CERT_RSA_PEM,
                "key_pem": crate::tests::TEST_KEY_RSA_PEM,
            })),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let manual = body_json(resp).await;
    assert_eq!(manual["data"]["source"], "manual");
    assert!(manual["data"]["adcs_authority_id"].is_null());
    let manual_id = manual["data"]["id"].as_str().expect("id").to_string();
    let acme_id = {
        let store = f.state.store.lock().await;
        let mut acme = store
            .get_certificate(&manual_id)
            .expect("read")
            .expect("row");
        acme.id = "acme-1".to_string();
        acme.is_acme = true;
        store.create_certificate(&acme).expect("acme row");
        acme.id
    };

    let resp = f.send("GET", "/api/v1/certificates", &f.admin, None).await;
    let list = body_json(resp).await;
    let sources: std::collections::BTreeMap<String, String> = list["data"]["certificates"]
        .as_array()
        .expect("certificates")
        .iter()
        .map(|row| {
            assert!(row.get("adcs_template_oid").is_some(), "{row}");
            assert!(row["subject"].is_string(), "{row}");
            (
                row["id"].as_str().unwrap_or_default().to_string(),
                row["source"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    for (id, source) in [
        (&adcs_id, "adcs"),
        (&manual_id, "manual"),
        (&acme_id, "acme"),
    ] {
        assert_eq!(sources.get(id).map(String::as_str), Some(source), "{id}");
        let resp = f
            .send("GET", &format!("/api/v1/certificates/{id}"), &f.admin, None)
            .await;
        let detail = body_json(resp).await;
        assert_eq!(detail["data"]["source"], source, "{id}");
        assert!(
            detail["data"]["subject"]
                .as_str()
                .is_some_and(|subject| subject.contains("CN=")),
            "{detail}"
        );
        assert_eq!(
            detail["data"]["adcs_request_id"].is_null(),
            source != "adcs",
            "{id}"
        );
    }
}

/// AC #8 and D6: no automation route reaches issuance, neither by its
/// handler nor by its path, so neither the plane nor the MCP tools it
/// is folded from can issue.
#[tokio::test]
async fn no_automation_route_reaches_the_issuance_endpoint() {
    for route in crate::automation::route_table() {
        assert!(
            !route.handler.contains("issue_certificate") && !route.handler.contains("adcs"),
            "{} {} mounts {}",
            route.method,
            route.path,
            route.handler
        );
        assert!(
            !route.path.contains("adcs"),
            "{} {}",
            route.method,
            route.path
        );
    }

    let mut w = crate::automation::test_support::a_node_with_something_to_write().await;
    let stub = StubAuthority::new(issue_v2());
    w.state.adcs =
        crate::adcs::AdcsRuntime::with_client(Arc::clone(&stub) as Arc<dyn AdcsClient>, None);
    let router = crate::automation::build_automation_router(w.state.clone());
    for path in ["/automation/v1/certificates/adcs", ISSUE] {
        let response = tower::ServiceExt::oneshot(
            router.clone(),
            http::Request::builder()
                .method(http::Method::POST)
                .uri(path)
                .header(http::header::AUTHORIZATION, w.bearer.clone())
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(web01().to_string()))
                .expect("test setup"),
        )
        .await
        .expect("infallible");
        let status = response.status();
        assert!(
            [
                StatusCode::NOT_FOUND,
                StatusCode::METHOD_NOT_ALLOWED,
                StatusCode::FORBIDDEN
            ]
            .contains(&status),
            "{path} answered {status}"
        );
    }
    assert_eq!(stub.calls(), 0);
}

/// D17: a template the authority does not list is refused before the
/// authority is contacted; a listed one is accepted whatever its case.
#[tokio::test]
async fn a_template_outside_the_allowlist_is_refused_before_the_authority() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let operator = f.user("operator-template", Role::Operator).await;

    let mut request = web01();
    request["template"] = serde_json::json!("User");
    let (status, error) = error_of(f.send("POST", ISSUE, &operator, Some(request)).await).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["code"], "adcs_template_refused");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("User"),
        "{error}"
    );
    assert_eq!(stub.calls(), 0);
    assert_eq!(
        f.audit_actions().await.last().map(String::as_str),
        Some("adcs.certificate.issue.refused:template")
    );

    let mut control = web01();
    control["template"] = serde_json::json!("Web\u{7}Server");
    let resp = f.issue(control).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(stub.calls(), 0);

    let mut listed = web01();
    listed["template"] = serde_json::json!(EXTRA_TEMPLATES[0].to_ascii_lowercase());
    let resp = f.issue(listed).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(stub.calls(), 1);
}

fn no_eku(params: &mut rcgen::CertificateParams) {
    params.extended_key_usages.clear();
}

fn client_auth_only(params: &mut rcgen::CertificateParams) {
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
}

fn any_purpose(params: &mut rcgen::CertificateParams) {
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::Any,
    ];
}

fn a_ca(params: &mut rcgen::CertificateParams) {
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
}

fn an_extra_dns_name(params: &mut rcgen::CertificateParams) {
    params.subject_alt_names.push(rcgen::SanType::DnsName(
        "dc01.corp.example.org"
            .try_into()
            .expect("test setup: DNS name"),
    ));
}

fn an_ip_address(params: &mut rcgen::CertificateParams) {
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
        )));
}

fn upper_case_names(params: &mut rcgen::CertificateParams) {
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "WEB01.Corp.Example.ORG"
            .try_into()
            .expect("test setup: DNS name"),
    )];
}

/// D17 and the request id on every post-issuance rejection: a leaf that
/// is not a server certificate, or whose names are not exactly the
/// requested ones, is not stored, and the error, the audit action and
/// the alert all carry the authority's request identifier.
#[tokio::test]
async fn an_issued_certificate_that_is_not_what_was_requested_is_not_stored() {
    let cases: [(Tweak, &str, &str); 6] = [
        (no_eku, "certificate_profile", "Server Authentication"),
        (
            client_auth_only,
            "certificate_profile",
            "Server Authentication",
        ),
        (any_purpose, "certificate_profile", "Any Purpose"),
        (a_ca, "certificate_profile", "CA certificate"),
        (an_extra_dns_name, "san_coverage", "dc01.corp.example.org"),
        (an_ip_address, "san_coverage", "IP address"),
    ];
    for (tweak, step, names) in cases {
        let stub = StubAuthority::new(Answer::Tweaked(tweak));
        let alerts = lorica_notify::AlertSender::new(16);
        let mut received = alerts.subscribe();
        let f = issuing(&stub, Some(alerts)).await;

        let (status, error) = error_of(f.issue(web01()).await).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{step} {names}");
        assert_eq!(error["code"], "adcs_error", "{step} {names}");
        assert_eq!(error["step"], step, "{names}");
        let message = error["message"].as_str().unwrap_or_default();
        assert!(message.contains(names), "{message}");
        assert!(message.contains("request 4242"), "{message}");
        assert!(message.contains("revoked"), "{message}");
        assert!(f.certificates().await.is_empty(), "{step} {names}");
        assert_eq!(f.authority_issuing_ca().await, None, "{step} {names}");

        let raised = alerts_of(&mut received);
        assert_eq!(raised.len(), 1, "{step} {names}");
        assert_eq!(
            raised[0].details.get("request_id").map(String::as_str),
            Some("4242")
        );
        assert_eq!(
            raised[0].details.get("step").map(String::as_str),
            Some(step)
        );
        assert_eq!(
            f.audit_actions().await.last().map(String::as_str),
            Some(format!("adcs.certificate.issue.error:{step}:4242").as_str())
        );
    }
}

/// The names are compared without regard to case, as DNS does.
#[tokio::test]
async fn names_issued_in_another_case_are_the_requested_names() {
    let stub = StubAuthority::new(Answer::Tweaked(upper_case_names));
    let f = issuing(&stub, None).await;
    assert_eq!(f.issue(web01()).await.status(), StatusCode::CREATED);
}

/// D12, pen L1: the issuing CA is learned only from a chain whose first
/// certificate signed the leaf; a look-alike of the same name is not.
#[tokio::test]
async fn an_issuing_ca_that_did_not_sign_the_leaf_is_not_learned() {
    let stub = StubAuthority::new(Answer::ForeignChain);
    let f = issuing(&stub, None).await;
    assert_eq!(f.issue(web01()).await.status(), StatusCode::CREATED);
    assert_eq!(f.authority_issuing_ca().await, None);
    assert!(!f
        .audit_actions()
        .await
        .iter()
        .any(|action| action.contains("issuing_ca")));

    stub.set_answer(issue_v2());
    assert_eq!(f.issue(web01()).await.status(), StatusCode::CREATED);
    assert_eq!(f.authority_issuing_ca().await, Some(stub.issuing_ca_pem()));
}

/// Arch M1: a renewal whose certificate was reverted to manual while it
/// was at the authority writes nothing over that decision, and says
/// which request to revoke.
#[tokio::test]
async fn a_replacement_of_a_certificate_reverted_meanwhile_is_not_written() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(16);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let id = body_json(f.issue(web01()).await).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let reverted: Certificate = {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&id).expect("read").expect("row");
        cert.adcs_authority_id = None;
        store.update_certificate(&cert).expect("reverted");
        cert
    };
    alerts_of(&mut received);

    let request = IssueRequest {
        sans: vec!["web01.corp.example.org".to_string()],
        template: None,
        key_type: None,
        subject: IssueSubject::Exact(AdcsSubjectDefaults::default()),
        auto_renew: None,
        replace: Some(id.clone()),
    };
    let ctx = AuditContext::node("adcs-renewal");
    match issue(&f.state, &ctx, request).await {
        Err(IssueError::Api(crate::error::ApiError::Conflict(_))) => {}
        other => panic!("expected a conflict, got {other:?}"),
    }
    let after: Certificate = f
        .state
        .store
        .lock()
        .await
        .get_certificate(&id)
        .expect("read")
        .expect("row");
    assert_eq!(after.fingerprint, reverted.fingerprint);
    assert_eq!(after.adcs_authority_id, None, "still manual");
    let raised = alerts_of(&mut received);
    assert_eq!(raised.len(), 1);
    assert_eq!(
        raised[0].details.get("request_id").map(String::as_str),
        Some("4242")
    );
    assert_eq!(
        f.audit_actions().await.last().map(String::as_str),
        Some("adcs.certificate.issue.error:store:4242")
    );
}
