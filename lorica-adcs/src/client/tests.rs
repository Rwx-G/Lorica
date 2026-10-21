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

//! The exchange against a local HTTPS server standing in for CES, with
//! the GSS-API layer replaced by a scripted double. The real Kerberos
//! path is the harness's (Story 13.1 Lot 4).

use std::convert::Infallible;
use std::sync::{Mutex, MutexGuard};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::gss::{ticket_error, TicketFailure};
use crate::test_support::{
    b64, fault_response, issued_response, pending_response, signed_data, TestPki,
};

const CLIENT_TOKEN: &[u8] = b"client-token";
const SERVER_TOKEN: &[u8] = b"server-token";
const PASSWORD: &str = "example-only-password";
/// `KRB5KDC_ERR_PREAUTH_FAILED` as GSS-API reports it.
const PREAUTH_FAILED_MINOR: u32 = 0x96C7_3A18;

// ---------------------------------------------------------------- GSS double

#[derive(Default)]
struct FakeLog {
    principals: Vec<String>,
    passwords: Vec<String>,
    hosts: Vec<String>,
    bindings: Vec<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum Acquisition {
    Succeeds,
    Fails(u32, &'static str),
}

#[derive(Clone, Copy)]
enum Mutual {
    Completes,
    StaysIncomplete,
}

/// Hands out [`CLIENT_TOKEN`], accepts only [`SERVER_TOKEN`] back, and
/// records what it was given.
struct FakeGss {
    acquisition: Acquisition,
    mutual: Mutual,
    log: Arc<Mutex<FakeLog>>,
}

impl FakeGss {
    fn new(acquisition: Acquisition, mutual: Mutual) -> Arc<FakeGss> {
        Arc::new(FakeGss {
            acquisition,
            mutual,
            log: Arc::new(Mutex::new(FakeLog::default())),
        })
    }

    fn working() -> Arc<FakeGss> {
        FakeGss::new(Acquisition::Succeeds, Mutual::Completes)
    }

    fn log(&self) -> MutexGuard<'_, FakeLog> {
        self.log.lock().expect("fake log")
    }
}

struct FakeContext {
    mutual: Mutual,
    log: Arc<Mutex<FakeLog>>,
    complete: bool,
}

impl GssBackend for FakeGss {
    type Credential = String;
    type Context = FakeContext;

    fn acquire_credential(&self, principal: &str, password: &Secret) -> Result<String, AdcsError> {
        let mut log: MutexGuard<'_, FakeLog> = self.log();
        log.principals.push(principal.to_owned());
        log.passwords.push(password.expose(str::to_owned));
        match self.acquisition {
            Acquisition::Succeeds => Ok(principal.to_owned()),
            Acquisition::Fails(minor, message) => {
                Err(ticket_error(principal, minor, message.to_owned()))
            }
        }
    }

    fn client_context(&self, _credential: String, host: &str) -> Result<FakeContext, AdcsError> {
        self.log().hosts.push(host.to_owned());
        Ok(FakeContext {
            mutual: self.mutual,
            log: Arc::clone(&self.log),
            complete: false,
        })
    }
}

impl GssContext for FakeContext {
    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        channel_binding: &[u8],
    ) -> Result<Option<Vec<u8>>, GssFailure> {
        self.log
            .lock()
            .expect("fake log")
            .bindings
            .push(channel_binding.to_vec());
        match input_token {
            None => Ok(Some(CLIENT_TOKEN.to_vec())),
            Some(token) if token == SERVER_TOKEN => match self.mutual {
                Mutual::Completes => {
                    self.complete = true;
                    Ok(None)
                }
                Mutual::StaysIncomplete => Ok(Some(b"another leg".to_vec())),
            },
            Some(_) => Err(GssFailure {
                message: "A token was invalid".to_owned(),
            }),
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

// ---------------------------------------------------------------- CES stand-in

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    authorization: Option<String>,
    body: String,
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
    delay: Duration,
}

impl Reply {
    fn new(status: u16) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: String::new(),
            delay: Duration::ZERO,
        }
    }

    fn header(mut self, name: &'static str, value: &str) -> Reply {
        self.headers.push((name, value.to_owned()));
        self
    }

    fn body(mut self, body: &str) -> Reply {
        self.body = body.to_owned();
        self
    }

    fn after(mut self, delay: Duration) -> Reply {
        self.delay = delay;
        self
    }

    /// Adds the response token that proves the server.
    fn proven(self) -> Reply {
        self.header(
            "www-authenticate",
            &format!("Negotiate {}", b64(SERVER_TOKEN)),
        )
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// IIS in front of CES: 401 `Negotiate` unless the request carries the
/// client token, then `authenticated` answers.
fn iis(authenticated: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Handler {
    let expected: String = format!("Negotiate {}", b64(CLIENT_TOKEN));
    Arc::new(move |seen: &Seen| match &seen.authorization {
        Some(value) if *value == expected => authenticated(seen),
        _ => Reply::new(401).header("www-authenticate", "Negotiate"),
    })
}

struct TestCes {
    endpoint: String,
    certificate_der: Vec<u8>,
    certificate_pem: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn self_signed_localhost() -> (Vec<u8>, String, KeyPair) {
    let key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("server key");
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("server params")
        .self_signed(&key)
        .expect("server certificate");
    (certificate.der().to_vec(), certificate.pem(), key)
}

impl TestCes {
    async fn start(handler: Handler) -> TestCes {
        let (certificate_der, certificate_pem, key): (Vec<u8>, String, KeyPair) =
            self_signed_localhost();
        let config: rustls::ServerConfig = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certificate_der.clone(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
        .expect("server config");
        let acceptor: TlsAcceptor = TlsAcceptor::from(Arc::new(config));
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port: u16 = listener.local_addr().expect("local addr").port();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(serve(listener, acceptor, handler, Arc::clone(&seen)));
        TestCes {
            endpoint: format!("https://localhost:{port}/CES"),
            certificate_der,
            certificate_pem,
            seen,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    fn params(&self) -> CesParams {
        CesParams {
            endpoint: self.endpoint.clone(),
            realm: Realm::new("CORP.EXAMPLE.ORG").expect("realm"),
            principal: "svc-lorica".to_owned(),
            trust_bundle_pem: Some(self.certificate_pem.clone()),
            timeouts: CesTimeouts {
                connect: Duration::from_secs(5),
                read: Duration::from_secs(5),
                operation: Duration::from_secs(20),
            },
        }
    }
}

async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: Handler,
    seen: Arc<Mutex<Vec<Seen>>>,
) {
    while let Ok((tcp, _)) = listener.accept().await {
        let acceptor: TlsAcceptor = acceptor.clone();
        let handler: Handler = Arc::clone(&handler);
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::clone(&seen);
        tokio::spawn(async move {
            // A client that refuses the certificate ends the handshake.
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                let handler: Handler = Arc::clone(&handler);
                let seen: Arc<Mutex<Vec<Seen>>> = Arc::clone(&seen);
                async move {
                    let (parts, body) = request.into_parts();
                    let body: Bytes = body.collect().await.expect("request body").to_bytes();
                    let request: Seen = Seen {
                        method: parts.method.to_string(),
                        authorization: parts
                            .headers
                            .get("authorization")
                            .map(|value| value.to_str().expect("ascii").to_owned()),
                        body: String::from_utf8_lossy(&body).into_owned(),
                    };
                    let reply: Reply = handler(&request);
                    seen.lock().expect("seen").push(request);
                    tokio::time::sleep(reply.delay).await;
                    let mut response = hyper::Response::builder().status(reply.status);
                    for (name, value) in reply.headers {
                        response = response.header(name, value);
                    }
                    Ok::<_, Infallible>(
                        response
                            .body(Full::new(Bytes::from(reply.body)))
                            .expect("response"),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}

fn password() -> Secret {
    Secret::new(PASSWORD.to_owned())
}

// ---------------------------------------------------------------- enroll

#[tokio::test]
async fn an_issued_certificate_after_a_bound_and_mutually_authenticated_exchange() {
    let pki: TestPki = TestPki::generate();
    let cmc: Vec<u8> = signed_data(&[&pki.root, &pki.leaf, &pki.intermediate]);
    let answer: String = issued_response(&pki.leaf, &cmc, "61");
    let ces: TestCes = TestCes::start(iis(move |_| Reply::new(200).body(&answer).proven())).await;
    let gss: Arc<FakeGss> = FakeGss::working();

    let outcome: EnrollOutcome = enroll_with(Arc::clone(&gss), &ces.params(), &password(), b"csr")
        .await
        .expect("issued");

    match outcome {
        EnrollOutcome::Issued {
            leaf_der,
            chain_der,
            request_id,
            ..
        } => {
            assert_eq!(leaf_der, pki.leaf);
            assert_eq!(chain_der, vec![pki.intermediate.clone()]);
            assert_eq!(request_id.as_deref(), Some("61"));
        }
        other => panic!("expected an issued certificate, got {other:?}"),
    }
    let log: MutexGuard<'_, FakeLog> = gss.log();
    assert_eq!(log.principals, vec!["svc-lorica@CORP.EXAMPLE.ORG"]);
    assert_eq!(log.passwords, vec![PASSWORD]);
    assert_eq!(log.hosts, vec!["localhost"]);
    // Both steps carry the binding of the certificate the server
    // presented.
    let binding: Vec<u8> = channel_binding(&ces.certificate_der).expect("binding");
    assert_eq!(log.bindings, vec![binding.clone(), binding]);
    let seen: Vec<Seen> = ces.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].authorization, None);
    for request in &seen {
        assert_eq!(request.method, "POST");
        assert!(request.body.contains(&b64(b"csr")), "{}", request.body);
        assert!(request.body.contains("RequestSecurityToken"));
    }
}

#[tokio::test]
async fn pending_and_denied_answers_are_outcomes_not_errors() {
    let pending: String = pending_response("4242");
    let ces: TestCes = TestCes::start(iis(move |_| Reply::new(200).body(&pending).proven())).await;
    let outcome: EnrollOutcome =
        enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
            .await
            .expect("pending");
    assert_eq!(
        outcome,
        EnrollOutcome::Pending {
            request_id: "4242".to_owned()
        }
    );

    let denial: String = fault_response(
        "Denied by Policy Module",
        Some((0x8009_4012_u32 as i32, true, "77")),
    );
    let ces: TestCes = TestCes::start(iis(move |_| Reply::new(500).body(&denial).proven())).await;
    let outcome: EnrollOutcome =
        enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
            .await
            .expect("denied");
    assert!(
        matches!(outcome, EnrollOutcome::Denied { ref request_id, .. } if request_id.as_deref() == Some("77")),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_unexpected_authenticated_status_is_an_http_error() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(404).proven())).await;
    let err: AdcsError = enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
        .await
        .expect_err("404");
    assert!(
        matches!(err, AdcsError::Http { stage, .. } if stage == AUTHENTICATED),
        "{err}"
    );
}

// ---------------------------------------------------------------- mutual authentication (AC #5)

#[tokio::test]
async fn an_answer_without_a_response_token_fails_mutual_authentication() {
    let pending: String = pending_response("1");
    let ces: TestCes = TestCes::start(iis(move |_| Reply::new(200).body(&pending))).await;
    let err: AdcsError = enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
        .await
        .expect_err("no token");
    assert!(matches!(err, AdcsError::MutualAuth { .. }), "{err}");
}

#[tokio::test]
async fn a_forged_response_token_fails_mutual_authentication() {
    let pending: String = pending_response("1");
    let forged: String = format!("Negotiate {}", b64(b"forged"));
    let ces: TestCes = TestCes::start(iis(move |_| {
        Reply::new(200)
            .body(&pending)
            .header("www-authenticate", &forged)
    }))
    .await;
    let err: AdcsError = enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
        .await
        .expect_err("forged");
    assert!(
        matches!(&err, AdcsError::MutualAuth { reason } if reason.contains("rejected")),
        "{err}"
    );
}

#[tokio::test]
async fn a_context_left_incomplete_fails_mutual_authentication() {
    let pending: String = pending_response("1");
    let ces: TestCes = TestCes::start(iis(move |_| Reply::new(200).body(&pending).proven())).await;
    let gss: Arc<FakeGss> = FakeGss::new(Acquisition::Succeeds, Mutual::StaysIncomplete);
    let err: AdcsError = enroll_with(gss, &ces.params(), &password(), b"csr")
        .await
        .expect_err("incomplete");
    assert!(
        matches!(&err, AdcsError::MutualAuth { reason } if reason.contains("incomplete")),
        "{err}"
    );
}

// ---------------------------------------------------------------- SPNEGO and ticket failures

#[tokio::test]
async fn a_second_401_names_the_binding_the_spn_and_the_ticket() {
    let ces: TestCes = TestCes::start(Arc::new(|_: &Seen| {
        Reply::new(401).header("www-authenticate", "Negotiate")
    }))
    .await;
    let err: AdcsError = enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
        .await
        .expect_err("refused");
    let shown: String = err.to_string();
    assert!(matches!(err, AdcsError::Spnego { .. }), "{shown}");
    for hint in ["refused", "channel binding", "SPN", "ticket"] {
        assert!(shown.contains(hint), "{hint} missing from {shown}");
    }
    assert_eq!(ces.seen().len(), 2);
}

#[tokio::test]
async fn an_endpoint_that_does_not_ask_for_negotiate_is_refused_before_any_ticket() {
    let open: TestCes = TestCes::start(Arc::new(|_: &Seen| Reply::new(200))).await;
    let gss: Arc<FakeGss> = FakeGss::working();
    let err: AdcsError = enroll_with(Arc::clone(&gss), &open.params(), &password(), b"csr")
        .await
        .expect_err("no 401");
    assert!(
        matches!(&err, AdcsError::Spnego { reason } if reason.contains("200")),
        "{err}"
    );

    let basic: TestCes = TestCes::start(Arc::new(|_: &Seen| {
        Reply::new(401)
            .header("www-authenticate", "Basic realm=\"ces\"")
            .header("www-authenticate", "NTLM")
    }))
    .await;
    let err: AdcsError = enroll_with(Arc::clone(&gss), &basic.params(), &password(), b"csr")
        .await
        .expect_err("no Negotiate");
    assert!(
        matches!(&err, AdcsError::Spnego { reason } if reason.contains("does not offer Negotiate")),
        "{err}"
    );
    assert!(gss.log().principals.is_empty(), "no ticket was asked for");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let ces: TestCes = TestCes::start(Arc::new(|_: &Seen| {
        Reply::new(302).header("location", "https://elsewhere.corp.example.org/CES")
    }))
    .await;
    let err: AdcsError = enroll_with(FakeGss::working(), &ces.params(), &password(), b"csr")
        .await
        .expect_err("redirect");
    assert!(
        matches!(&err, AdcsError::Spnego { reason } if reason.contains("302")),
        "{err}"
    );
    assert_eq!(ces.seen().len(), 1);
}

#[tokio::test]
async fn a_rejected_password_is_a_classified_ticket_error_and_sends_no_token() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(200).proven())).await;
    let gss: Arc<FakeGss> = FakeGss::new(
        Acquisition::Fails(PREAUTH_FAILED_MINOR, "Preauthentication failed"),
        Mutual::Completes,
    );
    let err: AdcsError = enroll_with(gss, &ces.params(), &password(), b"csr")
        .await
        .expect_err("rejected");
    assert_eq!(
        err.ticket_failure(),
        Some(TicketFailure::CredentialRejected)
    );
    assert!(
        matches!(
            err,
            AdcsError::Ticket {
                kdc_error_code: Some(24),
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(ces.seen().len(), 1, "only the unauthenticated request");
}

// ---------------------------------------------------------------- TLS and trust (AC #10)

#[tokio::test]
async fn a_server_outside_the_trust_bundle_is_a_tls_error() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(200).proven())).await;
    let (_, other_pem, _): (Vec<u8>, String, KeyPair) = self_signed_localhost();
    let mut params: CesParams = ces.params();
    params.trust_bundle_pem = Some(other_pem);
    let gss: Arc<FakeGss> = FakeGss::working();
    let err: AdcsError = enroll_with(Arc::clone(&gss), &params, &password(), b"csr")
        .await
        .expect_err("untrusted");
    assert!(matches!(err, AdcsError::Tls { .. }), "{err}");
    assert!(gss.log().principals.is_empty());
}

#[tokio::test]
async fn a_bundle_without_certificates_is_refused() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(200).proven())).await;
    let mut params: CesParams = ces.params();
    params.trust_bundle_pem = Some("not a PEM bundle".to_owned());
    let err: AdcsError = enroll_with(FakeGss::working(), &params, &password(), b"csr")
        .await
        .expect_err("empty bundle");
    assert!(
        matches!(&err, AdcsError::Tls { reason } if reason.contains("no PEM certificate")),
        "{err}"
    );
    assert!(ces.seen().is_empty());
}

// ---------------------------------------------------------------- bounds (AC #9)

#[tokio::test]
async fn the_outer_guard_bounds_the_whole_operation() {
    let ces: TestCes = TestCes::start(Arc::new(|_: &Seen| {
        Reply::new(401)
            .header("www-authenticate", "Negotiate")
            .after(Duration::from_secs(5))
    }))
    .await;
    let mut params: CesParams = ces.params();
    params.timeouts.operation = Duration::from_millis(300);
    let err: AdcsError = enroll_with(FakeGss::working(), &params, &password(), b"csr")
        .await
        .expect_err("timeout");
    assert!(matches!(err, AdcsError::Timeout { .. }), "{err}");
}

#[tokio::test]
async fn the_read_timeout_bounds_a_silent_server() {
    let ces: TestCes = TestCes::start(Arc::new(|_: &Seen| {
        Reply::new(401)
            .header("www-authenticate", "Negotiate")
            .after(Duration::from_secs(5))
    }))
    .await;
    let mut params: CesParams = ces.params();
    params.timeouts.read = Duration::from_millis(300);
    let err: AdcsError = enroll_with(FakeGss::working(), &params, &password(), b"csr")
        .await
        .expect_err("read timeout");
    assert!(
        matches!(&err, AdcsError::Http { stage, reason } if *stage == PROBE && reason.contains("timed out")),
        "{err}"
    );
}

// ---------------------------------------------------------------- parameters

#[tokio::test]
async fn unusable_parameters_are_refused_before_anything_is_sent() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(200).proven())).await;
    let base: CesParams = ces.params();
    let mut cases: Vec<CesParams> = Vec::new();
    for endpoint in [
        "http://ces.corp.example.org/CES",
        "https://192.0.2.10/CES",
        "https://user:secret@ces.corp.example.org/CES",
        "not a url",
    ] {
        cases.push(CesParams {
            endpoint: endpoint.to_owned(),
            ..base.clone()
        });
    }
    for principal in [
        "",
        "svc lorica",
        "svc@OTHER.EXAMPLE.ORG",
        "@CORP.EXAMPLE.ORG",
    ] {
        cases.push(CesParams {
            principal: principal.to_owned(),
            ..base.clone()
        });
    }
    let mut zero: CesParams = base.clone();
    zero.timeouts.connect = Duration::ZERO;
    cases.push(zero);
    for params in cases {
        let err: AdcsError = enroll_with(FakeGss::working(), &params, &password(), b"csr")
            .await
            .expect_err("refused");
        assert!(matches!(err, AdcsError::InvalidParams { .. }), "{err}");
    }
    assert!(ces.seen().is_empty());
}

#[test]
fn a_principal_with_its_realm_is_kept() {
    let realm: Realm = Realm::new("CORP.EXAMPLE.ORG").expect("realm");
    assert_eq!(
        principal_name("svc-lorica@CORP.EXAMPLE.ORG", &realm).expect("principal"),
        "svc-lorica@CORP.EXAMPLE.ORG"
    );
    assert_eq!(
        principal_name("svc-lorica", &realm).expect("principal"),
        "svc-lorica@CORP.EXAMPLE.ORG"
    );
}

// ---------------------------------------------------------------- test_connection

#[tokio::test]
async fn the_connection_test_authenticates_a_get_and_requests_nothing() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(405).proven())).await;
    let gss: Arc<FakeGss> = FakeGss::working();
    test_connection_with(Arc::clone(&gss), &ces.params(), &password())
        .await
        .expect("authenticated");
    let seen: Vec<Seen> = ces.seen();
    assert_eq!(seen.len(), 2);
    for request in &seen {
        assert_eq!(request.method, "GET");
        assert!(request.body.is_empty());
    }
    assert_eq!(gss.log().bindings.len(), 2);
}

#[tokio::test]
async fn the_connection_test_requires_mutual_authentication() {
    let ces: TestCes = TestCes::start(iis(|_| Reply::new(400))).await;
    let err: AdcsError = test_connection_with(FakeGss::working(), &ces.params(), &password())
        .await
        .expect_err("no token");
    assert!(matches!(err, AdcsError::MutualAuth { .. }), "{err}");
}

#[test]
fn negotiate_challenges_are_read_from_every_header_and_list() {
    let mut headers: HeaderMap = HeaderMap::new();
    headers.append(WWW_AUTHENTICATE, "NTLM, Negotiate".parse().expect("value"));
    headers.append(
        WWW_AUTHENTICATE,
        "negotiate c2VydmVy".parse().expect("value"),
    );
    assert_eq!(
        negotiate_challenges(&headers),
        vec![None, Some("c2VydmVy".to_owned())]
    );
}
