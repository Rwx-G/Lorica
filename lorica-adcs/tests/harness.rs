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

//! The client against a real MIT KDC and a CES fixture that enforces the
//! channel binding (Story 13.1 IV1 to IV3, AC #9, AC #12).
//!
//! Every test is `#[ignore]`d: it needs the containers of
//! `tests-e2e-docker/adcs/`, and `tests-e2e-docker/adcs/run.sh` runs
//! them with `--ignored` on the harness network. The fixture picks its
//! behaviour from the endpoint path, `/<outcome>/<mutual>/CES`.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use lorica_adcs::{
    build_csr, enroll, krb5_config_path, test_connection, AdcsError, CesParams, CesTimeouts,
    EnrollOutcome, FaultKind, GeneratedCsr, KdcAddress, KdcTiming, KeyType, Krb5Config, Realm,
    Secret, SubjectFields, TicketFailure,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;

const REALM: &str = "CORP.EXAMPLE.ORG";
const PRINCIPAL: &str = "svc-lorica";
const PASSWORD: &str = "harness-only-password";
const KDC: &str = "kdc.corp.example.org";
const CES_HOST: &str = "ces.corp.example.org";
/// The fixture's listener whose certificate is signed under SHA-256.
const SHA256_PORT: u16 = 443;
/// The fixture's listener whose certificate is signed under SHA-512.
const SHA512_PORT: u16 = 8443;
/// A realm whose only KDC accepts connections and never answers.
const BLACKHOLE_REALM: &str = "BLACKHOLE.EXAMPLE.ORG";
const BLACKHOLE_KDC: &str = "blackhole.corp.example.org";
const TEMPLATE: &str = "LoricaWebServer";

/// The generated files' `request_timeout`, which the renderer requires.
/// MIT krb5 before 1.22 ignores it: the black-hole test measured MIT
/// giving up on one silent KDC after about 27 s, which is why the outer
/// guard matters.
const KDC_REQUEST_TIMEOUT_SECS: u32 = 2;

/// The black-hole test's outer guard. Short enough that the test proves
/// the operation ends, long enough that MIT's own give-up, when it comes
/// first, is visible in the error.
const BLACKHOLE_OPERATION: Duration = Duration::from_secs(30);

/// `sha256WithRSAEncryption` and `sha512WithRSAEncryption`.
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

fn harness_dir() -> PathBuf {
    PathBuf::from(std::env::var("ADCS_HARNESS_DIR").unwrap_or_else(|_| "/harness".to_owned()))
}

/// Points `KRB5_CONFIG` at two files the crate's renderer writes: the
/// harness realm, and the black-hole realm.
///
/// `KRB5_CONFIG` is process-wide and every test of this binary shares
/// the process, so it is set exactly once, before the first GSS-API
/// call, as `main` does in the product: changing it later would race
/// MIT's `getenv` on another thread. Both realms therefore live in one
/// colon-separated file list, which MIT reads as one profile, instead
/// of one test rewriting the file another is reading.
fn configure_kerberos() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("lorica-adcs-harness-{}", std::process::id()));
    let timing: KdcTiming = KdcTiming::new(KDC_REQUEST_TIMEOUT_SECS).expect("timing");
    let harness: PathBuf = krb5_config_path(&dir);
    Krb5Config {
        realm: Realm::new(REALM).expect("realm"),
        kdcs: vec![KdcAddress::new(KDC).expect("kdc")],
        timing,
    }
    .write_to(&harness)
    .expect("write the harness krb5.conf");
    let blackhole: PathBuf = dir.join("adcs").join("blackhole.conf");
    Krb5Config {
        realm: Realm::new(BLACKHOLE_REALM).expect("realm"),
        kdcs: vec![KdcAddress::new(BLACKHOLE_KDC).expect("kdc")],
        timing,
    }
    .write_to(&blackhole)
    .expect("write the black-hole krb5.conf");
    std::env::set_var(
        "KRB5_CONFIG",
        format!("{}:{}", harness.display(), blackhole.display()),
    );
}

static KERBEROS: Once = Once::new();
/// The AS-REQ counts read the shared KDC log, so the tests never overlap.
static SERIAL: Mutex<()> = Mutex::new(());

fn run<F: Future<Output = ()>>(test: F) {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    KERBEROS.call_once(configure_kerberos);
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(test);
    // The client now awaits every blocking GSS-API step, so nothing is
    // left running when a test returns; shutting down in the background
    // only keeps a test that fails mid-exchange from hanging the binary.
    runtime.shutdown_background();
}

fn root_ca_pem() -> String {
    std::fs::read_to_string(harness_dir().join("ca").join("root.pem"))
        .expect("the fixture's root CA")
}

fn issuing_ca_der() -> Vec<u8> {
    let pem: String =
        std::fs::read_to_string(harness_dir().join("ca").join("issuing.pem")).expect("issuing CA");
    let (_, parsed): (_, Pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    parsed.contents
}

fn endpoint(port: u16, outcome: &str, mutual: &str) -> String {
    format!("https://{CES_HOST}:{port}/{outcome}/{mutual}/CES")
}

fn params_for(endpoint: String, realm: &str) -> CesParams {
    CesParams {
        endpoint,
        realm: Realm::new(realm).expect("realm"),
        principal: PRINCIPAL.to_owned(),
        trust_bundle_pem: Some(root_ca_pem()),
        timeouts: CesTimeouts::default(),
    }
}

fn params(port: u16, outcome: &str, mutual: &str) -> CesParams {
    params_for(endpoint(port, outcome, mutual), REALM)
}

fn password() -> Secret {
    Secret::new(PASSWORD.to_owned())
}

fn csr(sans: &[&str]) -> GeneratedCsr {
    let sans: Vec<String> = sans.iter().map(|san: &&str| (*san).to_owned()).collect();
    let subject: SubjectFields = SubjectFields {
        country: Some("FR".to_owned()),
        organization: Some("Example Corp".to_owned()),
        ..SubjectFields::default()
    };
    build_csr(&sans, &subject, TEMPLATE, KeyType::Rsa2048).expect("CSR")
}

fn https_client() -> reqwest::Client {
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(root_ca_pem().as_bytes()).expect("root CA"),
        )
        .tls_info(true)
        .build()
        .expect("client")
}

/// The AS-REQ lines the KDC logged for the service account. MIT logs
/// one line per AS-REQ; with pre-authentication required a client's
/// first AS-REQ carries none and is answered `NEEDED_PREAUTH`, and the
/// next one carries the encrypted timestamp and is logged `ISSUE` or
/// `PREAUTH_FAILED`.
fn as_reqs() -> Vec<String> {
    let principal: String = format!(" {PRINCIPAL}@{REALM} for ");
    std::fs::read_to_string(harness_dir().join("kdc.log"))
        .expect("the KDC log")
        .lines()
        .filter(|line: &&str| line.contains("AS_REQ") && line.contains(&principal))
        .map(str::to_owned)
        .collect()
}

fn count(lines: &[String], marker: &str) -> usize {
    lines
        .iter()
        .filter(|line: &&String| line.contains(marker))
        .count()
}

fn san_dns_names(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.subject_alternative_name()
        .expect("SAN extension parses")
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name: &GeneralName<'_>| match name {
                    GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `issuer`'s key signed `cert`, for the RSA PKCS#1 SHA-256
/// signatures the fixture's CAs make.
fn signed_by(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        SHA256_WITH_RSA
    );
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        issuer.public_key().subject_public_key.data.as_ref(),
    )
    .verify(
        cert.tbs_certificate.as_ref(),
        cert.signature_value.data.as_ref(),
    )
    .is_ok()
}

async fn server_signature_algorithm(port: u16) -> String {
    let response: reqwest::Response = https_client()
        .get(endpoint(port, "issued", "valid"))
        .send()
        .await
        .expect("TLS to the fixture");
    let der: Vec<u8> = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .expect("server certificate")
        .to_vec();
    let (_, cert): (_, X509Certificate<'_>) =
        X509Certificate::from_der(&der).expect("server certificate parses");
    cert.signature_algorithm.algorithm.to_id_string()
}

// IV1, first leg: the endpoint answers 401 Negotiate to a request
// without credentials, on both methods the client uses.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn iv1_a_request_without_credentials_gets_401_negotiate() {
    run(async {
        let client: reqwest::Client = https_client();
        for request in [
            client.get(endpoint(SHA256_PORT, "issued", "valid")),
            client
                .post(endpoint(SHA256_PORT, "issued", "valid"))
                .body("<s:Envelope/>"),
        ] {
            let response: reqwest::Response = request.send().await.expect("request");
            assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            let challenge: &str = response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .expect("WWW-Authenticate")
                .to_str()
                .expect("ASCII");
            assert_eq!(challenge, "Negotiate");
        }
    });
}

// IV1, second leg, and the Lot 3 open question on AS-REQs: one
// connection test authenticates, and acquires its ticket with exactly
// one pre-authenticated AS-REQ. Every failed pre-authentication counts
// against the account lockout (Epic 13 D15), so a second acquisition per
// operation would halve the attempts an operator has.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn iv1_a_bound_token_authenticates_with_one_ticket_request() {
    run(async {
        let before: Vec<String> = as_reqs();
        test_connection(&params(SHA256_PORT, "issued", "valid"), &password())
            .await
            .expect("test_connection against the harness");
        let after: Vec<String> = as_reqs();
        let new: &[String] = &after[before.len()..];
        println!("AS-REQs of one test_connection:\n{}", new.join("\n"));
        assert_eq!(
            count(new, "ISSUE:"),
            1,
            "one test_connection must obtain exactly one ticket"
        );
        assert_eq!(
            count(new, "ISSUE:") + count(new, "PREAUTH_FAILED"),
            1,
            "exactly one AS-REQ may carry pre-authentication"
        );
    });
}

// IV2: the binding hash follows the certificate's signature hash
// (RFC 5929 4.1), so SHA-256 and SHA-512 server certificates both
// authenticate. The fixture's certificates are checked first, so the
// test cannot pass on two SHA-256 listeners.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn iv2_sha256_and_sha512_server_certificates_both_authenticate() {
    run(async {
        for (port, algorithm) in [
            (SHA256_PORT, SHA256_WITH_RSA),
            (SHA512_PORT, SHA512_WITH_RSA),
        ] {
            assert_eq!(server_signature_algorithm(port).await, algorithm);
            test_connection(&params(port, "issued", "valid"), &password())
                .await
                .unwrap_or_else(|err: AdcsError| panic!("port {port}: {err}"));
        }
    });
}

// IV3: an answer without a response token, or with a forged one, fails
// the exchange as a mutual-authentication failure.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn iv3_a_missing_or_forged_response_token_fails_mutual_authentication() {
    run(async {
        for mutual in ["none", "forged"] {
            let err: AdcsError =
                test_connection(&params(SHA256_PORT, "issued", mutual), &password())
                    .await
                    .expect_err("no mutual authentication");
            assert!(
                matches!(err, AdcsError::MutualAuth { .. }),
                "{mutual}: {err}"
            );
            let csr: GeneratedCsr = csr(&["web01.corp.example.org"]);
            let err: AdcsError = enroll(
                &params(SHA256_PORT, "issued", mutual),
                &password(),
                &csr.csr_der,
            )
            .await
            .expect_err("an issued answer without mutual authentication is not trusted");
            assert!(
                matches!(err, AdcsError::MutualAuth { .. }),
                "{mutual}: {err}"
            );
        }
    });
}

// Issued: the leaf carries the requested names and key, and the chain
// is the fixture's issuing CA, verified by signature up to the root.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn enroll_issued_returns_the_leaf_and_its_verified_chain() {
    run(async {
        let sans: [&str; 2] = ["web01.corp.example.org", "web01-alt.corp.example.org"];
        let request: GeneratedCsr = csr(&sans);
        let outcome: EnrollOutcome = enroll(
            &params(SHA256_PORT, "issued", "valid"),
            &password(),
            &request.csr_der,
        )
        .await
        .expect("enroll");
        let EnrollOutcome::Issued {
            leaf_der,
            chain_der,
            request_id,
            ..
        } = outcome
        else {
            panic!("expected Issued, got {outcome:?}");
        };
        assert!(request_id.is_some());

        let (_, leaf): (_, X509Certificate<'_>) =
            X509Certificate::from_der(&leaf_der).expect("leaf parses");
        assert_eq!(san_dns_names(&leaf), sans);
        let common_name: Option<&str> = leaf
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());
        assert_eq!(common_name, Some(sans[0]));
        let (_, csr_info): (_, X509CertificationRequest<'_>) =
            X509CertificationRequest::from_der(&request.csr_der).expect("CSR parses");
        assert_eq!(
            leaf.public_key().raw,
            csr_info.certification_request_info.subject_pki.raw,
            "the leaf certifies the CSR's key"
        );

        let issuing: Vec<u8> = issuing_ca_der();
        assert_eq!(chain_der, vec![issuing.clone()], "chain without the root");
        let (_, issuing): (_, X509Certificate<'_>) =
            X509Certificate::from_der(&issuing).expect("issuing CA parses");
        let root_pem: String = root_ca_pem();
        let (_, root_pem): (_, Pem) =
            x509_parser::pem::parse_x509_pem(root_pem.as_bytes()).expect("root PEM");
        let (_, root): (_, X509Certificate<'_>) =
            X509Certificate::from_der(&root_pem.contents).expect("root parses");
        assert!(signed_by(&leaf, &issuing), "leaf signed by the issuing CA");
        assert!(signed_by(&issuing, &root), "issuing CA signed by the root");
    });
}

#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn enroll_pending_keeps_the_request_id() {
    run(async {
        let outcome: EnrollOutcome = enroll(
            &params(SHA256_PORT, "pending", "valid"),
            &password(),
            &csr(&["web02.corp.example.org"]).csr_der,
        )
        .await
        .expect("enroll");
        match outcome {
            EnrollOutcome::Pending { request_id } => assert!(!request_id.is_empty()),
            other => panic!("expected Pending, got {other:?}"),
        }
    });
}

#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn enroll_denied_is_a_denial() {
    run(async {
        let outcome: EnrollOutcome = enroll(
            &params(SHA256_PORT, "denied", "valid"),
            &password(),
            &csr(&["web03.corp.example.org"]).csr_der,
        )
        .await
        .expect("enroll");
        match outcome {
            EnrollOutcome::Denied {
                request_id,
                message,
                ..
            } => {
                assert!(request_id.is_some());
                assert!(message.contains("Denied"), "{message}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    });
}

#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn enroll_faults_are_classified_by_error_code() {
    run(async {
        for (outcome_mode, kind, code) in [
            ("permission", FaultKind::Permission, Some(0x8009_4012)),
            ("template", FaultKind::Template, Some(0x8009_4800)),
            ("nodetail", FaultKind::Other, None),
        ] {
            let outcome: EnrollOutcome = enroll(
                &params(SHA256_PORT, outcome_mode, "valid"),
                &password(),
                &csr(&["web04.corp.example.org"]).csr_der,
            )
            .await
            .expect("enroll");
            match outcome {
                EnrollOutcome::Error {
                    kind: got_kind,
                    error_code,
                    ..
                } => {
                    assert_eq!(got_kind, kind, "{outcome_mode}");
                    assert_eq!(error_code, code, "{outcome_mode}");
                }
                other => panic!("{outcome_mode}: expected Error, got {other:?}"),
            }
        }
    });
}

// A wrong password is a credential rejection carrying the KDC's code,
// and costs the account exactly one failed pre-authentication (D15).
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn a_wrong_password_is_rejected_after_one_failed_preauthentication() {
    run(async {
        let before: Vec<String> = as_reqs();
        let err: AdcsError = test_connection(
            &params(SHA256_PORT, "issued", "valid"),
            &Secret::new("harness-only-wrong-password".to_owned()),
        )
        .await
        .expect_err("a wrong password");
        let after: Vec<String> = as_reqs();
        let new: &[String] = &after[before.len()..];
        println!("AS-REQs of one wrong-password attempt:\n{}", new.join("\n"));
        assert_eq!(
            err.ticket_failure(),
            Some(TicketFailure::CredentialRejected),
            "{err}"
        );
        assert!(
            matches!(
                err,
                AdcsError::Ticket {
                    kdc_error_code: Some(24),
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(count(new, "PREAUTH_FAILED"), 1);
        assert_eq!(count(new, "ISSUE:"), 0);
    });
}

// AC #9: against a KDC that accepts connections and never answers, the
// operation ends, with an error, within its operation timeout.
#[test]
#[ignore = "needs the tests-e2e-docker/adcs harness"]
fn a_kdc_that_never_answers_fails_within_the_operation_timeout() {
    run(async {
        let mut params: CesParams =
            params_for(endpoint(SHA256_PORT, "issued", "valid"), BLACKHOLE_REALM);
        params.timeouts.operation = BLACKHOLE_OPERATION;
        let started: Instant = Instant::now();
        let err: AdcsError = test_connection(&params, &password())
            .await
            .expect_err("no KDC answers");
        let elapsed: Duration = started.elapsed();
        println!("black-hole KDC: failed after {elapsed:?} with: {err}");
        assert!(
            elapsed <= BLACKHOLE_OPERATION + Duration::from_secs(2),
            "took {elapsed:?}"
        );
        match &err {
            AdcsError::Ticket { failure, .. } => {
                assert_eq!(*failure, TicketFailure::KdcUnreachable, "{err}")
            }
            AdcsError::Timeout { after } => assert_eq!(*after, BLACKHOLE_OPERATION),
            other => panic!("expected a ticket or timeout failure, got {other}"),
        }
    });
}
