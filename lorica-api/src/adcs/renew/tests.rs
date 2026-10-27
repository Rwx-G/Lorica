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

//! Tests for AD CS renewal (Story 13.4 Lot 1): the loop through
//! `renewal_tick`, the dashboard's "Renew now", and the automation
//! plane and MCP refusals, with the stand-in authority of the issuance
//! tests behind [`crate::adcs::AdcsClient`].

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use lorica_adcs::FaultKind;
use lorica_config::models::{Certificate, Role};
use lorica_mcp::TierTools as _;
use lorica_notify::events::AlertType;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;

use crate::adcs::issue::tests::{
    alerts_of, issue_v2, issuing, rejected_credential, web01, Answer, StubAuthority,
};
use crate::adcs::tests::Fixture;
use crate::tests::body_json;

/// The loop's window, as production starts it.
const THRESHOLD_DAYS: i64 = 30;

fn renew_path(id: &str) -> String {
    format!("/api/v1/certificates/{id}/renew")
}

impl Fixture {
    /// Issue a certificate for `name`, bind it to a route of that name,
    /// and bring its stored expiry inside the window.
    async fn bound_in_window(&self, name: &str) -> String {
        let resp = self
            .issue(serde_json::json!({ "sans": [name], "key_type": "ecdsa_p256" }))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{name}");
        let id = body_json(resp).await["data"]["id"]
            .as_str()
            .expect("id")
            .to_string();
        self.set_expiry(&id, Duration::days(10)).await;
        let resp = self
            .send(
                "POST",
                "/api/v1/routes",
                &self.admin,
                Some(serde_json::json!({ "hostname": name, "certificate_id": id })),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "route for {name}");
        id
    }

    async fn set_expiry(&self, id: &str, left: Duration) {
        let store = self.state.store.lock().await;
        let mut cert = store.get_certificate(id).expect("read").expect("row");
        cert.not_after = Utc::now() + left;
        store.update_certificate(&cert).expect("expiry set");
    }

    async fn cert(&self, id: &str) -> Certificate {
        self.state
            .store
            .lock()
            .await
            .get_certificate(id)
            .expect("read")
            .expect("row")
    }

    async fn tick(&self) {
        crate::acme::renewal_tick(&self.state, THRESHOLD_DAYS, None).await;
    }

    /// Audit rows of `actor` under `prefix`.
    async fn audit_rows_of(&self, actor: &str, prefix: &str) -> Vec<crate::audit::AuditRecord> {
        let log_store = self.state.log_store.clone().expect("log store");
        log_store.flush_audit().await.expect("the audit drains");
        let (rows, _) = log_store
            .query_audit(&crate::audit::AuditQuery {
                operator: Some(actor.to_string()),
                action_prefix: Some(prefix.to_string()),
                from: None,
                to: None,
                limit: 100,
                before_id: None,
                node_id: None,
            })
            .expect("audit query");
        rows
    }
}

fn utf16be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn of_type(alerts: &[lorica_notify::AlertEvent], kind: AlertType) -> usize {
    alerts.iter().filter(|a| a.alert_type == kind).count()
}

/// IV1, AC #1, #2, #7: a bound certificate in the window is renewed by
/// the loop in place, keeps its id and its route, carries a new key and
/// was requested with its recorded template and its current subject;
/// the attempt is audited as the loop.
#[tokio::test]
async fn iv1_the_loop_renews_a_bound_certificate_in_place_with_its_recorded_template() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    let before: Certificate = {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&id).expect("read").expect("row");
        cert.adcs_template = Some("RecordedTemplate".to_string());
        store.update_certificate(&cert).expect("template recorded");
        cert
    };

    f.tick().await;

    assert_eq!(stub.calls(), 2, "the issuance, then one renewal");
    let after = f.cert(&id).await;
    assert_eq!(f.certificates().await.len(), 1, "no new row");
    assert_ne!(after.fingerprint, before.fingerprint);
    assert_ne!(after.key_pem, before.key_pem, "a new key");
    assert!(
        after.not_after > before.not_after,
        "out of the window again"
    );
    assert_eq!(after.adcs_template.as_deref(), Some("RecordedTemplate"));
    let routes = f.state.store.lock().await.list_routes().expect("routes");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].certificate_id.as_deref(), Some(id.as_str()));

    let csr_der = stub.last_csr();
    assert!(
        contains(&csr_der, &utf16be("RecordedTemplate")),
        "the CSR names the recorded template"
    );
    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("csr");
    let subject = csr.certification_request_info.subject.to_string();
    assert!(subject.contains("O=Example Corp"), "{subject}");
    assert!(subject.contains("C=FR"), "{subject}");
    assert!(subject.contains("CN=web01.corp.example.org"), "{subject}");

    let rows = f
        .audit_rows_of(crate::adcs::ADCS_RENEWAL_ACTOR, "adcs.certificate.issue.")
        .await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].action, format!("adcs.certificate.issue.ok:{id}"));
    assert_eq!(rows[0].operator_role, "node");

    f.tick().await;
    assert_eq!(stub.calls(), 2, "renewed out of the window");
}

/// AC #1: unbound, opted out, outside the window, and uploaded
/// certificates are not renewed by the loop.
#[tokio::test]
async fn the_loop_leaves_ineligible_certificates_alone() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    let unbound = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    f.set_expiry(&unbound, Duration::days(5)).await;
    let opted_out = f.bound_in_window("api.corp.example.org").await;
    {
        let store = f.state.store.lock().await;
        let mut cert = store
            .get_certificate(&opted_out)
            .expect("read")
            .expect("row");
        cert.acme_auto_renew = false;
        store.update_certificate(&cert).expect("opt out");
    }
    let far = f.bound_in_window("far.corp.example.org").await;
    f.set_expiry(&far, Duration::days(THRESHOLD_DAYS + 5)).await;
    let manual = f.bound_in_window("manual.corp.example.org").await;
    {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&manual).expect("read").expect("row");
        cert.adcs_authority_id = None;
        store.update_certificate(&cert).expect("reverted to manual");
    }
    let issued = stub.calls();

    f.tick().await;
    assert_eq!(stub.calls(), issued, "nothing was eligible");
}

/// IV2, AC #3: a wrong password and five certificates in the window:
/// one tick makes one attempt, raises one `adcs_authority_failed`, and
/// neither a later tick nor "Renew now" reaches the authority again.
#[tokio::test]
async fn iv2_a_rejected_credential_stops_the_tick_after_one_attempt() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let mut ids = Vec::new();
    for n in 1..=5 {
        ids.push(
            f.bound_in_window(&format!("web0{n}.corp.example.org"))
                .await,
        );
    }
    alerts_of(&mut received);
    let issued = stub.calls();
    stub.set_answer(Answer::Fail(rejected_credential));

    f.tick().await;

    assert_eq!(stub.calls(), issued + 1, "one ticket attempt for the tick");
    let raised = alerts_of(&mut received);
    assert_eq!(of_type(&raised, AlertType::AdcsAuthorityFailed), 1);
    assert_eq!(
        of_type(&raised, AlertType::CertIssuanceFailed),
        1,
        "only the attempted certificate alerts"
    );
    assert!(f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row")
        .is_failed());
    let now = Utc::now();
    for id in &ids {
        assert_eq!(
            f.state.adcs.renewals.backoff_until(id, now),
            None,
            "a credential failure backs off no certificate"
        );
    }

    f.tick().await;
    let resp = f.send("POST", &renew_path(&ids[3]), &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(resp).await["error"]["code"], "adcs_failed_state");
    assert_eq!(stub.calls(), issued + 1, "the failed state spends nothing");
    assert!(alerts_of(&mut received).is_empty());
    assert_eq!(
        f.audit_rows_of(crate::adcs::ADCS_RENEWAL_ACTOR, "adcs.certificate.issue.")
            .await
            .len(),
        1,
        "the certificates not attempted wrote no row"
    );
}

/// AC #5: a non-credential failure keeps the certificate, backs it off,
/// and alerts once per failure state: a repeat is silent, a different
/// step alerts, and a success re-arms the alert.
#[tokio::test]
async fn a_failure_backs_off_and_alerts_once_per_failure_state() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    let fingerprint = f.cert(&id).await.fingerprint;
    alerts_of(&mut received);
    let issued = stub.calls();
    stub.set_answer(Answer::Fault(FaultKind::Template));

    f.tick().await;
    assert_eq!(stub.calls(), issued + 1);
    assert_eq!(
        f.cert(&id).await.fingerprint,
        fingerprint,
        "kept in service"
    );
    let raised = alerts_of(&mut received);
    assert_eq!(raised.len(), 1);
    assert_eq!(
        raised[0].details.get("step").map(String::as_str),
        Some("fault_template")
    );
    let now = Utc::now();
    let until = f
        .state
        .adcs
        .renewals
        .backoff_until(&id, now)
        .expect("backed off");
    assert!(until > now + Duration::hours(crate::adcs::ADCS_RENEWAL_BACKOFF_HOURS - 1));
    assert!(
        f.state.renewals.cooldown_until(&id, now).is_none(),
        "the ACME cooldown is not used"
    );

    f.tick().await;
    assert_eq!(stub.calls(), issued + 1, "the back-off holds");

    let cert = f.cert(&id).await;
    let later = |hours: i64| now + Duration::hours(hours);
    crate::adcs::renew_due(&f.state, &[&cert], later(25)).await;
    assert_eq!(stub.calls(), issued + 2);
    assert!(alerts_of(&mut received).is_empty(), "same state, no alert");

    stub.set_answer(Answer::Denied);
    crate::adcs::renew_due(&f.state, &[&cert], later(50)).await;
    assert_eq!(stub.calls(), issued + 3);
    let raised = alerts_of(&mut received);
    assert_eq!(raised.len(), 1, "a new state alerts");
    assert_eq!(
        raised[0].details.get("step").map(String::as_str),
        Some("denied")
    );

    stub.set_answer(issue_v2());
    crate::adcs::renew_due(&f.state, &[&cert], later(75)).await;
    assert_ne!(f.cert(&id).await.fingerprint, fingerprint, "renewed");
    assert_eq!(f.state.adcs.renewals.backoff_until(&id, later(75)), None);

    stub.set_answer(Answer::Denied);
    let cert = f.cert(&id).await;
    crate::adcs::renew_due(&f.state, &[&cert], later(76)).await;
    assert_eq!(
        alerts_of(&mut received).len(),
        1,
        "a success re-arms the alert"
    );
}

/// AC #4: a pending answer keeps the current certificate, stores
/// nothing, is alerted naming the request, and backs off.
#[tokio::test]
async fn a_pending_renewal_is_a_failure_naming_the_request() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    let before = f.cert(&id).await;
    alerts_of(&mut received);
    stub.set_answer(Answer::Pending);

    f.tick().await;

    let after = f.cert(&id).await;
    assert_eq!(after.fingerprint, before.fingerprint);
    assert_eq!(after.adcs_request_id, before.adcs_request_id);
    let raised = alerts_of(&mut received);
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].alert_type, AlertType::CertIssuanceFailed);
    assert_eq!(
        raised[0].details.get("request_id").map(String::as_str),
        Some("77")
    );
    assert_eq!(
        raised[0].details.get("cert_id").map(String::as_str),
        Some(id.as_str())
    );
    assert!(f
        .state
        .adcs
        .renewals
        .backoff_until(&id, Utc::now())
        .is_some());
}

/// AC #6: for an AD CS certificate the expiry alert is
/// `check_cert_expiry`'s alone; the loop sends no `CertExpiring`.
#[tokio::test]
async fn an_adcs_certificate_gets_one_expiry_alert_from_the_expiry_check_only() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts.clone())).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    alerts_of(&mut received);
    stub.set_answer(Answer::Pending);

    crate::acme::renewal_tick(&f.state, THRESHOLD_DAYS, Some(&alerts)).await;
    let from_loop = alerts_of(&mut received);
    assert_eq!(of_type(&from_loop, AlertType::CertExpiring), 0);
    assert_eq!(of_type(&from_loop, AlertType::CertIssuanceFailed), 1);

    crate::acme::check_cert_expiry(&f.state, &alerts).await;
    let expiring: Vec<_> = alerts_of(&mut received)
        .into_iter()
        .filter(|a| {
            a.alert_type == AlertType::CertExpiring
                && a.details.get("cert_id").map(String::as_str) == Some(id.as_str())
        })
        .collect();
    assert_eq!(expiring.len(), 1);
}

/// AC #2, #7, #8: "Renew now" from the dashboard renews in place and
/// answers the renewed view; a renewal in flight is 409; a pending
/// answer is 202 naming the request; a viewer cannot renew.
#[tokio::test]
async fn renew_now_on_the_dashboard_renews_in_place() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    let id = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let before = f.cert(&id).await;
    let operator = f.user("operator-renew", Role::Operator).await;

    let resp = f.send("POST", &renew_path(&id), &operator, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp).await["data"].clone();
    assert_eq!(data["id"], id);
    assert_eq!(data["source"], "adcs");
    assert!(data["subject"]
        .as_str()
        .is_some_and(|s| s.contains("CN=web01.corp.example.org")));
    assert!(data["not_after"].is_string());
    let after = f.cert(&id).await;
    assert_ne!(after.fingerprint, before.fingerprint);
    assert_eq!(f.certificates().await.len(), 1);
    let rows = f.audit_rows_of("operator-renew", "").await;
    let actions: Vec<&str> = rows.iter().map(|row| row.action.as_str()).collect();
    assert!(actions.contains(&"certificate.renew"), "{actions:?}");
    assert!(
        actions.contains(&format!("adcs.certificate.issue.ok:{id}").as_str()),
        "{actions:?}"
    );

    let held = f.state.renewals.begin(&id).expect("free");
    let calls = stub.calls();
    let resp = f.send("POST", &renew_path(&id), &operator, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(stub.calls(), calls, "refused before the authority");
    drop(held);

    stub.set_answer(Answer::Pending);
    let resp = f.send("POST", &renew_path(&id), &operator, None).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let data = body_json(resp).await["data"].clone();
    assert_eq!(data["outcome"], "pending");
    assert_eq!(data["request_id"], "77");
    assert_eq!(f.cert(&id).await.fingerprint, after.fingerprint);

    let viewer = f.user("viewer-renew", Role::Viewer).await;
    let resp = f.send("POST", &renew_path(&id), &viewer, None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// "Renew now" of an AD CS certificate spends the bucket issuance
/// spends, not ACME provisioning's: the two sources no longer throttle
/// each other.
#[tokio::test]
async fn renew_now_of_an_adcs_certificate_spends_the_issuance_bucket() {
    use crate::server::{
        RL_ACME_PROVISION, RL_BUCKET_ACME_PROVISION, RL_BUCKET_ADCS_ISSUE, RL_WINDOW_S,
    };
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    let id = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let spend = |bucket: &'static str| {
        let limiter = f.rate_limiter.clone();
        async move {
            let _ = limiter
                .check_bucket(bucket, "127.0.0.1", RL_ACME_PROVISION, RL_WINDOW_S)
                .await;
        }
    };
    for _ in 0..RL_ACME_PROVISION {
        spend(RL_BUCKET_ACME_PROVISION).await;
    }
    let resp = f.send("POST", &renew_path(&id), &f.admin, None).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an exhausted ACME bucket does not stop an AD CS renewal"
    );
    for _ in 1..RL_ACME_PROVISION {
        spend(RL_BUCKET_ADCS_ISSUE).await;
    }
    let calls = stub.calls();
    let resp = f.send("POST", &renew_path(&id), &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(stub.calls(), calls, "refused before the authority");
}

/// AC #8 and D6, the three planes: for an in-grant AD CS certificate
/// the automation route and the MCP tool are refused with
/// `adcs_renewal_not_on_automation_plane` and reach no authority, a
/// token outside the grant learns nothing, and the dashboard renews it.
#[tokio::test]
async fn an_adcs_certificate_is_renewed_on_the_dashboard_and_refused_to_every_token() {
    use crate::automation::test_support::{automation_call, mcp_call, mint_automation};
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let resp = f.issue(web01()).await;
    let id = body_json(resp).await["data"]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let expires = Utc::now() + Duration::days(30);
    let every_scope = mint_automation(
        &f.state,
        "ci-every-scope",
        lorica_config::models::AutomationScope::ALL.to_vec(),
        &["*.corp.example.org"],
        expires,
        None,
    )
    .await;
    let config_tier = mint_automation(
        &f.state,
        "ci-config-tier",
        lorica_mcp::Tier::Config.minted_scopes(),
        &["*.corp.example.org"],
        expires,
        None,
    )
    .await;
    let elsewhere = mint_automation(
        &f.state,
        "ci-elsewhere",
        lorica_config::models::AutomationScope::ALL.to_vec(),
        &["*.other.example.org"],
        expires,
        None,
    )
    .await;
    let calls = stub.calls();
    let path = format!("/automation/v1/certificates/{id}/renew");

    for suffix in ["", "?dry_run=true"] {
        let resp = automation_call(
            &f.state,
            "POST",
            &format!("{path}{suffix}"),
            &format!("Bearer {every_scope}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{suffix}");
        assert_eq!(
            body_json(resp).await["error"]["code"],
            crate::acme::ADCS_NOT_ON_AUTOMATION_PLANE,
            "{suffix}"
        );

        let resp = automation_call(
            &f.state,
            "POST",
            &format!("{path}{suffix}"),
            &format!("Bearer {elsewhere}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{suffix}");
        let text = body_json(resp).await.to_string();
        assert!(
            !text.contains(crate::acme::ADCS_NOT_ON_AUTOMATION_PLANE),
            "a token outside its grant learns nothing about the row: {text}"
        );
    }

    let answered = mcp_call(
        &f.state,
        &format!("Bearer {config_tier}"),
        "lorica_certificate_renew",
        serde_json::json!({ "id": id }),
    )
    .await;
    assert_eq!(answered["result"]["isError"], serde_json::json!(true));
    let text = answered["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains("HTTP 403"), "{text}");
    assert!(
        text.contains(crate::acme::ADCS_NOT_ON_AUTOMATION_PLANE),
        "{text}"
    );
    assert_eq!(stub.calls(), calls, "no token reached the authority");

    let resp = f.send("POST", &renew_path(&id), &f.admin, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(stub.calls(), calls + 1);
    assert_eq!(f.cert(&id).await.id, id);
}

/// Part of the D6 surface: the automation certificate read answers
/// `source` and `subject` and none of the AD CS internals.
#[tokio::test]
async fn the_automation_certificate_read_withholds_the_adcs_internals() {
    use crate::automation::test_support::{automation_call, mint_automation};
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    assert_eq!(f.issue(web01()).await.status(), StatusCode::CREATED);
    let token = mint_automation(
        &f.state,
        "ci-read",
        vec![lorica_config::models::AutomationScope::CertificatesRead],
        &["*.corp.example.org"],
        Utc::now() + Duration::days(30),
        None,
    )
    .await;
    let resp = automation_call(
        &f.state,
        "GET",
        "/automation/v1/certificates",
        &format!("Bearer {token}"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let items = json["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{json}");
    assert_eq!(items[0]["source"], "adcs");
    assert!(items[0]["subject"].is_string());
    for field in crate::automation::redact::ADCS_INTERNAL_FIELDS {
        assert!(items[0].get(*field).is_none(), "{field} answered: {json}");
    }
}

#[test]
fn the_failure_memory_alerts_on_a_new_state_and_forgets_on_success() {
    let memory = Arc::new(crate::adcs::AdcsRenewalMemory::default());
    assert!(memory.is_new_failure_state("c-1", "tls"));
    assert!(!memory.is_new_failure_state("c-1", "tls"));
    assert!(memory.is_new_failure_state("c-1", "denied"));
    assert!(memory.is_new_failure_state("c-2", "denied"));
    memory.forget_failures("c-1");
    assert!(memory.is_new_failure_state("c-1", "denied"));
    let live: std::collections::HashSet<&str> = ["c-1"].into_iter().collect();
    memory.retain(&live, Utc::now());
    assert!(
        memory.is_new_failure_state("c-2", "denied"),
        "c-2 was forgotten"
    );
}

/// The key type of the CSR the stand-in received last.
fn last_csr_key_type(stub: &StubAuthority) -> Result<lorica_config::models::AdcsKeyType, String> {
    let csr_der = stub.last_csr();
    let (_, csr) = X509CertificationRequest::from_der(&csr_der).expect("csr");
    super::generated_key_type(&csr.certification_request_info.subject_pki)
}

/// Story 13.4 fix: a renewal keeps the current certificate's key type
/// and size, whatever the authority's default (RSA 2048 here) says, so
/// a changed default cannot turn a certificate into one its template
/// refuses.
#[tokio::test]
async fn a_renewal_keeps_the_current_key_type_and_size() {
    use lorica_config::models::AdcsKeyType;
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    for (key_type, expected) in [
        ("ecdsa_p256", AdcsKeyType::EcdsaP256),
        ("rsa3072", AdcsKeyType::Rsa3072),
    ] {
        let name = format!("{key_type}.corp.example.org").replace('_', "-");
        let resp = f
            .issue(serde_json::json!({ "sans": [name], "key_type": key_type }))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{key_type}");
        let id = body_json(resp).await["data"]["id"]
            .as_str()
            .expect("id")
            .to_string();
        assert_eq!(last_csr_key_type(&stub), Ok(expected), "{key_type} issued");

        let resp = f.send("POST", &renew_path(&id), &f.admin, None).await;
        assert_eq!(resp.status(), StatusCode::OK, "{key_type}");
        assert_eq!(last_csr_key_type(&stub), Ok(expected), "{key_type} renewed");
    }
}

/// A key Lorica cannot generate is named, so the renewal falls back to
/// the authority's default and says why.
#[test]
fn only_the_key_types_lorica_generates_are_kept() {
    use lorica_config::models::AdcsKeyType;
    let spki_of = |algorithm: &'static rcgen::SignatureAlgorithm| -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(algorithm).expect("test setup: key");
        let params = rcgen::CertificateParams::new(vec!["web01.corp.example.org".to_string()])
            .expect("test setup: params");
        params
            .self_signed(&key)
            .expect("test setup: certificate")
            .der()
            .to_vec()
    };
    let key_type = |der: &[u8]| {
        let (_, cert) = x509_parser::parse_x509_certificate(der).expect("certificate");
        super::generated_key_type(cert.public_key())
    };
    assert_eq!(
        key_type(&spki_of(&rcgen::PKCS_ECDSA_P256_SHA256)),
        Ok(AdcsKeyType::EcdsaP256)
    );
    let p384 = key_type(&spki_of(&rcgen::PKCS_ECDSA_P384_SHA384));
    assert_eq!(p384, Err("an ECDSA key on curve 1.3.132.0.34".to_string()));
    let ed25519 = key_type(&spki_of(&rcgen::PKCS_ED25519));
    assert_eq!(ed25519, Err("a key of algorithm 1.3.101.112".to_string()));
}

fn unreachable_kdc() -> lorica_adcs::AdcsError {
    lorica_adcs::AdcsError::Ticket {
        principal: "svc-lorica@CORP.EXAMPLE.ORG".to_string(),
        failure: lorica_adcs::TicketFailure::KdcUnreachable,
        kdc_error_code: None,
        minor_status: 0,
        message: "Cannot find KDC for realm \"CORP.EXAMPLE.ORG\"".to_string(),
    }
}

/// D3, D15: a tick renews every due certificate on one session, one
/// ticket in production.
#[tokio::test]
async fn a_tick_renews_every_due_certificate_on_one_session() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    for name in ["web01", "web02", "web03"] {
        f.bound_in_window(&format!("{name}.corp.example.org")).await;
    }
    let (calls, opens) = (stub.calls(), stub.opens());

    f.tick().await;

    assert_eq!(stub.calls(), calls + 3, "three renewals");
    assert_eq!(stub.opens(), opens + 1, "one session for the tick");
}

/// Perf H, arch M2: a failure of the authority rather than of one
/// certificate ends the tick after one attempt, without opening the
/// breaker and without backing any certificate off.
#[tokio::test]
async fn a_failure_of_the_authority_ends_the_tick_after_one_attempt() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let mut ids = Vec::new();
    for name in ["web01", "web02", "web03"] {
        ids.push(f.bound_in_window(&format!("{name}.corp.example.org")).await);
    }
    alerts_of(&mut received);
    let calls = stub.calls();
    stub.set_answer(Answer::Fail(unreachable_kdc));

    f.tick().await;

    assert_eq!(stub.calls(), calls + 1, "the first attempt ends the tick");
    let raised = alerts_of(&mut received);
    assert_eq!(of_type(&raised, AlertType::CertIssuanceFailed), 1);
    assert_eq!(of_type(&raised, AlertType::AdcsAuthorityFailed), 0);
    let now = Utc::now();
    for id in &ids {
        assert_eq!(f.state.adcs.renewals.backoff_until(id, now), None, "{id}");
    }
    assert!(!f
        .state
        .store
        .lock()
        .await
        .get_adcs_authority()
        .expect("read")
        .expect("row")
        .is_failed());

    stub.set_answer(issue_v2());
    f.tick().await;
    assert_eq!(stub.calls(), calls + 4, "the next tick renews them all");
}

/// Arch M on renew.rs: each certificate is read again right before its
/// renewal; one reverted, opted out, unbound or already renewed since
/// the tick selected it is left alone.
#[tokio::test]
async fn a_certificate_changed_since_selection_is_not_renewed() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let reverted = f.bound_in_window("web01.corp.example.org").await;
    let opted_out = f.bound_in_window("web02.corp.example.org").await;
    let unbound = f.bound_in_window("web03.corp.example.org").await;
    let renewed = f.bound_in_window("web04.corp.example.org").await;
    let selected: Vec<Certificate> = {
        let mut selected = Vec::new();
        for id in [&reverted, &opted_out, &unbound, &renewed] {
            selected.push(f.cert(id).await);
        }
        selected
    };
    {
        let store = f.state.store.lock().await;
        let mut cert = store
            .get_certificate(&reverted)
            .expect("read")
            .expect("row");
        cert.adcs_authority_id = None;
        store.update_certificate(&cert).expect("reverted");
        let mut cert = store
            .get_certificate(&opted_out)
            .expect("read")
            .expect("row");
        cert.acme_auto_renew = false;
        store.update_certificate(&cert).expect("opted out");
        for mut route in store.list_routes().expect("routes") {
            if route.certificate_id.as_deref() == Some(unbound.as_str()) {
                route.certificate_id = None;
                store.update_route(&route).expect("unbound");
            }
        }
        let mut cert = store.get_certificate(&renewed).expect("read").expect("row");
        cert.fingerprint = "sha256:renewed-meanwhile".to_string();
        store.update_certificate(&cert).expect("renewed");
    }
    let calls = stub.calls();

    let refs: Vec<&Certificate> = selected.iter().collect();
    crate::adcs::renew_due(&f.state, &refs, Utc::now()).await;

    assert_eq!(stub.calls(), calls, "nothing was still due");
    assert_eq!(f.cert(&reverted).await.adcs_authority_id, None);
}

/// Pen L5: a tick that finds another AD CS operation running waits and
/// tries again instead of leaving its renewals to the next tick.
#[tokio::test]
async fn a_tick_waits_for_a_busy_guard_instead_of_giving_up() {
    let stub = StubAuthority::new(issue_v2());
    let mut f = issuing(&stub, None).await;
    f.state.adcs = f
        .state
        .adcs
        .clone()
        .with_busy_retry_delay(std::time::Duration::from_millis(50));
    let id = f.bound_in_window("web01.corp.example.org").await;
    let cert = f.cert(&id).await;
    let calls = stub.calls();

    let permit = f.state.adcs.guard().try_acquire().expect("nothing runs");
    let state = f.state.clone();
    let tick = tokio::spawn(async move {
        crate::adcs::renew_due(&state, &[&cert], Utc::now()).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(stub.calls(), calls, "nothing while the guard is held");
    drop(permit);
    tick.await.expect("the tick ends");

    assert_eq!(stub.calls(), calls + 1, "renewed once the guard was free");
}

/// D17 at renewal: a recorded template the authority no longer lists is
/// refused before the authority is contacted, alerted, and backed off.
#[tokio::test]
async fn a_renewal_with_a_template_no_longer_allowed_is_refused() {
    let stub = StubAuthority::new(issue_v2());
    let alerts = lorica_notify::AlertSender::new(64);
    let mut received = alerts.subscribe();
    let f = issuing(&stub, Some(alerts)).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    {
        let store = f.state.store.lock().await;
        let mut cert = store.get_certificate(&id).expect("read").expect("row");
        cert.adcs_template = Some("RetiredTemplate".to_string());
        store.update_certificate(&cert).expect("template recorded");
    }
    alerts_of(&mut received);
    let calls = stub.calls();

    f.tick().await;

    assert_eq!(stub.calls(), calls, "nothing reached the authority");
    let raised = alerts_of(&mut received);
    assert_eq!(raised.len(), 1);
    assert_eq!(
        raised[0].details.get("step").map(String::as_str),
        Some("template_refused")
    );
    assert!(f
        .state
        .adcs
        .renewals
        .backoff_until(&id, Utc::now())
        .is_some());
}

/// Audit I1, D3: in a process started in secure mode MIT krb5 would
/// read the host's `krb5.conf`, so the connection test, an issuance,
/// "Renew now" and the loop all stop at the `krb5_conf` step, and none
/// reaches the authority.
#[tokio::test]
async fn every_operation_is_refused_when_krb5_config_would_be_ignored() {
    let stub = StubAuthority::new(issue_v2());
    let f = issuing(&stub, None).await;
    let id = f.bound_in_window("web01.corp.example.org").await;
    let not_after = f.cert(&id).await.not_after;
    let calls = stub.calls();
    let f = f.with_krb5_config_ignored();

    let requests: [(&str, String, Option<serde_json::Value>); 3] = [
        ("POST", "/api/v1/adcs/authority/test".to_string(), None),
        (
            "POST",
            "/api/v1/certificates/adcs".to_string(),
            Some(web01()),
        ),
        ("POST", renew_path(&id), None),
    ];
    for (method, uri, request) in requests {
        let resp = f.send(method, &uri, &f.admin, request).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
        let error = body_json(resp).await["error"].clone();
        assert_eq!(error["code"], "adcs_krb5_conf", "{uri}");
        assert_eq!(error["step"], "krb5_conf", "{uri}");
        assert!(
            error["message"]
                .as_str()
                .is_some_and(|message| message.contains("AT_SECURE")),
            "{uri}: {error}"
        );
    }
    f.tick().await;

    assert_eq!(stub.calls(), calls, "nothing reached the authority");
    assert_eq!(
        f.cert(&id).await.not_after,
        not_after,
        "nothing was renewed"
    );
}
