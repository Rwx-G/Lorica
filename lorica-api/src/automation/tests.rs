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

//! The automation plane's chain (Story 10.3), through the real
//! router: source filter above, then TLS, the bearer gate, the scope
//! gate and the audit layer, each exercised on `whoami` and on a
//! refused request.

use crate::automation::test_support::{automation_send, mint_automation};
use crate::server::AppState;
use crate::tests::{body_json, setup_admin_and_login, test_state};
use axum::http::StatusCode;
use std::sync::Arc;

/// A live token carrying `environments:read`, the narrowest grant that
/// reaches the environment resource.
async fn mint_live_reader(state: &AppState, name: &str) -> String {
    mint_automation(
        state,
        name,
        vec![lorica_config::models::AutomationScope::EnvironmentsRead],
        &["*.preview.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await
}

/// Every `automation.` audit action recorded so far, sorted.
///
/// Async because `record` only enqueues: the rows are durable within
/// the audit writer's next drain, so the flush is what makes "recorded
/// so far" a true statement.
async fn automation_audit_actions(state: &AppState) -> Vec<String> {
    let log_store = state.log_store.clone().expect("test setup: log store");
    log_store
        .flush_audit()
        .await
        .expect("the audit writer drains");
    let (rows, _total) = log_store
        .query_audit(&crate::audit::AuditQuery {
            operator: None,
            action_prefix: Some("automation.".to_string()),
            from: None,
            to: None,
            limit: 50,
            before_id: None,
            node_id: None,
        })
        .expect("audit query");
    let mut actions: Vec<String> = rows.into_iter().map(|row| row.action).collect();
    actions.sort();
    actions
}

#[tokio::test]
async fn automation_whoami_reports_the_token_behind_the_request() {
    let (state, _session_store, _rate_limiter) = test_state().await;
    let token = mint_live_reader(&state, "ci-preview").await;

    let response = automation_send(
        &state,
        "/automation/v1/whoami",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let public_id = token.split('.').next().expect("token has two halves");
    let body = body_json(response).await;
    assert_eq!(body["data"]["name"], "ci-preview");
    assert_eq!(body["data"]["public_id"], public_id);
    assert_eq!(
        body["data"]["scopes"],
        serde_json::json!(["environments:read"])
    );

    // A token that was accepted is a token in use.
    let store = state.store.lock().await;
    let stored = store
        .get_automation_token(public_id)
        .expect("stored token")
        .expect("stored token");
    assert!(
        stored.last_used_at.is_some(),
        "accepting a token must stamp last_used_at"
    );
}

#[tokio::test]
async fn automation_without_a_bearer_token_is_challenged() {
    let (state, _session_store, _rate_limiter) = test_state().await;

    let response = automation_send(&state, "/automation/v1/whoami", None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"lorica-automation\"")
    );
}

#[tokio::test]
async fn a_dashboard_session_cookie_is_not_an_automation_credential() {
    // The two planes share no credential. A cookie that opens every
    // management endpoint opens nothing here, and the automation
    // router has no cookie layer to read it with in the first place.
    let (state, session_store, rate_limiter) = test_state().await;
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let response = automation_send(&state, "/automation/v1/whoami", None, Some(&admin)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"lorica-automation\"")
    );
}

#[tokio::test]
async fn a_revoked_automation_token_is_refused_on_the_next_request() {
    let (state, _session_store, _rate_limiter) = test_state().await;
    let token = mint_live_reader(&state, "revoked-soon").await;
    let public_id = token
        .split('.')
        .next()
        .expect("token has two halves")
        .to_string();

    let response = automation_send(
        &state,
        "/automation/v1/whoami",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    {
        let store = state.store.lock().await;
        assert!(store
            .revoke_automation_token(&public_id, chrono::Utc::now())
            .expect("revoke"));
    }

    // Nothing is cached, so the revoke takes effect immediately.
    let response = automation_send(
        &state,
        "/automation/v1/whoami",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_expired_automation_token_is_refused() {
    let (state, _session_store, _rate_limiter) = test_state().await;
    let token = mint_automation(
        &state,
        "expired",
        vec![lorica_config::models::AutomationScope::EnvironmentsRead],
        &["*.preview.example.com"],
        chrono::Utc::now() - chrono::Duration::minutes(1),
        None,
    )
    .await;

    let response = automation_send(
        &state,
        "/automation/v1/whoami",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_without_the_scope_is_forbidden_and_not_unauthorized() {
    // 403, not 401. The caller authenticated: their credential is
    // real and the grant is missing. Answering 401 would tell them to
    // present a credential they just presented successfully, and would
    // send an operator to re-mint a token that was never the problem.
    //
    // The environment collection and not `whoami`: since Story 11.1
    // `whoami` is reachable by any live token, so it is no longer a
    // path that can demonstrate a missing grant.
    let (state, _session_store, _rate_limiter) = test_state().await;
    let token = mint_automation(
        &state,
        "write-only",
        vec![lorica_config::models::AutomationScope::EnvironmentsWrite],
        &["*.preview.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;

    let response = automation_send(
        &state,
        "/automation/v1/environments",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");

    // And the grant it does carry still reaches what it is for, so the
    // 403 above is the scope gate and not a broken route.
    let response = automation_send(
        &state,
        "/automation/v1/whoami",
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a token carrying no environment read grant still asks what it is"
    );
}

#[tokio::test]
async fn a_malformed_automation_token_is_refused_without_a_store_lookup() {
    let (state, _session_store, _rate_limiter) = test_state().await;

    // Holding the store mutex for the whole test is what makes the
    // absence of a lookup observable: anything reaching the store
    // queues behind this guard and never answers.
    let _guard = state.store.lock().await;

    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        automation_send(
            &state,
            "/automation/v1/whoami",
            Some("Bearer not-a-token"),
            None,
        ),
    )
    .await
    .expect("the shape guard must answer before any store access");
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    // Control for the assertion above: a well-shaped token DOES reach
    // the store, so the same timeout would have caught a lookup on the
    // malformed path. 24 hex characters and 43 base64url characters
    // are exactly a minted token's two halves.
    let well_shaped = format!("Bearer {}.{}", "0".repeat(24), "A".repeat(43));
    let blocked = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        automation_send(&state, "/automation/v1/whoami", Some(&well_shaped), None),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a well-shaped token must reach the store, otherwise the timeout above proves nothing"
    );
}

#[tokio::test]
async fn every_automation_request_lands_in_the_audit_log() {
    let data_dir = tempfile::tempdir().expect("test tempdir");
    let (mut state, session_store, rate_limiter) = test_state().await;
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let live = mint_live_reader(&state, "ci-preview").await;
    let write_only = mint_automation(
        &state,
        "write-only",
        vec![lorica_config::models::AutomationScope::EnvironmentsWrite],
        &["*.preview.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;

    // The 403 asks for the environment collection rather than
    // `whoami`: since Story 11.1 `whoami` is reachable by any live
    // token, so a scope refusal has to be driven at a path that still
    // demands one.
    const WHOAMI: &str = "/automation/v1/whoami";
    const ENVIRONMENTS: &str = "/automation/v1/environments";
    for (path, auth, cookie, expected) in [
        (WHOAMI, Some(format!("Bearer {live}")), None, StatusCode::OK),
        (WHOAMI, None, None, StatusCode::UNAUTHORIZED),
        (WHOAMI, None, Some(admin.clone()), StatusCode::UNAUTHORIZED),
        (
            WHOAMI,
            Some("Bearer not-a-token".to_string()),
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            ENVIRONMENTS,
            Some(format!("Bearer {write_only}")),
            None,
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = automation_send(&state, path, auth.as_deref(), cookie.as_deref()).await;
        assert_eq!(response.status(), expected, "{path} {auth:?}");
    }

    assert_eq!(
        automation_audit_actions(&state).await,
        vec![
            // The verb carries the precise cause after a colon, which
            // is how `GET /api/v1/audit` shows an operator why a
            // request was turned away (the wire said only 401 or 403).
            "automation.request.forbidden:environments:read",
            "automation.request.ok",
            "automation.request.unauthenticated:no_bearer",
            "automation.request.unauthenticated:no_bearer",
            "automation.request.unauthenticated:not_a_credential",
        ]
    );

    let log_store = state.log_store.clone().expect("log store");
    let (rows, _total) = log_store
        .query_audit(&crate::audit::AuditQuery {
            operator: None,
            action_prefix: Some("automation.".to_string()),
            from: None,
            to: None,
            limit: 50,
            before_id: None,
            node_id: None,
        })
        .expect("audit query");
    for row in &rows {
        assert_eq!(row.operator_role, "automation");
        assert_eq!(row.target_type, "automation_request");
        // The target names the request, so the one row driven at
        // another path says so rather than being smoothed over.
        let expected_target = if row.action.starts_with("automation.request.forbidden") {
            format!("GET {ENVIRONMENTS}")
        } else {
            format!("GET {WHOAMI}")
        };
        assert_eq!(row.target_id, expected_target);
    }

    // The row names the credential: its label and the id an operator
    // revokes. A request that never authenticated names neither.
    let ok_row = rows
        .iter()
        .find(|row| row.action == "automation.request.ok")
        .expect("the successful request is audited");
    let public_id = live.split('.').next().expect("token has two halves");
    assert_eq!(
        ok_row.operator_username,
        format!("ci-preview ({public_id})")
    );
    assert!(rows
        .iter()
        .filter(|row| row.action == "automation.request.unauthenticated")
        .all(|row| row.operator_username == "-"));
}

// ---- Story 12.3 D-m: `allow_local_backend` is never a token's ----

/// No write path of the automation plane names a stream, so no token and
/// no MCP tool (each a request to one of these paths) writes a stream
/// field, `allow_local_backend` included. The one read that names a
/// stream is its SLA (Story 12.9), which answers figures and no field.
/// Story 12.10 brings streams to this plane and must keep the flag out
/// of it.
#[test]
fn no_automation_write_path_reaches_a_stream() {
    let table = crate::automation::route_table();
    assert!(!table.is_empty());
    for route in table {
        if route.method == http::Method::GET {
            continue;
        }
        assert!(
            !route.path.contains("stream"),
            "{} {} reaches a stream",
            route.method,
            route.path
        );
    }
}

/// The address of a backend a stream with `allow_local_backend`
/// forwards to does not move under a token, on the plane's path, its
/// preview and the MCP tool that drives it; the refusal names the
/// stream, never an address. The same token keeps every other write on
/// that backend, and the address of a backend of an ordinary stream.
#[tokio::test]
async fn a_token_cannot_move_a_backend_a_stream_allowing_local_backends_forwards_to() {
    use crate::automation::test_support::{
        a_node_with_something_to_write, automation_call, mcp_call,
    };

    let f = a_node_with_something_to_write().await;
    let created = crate::tests::send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/streams",
        &f.admin,
        Some(serde_json::json!({
            "name": "pg",
            "protocol": "tcp",
            "listen_address": "0.0.0.0",
            "port_first": 5432,
            "allow_local_backend": true,
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let stream_id = body_json(created).await["data"]["id"]
        .as_str()
        .expect("an id")
        .to_string();
    let stored_address = || async {
        f.state
            .store
            .lock()
            .await
            .get_backend(&f.backend_id)
            .expect("read")
            .expect("stored")
            .address
    };
    let original = stored_address().await;
    let moved = serde_json::json!({ "address": "10.0.0.11:8080" });
    let path = format!("/automation/v1/backends/{}", f.backend_id);

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("{path}{suffix}"),
            &f.bearer,
            Some(moved.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{suffix}");
        let refusal = body_json(response).await;
        let message = refusal["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("stream `pg`"), "{suffix}: {message}");
        assert!(!message.contains("10.0.0."), "no address: {message}");
    }
    for tool in ["lorica_backend_update", "lorica_backend_update_preview"] {
        let refused = mcp_call(
            &f.state,
            &f.mcp_bearer,
            tool,
            serde_json::json!({ "id": f.backend_id, "backend": moved.clone() }),
        )
        .await;
        assert_eq!(
            refused["result"]["isError"],
            serde_json::json!(true),
            "{refused}"
        );
        let text = refused["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("HTTP 403"), "{tool}: {text}");
        assert!(text.contains("stream `pg`"), "{tool}: {text}");
    }
    assert_eq!(stored_address().await, original, "nothing moved");

    // The rest of the row stays the token's.
    let response = automation_call(
        &f.state,
        "PUT",
        &path,
        &f.bearer,
        Some(serde_json::json!({ "name": "renamed" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // An ordinary stream's backend is the token's to move: rule A still
    // refuses a local address on its own.
    let dropped = crate::tests::send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        &format!("/api/v1/streams/{stream_id}"),
        &f.admin,
        Some(serde_json::json!({ "allow_local_backend": false })),
    )
    .await;
    assert_eq!(dropped.status(), StatusCode::OK);
    let response = automation_call(&f.state, "PUT", &path, &f.bearer, Some(moved)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(stored_address().await, "10.0.0.11:8080");
}
