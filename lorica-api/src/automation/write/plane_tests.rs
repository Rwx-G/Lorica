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

//! The write surface (Story 11.2), through the real automation router:
//! the scope each write sits behind, the management row and the request
//! row every write lands, the grant bounding what a write targets, the
//! fields a token may only strengthen, and the previews.

use crate::automation::test_support::{
    a_node_with_something_to_read, a_node_with_something_to_write, allowlisted_settings,
    an_environment_owning, assert_forbidden_naming, assert_no_secret_field_name, audit_rows_under,
    automation_audit_rows, automation_call, automation_send, canonical_now, data_keys,
    mint_automation, WriteFixture, WRITE_TOKEN_NAME,
};
use crate::server::AppState;
use crate::tests::{body_json, parse_data, send, TEST_CERT_RSA_PEM, TEST_KEY_RSA_PEM};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceExt;

#[tokio::test]
async fn an_automation_write_path_needs_its_own_scope_and_no_other() {
    let f = a_node_with_something_to_write().await;

    for (method, path, scope) in crate::automation::scope::WRITE_SURFACE {
        let body = (*method != "DELETE").then(|| serde_json::json!({}));
        let only_this = mint_automation(
            &f.state,
            "narrow",
            vec![*scope],
            &["*.write.example.com"],
            chrono::Utc::now() + chrono::Duration::days(30),
            None,
        )
        .await;
        let response = automation_call(
            &f.state,
            method,
            path,
            &format!("Bearer {only_this}"),
            body.clone(),
        )
        .await;
        // Past the gate the handler answers for itself (a 404 for the
        // placeholder id, a 422 for the empty body); what the gate must
        // not do is refuse the token that carries exactly this grant.
        assert!(
            response.status() != StatusCode::FORBIDDEN
                && response.status() != StatusCode::UNAUTHORIZED,
            "{method} {path} answered {} to a token carrying {scope:?}",
            response.status()
        );

        // The same path, a token holding every OTHER grant there is:
        // every read scope and the environment write included.
        let everything_else: Vec<lorica_config::models::AutomationScope> =
            lorica_config::models::AutomationScope::ALL
                .iter()
                .copied()
                .filter(|held| held != scope)
                .collect();
        let wide = mint_automation(
            &f.state,
            "wide",
            everything_else,
            &["*.write.example.com"],
            chrono::Utc::now() + chrono::Duration::days(30),
            None,
        )
        .await;
        let response =
            automation_call(&f.state, method, path, &format!("Bearer {wide}"), body).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[tokio::test]
async fn iv1_a_route_created_through_the_automation_plane_is_the_dashboards_route_byte_for_byte() {
    // Story 11.2 IV1: the same body through the two doors lands the
    // same stored row, byte for byte in the canonical encoding once
    // the two things a fresh row cannot share, its id and its clock,
    // are set equal. That holds only because the automation handler
    // runs the management handler's own body.
    let f = a_node_with_something_to_write().await;
    let body = serde_json::json!({
        "hostname": "app.write.example.com",
        "path_prefix": "/app",
        "backend_ids": [f.backend_id],
        "certificate_id": f.certificate_id,
        "load_balancing": "random",
        "waf_enabled": true,
        "waf_mode": "blocking",
        "force_https": true,
        "connect_timeout_s": 7,
        "group_name": "prod",
        "hostname_aliases": ["app-alias.write.example.com"],
        "basic_auth_username": "user01",
    });

    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(body.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let automation_view = parse_data(response).await;
    assert_no_secret_field_name(&automation_view, "POST /automation/v1/routes");
    let automation_id = automation_view["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let through_automation = canonical_now(&f.state).await;

    // The hostname can be held once, so the automation row makes room
    // for the dashboard's; the rest of the store is untouched.
    {
        let store = f.state.store.lock().await;
        store
            .delete_route(&automation_id)
            .expect("test setup: the row leaves");
    }

    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let dashboard_view = parse_data(response).await;
    let dashboard_id = dashboard_view["id"].as_str().expect("route id").to_string();
    let mut through_dashboard = canonical_now(&f.state).await;

    let automation_route = through_automation
        .routes
        .iter()
        .find(|route| route.id == automation_id)
        .expect("the automation row is in the canonical config");
    for route in &mut through_dashboard.routes {
        if route.id == dashboard_id {
            route.id = automation_id.clone();
            route.created_at = automation_route.created_at;
            route.updated_at = automation_route.updated_at;
        }
    }
    for link in &mut through_dashboard.route_backends {
        if link.route_id == dashboard_id {
            link.route_id = automation_id.clone();
        }
    }
    // No Basic-auth password rides in the body: an automation token may
    // not send one (`WITHHELD_ROUTE_FIELDS`), so both rows carry the
    // username and no hash, and compare with nothing set equal.
    assert_eq!(
        lorica_config::canonical::encode_canonical(&through_automation).expect("encodes"),
        lorica_config::canonical::encode_canonical(&through_dashboard).expect("encodes"),
        "the route the automation plane wrote and the route the dashboard wrote differ"
    );

    // And the two answers agree to the same extent.
    let strip = |mut view: serde_json::Value| {
        let object = view.as_object_mut().expect("a route view is an object");
        for volatile in ["id", "created_at", "updated_at"] {
            object.remove(volatile);
        }
        view
    };
    assert_eq!(strip(automation_view), strip(dashboard_view));
}

#[tokio::test]
async fn iv2_a_refusal_by_the_management_validators_arrives_unchanged_and_writes_nothing() {
    // Story 11.2 IV2, both halves: the field-level error is the
    // management handler's own, byte for byte, and the store is the
    // store it was before.
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    let refused_by_a_validator = serde_json::json!({
        "hostname": "bad.write.example.com",
        "backend_ids": [f.backend_id],
        "connect_timeout_s": 0,
    });
    let through_automation = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(refused_by_a_validator.clone()),
    )
    .await;
    let through_dashboard = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(refused_by_a_validator),
    )
    .await;
    assert_eq!(through_automation.status(), StatusCode::BAD_REQUEST);
    assert_eq!(through_automation.status(), through_dashboard.status());
    let automation_error = body_json(through_automation).await;
    let dashboard_error = body_json(through_dashboard).await;
    assert_eq!(automation_error, dashboard_error);
    assert!(
        automation_error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("connect_timeout_s")),
        "{automation_error}"
    );

    // The rule the management plane owns on input, refused the same
    // way (422) and with the same words.
    let claims_the_mark = serde_json::json!({
        "hostname": "marked.write.example.com",
        "managed_by": { "kind": "automation", "environment": "pr-42" },
    });
    let through_automation = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(claims_the_mark.clone()),
    )
    .await;
    assert_eq!(
        through_automation.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let through_dashboard = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(claims_the_mark),
    )
    .await;
    assert_eq!(
        body_json(through_automation).await,
        body_json(through_dashboard).await
    );

    // And this plane's own refusal, the grant, before the handler runs.
    let outside_the_grant = serde_json::json!({
        "hostname": "www.example.com",
        "backend_ids": [f.backend_id],
    });
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(outside_the_grant),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let refusal = body_json(response).await;
    assert!(
        refusal["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("allowed_hostnames")),
        "{refusal}"
    );
    let aliased_outside = serde_json::json!({
        "hostname": "ok.write.example.com",
        "hostname_aliases": ["www.example.com"],
    });
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(aliased_outside),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let after = canonical_now(&f.state).await;
    let after_bytes = lorica_config::canonical::encode_canonical(&after).expect("encodes");
    assert_eq!(
        before_bytes, after_bytes,
        "a refused write changed the store"
    );
    assert_eq!(after.routes.len(), 0);
}

#[tokio::test]
async fn a_write_through_the_automation_plane_lands_the_management_row_and_the_request_row() {
    // Two layers, two rows, and the management one names the token
    // the way the environment rows do, so one audit filter finds every
    // machine-driven change whatever resource it touched.
    let f = a_node_with_something_to_write().await;
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/backends",
        &f.bearer,
        Some(serde_json::json!({ "address": "10.0.0.11:8080", "name": "audited" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let view = parse_data(response).await;
    assert_no_secret_field_name(&view, "POST /automation/v1/backends");
    let backend_id = view["id"].as_str().expect("backend id").to_string();

    let management_rows = audit_rows_under(&f.state, "backend.").await;
    let created = management_rows
        .iter()
        .find(|row| row.action == "backend.create" && row.target_id == backend_id)
        .expect("the management-side row the handler writes");
    assert_eq!(created.operator_role, "automation");
    assert_eq!(
        created.operator_username,
        format!("{WRITE_TOKEN_NAME} ({})", f.public_id)
    );

    let request_rows = audit_rows_under(&f.state, "automation.request.").await;
    assert!(
        request_rows.iter().any(|row| {
            row.action == "automation.request.ok"
                && row.target_id == "POST /automation/v1/backends"
                && row.operator_username == format!("{WRITE_TOKEN_NAME} ({})", f.public_id)
        }),
        "{request_rows:?}"
    );
}

#[tokio::test]
async fn a_row_an_environment_owns_is_refused_through_the_automation_plane_as_on_the_management_one(
) {
    // The 409 is the management handler's own check, reached through
    // the same function, so it needs no second copy here to hold.
    let f = a_node_with_something_to_write().await;
    let mark = Some(lorica_config::models::ManagedBy::Automation {
        environment: "pr-42".to_string(),
    });

    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "owned.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let route_id = parse_data(response).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    {
        let store = f.state.store.lock().await;
        let mut route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route exists");
        route.managed_by = mark.clone();
        store.update_route(&route).expect("the mark lands");
        let mut backend = store
            .get_backend(&f.backend_id)
            .expect("store")
            .expect("the backend exists");
        backend.managed_by = mark;
        store.update_backend(&backend).expect("the mark lands");
    }

    for (method, path, body) in [
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}"),
            Some(serde_json::json!({ "waf_enabled": true })),
        ),
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}/certificate"),
            Some(serde_json::json!({ "certificate_id": f.certificate_id })),
        ),
        (
            "PUT",
            format!("/automation/v1/backends/{}", f.backend_id),
            Some(serde_json::json!({ "name": "renamed" })),
        ),
        (
            "DELETE",
            format!("/automation/v1/backends/{}", f.backend_id),
            None,
        ),
    ] {
        let response = automation_call(&f.state, method, &path, &f.bearer, body).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{method} {path}");
        let refusal = body_json(response).await;
        assert!(
            refusal["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("pr-42")),
            "{refusal}"
        );
    }

    // A managed route is deletable, there and therefore here: the
    // environment goes with it.
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_backend_grant_bounds_what_a_backend_write_may_point_at() {
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await.backends.len();

    for (address, expected) in [
        ("192.0.2.10:8080", StatusCode::FORBIDDEN),
        (
            "db01.internal.example.org:5432",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("10.0.0.12:0", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = automation_call(
            &f.state,
            "POST",
            "/automation/v1/backends",
            &f.bearer,
            Some(serde_json::json!({ "address": address })),
        )
        .await;
        assert_eq!(response.status(), expected, "{address}");
    }
    assert_eq!(canonical_now(&f.state).await.backends.len(), before);

    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/backends",
        &f.bearer,
        Some(serde_json::json!({ "address": "10.0.0.12:8080", "name": "granted" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let backend_id = parse_data(response).await["id"]
        .as_str()
        .expect("backend id")
        .to_string();

    // An update names an address or does not; only one it names is
    // weighed against the grant.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/backends/{backend_id}"),
        &f.bearer,
        Some(serde_json::json!({ "address": "192.0.2.10:8080" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/backends/{backend_id}"),
        &f.bearer,
        Some(serde_json::json!({ "name": "renamed", "weight": 7 })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view = parse_data(response).await;
    assert_eq!(view["name"], "renamed");
    assert_eq!(view["weight"], 7);
    assert_eq!(view["address"], "10.0.0.12:8080");
}

#[tokio::test]
async fn a_certificate_is_bound_and_renewed_through_the_plane_and_never_uploaded() {
    // Story 11.2 AC #6 through the whole stack.
    let f = a_node_with_something_to_write().await;
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "bound.write.example.com",
            "backend_ids": [f.backend_id],
            "force_https": true,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let route_id = parse_data(response).await["id"]
        .as_str()
        .expect("route id")
        .to_string();

    // Bind: the id and nothing else.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}/certificate"),
        &f.bearer,
        Some(serde_json::json!({ "certificate_id": f.certificate_id })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view = parse_data(response).await;
    assert_no_secret_field_name(&view, "PUT /automation/v1/routes/{id}/certificate");
    assert_eq!(view["certificate_id"], f.certificate_id);
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert_eq!(
            route.certificate_id.as_deref(),
            Some(f.certificate_id.as_str())
        );
        assert!(route.force_https);
    }

    // A body that carries anything beside the id is refused before any
    // handler runs, key material first among them.
    for body in [
        serde_json::json!({ "certificate_id": f.certificate_id, "key_pem": "-----BEGIN PRIVATE KEY-----" }),
        serde_json::json!({ "certificate_id": f.certificate_id, "cert_pem": TEST_CERT_RSA_PEM }),
        serde_json::json!({ "certificate": f.certificate_id }),
    ] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{route_id}/certificate"),
            &f.bearer,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Unbind, as the management path reads the empty string.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}/certificate"),
        &f.bearer,
        Some(serde_json::json!({ "certificate_id": "" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert_eq!(route.certificate_id, None);
        assert!(!route.force_https);
    }

    // Renew: an uploaded certificate has nothing to renew against, and
    // the refusal is the management handler's own.
    let response = automation_call(
        &f.state,
        "POST",
        &format!("/automation/v1/certificates/{}/renew", f.certificate_id),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let refusal = body_json(response).await;
    assert!(
        refusal["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("ACME")),
        "{refusal}"
    );
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/certificates/no-such-certificate/renew",
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Upload, replace, generate: undeclared for every token, this one
    // carrying every scope included.
    let pem_body = serde_json::json!({
        "domain": "smuggled.write.example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM,
    });
    for (method, path) in [
        ("POST", "/automation/v1/certificates".to_string()),
        (
            "POST",
            "/automation/v1/certificates/self-signed".to_string(),
        ),
        (
            "PUT",
            format!("/automation/v1/certificates/{}", f.certificate_id),
        ),
    ] {
        let response =
            automation_call(&f.state, method, &path, &f.bearer, Some(pem_body.clone())).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
    let certificates = canonical_now(&f.state).await.certificates;
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0].id, f.certificate_id);
}

#[tokio::test]
async fn the_row_cap_on_an_automation_collection_is_the_servers() {
    // A caller asking for everything gets the window. The ceiling is
    // not a default the query string can raise.
    let (state, _token, _route_id) = a_node_with_something_to_read().await;
    let over_the_cap = crate::automation::AUTOMATION_READ_MAX_ROWS + 25;
    for n in 0..over_the_cap as u64 {
        state.log_buffer.push(crate::logs::LogEntry {
            id: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: "GET".to_string(),
            path: format!("/bulk/{n}"),
            host: "read.example.com".to_string(),
            status: 200,
            latency_ms: 1,
            backend: "10.0.0.10:8080".to_string(),
            error: None,
            client_ip: "192.0.2.10".to_string(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: format!("bulk-{n}"),
        });
    }
    let token = mint_automation(
        &state,
        "log-reader",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let bearer = format!("Bearer {token}");

    let body = body_json(
        automation_send(
            &state,
            "/automation/v1/logs?limit=100000",
            Some(&bearer),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        body["data"]["page"]["limit"],
        crate::automation::AUTOMATION_READ_MAX_ROWS
    );
    assert_eq!(
        body["data"]["items"].as_array().map(Vec::len),
        Some(crate::automation::AUTOMATION_READ_MAX_ROWS)
    );
    assert_eq!(body["data"]["page"]["has_more"], true);

    // And the default, for a caller that names nothing.
    let body =
        body_json(automation_send(&state, "/automation/v1/logs", Some(&bearer), None).await).await;
    assert_eq!(
        body["data"]["page"]["limit"],
        crate::automation::AUTOMATION_READ_DEFAULT_ROWS
    );
    assert_eq!(body["data"]["page"]["offset"], 0);
    assert_eq!(body["data"]["page"]["has_more"], true);
}

// ---- Pre-merge audit: protection fields move in the safe direction only ----

#[tokio::test]
async fn a_token_strengthens_a_protection_through_the_plane_and_never_weakens_one() {
    // The maintainer's decision of 2026-09-30, end to end: the rule runs
    // in the guard on the stored row, the apply and the preview alike,
    // and a refusal changes nothing.
    let f = a_node_with_something_to_write().await;
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "safe.write.example.com",
            "ip_allowlist": ["10.0.0.0/8"],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let route_path = format!("/automation/v1/routes/{route_id}");

    for body in [
        serde_json::json!({ "waf_enabled": true }),
        serde_json::json!({ "ip_allowlist": ["10.1.0.0/16"] }),
    ] {
        let response =
            automation_call(&f.state, "PUT", &route_path, &f.bearer, Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::OK, "{body}");
    }

    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    for (body, field) in [
        (serde_json::json!({ "waf_enabled": false }), "waf_enabled"),
        (serde_json::json!({ "ip_allowlist": [] }), "ip_allowlist"),
        (
            serde_json::json!({ "ip_allowlist": ["10.0.0.0/8"] }),
            "ip_allowlist",
        ),
    ] {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("{route_path}{suffix}"),
                &f.bearer,
                Some(body.clone()),
            )
            .await;
            assert_forbidden_naming(response, field, &format!("{body}{suffix}")).await;
        }
    }
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "password.write.example.com",
            "basic_auth_username": "user01",
            "basic_auth_password": "chosen-by-a-model",
        })),
    )
    .await;
    assert_forbidden_naming(response, "basic_auth_password", "POST with a password").await;
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/backends",
        &f.bearer,
        Some(serde_json::json!({
            "address": "10.0.0.11:8443",
            "tls_upstream": true,
            "tls_skip_verify": true,
        })),
    )
    .await;
    assert_forbidden_naming(response, "tls_skip_verify", "an unverified backend").await;
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/backends/{}", f.backend_id),
        &f.bearer,
        Some(serde_json::json!({ "tls_upstream": true, "tls_skip_verify": true })),
    )
    .await;
    assert_forbidden_naming(response, "tls_skip_verify", "verification switched off").await;
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused weakening changed the store"
    );

    // The management plane is not held to any of it.
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        &format!("/api/v1/routes/{route_id}"),
        &f.admin,
        Some(serde_json::json!({ "waf_enabled": false, "ip_allowlist": [] })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_certificate_bound_anew_is_weighed_against_the_hostname_grant() {
    // The grant said which routes a token may reach and nothing of
    // which certificates it may deploy on them: a route inside the
    // grant could carry a certificate for production names.
    let f = a_node_with_something_to_write().await;
    let production = "production-certificate".to_string();
    {
        let store = f.state.store.lock().await;
        let mut certificate = store
            .get_certificate(&f.certificate_id)
            .expect("store")
            .expect("the seeded certificate");
        certificate.id = production.clone();
        certificate.domain = "www.example.com".to_string();
        certificate.fingerprint = "production-fingerprint".to_string();
        store
            .create_certificate(&certificate)
            .expect("a certificate outside the grant lands");
    }
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "bind.write.example.com" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{route_id}/certificate{suffix}"),
            &f.bearer,
            Some(serde_json::json!({ "certificate_id": production })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{suffix}");
        let refusal = body_json(response).await;
        let message = refusal["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(&production), "{refusal}");
        assert!(!message.contains("www.example.com"), "{refusal}");
    }
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "bind-create.write.example.com",
            "certificate_id": production,
        })),
    )
    .await;
    assert_forbidden_naming(response, "allowed_hostnames", "a create binding it").await;

    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}/certificate"),
        &f.bearer,
        Some(serde_json::json!({ "certificate_id": f.certificate_id })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "inside the grant");
}

// ---- Pre-merge audit: a write lands whole or not at all ----

#[tokio::test]
async fn a_write_whose_client_hangs_up_still_lands_its_rows_and_its_reload() {
    // hyper drops the request future when the peer goes away, and a
    // store closure commits on the blocking pool whether or not anyone
    // still awaits it. The request is started, dropped while it waits
    // on the store, and the store is released after: the write must
    // then land as a unit, the row, the management row, the request
    // row and the reload signal together.
    let mut f = a_node_with_something_to_write().await;
    let (reload_tx, reload_rx) = tokio::sync::watch::channel(0u64);
    f.state.config_reload_tx = Some(reload_tx);
    let hostname = "hung-up.write.example.com";

    let held = Arc::clone(&f.state.store).lock_owned().await;
    let router = crate::automation::build_automation_router(f.state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/automation/v1/routes")
        .header(http::header::AUTHORIZATION, &f.bearer)
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({ "hostname": hostname, "backend_ids": [f.backend_id] }).to_string(),
        ))
        .expect("test setup");
    let mut in_flight = Box::pin(router.oneshot(request));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut in_flight)
            .await
            .is_err(),
        "the request answered while the store was held"
    );
    drop(in_flight);
    drop(held);

    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let stored = loop {
        let found = {
            let store = f.state.store.lock().await;
            store
                .list_routes()
                .expect("store")
                .into_iter()
                .find(|route| route.hostname == hostname)
        };
        if let Some(route) = found {
            break route;
        }
        assert!(
            Instant::now() < deadline,
            "the write never reached the store once the client had gone"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };

    // The unit ends after the store commit: wait for its request row,
    // the last thing it writes, then read everything it owes.
    loop {
        let requests = audit_rows_under(&f.state, "automation.request.ok").await;
        if requests
            .iter()
            .any(|row| row.target_id == "POST /automation/v1/routes")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no request row for a write that committed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let created = audit_rows_under(&f.state, "route.create").await;
    assert!(
        created.iter().any(|row| row.target_id == stored.id),
        "no route.create row for a route that is stored: {created:?}"
    );
    assert!(
        *reload_rx.borrow() > 0,
        "the proxy was never told the configuration changed"
    );
}

// ---- Story 11.2, security audit: the grant bounds what a write TARGETS ----

/// A route and a backend an operator wrote outside the write token's
/// grant: `www.example.com`, served by `192.0.2.10:8080`, with the
/// fixture's certificate bound and `force_https` on. What a config-tier
/// token scoped to `*.write.example.com` and `10.0.0.0/8` must not
/// reach by naming an id.
async fn a_production_route_and_backend(f: &WriteFixture) -> (String, String) {
    let created = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/backends",
        &f.admin,
        Some(serde_json::json!({ "address": "192.0.2.10:8080", "name": "prod-backend" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let backend_id = parse_data(created).await["id"]
        .as_str()
        .expect("backend id")
        .to_string();
    let created = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(serde_json::json!({
            "hostname": "www.example.com",
            "backend_ids": [backend_id],
            "certificate_id": f.certificate_id,
            "force_https": true,
            "waf_enabled": true,
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    (route_id, backend_id)
}

/// The `automation.request.forbidden` rows whose target names `path`.
async fn forbidden_rows_naming(state: &AppState, path: &str) -> usize {
    automation_audit_rows(state)
        .await
        .iter()
        .filter(|row| {
            row.action.starts_with("automation.request.forbidden") && row.target_id.contains(path)
        })
        .count()
}

#[tokio::test]
async fn a_route_write_is_refused_when_the_route_it_names_is_outside_the_grant() {
    // The grant bounds what a write TARGETS and not only what it
    // claims. A token scoped to `*.write.example.com` naming a route on
    // `www.example.com` by id must not disable its WAF, redirect it,
    // disable it, move it under the grant, rewrite its error page,
    // unbind its certificate or delete it; and a preview of any of
    // those must not show it the row either. Every refusal is the
    // plane's grant refusal, audited as forbidden.
    let f = a_node_with_something_to_write().await;
    let (prod_route, _) = a_production_route_and_backend(&f).await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    let patches = [
        serde_json::json!({ "waf_enabled": false }),
        serde_json::json!({ "redirect_to": "https://attacker.example.net" }),
        serde_json::json!({ "enabled": false }),
        serde_json::json!({ "hostname": "pr-1.write.example.com" }),
        serde_json::json!({ "error_page_html": "<h1>moved</h1>" }),
        serde_json::json!({}),
    ];
    for patch in &patches {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/routes/{prod_route}{suffix}"),
                &f.bearer,
                Some(patch.clone()),
            )
            .await;
            assert_forbidden_naming(
                response,
                "allowed_hostnames",
                &format!("PUT {patch}{suffix}"),
            )
            .await;
        }
    }
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "DELETE",
            &format!("/automation/v1/routes/{prod_route}{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_forbidden_naming(response, "allowed_hostnames", &format!("DELETE {suffix}")).await;
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{prod_route}/certificate{suffix}"),
            &f.bearer,
            Some(serde_json::json!({ "certificate_id": "" })),
        )
        .await;
        assert_forbidden_naming(response, "allowed_hostnames", &format!("unbind {suffix}")).await;
    }

    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused write changed the store"
    );
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&prod_route)
            .expect("store")
            .expect("the production route is still there");
        assert_eq!(route.hostname, "www.example.com");
        assert!(route.enabled && route.waf_enabled && route.force_https);
        assert_eq!(
            route.certificate_id.as_deref(),
            Some(f.certificate_id.as_str())
        );
        assert_eq!(route.redirect_to, None);
    }
    assert_eq!(
        forbidden_rows_naming(&f.state, &format!("/automation/v1/routes/{prod_route}")).await,
        patches.len() * 2 + 4
    );

    // The same patch on a route inside the grant is the write it was.
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "app.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let own_route = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{own_route}"),
        &f.bearer,
        Some(serde_json::json!({ "waf_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/routes/{own_route}"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_managed_route_goes_through_the_plane_only_for_its_environments_owner() {
    // A route inside the hostname grant that another pipeline's
    // environment owns: deleting it would cascade that environment,
    // which the environment resource's own ownership rule refuses, so
    // the route delete refuses it too. The owner's own token is let
    // through, and the delete then cascades as the dashboard's does.
    let f = a_node_with_something_to_write().await;
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "pr-7.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    an_environment_owning(&f.state, "pr-7", &route_id, "other-pipeline").await;

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "DELETE",
            &format!("/automation/v1/routes/{route_id}{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_forbidden_naming(response, "environment", &format!("DELETE {suffix}")).await;
    }
    // Another owner's row is not even the 409 the owner would get.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "waf_enabled": true })),
    )
    .await;
    assert_forbidden_naming(response, "environment", "PUT on another owner's row").await;
    {
        let store = f.state.store.lock().await;
        assert!(store.get_route(&route_id).expect("store").is_some());
        assert!(store
            .get_automation_environment("pr-7")
            .expect("store")
            .is_some());
    }

    // The token's own environment: the managed-row 409 on an update,
    // as on the management plane, and the cascading delete.
    an_environment_owning(&f.state, "pr-7", &route_id, WRITE_TOKEN_NAME).await;
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "waf_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let store = f.state.store.lock().await;
        assert!(store.get_route(&route_id).expect("store").is_none());
        assert!(store
            .get_automation_environment("pr-7")
            .expect("store")
            .is_none());
    }
}

#[tokio::test]
async fn a_backend_write_is_refused_when_the_backend_it_names_is_outside_the_grant() {
    // The CIDR grant bounds the backend a write TARGETS: a token scoped
    // to `10.0.0.0/8` naming a backend at `192.0.2.10` by id must not
    // move it inside the grant, reweight it, loosen its TLS, silence its
    // health check or drain it, previews included. A backend inside the
    // CIDR that another pipeline's environment holds is that
    // environment's, and refused as such.
    let f = a_node_with_something_to_write().await;
    let (_, prod_backend) = a_production_route_and_backend(&f).await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    let patches = [
        serde_json::json!({ "address": "10.9.9.9:80" }),
        serde_json::json!({ "weight": 1 }),
        serde_json::json!({ "tls_skip_verify": true }),
        serde_json::json!({ "health_check_enabled": false }),
        serde_json::json!({}),
    ];
    for patch in &patches {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/backends/{prod_backend}{suffix}"),
                &f.bearer,
                Some(patch.clone()),
            )
            .await;
            assert_forbidden_naming(
                response,
                "allowed_backend_cidrs",
                &format!("PUT {patch}{suffix}"),
            )
            .await;
        }
    }
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "DELETE",
            &format!("/automation/v1/backends/{prod_backend}{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_forbidden_naming(
            response,
            "allowed_backend_cidrs",
            &format!("DELETE {suffix}"),
        )
        .await;
    }
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused write changed the store"
    );
    {
        let store = f.state.store.lock().await;
        let backend = store
            .get_backend(&prod_backend)
            .expect("store")
            .expect("the production backend is still there");
        assert_eq!(backend.address, "192.0.2.10:8080");
        assert_eq!(
            backend.lifecycle_state,
            lorica_config::models::LifecycleState::Normal
        );
        assert!(!backend.tls_skip_verify && backend.health_check_enabled);
    }
    assert_eq!(
        forbidden_rows_naming(&f.state, &format!("/automation/v1/backends/{prod_backend}")).await,
        patches.len() * 2 + 2
    );

    // Inside the CIDR, held by another pipeline's environment.
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "pr-9.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    an_environment_owning(&f.state, "pr-9", &route_id, "other-pipeline").await;
    {
        let store = f.state.store.lock().await;
        let mut backend = store
            .get_backend(&f.backend_id)
            .expect("store")
            .expect("the backend exists");
        backend.managed_by = Some(lorica_config::models::ManagedBy::Automation {
            environment: "pr-9".to_string(),
        });
        store.update_backend(&backend).expect("the mark lands");
    }
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/backends/{}", f.backend_id),
        &f.bearer,
        Some(serde_json::json!({ "name": "renamed" })),
    )
    .await;
    assert_forbidden_naming(
        response,
        "environment",
        "PUT on another environment's backend",
    )
    .await;
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/backends/{}", f.backend_id),
        &f.bearer,
        None,
    )
    .await;
    assert_forbidden_naming(
        response,
        "environment",
        "DELETE on another environment's backend",
    )
    .await;
}

#[tokio::test]
async fn a_renewal_is_refused_when_the_certificate_covers_a_name_outside_the_grant() {
    // A renewal spends an ACME budget and rotates the node's bot HMAC,
    // for a certificate the token may have no business with. Every name
    // the certificate carries, `domain` and each SAN, must be inside the
    // hostname grant, or the renewal and its preview are refused before
    // the ACME-only check can say anything about the row.
    let f = a_node_with_something_to_write().await;
    let outside_id = {
        let store = f.state.store.lock().await;
        let mut outside = store
            .get_certificate(&f.certificate_id)
            .expect("store")
            .expect("the seeded certificate");
        outside.id = uuid::Uuid::new_v4().to_string();
        outside.domain = "www.example.com".to_string();
        outside.fingerprint = format!("{}-www", outside.fingerprint);
        outside.is_acme = true;
        store
            .create_certificate(&outside)
            .expect("the production certificate lands");
        outside.id
    };
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("/automation/v1/certificates/{outside_id}/renew{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_forbidden_naming(response, "allowed_hostnames", &format!("renew {suffix}")).await;
    }

    // A SAN outside the grant refuses the renewal as the domain does.
    {
        let store = f.state.store.lock().await;
        let mut certificate = store
            .get_certificate(&f.certificate_id)
            .expect("store")
            .expect("the seeded certificate");
        certificate.is_acme = true;
        certificate.san_domains = vec!["www.example.com".to_string()];
        store
            .update_certificate(&certificate)
            .expect("the SAN lands");
    }
    let response = automation_call(
        &f.state,
        "POST",
        &format!(
            "/automation/v1/certificates/{}/renew?dry_run=true",
            f.certificate_id
        ),
        &f.bearer,
        None,
    )
    .await;
    assert_forbidden_naming(response, "allowed_hostnames", "renew with a SAN outside").await;
    assert_eq!(
        forbidden_rows_naming(&f.state, "/renew").await,
        3,
        "every refused renewal is audited as forbidden"
    );

    // Every name inside the grant: the preview answers the row, the
    // apply would place the order.
    {
        let store = f.state.store.lock().await;
        let mut certificate = store
            .get_certificate(&f.certificate_id)
            .expect("store")
            .expect("the seeded certificate");
        certificate.san_domains = vec!["api.write.example.com".to_string()];
        store
            .update_certificate(&certificate)
            .expect("the SAN lands");
    }
    let response = automation_call(
        &f.state,
        "POST",
        &format!(
            "/automation/v1/certificates/{}/renew?dry_run=true",
            f.certificate_id
        ),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        parse_data(response).await["operation"],
        serde_json::json!("renew")
    );
}

#[tokio::test]
async fn a_route_body_cannot_aim_traffic_or_credentials_outside_the_grant() {
    // The CIDR grant bounded one field of the eight that point
    // somewhere. `forward_auth` is a URL the grant cannot weigh, and the
    // proxy forwards every downstream Cookie and Authorization header to
    // it; `mirror` ships a copy of every request to a second set of
    // backends. Both are refused outright from an automation token. And
    // every `backend_ids` list, at the top level and inside path rules,
    // header rules and traffic splits, links a backend by id: each one
    // the write links anew must sit inside the CIDR grant and belong to
    // no other pipeline's environment.
    let f = a_node_with_something_to_write().await;
    let (_, prod_backend) = a_production_route_and_backend(&f).await;

    // A backend inside the CIDR that another pipeline's environment
    // holds.
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "pr-8.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let environment_route = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    an_environment_owning(&f.state, "pr-8", &environment_route, "other-pipeline").await;
    let created = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/backends",
        &f.admin,
        Some(serde_json::json!({ "address": "10.0.0.20:8080", "name": "pr-8-0" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let owned_backend = parse_data(created).await["id"]
        .as_str()
        .expect("backend id")
        .to_string();
    {
        let store = f.state.store.lock().await;
        let mut backend = store
            .get_backend(&owned_backend)
            .expect("store")
            .expect("the backend exists");
        backend.managed_by = Some(lorica_config::models::ManagedBy::Automation {
            environment: "pr-8".to_string(),
        });
        store.update_backend(&backend).expect("the mark lands");
    }
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    let refused_bodies: Vec<(serde_json::Value, &str)> = vec![
        (
            serde_json::json!({ "forward_auth": { "address": "https://collector.attacker.example.net/v", "timeout_ms": 1000 } }),
            "forward_auth",
        ),
        (
            serde_json::json!({ "forward_auth": { "address": "http://169.254.169.254/latest/meta-data/" } }),
            "forward_auth",
        ),
        (
            serde_json::json!({ "mirror": { "backend_ids": [f.backend_id] } }),
            "mirror",
        ),
        (
            serde_json::json!({ "backend_ids": [prod_backend] }),
            "allowed_backend_cidrs",
        ),
        (
            serde_json::json!({ "traffic_splits": [{ "name": "canary", "weight_percent": 10, "backend_ids": [prod_backend] }] }),
            "allowed_backend_cidrs",
        ),
        (
            serde_json::json!({ "header_rules": [{ "header_name": "X-Canary", "value": "1", "backend_ids": [prod_backend] }] }),
            "allowed_backend_cidrs",
        ),
        (
            serde_json::json!({ "path_rules": [{ "path": "/admin", "backend_ids": [prod_backend] }] }),
            "allowed_backend_cidrs",
        ),
        (
            serde_json::json!({ "backend_ids": [owned_backend] }),
            "environment",
        ),
    ];
    for (fields, marker) in &refused_bodies {
        let mut body = fields.clone();
        body["hostname"] = serde_json::json!("app.write.example.com");
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "POST",
                &format!("/automation/v1/routes{suffix}"),
                &f.bearer,
                Some(body.clone()),
            )
            .await;
            assert_forbidden_naming(response, marker, &format!("POST {fields}{suffix}")).await;
        }
    }
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused create changed the store"
    );

    // A route inside the grant, linked inside the grant: created, and
    // then patched with each body the create refused.
    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "app.write.example.com",
            "backend_ids": [f.backend_id],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    for (fields, marker) in &refused_bodies {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/routes/{route_id}{suffix}"),
                &f.bearer,
                Some(fields.clone()),
            )
            .await;
            assert_forbidden_naming(response, marker, &format!("PUT {fields}{suffix}")).await;
        }
    }
    // Clearing `forward_auth` is refused with the rest: the field is
    // not the tier's, in either direction.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "forward_auth": { "address": "" } })),
    )
    .await;
    assert_forbidden_naming(response, "forward_auth", "PUT clearing forward_auth").await;
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused patch changed the store"
    );

    // Inside the grant, every position links: the same backend at the
    // top level again, and in a path rule.
    for body in [
        serde_json::json!({ "backend_ids": [f.backend_id] }),
        serde_json::json!({ "path_rules": [{ "path": "/api", "backend_ids": [f.backend_id] }] }),
        serde_json::json!({ "waf_enabled": true }),
    ] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{route_id}"),
            &f.bearer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{body}");
    }
    // A patch that leaves the links alone does not re-weigh them: the
    // route now carries a path rule, and toggling a flag beside it is
    // still the write it was.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "compression_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let store = f.state.store.lock().await;
        let linked = store.list_backends_for_route(&route_id).expect("store");
        assert_eq!(linked, vec![f.backend_id.clone()]);
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert!(route.forward_auth.is_none() && route.mirror.is_none());
        assert_eq!(
            route.path_rules[0].backend_ids.as_deref(),
            Some(&[f.backend_id.clone()][..])
        );
    }
}

/// The header rules of `route_id` as the store holds them, as
/// `(header_name, match_type, value)`.
async fn stored_header_rules(state: &AppState, route_id: &str) -> Vec<(String, String, String)> {
    let store = state.store.lock().await;
    store
        .get_route(route_id)
        .expect("store")
        .expect("the route exists")
        .header_rules
        .into_iter()
        .map(|rule| {
            (
                rule.header_name,
                rule.match_type.as_str().to_string(),
                rule.value,
            )
        })
        .collect()
}

#[tokio::test]
async fn a_header_rule_value_is_masked_on_the_plane_and_a_masked_value_sent_back_keeps_the_stored_one(
) {
    // Backlog #94 (c). The value a header rule matches is where a
    // secret shared between a client and its canary goes, so no answer
    // on this plane carries it. The config tier writes the list whole,
    // so the mask it read must come back as "keep what is stored",
    // matched by position, header name and match type, and never be
    // stored itself.
    use crate::automation::redact::REDACTED;
    let f = a_node_with_something_to_write().await;
    let created = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(serde_json::json!({
            "hostname": "canary.write.example.com",
            "backend_ids": [f.backend_id],
            "header_rules": [
                { "header_name": "X-Canary-Key", "value": "s3cr3t-one", "backend_ids": [f.backend_id] },
                { "header_name": "X-Tenant", "match_type": "prefix", "value": "acme-s3cr3t-", "backend_ids": [] },
            ],
        })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let stored = stored_header_rules(&f.state, &route_id).await;

    // Read: the values are masked, everything else of each rule kept.
    let response = automation_call(&f.state, "GET", "/automation/v1/routes", &f.bearer, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listing = body_json(response).await;
    assert!(!listing.to_string().contains("s3cr3t"), "{listing}");
    let read = listing["data"]["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|route| route["id"] == route_id.as_str())
        .expect("the route is listed")
        .clone();
    assert_eq!(read["header_rules"][0]["value"], REDACTED);
    assert_eq!(read["header_rules"][0]["header_name"], "X-Canary-Key");
    assert_eq!(read["header_rules"][1]["value"], REDACTED);
    assert_eq!(read["header_rules"][1]["match_type"], "prefix");

    // Written back as read, with one backend list changed: the stored
    // values stay, the change lands, and neither the apply nor the
    // preview answer carries a value.
    let mut rules = read["header_rules"].clone();
    rules[1]["backend_ids"] = serde_json::json!([f.backend_id]);
    for suffix in ["?dry_run=true", ""] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{route_id}{suffix}"),
            &f.bearer,
            Some(serde_json::json!({ "header_rules": rules })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "PUT{suffix}");
        let answer = body_json(response).await;
        assert!(!answer.to_string().contains("s3cr3t"), "{answer}");
    }
    assert_eq!(stored_header_rules(&f.state, &route_id).await, stored);
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert_eq!(
            route.header_rules[1].backend_ids,
            vec![f.backend_id.clone()]
        );
    }

    // A marker no stored rule answers to is refused, and nothing moves:
    // a rule added, two rules swapped, a header renamed, a match type
    // changed, and any marker on a create.
    let mut added = rules.clone();
    added
        .as_array_mut()
        .expect("a list")
        .push(serde_json::json!({ "header_name": "X-New", "value": REDACTED }));
    let swapped = serde_json::json!([rules[1].clone(), rules[0].clone()]);
    let mut renamed = rules.clone();
    renamed[0]["header_name"] = serde_json::json!("X-Other");
    let mut retyped = rules.clone();
    retyped[0]["match_type"] = serde_json::json!("regex");
    for (what, header_rules) in [
        ("added", added),
        ("swapped", swapped),
        ("renamed", renamed),
        ("retyped", retyped),
    ] {
        let response = automation_call(
            &f.state,
            "PUT",
            &format!("/automation/v1/routes/{route_id}"),
            &f.bearer,
            Some(serde_json::json!({ "header_rules": header_rules })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{what}");
        let refusal = body_json(response).await;
        assert!(
            refusal["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("header_rules[")),
            "{what}: {refusal}"
        );
        assert_eq!(
            stored_header_rules(&f.state, &route_id).await,
            stored,
            "{what}"
        );
    }
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "fresh.write.example.com",
            "header_rules": [{ "header_name": "X-Canary-Key", "value": REDACTED }],
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A real value is a value, and is stored as sent.
    let mut rotated = rules.clone();
    rotated[0]["value"] = serde_json::json!("rotated-value");
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "header_rules": rotated })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let now = stored_header_rules(&f.state, &route_id).await;
    assert_eq!(now[0].2, "rotated-value");
    assert_eq!(now[1], stored[1]);

    // The dashboard is not a token: it reads the values, and a marker
    // it sends is the literal it typed.
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "GET",
        &format!("/api/v1/routes/{route_id}"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(
        parse_data(response).await["header_rules"][0]["value"],
        "rotated-value"
    );
}

#[tokio::test]
async fn a_backend_delete_preview_reports_the_drain_the_apply_starts() {
    // The apply of a backend delete marks the row closing and drains it
    // for up to a minute before the row leaves; only a backend already
    // closing goes at once. The preview says which of the two the apply
    // would do, rather than promising a row gone that the apply keeps.
    let f = a_node_with_something_to_write().await;
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/backends/{}?dry_run=true", f.backend_id),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let change = parse_data(response).await;
    assert_eq!(change["operation"], serde_json::json!("delete"));
    assert_eq!(
        change["before"]["lifecycle_state"],
        serde_json::json!("normal")
    );
    assert_eq!(
        change["after"]["lifecycle_state"],
        serde_json::json!("closing")
    );
    assert_eq!(
        change["changes"],
        serde_json::json!({ "lifecycle_state": { "from": "normal", "to": "closing" } })
    );

    {
        let store = f.state.store.lock().await;
        let mut backend = store
            .get_backend(&f.backend_id)
            .expect("store")
            .expect("the backend exists");
        backend.lifecycle_state = lorica_config::models::LifecycleState::Closing;
        store.update_backend(&backend).expect("the state lands");
    }
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/backends/{}?dry_run=true", f.backend_id),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let change = parse_data(response).await;
    assert_eq!(
        change["before"]["lifecycle_state"],
        serde_json::json!("closing")
    );
    assert_eq!(change["after"], serde_json::Value::Null);
}

#[tokio::test]
async fn a_renewal_preview_refuses_what_the_apply_refuses() {
    // A preview that answers "would renew" for a certificate the apply
    // then refuses is a preview promising more than the apply does. The
    // method and the DNS provider are resolved before the preview
    // branch, so the two answer alike, and a refusal the row provokes is
    // a 400 naming it rather than a 500 from inside the order.
    let f = a_node_with_something_to_write().await;
    for (method, provider, marker) in [
        ("dns01-manual", None, "manual"),
        ("dns01-cloudflare", None, "no DNS provider"),
        (
            "dns01-cloudflare",
            Some("no-such-provider"),
            "no longer exists",
        ),
        ("carrier-pigeon", None, "unknown ACME method"),
    ] {
        {
            let store = f.state.store.lock().await;
            let mut certificate = store
                .get_certificate(&f.certificate_id)
                .expect("store")
                .expect("the seeded certificate");
            certificate.is_acme = true;
            certificate.acme_method = Some(method.to_string());
            certificate.acme_dns_provider_id = provider.map(str::to_string);
            store
                .update_certificate(&certificate)
                .expect("the method lands");
        }
        let mut answers = Vec::new();
        for suffix in ["?dry_run=true", ""] {
            let response = automation_call(
                &f.state,
                "POST",
                &format!(
                    "/automation/v1/certificates/{}/renew{suffix}",
                    f.certificate_id
                ),
                &f.bearer,
                None,
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{method} {provider:?} {suffix}"
            );
            let refusal = body_json(response).await;
            assert!(
                refusal["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains(marker)),
                "{method} {provider:?} {suffix}: {refusal}"
            );
            answers.push(refusal);
        }
        assert_eq!(
            answers[0], answers[1],
            "{method}: the preview and the apply disagree"
        );
    }
}

// ---- Story 11.2, security audit lot 4: the Mediums and Lows ----

/// A self-signed CA, generated per test so no key bytes live in the
/// repository: what `mtls.ca_cert_pem` takes.
fn a_client_ca_pem() -> String {
    let mut params =
        rcgen::CertificateParams::new(vec!["Test CA".to_string()]).expect("test setup");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("test setup");
    params.self_signed(&key).expect("test setup").pem()
}

#[tokio::test]
async fn a_route_body_cannot_install_a_client_authentication_trust_anchor() {
    // `mtls.ca_cert_pem` is the CA whose client certificates a route
    // accepts. It is not private key material, so AC #6's letter held,
    // but a model reading attacker text that can replace it lets any
    // client certificate the attacker mints through that route. It is
    // refused from a token outright, whatever the value, on the create,
    // the update and their previews; the dashboard's own path still
    // sets it.
    let f = a_node_with_something_to_write().await;
    let ca = a_client_ca_pem();
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("/automation/v1/routes{suffix}"),
            &f.bearer,
            Some(serde_json::json!({
                "hostname": "anchored.write.example.com",
                "mtls": { "ca_cert_pem": ca, "required": true },
            })),
        )
        .await;
        assert_forbidden_naming(response, "mtls", &format!("POST {suffix}")).await;
    }
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&canonical_now(&f.state).await)
            .expect("encodes"),
        "a refused create changed the store"
    );

    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "anchored.write.example.com" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    for (body, what) in [
        (
            serde_json::json!({ "mtls": { "ca_cert_pem": ca, "required": true } }),
            "install",
        ),
        (
            serde_json::json!({ "mtls": { "ca_cert_pem": "" } }),
            "clear",
        ),
    ] {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/routes/{route_id}{suffix}"),
                &f.bearer,
                Some(body.clone()),
            )
            .await;
            assert_forbidden_naming(response, "mtls", &format!("PUT {what}{suffix}")).await;
        }
    }
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert!(route.mtls.is_none(), "a token installed a trust anchor");
    }

    // The dashboard's own path is unchanged: an operator sets it.
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        &format!("/api/v1/routes/{route_id}"),
        &f.admin,
        Some(serde_json::json!({ "mtls": { "ca_cert_pem": ca, "required": true } })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert!(route.mtls.is_some_and(|mtls| mtls.required));
    }
}

#[tokio::test]
async fn a_route_body_cannot_carry_a_static_header_map_to_the_upstream() {
    // `proxy_headers` is a static map sent to the upstream on every
    // request, which is where an operator puts an upstream credential.
    // A model reading attacker text must neither set one nor clear one:
    // refused from a token outright on the create, the update and their
    // previews, the clearing value included, while the dashboard's own
    // path still sets it.
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let headers = serde_json::json!({ "X-Upstream-Auth": "static-value" });

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("/automation/v1/routes{suffix}"),
            &f.bearer,
            Some(serde_json::json!({
                "hostname": "headed.write.example.com",
                "proxy_headers": headers,
            })),
        )
        .await;
        assert_forbidden_naming(response, "proxy_headers", &format!("POST {suffix}")).await;
    }
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&canonical_now(&f.state).await)
            .expect("encodes"),
        "a refused create changed the store"
    );

    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "headed.write.example.com" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    for (body, what) in [
        (serde_json::json!({ "proxy_headers": headers }), "set"),
        (serde_json::json!({ "proxy_headers": {} }), "clear"),
    ] {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/routes/{route_id}{suffix}"),
                &f.bearer,
                Some(body.clone()),
            )
            .await;
            assert_forbidden_naming(response, "proxy_headers", &format!("PUT {what}{suffix}"))
                .await;
        }
    }
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert!(route.proxy_headers.is_empty(), "a token set a header map");
    }

    // The dashboard's own path is unchanged: an operator sets it.
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        &format!("/api/v1/routes/{route_id}"),
        &f.admin,
        Some(serde_json::json!({ "proxy_headers": headers })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert_eq!(
            route
                .proxy_headers
                .get("X-Upstream-Auth")
                .map(String::as_str),
            Some("static-value")
        );
    }
}

#[tokio::test]
async fn a_certificate_binding_on_a_route_write_needs_the_certificates_write_scope() {
    // The binding tool sits behind `certificates:write`, and the route
    // create and update bodies carry `certificate_id` under
    // `routes:write`, so withholding the certificate scope stopped
    // nothing. It is a boundary now: a route write naming
    // `certificate_id`, the empty string included, needs
    // `certificates:write` beside `routes:write`.
    use lorica_config::models::AutomationScope;
    let f = a_node_with_something_to_write().await;
    let routes_only = mint_automation(
        &f.state,
        "routes-only",
        vec![AutomationScope::RoutesWrite, AutomationScope::RoutesRead],
        &["*.write.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let routes_only = format!("Bearer {routes_only}");

    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("/automation/v1/routes{suffix}"),
            &routes_only,
            Some(serde_json::json!({
                "hostname": "bound.write.example.com",
                "certificate_id": f.certificate_id,
            })),
        )
        .await;
        assert_forbidden_naming(response, "certificates:write", &format!("POST {suffix}")).await;
    }
    assert_eq!(canonical_now(&f.state).await.routes.len(), 0);

    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &routes_only,
        Some(serde_json::json!({ "hostname": "bound.write.example.com" })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    for certificate_id in [f.certificate_id.as_str(), ""] {
        for suffix in ["", "?dry_run=true"] {
            let response = automation_call(
                &f.state,
                "PUT",
                &format!("/automation/v1/routes/{route_id}{suffix}"),
                &routes_only,
                Some(serde_json::json!({ "certificate_id": certificate_id })),
            )
            .await;
            assert_forbidden_naming(
                response,
                "certificates:write",
                &format!("PUT `{certificate_id}`{suffix}"),
            )
            .await;
        }
    }
    {
        let store = f.state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("store")
            .expect("the route");
        assert_eq!(route.certificate_id, None);
    }
    // The same patch without the field is the write it was, and the
    // fixture's token, which carries the certificate scope, binds.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &routes_only,
        Some(serde_json::json!({ "waf_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}"),
        &f.bearer,
        Some(serde_json::json!({ "certificate_id": f.certificate_id })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        parse_data(response).await["certificate_id"],
        serde_json::json!(f.certificate_id)
    );
}

#[tokio::test]
async fn a_mistyped_dry_run_is_refused_and_never_an_apply() {
    // `?dryrun=true` from a client that typed the preview by hand was
    // an apply: the query struct ignored a key it did not know. Any key
    // the write path's query does not declare is a 400 now, and the
    // store is what it was.
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let route = serde_json::json!({
        "hostname": "typo.write.example.com",
        "backend_ids": [f.backend_id],
    });
    for query in [
        "?dryrun=true",
        "?dry-run=true",
        "?dry_run=1",
        "?dry_run=true&dryrun=true",
    ] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("/automation/v1/routes{query}"),
            &f.bearer,
            Some(route.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&canonical_now(&f.state).await)
            .expect("encodes"),
        "a mistyped dry run wrote"
    );
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes?dry_run=true",
        &f.bearer,
        Some(route),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        parse_data(response).await["dry_run"],
        serde_json::json!(true)
    );
}

#[tokio::test]
async fn a_token_renews_one_certificate_at_a_time_and_not_twice_inside_the_interval() {
    // Each renewal places an ACME order against a budget the CA counts
    // per identifier set, and rotates the node's bot HMAC. From a
    // token: 409 while an order for that id is open, 429 for a
    // certificate issued less than the interval ago, 429 while the
    // background loop holds the id in a CA cooldown; the preview
    // answers what the apply would. An operator's session is bounded by
    // none of it.
    let f = a_node_with_something_to_write().await;
    let renew = format!("/automation/v1/certificates/{}/renew", f.certificate_id);
    // The fixture's upload is a `certificate.` row of its own.
    let management_rows_before = audit_rows_under(&f.state, "certificate.").await.len();
    let set = |is_manual: bool, issued_ago: chrono::Duration| {
        let state = f.state.clone();
        let id = f.certificate_id.clone();
        async move {
            let store = state.store.lock().await;
            let mut certificate = store
                .get_certificate(&id)
                .expect("store")
                .expect("the seeded certificate");
            certificate.is_acme = true;
            certificate.acme_method = is_manual.then(|| "dns01-manual".to_string());
            certificate.not_before = chrono::Utc::now() - issued_ago;
            store
                .update_certificate(&certificate)
                .expect("the row lands");
        }
    };

    // In flight: the token is refused, the operator reaches the plan's
    // own refusal of a manual certificate, which is past the budget.
    set(true, chrono::Duration::days(10)).await;
    let held = f
        .state
        .renewals
        .begin(&f.certificate_id)
        .expect("nothing in flight yet");
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("{renew}{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "in flight {suffix}"
        );
        let refusal = body_json(response).await;
        assert!(
            refusal["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains(&f.certificate_id) && m.contains("in flight")),
            "{refusal}"
        );
    }
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        &format!("/api/v1/certificates/{}/renew", f.certificate_id),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "the operator is not budgeted"
    );
    drop(held);
    assert!(!f.state.renewals.is_in_flight(&f.certificate_id));

    // Issued an hour ago: refused until the interval has passed, with
    // the wait in the header.
    set(false, chrono::Duration::hours(1)).await;
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            "POST",
            &format!("{renew}{suffix}"),
            &f.bearer,
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "inside the interval {suffix}"
        );
        let retry_after: u64 = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("a Retry-After");
        let hours = crate::acme::MIN_TOKEN_RENEWAL_INTERVAL_HOURS as u64;
        assert!(
            retry_after > (hours - 2) * 3_600 && retry_after <= (hours - 1) * 3_600,
            "{retry_after}"
        );
        let refusal = body_json(response).await;
        assert!(
            refusal["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains(&f.certificate_id) && m.contains("hours")),
            "{refusal}"
        );
    }

    // Issued long ago but on a CA cooldown the loop recorded.
    set(false, chrono::Duration::days(10)).await;
    f.state.renewals.record_cooldown(
        &f.certificate_id,
        chrono::Utc::now() + chrono::Duration::hours(2),
    );
    let response = automation_call(
        &f.state,
        "POST",
        &format!("{renew}?dry_run=true"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "cooldown");
    let refusal = body_json(response).await;
    assert!(
        refusal["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("rate limit")),
        "{refusal}"
    );
    f.state.renewals.clear_cooldown(&f.certificate_id);

    // Nothing in the way: the preview answers the row.
    let response = automation_call(
        &f.state,
        "POST",
        &format!("{renew}?dry_run=true"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        parse_data(response).await["operation"],
        serde_json::json!("renew")
    );
    assert_eq!(
        audit_rows_under(&f.state, "certificate.").await.len(),
        management_rows_before,
        "a refused renewal landed a management row"
    );
}

#[tokio::test]
async fn a_preview_needs_the_read_scope_of_the_row_it_answers() {
    // A preview answers the full row it would change, so a write scope
    // alone read any route, backend or certificate inside the grant
    // through it. It needs the matching read scope now, which the
    // config tier's tokens carry anyway since the tier finds its ids
    // through them; the apply is unchanged.
    use lorica_config::models::AutomationScope;
    let f = a_node_with_something_to_write().await;
    let minted = |name: &'static str, scopes: Vec<AutomationScope>| {
        let state = f.state.clone();
        async move {
            let token = mint_automation(
                &state,
                name,
                scopes,
                &["*.write.example.com"],
                chrono::Utc::now() + chrono::Duration::days(30),
                None,
            )
            .await;
            format!("Bearer {token}")
        }
    };
    let routes_write = minted("routes-write", vec![AutomationScope::RoutesWrite]).await;
    let backends_write = minted("backends-write", vec![AutomationScope::BackendsWrite]).await;
    let certificates_write = minted(
        "certificates-write",
        vec![AutomationScope::CertificatesWrite],
    )
    .await;
    let settings_write = minted("settings-write", vec![AutomationScope::SettingsWrite]).await;

    let created = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &routes_write,
        Some(serde_json::json!({ "hostname": "app.write.example.com" })),
    )
    .await;
    assert_eq!(
        created.status(),
        StatusCode::CREATED,
        "the apply needs no read scope"
    );
    let route_id = parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string();

    let previews: Vec<(&str, String, &str, Option<serde_json::Value>, &str)> = vec![
        (
            "POST",
            "/automation/v1/routes".to_string(),
            routes_write.as_str(),
            Some(serde_json::json!({ "hostname": "new.write.example.com" })),
            "routes:read",
        ),
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}"),
            routes_write.as_str(),
            Some(serde_json::json!({})),
            "routes:read",
        ),
        (
            "DELETE",
            format!("/automation/v1/routes/{route_id}"),
            routes_write.as_str(),
            None,
            "routes:read",
        ),
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}/certificate"),
            certificates_write.as_str(),
            Some(serde_json::json!({ "certificate_id": f.certificate_id })),
            "routes:read",
        ),
        (
            "POST",
            "/automation/v1/backends".to_string(),
            backends_write.as_str(),
            Some(serde_json::json!({ "address": "10.0.0.12:8080" })),
            "backends:read",
        ),
        (
            "PUT",
            format!("/automation/v1/backends/{}", f.backend_id),
            backends_write.as_str(),
            Some(serde_json::json!({})),
            "backends:read",
        ),
        (
            "DELETE",
            format!("/automation/v1/backends/{}", f.backend_id),
            backends_write.as_str(),
            None,
            "backends:read",
        ),
        (
            "POST",
            format!("/automation/v1/certificates/{}/renew", f.certificate_id),
            certificates_write.as_str(),
            None,
            "certificates:read",
        ),
    ];
    // The rule is a property of the answer, not of the scope: a preview
    // needs the read scope of what it answers unless what it answers is
    // exactly its own write vocabulary. A preview listed here is exempt
    // only because its answer, read below from the write scope alone,
    // carries those keys and no other (Story 11.3's settings write).
    let answering_their_own_vocabulary = [(
        "PUT",
        "/automation/v1/settings".to_string(),
        settings_write.as_str(),
        serde_json::json!({ "cert_warning_days": 20 }),
        allowlisted_settings(),
    )];
    assert_eq!(
        previews.len() + answering_their_own_vocabulary.len(),
        crate::automation::scope::WRITE_SURFACE.len()
    );
    for (method, path, bearer, body, vocabulary) in answering_their_own_vocabulary {
        let response = automation_call(
            &f.state,
            method,
            &format!("{path}?dry_run=true"),
            bearer,
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        let change = parse_data(response).await;
        assert_eq!(data_keys(&change["before"]), vocabulary, "{method} {path}");
        assert_eq!(data_keys(&change["after"]), vocabulary, "{method} {path}");
    }
    for (method, path, bearer, body, needed) in previews {
        let response = automation_call(
            &f.state,
            method,
            &format!("{path}?dry_run=true"),
            bearer,
            body,
        )
        .await;
        assert_forbidden_naming(response, needed, &format!("{method} {path}?dry_run=true")).await;
    }
    // And a preview by the fixture's token, which reads, answers.
    let response = automation_call(
        &f.state,
        "PUT",
        &format!("/automation/v1/routes/{route_id}?dry_run=true"),
        &f.bearer,
        Some(serde_json::json!({ "waf_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
