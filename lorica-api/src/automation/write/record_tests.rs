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

//! Backlog #93 end to end, through the real routers: a protected route a
//! token deletes leaves a record, every automation write that would
//! serve its names is held to it, and the operator ends it.

use crate::automation::test_support::{
    a_node_with_something_to_write, assert_no_secret_field_name, audit_rows_under, automation_call,
    canonical_now, mcp_call, WriteFixture, WRITE_TOKEN_NAME,
};
use crate::route_protection_records::{
    RECORD_CLEAR_ACTION, RECORD_CLEAR_BY_ROUTE_WRITE_ACTION, RECORD_CREATE_ACTION,
};
use crate::tests::{body_json, parse_data, send};
use axum::http::StatusCode;

const RECORDS: &str = "/api/v1/automation/route-protection-records";

/// The password an operator sets on the protected route; nothing a
/// token or the listing reads may carry it or its hash.
const PASSWORD: &str = "operator-chosen-sentinel";

/// An operator route through the management API, `body` as sent; its id.
async fn operator_route(f: &WriteFixture, body: serde_json::Value) -> String {
    let created = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(body.clone()),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED, "{body}");
    parse_data(created).await["id"]
        .as_str()
        .expect("route id")
        .to_string()
}

/// The protected operator route every test starts from.
async fn protected_route(f: &WriteFixture) -> String {
    operator_route(
        f,
        serde_json::json!({
            "hostname": "app.write.example.com",
            "hostname_aliases": ["www.write.example.com"],
            "ip_allowlist": ["10.0.0.0/8"],
            "waf_enabled": true,
        }),
    )
    .await
}

/// The records the management listing answers.
async fn listed(f: &WriteFixture) -> serde_json::Value {
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "GET",
        RECORDS,
        &f.admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    parse_data(response).await["records"].clone()
}

/// A token's route delete, answered 200.
async fn token_deletes(f: &WriteFixture, route_id: &str) {
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

/// A token route write refused for serving a recorded name weaker: a
/// 403 naming `field` and the record, echoing no recorded value, and
/// nothing written, the preview included.
async fn assert_record_refused(
    f: &WriteFixture,
    method: &str,
    path: &str,
    body: serde_json::Value,
    field: &str,
    record_id: &str,
) {
    let before = lorica_config::canonical::encode_canonical(&canonical_now(&f.state).await)
        .expect("encodes");
    for suffix in ["", "?dry_run=true"] {
        let response = automation_call(
            &f.state,
            method,
            &format!("{path}{suffix}"),
            &f.bearer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}{suffix}");
        let refusal = body_json(response).await;
        let message = refusal["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("{field}: route protection record `{record_id}`")),
            "{body}{suffix}: {refusal}"
        );
        assert!(!message.contains("10.0.0.0"), "{body}{suffix}: {refusal}");
    }
    let after = lorica_config::canonical::encode_canonical(&canonical_now(&f.state).await)
        .expect("encodes");
    assert_eq!(before, after, "a refused write changed the store");
}

#[tokio::test]
async fn a_protected_route_a_token_deleted_is_not_created_again_weaker() {
    let f = a_node_with_something_to_write().await;
    let route_id = protected_route(&f).await;
    token_deletes(&f, &route_id).await;

    // One record, audited, listing what it holds and nothing of its
    // values.
    let records = listed(&f).await;
    assert_eq!(records.as_array().map(Vec::len), Some(1), "{records}");
    let record = &records[0];
    let record_id = record["id"].as_str().expect("record id").to_string();
    assert_eq!(record["route_id"], route_id.as_str());
    assert_eq!(record["hostname"], "app.write.example.com");
    assert_eq!(
        record["hostname_aliases"],
        serde_json::json!(["www.write.example.com"])
    );
    assert_eq!(record["path_prefix"], "/");
    assert_eq!(record["readable"], true);
    assert!(
        record["deleted_by"]
            .as_str()
            .is_some_and(|by| by.contains(WRITE_TOKEN_NAME) && by.contains(&f.public_id)),
        "{record}"
    );
    let controls: Vec<serde_json::Value> = record["controls"]
        .as_array()
        .expect("controls")
        .iter()
        .map(|control| control["fields"].clone())
        .collect();
    assert_eq!(
        controls,
        vec![
            serde_json::json!(["ip_allowlist"]),
            serde_json::json!(["waf_enabled"])
        ]
    );
    assert!(!records.to_string().contains("10.0.0.0"), "{records}");
    let created = audit_rows_under(&f.state, RECORD_CREATE_ACTION).await;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].target_id, record_id);
    assert!(created[0].operator_username.contains(WRITE_TOKEN_NAME));

    // The bare recreate, a recreate under another primary name with the
    // recorded one as an alias, and a recreate weaker on one control.
    assert_record_refused(
        &f,
        "POST",
        "/automation/v1/routes",
        serde_json::json!({ "hostname": "app.write.example.com" }),
        "ip_allowlist",
        &record_id,
    )
    .await;
    assert_record_refused(
        &f,
        "POST",
        "/automation/v1/routes",
        serde_json::json!({
            "hostname": "elsewhere.write.example.com",
            "hostname_aliases": ["www.write.example.com"],
        }),
        "ip_allowlist",
        &record_id,
    )
    .await;
    assert_record_refused(
        &f,
        "POST",
        "/automation/v1/routes",
        serde_json::json!({
            "hostname": "app.write.example.com",
            "ip_allowlist": ["10.0.0.0/8"],
        }),
        "waf_enabled",
        &record_id,
    )
    .await;

    // An update that adds the recorded name to a route of the token's.
    let side = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "side.write.example.com" })),
    )
    .await;
    assert_eq!(side.status(), StatusCode::CREATED);
    let side_id = parse_data(side).await["id"]
        .as_str()
        .expect("route id")
        .to_string();
    assert_record_refused(
        &f,
        "PUT",
        &format!("/automation/v1/routes/{side_id}"),
        serde_json::json!({ "hostname_aliases": ["app.write.example.com"] }),
        "ip_allowlist",
        &record_id,
    )
    .await;

    // Matching, or stronger, lands; the record is kept.
    let recreated = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "app.write.example.com",
            "hostname_aliases": ["www.write.example.com"],
            "ip_allowlist": ["10.1.0.0/16"],
            "waf_enabled": true,
            "waf_mode": "blocking",
        })),
    )
    .await;
    assert_eq!(recreated.status(), StatusCode::CREATED);
    assert_eq!(listed(&f).await.as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn the_same_delete_and_recreate_through_mcp_is_refused() {
    let f = a_node_with_something_to_write().await;
    let route_id = protected_route(&f).await;
    let deleted = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_delete",
        serde_json::json!({ "id": route_id }),
    )
    .await;
    assert_eq!(deleted["result"]["isError"], false, "{deleted}");
    let record_id = listed(&f).await[0]["id"]
        .as_str()
        .expect("the MCP delete left a record")
        .to_string();

    let recreated = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": { "hostname": "app.write.example.com" } }),
    )
    .await;
    assert_eq!(recreated["result"]["isError"], true, "{recreated}");
    let text = recreated["result"].to_string();
    assert!(
        text.contains(&format!("route protection record `{record_id}`")),
        "{text}"
    );
    assert!(!text.contains("10.0.0.0"), "{text}");
}

#[tokio::test]
async fn an_operator_clears_a_record_and_a_token_may_then_create_the_route_bare() {
    let f = a_node_with_something_to_write().await;
    let route_id = protected_route(&f).await;
    token_deletes(&f, &route_id).await;
    let record_id = listed(&f).await[0]["id"]
        .as_str()
        .expect("record id")
        .to_string();

    let cleared = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "DELETE",
        &format!("{RECORDS}/{record_id}"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(parse_data(cleared).await["id"], record_id.as_str());
    assert_eq!(listed(&f).await, serde_json::json!([]));
    let rows = audit_rows_under(&f.state, RECORD_CLEAR_ACTION).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, record_id);
    assert_eq!(rows[0].operator_username, "admin");

    let again = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "DELETE",
        &format!("{RECORDS}/{record_id}"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);

    let bare = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "app.write.example.com" })),
    )
    .await;
    assert_eq!(bare.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn an_operator_route_write_serving_a_recorded_name_clears_the_record() {
    let f = a_node_with_something_to_write().await;
    for (index, alias_only) in [false, true].into_iter().enumerate() {
        let route_id = protected_route(&f).await;
        token_deletes(&f, &route_id).await;
        let record_id = listed(&f).await[0]["id"]
            .as_str()
            .expect("record id")
            .to_string();

        // A create on the recorded hostname, or an update that adds a
        // recorded alias to an operator's route.
        let written = if alias_only {
            let other = operator_route(
                &f,
                serde_json::json!({ "hostname": "other.write.example.com" }),
            )
            .await;
            let response = send(
                &f.state,
                &f.session_store,
                &f.rate_limiter,
                "PUT",
                &format!("/api/v1/routes/{other}"),
                &f.admin,
                Some(serde_json::json!({ "hostname_aliases": ["www.write.example.com"] })),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            other
        } else {
            operator_route(
                &f,
                serde_json::json!({ "hostname": "app.write.example.com" }),
            )
            .await
        };
        assert_eq!(listed(&f).await, serde_json::json!([]), "{alias_only}");
        let rows = audit_rows_under(&f.state, RECORD_CLEAR_BY_ROUTE_WRITE_ACTION).await;
        assert_eq!(rows.len(), index + 1);
        assert_eq!(rows[0].target_id, record_id);

        // Back to an empty node for the next round.
        let response = send(
            &f.state,
            &f.session_store,
            &f.rate_limiter,
            "DELETE",
            &format!("/api/v1/routes/{written}"),
            &f.admin,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn an_operator_delete_records_nothing() {
    let f = a_node_with_something_to_write().await;
    let route_id = protected_route(&f).await;
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "DELETE",
        &format!("/api/v1/routes/{route_id}"),
        &f.admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(listed(&f).await, serde_json::json!([]));
    assert!(audit_rows_under(&f.state, RECORD_CREATE_ACTION)
        .await
        .is_empty());
    let bare = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "app.write.example.com" })),
    )
    .await;
    assert_eq!(bare.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_token_delete_preview_records_nothing() {
    let f = a_node_with_something_to_write().await;
    let route_id = protected_route(&f).await;
    let response = automation_call(
        &f.state,
        "DELETE",
        &format!("/automation/v1/routes/{route_id}?dry_run=true"),
        &f.bearer,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(listed(&f).await, serde_json::json!([]));
}

#[tokio::test]
async fn an_environment_on_a_recorded_name_inherits_the_record_and_answers_no_secret() {
    // The environment resource is not refused: it takes the recorded
    // controls over, the Basic-auth credential copied server side, as
    // it takes a displaced route's.
    let f = a_node_with_something_to_write().await;
    let route_id = operator_route(
        &f,
        serde_json::json!({
            "hostname": "tls.write.example.com",
            "basic_auth_username": "user01",
            "basic_auth_password": PASSWORD,
            "waf_enabled": true,
        }),
    )
    .await;
    let protected = f
        .state
        .store
        .lock()
        .await
        .get_route(&route_id)
        .expect("store")
        .expect("the protected route");
    let hash = protected
        .basic_auth_password_hash
        .clone()
        .expect("the stored hash");
    token_deletes(&f, &route_id).await;
    let records = listed(&f).await;
    let record_id = records[0]["id"].as_str().expect("record id").to_string();
    assert_eq!(
        records[0]["controls"][0]["fields"],
        serde_json::json!(["basic_auth_username"])
    );
    assert_no_secret_field_name(&records, "the record listing");
    for secret in [PASSWORD, hash.as_str()] {
        assert!(!records.to_string().contains(secret), "{records}");
    }

    // A token's own route on the name is refused on the credential.
    let response = automation_call(
        &f.state,
        "POST",
        "/automation/v1/routes",
        &f.bearer,
        Some(serde_json::json!({ "hostname": "tls.write.example.com", "waf_enabled": true })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/environments/pr-93",
        &f.bearer,
        Some(serde_json::json!({
            "hostname": "tls.write.example.com",
            "backends": [{ "address": "10.0.0.20:8080" }],
            "certificate": "auto",
            "ttl_seconds": 600,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let answer = body_json(response).await;
    let data = &answer["data"];
    assert_eq!(data["protections_inherited_from"], serde_json::json!([]));
    assert_eq!(
        data["protections_inherited_from_records"],
        serde_json::json!([record_id])
    );
    for secret in [PASSWORD, hash.as_str(), "user01"] {
        assert!(!answer.to_string().contains(secret), "{answer}");
    }
    let inherited = f
        .state
        .store
        .lock()
        .await
        .get_route(data["route_id"].as_str().expect("route id"))
        .expect("store")
        .expect("the environment's route");
    assert_eq!(inherited.basic_auth_username.as_deref(), Some("user01"));
    assert_eq!(inherited.basic_auth_password_hash, Some(hash));
    assert!(inherited.waf_enabled);

    // Deleting the environment, its route with it, records nothing more.
    let response = automation_call(
        &f.state,
        "DELETE",
        "/automation/v1/environments/pr-93",
        &f.bearer,
        None,
    )
    .await;
    assert!(response.status().is_success(), "{}", response.status());
    assert_eq!(listed(&f).await.as_array().map(Vec::len), Some(1));
}
