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

//! The MCP Streamable HTTP binding (Story 11.1 AC #9) and the config
//! tier over it (Story 11.2), through the whole stack: the bearer gate,
//! the endpoint, the core, the in-process router with its scope gate,
//! the handler, and the audit layer around all of it.

use crate::automation::test_support::{
    a_node_with_something_to_read, a_node_with_something_to_write, assert_no_secret_field_name,
    audit_rows_under, automation_audit_rows, automation_call, automation_send,
    automation_send_with_headers, canonical_now, json_keys_and_strings, mcp_call, mcp_headers_for,
    mcp_post, mcp_post_with, mint_automation, NEVER_LEAVES_THE_NODE, WRITE_TOKEN_NAME,
};
use crate::server::AppState;
use crate::tests::{body_json, parse_data, send, test_state};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use lorica_mcp::TierTools as _;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn an_mcp_tool_call_is_audited_with_what_the_node_proved_and_what_the_caller_claimed() {
    // AC #6. The MCP server is a separate process and reaches this
    // plane over HTTP, where there is no tool to observe: a tool is a
    // concept of the protocol that process speaks, not of the one it
    // speaks over. So the tool name and the transport are the caller's
    // declaration and the row says so, while the token's `public_id`
    // is the part this node proved and is what anchors the row.
    let data_dir = tempfile::tempdir().expect("test tempdir");
    let (mut state, _session_store, _rate_limiter) = test_state().await;
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    let token = mint_automation(
        &state,
        "mcp-read",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let bearer = format!("Bearer {token}");
    let public_id = token.split('.').next().expect("a token has two halves");

    let response = automation_send_with_headers(
        &state,
        "/automation/v1/logs?limit=5&search=secret",
        &bearer,
        &[
            (
                crate::automation::audit::ASSERTED_TRANSPORT_HEADER,
                "mcp-stdio",
            ),
            (
                crate::automation::audit::ASSERTED_TOOL_HEADER,
                "lorica_logs",
            ),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let rows = automation_audit_rows(&state).await;
    assert_eq!(rows.len(), 1, "one row per request: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.action, "automation.request.ok");
    // Established by verifying the credential: the id an operator
    // withdraws by, which is what the row is anchored on.
    assert_eq!(row.operator_username, format!("mcp-read ({public_id})"));
    // Established from the request line, and the filter VALUES stay out
    // (Story 9.9), which is the argument redaction AC #6 asks for: a
    // search string an operator typed and an attacker's payload are
    // equally absent.
    assert_eq!(
        row.target_id,
        "GET /automation/v1/logs?limit,search asserted[transport=mcp-stdio,tool=lorica_logs]"
    );
    assert!(!row.target_id.contains("secret"), "{}", row.target_id);
}

#[tokio::test]
async fn a_claim_the_node_cannot_store_is_dropped_and_a_call_without_one_claims_nothing() {
    let data_dir = tempfile::tempdir().expect("test tempdir");
    let (mut state, _session_store, _rate_limiter) = test_state().await;
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    let token = mint_automation(
        &state,
        "mcp-read",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let bearer = format!("Bearer {token}");

    // Anyone holding a live token can send any header they like, so the
    // claim is attacker-influenced. A value outside the accepted set is
    // dropped whole: the row must not carry a forged clause, and must
    // not carry half of one either.
    let forged = automation_send_with_headers(
        &state,
        "/automation/v1/logs",
        &bearer,
        &[
            (
                crate::automation::audit::ASSERTED_TOOL_HEADER,
                "x],transport=dashboard-session",
            ),
            (
                crate::automation::audit::ASSERTED_TRANSPORT_HEADER,
                "a b c d",
            ),
        ],
    )
    .await;
    assert_eq!(forged.status(), StatusCode::OK);

    // And a CI call, which is the common case: it claims nothing and
    // the row carries no clause at all.
    let plain = automation_send(&state, "/automation/v1/logs", Some(&bearer), None).await;
    assert_eq!(plain.status(), StatusCode::OK);

    let targets: Vec<String> = automation_audit_rows(&state)
        .await
        .iter()
        .map(|row| row.target_id.clone())
        .collect();
    assert_eq!(targets.len(), 2, "{targets:?}");
    for target in &targets {
        assert_eq!(target, "GET /automation/v1/logs", "{target}");
    }
}

/// One token per MCP tier on the node the read surface seeds, each
/// carrying every scope its tier mints: between them they register the
/// whole catalogue, which no single token may any more (Story 11.4 AC
/// #1).
async fn a_node_and_a_token_per_tier() -> (AppState, Vec<(lorica_mcp::Tier, String)>, String) {
    let (state, _read_token, route_id) = a_node_with_something_to_read().await;
    let mut bearers = Vec::new();
    for tier in lorica_mcp::Tier::ALL {
        // The seeded route answers on `read.example.com` itself, which
        // the one-label wildcard does not cover, and since the grant
        // bounds what a write targets the previews the config token
        // drives need the exact name granted beside the wildcard.
        let token = mint_automation(
            &state,
            &format!("mcp-{}", tier.as_str()),
            tier.minted_scopes(),
            &["read.example.com", "*.read.example.com"],
            chrono::Utc::now() + chrono::Duration::days(30),
            None,
        )
        .await;
        bearers.push((tier, format!("Bearer {token}")));
    }
    (state, bearers, route_id)
}

/// A token carrying `logs:read` alone, on the same node.
async fn a_node_and_a_token_for_the_log_alone() -> (AppState, String) {
    let (state, _read_token, _route_id) = a_node_with_something_to_read().await;
    let token = mint_automation(
        &state,
        "mcp-logs-only",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    (state, format!("Bearer {token}"))
}

#[tokio::test]
async fn the_mcp_endpoint_is_reached_by_any_live_token_and_answers_one_object() {
    // The endpoint cannot be declared behind one scope, so it is
    // declared reachable by any live token. This is that half: a token
    // carrying a read grant and nothing about environments gets an
    // answer rather than the 403 an undeclared path gives everyone.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;

    let response = mcp_post(
        &state,
        &bearer,
        &serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("application/json")),
        Some(true)
    );

    let body = body_json(response).await;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 7);
    assert_eq!(body["result"]["resultType"], "complete");
}

#[tokio::test]
async fn the_tool_set_is_the_one_the_presented_token_can_reach_and_nothing_else() {
    // The per-tool authorization the scope matrix cannot express. The
    // specification permits a tool set to vary by the authorization
    // presented on the request, since credentials are per-request input
    // rather than connection state, and forbids it varying per
    // connection, which nothing here does: the registry is built from
    // this request's principal and dropped with it.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;

    let body = body_json(
        mcp_post(
            &state,
            &bearer,
            &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
        )
        .await,
    )
    .await;
    let offered: Vec<String> = body["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_string())
        .collect();
    assert_eq!(offered, vec!["lorica_logs".to_string()]);

    // And a tool outside the grant does not exist to be called: a
    // protocol error raised before any read is reached, rather than the
    // 403 the read itself would have answered.
    let refused = mcp_call(
        &state,
        &bearer,
        "lorica_certificates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        refused["error"]["code"],
        lorica_mcp::jsonrpc::code::METHOD_NOT_FOUND
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("certificates:read")),
        "{refused}"
    );
    assert!(refused.get("result").is_none(), "{refused}");
}

/// The ids a sweep of the config tier's previews names, read off the
/// tier's own listings.
struct SweptIds {
    route: String,
    backend: String,
    certificate: String,
}

/// The arguments a sweep gives `spec`: the seeded resource it names,
/// and for a preview a body the plane accepts.
///
/// A mutation added to the catalogue and absent here stops the sweep
/// with its name, which is the decision the sweep exists to force: a
/// preview nobody drove through the in-process router is a preview
/// nobody proved reaches its handler.
fn sweep_arguments(spec: &lorica_mcp::tools::ToolSpec, ids: &SweptIds) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(param) = spec.resource {
        let id = match spec.path {
            "/automation/v1/backends" => &ids.backend,
            "/automation/v1/certificates" => &ids.certificate,
            _ => &ids.route,
        };
        map.insert(param.name.to_string(), serde_json::json!(id));
    }
    if let Some(body) = spec.body() {
        let value = match spec.name {
            "lorica_route_create_preview" => serde_json::json!({
                "hostname": "swept.read.example.com",
                "backend_ids": [ids.backend],
            }),
            "lorica_route_update_preview" => serde_json::json!({ "waf_enabled": true }),
            "lorica_route_bind_certificate_preview" => {
                serde_json::json!({ "certificate_id": ids.certificate })
            }
            "lorica_backend_create_preview" => serde_json::json!({ "address": "10.0.0.12:8080" }),
            "lorica_backend_update_preview" => serde_json::json!({ "name": "swept" }),
            "lorica_settings_update_preview" => serde_json::json!({ "cert_warning_days": 20 }),
            other => panic!("{other} is a mutation this sweep has no body for; give it one"),
        };
        map.insert(body.argument.to_string(), value);
    }
    serde_json::Value::Object(map)
}

#[tokio::test]
async fn every_registered_tool_answers_through_the_endpoint_without_leaving_the_process() {
    // Two things at once, deliberately. That the in-process plane
    // routes every call the catalogue can build, reads and previews
    // alike, which is what stops a tool added later reaching a handler
    // nobody mounted. And that what comes back is the plane's own
    // filtered view, which is what stops the in-process route becoming
    // a second way out for a field the HTTP route strips. The apply
    // tools are listed and not driven here: what they change, and what
    // they land in the audit trail, is the config tier's own tests'.
    let (state, bearers, route_id) = a_node_and_a_token_per_tier().await;
    let bearer_of = |wanted: lorica_mcp::Tier| -> String {
        bearers
            .iter()
            .find(|(tier, _)| *tier == wanted)
            .map(|(_, bearer)| bearer.clone())
            .expect("test setup: a token per tier")
    };
    let bearer = bearer_of(lorica_mcp::Tier::Read);

    // The ids the previews name, read through the read tier's listings.
    let first_id = |answered: &serde_json::Value| -> String {
        answered["result"]["structuredContent"]["untrusted"]["data"]["items"][0]["id"]
            .as_str()
            .expect("a listing carries an id")
            .to_string()
    };
    let ids = SweptIds {
        route: route_id,
        backend: first_id(
            &mcp_call(&state, &bearer, "lorica_backends", serde_json::json!({})).await,
        ),
        certificate: first_id(
            &mcp_call(
                &state,
                &bearer,
                "lorica_certificates",
                serde_json::json!({}),
            )
            .await,
        ),
    };
    // The renewal preview refuses a certificate that was uploaded, as
    // the apply would; the seeded one is marked as issued so the
    // preview reaches its answer rather than its refusal. Its SANs are
    // the test PEM's own names, which the grant does not cover and
    // which this sweep is not about, so the row carries none.
    {
        let store = state.store.lock().await;
        let mut certificate = store
            .get_certificate(&ids.certificate)
            .expect("store")
            .expect("the seeded certificate");
        certificate.is_acme = true;
        certificate.san_domains = Vec::new();
        store
            .update_certificate(&certificate)
            .expect("the mark lands");
    }

    let mut walked = 0usize;
    let mut driven = 0usize;
    let mut owned = 0usize;
    let mut offered: Vec<(String, String)> = Vec::new();
    for (tier, bearer) in &bearers {
        let listed = body_json(
            mcp_post(
                &state,
                bearer,
                &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
            )
            .await,
        )
        .await;
        for tool in listed["result"]["tools"].as_array().expect("a tool list") {
            let name = tool["name"].as_str().expect("a name");
            let spec = lorica_mcp::tools::find(name).expect("the catalogue knows what it offered");
            // A read a config token registers because its tier tolerates
            // the scope is driven once, by the read tier that owns it.
            if spec.tier == *tier {
                owned += 1;
                offered.push((name.to_string(), bearer.clone()));
            }
        }
    }
    assert_eq!(
        owned,
        lorica_mcp::tools::catalogue().len(),
        "one token per tier registers every tool between them: {offered:?}"
    );
    for (name, bearer) in &offered {
        let spec = lorica_mcp::tools::find(name).expect("the catalogue knows what it offered");
        if !spec.changes_nothing() {
            continue;
        }
        driven += 1;
        let answered = mcp_call(&state, bearer, name, sweep_arguments(spec, &ids)).await;
        assert_eq!(
            answered["result"]["isError"],
            serde_json::json!(false),
            "{name} answered an execution error: {answered}"
        );
        if spec.write().is_some() {
            assert_eq!(
                answered["result"]["structuredContent"]["untrusted"]["data"]["dry_run"],
                serde_json::json!(true),
                "{name} did not answer a preview: {answered}"
            );
        }

        let mut keys = Vec::new();
        let mut texts = Vec::new();
        json_keys_and_strings(&answered, &mut keys, &mut texts);
        walked += keys.len();
        for key in &keys {
            let lowered = key.to_ascii_lowercase();
            for marker in NEVER_LEAVES_THE_NODE {
                assert!(
                    !lowered.contains(marker),
                    "{name} answers a field named `{key}`, which matches `{marker}`"
                );
            }
        }
        for text in &texts {
            assert!(
                !text.contains("PRIVATE KEY"),
                "{name} answers a value carrying a PEM private key block"
            );
        }
    }
    assert!(
        walked > 100,
        "the sweep walked only {walked} field names across every tool, so it is broken"
    );
    assert_eq!(
        driven,
        lorica_mcp::tools::catalogue()
            .iter()
            .filter(|spec| spec.changes_nothing())
            .count(),
        "the sweep drove fewer tools than change nothing"
    );
}

#[tokio::test]
async fn the_verbs_this_revision_removed_answer_405_and_not_403() {
    // Revision 2026-07-28 dropped protocol-level sessions and the
    // standalone GET stream, so neither verb exists here. A 403 would
    // tell a client its token lacks a grant, which is not what is
    // wrong: the path answers one verb.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    for method in ["GET", "DELETE", "PUT", "PATCH"] {
        let router = crate::automation::build_automation_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(crate::automation::MCP_PATH)
                    .header(http::header::AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .expect("test setup"),
            )
            .await
            .expect("test setup");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }
}

#[tokio::test]
async fn a_session_id_and_a_last_event_id_are_ignored_and_never_echoed() {
    // Both belong to eras this revision replaced. They are accepted and
    // do nothing, and nothing comes back that would let a client think
    // a session was established.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let message = serde_json::json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" });
    let mut headers = mcp_headers_for(&message);
    headers.push((
        crate::automation::mcp::SESSION_ID_HEADER.to_string(),
        "a-session-from-an-older-era".to_string(),
    ));
    headers.push((
        crate::automation::mcp::LAST_EVENT_ID_HEADER.to_string(),
        "42".to_string(),
    ));

    let response = mcp_post_with(&state, &bearer, &message, &headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(crate::automation::mcp::SESSION_ID_HEADER)
            .is_none(),
        "a session id was echoed"
    );
    assert_eq!(body_json(response).await["id"], 3);
}

#[tokio::test]
async fn a_notification_is_accepted_with_no_body_at_all() {
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let response = mcp_post(
        &state,
        &bearer,
        &serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": { "requestId": 1 },
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    assert!(body.is_empty(), "a 202 carries no body");
}

#[tokio::test]
async fn an_origin_header_is_refused_through_the_whole_stack() {
    // The specification's one MUST on this transport, against DNS
    // rebinding. Asserted through the router and not only on the pure
    // function, because the gates in front of it are where a refusal
    // could be turned into something else.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let message = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let mut headers = mcp_headers_for(&message);
    headers.push((
        http::header::ORIGIN.to_string(),
        "https://evil.example.com".to_string(),
    ));

    let response = mcp_post_with(&state, &bearer, &message, &headers).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["id"], serde_json::Value::Null);
    assert!(body["error"]["message"].is_string(), "{body}");
}

#[tokio::test]
async fn a_header_that_does_not_mirror_its_body_is_refused_through_the_whole_stack() {
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let message = serde_json::json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": { "name": "lorica_logs", "arguments": {} },
    });

    // The header naming another tool than the body does. This is what
    // an intermediary is asked to validate rather than trust, and
    // Lorica is exactly that kind of intermediary.
    let forged = with_header(
        &message,
        crate::automation::mcp::NAME_HEADER,
        "lorica_certificates",
    );
    let response = mcp_post_with(&state, &bearer, &message, &forged).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(
        body["error"]["code"],
        crate::automation::mcp::HEADER_MISMATCH
    );
    assert_eq!(body["id"], 4);

    // And the same forgery behind a Base64 sentinel, which is the shape
    // that makes the check bypassable on a server comparing the raw
    // header instead of decoding it first.
    use base64::Engine as _;
    let sentinel = format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode("lorica_certificates")
    );
    let smuggled = with_header(&message, crate::automation::mcp::NAME_HEADER, &sentinel);
    let response = mcp_post_with(&state, &bearer, &message, &smuggled).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["error"]["code"],
        crate::automation::mcp::HEADER_MISMATCH
    );
}

/// The conforming headers for `message`, with one of them replaced.
fn with_header(message: &serde_json::Value, header: &str, value: &str) -> Vec<(String, String)> {
    mcp_headers_for(message)
        .into_iter()
        .map(|(name, carried)| {
            if name == header {
                (name, value.to_string())
            } else {
                (name, carried)
            }
        })
        .collect()
}

#[tokio::test]
async fn a_method_this_revision_does_not_define_is_a_404_through_the_whole_stack() {
    // Deliberately unusual: a JSON-RPC server would answer -32601 in a
    // 200. The 404 is how a client tells a server implementing this
    // revision from one implementing the era where `initialize` existed.
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let response = mcp_post(
        &state,
        &bearer,
        &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(response).await["error"]["code"],
        lorica_mcp::jsonrpc::code::METHOD_NOT_FOUND
    );
}

#[tokio::test]
async fn a_protocol_version_this_server_does_not_implement_names_what_it_does() {
    let (state, bearer) = a_node_and_a_token_for_the_log_alone().await;
    let message = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let older = with_header(
        &message,
        crate::automation::mcp::PROTOCOL_VERSION_HEADER,
        "2025-11-25",
    );

    let response = mcp_post_with(&state, &bearer, &message, &older).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(
        body["error"]["data"]["supportedVersions"],
        serde_json::json!([lorica_mcp::MCP_PROTOCOL_REVISION])
    );
    assert_eq!(
        body["error"]["data"]["name"],
        "UnsupportedProtocolVersionError"
    );
}

/// A node with a log store to audit into, and a token carrying
/// `logs:read` alone, minted on it.
async fn a_node_that_audits_and_a_log_token() -> (AppState, String, String, tempfile::TempDir) {
    let data_dir = tempfile::tempdir().expect("test tempdir");
    let (mut state, _session_store, _rate_limiter) = test_state().await;
    state.log_store = Some(Arc::new(
        crate::log_store::LogStore::open(data_dir.path()).expect("test setup: log store"),
    ));
    let token = mint_automation(
        &state,
        "mcp-http",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let public_id = token
        .split('.')
        .next()
        .expect("a token has two halves")
        .to_string();
    (state, format!("Bearer {token}"), public_id, data_dir)
}

/// The rows naming the MCP endpoint, newest first.
async fn mcp_audit_rows(state: &AppState) -> Vec<crate::audit::AuditRecord> {
    automation_audit_rows(state)
        .await
        .into_iter()
        .filter(|row| row.target_id.contains(crate::automation::MCP_PATH))
        .collect()
}

#[tokio::test]
async fn iv1_on_this_binding_a_token_spanning_two_tiers_is_refused_with_both_scopes_named() {
    // Story 11.4 IV1 through the Streamable HTTP stack, which builds a
    // server per request through the constructor the stdio binding runs
    // at startup, so the refusal is that constructor's. A 403 with a
    // JSON-RPC error under the request's id, naming both scopes; no
    // tool list, no tool call, and a row that says why.
    let (state, _bearer, _public_id, _data_dir) = a_node_that_audits_and_a_log_token().await;
    let token = mint_automation(
        &state,
        "mcp-two-tiers",
        vec![
            lorica_config::models::AutomationScope::LogsRead,
            lorica_config::models::AutomationScope::RoutesWrite,
        ],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let bearer = format!("Bearer {token}");

    for message in [
        serde_json::json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "lorica_logs", "arguments": {} },
        }),
    ] {
        let response = mcp_post(&state, &bearer, &message).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{message}");
        let body = body_json(response).await;
        assert_eq!(body["id"], 5, "{body}");
        assert!(body.get("result").is_none(), "{body}");
        assert_eq!(
            body["error"]["code"],
            lorica_mcp::jsonrpc::code::INVALID_REQUEST,
            "{body}"
        );
        let told = body["error"]["message"].as_str().unwrap_or_default();
        assert!(told.contains("logs:read"), "{told}");
        assert!(told.contains("routes:write"), "{told}");
    }

    let rows = mcp_audit_rows(&state).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        assert_eq!(
            row.action, "automation.request.forbidden:spans_tiers",
            "{row:?}"
        );
    }
    // The tool the refused call named is what the node read off the
    // body, not a claim: the mirror check ran before the refusal.
    assert_eq!(
        rows[0].target_id,
        format!("POST {} tool=lorica_logs", crate::automation::MCP_PATH)
    );
}

#[tokio::test]
async fn a_tool_call_on_this_binding_is_audited_with_what_the_node_established() {
    // AC #6 for the second binding, and what differs from stdio: the
    // node routed this request to the MCP endpoint itself, so the path
    // in the row IS the transport; the handler parsed the body, the
    // mirror check proved `Mcp-Name` equal to it and the catalogue
    // resolved the name, so the tool is established too and is written
    // OUTSIDE any `asserted[...]` clause, with the declared argument
    // names the call carried and never their values.
    let (state, bearer, public_id, _data_dir) = a_node_that_audits_and_a_log_token().await;

    let answered = mcp_call(
        &state,
        &bearer,
        "lorica_logs",
        serde_json::json!({ "limit": 5, "search": "secret" }),
    )
    .await;
    assert_eq!(answered["result"]["isError"], serde_json::json!(false));

    let rows = mcp_audit_rows(&state).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert!(row.operator_username.contains(&public_id), "{row:?}");
    assert_eq!(row.action, "automation.request.ok", "{row:?}");
    assert_eq!(
        row.target_id,
        format!(
            "POST {} tool=lorica_logs?search,limit",
            crate::automation::MCP_PATH
        )
    );
    assert!(!row.target_id.contains("asserted"), "{row:?}");
    assert!(!row.target_id.contains("secret"), "{row:?}");
}

#[tokio::test]
async fn iv2_on_this_binding_a_tool_outside_the_grant_and_a_revoked_token_are_audited_as_refusals()
{
    // IV2 through the Streamable HTTP stack. Every message the core
    // produced is answered with a 200, so a row keyed on the status
    // would say `ok` for a call on a tool the token does not hold. The
    // row and the metric take the core's outcome instead, and read like
    // the read path's own 403: the scope the tool needed. A token
    // revoked mid-session never reaches the core; its refusal is the
    // bearer gate's, and the row says so.
    let (state, bearer, public_id, _data_dir) = a_node_that_audits_and_a_log_token().await;
    let by_path = |outcome: &str| {
        crate::metrics::gathered_counter(
            "lorica_automation_requests_by_path_total",
            &[("path", crate::automation::MCP_PATH), ("outcome", outcome)],
        )
    };
    let forbidden_before = by_path("forbidden");

    let refused = mcp_call(
        &state,
        &bearer,
        "lorica_certificates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        refused["error"]["code"],
        lorica_mcp::jsonrpc::code::METHOD_NOT_FOUND
    );
    let rows = mcp_audit_rows(&state).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].action, "automation.request.forbidden:certificates:read",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_certificates",
            crate::automation::MCP_PATH
        )
    );
    // The counter is process-wide and other tests drive this endpoint in
    // parallel, so only a lower bound holds here: the refusal was counted
    // as `forbidden`. That it was not also counted as `ok` follows from
    // the row above, whose word is the one the counter is given
    // (`automation::audit`), and cannot be asserted from a shared counter.
    assert!(by_path("forbidden") > forbidden_before);

    // And an execution error: the plane refusing the read the tool
    // made. An offset deeper than the log can answer is the plane's
    // 400, which keeps the word that status has on every other row,
    // and the tool that ran is established with the names it carried.
    let failed = mcp_call(
        &state,
        &bearer,
        "lorica_logs",
        serde_json::json!({ "offset": 100_000, "limit": 200 }),
    )
    .await;
    assert_eq!(
        failed["result"]["isError"],
        serde_json::json!(true),
        "{failed}"
    );
    let rows = mcp_audit_rows(&state).await;
    assert_eq!(
        rows[0].action, "automation.request.refused",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_logs?limit,offset",
            crate::automation::MCP_PATH
        )
    );

    // Revoked mid-session: the next call is the bearer gate's 401 and
    // the row names the reason; the tool the POST named is a claim on
    // that row, because the core never saw the body.
    {
        let store = state.store.lock().await;
        assert!(store
            .revoke_automation_token(&public_id, chrono::Utc::now())
            .expect("revoke"));
    }
    let response = mcp_post(
        &state,
        &bearer,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "lorica_logs", "arguments": {} },
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let rows = mcp_audit_rows(&state).await;
    assert_eq!(
        rows[0].action, "automation.request.unauthenticated:token_revoked",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} asserted[tool=lorica_logs]",
            crate::automation::MCP_PATH
        )
    );
}

#[tokio::test]
async fn the_invocation_budget_binds_across_requests_on_this_binding() {
    // The revision's "rate limit tool invocations" MUST, on the binding
    // where it matters. The core is built per request here, so a
    // budget it owned counted one call and reset; the budget is the
    // token's, held by the process, and the window opened by the first
    // request is the one the hundred-and-twenty-first finds spent.
    let (state, bearer, _public_id, _data_dir) = a_node_that_audits_and_a_log_token().await;
    for n in 0..lorica_mcp::server::RATE_BUDGET {
        let answered = mcp_call(&state, &bearer, "lorica_logs", serde_json::json!({})).await;
        assert_eq!(
            answered["result"]["isError"],
            serde_json::json!(false),
            "call {n}: {answered}"
        );
    }
    let over = mcp_call(&state, &bearer, "lorica_logs", serde_json::json!({})).await;
    assert_eq!(over["result"]["isError"], serde_json::json!(true), "{over}");
    let window = format!(
        "every {} seconds",
        lorica_mcp::server::RATE_WINDOW.as_secs()
    );
    assert!(
        over["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains(&window)),
        "{over}"
    );
    // Audited as the refusal it is, not as the 200 it travelled in.
    let rows = mcp_audit_rows(&state).await;
    assert_eq!(
        rows[0].action, "automation.request.refused:rate_limited",
        "{:?}",
        rows[0]
    );

    // Per token: another token on the same node has its own window.
    let other = mint_automation(
        &state,
        "mcp-other",
        vec![lorica_config::models::AutomationScope::LogsRead],
        &["*.read.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let answered = mcp_call(
        &state,
        &format!("Bearer {other}"),
        "lorica_logs",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(answered["result"]["isError"], serde_json::json!(false));
}

#[tokio::test]
async fn the_assertion_headers_cannot_replace_the_tool_the_node_ran_on_this_binding() {
    // On this path the transport is the path and the tool is what the
    // body named, so Lorica's own two assertion headers are ignored: a
    // caller could otherwise put a different tool in the row than the
    // one the node ran. And `Mcp-Name` in a Base64 sentinel is decoded
    // wherever it is read, so it can neither dodge the mirror check nor
    // leave the row blank.
    use base64::Engine as _;

    let (state, bearer, _public_id, _data_dir) = a_node_that_audits_and_a_log_token().await;
    let message = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "lorica_logs", "arguments": { "limit": 1 } },
    });
    let sentinel = format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode("lorica_logs")
    );
    let mut headers = with_header(&message, crate::automation::mcp::NAME_HEADER, &sentinel);
    headers.push((
        crate::automation::audit::ASSERTED_TOOL_HEADER.to_string(),
        "lorica_waf_stats".to_string(),
    ));
    headers.push((
        crate::automation::audit::ASSERTED_TRANSPORT_HEADER.to_string(),
        "mcp-stdio".to_string(),
    ));
    let response = mcp_post_with(&state, &bearer, &message, &headers).await;
    assert_eq!(response.status(), StatusCode::OK);

    let rows = mcp_audit_rows(&state).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_logs?limit",
            crate::automation::MCP_PATH
        )
    );
    assert!(!rows[0].target_id.contains("waf_stats"), "{:?}", rows[0]);
    assert!(!rows[0].target_id.contains("mcp-stdio"), "{:?}", rows[0]);

    // A POST the mirror check refuses never reaches the core, and its
    // row carries the decoded header as the claim it is, with the
    // assertion headers still ignored.
    let mut forged = with_header(
        &message,
        crate::automation::mcp::NAME_HEADER,
        &format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode("lorica_certificates")
        ),
    );
    forged.push((
        crate::automation::audit::ASSERTED_TOOL_HEADER.to_string(),
        "lorica_waf_stats".to_string(),
    ));
    let response = mcp_post_with(&state, &bearer, &message, &forged).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let rows = mcp_audit_rows(&state).await;
    assert_eq!(
        rows[0].action, "automation.request.refused",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} asserted[tool=lorica_certificates]",
            crate::automation::MCP_PATH
        )
    );
}

// ---- The MCP config tier (Story 11.2), over the Streamable HTTP binding ----
//
// The write fixture's token carries every scope over
// `*.write.example.com` and `10.0.0.0/8`, so the tier it starts on
// this binding is the config tier with every read tool beside it. What
// these tests prove is what the tier does to the store and to the
// trail, through the whole stack: the bearer gate, the endpoint, the
// core, the in-process router with its scope gate, the write handler,
// and the audit layer around all of it.

/// The plane's answer inside a tool result.
fn plane_answer(result: &serde_json::Value) -> &serde_json::Value {
    &result["result"]["structuredContent"]["untrusted"]["data"]
}

/// The text of a tool result's one content block.
fn result_text(result: &serde_json::Value) -> &str {
    result["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
}

/// Every scope of the token model that reads, as the read tier is
/// minted.
fn every_read_scope() -> Vec<lorica_config::models::AutomationScope> {
    lorica_config::models::AutomationScope::ALL
        .iter()
        .copied()
        .filter(|scope| {
            serde_json::to_value(scope)
                .ok()
                .and_then(|value| value.as_str().map(|spelled| spelled.ends_with(":read")))
                .unwrap_or(false)
        })
        .collect()
}

#[tokio::test]
async fn the_config_tier_on_this_binding_is_the_tokens_scopes_and_a_read_tier_token_gains_no_write()
{
    // Story 11.2 AC #2 through the whole stack. The tier is decided per
    // request from the presented token: a config-tier token lists every
    // mutation with its preview and the reads its tier tolerates, and a
    // token minted on the same node with every read scope lists the
    // reads alone and cannot call a mutation, whose refusal is audited
    // as the scope it needed.
    let f = a_node_with_something_to_write().await;
    let list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });

    let offered: Vec<String> = body_json(mcp_post(&f.state, &f.mcp_bearer, &list).await).await
        ["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_string())
        .collect();
    for mutation in lorica_mcp::tools::MUTATIONS {
        assert!(offered.contains(&mutation.apply.to_string()), "{offered:?}");
        assert!(
            offered.contains(&mutation.preview.to_string()),
            "{offered:?}"
        );
    }
    assert!(offered.contains(&"lorica_routes".to_string()));

    let read_tier = mint_automation(
        &f.state,
        "read-tier",
        every_read_scope(),
        &["*.write.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let read_bearer = format!("Bearer {read_tier}");
    let offered: Vec<String> = body_json(mcp_post(&f.state, &read_bearer, &list).await).await
        ["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_string())
        .collect();
    assert!(!offered.is_empty());
    for name in &offered {
        let spec = lorica_mcp::tools::find(name).expect("listed tools are in the catalogue");
        assert!(
            spec.write().is_none(),
            "{name} is offered to a read-tier token"
        );
    }
    let refused = mcp_call(
        &f.state,
        &read_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": { "hostname": "app.write.example.com" } }),
    )
    .await;
    assert_eq!(
        refused["error"]["code"],
        lorica_mcp::jsonrpc::code::METHOD_NOT_FOUND
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("routes:write")),
        "{refused}"
    );
    let rows = mcp_audit_rows(&f.state).await;
    assert_eq!(
        rows[0].action, "automation.request.forbidden:routes:write",
        "{:?}",
        rows[0]
    );
    assert_eq!(canonical_now(&f.state).await.routes.len(), 0);
}

#[tokio::test]
async fn iv1_a_route_created_through_the_config_tier_is_the_dashboards_route_byte_for_byte() {
    // Story 11.2 IV1 through the tier: the same body through
    // `lorica_route_create` and through the dashboard lands the same
    // stored row, byte for byte in the canonical encoding once the id
    // and the clock are set equal. It holds because the tool's call
    // runs the management handler's own body, in process, and the tool
    // layer never touches a field.
    let f = a_node_with_something_to_write().await;
    let route = serde_json::json!({
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
    });

    let answered = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": route.clone() }),
    )
    .await;
    assert_eq!(
        answered["result"]["isError"],
        serde_json::json!(false),
        "{answered}"
    );
    let tier_view = plane_answer(&answered).clone();
    assert_no_secret_field_name(&tier_view, "lorica_route_create");
    let tier_id = tier_view["id"].as_str().expect("route id").to_string();
    let through_tier = canonical_now(&f.state).await;

    {
        let store = f.state.store.lock().await;
        store
            .delete_route(&tier_id)
            .expect("test setup: the row leaves");
    }
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(route),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let dashboard_view = parse_data(response).await;
    let dashboard_id = dashboard_view["id"].as_str().expect("route id").to_string();
    let mut through_dashboard = canonical_now(&f.state).await;

    let tier_route = through_tier
        .routes
        .iter()
        .find(|route| route.id == tier_id)
        .expect("the tier's row is in the canonical config");
    for route in &mut through_dashboard.routes {
        if route.id == dashboard_id {
            route.id = tier_id.clone();
            route.created_at = tier_route.created_at;
            route.updated_at = tier_route.updated_at;
        }
    }
    for link in &mut through_dashboard.route_backends {
        if link.route_id == dashboard_id {
            link.route_id = tier_id.clone();
        }
    }
    assert_eq!(
        lorica_config::canonical::encode_canonical(&through_tier).expect("encodes"),
        lorica_config::canonical::encode_canonical(&through_dashboard).expect("encodes"),
        "the route the config tier wrote and the route the dashboard wrote differ"
    );
    let strip = |mut view: serde_json::Value| {
        let object = view.as_object_mut().expect("a route view is an object");
        for volatile in ["id", "created_at", "updated_at"] {
            object.remove(volatile);
        }
        view
    };
    assert_eq!(strip(tier_view), strip(dashboard_view));
}

#[tokio::test]
async fn iv2_a_refusal_through_the_config_tier_arrives_unchanged_and_writes_nothing() {
    // Story 11.2 IV2 through the tier, both halves and both refusals:
    // the management validator's, whose message crosses inside the
    // fence exactly as the dashboard shows it, and the plane's own
    // grant. Each is a tool EXECUTION error the model reads and stops
    // on, each is audited as the refusal it is, and the store is the
    // store it was.
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");

    let refused_by_a_validator = serde_json::json!({
        "hostname": "bad.write.example.com",
        "backend_ids": [f.backend_id],
        "connect_timeout_s": 0,
    });
    let through_dashboard = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "POST",
        "/api/v1/routes",
        &f.admin,
        Some(refused_by_a_validator.clone()),
    )
    .await;
    assert_eq!(through_dashboard.status(), StatusCode::BAD_REQUEST);
    let dashboard_error = body_json(through_dashboard).await;
    let dashboard_message = dashboard_error["error"]["message"]
        .as_str()
        .expect("the dashboard's message");
    assert!(dashboard_message.contains("connect_timeout_s"));

    let answered = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": refused_by_a_validator }),
    )
    .await;
    assert!(answered.get("error").is_none(), "{answered}");
    assert_eq!(answered["result"]["isError"], serde_json::json!(true));
    let text = result_text(&answered);
    assert!(text.contains("HTTP 400"), "{text}");
    assert!(text.contains(dashboard_message), "{text}");
    assert!(text.contains(lorica_mcp::untrusted::NOTICE), "{text}");
    let rows = mcp_audit_rows(&f.state).await;
    assert_eq!(
        rows[0].action, "automation.request.refused",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_route_create?route",
            crate::automation::MCP_PATH
        )
    );

    // The plane's own refusal, the grant, before the handler runs.
    let answered = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": { "hostname": "www.example.com" } }),
    )
    .await;
    assert_eq!(answered["result"]["isError"], serde_json::json!(true));
    let text = result_text(&answered);
    assert!(text.contains("HTTP 403"), "{text}");
    assert!(text.contains("allowed_hostnames"), "{text}");
    let rows = mcp_audit_rows(&f.state).await;
    assert_eq!(
        rows[0].action, "automation.request.forbidden",
        "{:?}",
        rows[0]
    );

    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused write changed the store"
    );
    assert!(audit_rows_under(&f.state, "route.").await.is_empty());
}

#[tokio::test]
async fn a_preview_through_the_config_tier_answers_the_change_and_writes_nothing() {
    // Story 11.2 AC #3 through the tier. The preview takes the apply
    // tool's arguments, answers the change as the plane's own JSON,
    // lands the request row and no management row, and leaves the
    // canonical configuration byte for byte where it was; the apply
    // then makes exactly that change.
    let f = a_node_with_something_to_write().await;
    let created = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({ "route": {
            "hostname": "app.write.example.com",
            "backend_ids": [f.backend_id],
        } }),
    )
    .await;
    assert_eq!(
        created["result"]["isError"],
        serde_json::json!(false),
        "{created}"
    );
    let route_id = plane_answer(&created)["id"]
        .as_str()
        .expect("route id")
        .to_string();
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let management_rows_before = audit_rows_under(&f.state, "route.").await.len();

    let patch = serde_json::json!({ "id": route_id, "route": {
        "waf_enabled": true,
        "hostname_aliases": ["alias.write.example.com"],
    } });
    let previewed = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_update_preview",
        patch.clone(),
    )
    .await;
    assert_eq!(
        previewed["result"]["isError"],
        serde_json::json!(false),
        "{previewed}"
    );
    let change = plane_answer(&previewed);
    assert_eq!(change["dry_run"], serde_json::json!(true));
    assert_eq!(change["operation"], serde_json::json!("update"));
    assert_eq!(change["before"]["id"], serde_json::json!(route_id));
    assert_eq!(change["before"]["waf_enabled"], serde_json::json!(false));
    assert_eq!(change["after"]["waf_enabled"], serde_json::json!(true));
    assert_eq!(
        change["changes"]["waf_enabled"],
        serde_json::json!({ "from": false, "to": true })
    );
    assert_eq!(
        change["changes"]["hostname_aliases"],
        serde_json::json!({ "from": [], "to": ["alias.write.example.com"] })
    );
    assert!(change["changes"].get("hostname").is_none(), "{change}");
    // The backend links survive a preview's `after`, and the ones
    // before are read for the `before` view.
    assert_eq!(
        change["before"]["backends"],
        serde_json::json!([f.backend_id])
    );
    assert_eq!(
        change["after"]["backends"],
        serde_json::json!([f.backend_id])
    );

    let deleted = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_delete_preview",
        serde_json::json!({ "id": route_id }),
    )
    .await;
    let change = plane_answer(&deleted);
    assert_eq!(change["operation"], serde_json::json!("delete"));
    assert_eq!(change["before"]["id"], serde_json::json!(route_id));
    assert_eq!(change["after"], serde_json::Value::Null);

    let would_create = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create_preview",
        serde_json::json!({ "route": { "hostname": "new.write.example.com" } }),
    )
    .await;
    let change = plane_answer(&would_create);
    assert_eq!(change["operation"], serde_json::json!("create"));
    assert_eq!(change["before"], serde_json::Value::Null);
    assert_eq!(
        change["after"]["hostname"],
        serde_json::json!("new.write.example.com")
    );
    assert!(change["after"].get("id").is_none(), "{change}");

    // Nothing moved: not the store, not the management trail. The
    // request rows name the previews as what they are.
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a preview changed the store"
    );
    assert_eq!(
        audit_rows_under(&f.state, "route.").await.len(),
        management_rows_before
    );
    let rows = mcp_audit_rows(&f.state).await;
    assert!(
        rows.iter().any(|row| {
            row.action == "automation.request.ok"
                && row.target_id
                    == format!(
                        "POST {} tool=lorica_route_update_preview?id,route",
                        crate::automation::MCP_PATH
                    )
        }),
        "{rows:?}"
    );

    // And the apply, with the same arguments, is the change the
    // preview showed.
    let applied = mcp_call(&f.state, &f.mcp_bearer, "lorica_route_update", patch).await;
    assert_eq!(
        applied["result"]["isError"],
        serde_json::json!(false),
        "{applied}"
    );
    let now = canonical_now(&f.state).await;
    let route = now
        .routes
        .iter()
        .find(|route| route.id == route_id)
        .expect("the route is there");
    assert!(route.waf_enabled);
    assert_eq!(route.hostname_aliases, vec!["alias.write.example.com"]);
    assert_eq!(
        audit_rows_under(&f.state, "route.").await.len(),
        management_rows_before + 1
    );
}

#[tokio::test]
async fn every_write_path_previews_under_dry_run_and_writes_nothing() {
    // Story 11.2 AC #3 on the plane, one entry per write path: each
    // answers the change under `?dry_run=true`, and when all eight have
    // answered the canonical configuration and the management trail are
    // what they were. The table is asserted against `WRITE_SURFACE`, so
    // a write path added to the plane has to be given a preview here.
    let f = a_node_with_something_to_write().await;
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
    {
        let store = f.state.store.lock().await;
        let mut certificate = store
            .get_certificate(&f.certificate_id)
            .expect("store")
            .expect("the seeded certificate");
        certificate.is_acme = true;
        store
            .update_certificate(&certificate)
            .expect("the mark lands");
    }
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let management_rows = |state: AppState| async move {
        audit_rows_under(&state, "route.").await.len()
            + audit_rows_under(&state, "backend.").await.len()
            + audit_rows_under(&state, "certificate.").await.len()
            + audit_rows_under(&state, "settings.").await.len()
    };
    let rows_before = management_rows(f.state.clone()).await;

    let previews: Vec<(&str, String, Option<serde_json::Value>, &str)> = vec![
        (
            "POST",
            "/automation/v1/routes".to_string(),
            Some(serde_json::json!({
                "hostname": "dry.write.example.com",
                "backend_ids": [f.backend_id],
            })),
            "create",
        ),
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}"),
            Some(serde_json::json!({ "waf_enabled": true })),
            "update",
        ),
        (
            "DELETE",
            format!("/automation/v1/routes/{route_id}"),
            None,
            "delete",
        ),
        (
            "PUT",
            format!("/automation/v1/routes/{route_id}/certificate"),
            Some(serde_json::json!({ "certificate_id": f.certificate_id })),
            "update",
        ),
        (
            "POST",
            "/automation/v1/backends".to_string(),
            Some(serde_json::json!({ "address": "10.0.0.12:8080" })),
            "create",
        ),
        (
            "PUT",
            format!("/automation/v1/backends/{}", f.backend_id),
            Some(serde_json::json!({ "name": "renamed" })),
            "update",
        ),
        (
            "DELETE",
            format!("/automation/v1/backends/{}", f.backend_id),
            None,
            "delete",
        ),
        (
            "POST",
            format!("/automation/v1/certificates/{}/renew", f.certificate_id),
            None,
            "renew",
        ),
        (
            "PUT",
            "/automation/v1/settings".to_string(),
            Some(serde_json::json!({ "cert_warning_days": 20 })),
            "update",
        ),
    ];
    assert_eq!(
        previews.len(),
        crate::automation::scope::WRITE_SURFACE.len()
    );

    for (method, path, body, operation) in previews {
        let response = automation_call(
            &f.state,
            method,
            &format!("{path}?dry_run=true"),
            &f.bearer,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        let change = parse_data(response).await;
        assert_eq!(
            change["dry_run"],
            serde_json::json!(true),
            "{method} {path}"
        );
        assert_eq!(
            change["operation"],
            serde_json::json!(operation),
            "{method} {path}"
        );
        assert_no_secret_field_name(&change, &format!("{method} {path}?dry_run=true"));
    }

    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a dry run changed the store"
    );
    assert_eq!(management_rows(f.state.clone()).await, rows_before);
    let request_rows = audit_rows_under(&f.state, "automation.request.").await;
    assert!(
        request_rows.iter().any(
            |row| row.target_id == "POST /automation/v1/backends?dry_run"
                && row.action == "automation.request.ok"
        ),
        "{request_rows:?}"
    );
}

/// A span as [`SpanRecorder`] keeps it.
type RecordedSpan = (&'static str, Option<u64>, String);

/// A subscriber that remembers each span's name, parent and `mcp.tool`
/// field, and the span each `lorica::audit` event was recorded in, for
/// a test that asks what a trace would show.
///
/// Installed with `set_default` on a current-thread runtime, so every
/// task the request spawns runs on the thread it is installed on.
#[derive(Default)]
struct SpanRecorder {
    next_id: std::sync::atomic::AtomicU64,
    /// Each span by id: its name, its parent and its `mcp.tool` field.
    spans: std::sync::Mutex<std::collections::HashMap<u64, RecordedSpan>>,
    entered: std::sync::Mutex<Vec<u64>>,
    audit_events: std::sync::Mutex<Vec<(String, Option<u64>)>>,
}

/// The value of one named field, as the recorder keeps it.
struct FieldNamed(&'static str, String);

impl tracing::field::Visit for FieldNamed {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == self.0 {
            self.1 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == self.0 {
            self.1 = value.to_string();
        }
    }
}

impl SpanRecorder {
    fn current(&self) -> Option<u64> {
        self.entered.lock().expect("recorder").last().copied()
    }

    /// The names of `span` and each of its ancestors, innermost first,
    /// each with its `mcp.tool` field.
    fn chain(&self, mut span: Option<u64>) -> Vec<(String, String)> {
        let spans = self.spans.lock().expect("recorder");
        let mut chain = Vec::new();
        while let Some(id) = span {
            let (name, parent, tool) = &spans[&id];
            chain.push((name.to_string(), tool.clone()));
            span = *parent;
        }
        chain
    }
}

/// The recorder as the subscriber `set_default` installs.
struct Recording(Arc<SpanRecorder>);

impl tracing::Subscriber for Recording {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
        let id = self
            .0
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let parent = match attrs.parent() {
            Some(parent) => Some(parent.into_u64()),
            None if attrs.is_contextual() => self.0.current(),
            None => None,
        };
        let mut tool = FieldNamed("mcp.tool", String::new());
        attrs.record(&mut tool);
        self.0
            .spans
            .lock()
            .expect("recorder")
            .insert(id, (attrs.metadata().name(), parent, tool.1));
        tracing::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != "lorica::audit" {
            return;
        }
        let mut action = FieldNamed("action", String::new());
        event.record(&mut action);
        let span = match event.parent() {
            Some(parent) => Some(parent.into_u64()),
            None if event.is_contextual() => self.0.current(),
            None => None,
        };
        self.0
            .audit_events
            .lock()
            .expect("recorder")
            .push((action.1, span));
    }

    fn enter(&self, span: &tracing::Id) {
        self.0
            .entered
            .lock()
            .expect("recorder")
            .push(span.into_u64());
    }

    fn exit(&self, span: &tracing::Id) {
        let mut entered = self.0.entered.lock().expect("recorder");
        if let Some(at) = entered.iter().rposition(|id| *id == span.into_u64()) {
            entered.remove(at);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_trace_follows_an_mcp_call_into_the_handler_it_ran() {
    // Backlog #92 (a). The automation plane opened no span, so an MCP
    // call's trace stopped at the listener and nothing the handler did
    // under it could be found from the call. Now the request is an
    // `automation_request` span, each tool call an `mcp_tool_call`
    // span under it naming the tool, and what the handler records sits
    // under that. No log store, so the management audit event is
    // emitted inside the handler rather than by the writer thread.
    let mut f = a_node_with_something_to_write().await;
    f.state.log_store = None;
    let recorder = Arc::new(SpanRecorder::default());
    let _installed = tracing::subscriber::set_default(Recording(Arc::clone(&recorder)));

    let answer = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_route_create",
        serde_json::json!({
            "route": { "hostname": "traced.write.example.com", "backend_ids": [f.backend_id] },
        }),
    )
    .await;
    assert_eq!(answer["result"]["isError"], false, "{answer}");

    let events = recorder.audit_events.lock().expect("recorder").clone();
    let (_, span) = events
        .iter()
        .find(|(action, _)| action == "route.create")
        .unwrap_or_else(|| panic!("the handler recorded its row: {events:?}"));
    let chain = recorder.chain(*span);
    let position = |name: &str| chain.iter().position(|(span, _)| span == name);
    let tool_call = position("mcp_tool_call")
        .unwrap_or_else(|| panic!("the handler ran inside the tool call's span: {chain:?}"));
    assert_eq!(chain[tool_call].1, "lorica_route_create", "{chain:?}");
    let request = position("automation_request")
        .unwrap_or_else(|| panic!("inside the request's span: {chain:?}"));
    assert!(
        tool_call < request,
        "the tool call is under the request: {chain:?}"
    );
}

#[tokio::test]
async fn a_write_through_the_config_tier_lands_the_management_row_and_the_mcp_row() {
    // Story 11.2 AC #7's audit half, through the tier: a mutation
    // lands the management-side row under the token's identity, as a
    // write over the socket does, beside the MCP request row that names
    // the tool the node ran and the argument names it carried; and a
    // refusal by the plane is audited as the refusal it is, from the
    // core's outcome and not from the 200 it travelled in.
    let f = a_node_with_something_to_write().await;
    let answered = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_backend_create",
        serde_json::json!({ "backend": { "address": "10.0.0.11:8080", "name": "via-mcp" } }),
    )
    .await;
    assert_eq!(
        answered["result"]["isError"],
        serde_json::json!(false),
        "{answered}"
    );
    let backend_id = plane_answer(&answered)["id"]
        .as_str()
        .expect("backend id")
        .to_string();

    let management_rows = audit_rows_under(&f.state, "backend.").await;
    let created = management_rows
        .iter()
        .find(|row| row.action == "backend.create" && row.target_id == backend_id)
        .expect("the management-side row the handler writes");
    assert_eq!(created.operator_role, "automation");
    assert_eq!(
        created.operator_username,
        format!("{WRITE_TOKEN_NAME} ({})", f.mcp_public_id)
    );

    let rows = mcp_audit_rows(&f.state).await;
    assert_eq!(rows[0].action, "automation.request.ok", "{:?}", rows[0]);
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_backend_create?backend",
            crate::automation::MCP_PATH
        )
    );
    assert!(rows[0].operator_username.contains(&f.mcp_public_id));
    // No row for the in-process call itself: one request, one request
    // row, and the management row beside it.
    assert!(
        !rows
            .iter()
            .any(|row| row.target_id.starts_with("POST /automation/v1/backends")),
        "{rows:?}"
    );

    // A refusal the plane makes: the address outside the grant.
    let refused = mcp_call(
        &f.state,
        &f.mcp_bearer,
        "lorica_backend_create",
        serde_json::json!({ "backend": { "address": "192.0.2.10:80" } }),
    )
    .await;
    assert_eq!(refused["result"]["isError"], serde_json::json!(true));
    assert!(result_text(&refused).contains("HTTP 403"), "{refused}");
    let rows = mcp_audit_rows(&f.state).await;
    assert_eq!(
        rows[0].action, "automation.request.forbidden",
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "POST {} tool=lorica_backend_create?backend",
            crate::automation::MCP_PATH
        )
    );
    assert_eq!(
        audit_rows_under(&f.state, "backend.").await.len(),
        management_rows.len(),
        "a refused write landed a management row"
    );
}
