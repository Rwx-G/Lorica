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

//! The admin tier (Story 11.3), through the real automation router and
//! the MCP binding: the settings allowlist, its bounds, the write budget,
//! and the identity and fleet paths no token reaches.

use crate::automation::test_support::{
    a_node_with_something_to_write, allowlisted_settings, assert_forbidden_naming,
    assert_no_secret_field_name, audit_rows_under, automation_call, canonical_now, data_keys,
    mcp_call, mcp_post, mint_automation, WriteFixture,
};
use crate::server::AppState;
use crate::tests::{body_json, parse_data, send};
use axum::http::StatusCode;

// ---- Story 11.3: the admin tier ----

/// A token carrying `scopes` on the write fixture's node, as its
/// `Bearer` header and its lookup half.
async fn a_token_carrying(
    f: &WriteFixture,
    name: &str,
    scopes: Vec<lorica_config::models::AutomationScope>,
) -> (String, String) {
    let token = mint_automation(
        &f.state,
        name,
        scopes,
        &["*.write.example.com"],
        chrono::Utc::now() + chrono::Duration::days(30),
        None,
    )
    .await;
    let public_id = token
        .split('.')
        .next()
        .expect("token has two halves")
        .to_string();
    (format!("Bearer {token}"), public_id)
}

/// A token carrying `settings:write` and nothing else, on the write
/// fixture's node, as its `Bearer` header and its lookup half.
async fn an_admin_tier_token(f: &WriteFixture) -> (String, String) {
    a_token_carrying(
        f,
        "admin-tier",
        vec![lorica_config::models::AutomationScope::SettingsWrite],
    )
    .await
}

/// The stored settings document.
async fn stored_settings(state: &AppState) -> lorica_config::models::GlobalSettings {
    let store = state.store.lock().await;
    store.get_global_settings().expect("settings")
}

#[tokio::test]
async fn the_admin_tier_changes_an_allowlisted_setting_as_the_dashboard_would_and_names_what_moved()
{
    // AC #1 and AC #4. The write lands through the dashboard's own
    // function, the answer is the allowlisted part of the document and
    // nothing else, and the `settings.update` row names the token and
    // each key the write changed with its value before and after; a key
    // sent with its current value is not one that changed.
    let f = a_node_with_something_to_write().await;
    let (bearer, public_id) = an_admin_tier_token(&f).await;
    let before = stored_settings(&f.state).await;
    let threshold = before.waf_ban_threshold + 1;
    let retention = before.waf_event_retention * 2;

    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/settings",
        &bearer,
        Some(serde_json::json!({
            "waf_ban_threshold": threshold,
            "waf_event_retention": retention,
            "cert_warning_days": before.cert_warning_days,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let answered = parse_data(response).await;
    assert_eq!(data_keys(&answered), allowlisted_settings());
    assert_eq!(answered["waf_ban_threshold"], serde_json::json!(threshold));
    assert_eq!(
        answered["waf_event_retention"],
        serde_json::json!(retention)
    );
    assert_no_secret_field_name(&answered, "PUT /automation/v1/settings");

    let stored = stored_settings(&f.state).await;
    assert_eq!(stored.waf_ban_threshold, threshold);
    assert_eq!(stored.waf_event_retention, retention);

    let rows = audit_rows_under(&f.state, "settings.update").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].operator_role, "automation");
    assert!(
        rows[0].operator_username.contains(&public_id),
        "{:?}",
        rows[0]
    );
    assert_eq!(
        rows[0].target_id,
        format!(
            "waf_ban_threshold:{}->{threshold},waf_event_retention:{}->{retention}",
            before.waf_ban_threshold, before.waf_event_retention
        )
    );

    // AC #3: the dashboard undoes it, through its own path, the lowered
    // retention included, and its row names the keys it moved and none
    // of their values: the dashboard's write reaches secrets.
    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        "/api/v1/settings",
        &f.admin,
        Some(serde_json::json!({
            "waf_ban_threshold": before.waf_ban_threshold,
            "waf_event_retention": before.waf_event_retention,
        })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let restored = stored_settings(&f.state).await;
    assert_eq!(restored.waf_ban_threshold, before.waf_ban_threshold);
    assert_eq!(restored.waf_event_retention, before.waf_event_retention);
    let rows = audit_rows_under(&f.state, "settings.update").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        rows[0].target_id, "waf_ban_threshold,waf_event_retention",
        "{:?}",
        rows[0]
    );
    assert_ne!(rows[0].operator_role, "automation");
}

#[tokio::test]
async fn a_value_outside_the_tiers_bound_is_refused_naming_the_key_and_nothing_is_written() {
    // Decision A of 2026-09-28: each key moves only inside its bound and
    // in its safe direction. Just past each end of every entry's bound
    // is refused; where the dashboard's own validator would accept the
    // value, the refusal is the tier's, a 422 naming the key and the
    // bound. A retention lowered is refused even inside the bound.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let stored = serde_json::to_value(stored_settings(&f.state).await).expect("settings");
    let shared = crate::settings::settings_schema();

    for setting in crate::automation::write::SETTINGS_ALLOWLIST {
        for value in [setting.min - 1, setting.max + 1] {
            let inside_the_dashboards = shared[setting.name]["min"]
                .as_i64()
                .is_none_or(|min| value >= min)
                && shared[setting.name]["max"]
                    .as_i64()
                    .is_none_or(|max| value <= max);
            let response = automation_call(
                &f.state,
                "PUT",
                "/automation/v1/settings",
                &bearer,
                Some(serde_json::json!({ setting.name: value })),
            )
            .await;
            let status = response.status();
            let refusal = body_json(response).await;
            let what = format!("{}={value}", setting.name);
            if inside_the_dashboards {
                assert_eq!(
                    status,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{what}: {refusal}"
                );
                let message = refusal["error"]["message"].as_str().unwrap_or_default();
                assert!(
                    message.contains(setting.name) && message.contains(&setting.bound_text()),
                    "{what}: {refusal}"
                );
            } else {
                assert!(status.is_client_error(), "{what}: {status} {refusal}");
            }
        }
        if setting.direction == crate::automation::write::Direction::RaiseOnly {
            let current = stored[setting.name].as_i64().expect("an integer setting");
            let lowered = current - 1;
            assert!(
                lowered >= setting.min,
                "{} is stored at its floor",
                setting.name
            );
            let response = automation_call(
                &f.state,
                "PUT",
                "/automation/v1/settings",
                &bearer,
                Some(serde_json::json!({ setting.name: lowered })),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{} lowered",
                setting.name
            );
            let refusal = body_json(response).await;
            assert!(
                refusal["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("below the stored")),
                "{refusal}"
            );
        }
    }
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused settings write changed the store"
    );
    assert!(audit_rows_under(&f.state, "settings.").await.is_empty());
}

#[tokio::test]
async fn a_write_that_changes_nothing_writes_nothing_on_either_plane() {
    // An empty body, or one repeating the stored values, is answered
    // with the document as it stands and lands no `settings.update`
    // row, from a token or from the dashboard: nothing moved, so there
    // is nothing to reload and nothing to attribute.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    let stored = stored_settings(&f.state).await;
    for body in [
        serde_json::json!({}),
        serde_json::json!({ "cert_warning_days": stored.cert_warning_days }),
    ] {
        let response = automation_call(
            &f.state,
            "PUT",
            "/automation/v1/settings",
            &bearer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{body}");
        let answered = parse_data(response).await;
        assert_eq!(
            answered["cert_warning_days"],
            serde_json::json!(stored.cert_warning_days)
        );
        let response = send(
            &f.state,
            &f.session_store,
            &f.rate_limiter,
            "PUT",
            "/api/v1/settings",
            &f.admin,
            Some(body.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{body}");
    }
    assert!(audit_rows_under(&f.state, "settings.").await.is_empty());
}

#[tokio::test]
async fn a_broken_sink_the_patch_does_not_touch_neither_refuses_nor_describes_itself() {
    // The syslog TLS connector is built only when the patch names a
    // `syslog_*` field. A stored sink the admin tier cannot see or fix
    // neither refuses its write nor answers it with a description of
    // that sink; the dashboard writing a sink field still meets the
    // check.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    {
        let store = f.state.store.lock().await;
        let mut settings = store.get_global_settings().expect("settings");
        settings.syslog_endpoint = Some("192.0.2.10:6514".to_string());
        settings.syslog_transport = "tcp-tls".to_string();
        settings.syslog_tls_ca_pem = Some("no certificate here".to_string());
        store.update_global_settings(&settings).expect("stored");
    }
    let raised = stored_settings(&f.state).await.cert_warning_days + 1;
    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/settings",
        &bearer,
        Some(serde_json::json!({ "cert_warning_days": raised })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let answered = body_json(response).await.to_string();
    assert!(!answered.contains("CA PEM"), "{answered}");
    assert_eq!(stored_settings(&f.state).await.cert_warning_days, raised);

    let response = send(
        &f.state,
        &f.session_store,
        &f.rate_limiter,
        "PUT",
        "/api/v1/settings",
        &f.admin,
        Some(serde_json::json!({ "syslog_transport": "tcp-tls" })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_credential_that_spends_its_write_window_is_refused_and_another_is_not() {
    // The plane budgets its own writes per credential: past the
    // dashboard's own settings figure a token's settings write answers
    // 429 with `Retry-After`, and a second token's window is its own.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    for n in 0..crate::server::RL_SETTINGS_UPDATE {
        let response = automation_call(
            &f.state,
            "PUT",
            "/automation/v1/settings",
            &bearer,
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "write {n}");
    }
    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/settings",
        &bearer,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.headers().get(http::header::RETRY_AFTER).is_some(),
        "a 429 without Retry-After"
    );
    let (other, _public_id) = a_token_carrying(
        &f,
        "admin-tier-2",
        vec![lorica_config::models::AutomationScope::SettingsWrite],
    )
    .await;
    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/settings",
        &other,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_key_outside_the_allowlist_is_refused_by_the_plane_whoever_sends_it() {
    // The allowlist binds at the plane, not in the tool schema: a token
    // holding every scope there is, calling the path directly with no
    // tool in between, is refused on a key outside it, with the key
    // named, and nothing is written. Every key of the settings document
    // outside the allowlist is walked, derived from the document. The
    // sweep sends more writes than one credential's window holds, so it
    // changes credential each time the window would be spent.
    let f = a_node_with_something_to_write().await;
    let before = canonical_now(&f.state).await;
    let before_bytes = lorica_config::canonical::encode_canonical(&before).expect("encodes");
    let document =
        serde_json::to_value(lorica_config::models::GlobalSettings::default()).expect("settings");
    let allowed = allowlisted_settings();
    let inside = allowed.first().expect("an allowlisted key").clone();
    let mut refused = 0usize;
    let mut bearer = f.bearer.clone();
    for key in document.as_object().expect("an object").keys() {
        if allowed.contains(key) {
            continue;
        }
        if refused > 0 && refused.is_multiple_of(crate::server::RL_SETTINGS_UPDATE as usize) {
            bearer = a_token_carrying(
                &f,
                &format!("every-scope-{refused}"),
                lorica_config::models::AutomationScope::ALL.to_vec(),
            )
            .await
            .0;
        }
        refused += 1;
        let response = automation_call(
            &f.state,
            "PUT",
            "/automation/v1/settings",
            &bearer,
            Some(serde_json::json!({ inside.clone(): null, key.clone(): null })),
        )
        .await;
        assert_forbidden_naming(response, &format!("`{key}`"), key).await;
    }
    assert_eq!(
        refused + allowed.len(),
        document.as_object().expect("an object").len()
    );
    let after = canonical_now(&f.state).await;
    assert_eq!(
        before_bytes,
        lorica_config::canonical::encode_canonical(&after).expect("encodes"),
        "a refused settings write changed the store"
    );
    assert!(audit_rows_under(&f.state, "settings.").await.is_empty());
}

#[tokio::test]
async fn the_admin_tier_previews_what_it_writes_and_nothing_else() {
    // The preview needs no read scope beside `settings:write`, and that
    // holds because it answers only the allowlisted keys: the listener
    // addresses, the sink destinations and the masked secrets of the
    // settings document are in neither view.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    let stored = stored_settings(&f.state).await;
    let lowered = stored.cert_warning_days - 1;
    let response = automation_call(
        &f.state,
        "PUT",
        "/automation/v1/settings?dry_run=true",
        &bearer,
        Some(serde_json::json!({ "cert_warning_days": lowered })),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let change = parse_data(response).await;
    assert_eq!(change["dry_run"], serde_json::json!(true));
    assert_eq!(change["operation"], serde_json::json!("update"));
    assert_eq!(data_keys(&change["before"]), allowlisted_settings());
    assert_eq!(data_keys(&change["after"]), allowlisted_settings());
    assert_eq!(
        change["after"]["cert_warning_days"],
        serde_json::json!(lowered)
    );
    assert_eq!(
        change["changes"]["cert_warning_days"]["to"],
        serde_json::json!(lowered)
    );
    assert_eq!(
        stored_settings(&f.state).await.cert_warning_days,
        stored.cert_warning_days,
        "a dry run wrote the setting"
    );
    assert!(audit_rows_under(&f.state, "settings.").await.is_empty());

    // The tier's bound refuses a preview as it refuses the apply, and
    // so does the dashboard's own cross-field rule.
    for (body, refused) in [
        (
            serde_json::json!({ "cert_warning_days": 5 }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            serde_json::json!({ "cert_critical_days": stored.cert_warning_days }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = automation_call(
            &f.state,
            "PUT",
            "/automation/v1/settings?dry_run=true",
            &bearer,
            Some(body.clone()),
        )
        .await;
        assert_eq!(response.status(), refused, "{body}");
    }
}

#[tokio::test]
async fn an_admin_tier_token_lists_the_settings_tools_and_nothing_else() {
    // IV1 through the whole stack: a token carrying the admin tier's
    // scope is offered exactly the tools that sit behind it, derived
    // from the catalogue, and those tools offer exactly the keys the
    // plane's allowlist names.
    let f = a_node_with_something_to_write().await;
    let (bearer, _public_id) = an_admin_tier_token(&f).await;
    let list = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let listed = body_json(mcp_post(&f.state, &bearer, &list).await).await;
    let mut offered: Vec<String> = listed["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_string())
        .collect();
    offered.sort_unstable();
    let mut behind_the_scope: Vec<String> = lorica_mcp::tools::catalogue()
        .iter()
        .filter(|spec| spec.scope == lorica_config::models::AutomationScope::SettingsWrite)
        .map(|spec| spec.name.to_string())
        .collect();
    behind_the_scope.sort_unstable();
    assert!(!behind_the_scope.is_empty());
    assert_eq!(offered, behind_the_scope);
    for name in &offered {
        let spec = lorica_mcp::tools::find(name).expect("a listed tool is catalogued");
        let mut fields: Vec<String> = spec
            .body()
            .map(|body| body.fields.iter().map(|f| (*f).to_string()).collect())
            .unwrap_or_default();
        fields.sort_unstable();
        assert_eq!(fields, allowlisted_settings(), "{name}");
    }

    // The preview and the apply both reach the plane in process.
    let before = stored_settings(&f.state).await.cert_warning_days;
    let raised = before + 1;
    let previewed = mcp_call(
        &f.state,
        &bearer,
        "lorica_settings_update_preview",
        serde_json::json!({ "settings": { "cert_warning_days": raised } }),
    )
    .await;
    assert_eq!(
        previewed["result"]["isError"],
        serde_json::json!(false),
        "{previewed}"
    );
    let applied = mcp_call(
        &f.state,
        &bearer,
        "lorica_settings_update",
        serde_json::json!({ "settings": { "cert_warning_days": raised } }),
    )
    .await;
    assert_eq!(
        applied["result"]["isError"],
        serde_json::json!(false),
        "{applied}"
    );
    assert_eq!(stored_settings(&f.state).await.cert_warning_days, raised);
    let rows = audit_rows_under(&f.state, "settings.update").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].target_id,
        format!("cert_warning_days:{before}->{raised}")
    );
}

#[tokio::test]
async fn identity_and_fleet_paths_are_refused_at_the_scope_gate_for_every_token() {
    // AC #2 and IV2 through the listener: users, the automation tokens
    // and OIDC issuers, the cluster's nodes, enrolment tokens and
    // fleet bans, `leave` and break-glass are refused by the scope gate,
    // with the undeclared-path refusal, for the admin tier's token and
    // for a token carrying every scope. The derived sweep over the
    // management route table is `tests/admin_tier.rs`; this proves what
    // a caller meets.
    let f = a_node_with_something_to_write().await;
    let (admin_bearer, _public_id) = an_admin_tier_token(&f).await;
    for bearer in [admin_bearer.as_str(), f.bearer.as_str()] {
        for (method, path) in [
            ("GET", "/automation/v1/users"),
            ("POST", "/automation/v1/users"),
            ("PUT", "/automation/v1/users/u-1"),
            ("DELETE", "/automation/v1/users/u-1"),
            ("PUT", "/automation/v1/auth/password"),
            ("POST", "/automation/v1/automation/tokens"),
            ("DELETE", "/automation/v1/automation/tokens/t-1"),
            ("POST", "/automation/v1/automation/oidc-issuers"),
            ("DELETE", "/automation/v1/automation/oidc-issuers/i-1"),
            ("POST", "/automation/v1/cluster/tokens"),
            ("DELETE", "/automation/v1/cluster/nodes/n-1"),
            ("POST", "/automation/v1/cluster/nodes/n-1/activate"),
            ("POST", "/automation/v1/cluster/bans"),
            ("POST", "/automation/v1/cluster/break-glass"),
            ("POST", "/automation/v1/cluster/leave"),
            ("GET", "/automation/v1/settings"),
        ] {
            let body = (method != "GET" && method != "DELETE").then(|| serde_json::json!({}));
            let response = automation_call(&f.state, method, path, bearer, body).await;
            assert_forbidden_naming(
                response,
                "declares no automation scope",
                &format!("{method} {path}"),
            )
            .await;
        }
    }
}
