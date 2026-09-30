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

//! What the automation plane withholds from the management plane's
//! views before a row crosses to a token (fix pass of Story 11.4,
//! 2026-09-30).
//!
//! # Why a second pass over views that are otherwise answered unchanged
//!
//! [`super::read`] answers the management plane's own rows so the two
//! surfaces cannot drift on what a row carries. That property is also
//! how a secret crossed: the management route view carries
//! `proxy_headers` with their values, because the dashboard edits them,
//! and a static header map to the upstream is exactly where an operator
//! puts an upstream credential (`write.rs` refuses a token writing it
//! for that reason). A token reading routes read the credential, and on
//! a hosted model it left the node on the first `lorica_routes` call.
//!
//! So the plane keeps the rows and withholds the VALUES that can carry a
//! credential, replacing each with [`REDACTED`] and keeping every key:
//!
//! - a route's `proxy_headers`: each header's value, names kept;
//! - a route's `header_rules`: each rule's `value`, its header name,
//!   match type and backends kept, since the value a routing rule
//!   matches is where a shared secret between a client and its canary
//!   goes;
//! - a route's `forward_auth.address`: the URL's userinfo and every
//!   query value, since an authentication endpoint is addressed with
//!   whatever the verifier needs;
//! - a backend's `health_check_path`: every query value;
//! - an access-log row's `path`: every query value and the fragment;
//! - a route's or a backend's `managed_by.environment`, unless the
//!   reader may look that environment up
//!   ([`super::environments::environments_visible_to`]).
//!
//! The mask applies wherever the automation plane or the MCP server
//! answers such a row: the read listings, and every write answer and
//! preview, including a preview's list of changed fields. The dashboard
//! and the log sinks are unchanged: they sit behind a session or an
//! operator's own export, not behind a model.
//!
//! # A masked header-rule value may be sent back
//!
//! `header_rules` is a field the config tier writes, and a patch that
//! names it replaces the whole list, so a model that read the rules,
//! changed one backend and wrote the list back would have stored the
//! mask as the match value of every other rule. The write surface
//! therefore reads a rule whose `value` is exactly [`REDACTED`] as
//! "keep the value stored for this rule" ([`restore_header_rule_values`]),
//! and never stores the marker. The rule it keeps the value of is the
//! stored rule at the same position with the same header name (case
//! aside) and the same match type: position alone would hand one
//! rule's secret to a different header after a reorder, and a name
//! alone is ambiguous when two rules test one header. A marker with no
//! such stored rule, on a create, a rule added, moved or retyped, is
//! refused and names the rule by its position, so the caller sends the
//! value itself.
//!
//! # What is not masked, and why
//!
//! A route's `response_headers` go to every visitor, and
//! `mtls.ca_cert_pem` is a public CA certificate. A WAF event carries no URI and no query
//! string, only the span a signature matched, which is the attacker's
//! payload the event exists to show. Basic-auth hashes and certificate
//! key material never enter these views at all.

use axum::Json;
use serde_json::Value;

/// What a withheld value reads as.
pub const REDACTED: &str = "[redacted]";

/// `target` with every query-parameter value replaced by [`REDACTED`],
/// names kept, and any fragment replaced whole.
///
/// Nothing is decoded, so a percent-encoded `&` or `=` inside a value
/// (`%26`, `%3D`) stays inside the value it belongs to and is withheld
/// with it, and malformed percent-encoding cannot fail the mask. A
/// parameter with no `=` (`?flag`) is a name and is kept; a repeated
/// name is masked each time; an empty value is masked too, so the
/// answer does not say which values were empty.
///
/// ```
/// use lorica_api::automation::redact::query_values;
/// assert_eq!(
///     query_values("/reset?token=abc&user=bob#top"),
///     "/reset?token=[redacted]&user=[redacted]#[redacted]"
/// );
/// assert_eq!(query_values("/plain/path"), "/plain/path");
/// ```
pub fn query_values(target: &str) -> String {
    let (before_fragment, fragment) = match target.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (target, None),
    };
    let mut masked = match before_fragment.split_once('?') {
        None => before_fragment.to_string(),
        Some((path, query)) => {
            let parameters: Vec<String> = query
                .split('&')
                .map(|parameter| match parameter.split_once('=') {
                    Some((name, _value)) => format!("{name}={REDACTED}"),
                    None => parameter.to_string(),
                })
                .collect();
            format!("{path}?{}", parameters.join("&"))
        }
    };
    if let Some(fragment) = fragment {
        masked.push('#');
        if !fragment.is_empty() {
            masked.push_str(REDACTED);
        }
    }
    masked
}

/// `url` with its userinfo and every query value withheld.
///
/// The authority is what sits between `://` and the first `/`, `?` or
/// `#`; a `@` inside it separates a userinfo, which is replaced whole.
fn url_secrets(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("{REDACTED}@{host}"),
        None => authority.to_string(),
    };
    let rest = format!("{authority}{}", query_values(tail));
    match scheme {
        Some(scheme) => format!("{scheme}://{rest}"),
        None => rest,
    }
}

/// Replace the string at `row[field]` with `mask` of it, when it is a
/// string.
fn mask_string(row: &mut Value, field: &str, mask: fn(&str) -> String) {
    if let Some(Value::String(text)) = row.get_mut(field) {
        *text = mask(text);
    }
}

/// A route row as the automation plane may answer it.
pub fn route_row(row: &mut Value) {
    if let Some(Value::Object(headers)) = row.get_mut("proxy_headers") {
        for value in headers.values_mut() {
            *value = Value::String(REDACTED.to_string());
        }
    }
    if let Some(Value::Array(rules)) = row.get_mut("header_rules") {
        for rule in rules {
            if let Some(value) = rule.get_mut("value") {
                *value = Value::String(REDACTED.to_string());
            }
        }
    }
    if let Some(forward_auth) = row.get_mut("forward_auth") {
        mask_string(forward_auth, "address", url_secrets);
    }
}

/// `after`'s header rules with every [`REDACTED`] value replaced by the
/// value `before` stores for the same rule: the rule at the same
/// position, testing the same header (case aside) with the same match
/// type. `before` is `None` on a create.
///
/// Run by the route write guard under the store lock, on the row the
/// write replaces, so the value put back is the value stored. The match
/// type is part of the identity because the value is validated against
/// it: a stored exact value kept under a regex rule could be a pattern
/// that does not compile.
///
/// # Errors
///
/// `BadRequest` naming the rule by position for a marker no stored rule
/// answers to; nothing the caller sent is echoed.
pub fn restore_header_rule_values(
    before: Option<&lorica_config::models::Route>,
    after: &mut lorica_config::models::Route,
) -> Result<(), crate::error::ApiError> {
    let stored: &[lorica_config::models::HeaderRule] =
        before.map_or(&[], |route| route.header_rules.as_slice());
    for (position, rule) in after.header_rules.iter_mut().enumerate() {
        if rule.value != REDACTED {
            continue;
        }
        let kept = stored.get(position).filter(|kept| {
            kept.header_name.eq_ignore_ascii_case(&rule.header_name)
                && kept.match_type == rule.match_type
        });
        let Some(kept) = kept else {
            return Err(crate::error::ApiError::BadRequest(format!(
                "header_rules[{position}].value: `{REDACTED}` keeps the value stored for the rule \
                 at the same position with the same header_name and match_type, and this route \
                 stores no such rule there; send the value itself"
            )));
        };
        rule.value = kept.value.clone();
    }
    Ok(())
}

/// The environment `row`'s `managed_by` mark names, when it names one.
pub fn managed_by_environment(row: &Value) -> Option<&str> {
    row.get("managed_by")?.get("environment")?.as_str()
}

/// `row` with the environment its `managed_by` mark names withheld
/// unless it is one of `visible`, the mark itself kept: the row still
/// reads as owned by an environment, which is what tells a model that
/// the management plane refuses it in place, and names none the reader
/// could not look up.
pub fn environment_outside(row: &mut Value, visible: &std::collections::BTreeSet<String>) {
    let foreign = managed_by_environment(row).is_some_and(|name| !visible.contains(name));
    if foreign {
        if let Some(name) = row
            .get_mut("managed_by")
            .and_then(|mark| mark.get_mut("environment"))
        {
            *name = Value::String(REDACTED.to_string());
        }
    }
}

/// A backend row as the automation plane may answer it.
pub fn backend_row(row: &mut Value) {
    mask_string(row, "health_check_path", query_values);
}

/// An access-log row as the automation plane may answer it.
///
/// The proxy records the request path without its query string (it
/// logs `uri.path()`), so on a row the proxy wrote this changes
/// nothing; it is what keeps that true of a row from any other
/// producer, and it is the one place the promise is made.
pub fn access_log_row(row: &mut Value) {
    mask_string(row, "path", query_values);
}

/// A write answer with `row` applied to every row it carries.
///
/// An apply answers the row under `data`. A preview
/// (`crate::preview::previewed`) answers `before` and `after` and the
/// fields that differ as `{ from, to }`, and each side of each change is
/// masked as the field it is, so a value withheld from `after` is not
/// read back out of `changes`.
pub fn write_answer(mut answer: Json<Value>, row: fn(&mut Value)) -> Json<Value> {
    let Some(data) = answer.0.get_mut("data") else {
        return answer;
    };
    if data.get("dry_run") != Some(&Value::Bool(true)) {
        row(data);
        return answer;
    }
    for side in ["before", "after"] {
        if let Some(view) = data.get_mut(side) {
            row(view);
        }
    }
    if let Some(Value::Object(changes)) = data.get_mut("changes") {
        for (field, change) in changes.iter_mut() {
            for end in ["from", "to"] {
                if let Some(value) = change.get_mut(end) {
                    let mut alone =
                        Value::Object(serde_json::Map::from_iter([(field.clone(), value.take())]));
                    row(&mut alone);
                    *value = alone
                        .get_mut(field.as_str())
                        .map(Value::take)
                        .unwrap_or(Value::Null);
                }
            }
        }
    }
    answer
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_query_value_is_withheld_and_its_name_kept_whatever_the_shape() {
        for (target, expected) in [
            ("/p", "/p"),
            ("/p?", "/p?"),
            ("/p?a=1", "/p?a=[redacted]"),
            ("/p?a=", "/p?a=[redacted]"),
            ("/p?=1", "/p?=[redacted]"),
            // A bare name carries no value.
            ("/p?flag", "/p?flag"),
            ("/p?flag&a=1", "/p?flag&a=[redacted]"),
            // Repeated names are each masked.
            ("/p?a=1&a=2", "/p?a=[redacted]&a=[redacted]"),
            // An encoded separator stays inside the value it is in.
            (
                "/p?next=%2Fa%3Fb%3D1%26c%3D2&x=y",
                "/p?next=[redacted]&x=[redacted]",
            ),
            // A second `=` is part of the value.
            ("/p?a=b=c", "/p?a=[redacted]"),
            // Malformed percent-encoding cannot fail a mask that never
            // decodes.
            ("/p?a=%zz%&b=%", "/p?a=[redacted]&b=[redacted]"),
            // An encoded `?` in the path is path, not a query.
            ("/a%3Fb=c", "/a%3Fb=c"),
            // The fragment is withheld whole, wherever the `?` is.
            ("/p?a=1#frag", "/p?a=[redacted]#[redacted]"),
            ("/p#access_token=abc", "/p#[redacted]"),
            ("/p#x?a=1", "/p#[redacted]"),
            ("/p#", "/p#"),
            // Empty segments are kept as they came.
            ("/p?a=1&&b=2", "/p?a=[redacted]&&b=[redacted]"),
        ] {
            assert_eq!(query_values(target), expected, "{target}");
        }
    }

    #[test]
    fn a_url_loses_its_userinfo_and_its_query_values_and_keeps_its_address() {
        for (url, expected) in [
            (
                "https://user:pass@auth.internal:9000/verify?key=abc",
                "https://[redacted]@auth.internal:9000/verify?key=[redacted]",
            ),
            ("http://auth.internal/verify", "http://auth.internal/verify"),
            // An `@` after the authority is path, not userinfo.
            (
                "http://auth.internal/a@b?x=1",
                "http://auth.internal/a@b?x=[redacted]",
            ),
            ("auth.internal:9000?k=v", "auth.internal:9000?k=[redacted]"),
        ] {
            assert_eq!(url_secrets(url), expected, "{url}");
        }
    }

    #[test]
    fn a_route_row_keeps_its_header_names_and_withholds_their_values() {
        let mut row = json!({
            "hostname": "api.example.com",
            "proxy_headers": { "authorization": "Bearer s3cr3t", "x-api-key": "k3y" },
            "response_headers": { "x-frame-options": "DENY" },
            "forward_auth": { "address": "https://u:p@auth.internal/v?t=1", "timeout_ms": 500 },
        });
        route_row(&mut row);
        assert_eq!(
            row["proxy_headers"],
            json!({ "authorization": REDACTED, "x-api-key": REDACTED })
        );
        assert_eq!(row["response_headers"]["x-frame-options"], "DENY");
        assert_eq!(
            row["forward_auth"]["address"],
            "https://[redacted]@auth.internal/v?t=[redacted]"
        );
        assert_eq!(row["forward_auth"]["timeout_ms"], 500);
        assert_eq!(row["hostname"], "api.example.com");

        // A route with none of them is untouched.
        let mut plain = json!({ "hostname": "a", "forward_auth": null, "proxy_headers": {} });
        let before = plain.clone();
        route_row(&mut plain);
        assert_eq!(plain, before);
    }

    #[test]
    fn the_route_tools_spell_the_mask_this_module_answers_with() {
        // `lorica-mcp` cannot depend on this crate, so its prose restates
        // the marker; a model told to send back a different string would
        // have every write-back refused.
        for tool in ["lorica_routes", "lorica_route_update"] {
            let spec = lorica_mcp::tools::find(tool).expect("the tool is in the catalogue");
            assert!(spec.summary.contains(&format!("`{REDACTED}`")), "{tool}");
        }
    }

    #[test]
    fn a_route_row_withholds_each_header_rule_value_and_keeps_the_rest_of_the_rule() {
        let mut row = json!({
            "header_rules": [
                { "header_name": "X-Canary-Key", "match_type": "exact", "value": "s3cr3t", "backend_ids": ["b-1"], "disabled": false },
                { "header_name": "X-Tenant", "match_type": "prefix", "value": "", "backend_ids": [], "disabled": false },
            ],
        });
        route_row(&mut row);
        assert_eq!(row["header_rules"][0]["value"], REDACTED);
        assert_eq!(row["header_rules"][1]["value"], REDACTED);
        assert_eq!(row["header_rules"][0]["header_name"], "X-Canary-Key");
        assert_eq!(row["header_rules"][0]["backend_ids"], json!(["b-1"]));
        assert_eq!(row["header_rules"][1]["match_type"], "prefix");
    }

    fn rule(name: &str, match_type: &str, value: &str) -> lorica_config::models::HeaderRule {
        lorica_config::models::HeaderRule {
            header_name: name.to_string(),
            match_type: match_type.parse().expect("test setup: a match type"),
            value: value.to_string(),
            backend_ids: Vec::new(),
        }
    }

    fn route_with(rules: Vec<lorica_config::models::HeaderRule>) -> lorica_config::models::Route {
        let mut route: lorica_config::models::Route = serde_json::from_value(json!({
            "id": "r-1",
            "hostname": "a.example.com",
            "path_prefix": "/",
            "certificate_id": null,
            "load_balancing": "round_robin",
            "waf_enabled": false,
            "waf_mode": "detection",
            "enabled": true,
            "created_at": "2026-09-30T00:00:00Z",
            "updated_at": "2026-09-30T00:00:00Z",
        }))
        .expect("test setup: a route");
        route.header_rules = rules;
        route
    }

    #[test]
    fn a_masked_header_rule_value_keeps_the_stored_value_of_the_same_rule_and_nothing_else() {
        let stored = route_with(vec![
            rule("X-Canary-Key", "exact", "s3cr3t"),
            rule("X-Tenant", "prefix", "acme-"),
        ]);

        // Sent back as read, a header name in another case included:
        // the stored values come back.
        let mut after = route_with(vec![
            rule("x-canary-key", "exact", REDACTED),
            rule("X-Tenant", "prefix", REDACTED),
        ]);
        restore_header_rule_values(Some(&stored), &mut after).expect("both rules are known");
        assert_eq!(after.header_rules[0].value, "s3cr3t");
        assert_eq!(after.header_rules[1].value, "acme-");

        // A real value is left as sent, beside a kept one.
        let mut after = route_with(vec![
            rule("X-Canary-Key", "exact", "rotated"),
            rule("X-Tenant", "prefix", REDACTED),
        ]);
        restore_header_rule_values(Some(&stored), &mut after).expect("a value and a kept one");
        assert_eq!(after.header_rules[0].value, "rotated");
        assert_eq!(after.header_rules[1].value, "acme-");

        // Every marker no stored rule answers to is refused, by position.
        for (what, rules, position) in [
            (
                "a rule past the stored ones",
                vec![
                    rule("X-Canary-Key", "exact", REDACTED),
                    rule("X-Tenant", "prefix", REDACTED),
                    rule("X-New", "exact", REDACTED),
                ],
                2,
            ),
            (
                "two rules swapped",
                vec![
                    rule("X-Tenant", "prefix", REDACTED),
                    rule("X-Canary-Key", "exact", REDACTED),
                ],
                0,
            ),
            (
                "a match type changed",
                vec![rule("X-Canary-Key", "regex", REDACTED)],
                0,
            ),
        ] {
            let mut after = route_with(rules);
            let refused = restore_header_rule_values(Some(&stored), &mut after).expect_err(what);
            let crate::error::ApiError::BadRequest(message) = refused else {
                panic!("{what}: the refusal is a 400")
            };
            assert!(
                message.contains(&format!("header_rules[{position}]")),
                "{what}: {message}"
            );
            assert!(!message.contains("s3cr3t"), "{what}: {message}");
        }

        // A create has no stored rule at all.
        let mut created = route_with(vec![rule("X-Canary-Key", "exact", REDACTED)]);
        restore_header_rule_values(None, &mut created).expect_err("nothing is stored on a create");
        let mut created = route_with(vec![rule("X-Canary-Key", "exact", "v")]);
        restore_header_rule_values(None, &mut created).expect("a create with values");
    }

    #[test]
    fn a_preview_withholds_the_value_on_both_sides_and_inside_its_changes() {
        let answer = crate::preview::previewed(
            "update",
            Some(json!({ "id": "b-1", "health_check_path": "/h?token=old" })),
            Some(json!({ "id": "b-1", "health_check_path": "/h?token=new" })),
        );
        let masked = write_answer(answer, backend_row).0;
        let text = masked.to_string();
        assert!(!text.contains("old") && !text.contains("new"), "{text}");
        assert_eq!(
            masked["data"]["before"]["health_check_path"],
            "/h?token=[redacted]"
        );
        assert_eq!(
            masked["data"]["after"]["health_check_path"],
            "/h?token=[redacted]"
        );
        assert_eq!(
            masked["data"]["changes"]["health_check_path"],
            json!({ "from": "/h?token=[redacted]", "to": "/h?token=[redacted]" })
        );

        // An apply answers the row under `data`.
        let applied = write_answer(
            crate::error::json_data(json!({ "id": "b-1", "health_check_path": "/h?t=1" })),
            backend_row,
        )
        .0;
        assert_eq!(applied["data"]["health_check_path"], "/h?t=[redacted]");
    }

    #[test]
    fn an_access_log_row_keeps_its_path_and_loses_its_query_values() {
        let mut row = json!({ "path": "/login?password=hunter2", "host": "a.example.com" });
        access_log_row(&mut row);
        assert_eq!(row["path"], "/login?password=[redacted]");
        assert_eq!(row["host"], "a.example.com");
    }
}
