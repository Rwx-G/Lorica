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
//! - a route's `forward_auth.address`: the URL's userinfo and every
//!   query value, since an authentication endpoint is addressed with
//!   whatever the verifier needs;
//! - a backend's `health_check_path`: every query value;
//! - an access-log row's `path`: every query value and the fragment.
//!
//! The mask applies wherever the automation plane or the MCP server
//! answers such a row: the read listings, and every write answer and
//! preview, including a preview's list of changed fields. The dashboard
//! and the log sinks are unchanged: they sit behind a session or an
//! operator's own export, not behind a model.
//!
//! # What is not masked, and why
//!
//! A route's `response_headers` go to every visitor, `header_rules`
//! match values the config tier itself may write, and `mtls.ca_cert_pem`
//! is a public CA certificate. A WAF event carries no URI and no query
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
    if let Some(forward_auth) = row.get_mut("forward_auth") {
        mask_string(forward_auth, "address", url_secrets);
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
