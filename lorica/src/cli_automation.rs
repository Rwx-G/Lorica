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

//! `lorica automation token create` (Story 10.3 AC #8).
//!
//! Goes through the local management API like `lorica cluster token`
//! does, and for the same reason: the mint is a SuperAdmin operation
//! on a running node, not a database edit.
//!
//! # The secret never reaches argv
//!
//! It is only ever an OUTPUT of this command. Nothing about minting
//! requires the operator to supply a token, so there is nothing to
//! keep off the command line on the way in, and there is deliberately
//! no `--token` flag to add one later: argv is readable through
//! `/proc`, lands in shell history, and is echoed verbatim by CI and
//! by configuration-management `command` modules. The command that
//! CONSUMES a token is the automation's own client, which reads it
//! from a file, standard input or the environment.
//!
//! # Standard output carries the token and nothing else
//!
//! No banner, no confirmation, no trailing advice, so
//! `lorica automation token create ... > /run/secret` and
//! `... | vault kv put ...` both store exactly the credential. The one
//! line naming the `public_id` goes to STDERR, where a pipe never sees
//! it: an operator still learns the id they would revoke, and the
//! redirect stays clean.
//!
//! The server side is symmetric: `automation_tokens.rs` logs and
//! audits the `public_id` only, so nothing on either end of this
//! command writes the secret anywhere but the operator's terminal.

use crate::cli_client::{fail, management_client, management_data, management_login};

/// Mint a scoped automation token and print it once on standard
/// output.
#[allow(clippy::too_many_arguments)] // One parameter per CLI flag; grouping
                                     // them into a struct would put the
                                     // clap definition and its use out of
                                     // step for no reader's benefit.
pub(crate) fn run_automation_token_create(
    management_port: u16,
    name: String,
    scopes: Vec<String>,
    hostnames: Vec<String>,
    backend_cidrs: Vec<String>,
    max_ttl_seconds: Option<u32>,
    lifetime_days: Option<i64>,
    user: String,
    password: String,
) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let client = management_client();
        management_login(&client, management_port, &user, &password).await;
        let url = format!("https://127.0.0.1:{management_port}/api/v1/automation/tokens");
        let body = mint_request_body(
            &name,
            &scopes,
            &hostnames,
            &backend_cidrs,
            max_ttl_seconds,
            lifetime_days,
        );
        let response = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| fail(format!("automation token request failed: {e}")));
        let data = management_data(response, "automation token mint").await;
        let token = data
            .get("token")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| fail("automation token mint: no token in the answer"));

        // The only thing on stdout.
        println!("{token}");
        eprintln!("{}", minted_notice(&data));
    });
}

/// Turn the command's flags into the mint request body.
///
/// Optional fields are OMITTED rather than sent as null: the API's
/// `deny_unknown_fields` body takes an absent field as "use the
/// model's default", and `expires_at` against `lifetime_days` is a
/// mutual exclusion the server refuses.
fn mint_request_body(
    name: &str,
    scopes: &[String],
    hostnames: &[String],
    backend_cidrs: &[String],
    max_ttl_seconds: Option<u32>,
    lifetime_days: Option<i64>,
) -> serde_json::Value {
    let mut body: serde_json::Value = serde_json::json!({
        "name": name,
        "scopes": scopes,
        "allowed_hostnames": hostnames,
        "allowed_backend_cidrs": backend_cidrs,
    });
    if let Some(ttl) = max_ttl_seconds {
        body["max_ttl_seconds"] = serde_json::json!(ttl);
    }
    if let Some(days) = lifetime_days {
        body["lifetime_days"] = serde_json::json!(days);
    }
    body
}

/// The one informational line, for STDERR.
///
/// It names the `public_id` an operator would revoke and when the
/// token expires, and it never carries the secret: stdout is the
/// credential, stderr is the note about it, and a redirect must be
/// able to keep the two apart. A field the answer did not carry
/// prints as `?` rather than failing the mint that already happened;
/// the token is on stdout either way and cannot be minted twice.
fn minted_notice(data: &serde_json::Value) -> String {
    let field = |name: &str| -> String {
        data.get(name)
            .and_then(|value| value.as_str())
            .unwrap_or("?")
            .to_string()
    };
    format!(
        "minted automation token {} (expires {}); it is shown once and cannot be recovered",
        field("public_id"),
        field("expires_at")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "lat_v1_thisisthesecretnobodymayseetwice";

    fn answer() -> serde_json::Value {
        serde_json::json!({
            "public_id": "atk_01HZ",
            "expires_at": "2026-10-01T00:00:00Z",
            "token": SECRET,
        })
    }

    #[test]
    fn the_flags_become_the_body_the_api_accepts() {
        let body = mint_request_body(
            "ci",
            &["environments:write".to_string()],
            &["app.example.com".to_string()],
            &["10.0.0.0/8".to_string()],
            Some(3600),
            Some(30),
        );
        assert_eq!(body["name"], "ci");
        assert_eq!(body["scopes"], serde_json::json!(["environments:write"]));
        assert_eq!(
            body["allowed_hostnames"],
            serde_json::json!(["app.example.com"])
        );
        assert_eq!(
            body["allowed_backend_cidrs"],
            serde_json::json!(["10.0.0.0/8"])
        );
        assert_eq!(body["max_ttl_seconds"], 3600);
        assert_eq!(body["lifetime_days"], 30);
    }

    #[test]
    fn an_unset_flag_is_absent_not_null() {
        // `deny_unknown_fields` reads an absent field as "use the
        // model's default" and a null as a value; sending null would
        // refuse the mint or override a default the operator never
        // touched.
        let body = mint_request_body("ci", &[], &[], &[], None, None);
        assert!(body.get("max_ttl_seconds").is_none());
        assert!(body.get("lifetime_days").is_none());
        assert_eq!(body["scopes"], serde_json::json!([]));
    }

    #[test]
    fn the_notice_names_the_id_and_never_the_secret() {
        let notice = minted_notice(&answer());
        assert!(notice.contains("atk_01HZ"), "{notice}");
        assert!(notice.contains("2026-10-01T00:00:00Z"), "{notice}");
        assert!(
            !notice.contains(SECRET),
            "the informational line must never carry the credential: {notice}"
        );
        // One line, so a terminal shows it as one and a log keeps it
        // as one record.
        assert_eq!(notice.lines().count(), 1);
    }

    #[test]
    fn a_missing_field_degrades_to_a_question_mark() {
        let notice = minted_notice(&serde_json::json!({ "token": SECRET }));
        assert!(notice.contains('?'), "{notice}");
        assert!(!notice.contains(SECRET), "{notice}");
    }

    #[test]
    fn stdout_carries_the_token_and_nothing_else() {
        // The split this command exists to guarantee:
        // `... > /run/secret` must store exactly the credential, with
        // no banner, no newline of advice, no trailing confirmation.
        // stdout is `println!("{token}")`, so what a redirect captures
        // is the token plus one newline.
        let data = answer();
        let token: &str = data
            .get("token")
            .and_then(|value| value.as_str())
            .expect("the answer carries a token");
        let stdout = format!("{token}\n");
        assert_eq!(stdout, format!("{SECRET}\n"));
        assert_eq!(stdout.trim_end_matches('\n'), SECRET);

        let stderr = format!("{}\n", minted_notice(&data));
        assert!(!stderr.contains(SECRET));
        assert!(!stdout.contains("minted automation token"));
    }
}
