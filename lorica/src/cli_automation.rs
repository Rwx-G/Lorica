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
//!
//! # One minting route
//!
//! [`mint`] is the only place the CLI creates a token, and
//! `lorica mcp token create --tier` (`cli_mcp.rs`) goes through it with
//! a body built by [`mint_request_body`], so a token minted for an MCP
//! tier is the same credential, through the same request, under the
//! same audit row, as one minted here.

use lorica_config::models::{
    validate_automation_grants, AutomationScope, AUTOMATION_TOKEN_SUBJECT,
};

use std::path::Path;

use crate::cli_client::{fail, management_data, management_session};

/// What `lorica automation token create` was asked to mint, one field
/// per flag.
pub(crate) struct TokenMint {
    /// `--name`.
    pub(crate) name: String,
    /// Every `--scope`, as typed.
    pub(crate) scopes: Vec<String>,
    /// Every `--hostname`.
    pub(crate) hostnames: Vec<String>,
    /// Every `--backend-cidr`.
    pub(crate) backend_cidrs: Vec<String>,
    /// `--max-ttl-seconds`.
    pub(crate) max_ttl_seconds: Option<u32>,
    /// `--lifetime-days`.
    pub(crate) lifetime_days: Option<i64>,
}

/// Mint a scoped automation token and print it once on standard
/// output.
pub(crate) fn run_automation_token_create(
    data_dir: &Path,
    management_port: u16,
    request: &TokenMint,
    user: &str,
    password: &str,
) {
    let (stdout, stderr) = mint_token(request, |body| {
        mint(data_dir, management_port, body, user, password)
    })
    .unwrap_or_else(|refused| fail(refused));
    // The only thing on stdout.
    print!("{stdout}");
    eprint!("{stderr}");
}

/// What the command prints on standard output and on standard error,
/// minting through `mint`, apart from the network and the terminal so
/// the split between the two streams can be asserted.
///
/// `mcp token create` mints through this too, with the request its
/// tier resolves to, and appends its blast radius to standard error.
///
/// # Errors
///
/// The grant rule's refusal, in the flags' words, before `mint` runs.
pub(crate) fn mint_token(
    request: &TokenMint,
    mint: impl FnOnce(&serde_json::Value) -> serde_json::Value,
) -> Result<(String, String), String> {
    grants_refusal(&request.scopes, &request.hostnames, &request.backend_cidrs)?;
    let data = mint(&mint_request_body(request));
    Ok((
        format!("{}\n", minted_token(&data)),
        format!("{}\n", minted_notice(&data)),
    ))
}

/// The scopes `spellings` name, or `None` when one is a spelling this
/// build does not know.
pub(crate) fn known_scopes(spellings: &[String]) -> Option<Vec<AutomationScope>> {
    spellings
        .iter()
        .map(|spelling| AutomationScope::from_wire(spelling))
        .collect()
}

/// The model's own grant rule, run before the round trip, and answered
/// in the words of the flags an operator typed.
///
/// Typed absence: the grants are required when a scope they bound is
/// carried and refused when none is. The node applies the same function
/// on the mint, so this only spares a login; a scope spelling the model
/// does not know is left for the node to refuse by name. Both
/// `automation token create` and `mcp token create --tier` answer a
/// grant mistake through this one function, so the two commands, which
/// are one route, answer it alike.
///
/// # Errors
///
/// The model's refusal, with its field names read as the flags.
pub(crate) fn grants_refusal(
    scopes: &[String],
    hostnames: &[String],
    backend_cidrs: &[String],
) -> Result<(), String> {
    match known_scopes(scopes) {
        Some(parsed) => {
            validate_automation_grants(AUTOMATION_TOKEN_SUBJECT, &parsed, hostnames, backend_cidrs)
                .map_err(|refused| {
                    refused
                        .replace("allowed_hostnames", "--hostname")
                        .replace("allowed_backend_cidrs", "--backend-cidr")
                })
        }
        None => Ok(()),
    }
}

/// Log in on the local management API, send one mint request, and
/// answer the mint's `data`, exiting with the node's words on any
/// refusal.
///
/// The one route the CLI mints through: `automation token create` and
/// `mcp token create` both call it.
pub(crate) fn mint(
    data_dir: &Path,
    management_port: u16,
    body: &serde_json::Value,
    user: &str,
    password: &str,
) -> serde_json::Value {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let client = management_session(data_dir, management_port, user, password).await;
        let url = crate::cli_client::management_url(management_port, "/api/v1/automation/tokens");
        let response = client
            .post(&url)
            .json(body)
            .send()
            .await
            .unwrap_or_else(|e| fail(format!("automation token request failed: {e}")));
        management_data(response, "automation token mint").await
    })
}

/// The full token a mint answered, or exit: the mint already happened,
/// and an answer without the token is one nobody can use.
pub(crate) fn minted_token(data: &serde_json::Value) -> &str {
    data.get("token")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| fail("automation token mint: no token in the answer"))
}

/// Turn a mint request into the body the management API accepts.
///
/// Optional fields are OMITTED rather than sent as null: the API's
/// `deny_unknown_fields` body takes an absent field as "use the
/// model's default", and `expires_at` against `lifetime_days` is a
/// mutual exclusion the server refuses. The two grants are sent as
/// given, empty included: an empty list is the typed absence a token
/// carrying no grant-bounded scope must send.
pub(crate) fn mint_request_body(request: &TokenMint) -> serde_json::Value {
    let mut body: serde_json::Value = serde_json::json!({
        "name": request.name,
        "scopes": request.scopes,
        "allowed_hostnames": request.hostnames,
        "allowed_backend_cidrs": request.backend_cidrs,
    });
    if let Some(ttl) = request.max_ttl_seconds {
        body["max_ttl_seconds"] = serde_json::json!(ttl);
    }
    if let Some(days) = request.lifetime_days {
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
pub(crate) fn minted_notice(data: &serde_json::Value) -> String {
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
        let body = mint_request_body(&TokenMint {
            name: "ci".to_string(),
            scopes: vec!["environments:write".to_string()],
            hostnames: vec!["app.example.com".to_string()],
            backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: Some(3600),
            lifetime_days: Some(30),
        });
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
        let body = mint_request_body(&TokenMint {
            name: "ci".to_string(),
            scopes: Vec::new(),
            hostnames: Vec::new(),
            backend_cidrs: Vec::new(),
            max_ttl_seconds: None,
            lifetime_days: None,
        });
        assert!(body.get("max_ttl_seconds").is_none());
        assert!(body.get("lifetime_days").is_none());
        assert_eq!(body["scopes"], serde_json::json!([]));
    }

    #[test]
    fn the_grant_rule_is_the_models_and_an_unknown_scope_is_left_to_the_node() {
        let read = ["logs:read".to_string()];
        let write = ["routes:write".to_string()];
        let host = ["app.example.com".to_string()];
        let cidr = ["10.0.0.0/8".to_string()];
        assert_eq!(grants_refusal(&read, &[], &[]), Ok(()));
        assert!(grants_refusal(&read, &host, &[]).is_err());
        assert!(grants_refusal(&read, &[], &cidr).is_err());
        assert_eq!(grants_refusal(&write, &host, &cidr), Ok(()));
        assert!(grants_refusal(&write, &host, &[]).is_err());
        assert!(grants_refusal(&write, &[], &cidr).is_err());
        assert_eq!(
            grants_refusal(&["dns:write".to_string()], &host, &cidr),
            Ok(()),
            "the node names a scope it does not know; this does not guess"
        );
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
        // The split this command exists to guarantee, on what the
        // command itself produces: `... > /run/secret` must store
        // exactly the credential, with no banner, no newline of advice,
        // no trailing confirmation.
        let request = TokenMint {
            name: "ci".to_string(),
            scopes: vec!["logs:read".to_string()],
            hostnames: Vec::new(),
            backend_cidrs: Vec::new(),
            max_ttl_seconds: None,
            lifetime_days: Some(30),
        };
        let mut sent = None;
        let (stdout, stderr) = mint_token(&request, |body| {
            sent = Some(body.clone());
            answer()
        })
        .expect("a read token takes no grant");
        assert_eq!(stdout, format!("{SECRET}\n"));
        assert!(!stderr.contains(SECRET), "{stderr}");
        assert!(stderr.contains("atk_01HZ"), "{stderr}");
        assert_eq!(sent, Some(mint_request_body(&request)));
    }

    #[test]
    fn a_grant_mistake_is_answered_in_the_flags_words_before_anything_is_sent() {
        let request = TokenMint {
            name: "ci".to_string(),
            scopes: vec!["logs:read".to_string()],
            hostnames: vec!["app.example.com".to_string()],
            backend_cidrs: Vec::new(),
            max_ttl_seconds: None,
            lifetime_days: None,
        };
        let refused = mint_token(&request, |_| {
            panic!("a refused grant must not reach the node")
        })
        .expect_err("a read token takes no grant");
        assert!(refused.contains("--hostname"), "{refused}");
        assert!(!refused.contains("allowed_"), "{refused}");
    }
}
