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
        // Optional fields are omitted rather than sent as null: the
        // API's `deny_unknown_fields` body takes an absent field as
        // "use the model's default", and `expires_at` against
        // `lifetime_days` is a mutual exclusion the server refuses.
        let mut body = serde_json::json!({
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
        eprintln!(
            "minted automation token {} (expires {}); it is shown once and cannot be recovered",
            data.get("public_id")
                .and_then(|value| value.as_str())
                .unwrap_or("?"),
            data.get("expires_at")
                .and_then(|value| value.as_str())
                .unwrap_or("?")
        );
    });
}
