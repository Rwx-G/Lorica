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

//! `lorica mcp token create --tier` (Story 11.4 AC #3).
//!
//! # A front end, not a second way to mint
//!
//! The tier resolves to its scope set through [`Tier::minted_scopes`],
//! which reads the MCP server's own tier table, and the token is minted
//! by [`cli_automation::mint`] with a body [`cli_automation::mint_request_body`]
//! built: the request, the model's validation and the audit row are the
//! ones `lorica automation token create` produces. There is one place a
//! token is born, and one grant rule, [`cli_automation::grants_refusal`],
//! in the flags' words for both commands.
//!
//! # A lifetime by tier
//!
//! With no `--lifetime-days`, the token lives the tier's
//! [`Tier::default_lifetime_days`] (maintainer decision, 2026-09-30):
//! the further a tier reaches, the shorter it lives unattended. The
//! lifetime is always sent, so the node's own year-long default never
//! applies to an MCP token, and it is printed with the blast radius.
//!
//! # What goes where
//!
//! Standard output carries the token and nothing else, exactly as the
//! command it fronts does, so `> /run/secret` still stores exactly the
//! credential. The minted notice and the blast radius go to standard
//! error, beside it on a terminal and out of any redirect.
//!
//! # The blast radius is derived when it is printed
//!
//! [`blast_radius`] reads the tier table, the tool catalogue through
//! [`Tier::registers`] (the rule the server builds its registry with)
//! and, for the admin tier, the automation plane's settings allowlist,
//! at the moment it prints. A scope moved between tiers, a tool added,
//! or a setting added to the allowlist moves the printed text with it.

use std::path::Path;

use lorica_api::automation::write::SETTINGS_ALLOWLIST;
use lorica_mcp::tools::{self, ToolSpec};
use lorica_mcp::Tier;

use crate::cli_automation;
use crate::cli_client::fail;

/// What `lorica mcp token create` was asked to mint.
pub(crate) struct TierMint {
    /// The tier the token serves.
    pub(crate) tier: Tier,
    /// `--name`, or `None` for `mcp-<tier>`.
    pub(crate) name: Option<String>,
    /// Every `--hostname`.
    pub(crate) hostnames: Vec<String>,
    /// Every `--backend-cidr`.
    pub(crate) backend_cidrs: Vec<String>,
    /// `--lifetime-days`, or `None` for the tier's default.
    pub(crate) lifetime_days: Option<i64>,
}

/// Mint a token for the requested tier through the local management
/// API, print it once on standard output, and print what it can do on
/// standard error.
pub(crate) fn run_mcp_token_create(
    data_dir: &Path,
    management_port: u16,
    request: &TierMint,
    user: &str,
    password: &str,
) {
    let (stdout, stderr) = mint_tier(request, |body| {
        cli_automation::mint(data_dir, management_port, body, user, password)
    })
    .unwrap_or_else(|refused| fail(refused));
    // The only thing on stdout.
    print!("{stdout}");
    eprint!("{stderr}");
}

/// What the command prints on standard output and on standard error,
/// minting through `mint`: the grant check, the request body and the
/// split between the two streams, apart from the network and the
/// terminal so they can be asserted.
///
/// # Errors
///
/// The grant rule's refusal, in the flags' words, before `mint` runs.
fn mint_tier(
    request: &TierMint,
    mint: impl FnOnce(&serde_json::Value) -> serde_json::Value,
) -> Result<(String, String), String> {
    let tier = request.tier;
    let lifetime_days = request
        .lifetime_days
        .unwrap_or_else(|| tier.default_lifetime_days());
    let (stdout, mut stderr) = cli_automation::mint_token(&minted_as(request), mint)?;
    stderr.push_str(&blast_radius(
        tier,
        &request.hostnames,
        &request.backend_cidrs,
        lifetime_days,
    ));
    stderr.push('\n');
    Ok((stdout, stderr))
}

/// The `automation token create` request a tier mint is: the tier's
/// scopes, its default label and lifetime where none was named, and
/// never a per-request TTL.
fn minted_as(request: &TierMint) -> cli_automation::TokenMint {
    let tier = request.tier;
    cli_automation::TokenMint {
        name: request.name.clone().unwrap_or_else(|| default_name(tier)),
        scopes: scopes_of(tier),
        hostnames: request.hostnames.clone(),
        backend_cidrs: request.backend_cidrs.clone(),
        max_ttl_seconds: None,
        lifetime_days: Some(
            request
                .lifetime_days
                .unwrap_or_else(|| tier.default_lifetime_days()),
        ),
    }
}

/// The label a token gets when `--name` is not given.
fn default_name(tier: Tier) -> String {
    format!("mcp-{}", tier.as_str())
}

/// The scopes `tier` mints, as the wire spells them.
fn scopes_of(tier: Tier) -> Vec<String> {
    tier.minted_scopes()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// What a token of `tier` can do, for the operator, next to the token.
fn blast_radius(
    tier: Tier,
    hostnames: &[String],
    backend_cidrs: &[String],
    lifetime_days: i64,
) -> String {
    let minted = tier.minted_scopes();
    let reachable: Vec<&ToolSpec> = tools::catalogue()
        .iter()
        .filter(|spec| tier.registers(spec, &minted))
        .collect();
    let mut text = format!(
        "What this {tier} token can do through lorica-mcp.\n  Scopes: {}\n  Lifetime: {lifetime_days} \
         days (this tier's default is {})\n  Tools:\n",
        minted.join(", "),
        tier.default_lifetime_days()
    );
    for spec in &reachable {
        let effect = if spec.changes_nothing() {
            "reads"
        } else {
            "changes"
        };
        text.push_str(&format!(
            "    {} [{}, {effect}] {}\n",
            spec.name, spec.scope, spec.title
        ));
    }
    if reachable.iter().all(|spec| spec.changes_nothing()) {
        text.push_str("  Every tool reads; none changes the node.\n");
    }
    if !hostnames.is_empty() || !backend_cidrs.is_empty() {
        text.push_str(&format!(
            "  Writes only hostnames matching: {}\n  Points backends only inside: {}\n",
            hostnames.join(", "),
            backend_cidrs.join(", ")
        ));
    }
    if reachable.iter().any(|spec| spec.tier == Tier::Admin) {
        text.push_str("  Settings it may change (the automation plane refuses every other key):\n");
        for setting in SETTINGS_ALLOWLIST {
            text.push_str(&format!(
                "    {}: {}, {}, {}\n",
                setting.name,
                setting.bound_text(),
                setting.reach.describe(),
                setting.takes_effect.describe()
            ));
        }
    }
    text.push_str(
        "  One process serves one tier: give lorica-mcp this token alone, and revoke it when \
         the task it was minted for is done.",
    );
    text
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use lorica_config::models::{
        AutomationScope, AutomationToken, AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
    };

    use super::*;

    const SECRET: &str = "lat_v1_thisisthesecretnobodymayseetwice";

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn asked(tier: Tier, hostnames: &[&str], backend_cidrs: &[&str]) -> TierMint {
        TierMint {
            tier,
            name: None,
            hostnames: owned(hostnames),
            backend_cidrs: owned(backend_cidrs),
            lifetime_days: None,
        }
    }

    /// The grants a tier needs to be minted at all.
    fn granted(tier: Tier) -> TierMint {
        let bounded = tier
            .minted_scopes()
            .iter()
            .filter_map(|scope| AutomationScope::from_wire(scope))
            .any(AutomationScope::is_grant_bounded);
        if bounded {
            asked(tier, &["*.app.example.com"], &["10.0.0.0/8"])
        } else {
            asked(tier, &[], &[])
        }
    }

    /// A mint that answers what the node would, and keeps the body it
    /// was sent.
    fn minting(
        sent: &RefCell<Option<serde_json::Value>>,
    ) -> impl FnOnce(&serde_json::Value) -> serde_json::Value + '_ {
        move |body| {
            *sent.borrow_mut() = Some(body.clone());
            serde_json::json!({
                "token": SECRET,
                "public_id": "atk_01HZ",
                "expires_at": "2026-10-01T00:00:00Z",
            })
        }
    }

    #[test]
    fn the_request_is_the_automation_commands_own_with_the_tiers_scopes_and_lifetime() {
        // The thin front end, asserted on what the command sends: the
        // body is the one `automation token create` builds, with the
        // scopes the tier table mints, the tier's default lifetime when
        // none was named, and nothing else chosen here.
        for tier in Tier::ALL {
            let request = granted(tier);
            let sent = RefCell::new(None);
            mint_tier(&request, minting(&sent)).expect("the grants fit the tier");
            let body = sent.into_inner().expect("the mint ran");
            let expected = cli_automation::mint_request_body(&cli_automation::TokenMint {
                name: default_name(tier),
                scopes: scopes_of(tier),
                hostnames: request.hostnames.clone(),
                backend_cidrs: request.backend_cidrs.clone(),
                max_ttl_seconds: None,
                lifetime_days: Some(tier.default_lifetime_days()),
            });
            assert_eq!(body, expected, "{tier}");
            assert!(body.get("max_ttl_seconds").is_none());
        }
        // A named lifetime and a named label win over the defaults.
        let request = TierMint {
            lifetime_days: Some(3),
            name: Some("mcp-for-the-migration".to_string()),
            ..granted(Tier::Read)
        };
        let sent = RefCell::new(None);
        mint_tier(&request, minting(&sent)).expect("read takes no grant");
        let body = sent.into_inner().expect("the mint ran");
        assert_eq!(body["lifetime_days"], 3);
        assert_eq!(body["name"], "mcp-for-the-migration");
    }

    #[test]
    fn stdout_carries_the_token_alone_and_stderr_everything_else() {
        for tier in Tier::ALL {
            let sent = RefCell::new(None);
            let (stdout, stderr) =
                mint_tier(&granted(tier), minting(&sent)).expect("the grants fit the tier");
            assert_eq!(stdout, format!("{SECRET}\n"), "{tier}");
            assert!(!stderr.contains(SECRET), "{tier}: {stderr}");
            assert!(stderr.contains("atk_01HZ"), "{tier}: {stderr}");
            assert!(stderr.contains(&tier.to_string()), "{tier}: {stderr}");
        }
    }

    #[test]
    fn the_grants_are_required_for_a_bounded_tier_and_refused_for_the_others() {
        for tier in Tier::ALL {
            let bounded = !granted(tier).hostnames.is_empty();
            let never = |_: &serde_json::Value| -> serde_json::Value {
                panic!("a refused grant must not reach the node")
            };
            let refused = |hostnames: &[&str], cidrs: &[&str]| {
                mint_tier(&asked(tier, hostnames, cidrs), never).expect_err("refused")
            };
            if bounded {
                for message in [
                    refused(&["*.app.example.com"], &[]),
                    refused(&[], &["10.0.0.0/8"]),
                    refused(&[], &[]),
                    // The model's shape rule still applies to them.
                    refused(&["*"], &["10.0.0.0/8"]),
                ] {
                    // In the flags' words, never the model's field names.
                    assert!(!message.contains("allowed_"), "{tier}: {message}");
                }
            } else {
                for message in [
                    refused(&["*.app.example.com"], &[]),
                    refused(&[], &["10.0.0.0/8"]),
                ] {
                    assert!(
                        message.contains("--hostname") || message.contains("--backend-cidr"),
                        "{tier}: {message}"
                    );
                }
            }
        }
        // The config tier is the bounded one, which is what the story
        // asks of `--tier config`.
        assert!(!granted(Tier::Config).hostnames.is_empty());
        assert!(granted(Tier::Read).hostnames.is_empty());
        assert!(granted(Tier::Admin).hostnames.is_empty());
    }

    #[test]
    fn every_tier_mints_by_default_a_token_the_node_accepts() {
        // The node's validator is the authority on lifetimes (the
        // settings:write ceiling included); the tier table's defaults
        // are held to it here, on the token the command would mint.
        let created_at = chrono::Utc::now();
        for tier in Tier::ALL {
            let request = granted(tier);
            let token = AutomationToken {
                public_id: "0123456789abcdef01234567".to_string(),
                name: default_name(tier),
                secret_hmac: String::new(),
                scopes: tier
                    .minted_scopes()
                    .iter()
                    .map(|scope| AutomationScope::from_wire(scope).expect("a known scope"))
                    .collect(),
                allowed_hostnames: request.hostnames.clone(),
                allowed_backend_cidrs: request.backend_cidrs.clone(),
                max_ttl_seconds: AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS,
                created_by: "admin".to_string(),
                created_at,
                expires_at: created_at + chrono::Duration::days(tier.default_lifetime_days()),
                last_used_at: None,
                revoked_at: None,
            };
            token
                .validate()
                .unwrap_or_else(|refused| panic!("{tier}: {refused}"));
        }
    }

    #[test]
    fn the_blast_radius_names_every_scope_and_tool_the_tier_reaches_and_nothing_else() {
        for tier in Tier::ALL {
            let minted = tier.minted_scopes();
            let text = blast_radius(tier, &[], &[], tier.default_lifetime_days());
            // The `Scopes:` line is what the e2e smoke compares the
            // stored token against, so its shape is pinned here.
            assert!(
                text.lines()
                    .any(|line| line == format!("  Scopes: {}", minted.join(", "))),
                "{tier}\n{text}"
            );
            assert!(
                text.contains(&format!(
                    "  Lifetime: {} days",
                    tier.default_lifetime_days()
                )),
                "{tier}\n{text}"
            );
            for spec in tools::catalogue() {
                assert_eq!(
                    text.contains(&format!("    {} [", spec.name)),
                    tier.registers(spec, &minted),
                    "{tier}: {}\n{text}",
                    spec.name
                );
            }
            assert!(text.contains(&tier.to_string()), "{text}");
        }
    }

    #[test]
    fn the_blast_radius_is_what_the_server_registers_for_that_token() {
        // The printed list against the server's own registry for a
        // token carrying exactly the minted scopes, so the two cannot
        // describe different tool sets.
        for tier in Tier::ALL {
            let server = lorica_mcp::McpServer::over(lorica_mcp::Identity {
                public_id: "0123456789abcdef01234567".to_string(),
                scopes: scopes_of(tier),
            })
            .expect("a minted tier resolves to itself");
            let text = blast_radius(tier, &[], &[], tier.default_lifetime_days());
            let printed: Vec<&str> = text
                .lines()
                .filter_map(|line| line.strip_prefix("    "))
                .filter_map(|line| line.split_once(" [").map(|(name, _)| name))
                .filter(|name| name.starts_with("lorica_"))
                .collect();
            let registered: Vec<&str> = server.tools().iter().map(|spec| spec.name).collect();
            assert_eq!(printed, registered, "{tier}");
        }
    }

    #[test]
    fn the_admin_blast_radius_lists_the_allowlist_with_its_bounds_and_the_read_tier_changes_nothing(
    ) {
        let admin = blast_radius(Tier::Admin, &[], &[], 1);
        assert!(!SETTINGS_ALLOWLIST.is_empty());
        for setting in SETTINGS_ALLOWLIST {
            assert!(
                admin.contains(&format!(
                    "{}: {}, {}, {}",
                    setting.name,
                    setting.bound_text(),
                    setting.reach.describe(),
                    setting.takes_effect.describe()
                )),
                "{}\n{admin}",
                setting.name
            );
        }
        for tier in [Tier::Read, Tier::Config] {
            let text = blast_radius(tier, &[], &[], 1);
            for setting in SETTINGS_ALLOWLIST {
                assert!(!text.contains(setting.name), "{tier}: {}", setting.name);
            }
        }
        assert!(blast_radius(Tier::Read, &[], &[], 1).contains("none changes the node"));
        assert!(!blast_radius(Tier::Config, &[], &[], 1).contains("none changes the node"));
    }

    #[test]
    fn the_config_blast_radius_names_the_grants_it_was_minted_with() {
        let text = blast_radius(
            Tier::Config,
            &owned(&["*.app.example.com"]),
            &owned(&["10.0.0.0/8"]),
            7,
        );
        assert!(text.contains("*.app.example.com"), "{text}");
        assert!(text.contains("10.0.0.0/8"), "{text}");
    }
}
