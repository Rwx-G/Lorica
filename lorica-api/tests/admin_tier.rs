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

//! Story 11.3's two integration verifications, asserted on the two
//! tables that decide them rather than described.
//!
//! IV1: the admin tier's tool list matches the allowlist exactly. The
//! tier is the tools a token carrying `settings:write` registers, and
//! what those tools can change is the union of their body vocabularies;
//! both are read off `lorica_mcp`, the allowlist off
//! `lorica_api::automation::write::SETTINGS_ALLOWLIST`, and nothing is
//! typed a second time here.
//!
//! IV2 and AC #2: a user-management or cluster-membership operation
//! fails at the scope check, not at a tool that exists and refuses. The
//! operations are read off the management plane's own route table, so a
//! path added there under one of these families is swept the day it
//! lands, and each is mirrored onto the automation plane and asked of
//! the scope matrix for every verb: the answer must be "declared for
//! nobody", which the gate turns into a 403 for every token, the widest
//! included. No MCP tool calls one of them either.

use std::collections::BTreeSet;

use lorica_api::automation::required_scope;
use lorica_api::automation::write::{AdminSetting, Reach, TakesEffect, SETTINGS_ALLOWLIST};
use lorica_config::models::AutomationScope;
use lorica_mcp::server::{Identity, McpServer};
use lorica_mcp::tools::{catalogue, ToolSpec};
use lorica_mcp::Tier;

/// The management route table, read as source.
const MANAGEMENT_ROUTES: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server.rs"));

/// The automation plane's route table, read as source.
const AUTOMATION_ROUTES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/automation/router.rs"
));

/// The families of management operations no automation token may reach
/// through any tier (Story 11.3 AC #1 and AC #2, Story 9.9): identity
/// (users, the session and password operations), the credentials that
/// grant automation access (the static tokens and the OIDC issuer
/// entries), and the fleet (nodes, enrolment tokens, fleet-wide bans,
/// `leave`, break-glass).
///
/// Families and not paths: every path the management plane mounts under
/// one of these prefixes is swept, whatever it is called, and every
/// path the automation plane mounts is swept against them too.
const HUMAN_ONLY_FAMILIES: &[&str] = &[
    "/api/v1/users",
    "/api/v1/auth",
    "/api/v1/automation/tokens",
    "/api/v1/automation/oidc-issuers",
    "/api/v1/cluster/nodes",
    "/api/v1/cluster/tokens",
    "/api/v1/cluster/bans",
    "/api/v1/cluster/leave",
    "/api/v1/cluster/break-glass",
];

const EVERY_VERB: [http::Method; 5] = [
    http::Method::GET,
    http::Method::POST,
    http::Method::PUT,
    http::Method::DELETE,
    http::Method::PATCH,
];

/// Every string literal in `source` that opens with `"<prefix>`.
///
/// Anchored on the opening quote and the prefix together, and read to
/// the next quote, so a stray quote elsewhere in the file (a comment,
/// a char literal) cannot shift which segments count as literals. Each
/// literal read must look like a route path; one that does not means
/// the scan is reading something else and the test says so.
fn path_literals(source: &str, prefix: &str) -> BTreeSet<String> {
    let opening = format!("\"{prefix}");
    let mut paths = BTreeSet::new();
    for (at, _) in source.match_indices(&opening) {
        let literal = &source[at + 1..];
        let end = literal
            .find('"')
            .unwrap_or_else(|| panic!("an unterminated literal opens at byte {at}"));
        let path = &literal[..end];
        assert!(
            path.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/-_{}".contains(&b)),
            "{path:?} was read as a route path and is not shaped like one"
        );
        paths.insert(path.to_string());
    }
    paths
}

/// Every `/api/v1/...` string literal in the management route table.
fn management_paths() -> BTreeSet<String> {
    let paths = path_literals(MANAGEMENT_ROUTES, "/api/v1/");
    // A floor, not a count: the management plane mounts well over a
    // hundred paths, and a scan that finds a handful has gone blind
    // without any family noticing.
    assert!(
        paths.len() >= 50,
        "only {} management paths read off src/server.rs",
        paths.len()
    );
    paths
}

/// Every `/automation/v1/...` string literal in the automation route
/// table.
fn automation_paths() -> BTreeSet<String> {
    let paths = path_literals(AUTOMATION_ROUTES, "/automation/v1/");
    assert!(
        paths.len() >= 10,
        "only {} automation paths read off src/automation/router.rs",
        paths.len()
    );
    paths
}

/// `path` with each `{parameter}` given a concrete one-segment value.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "x-1"
            } else {
                segment
            }
        })
        .collect::<Vec<&str>>()
        .join("/")
}

/// A management path as the automation plane would spell it, with each
/// `{parameter}` given a concrete one-segment value.
fn mirrored(management_path: &str) -> String {
    let rest = management_path
        .strip_prefix("/api/v1")
        .expect("a management path");
    format!("/automation/v1{}", concrete(rest))
}

/// The path a tool calls, built by the tool itself, without its query.
fn path_of(spec: &ToolSpec) -> String {
    let mut arguments = serde_json::Map::new();
    if let Some(param) = spec.resource {
        arguments.insert(param.name.to_string(), serde_json::json!("x-1"));
    }
    if let Some(body) = spec.body() {
        arguments.insert(body.argument.to_string(), serde_json::json!({}));
    }
    let call = spec
        .call_for(&serde_json::Value::Object(arguments))
        .unwrap_or_else(|refused| panic!("{} builds no call: {}", spec.name, refused.message));
    call.path
        .split_once('?')
        .map_or(call.path.clone(), |(path, _)| path.to_string())
}

/// How the enum spells a scope.
fn wire(scope: AutomationScope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .expect("a scope serialises to a string")
}

/// A server over a token carrying exactly `scopes`, which must be one
/// tier's.
fn server_carrying(scopes: &[AutomationScope]) -> McpServer {
    McpServer::over(Identity {
        public_id: "0123456789abcdef01234567".to_string(),
        scopes: scopes.iter().copied().map(wire).collect(),
    })
    .unwrap_or_else(|refused| panic!("test setup: {refused}"))
}

#[test]
fn iv1_the_admin_tiers_tools_change_exactly_the_allowlist() {
    let allowlist: BTreeSet<String> = SETTINGS_ALLOWLIST
        .iter()
        .map(|setting| setting.name.to_string())
        .collect();
    assert!(!allowlist.is_empty(), "SETTINGS_ALLOWLIST is empty");
    assert_eq!(
        allowlist.len(),
        SETTINGS_ALLOWLIST.len(),
        "SETTINGS_ALLOWLIST names a setting twice"
    );

    let server = server_carrying(&[AutomationScope::SettingsWrite]);
    let registered: &[&ToolSpec] = server.tools();
    assert_eq!(server.tier(), Tier::Admin);

    // Exactly the catalogue's tools behind the scope, and each of them
    // is a mutation or its preview on the settings path.
    let behind_the_scope: BTreeSet<&str> = catalogue()
        .iter()
        .filter(|spec| spec.scope == wire(AutomationScope::SettingsWrite))
        .map(|spec| spec.name)
        .collect();
    let names: BTreeSet<&str> = registered.iter().map(|spec| spec.name).collect();
    assert_eq!(names, behind_the_scope);
    assert!(!names.is_empty(), "the admin tier registers no tool");
    for spec in registered {
        let write = spec
            .write()
            .unwrap_or_else(|| panic!("{} is registered and is not a mutation", spec.name));
        assert!(
            names.contains(write.counterpart),
            "{} is registered without its counterpart {}",
            spec.name,
            write.counterpart
        );
    }

    // What the registered tools can change, together, is the allowlist:
    // no setting more, no setting less.
    let reachable: BTreeSet<String> = registered
        .iter()
        .filter_map(|spec| spec.body())
        .flat_map(|body| body.fields.iter().map(|field| (*field).to_string()))
        .collect();
    let missing: Vec<&String> = allowlist.difference(&reachable).collect();
    let extra: Vec<&String> = reachable.difference(&allowlist).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the admin tier's tools and SETTINGS_ALLOWLIST disagree.\n  allowlisted and not \
         offered: {missing:?}\n  offered and not allowlisted: {extra:?}"
    );
}

/// The operator reference, whose admin-tier section restates the
/// allowlist as a table an operator reads.
const MCP_REFERENCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/mcp.md"));

/// The header row of that table; its body runs to the first blank line.
const ALLOWLIST_TABLE_HEADER: &str = "| Setting | Tier bound | Reach | Takes effect |";

/// The row `docs/mcp.md` must carry for `setting`, rendered from the
/// entry itself.
fn documented_row(setting: &AdminSetting) -> String {
    format!(
        "| `{}` | {} | {} | {} |",
        setting.name,
        setting.bound_text(),
        setting.reach.describe(),
        setting.takes_effect.describe()
    )
}

#[test]
fn the_operator_reference_lists_exactly_the_allowlist_with_its_bounds() {
    // `docs/mcp.md` tells an operator what the admin tier can change,
    // how far, where and when. A table there is a transcription, so
    // every row is asserted against the entry it transcribes, both
    // ways, rather than trusted.
    let (_, after_header) = MCP_REFERENCE
        .split_once(ALLOWLIST_TABLE_HEADER)
        .expect("docs/mcp.md carries the admin tier's settings table");
    let documented: BTreeSet<String> = after_header
        .lines()
        .skip(2)
        .take_while(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();
    let expected: BTreeSet<String> = SETTINGS_ALLOWLIST.iter().map(documented_row).collect();
    assert!(
        !documented.is_empty(),
        "the table in docs/mcp.md was found and read as empty; the parse went blind"
    );
    let missing: Vec<&String> = expected.difference(&documented).collect();
    let extra: Vec<&String> = documented.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "docs/mcp.md's admin-tier table and SETTINGS_ALLOWLIST disagree.\n  expected and \
         absent: {missing:#?}\n  present and not expected: {extra:#?}"
    );
}

#[test]
fn the_admin_tool_states_each_bound_where_its_writes_land_and_when_they_act() {
    // The tool's description is what a model reads before it calls. It
    // is prose in a crate that cannot read the allowlist, so each claim
    // it makes is pinned against the entries here.
    let tools: Vec<&ToolSpec> = catalogue()
        .iter()
        .filter(|spec| spec.scope == wire(AutomationScope::SettingsWrite))
        .collect();
    assert!(!tools.is_empty(), "no tool behind settings:write");
    let every_fleet = SETTINGS_ALLOWLIST
        .iter()
        .all(|setting| setting.reach == Reach::Fleet);
    let every_live = SETTINGS_ALLOWLIST
        .iter()
        .all(|setting| setting.takes_effect == TakesEffect::Live);
    for spec in tools {
        let body = spec
            .body()
            .unwrap_or_else(|| panic!("{} has no body", spec.name));
        for setting in SETTINGS_ALLOWLIST {
            let stated = format!("`{}` {}", setting.name, setting.bound_text());
            assert!(
                body.doc.contains(&stated),
                "{}'s body does not state {stated:?}",
                spec.name
            );
        }
        assert_eq!(
            spec.summary
                .contains("every one of these is fleet policy, replicated to every follower"),
            every_fleet,
            "{}'s summary and the allowlist's reach disagree",
            spec.name
        );
        assert_eq!(
            spec.summary.contains("Each takes effect without a restart"),
            every_live,
            "{}'s summary and the allowlist's takes_effect disagree",
            spec.name
        );
    }
}

#[test]
fn iv2_identity_and_fleet_operations_are_declared_for_no_token_on_any_verb() {
    let paths = management_paths();
    let mut swept = 0usize;
    for family in HUMAN_ONLY_FAMILIES {
        let members: Vec<&String> = paths
            .iter()
            .filter(|path| path.as_str() == *family || path.starts_with(&format!("{family}/")))
            .collect();
        assert!(
            !members.is_empty(),
            "no management route under {family}: the family moved or the scan went blind"
        );
        for path in members {
            let automation = mirrored(path);
            for method in &EVERY_VERB {
                swept += 1;
                assert_eq!(
                    required_scope(method, &automation),
                    None,
                    "{method} {automation} (mirroring {path}) is declared on the automation \
                     plane; identity and fleet membership stay human-only at every tier"
                );
            }
        }
    }
    assert!(
        swept >= 5 * HUMAN_ONLY_FAMILIES.len(),
        "only {swept} pairs swept"
    );
}

#[test]
fn iv2_nothing_the_automation_plane_mounts_and_declares_is_an_identity_or_fleet_operation() {
    // The inverse of the sweep above, which only asks about the names
    // the management plane uses: every path the automation plane itself
    // mounts, whatever it is called, is asked of the matrix for every
    // verb, and whatever the matrix declares there sits under no
    // identity or fleet family.
    let families: Vec<String> = HUMAN_ONLY_FAMILIES.iter().copied().map(mirrored).collect();
    let mut declared = 0usize;
    for path in automation_paths() {
        let path = concrete(&path);
        for method in &EVERY_VERB {
            if required_scope(method, &path).is_none() {
                continue;
            }
            declared += 1;
            for family in &families {
                assert!(
                    path != *family && !path.starts_with(&format!("{family}/")),
                    "{method} {path} is declared on the automation plane, under {family}"
                );
            }
        }
    }
    assert!(
        declared > 0,
        "no declared (verb, path) on the automation plane"
    );
}

#[test]
fn iv2_no_tool_of_any_tier_calls_an_identity_or_fleet_operation() {
    // The refusal is at the gate because the tool does not exist, not
    // because it exists and says no. No tool of any tier calls a path
    // under a human-only family. The catalogue is walked directly: no
    // one token registers every tool any more, since one process
    // serves one tier.
    let mirrored_families: Vec<String> =
        HUMAN_ONLY_FAMILIES.iter().copied().map(mirrored).collect();
    for spec in catalogue() {
        let path = path_of(spec);
        for family in &mirrored_families {
            assert!(
                path != *family && !path.starts_with(&format!("{family}/")),
                "{} calls {path}, under {family}",
                spec.name
            );
        }
    }
}
