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

//! The Story 11.1 guard lot 2 named and deferred to lot 4, grown by
//! Story 11.2 to every verb: the scope each MCP tool declares, against
//! the scope the automation plane's matrix puts on the verb and path
//! that tool calls.
//!
//! # Why there is something to guard
//!
//! Two tables name a scope per call. `lorica_mcp::tools::catalogue`
//! names one per TOOL, because the Streamable HTTP binding authorizes
//! per tool call and the stdio binding registers a tool set from a
//! token's grants. `lorica_api::automation::required_scope` names one
//! per `(verb, path)`, because that is what an HTTP gate can weigh.
//! They are two statements of one rule and there is no third table to
//! derive both from: the crates are separate on purpose, and this is
//! the one place that can see both.
//!
//! # What drifts, and how quietly
//!
//! A scope loosened on the catalogue side registers a tool for a token
//! the gate would refuse. Since Story 11.2 the in-process binding runs
//! a tool's call through the plane's own router, scope gate included,
//! so such a call is refused by the plane on both bindings and this
//! guard is what keeps that refusal from being the first thing an
//! operator learns: a 403 on a tool the server listed is a confusing
//! error, not a leak. A scope tightened on the catalogue side is the
//! quiet direction: the tool simply never registers for a token that
//! should have it, nothing fails, and an operator concludes the feature
//! does not work.
//!
//! So: one assertion per catalogue entry, both spellings resolved
//! through `AutomationScope` rather than compared as strings, and the
//! verb and the path taken from the tool itself rather than typed again
//! here.

use std::collections::BTreeSet;

use lorica_api::automation::{required_scope, ScopeRequirement};
use lorica_config::models::AutomationScope;
use lorica_mcp::tools::{catalogue, ToolSpec};
use lorica_mcp::Verb;

/// The verb and path a tool calls, as the tool itself builds them.
///
/// Derived and not transcribed: `call_for` is what the running server
/// calls, so a tool whose path or verb moves moves here too. The
/// resource tools get a placeholder id, which the matrix collapses into
/// its template exactly as it collapses a real one, and a write tool an
/// empty body, which the path does not depend on.
fn call_of(spec: &ToolSpec) -> (http::Method, String) {
    let mut arguments = serde_json::Map::new();
    if let Some(param) = spec.resource {
        arguments.insert(param.name.to_string(), serde_json::json!("r-1"));
    }
    if let Some(body) = spec.body() {
        arguments.insert(body.argument.to_string(), serde_json::json!({}));
    }
    let built = spec
        .call_for(&serde_json::Value::Object(arguments))
        .unwrap_or_else(|refused| panic!("{} builds no call: {}", spec.name, refused.message));
    let path = built
        .path
        .split_once('?')
        .map_or(built.path.clone(), |(path, _query)| path.to_string());
    (method_of(built.verb), path)
}

/// The `http::Method` a seam verb is, through its wire spelling.
fn method_of(verb: Verb) -> http::Method {
    verb.as_str()
        .parse()
        .unwrap_or_else(|_| panic!("{verb} is not an HTTP method"))
}

/// The `AutomationScope` a wire spelling names.
fn scope_of(spelled: &str) -> AutomationScope {
    serde_json::from_str::<AutomationScope>(&format!("\"{spelled}\""))
        .unwrap_or_else(|_| panic!("`{spelled}` is not an AutomationScope spelling"))
}

/// How the enum spells itself, which is the one authority on the word.
fn wire_name(scope: AutomationScope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .expect("a scope serialises to a string")
}

const OTHER_VERBS: [http::Method; 4] = [
    http::Method::POST,
    http::Method::PUT,
    http::Method::DELETE,
    http::Method::PATCH,
];

#[test]
fn every_mcp_tool_names_the_scope_its_verb_and_path_sit_behind() {
    // Extraction sanity before any comparison: an empty catalogue would
    // pass a loop over it without asserting anything at all.
    assert!(
        catalogue().len() >= 25,
        "the MCP catalogue holds {} tools, which is fewer than Stories 11.1 and 11.2 shipped: \
         this guard is reading a shape the crate no longer has",
        catalogue().len()
    );

    let mut wrong: Vec<String> = Vec::new();
    for spec in catalogue() {
        let (method, path) = call_of(spec);
        let declared = ScopeRequirement::Scope(scope_of(spec.scope));
        let enforced = required_scope(&method, &path);
        if enforced != Some(declared) {
            wrong.push(format!(
                "  {} calls {method} {path}\n    the tool declares {:?}\n    the matrix enforces {:?}",
                spec.name, declared, enforced
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "\nThe MCP tool catalogue and the automation scope matrix disagree.\n\n{}\n\n\
         Fix whichever side is wrong. A tool declaring a scope the gate does not require \
         registers for a token the gate refuses, which is a 403 on a listed tool nobody can \
         explain. A tool declaring a scope the gate does not use simply never registers, \
         which fails nothing and looks like the feature not working.\n\
         The two tables are lorica_mcp::tools::catalogue and \
         lorica_api::automation::scope::required_scope.\n",
        wrong.join("\n")
    );
}

#[test]
fn every_read_tool_is_a_get_the_plane_declares_and_no_read_scope_reaches_another_verb() {
    // The read tier exists to be unable to change anything. The
    // catalogue says every read tool is a GET; this says the plane
    // agrees, which is the half the catalogue cannot assert about
    // itself: on a read tool's path, any other verb is either undeclared
    // or behind a write scope of its own (Story 11.2 mounts `POST` on
    // two of the collections), never behind a read scope and never open
    // to any live token.
    let mut reads = 0usize;
    for spec in catalogue().iter().filter(|spec| spec.write().is_none()) {
        reads += 1;
        let (method, path) = call_of(spec);
        assert_eq!(method, http::Method::GET, "{}", spec.name);
        assert!(
            required_scope(&http::Method::GET, &path).is_some(),
            "{} reads {path}, which the automation plane declares for no token",
            spec.name
        );
        for other in OTHER_VERBS {
            match required_scope(&other, &path) {
                None => {}
                Some(ScopeRequirement::Scope(scope)) => assert!(
                    wire_name(scope).ends_with(":write"),
                    "{} reads {path}, and the plane declares it for {other} behind the read \
                     scope {}",
                    spec.name,
                    wire_name(scope)
                ),
                Some(ScopeRequirement::AnyLiveToken) => panic!(
                    "{} reads {path}, and the plane opens {other} on it to any live token",
                    spec.name
                ),
            }
        }
    }
    assert!(reads >= 9, "only {reads} read tools");
}

#[test]
fn every_write_tool_and_its_preview_sit_behind_one_write_scope_on_one_verb_and_get_is_not_it() {
    // Story 11.2 AC #2 and AC #3 on the plane's side. A write tool and
    // its preview call the same verb and path (the preview adds a
    // query, which the matrix does not read), so they sit behind one
    // write scope by construction; `GET` on that path is the read
    // surface's business or nobody's and never inherits the write
    // scope; and no other verb on it is open to any live token.
    let mut writes = 0usize;
    for spec in catalogue() {
        let Some(write) = spec.write() else {
            continue;
        };
        writes += 1;
        let (method, path) = call_of(spec);
        assert_ne!(method, http::Method::GET, "{}", spec.name);
        let declared = scope_of(spec.scope);
        assert!(wire_name(declared).ends_with(":write"), "{}", spec.name);

        let counterpart = lorica_mcp::tools::find(write.counterpart)
            .unwrap_or_else(|| panic!("{} names no counterpart", spec.name));
        assert_eq!(call_of(counterpart), (method.clone(), path.clone()));
        assert_eq!(counterpart.scope, spec.scope);

        assert_ne!(
            required_scope(&http::Method::GET, &path),
            Some(ScopeRequirement::Scope(declared)),
            "{}: GET {path} inherits the write scope",
            spec.name
        );
        for other in OTHER_VERBS {
            assert_ne!(
                required_scope(&other, &path),
                Some(ScopeRequirement::AnyLiveToken),
                "{}: {other} {path} is open to any live token",
                spec.name
            );
        }
    }
    assert!(writes >= 16, "only {writes} write tools");
}

#[test]
fn the_mcp_endpoint_itself_is_reached_by_any_live_token() {
    // It cannot be declared behind one scope: an MCP request carries its
    // own tool and each tool has its own. The authorization that matters
    // is the per-tool one the tests above pin, and this is the statement
    // that the path-level gate is deliberately the other state rather
    // than a declaration somebody forgot.
    assert_eq!(
        required_scope(&http::Method::POST, lorica_api::automation::MCP_PATH),
        Some(ScopeRequirement::AnyLiveToken)
    );
    // Declared for the removed verbs too, so they answer the 405 the
    // revision asks for rather than a 403 about a grant.
    for method in [http::Method::GET, http::Method::DELETE] {
        assert_eq!(
            required_scope(&method, lorica_api::automation::MCP_PATH),
            Some(ScopeRequirement::AnyLiveToken),
            "{method}"
        );
    }
    // And nothing deeper inherits it.
    for deeper in [
        "/automation/v1/mcp/",
        "/automation/v1/mcp/tools",
        "/automation/v1/mcp/sse",
    ] {
        assert_eq!(
            required_scope(&http::Method::POST, deeper),
            None,
            "{deeper}"
        );
    }
    // And no tool calls it: a tool cannot reach the endpoint that is
    // running it.
    for spec in catalogue() {
        let (_, path) = call_of(spec);
        assert_ne!(path, lorica_api::automation::MCP_PATH, "{}", spec.name);
    }
}

#[test]
fn the_scopes_the_catalogue_uses_are_every_scope_but_the_environment_ones() {
    // The complement, stated once and deliberately: a scope added to the
    // token model either gets a tool or is named here as one that does
    // not. `lorica-mcp` asserts the same thing from its own side with
    // its own copy of the spellings; this asserts it from the side that
    // holds the enum, so the two cannot both be wrong in the same way.
    // Compared as the enum's own spellings and not as the catalogue's
    // strings: `scope_of` resolves each tool's word through
    // `AutomationScope` first, so a word this enum does not know has
    // already failed by the time the sets are built.
    let named: BTreeSet<String> = catalogue()
        .iter()
        .map(|spec| wire_name(scope_of(spec.scope)))
        .collect();
    let declared: BTreeSet<String> = AutomationScope::ALL
        .iter()
        .copied()
        .map(wire_name)
        .collect();
    let outside: BTreeSet<String> = declared.difference(&named).cloned().collect();
    assert_eq!(
        outside,
        BTreeSet::from([
            // Story 10.4's environment resource is a pipeline's surface
            // and not an operator's; neither tier names it.
            "environments:read".to_string(),
            "environments:write".to_string(),
        ]),
        "a scope moved: either give it a tool or add it to this complement, \
         deliberately"
    );
    // And the split between the tiers is the split in the vocabulary:
    // every read tool names a read scope, every write tool a write one.
    for spec in catalogue() {
        let spelled = wire_name(scope_of(spec.scope));
        assert_eq!(
            spelled.ends_with(":write"),
            spec.write().is_some(),
            "{} declares {spelled}",
            spec.name
        );
    }
}

#[test]
fn the_write_tools_body_cap_is_the_planes() {
    // `lorica-mcp` refuses a body over its cap before the call leaves,
    // in its own words; the plane refuses one over its own with a 413.
    // The two figures are one figure, or a body the tool accepts is a
    // body the listener refuses.
    assert_eq!(
        lorica_mcp::tools::MAX_BODY_BYTES,
        lorica_api::automation::AUTOMATION_BODY_CAP
    );
}
