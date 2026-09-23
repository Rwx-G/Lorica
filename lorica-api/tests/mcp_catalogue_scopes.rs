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

//! The Story 11.1 guard lot 2 named and deferred to lot 4: the scope
//! each MCP tool declares, against the scope the automation plane's
//! matrix puts on the path that tool reads.
//!
//! # Why there is something to guard
//!
//! Two tables name a scope per read. `lorica_mcp::tools::CATALOGUE`
//! names one per TOOL, because the Streamable HTTP binding authorizes
//! per tool call and the stdio binding registers a tool set from a
//! token's grants. `lorica_api::automation::required_scope` names one
//! per PATH, because that is what an HTTP gate can weigh. They are two
//! statements of one rule and there is no third table to derive both
//! from: the crates are separate on purpose, and this is the first lot
//! where one can see the other at all.
//!
//! # What drifts, and how quietly
//!
//! A scope loosened on the catalogue side registers a tool for a token
//! that the gate would refuse: over stdio every call from it answers a
//! 403 the operator cannot explain, and over the in-process binding the
//! read is reached WITHOUT the gate, because [`InProcessReads`] calls
//! the handler rather than the listener. That second one is not a
//! confusing error, it is a token reading what it was not granted.
//!
//! A scope tightened on the catalogue side is the quiet direction: the
//! tool simply never registers for a token that should have it, nothing
//! fails, and an operator concludes the feature does not work.
//!
//! So: one assertion per catalogue entry, both spellings resolved
//! through `AutomationScope` rather than compared as strings, and the
//! path taken from the tool itself rather than typed again here.

use std::collections::BTreeSet;

use lorica_api::automation::{required_scope, ScopeRequirement};
use lorica_config::models::AutomationScope;
use lorica_mcp::tools::{ToolSpec, CATALOGUE};

/// The path a tool reads, as the tool itself builds it.
///
/// Derived and not transcribed: `path_for` is what the running server
/// calls, so a tool whose path moves moves here too. The resource tools
/// get a placeholder id, which the matrix collapses into its template
/// exactly as it collapses a real one.
fn path_of(spec: &ToolSpec) -> String {
    let arguments = match spec.resource {
        Some(param) => {
            let mut map = serde_json::Map::new();
            map.insert(param.name.to_string(), serde_json::json!("r-1"));
            serde_json::Value::Object(map)
        }
        None => serde_json::json!({}),
    };
    let built = spec
        .path_for(&arguments)
        .unwrap_or_else(|refused| panic!("{} builds no path: {}", spec.name, refused.message));
    built
        .split_once('?')
        .map_or(built.clone(), |(path, _query)| path.to_string())
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

#[test]
fn every_mcp_tool_names_the_scope_its_path_sits_behind() {
    // Extraction sanity before any comparison: an empty catalogue would
    // pass a loop over it without asserting anything at all.
    assert!(
        CATALOGUE.len() >= 9,
        "the MCP catalogue holds {} tools, which is fewer than Story 11.1 shipped: this \
         guard is reading a shape the crate no longer has",
        CATALOGUE.len()
    );

    let mut wrong: Vec<String> = Vec::new();
    for spec in CATALOGUE {
        let path = path_of(spec);
        let declared = ScopeRequirement::Scope(scope_of(spec.scope));
        let enforced = required_scope(&http::Method::GET, &path);
        if enforced != Some(declared) {
            wrong.push(format!(
                "  {} reads {path}\n    the tool declares {:?}\n    the matrix enforces {:?}",
                spec.name, declared, enforced
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "\nThe MCP tool catalogue and the automation scope matrix disagree.\n\n{}\n\n\
         Fix whichever side is wrong. A tool declaring a scope the gate does not require \
         registers for a token the gate refuses, which over stdio is a 403 nobody can \
         explain and over the in-process binding is a read reached without the gate at \
         all, because the adapter calls the handler and not the listener. A tool \
         declaring a scope the gate does not use simply never registers, which fails \
         nothing and looks like the feature not working.\n\
         The two tables are lorica_mcp::tools::CATALOGUE and \
         lorica_api::automation::scope::required_scope.\n",
        wrong.join("\n")
    );
}

#[test]
fn every_mcp_tool_reads_a_path_this_plane_declares_for_get_and_no_read_scope_reaches_another_verb()
{
    // The tier exists to be unable to change anything. The catalogue
    // says every path is a GET; this says the plane agrees, which is the
    // half the catalogue cannot assert about itself: on a read tool's
    // path, any other verb is either undeclared or behind a write scope
    // of its own (Story 11.2 mounts `POST` on two of the collections),
    // never behind a read scope and never open to any live token.
    for spec in CATALOGUE {
        let path = path_of(spec);
        assert!(
            required_scope(&http::Method::GET, &path).is_some(),
            "{} reads {path}, which the automation plane declares for no token",
            spec.name
        );
        for method in [
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
        ] {
            match required_scope(&method, &path) {
                None => {}
                Some(ScopeRequirement::Scope(scope)) => assert!(
                    wire_name(scope).ends_with(":write"),
                    "{} reads {path}, and the plane declares it for {method} behind the read \
                     scope {}",
                    spec.name,
                    wire_name(scope)
                ),
                Some(ScopeRequirement::AnyLiveToken) => panic!(
                    "{} reads {path}, and the plane opens {method} on it to any live token",
                    spec.name
                ),
            }
        }
    }
}

#[test]
fn the_mcp_endpoint_itself_is_reached_by_any_live_token() {
    // It cannot be declared behind one scope: an MCP request carries its
    // own tool and each tool has its own. The authorization that matters
    // is the per-tool one the two tests above pin, and this is the
    // statement that the path-level gate is deliberately the other
    // state rather than a declaration somebody forgot.
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
}

#[test]
fn the_scopes_the_catalogue_uses_are_the_read_half_of_the_vocabulary() {
    // The complement, stated once and deliberately: a scope added to the
    // token model either gets a tool or is named here as one that does
    // not. `lorica-mcp` asserts the same thing from its own side with
    // its own copy of the spellings; this asserts it from the side that
    // holds the enum, so the two cannot both be wrong in the same way.
    // Compared as the enum's own spellings and not as the catalogue's
    // strings: `scope_of` resolves each tool's word through
    // `AutomationScope` first, so a word this enum does not know has
    // already failed by the time the sets are built.
    let named: BTreeSet<String> = CATALOGUE
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
            "environments:read".to_string(),
            "environments:write".to_string(),
            // Story 11.2's config tier. The write paths they gate are on
            // the plane; the tools over them are that story's lot 2, and
            // a read-tier catalogue must never name them.
            "routes:write".to_string(),
            "backends:write".to_string(),
            "certificates:write".to_string(),
        ]),
        "a scope moved: either give it a read tool or add it to this complement, \
         deliberately"
    );
}
