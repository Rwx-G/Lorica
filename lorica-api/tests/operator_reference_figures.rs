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

//! The figures the operator references quote beside the constant they
//! come from.
//!
//! `docs/mcp.md` and `docs/automation.md` name each budget, ceiling and
//! lifetime by its constant and give its value in the same sentence, so
//! an operator reads a number rather than a name. The number is a
//! transcription, and nothing else would notice the constant moving
//! away from it; this test renders each phrase from the constant and
//! asserts the document still says it, whitespace normalised, since
//! the documents wrap.

use std::time::Duration;

use lorica_api::automation::{AUTOMATION_READ_DEFAULT_ROWS, AUTOMATION_READ_MAX_ROWS};
use lorica_api::server::{RL_ROUTES_CUD, RL_SETTINGS_UPDATE, RL_WINDOW_S};
use lorica_config::models::{
    AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS, AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS,
};
use lorica_mcp::server::{RATE_BUDGET, RATE_WINDOW};

/// The MCP operator reference.
const MCP_REFERENCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/mcp.md"));

/// The automation plane's operator reference.
const AUTOMATION_REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/automation.md"
));

/// `text` with every run of whitespace read as one space.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

#[test]
fn every_figure_the_operator_references_quote_is_the_constant_they_name() {
    // "a minute" is itself a figure: both windows are asserted to be
    // one before any sentence saying so is trusted.
    assert_eq!(RATE_WINDOW, Duration::from_secs(60));
    assert_eq!(RL_WINDOW_S, 60);

    let mcp = words(MCP_REFERENCE);
    let automation = words(AUTOMATION_REFERENCE);
    let quoted: Vec<(&str, &String, String)> = vec![
        (
            "docs/mcp.md",
            &mcp,
            format!("`AUTOMATION_READ_MAX_ROWS` ({AUTOMATION_READ_MAX_ROWS})"),
        ),
        (
            "docs/mcp.md",
            &mcp,
            format!("`AUTOMATION_READ_DEFAULT_ROWS` ({AUTOMATION_READ_DEFAULT_ROWS})"),
        ),
        (
            "docs/mcp.md",
            &mcp,
            format!("`RATE_WINDOW` ({RATE_BUDGET} a minute"),
        ),
        (
            "docs/mcp.md",
            &mcp,
            format!("`RL_SETTINGS_UPDATE` settings writes a window ({RL_SETTINGS_UPDATE} a minute"),
        ),
        (
            "docs/mcp.md",
            &mcp,
            format!("`RL_ROUTES_CUD` of every other write together ({RL_ROUTES_CUD},"),
        ),
        (
            "docs/automation.md",
            &automation,
            format!("`RATE_BUDGET` a `RATE_WINDOW` ({RATE_BUDGET} a minute)"),
        ),
        (
            "docs/automation.md",
            &automation,
            format!("clamped to {AUTOMATION_READ_MAX_ROWS} rows"),
        ),
        (
            "docs/automation.md",
            &automation,
            format!("absent, it is {AUTOMATION_READ_DEFAULT_ROWS}."),
        ),
        (
            "docs/automation.md",
            &automation,
            format!(
                "`AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS` ({AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS} days)"
            ),
        ),
        (
            "docs/automation.md",
            &automation,
            format!(
                "`AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS` \
                 ({AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS} days)"
            ),
        ),
    ];
    for (document, text, phrase) in quoted {
        assert!(
            text.contains(&phrase),
            "{document} no longer says `{phrase}`: the constant moved and the document \
             did not, or the sentence was reworded; render the figure from the constant \
             again"
        );
    }
}
