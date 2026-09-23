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

//! The Story 11.1 AC #6 header names, pinned across two crates that do
//! not depend on each other.
//!
//! `lorica-mcp` writes [`lorica_api::automation::audit`]'s two assertion
//! headers and `lorica-api` reads them. Neither can see the other's
//! constants today: `lorica-mcp` must not depend on `lorica-api` from
//! `src/`, and `lorica-api` depends on `lorica-mcp` only from the lot
//! that mounts the Streamable HTTP adapter inside it.
//!
//! The drift would be silent. A rename on either side makes the plane
//! record no assertion at all, every gate stays green, and the audit
//! trail quietly stops saying which tool a model asked for. So the
//! coupling is this file: `include_str!` on the committed source of the
//! emitting side, the literals extracted from it, and a both-directions
//! diff against the constants the reading side declares. It is the
//! `openapi_contract.rs` idiom - extraction sanity first, both
//! directions, a `panic!` naming what to do, nothing auto-written - and
//! it needs no dependency edge at all.
//!
//! When lot 4 makes `lorica-api` depend on `lorica-mcp`, this file
//! should become a direct comparison of the two constants and stop
//! parsing source.

use std::collections::BTreeSet;

use lorica_api::automation::audit::{ASSERTED_TOOL_HEADER, ASSERTED_TRANSPORT_HEADER};

/// The emitting side, as committed.
const MCP_HTTP_SOURCE: &str = include_str!("../../lorica-mcp/src/http.rs");

/// Every `pub const NAME: &str = "value";` in `source`, before its
/// tests.
///
/// The test module is excluded because it quotes both spellings in its
/// own assertions, and a fixture is not what the crate emits.
fn published_string_constants(source: &str) -> BTreeSet<(String, String)> {
    let source = source.split("#[cfg(test)]").next().unwrap_or(source);
    source
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub const ")?;
            let (name, rest) = rest.split_once(": &str = \"")?;
            let (value, _) = rest.split_once('"')?;
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

#[test]
fn the_header_names_the_mcp_server_writes_are_the_ones_this_plane_reads() {
    let published = published_string_constants(MCP_HTTP_SOURCE);
    // A broken parser passes by comparing two empty sets, so the
    // extraction states what it expects to have found before anything
    // is compared.
    assert!(
        published.len() >= 3,
        "no `pub const NAME: &str` was found in lorica-mcp/src/http.rs: the extractor below is \
         reading a shape that file no longer has. {published:?}"
    );

    let emitted: BTreeSet<&str> = published
        .iter()
        .filter(|(name, _)| name.starts_with("ASSERTED_") && name.ends_with("_HEADER"))
        .map(|(_, value)| value.as_str())
        .collect();
    let read: BTreeSet<&str> = BTreeSet::from([ASSERTED_TOOL_HEADER, ASSERTED_TRANSPORT_HEADER]);

    let only_emitted: Vec<&&str> = emitted.difference(&read).collect();
    let only_read: Vec<&&str> = read.difference(&emitted).collect();
    if !only_emitted.is_empty() || !only_read.is_empty() {
        panic!(
            "the Story 11.1 AC #6 assertion headers drifted between the crate that writes them \
             and the plane that records them.\n\
             \n\
             written by lorica-mcp and not read here: {only_emitted:?}\n\
             read here and not written by lorica-mcp: {only_read:?}\n\
             \n\
             Fix whichever side is wrong. A rename on either one makes the automation plane \
             record no assertion at all: the request still succeeds, every gate still passes, \
             and the audit row quietly stops saying which tool a model asked for. The \
             constants are ASSERTED_TOOL_HEADER and ASSERTED_TRANSPORT_HEADER in \
             lorica-api/src/automation/audit.rs and in lorica-mcp/src/http.rs."
        );
    }
}

#[test]
fn the_transport_marker_the_mcp_server_asserts_fits_what_this_plane_will_record() {
    // The value, not only the header it travels in. The plane drops an
    // assertion it cannot store, so a marker outside the accepted set
    // would be a row that silently says nothing.
    let published = published_string_constants(MCP_HTTP_SOURCE);
    let marker = published
        .iter()
        .find(|(name, _)| name == "TRANSPORT_MARKER")
        .map(|(_, value)| value.as_str())
        .expect("lorica-mcp/src/http.rs declares TRANSPORT_MARKER");

    assert!(
        marker.starts_with("mcp"),
        "every MCP binding's marker starts with `mcp` so one filter finds them all: {marker}"
    );
    assert!(
        (1..=32).contains(&marker.len())
            && marker
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')),
        "`{marker}` is outside what lorica-api/src/automation/audit.rs will record, so the \
         assertion would be dropped and the row would say nothing about the transport"
    );
}
