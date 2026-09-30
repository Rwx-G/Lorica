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

//! The Story 11.1 AC #6 header names, pinned between the crate that
//! writes them and the plane that records them.
//!
//! `lorica-mcp`'s stdio client declares the transport and the tool in
//! two headers of Lorica's own, and
//! [`lorica_api::automation::audit`] reads them into the `asserted[...]`
//! clause of the audit row. The drift would be silent in the worst way:
//! a rename on either side makes the plane record no assertion at all,
//! the request still succeeds, every gate still passes, and the trail
//! quietly stops saying which tool a model asked for.
//!
//! The header names themselves cannot drift: `lorica-api` depends on
//! `lorica-mcp` and re-exports its two constants rather than spelling
//! them again, so they are one definition. What this file pins is what
//! a shared constant cannot: that the marker the stdio client sends is
//! a value the plane will record, and that the Streamable HTTP binding
//! asserts nothing.

use lorica_mcp::http::{
    ASSERTED_TOOL_HEADER as EMITTED_TOOL_HEADER,
    ASSERTED_TRANSPORT_HEADER as EMITTED_TRANSPORT_HEADER, TRANSPORT_MARKER,
};

/// The bound `lorica_api::automation::audit::assertable` applies to a
/// claimed transport before it may become a row.
///
/// Restated here because the function is private and the point is the
/// VALUE, not the function: a marker outside these bounds is dropped
/// whole, so the row would say nothing about the transport while every
/// gate stayed green. The test below is the executable case. The
/// character class itself is not restated: both crates read it from
/// `lorica_mcp::tools::fits_tool_name_grammar`.
const ASSERTED_TRANSPORT_MAX_BYTES: usize = 32;

#[test]
fn the_transport_marker_the_mcp_server_asserts_fits_what_this_plane_will_record() {
    // The value, not only the header it travels in. The plane drops an
    // assertion it cannot store, so a marker outside the accepted set
    // would be a row that silently says nothing.
    assert!(
        TRANSPORT_MARKER.starts_with("mcp"),
        "every MCP binding's marker starts with `mcp` so one filter finds them all: \
         {TRANSPORT_MARKER}"
    );
    assert!(
        lorica_mcp::tools::fits_tool_name_grammar(TRANSPORT_MARKER, ASSERTED_TRANSPORT_MAX_BYTES),
        "`{TRANSPORT_MARKER}` is outside what lorica-api/src/automation/audit.rs will \
         record, so the assertion would be dropped and the row would say nothing about \
         the transport"
    );
}

#[test]
fn the_streamable_http_binding_asserts_nothing_and_needs_no_marker_of_its_own() {
    // The in-process binding does not claim a transport or a tool, and
    // that is the design rather than an omission: the node routed the
    // request to `MCP_PATH` itself, so the path already in the audit
    // row IS the transport, established, and the handler parsed the
    // body, so the tool is established too. The stdio binding has no
    // such path - it reaches `/automation/v1/logs` like any other
    // client - which is exactly why it has to assert both.
    //
    // Asserted against the adapter's own source, the way its siblings
    // in that module assert that it opens no connection: the assertion
    // headers, the marker, and the constants that name them may appear
    // nowhere in the module body. The first version of this test
    // compared two path strings and would have stayed green while the
    // adapter started asserting a transport.
    let source = include_str!("../src/automation/mcp.rs");
    let body = source.split("#[cfg(test)]").next().unwrap_or(source);
    for asserting in [
        EMITTED_TOOL_HEADER,
        EMITTED_TRANSPORT_HEADER,
        TRANSPORT_MARKER,
        "ASSERTED_TOOL_HEADER",
        "ASSERTED_TRANSPORT_HEADER",
        "TRANSPORT_MARKER",
        "lorica-asserted-",
    ] {
        assert!(
            !body.contains(asserting),
            "`{asserting}` appears in the Streamable HTTP adapter, which asserts nothing"
        );
    }
    // And the scan is worth something: the in-process plane it is
    // about really is in the module, and so is the constant the audit
    // layer keys the established row on.
    assert!(body.contains("impl AutomationPlane for InProcessPlane"));
    assert!(body.contains("pub struct McpCallRecord"));
}
