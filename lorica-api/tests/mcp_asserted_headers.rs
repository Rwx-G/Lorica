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
//! It used to be pinned by `include_str!` on the emitting source, with
//! the literals hand-extracted, because neither crate could see the
//! other. Lot 4 makes `lorica-api` depend on `lorica-mcp` in order to
//! mount the Streamable HTTP binding in process, so the constants can
//! now be compared as constants. A comparison that cannot misparse is
//! worth more than one that reads a file and might.

use lorica_api::automation::audit::{ASSERTED_TOOL_HEADER, ASSERTED_TRANSPORT_HEADER};
use lorica_mcp::http::{
    ASSERTED_TOOL_HEADER as EMITTED_TOOL_HEADER,
    ASSERTED_TRANSPORT_HEADER as EMITTED_TRANSPORT_HEADER, TRANSPORT_MARKER,
};

/// The bounds `lorica_api::automation::audit::assertable` applies before
/// a claimed value may become a row.
///
/// Restated here because the function is private and the point is the
/// VALUE, not the function: a marker outside these bounds is dropped
/// whole, so the row would say nothing about the transport while every
/// gate stayed green. The test below is the executable case.
const ASSERTED_TRANSPORT_MAX_BYTES: usize = 32;

#[test]
fn the_header_names_the_mcp_server_writes_are_the_ones_this_plane_reads() {
    assert_eq!(
        EMITTED_TOOL_HEADER, ASSERTED_TOOL_HEADER,
        "the tool assertion header drifted: lorica-mcp writes `{EMITTED_TOOL_HEADER}` and \
         lorica-api reads `{ASSERTED_TOOL_HEADER}`. A rename on either side makes the \
         automation plane record no assertion at all, and the audit row quietly stops \
         saying which tool a model asked for."
    );
    assert_eq!(
        EMITTED_TRANSPORT_HEADER, ASSERTED_TRANSPORT_HEADER,
        "the transport assertion header drifted: lorica-mcp writes \
         `{EMITTED_TRANSPORT_HEADER}` and lorica-api reads `{ASSERTED_TRANSPORT_HEADER}`."
    );
}

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
        (1..=ASSERTED_TRANSPORT_MAX_BYTES).contains(&TRANSPORT_MARKER.len())
            && TRANSPORT_MARKER
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')),
        "`{TRANSPORT_MARKER}` is outside what lorica-api/src/automation/audit.rs will \
         record, so the assertion would be dropped and the row would say nothing about \
         the transport"
    );
}

#[test]
fn the_streamable_http_binding_asserts_nothing_and_needs_no_marker_of_its_own() {
    // The in-process binding does not claim a transport, and that is the
    // design rather than an omission: the node routed the request to
    // `MCP_PATH` itself, so the path already in the audit row IS the
    // transport, established. The stdio binding has no such path - it
    // reaches `/automation/v1/logs` like any other client - which is
    // exactly why it has to assert one.
    assert_ne!(
        lorica_api::automation::MCP_PATH,
        "/automation/v1/logs",
        "the MCP endpoint and a read path must be distinguishable in a row"
    );
    assert!(lorica_api::automation::MCP_PATH.ends_with("/mcp"));
}
