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

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The Lorica management MCP server (Epic 11) as a library: the shared
//! core both transports run, and the seam they reach the automation
//! plane's read views through.
//!
//! # Why a library at all, before there is anything to put in it
//!
//! Story 11.1 lands in four lots and the last one mounts the Streamable
//! HTTP adapter INSIDE `lorica-api`, on the Story 10.3 listener that
//! already owns the TLS, the source-CIDR allowlist, the connection caps
//! and the audit layer. There is no third management plane, so that
//! adapter cannot be a second process, and `lorica-api` has to be able
//! to depend on this crate. A binary-only crate gives it nothing to
//! depend on, and the only remaining shape is the in-process adapter
//! looping back over its own listener, which the mandatory source
//! allowlist and the per-source connection budget would refuse or
//! throttle by default, and which would be absurd even if they did not.
//!
//! The seam is cheap now and structural later. AC #10 requires one
//! shared core across both bindings, and what decides whether that
//! holds is how the FIRST tool body reaches a read view: a tool written
//! against an HTTP client is a tool that has to be rewritten for the
//! in-process case, and the two then drift in exactly the way AC #10
//! forbids. [`ReadSource`] is that decision taken before the first tool
//! exists rather than after.
//!
//! # What is here, and what is deliberately not
//!
//! Here: the protocol revision this crate implements, the fetch seam,
//! the configuration intake ([`config`]), the JSON-RPC envelope
//! ([`jsonrpc`]), the untrusted-text delimiting ([`untrusted`]), the
//! read tools ([`tools`]), the protocol core that runs them
//! ([`server`]), the HTTPS implementation of the seam ([`http`]) and
//! the stdio binding ([`stdio`]).
//!
//! NOT here, and not stubbed anywhere: the Streamable HTTP adapter and
//! the in-process [`ReadSource`] it calls the read handlers through.
//! Both live in `lorica-api`, in `automation::mcp`, because that
//! binding is a path on the Story 10.3 listener rather than a process
//! of its own. `lorica-api` depends on this crate for [`server`] and
//! [`tools`]; nothing here depends on `lorica-api`, or a stdio
//! subprocess would carry the whole management crate.
//!
//! # Where each acceptance criterion lives
//!
//! AC #1 is [`config`]. AC #3 is [`server::McpServer::introspect`] and
//! [`server::McpServer::startup_notice`]. AC #4 is
//! [`tools::CATALOGUE`]. AC #6 is [`http`], which is where the two
//! assertion headers are written. AC #7 is [`untrusted`], and it is in
//! the shared core rather than in each tool precisely so that a tool
//! added in a later story gets it without knowing it exists. AC #10 is
//! [`stdio`].

use core::fmt;
use core::future::Future;

pub mod config;
pub mod http;
pub mod jsonrpc;
pub mod server;
pub mod stdio;
pub mod tools;
pub mod untrusted;

pub use config::{ConfigError, ServerConfig};
pub use http::HttpsReadSource;
pub use server::{Identity, McpServer, StartupError};
pub use tools::ToolSpec;

/// The MCP specification revision this crate implements.
///
/// The specification has moved three times in eighteen months, most
/// recently dropping sessions and the GET stream, so the revision is a
/// fact the crate states rather than one a reader infers. Changing it
/// is a release note.
pub const MCP_PROTOCOL_REVISION: &str = "2026-07-28";

/// Why a read view could not be fetched.
///
/// Deliberately two variants and not a rich taxonomy. The MCP layer
/// owes a caller two different things and this is the boundary where
/// they part: a transport failure is the server's own problem, and a
/// status the automation plane chose is an answer the model should read
/// and stop on rather than retry. Story 11.1's Dev Notes state that an
/// authorization refusal from the API behind us is a tool EXECUTION
/// error (`isError: true`), never a JSON-RPC protocol error, and the
/// distinction only survives if the fetch seam keeps the status.
#[derive(Debug)]
pub enum ReadError {
    /// The request never produced an answer: no connection, a broken
    /// stream, a body that did not arrive.
    Transport(String),
    /// The automation plane answered, and refused.
    Refused {
        /// The HTTP status it answered with.
        status: u16,
        /// Its response body, verbatim.
        body: String,
    },
}

/// The most bytes of a refusal body [`ReadError`]'s `Display` quotes.
///
/// The plane's own error envelope is two short fields. What is being
/// bounded is the case where the endpoint is not the plane, a captive
/// portal or a proxy error page, whose megabytes of HTML would
/// otherwise land whole in the client's MCP log at startup.
pub const DISPLAYED_BODY_MAX_BYTES: usize = 512;

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Transport(detail) => write!(f, "automation read failed: {detail}"),
            ReadError::Refused { status, body } => {
                let cut = (0..=body.len().min(DISPLAYED_BODY_MAX_BYTES))
                    .rev()
                    .find(|end| body.is_char_boundary(*end))
                    .unwrap_or(0);
                if cut < body.len() {
                    write!(
                        f,
                        "automation read refused with {status}: {} [and {} more bytes]",
                        &body[..cut],
                        body.len() - cut
                    )
                } else {
                    write!(f, "automation read refused with {status}: {body}")
                }
            }
        }
    }
}

impl std::error::Error for ReadError {}

/// What one fetch across the seam is on behalf of.
///
/// AC #6 is why this exists. The audit row the automation plane writes
/// is anchored on the token's `public_id`, which the node established
/// by verifying the credential, and the plane has no way to observe a
/// tool name because there is no tool at the HTTP layer. So the tool
/// name has to be something this server DECLARES, and a declaration
/// only reaches the wire if the seam carries it: an implementation that
/// saw a path alone could not say what the read was for.
///
/// [`Reason::Introspection`] is not a tool and is not dressed up as
/// one. The startup `whoami` runs before any client has spoken, and a
/// row claiming a tool ran there would be a false claim in the one
/// place that exists to tell claims from facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason<'a> {
    /// The server's own startup `whoami`. No tool has been called.
    Introspection,
    /// The single read of the named tool.
    Tool(&'a str),
}

impl Reason<'_> {
    /// The tool name to declare, or `None` when no tool is running.
    pub fn tool(&self) -> Option<&str> {
        match self {
            Reason::Introspection => None,
            Reason::Tool(name) => Some(name),
        }
    }
}

/// How a tool reaches one read view of the automation plane.
///
/// One method, taking the path a read is mounted at with its query
/// string already built, and answering the JSON body verbatim. The
/// verbatim part is the point: the automation read surface is already
/// the management plane's own answer passed through untouched, and a
/// second place that reshapes it is a second place that can stop
/// stripping a field. The tool layer parses; this seam transports.
///
/// Two implementations exist. [`HttpsReadSource`] is the one the stdio
/// binary drives. The other lives inside `lorica-api`, as
/// `automation::mcp::InProcessReads`, where the Streamable HTTP adapter
/// calls the read handlers directly rather than dialling the listener
/// it is itself mounted on.
///
/// The bound is `Future` in return position rather than a boxed future,
/// so a tool layer generic over this trait pays nothing for the
/// indirection; no implementation of it is reached through a trait
/// object today, and the day one is, the boxing belongs on that call
/// site rather than in this signature.
pub trait ReadSource {
    /// Fetch `path` and answer the response body.
    ///
    /// `path` is an automation-plane path, `/automation/v1/...`, with
    /// any query string already appended. It is never caller text: a
    /// tool builds it from a vocabulary it owns, so nothing a model
    /// says chooses which endpoint is reached.
    ///
    /// `reason` is what the read is for, which an implementation that
    /// talks to a remote plane declares on the request so the audit row
    /// can record it as a caller's assertion. See [`Reason`].
    ///
    /// # Errors
    ///
    /// [`ReadError::Transport`] when no answer arrived,
    /// [`ReadError::Refused`] for the status the plane chose.
    fn fetch(
        &self,
        path: &str,
        reason: Reason<'_>,
    ) -> impl Future<Output = Result<String, ReadError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the in-process adapter takes: no client, no socket,
    /// just an answer. It exists to prove the seam is implementable
    /// without a transport, which is the half of AC #10 a binary-only
    /// crate had nowhere to put.
    struct InProcess;

    impl ReadSource for InProcess {
        async fn fetch(&self, path: &str, _reason: Reason<'_>) -> Result<String, ReadError> {
            Ok(format!("{{\"data\":{{\"path\":\"{path}\"}}}}"))
        }
    }

    /// The shape every tool body will take: generic over the seam, so
    /// one body serves the stdio client and the in-process adapter
    /// alike rather than two bodies agreeing by discipline.
    async fn a_tool_body<S: ReadSource>(source: &S) -> Result<String, ReadError> {
        source
            .fetch("/automation/v1/logs?limit=1", Reason::Tool("lorica_logs"))
            .await
    }

    #[test]
    fn one_tool_body_serves_a_source_that_owns_no_transport() {
        // The assertion is the compile. Polling the future would need a
        // runtime, and a crate that declares no dependency has none to
        // reach for; what matters here is that a body written once type
        // checks against an implementation holding no client at all.
        let _unpolled = a_tool_body(&InProcess);
    }

    #[test]
    fn a_refusal_keeps_the_status_the_plane_chose() {
        // A 403 from the automation plane is a tool execution error the
        // model reads and stops on, not a protocol error it retries.
        // That distinction only survives if the status crosses the seam.
        let refused = ReadError::Refused {
            status: 403,
            body: "{\"error\":{\"code\":\"forbidden\"}}".to_string(),
        };
        assert!(refused.to_string().contains("403"), "{refused}");
        assert!(refused.to_string().contains("forbidden"), "{refused}");

        let broken = ReadError::Transport("connection reset".to_string());
        assert!(broken.to_string().contains("connection reset"), "{broken}");
    }

    #[test]
    fn a_displayed_refusal_quotes_a_bounded_slice_of_a_body_that_is_not_the_planes() {
        // A captive portal answers megabytes of HTML; the startup
        // refusal that quotes it goes to the client's MCP log.
        let portal = ReadError::Refused {
            status: 302,
            body: "<html>".repeat(100_000),
        };
        let shown = portal.to_string();
        assert!(
            shown.len() < DISPLAYED_BODY_MAX_BYTES + 100,
            "{}",
            shown.len()
        );
        assert!(shown.contains("more bytes"), "{shown}");
        // And a cut never splits a character.
        let accented = ReadError::Refused {
            status: 400,
            body: "é".repeat(DISPLAYED_BODY_MAX_BYTES),
        };
        assert!(accented.to_string().contains("more bytes"));
    }

    #[test]
    fn the_startup_introspection_declares_no_tool_because_none_ran() {
        // AC #6's honesty rule at the seam. A row claiming a tool ran
        // during the startup whoami would be a false claim in the one
        // place that exists to tell a claim from a fact.
        assert_eq!(Reason::Introspection.tool(), None);
        assert_eq!(Reason::Tool("lorica_logs").tool(), Some("lorica_logs"));
    }
}
