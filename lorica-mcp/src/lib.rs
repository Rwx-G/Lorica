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
//! plane through.
//!
//! # Why a library at all
//!
//! Story 11.1 mounts the Streamable HTTP adapter INSIDE `lorica-api`,
//! on the Story 10.3 listener that already owns the TLS, the
//! source-CIDR allowlist, the connection caps and the audit layer. There
//! is no third management plane, so that adapter cannot be a second
//! process, and `lorica-api` has to be able to depend on this crate. A
//! binary-only crate gives it nothing to depend on, and the only
//! remaining shape is the in-process adapter looping back over its own
//! listener, which the mandatory source allowlist and the per-source
//! connection budget would refuse or throttle by default, and which
//! would be absurd even if they did not.
//!
//! The seam is cheap now and structural later. AC #10 requires one
//! shared core across both bindings, and what decides whether that
//! holds is how a tool body reaches the plane: a tool written against
//! an HTTP client is a tool that has to be rewritten for the in-process
//! case, and the two then drift in exactly the way AC #10 forbids.
//! [`AutomationPlane`] is that decision taken before the first tool
//! existed rather than after.
//!
//! # The seam carries a verb and a body, not only a path
//!
//! Story 11.1 shipped it as `fetch(path)`, which was the whole of what a
//! read tier needs. Story 11.2's config tier adds mutations, and a
//! mutation is a verb, a path and a body: the seam grew to
//! [`AutomationPlane::call`] rather than a second seam beside the first,
//! so a write tool and a read tool reach the plane through one method
//! and both bindings implement one trait. The in-process binding does
//! not dispatch by hand any more either: it builds the request the seam
//! describes and runs it through the plane's own router, scope gate
//! included, which is what lets the write handlers run unchanged with
//! their per-token grants and their own audit rows.
//!
//! # What is here, and what is deliberately not
//!
//! Here: the protocol revision this crate implements, the call seam,
//! the configuration intake ([`config`]), the JSON-RPC envelope
//! ([`jsonrpc`]), the untrusted-text delimiting ([`untrusted`]), the
//! tools of every tier ([`tools`]), the protocol core that runs them
//! ([`server`]), the HTTPS implementation of the seam ([`http`]) and
//! the stdio binding ([`stdio`]).
//!
//! NOT here, and not stubbed anywhere: the Streamable HTTP adapter and
//! the in-process [`AutomationPlane`] it runs the plane's router
//! through. Both live in `lorica-api`, in `automation::mcp`, because
//! that binding is a path on the Story 10.3 listener rather than a
//! process of its own. `lorica-api` depends on this crate for [`server`]
//! and [`tools`]; nothing here depends on `lorica-api`, or a stdio
//! subprocess would carry the whole management crate.
//!
//! # Where each acceptance criterion lives
//!
//! Story 11.1: AC #1 is [`config`]. AC #3 is
//! [`server::McpServer::introspect`] and
//! [`server::McpServer::startup_notice`]. AC #4 is the read half of
//! [`tools::catalogue`]. AC #6 is [`http`], which is where the two
//! assertion headers are written. AC #7 is [`untrusted`], and it is in
//! the shared core rather than in each tool precisely so that a tool
//! added in a later story gets it without knowing it exists. AC #10 is
//! [`stdio`].
//!
//! Story 11.2: AC #2 is [`server::McpServer::sharing`], which registers
//! a tool for a scope the token holds and no other, over a catalogue
//! whose write tools declare write scopes by construction. AC #3 and
//! AC #4 are [`tools::MUTATIONS`] and what [`tools::catalogue`] builds
//! from it. AC #6 is the field vocabulary each [`tools::Body`] declares,
//! pinned in `lorica-api`'s tests against the handler that reads it.
//!
//! Story 11.3: AC #1 is [`tools::ADMIN_MUTATIONS`], whose settings body
//! restates the automation plane's allowlist and is pinned against it
//! in `lorica-api`'s tests; the plane is what enforces it. AC #2 and
//! IV2 hold by absence: no tool here names an identity or a cluster
//! membership operation, which `tools` asserts.

use core::fmt;
use core::future::Future;

use serde_json::Value;

pub mod config;
pub mod http;
pub mod jsonrpc;
pub mod server;
pub mod stdio;
pub mod tools;
pub mod untrusted;

pub use config::{ConfigError, ServerConfig};
pub use http::HttpsPlane;
pub use server::{Identity, McpServer, StartupError};
pub use tools::ToolSpec;

/// The MCP specification revision this crate implements.
///
/// The specification has moved three times in eighteen months, most
/// recently dropping sessions and the GET stream, so the revision is a
/// fact the crate states rather than one a reader infers. Changing it
/// is a release note.
pub const MCP_PROTOCOL_REVISION: &str = "2026-07-28";

/// The HTTP verb one call across the seam carries.
///
/// Four and no more: the automation plane mounts nothing under any
/// other verb, and a tool declares one of these rather than a string a
/// typo could widen into a verb the plane never declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    /// A read. Every tool of the read tier is one.
    Get,
    /// A create, or an action on one named resource.
    Post,
    /// A patch of one named resource.
    Put,
    /// The removal of one named resource.
    Delete,
}

impl Verb {
    /// The verb as the request line spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "GET",
            Verb::Post => "POST",
            Verb::Put => "PUT",
            Verb::Delete => "DELETE",
        }
    }

    /// Whether this verb changes nothing.
    pub fn is_read(self) -> bool {
        matches!(self, Verb::Get)
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a call to the plane did not answer.
///
/// Deliberately two variants and not a rich taxonomy. The MCP layer
/// owes a caller two different things and this is the boundary where
/// they part: a transport failure is the server's own problem, and a
/// status the automation plane chose is an answer the model should read
/// and stop on rather than retry. Story 11.1's Dev Notes state that an
/// authorization refusal from the API behind us is a tool EXECUTION
/// error (`isError: true`), never a JSON-RPC protocol error, and the
/// distinction only survives if the seam keeps the status. The same
/// holds for a validator's refusal of a write: the message is the
/// plane's, verbatim, and the status says which kind of refusal it was.
#[derive(Debug)]
pub enum PlaneError {
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

/// The most bytes of a refusal body [`PlaneError`]'s `Display` quotes.
///
/// The plane's own error envelope is two short fields. What is being
/// bounded is the case where the endpoint is not the plane, a captive
/// portal or a proxy error page, whose megabytes of HTML would
/// otherwise land whole in the client's MCP log at startup.
pub const DISPLAYED_BODY_MAX_BYTES: usize = 512;

impl fmt::Display for PlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlaneError::Transport(detail) => write!(f, "automation call failed: {detail}"),
            PlaneError::Refused { status, body } => {
                let cut = (0..=body.len().min(DISPLAYED_BODY_MAX_BYTES))
                    .rev()
                    .find(|end| body.is_char_boundary(*end))
                    .unwrap_or(0);
                if cut < body.len() {
                    write!(
                        f,
                        "automation call refused with {status}: {} [and {} more bytes]",
                        &body[..cut],
                        body.len() - cut
                    )
                } else {
                    write!(f, "automation call refused with {status}: {body}")
                }
            }
        }
    }
}

impl std::error::Error for PlaneError {}

/// What one call across the seam is on behalf of.
///
/// AC #6 is why this exists. The audit row the automation plane writes
/// is anchored on the token's `public_id`, which the node established
/// by verifying the credential, and the plane has no way to observe a
/// tool name because there is no tool at the HTTP layer. So the tool
/// name has to be something this server DECLARES, and a declaration
/// only reaches the wire if the seam carries it: an implementation that
/// saw a path alone could not say what the call was for.
///
/// [`Reason::Introspection`] is not a tool and is not dressed up as
/// one. The startup `whoami` runs before any client has spoken, and a
/// row claiming a tool ran there would be a false claim in the one
/// place that exists to tell claims from facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason<'a> {
    /// The server's own startup `whoami`. No tool has been called.
    Introspection,
    /// The single call of the named tool.
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

/// How a tool reaches the automation plane.
///
/// One method, taking the verb, the path a call is mounted at with its
/// query string already built, and the JSON body a write carries, and
/// answering the response body verbatim. The verbatim part is the
/// point: the automation surface is already the management plane's own
/// answer passed through untouched, and a second place that reshapes
/// it is a second place that can stop stripping a field. The tool layer
/// parses; this seam transports.
///
/// Two implementations exist. [`HttpsPlane`] is the one the stdio
/// binary drives. The other lives inside `lorica-api`, as
/// `automation::mcp::InProcessPlane`, where the Streamable HTTP adapter
/// runs the request through the plane's own router rather than dialling
/// the listener it is itself mounted on.
///
/// The bound is `Future` in return position rather than a boxed future,
/// so a tool layer generic over this trait pays nothing for the
/// indirection; no implementation of it is reached through a trait
/// object today, and the day one is, the boxing belongs on that call
/// site rather than in this signature.
pub trait AutomationPlane {
    /// Send `verb path` with `body`, and answer the response body.
    ///
    /// `path` is an automation-plane path, `/automation/v1/...`, with
    /// any query string already appended. It is never caller text: a
    /// tool builds it from a vocabulary it owns, so nothing a model
    /// says chooses which endpoint is reached. `body` is the management
    /// request body a write carries, already bounded and checked for
    /// shape by the tool layer, and `None` on a read and on a write
    /// that takes none.
    ///
    /// `reason` is what the call is for, which an implementation that
    /// talks to a remote plane declares on the request so the audit row
    /// can record it as a caller's assertion. See [`Reason`].
    ///
    /// # Errors
    ///
    /// [`PlaneError::Transport`] when no answer arrived,
    /// [`PlaneError::Refused`] for the status the plane chose.
    fn call(
        &self,
        verb: Verb,
        path: &str,
        body: Option<&Value>,
        reason: Reason<'_>,
    ) -> impl Future<Output = Result<String, PlaneError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the in-process adapter takes: no client, no socket,
    /// just an answer. It exists to prove the seam is implementable
    /// without a transport, which is the half of AC #10 a binary-only
    /// crate had nowhere to put.
    struct InProcess;

    impl AutomationPlane for InProcess {
        async fn call(
            &self,
            verb: Verb,
            path: &str,
            body: Option<&Value>,
            _reason: Reason<'_>,
        ) -> Result<String, PlaneError> {
            Ok(format!(
                "{{\"data\":{{\"verb\":\"{verb}\",\"path\":\"{path}\",\"body\":{}}}}}",
                body.map_or("null".to_string(), Value::to_string)
            ))
        }
    }

    /// The shape every tool body takes: generic over the seam, so one
    /// body serves the stdio client and the in-process adapter alike
    /// rather than two bodies agreeing by discipline.
    async fn a_tool_body<S: AutomationPlane>(source: &S) -> Result<String, PlaneError> {
        source
            .call(
                Verb::Get,
                "/automation/v1/logs?limit=1",
                None,
                Reason::Tool("lorica_logs"),
            )
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
    fn a_verb_spells_itself_the_way_the_request_line_does() {
        // The four the plane mounts, and no way to spell a fifth: the
        // in-process binding parses `as_str` back into an `http::Method`
        // and the stdio client into a `reqwest::Method`, so a spelling
        // that drifted would refuse every call rather than reach an
        // undeclared verb.
        assert_eq!(Verb::Get.as_str(), "GET");
        assert_eq!(Verb::Post.as_str(), "POST");
        assert_eq!(Verb::Put.as_str(), "PUT");
        assert_eq!(Verb::Delete.as_str(), "DELETE");
        assert!(Verb::Get.is_read());
        for write in [Verb::Post, Verb::Put, Verb::Delete] {
            assert!(!write.is_read(), "{write}");
        }
    }

    #[test]
    fn a_refusal_keeps_the_status_the_plane_chose() {
        // A 403 from the automation plane is a tool execution error the
        // model reads and stops on, not a protocol error it retries.
        // That distinction only survives if the status crosses the seam.
        let refused = PlaneError::Refused {
            status: 403,
            body: "{\"error\":{\"code\":\"forbidden\"}}".to_string(),
        };
        assert!(refused.to_string().contains("403"), "{refused}");
        assert!(refused.to_string().contains("forbidden"), "{refused}");

        let broken = PlaneError::Transport("connection reset".to_string());
        assert!(broken.to_string().contains("connection reset"), "{broken}");
    }

    #[test]
    fn a_displayed_refusal_quotes_a_bounded_slice_of_a_body_that_is_not_the_planes() {
        // A captive portal answers megabytes of HTML; the startup
        // refusal that quotes it goes to the client's MCP log.
        let portal = PlaneError::Refused {
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
        let accented = PlaneError::Refused {
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
