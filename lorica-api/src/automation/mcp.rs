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

//! Story 11.1 AC #9: the Streamable HTTP binding of the MCP server, every
//! tier, as ONE path on the Story 10.3 automation listener.
//!
//! # Why it lives here and not in `lorica-mcp`
//!
//! PRD decision D1: an operator who has not enabled the automation
//! listener gains no MCP surface. So this is not a third management
//! plane, not a second port and not a second listener. It is a path on
//! the listener that already owns the TLS, the mandatory source-CIDR
//! allowlist, the connection caps, the per-IP limiter and the
//! per-request audit, and everything below inherits all of them by
//! being mounted inside [`super::router::build_automation_router`].
//!
//! The protocol itself is not here. [`lorica_mcp::server::McpServer`] is
//! the shared core AC #10 asks for, the same one the stdio binary runs;
//! this module is the transport around it and decides nothing a method
//! means.
//!
//! # The in-process plane runs the plane's own router, and dials nothing
//!
//! [`InProcessPlane`] implements [`AutomationPlane`] by building the
//! request the seam describes - the verb, the path, the body - and
//! running it through [`super::router::in_process_router`]: the plane's
//! route table under its scope gate, with the caller's principal, the
//! state and the connection info travelling as request extensions,
//! which is where the handlers and the gate read them from on the
//! listener. Looping back over the socket would be refused or throttled
//! by the plane's own source allowlist and per-source connection
//! budget, and would be absurd if it were not: the process holds the
//! state the request is about.
//!
//! Story 11.1 dispatched by hand instead, a `match` over the read paths
//! calling each handler, which was a second router that ran no scope
//! gate and could carry no verb, no body and no principal. Story 11.2
//! needed all three for its writes, and needed the write handlers to
//! run unchanged with their per-token grants and their own audit rows,
//! so the dispatch went and the router came in. The scope matrix now
//! authorizes every in-process call exactly as it does one over the
//! socket, and a tool mis-declared against it is refused by the plane
//! rather than merely absent from a list.
//!
//! # Authorization is per tool, because the request carries the tool
//!
//! The scope matrix declares one requirement per path, and an MCP
//! request carries its own tool with its own scope, so the endpoint
//! cannot be declared behind any single scope. It is declared
//! [`super::ScopeRequirement::AnyLiveToken`], and the authorization that
//! matters happens per call: [`McpServer::sharing`] registers only the
//! tools the presented token's scopes cover, so a tool the caller cannot
//! reach is absent from its `tools/list` and unknown to its
//! `tools/call`, and the matrix refuses it again in process if a tool
//! ever declared a scope its path does not sit behind. The specification
//! blesses exactly this - a tool set "MAY vary by the authorization
//! presented on the request ... since credentials are per-request input,
//! not connection state" - while forbidding variation per connection,
//! which nothing here does: the registry is built from the request's
//! own principal and dropped with it.
//!
//! Before any of that, the principal has to be ONE tier: Story 11.4 AC
//! #1 refuses a token whose scopes span two, in the constructor this
//! handler and the stdio binding share, and this handler answers the
//! refusal as a `403` naming the scopes (see `Refusal::spans_tiers`).
//!
//! The scope each tool names is `lorica-mcp`'s, and the scope each path
//! sits behind is [`super::scope::required_scope`]'s. They are two
//! statements of one rule, so `tests/mcp_catalogue_scopes.rs` pins them
//! against each other, one assertion per tool, on the tool's verb.
//!
//! # The invocation budget outlives the request
//!
//! The registry is per request; the tool-invocation budget the revision
//! requires must not be, or it counts one call and resets. So the
//! server is built over [`AppState::mcp_invocations`], one
//! [`lorica_mcp::server::InvocationLimiter`] for the process, keyed by
//! the token's `public_id`, and a token's window survives every
//! request that spends from it. The listener's own budgets do not meet
//! this MUST: they count connections at accept, and a keep-alive or
//! HTTP/2 caller issues requests without opening one.
//!
//! # What the audit row learns from this module
//!
//! Every message the core produced is answered with a `200`, including
//! a `tools/call` on a tool the token does not hold and a result
//! carrying `isError: true`. The audit layer keys its outcome word on
//! the status, so left alone it would record every one of those as
//! `ok`. The handler therefore attaches an [`McpCallRecord`] to the
//! response: the tool the body named, the declared argument names it
//! carried, and what the call came to in the core's own vocabulary, and
//! [`super::audit`] derives the row's outcome and the metric's label
//! from that rather than from the `200`.
//!
//! # What revision 2026-07-28 requires of this transport
//!
//! One endpoint, `POST` only. `Origin` validated on every connection.
//! `MCP-Protocol-Version` on every POST, `Mcp-Method` mirrored from the
//! body's `method`, `Mcp-Name` mirrored from `params.name` for
//! `tools/call`. A header that does not match its body counterpart, a
//! required header missing, or a value carrying characters that cannot
//! be compared is `400` with [`HEADER_MISMATCH`]. A version this server
//! does not implement is `400` naming what it does. A method it does not
//! implement is `404` with `-32601`, which is not what a JSON-RPC server
//! usually does and is deliberate: it is how a client tells a modern
//! server from a legacy one. A notification is `202` with no body.
//!
//! The revision REMOVED protocol-level sessions, the standalone `GET`
//! stream and `Last-Event-ID` resumability. `GET` and `DELETE` here
//! answer `405`, which is the router's doing rather than this module's:
//! the path is mounted for `POST` alone. The session header is ignored
//! and never echoed, and the resumption header is ignored; both are
//! named below so a reader can see they were considered.
//!
//! # Why every `Origin` is refused
//!
//! The specification's one MUST on this transport is against DNS
//! rebinding, and the usual shape of it - accept an origin whose host
//! matches the request's `Host` - is precisely the check rebinding
//! defeats, because the attacker's page and the attacker's DNS name
//! agree with each other. This plane serves no browser: it is a
//! machine-facing API behind a bearer token, with no cookie layer, no
//! CSRF layer and no session store anywhere in the router. An MCP client
//! speaking to it directly sends no `Origin` at all. A present one
//! therefore means a page is driving the endpoint, which is the case the
//! MUST exists for, so it is refused. An allowlist an operator
//! configures is the additive change if a browser front end ever needs
//! one; refusing by default is what keeps that decision explicit.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Extension};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use http::{HeaderMap, HeaderValue, StatusCode};
use lorica_config::models::OwnerKind;
use lorica_mcp::server::{Identity, McpServer, Outcome};
use lorica_mcp::{
    jsonrpc, tools, AutomationPlane, PlaneError, Reason, TierError, Verb, MCP_PROTOCOL_REVISION,
};
use serde_json::Value;
use tower::ServiceExt as _;
use tracing::Instrument;

use super::auth::AutomationPrincipal;
use crate::audit::ClientConnectInfo;
use crate::server::AppState;

/// The one endpoint this transport defines.
///
/// [`super::scope::required_scope`] declares it, without which it would
/// be reachable by no token at all, and
/// [`super::router::build_automation_router`] mounts it for `POST`.
pub const MCP_PATH: &str = "/automation/v1/mcp";

/// The revision the client claims, mirrored from the body's `_meta`.
pub const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// The method the client claims, mirrored from the body's `method`.
pub const METHOD_HEADER: &str = "mcp-method";

/// The tool the client claims, mirrored from `params.name`.
///
/// Read twice: here, to refuse a request whose header and body disagree,
/// and in [`super::audit`], which records it as the caller's assertion
/// of what the request was for on a POST the core never saw.
pub const NAME_HEADER: &str = "mcp-name";

/// Revision 2026-07-28 removed protocol-level sessions. This header is
/// read only to be ignored, and is never echoed.
pub const SESSION_ID_HEADER: &str = "mcp-session-id";

/// Revision 2026-07-28 removed stream resumability. Ignored.
pub const LAST_EVENT_ID_HEADER: &str = "last-event-id";

/// The JSON-RPC code for a header that does not match its body.
///
/// The revision's own, outside the standard range, and declared here
/// rather than in `lorica-mcp::jsonrpc` because it belongs to this
/// transport: nothing in the core reads a header.
pub const HEADER_MISMATCH: i64 = -32020;

/// The opening of the Base64 sentinel a header value may arrive in.
const SENTINEL_PREFIX: &str = "=?base64?";

/// Its closing.
const SENTINEL_SUFFIX: &str = "?=";

/// The methods this endpoint routes to the core.
///
/// Anything else is `404`. The list is this transport's own statement of
/// what the core implements, and the test below drives
/// [`McpServer::handle`] with each of these and with names outside them,
/// so a method the core gains or loses turns this red rather than
/// leaving the two ends quietly disagreeing about what exists.
const IMPLEMENTED_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "tools/call",
    "notifications/cancelled",
];

/// The most bytes of an answer carried back across the seam.
///
/// A read answers at most the plane's 256 KiB of rows plus its envelope
/// and a write answers one row; this is here so a handler that somehow
/// answered more cannot choose this process's memory on the way to a
/// tool result.
const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;

/// `POST /automation/v1/mcp` - one MCP message, answered in one object.
///
/// The answer is `application/json` carrying a single JSON-RPC object.
/// The revision also permits `text/event-stream` with a request-scoped
/// stream, which this binding does not open: every method here answers
/// in one message, so a stream would be an SSE frame per response and a
/// second framing to keep correct. `X-Accel-Buffering` is an SSE
/// concern and correspondingly absent.
pub async fn mcp_endpoint(
    Extension(state): Extension<AppState>,
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request = match examine(&headers, &body) {
        Ok(request) => request,
        Err(refusal) => return refusal.into_response(),
    };

    // The registry is built from THIS request's principal and dropped
    // with it: the tool set may vary by the authorization presented on
    // the request and must not vary per connection, and a registry that
    // outlived the request would be the second of those. The limiter is
    // the process's, keyed by token, or the budget would reset with the
    // registry. The constructor is also Story 11.4's tier check, the one
    // the stdio binding runs at startup, so a token spanning two tiers
    // is refused here on every request rather than served.
    let server =
        match McpServer::sharing(identity_of(&principal), Arc::clone(&state.mcp_invocations)) {
            Ok(server) => server,
            Err(refused) => {
                let (tool, argument_names) = named_call(&request);
                let mut response = Refusal::spans_tiers(
                    &request.id.clone().unwrap_or(Value::Null),
                    &refused,
                    principal.kind,
                )
                .into_response();
                response.extensions_mut().insert(McpCallRecord {
                    tool,
                    argument_names,
                    outcome: Outcome::SpansTiers,
                });
                return response;
            }
        };
    let source = InProcessPlane {
        state,
        principal,
        connect_info: connect_info.as_ref().copied(),
        user_agent: headers.get(http::header::USER_AGENT).cloned(),
    };

    // Read before the request is consumed: the body the mirror pinned
    // to the header is what the row names.
    let (tool, argument_names) = named_call(&request);
    let handled = server.respond(&source, request).await;

    let mut response = match handled.answer {
        // A notification. This revision defines no client-to-server
        // notification over HTTP, so nothing useful arrives here and the
        // status is transport mechanics rather than a path with a
        // purpose.
        None => StatusCode::ACCEPTED.into_response(),
        Some(answer) => Json(answer).into_response(),
    };
    response.extensions_mut().insert(McpCallRecord {
        tool,
        argument_names,
        outcome: handled.outcome,
    });
    response
}

/// What the node established about one MCP message, for the audit row
/// and the request metric.
///
/// Attached to the response by [`mcp_endpoint`] and read back by
/// [`super::audit`], which is the outermost layer and sees the
/// response after every extension the request carried is gone. Present
/// when the core ran, and on the one refusal the core's constructor
/// made before anything ran: a token spanning two tiers, recorded with
/// [`Outcome::SpansTiers`]. A POST refused by [`examine`] or by a gate
/// in front of it carries none, and the row for it is written from the
/// status and from what the caller claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCallRecord {
    /// The tool the body named on a `tools/call`, which the mirror
    /// check proved equal to `Mcp-Name`. `None` off `tools/call`, and
    /// `None` for a name outside the tool-name grammar, which no tool
    /// has and no row may carry.
    pub tool: Option<String>,
    /// The argument names the call carried that the tool declares, in
    /// catalogue order: the `Param` vocabulary and never a caller's key.
    /// Empty when the catalogue does not know the tool, since no
    /// vocabulary exists to check the keys against.
    pub argument_names: Vec<&'static str>,
    /// What the call came to, in the core's own words.
    pub outcome: Outcome,
}

/// The tool a request names and the declared arguments it carries, or
/// nothing off `tools/call`.
fn named_call(request: &jsonrpc::Request) -> (Option<String>, Vec<&'static str>) {
    if request.method != "tools/call" {
        return (None, Vec::new());
    }
    let tool: Option<String> = request
        .params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| tools::is_legal_tool_name(name))
        .map(str::to_string);
    let argument_names: Vec<&'static str> = match tool.as_deref().and_then(tools::find) {
        Some(spec) => match request.params.get("arguments") {
            Some(Value::Object(arguments)) => spec
                .argument_names()
                .into_iter()
                .filter(|name| arguments.contains_key(*name))
                .collect(),
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    (tool, argument_names)
}

/// What the presented credential is, in the core's own terms.
///
/// The `public_id` and not the token's operator-facing name: the id is
/// what somebody withdraws by, and the name is operator-authored text
/// with nowhere safe to go in an answer a model reads.
fn identity_of(principal: &AutomationPrincipal) -> Identity {
    Identity {
        // The key the invocation budget counts under: the token's
        // `public_id`, or for an ID token its entry and its project,
        // so one project under a shared entry spends only its own.
        public_id: principal.budget_key(),
        scopes: principal
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_string())
            .collect(),
    }
}

/// A POST answered without the core ever seeing it.
#[derive(Debug)]
struct Refusal {
    status: StatusCode,
    body: Option<Value>,
}

impl Refusal {
    /// The revision's `-32020`, under the id the request named.
    fn header_mismatch(id: &Value, detail: &str) -> Refusal {
        Refusal {
            status: StatusCode::BAD_REQUEST,
            body: Some(jsonrpc::error(id, HEADER_MISMATCH, detail)),
        }
    }

    /// A token whose scopes span two MCP tiers, under the id the request
    /// named, with the scopes named.
    ///
    /// `403` because it is the answer this listener gives every refusal
    /// of a credential that authenticated and may not do what it asked:
    /// the scope gate's missing grant and this endpoint's own `Origin`
    /// refusal are both `403`. It is not a `200` carrying an execution
    /// error, because no server was built and no tool could have run,
    /// and it is not a `401`, because the credential is live and the
    /// fix is a different token rather than a valid one. The body is a
    /// JSON-RPC error, as the transport's other refusals are, and names
    /// the scopes: the caller holds the token and reads the same list
    /// from `whoami`.
    ///
    /// The remedy follows the credential. A static token is minted
    /// again per tier; an OIDC issuer entry grants its scopes to every
    /// job its claims match, so the fix is one entry per tier, and
    /// telling a pipeline to run `lorica mcp token create` would name a
    /// command it cannot use.
    fn spans_tiers(id: &Value, refused: &TierError, kind: OwnerKind) -> Refusal {
        let remedy = match kind {
            OwnerKind::StaticToken => refused.remedy_for_static_token(),
            OwnerKind::OidcProject => "This OIDC issuer entry grants its scopes to every job it \
                                       matches: register one entry per tier."
                .to_string(),
        };
        Refusal {
            status: StatusCode::FORBIDDEN,
            body: Some(jsonrpc::error(
                id,
                jsonrpc::code::INVALID_REQUEST,
                &format!("{refused} {remedy}"),
            )),
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self.body {
            Some(body) => (self.status, Json(body)).into_response(),
            None => self.status.into_response(),
        }
    }
}

/// The request to hand the core, or why this POST is answered instead.
///
/// Pure: it reads headers and bytes and touches neither the state nor
/// the network, which is what lets every normative point of the
/// transport be asserted without a listener. The parsed request is what
/// comes back, so the core does not read the same bytes a second time.
fn examine(headers: &HeaderMap, body: &[u8]) -> Result<jsonrpc::Request, Refusal> {
    if headers.contains_key(http::header::ORIGIN) {
        // The body MAY be a JSON-RPC error and carries no id: the
        // request was not read far enough to have one, and inventing
        // one would be answering a correlation that was never made.
        return Err(Refusal {
            status: StatusCode::FORBIDDEN,
            body: Some(jsonrpc::error(
                &Value::Null,
                jsonrpc::code::INVALID_REQUEST,
                "this endpoint serves no browser origin, so an Origin header is refused \
                 whatever it names. An MCP client speaking to it directly sends none.",
            )),
        });
    }

    // The body has to be a JSON-RPC message before a header can be
    // compared against it.
    let Ok(message) = serde_json::from_slice::<Value>(body) else {
        return Err(Refusal {
            status: StatusCode::BAD_REQUEST,
            body: Some(jsonrpc::parse_error()),
        });
    };
    let request = jsonrpc::parse(message).map_err(|refused| Refusal {
        status: StatusCode::BAD_REQUEST,
        body: Some(refused.into_response()),
    })?;
    let id = request.id.clone().unwrap_or(Value::Null);

    let version = match mirrored(headers, PROTOCOL_VERSION_HEADER) {
        Err(why) => return Err(unreadable(&id, PROTOCOL_VERSION_HEADER, why)),
        Ok(None) => {
            return Err(Refusal::header_mismatch(
                &id,
                "every POST on this endpoint carries `mcp-protocol-version`, and it equals \
                 the body's `_meta` protocol version when the body names one",
            ))
        }
        Ok(Some(version)) => version,
    };
    if let Some(claimed) = request.protocol_version() {
        if claimed != version {
            return Err(Refusal::header_mismatch(
                &id,
                "`mcp-protocol-version` does not equal the protocol version the body's \
                 `_meta` names",
            ));
        }
    }
    if version != MCP_PROTOCOL_REVISION {
        // The core's own answer for the same condition, so a client
        // negotiating from `error.data.supportedVersions` reads one
        // shape on either binding; the 400 is the transport's part.
        return Err(Refusal {
            status: StatusCode::BAD_REQUEST,
            body: Some(jsonrpc::unsupported_protocol_version(
                &id,
                MCP_PROTOCOL_REVISION,
            )),
        });
    }

    match mirrored(headers, METHOD_HEADER) {
        Err(why) => return Err(unreadable(&id, METHOD_HEADER, why)),
        Ok(None) => {
            return Err(Refusal::header_mismatch(
                &id,
                "every POST on this endpoint carries `mcp-method`, and it equals the body's \
                 `method`",
            ))
        }
        Ok(Some(declared)) if declared != request.method => {
            return Err(Refusal::header_mismatch(
                &id,
                "`mcp-method` does not equal the body's `method`",
            ))
        }
        Ok(Some(_)) => {}
    }

    let named = match mirrored(headers, NAME_HEADER) {
        Err(why) => return Err(unreadable(&id, NAME_HEADER, why)),
        Ok(named) => named,
    };
    let in_body = request.params.get("name").and_then(Value::as_str);
    let is_call = request.method == "tools/call";
    match (is_call, named.as_deref(), in_body) {
        (true, None, _) => {
            return Err(Refusal::header_mismatch(
                &id,
                "`mcp-name` is required on a tools/call and equals the body's `params.name`",
            ))
        }
        (true, Some(declared), Some(carried)) if declared == carried => {}
        (true, Some(_), _) => {
            return Err(Refusal::header_mismatch(
                &id,
                "`mcp-name` does not equal the body's `params.name`",
            ))
        }
        (false, Some(_), _) => {
            return Err(Refusal::header_mismatch(
                &id,
                "`mcp-name` travels with a tools/call and with nothing else",
            ))
        }
        (false, None, _) => {}
    }

    if !IMPLEMENTED_METHODS.contains(&request.method.as_str()) {
        // 404 and not -32601 in a 200, deliberately: it is how a client
        // tells a server that implements this revision from one that
        // implements an era where the method it asked for existed.
        return Err(Refusal {
            status: StatusCode::NOT_FOUND,
            body: Some(jsonrpc::error(
                &id,
                jsonrpc::code::METHOD_NOT_FOUND,
                "this server implements server/discover, tools/list and tools/call, and \
                 accepts notifications/cancelled",
            )),
        });
    }

    Ok(request)
}

/// The refusal for a header value this server cannot compare to a body.
fn unreadable(id: &Value, header: &str, why: Unreadable) -> Refusal {
    Refusal::header_mismatch(
        id,
        &format!(
            "`{header}` {}, so it cannot be compared to the body",
            why.describe()
        ),
    )
}

/// Why a mirrored header could not be read, so a client developer is
/// told which of the three it was rather than one sentence for all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unreadable {
    /// The value is not visible ASCII text.
    NotText,
    /// A Base64 sentinel whose payload is not Base64.
    NotBase64,
    /// A Base64 sentinel whose payload decodes to bytes that are not
    /// UTF-8.
    NotUtf8,
}

impl Unreadable {
    /// The clause a refusal says, in the node's own words and none of
    /// the caller's.
    fn describe(self) -> &'static str {
        match self {
            Unreadable::NotText => "carries characters this server cannot read as text",
            Unreadable::NotBase64 => "is a Base64 sentinel whose payload is not Base64",
            Unreadable::NotUtf8 => "is a Base64 sentinel whose payload is not UTF-8",
        }
    }
}

/// One header value, Base64-sentinel decoded, or `None` when absent.
///
/// Decoding BEFORE the comparison is the whole point rather than a
/// convenience. A server that compared the raw header to the body would
/// let any mismatch through behind a sentinel that decodes to the body's
/// value, which is to say the mismatch check - the reason the headers
/// are mirrored at all - would be bypassable by anyone who read the
/// specification.
///
/// [`super::audit`] reads `Mcp-Name` through this same function, so the
/// value a row records as claimed is the value this module compared,
/// and a sentinel is never taken raw there either.
///
/// # Errors
///
/// [`Unreadable`] for a value that is not readable text, or a sentinel
/// whose payload is not Base64 of UTF-8.
pub(super) fn mirrored(headers: &HeaderMap, name: &str) -> Result<Option<String>, Unreadable> {
    let Some(raw) = headers.get(name) else {
        return Ok(None);
    };
    let text = raw.to_str().map_err(|_| Unreadable::NotText)?;
    let Some(encoded) = text
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    else {
        return Ok(Some(text.to_string()));
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Unreadable::NotBase64)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| Unreadable::NotUtf8)
}

/// The [`AutomationPlane`] the in-process binding runs: the plane's own
/// router, called with a request this process built.
///
/// No client, no socket and no loopback. The alternative - this adapter
/// dialling the listener it is mounted on - would be refused by the
/// mandatory source-CIDR allowlist or throttled by the per-source
/// connection budget, and it would be spending a TLS handshake to ask
/// the process a question it already holds the answer to.
///
/// What the request carries is what a request over the socket carries
/// once the bearer gate has run: the [`AppState`] extension the handlers
/// read, the [`AutomationPrincipal`] the scope gate and the write
/// handlers read (the grants, the audit identity), the caller's
/// [`ConnectInfo`] so a write's management audit row names the address
/// the MCP POST came from, and the caller's `User-Agent` for the same
/// row. The scope gate runs on every call, so the matrix authorizes an
/// in-process call exactly as it would one over the listener.
pub struct InProcessPlane {
    state: AppState,
    principal: AutomationPrincipal,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    user_agent: Option<HeaderValue>,
}

// There is no public constructor: a plane acts as whatever principal
// it holds without any bearer having been checked, so the one
// production way to build one is the struct literal in `mcp_endpoint`,
// from the principal the outer gate installed. The tests below have a
// constructor of their own, under `cfg(test)`.

impl AutomationPlane for InProcessPlane {
    async fn call(
        &self,
        verb: Verb,
        path: &str,
        body: Option<&Value>,
        reason: Reason<'_>,
    ) -> Result<String, PlaneError> {
        // `reason` names the tool for the trace and for nothing else. It
        // exists so a plane reached from a separate process can be told
        // what the call is for; this one IS the plane, and the audit row
        // for the POST that drove it is written by the layer wrapping
        // this handler, from the request that carried the tool name.
        //
        // The span is the tool call's, a child of the POST's
        // `automation_request` span, and what the handler does runs
        // inside it: the path without its query, which carries the
        // caller's filter values.
        let span = tracing::info_span!(
            "mcp_tool_call",
            "mcp.tool" = reason.tool().unwrap_or_default(),
            "http.request.method" = verb.as_str(),
            "url.path" = path.split_once('?').map_or(path, |(path, _)| path),
        );
        self.answer(verb, path, body).instrument(span).await
    }
}

impl InProcessPlane {
    /// The call [`AutomationPlane::call`] makes, run through
    /// [`super::router::in_process_router`] and answered as text.
    async fn answer(
        &self,
        verb: Verb,
        path: &str,
        body: Option<&Value>,
    ) -> Result<String, PlaneError> {
        let mut request = http::Request::builder().method(verb.as_str()).uri(path);
        if body.is_some() {
            request = request.header(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        if let Some(agent) = &self.user_agent {
            request = request.header(http::header::USER_AGENT, agent.clone());
        }
        let bytes: Vec<u8> = match body {
            Some(body) => serde_json::to_vec(body)
                .map_err(|reason| PlaneError::Transport(reason.to_string()))?,
            None => Vec::new(),
        };
        let mut request = request.body(Body::from(bytes)).map_err(|reason| {
            PlaneError::Transport(format!(
                "automation MCP: a tool built a call the router cannot take: {reason}"
            ))
        })?;
        request.extensions_mut().insert(self.state.clone());
        request.extensions_mut().insert(self.principal.clone());
        if let Some(connect_info) = self.connect_info {
            request.extensions_mut().insert(connect_info);
        }

        let response = match super::router::in_process_router().oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        };
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), MAX_ANSWER_BYTES)
            .await
            .map_err(|reason| PlaneError::Transport(reason.to_string()))?;
        // `Vec::from` takes the buffer the router answered with rather
        // than copying it: the body is one unshared buffer here, which
        // `Bytes` hands over whole.
        let text = String::from_utf8(Vec::from(body))
            .map_err(|_| PlaneError::Transport("the answer is not UTF-8".to_string()))?;
        if status.is_success() {
            Ok(text)
        } else {
            // The status has to survive: `lorica-mcp` turns a refusal
            // from the plane into a tool EXECUTION error the model reads
            // and stops on, rather than a protocol error it would reword
            // and retry, and that distinction is made from the status.
            Err(PlaneError::Refused {
                status: status.as_u16(),
                body: text,
            })
        }
    }
}

#[cfg(test)]
mod plane_tests;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    impl InProcessPlane {
        /// A plane over `state`, calling as `principal` from nowhere in
        /// particular: the shape for a caller that holds no connection,
        /// which only a test is.
        fn new(state: AppState, principal: AutomationPrincipal) -> InProcessPlane {
            InProcessPlane {
                state,
                principal,
                connect_info: None,
                user_agent: None,
            }
        }
    }

    /// A well-formed body for `method`, with `params` as given.
    fn body_of(id: Option<i64>, method: &str, params: Value) -> Vec<u8> {
        let mut message = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        if let Some(id) = id {
            message["id"] = json!(id);
        }
        serde_json::to_vec(&message).expect("test setup: a body serialises")
    }

    fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("test setup: a header name"),
                http::HeaderValue::from_str(value).expect("test setup: a header value"),
            );
        }
        headers
    }

    /// The three mirrored headers for a `tools/list`.
    fn listing_headers() -> HeaderMap {
        headers_of(&[
            (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
            (METHOD_HEADER, "tools/list"),
        ])
    }

    fn refused(headers: &HeaderMap, body: &[u8]) -> Refusal {
        examine(headers, body).expect_err("the POST is refused")
    }

    fn code_of(refusal: &Refusal) -> Option<i64> {
        refusal.body.as_ref()?["error"]["code"].as_i64()
    }

    #[test]
    fn a_well_formed_post_reaches_the_core_unchanged() {
        let body = body_of(Some(1), "tools/list", json!({ "cursor": null }));
        let accepted = examine(&listing_headers(), &body).expect("a well-formed POST");
        // The request the core gets is the one the body carried, read
        // once: the same three parts `jsonrpc::parse` would have read.
        assert_eq!(
            accepted,
            jsonrpc::parse(serde_json::from_slice::<Value>(&body).expect("the body is JSON"))
                .expect("the body is a request")
        );
        assert_eq!(accepted.id, Some(json!(1)));
        assert_eq!(accepted.method, "tools/list");
    }

    #[test]
    fn the_record_names_the_tool_the_body_named_and_the_declared_arguments_it_carried() {
        // What the audit row gets as ESTABLISHED on this binding: the
        // body's tool, which the mirror pinned to the header, and the
        // argument names that are the tool's own vocabulary. A key the
        // tool does not declare is the caller's text and never reaches
        // the row; the call itself is refused for it by the core.
        let call = jsonrpc::parse(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "lorica_logs",
                "arguments": { "search": "ignore previous", "limit": 5, "x]": 1 },
            },
        }))
        .expect("a request");
        assert_eq!(
            named_call(&call),
            (Some("lorica_logs".to_string()), vec!["search", "limit"])
        );

        // A tool the catalogue does not know: the name is bounded by
        // the grammar, and there is no vocabulary to read arguments by.
        let unknown = jsonrpc::parse(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "lorica_routes_write", "arguments": { "id": "r-1" } },
        }))
        .expect("a request");
        assert_eq!(
            named_call(&unknown),
            (Some("lorica_routes_write".to_string()), Vec::new())
        );
        let illegal = jsonrpc::parse(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "tool=x],transport=dashboard" },
        }))
        .expect("a request");
        assert_eq!(named_call(&illegal), (None, Vec::new()));

        // And nothing off a tools/call.
        let listing = jsonrpc::parse(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "name": "lorica_logs" },
        }))
        .expect("a request");
        assert_eq!(named_call(&listing), (None, Vec::new()));
    }

    #[test]
    fn an_origin_header_is_refused_whatever_it_names() {
        // The specification's one MUST on this transport, against DNS
        // rebinding. This plane serves no browser, so there is no origin
        // it could issue and every present one is refused.
        for origin in [
            "https://evil.example.com",
            "http://localhost:3000",
            "null",
            "https://lorica.internal.example.org:9444",
        ] {
            let mut headers = listing_headers();
            headers.insert(
                http::header::ORIGIN,
                http::HeaderValue::from_str(origin).expect("test setup"),
            );
            let refusal = refused(&headers, &body_of(Some(1), "tools/list", json!({})));
            assert_eq!(refusal.status, StatusCode::FORBIDDEN, "{origin}");
            // The body MAY be a JSON-RPC error, and it carries no id:
            // the request was never read far enough to have one.
            assert_eq!(
                refusal.body.as_ref().map(|body| body["id"].clone()),
                Some(Value::Null),
                "{origin}"
            );
        }
    }

    #[test]
    fn every_post_carries_the_protocol_version_and_an_absent_one_is_a_mismatch() {
        let refusal = refused(
            &headers_of(&[(METHOD_HEADER, "tools/list")]),
            &body_of(Some(4), "tools/list", json!({})),
        );
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));
        // Answered under the id the request named, or a client
        // correlating by id cannot match it.
        assert_eq!(refusal.body.map(|body| body["id"].clone()), Some(json!(4)));
    }

    #[test]
    fn a_version_this_server_does_not_implement_names_what_it_does() {
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, "2025-11-25"),
                (METHOD_HEADER, "tools/list"),
            ]),
            &body_of(Some(5), "tools/list", json!({})),
        );
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        let body = refusal.body.expect("a body");
        assert_eq!(
            body["error"]["data"]["name"],
            json!(jsonrpc::UNSUPPORTED_PROTOCOL_VERSION)
        );
        assert_eq!(
            body["error"]["data"]["supportedVersions"],
            json!([MCP_PROTOCOL_REVISION])
        );
        // And it is NOT the mismatch code: a client that cannot speak
        // this revision has a different thing to do about it.
        assert_ne!(body["error"]["code"], json!(HEADER_MISMATCH));
    }

    #[test]
    fn the_version_header_must_equal_the_one_the_body_meta_names() {
        let meta = json!({ "_meta": { jsonrpc::META_PROTOCOL_VERSION: "2025-11-25" } });
        let refusal = refused(&listing_headers(), &body_of(Some(6), "tools/list", meta));
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        // And the agreeing case passes, so the assertion above is about
        // the disagreement and not about `_meta` being present at all.
        let meta = json!({ "_meta": { jsonrpc::META_PROTOCOL_VERSION: MCP_PROTOCOL_REVISION } });
        examine(&listing_headers(), &body_of(Some(6), "tools/list", meta))
            .expect("an agreeing claim passes");
    }

    #[test]
    fn the_method_header_must_equal_the_body_method() {
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "tools/list"),
            ]),
            &body_of(Some(7), "server/discover", json!({})),
        );
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        let refusal = refused(
            &headers_of(&[(PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION)]),
            &body_of(Some(7), "tools/list", json!({})),
        );
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));
    }

    #[test]
    fn the_name_header_is_required_on_a_call_and_must_equal_the_body() {
        let call = body_of(
            Some(8),
            "tools/call",
            json!({ "name": "lorica_logs", "arguments": {} }),
        );
        let mirrored_headers = headers_of(&[
            (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
            (METHOD_HEADER, "tools/call"),
            (NAME_HEADER, "lorica_logs"),
        ]);
        examine(&mirrored_headers, &call).expect("a mirrored call passes");

        // Absent.
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "tools/call"),
            ]),
            &call,
        );
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        // Naming another tool than the body does. This is the whole
        // reason an intermediary validates the mirror: a proxy routing
        // on the header would send one tool where the body asks for
        // another.
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "tools/call"),
                (NAME_HEADER, "lorica_certificates"),
            ]),
            &call,
        );
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        // And it travels with a call and nothing else.
        let mut stray = listing_headers();
        stray.insert(
            http::HeaderName::from_static(NAME_HEADER),
            http::HeaderValue::from_static("lorica_logs"),
        );
        let refusal = refused(&stray, &body_of(Some(8), "tools/list", json!({})));
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));
    }

    #[test]
    fn a_header_is_decoded_out_of_its_base64_sentinel_before_it_is_compared() {
        // The bypass this closes: a server comparing the RAW header to
        // the body accepts any mismatch wearing a sentinel, which makes
        // the check the mirror exists for optional for anyone who read
        // the specification.
        //
        // The wire shape is written out here rather than built from
        // this module's own constants. A test that spelled the sentinel
        // with `SENTINEL_PREFIX` would follow the constant anywhere it
        // went, including somewhere no client speaks, and would still
        // be green while every real sentinel arrived undecoded.
        assert_eq!(SENTINEL_PREFIX, "=?base64?");
        assert_eq!(SENTINEL_SUFFIX, "?=");
        let sentinel = |value: &str| {
            format!(
                "=?base64?{}?=",
                base64::engine::general_purpose::STANDARD.encode(value)
            )
        };
        let call = body_of(
            Some(9),
            "tools/call",
            json!({ "name": "lorica_logs", "arguments": {} }),
        );

        // Encoded and agreeing: accepted, which a raw comparison would
        // have refused.
        examine(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, &sentinel("tools/call")),
                (NAME_HEADER, &sentinel("lorica_logs")),
            ]),
            &call,
        )
        .expect("a sentinel that decodes to the body's value passes");

        // Encoded and disagreeing: refused, which a raw comparison would
        // have accepted.
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "tools/call"),
                (NAME_HEADER, &sentinel("lorica_certificates")),
            ]),
            &call,
        );
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        // A sentinel that is not Base64 of UTF-8 cannot be compared at
        // all, and is the same refusal rather than a value taken raw.
        let refusal = refused(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "=?base64?!!!!?="),
                (NAME_HEADER, "lorica_logs"),
            ]),
            &call,
        );
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));

        // And the version header decodes too, which is the one a
        // reader is most likely to assume is always plain ASCII.
        examine(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, &sentinel(MCP_PROTOCOL_REVISION)),
                (METHOD_HEADER, "tools/call"),
                (NAME_HEADER, "lorica_logs"),
            ]),
            &call,
        )
        .expect("an encoded version that decodes to ours passes");
    }

    #[test]
    fn an_unreadable_header_says_which_of_the_three_it_was() {
        let mut headers = headers_of(&[(METHOD_HEADER, "=?base64?!!!!?=")]);
        assert_eq!(
            mirrored(&headers, METHOD_HEADER),
            Err(Unreadable::NotBase64)
        );
        let not_utf8 = format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe])
        );
        headers = headers_of(&[(METHOD_HEADER, not_utf8.as_str())]);
        assert_eq!(mirrored(&headers, METHOD_HEADER), Err(Unreadable::NotUtf8));
        headers.insert(
            http::HeaderName::from_static(METHOD_HEADER),
            http::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("test setup: a raw value"),
        );
        assert_eq!(mirrored(&headers, METHOD_HEADER), Err(Unreadable::NotText));
        for why in [
            Unreadable::NotText,
            Unreadable::NotBase64,
            Unreadable::NotUtf8,
        ] {
            let refusal = unreadable(&json!(1), METHOD_HEADER, why);
            let message = refusal
                .body
                .as_ref()
                .and_then(|body| body["error"]["message"].as_str())
                .unwrap_or_default()
                .to_string();
            assert!(message.contains(why.describe()), "{message}");
        }
    }

    #[test]
    fn a_header_value_that_is_not_readable_text_is_a_mismatch() {
        let mut headers = headers_of(&[(PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION)]);
        headers.insert(
            http::HeaderName::from_static(METHOD_HEADER),
            http::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("test setup: a raw value"),
        );
        let refusal = refused(&headers, &body_of(Some(10), "tools/list", json!({})));
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        assert_eq!(code_of(&refusal), Some(HEADER_MISMATCH));
    }

    #[test]
    fn a_method_this_server_does_not_implement_is_a_404() {
        // Unusual for a JSON-RPC server and deliberate: it is how a
        // client tells this revision from the eras it replaced.
        for method in ["initialize", "resources/list", "prompts/get", "shutdown"] {
            let refusal = refused(
                &headers_of(&[
                    (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                    (METHOD_HEADER, method),
                ]),
                &body_of(Some(11), method, json!({})),
            );
            assert_eq!(refusal.status, StatusCode::NOT_FOUND, "{method}");
            assert_eq!(
                code_of(&refusal),
                Some(jsonrpc::code::METHOD_NOT_FOUND),
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn the_methods_this_endpoint_routes_are_the_ones_the_core_implements() {
        // `IMPLEMENTED_METHODS` is this transport's statement about
        // somebody else's dispatch, so it is checked against that
        // dispatch rather than kept in step by memory: a method the core
        // gains answers something other than METHOD_NOT_FOUND, and one
        // it loses answers exactly that.
        struct Nothing;
        impl AutomationPlane for Nothing {
            async fn call(
                &self,
                _verb: Verb,
                _path: &str,
                _body: Option<&Value>,
                _reason: Reason<'_>,
            ) -> Result<String, PlaneError> {
                Ok("{\"data\":{}}".to_string())
            }
        }

        let server = McpServer::over(Identity {
            public_id: "0123456789abcdef01234567".to_string(),
            scopes: vec!["logs:read".to_string()],
        })
        .expect("a token of one tier");
        for method in IMPLEMENTED_METHODS {
            // A notification carries no id, and the core answers one
            // with silence. Sending it as a request would ask a
            // different question and get METHOD_NOT_FOUND for a reason
            // that is not the one under test.
            let is_notification = method.starts_with("notifications/");
            let message = if is_notification {
                json!({ "jsonrpc": "2.0", "method": method })
            } else {
                json!({ "jsonrpc": "2.0", "id": 1, "method": method,
                        "params": { "name": "lorica_logs" } })
            };
            match server.handle(&Nothing, message).await {
                None => assert!(is_notification, "{method} answered nothing"),
                Some(answer) => assert_ne!(
                    answer["error"]["code"],
                    json!(jsonrpc::code::METHOD_NOT_FOUND),
                    "{method} is routed here and unknown to the core"
                ),
            }
        }
        for outside in ["initialize", "resources/list", "sampling/createMessage"] {
            let answered = server
                .handle(
                    &Nothing,
                    json!({ "jsonrpc": "2.0", "id": 1, "method": outside }),
                )
                .await
                .expect("a request is answered");
            assert_eq!(
                answered["error"]["code"],
                json!(jsonrpc::code::METHOD_NOT_FOUND),
                "{outside} is not routed here and the core answers it"
            );
        }
    }

    #[test]
    fn a_notification_passes_the_transport_and_the_core_answers_it_with_silence() {
        // The 202 is the handler's, because the core returning `None`
        // is what says there is nothing to send. What this asserts is
        // that a notification is not refused on its way there.
        let accepted = examine(
            &headers_of(&[
                (PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_REVISION),
                (METHOD_HEADER, "notifications/cancelled"),
            ]),
            &body_of(None, "notifications/cancelled", json!({ "requestId": 1 })),
        )
        .expect("a notification passes");
        assert!(accepted.is_notification());
    }

    #[test]
    fn a_body_that_is_not_a_jsonrpc_message_is_refused_before_any_header_is_read() {
        let refusal = refused(&listing_headers(), b"<html>not json</html>");
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        assert_eq!(code_of(&refusal), Some(jsonrpc::code::PARSE_ERROR));

        let refusal = refused(&listing_headers(), b"{\"id\":1}");
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
        assert_eq!(code_of(&refusal), Some(jsonrpc::code::INVALID_REQUEST));
    }

    #[test]
    fn the_headers_this_revision_removed_are_ignored_and_never_read() {
        // No protocol-level session, no resumable stream. Both headers
        // are accepted and do nothing, and neither appears anywhere this
        // module acts on.
        let mut headers = listing_headers();
        headers.insert(
            http::HeaderName::from_static(SESSION_ID_HEADER),
            http::HeaderValue::from_static("a-session-from-an-older-era"),
        );
        headers.insert(
            http::HeaderName::from_static(LAST_EVENT_ID_HEADER),
            http::HeaderValue::from_static("42"),
        );
        examine(&headers, &body_of(Some(12), "tools/list", json!({})))
            .expect("a removed header changes nothing");

        // Asserted against this file's own source: both constants exist
        // to be named as ignored, so neither may reach a `get` or a
        // `contains_key`. That an answer never echoes a session id is
        // asserted through the whole stack in `plane_tests`.
        let source = include_str!("mcp.rs");
        let body = source.split("#[cfg(test)]").next().unwrap_or(source);
        for ignored in ["SESSION_ID_HEADER", "LAST_EVENT_ID_HEADER"] {
            for reading in [
                format!("get({ignored})"),
                format!("contains_key({ignored})"),
                format!("mirrored(headers, {ignored})"),
            ] {
                assert!(!body.contains(&reading), "{reading} is in this module");
            }
        }
    }

    #[test]
    fn this_module_opens_no_connection_of_its_own() {
        // The in-process plane must not loop back over the listener it
        // is mounted on: the mandatory source-CIDR allowlist and the
        // per-source connection budget would refuse or throttle it, and
        // it would be absurd regardless. Asserted against the source
        // rather than promised in the comment above it.
        let source = include_str!("mcp.rs");
        let body = source.split("#[cfg(test)]").next().unwrap_or(source);
        for dialled in ["reqwest", "TcpStream", "connect(", "https://"] {
            assert!(
                !body.contains(dialled),
                "{dialled} appears in the in-process MCP adapter"
            );
        }
        // And the scan is worth something: the router it is meant to
        // run the call through instead really is called here, and no
        // read handler is called by hand any more.
        assert!(body.contains("in_process_router()"));
        assert!(!body.contains("super::read::"));
    }

    /// A principal carrying exactly `scopes`, with the grants the
    /// write tests use.
    fn principal_carrying(
        scopes: Vec<lorica_config::models::AutomationScope>,
    ) -> AutomationPrincipal {
        AutomationPrincipal {
            kind: lorica_config::models::OwnerKind::StaticToken,
            principal: "mcp-in-process".to_string(),
            grant_id: "0123456789abcdef01234567".to_string(),
            scopes,
            allowed_hostnames: vec!["*.write.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            pipeline: None,
            required_environment_slug: None,
        }
    }

    /// Backlog #92 (d): what one MCP read answer at the plane's byte
    /// ceiling costs on the in-process binding, the plane's half and the
    /// whole call apart. A measurement and not a gate, since its figures
    /// are the machine's: run it by name with `--ignored --nocapture`.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "a measurement, not a gate: run it by name with --ignored --nocapture"]
    async fn measure_an_mcp_read_answer_at_the_byte_ceiling() {
        use lorica_config::models::AutomationScope;
        use std::time::{Duration, Instant};

        const WARM_UP: u32 = 20;
        const ROUNDS: u32 = 300;

        let (state, _session_store, _rate_limiter) = crate::tests::test_state().await;
        // Paths carrying characters JSON escapes, so the answer pays
        // for escaping as a real one does, and enough of them that the
        // byte ceiling, not the row limit, ends the window.
        for n in 0..300u64 {
            state.log_buffer.push(crate::logs::LogEntry {
                id: 0,
                timestamp: "2026-09-30T00:00:00Z".to_string(),
                method: "GET".to_string(),
                path: format!("/measured/{n}/{}", "a\"b\\c/".repeat(160)),
                host: "measure.example.com".to_string(),
                status: 200,
                latency_ms: 1,
                backend: "10.0.0.10:8080".to_string(),
                error: None,
                client_ip: "192.0.2.10".to_string(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: format!("measured-{n}"),
            });
        }
        let plane = InProcessPlane::new(state, principal_carrying(vec![AutomationScope::LogsRead]));
        let call = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "lorica_logs", "arguments": { "limit": 200 } },
        });

        let mut plane_time = Duration::ZERO;
        let mut plane_bytes = 0usize;
        for round in 0..WARM_UP + ROUNDS {
            let started = Instant::now();
            let text = plane
                .call(
                    Verb::Get,
                    "/automation/v1/logs?limit=200",
                    None,
                    Reason::Tool("lorica_logs"),
                )
                .await
                .expect("the read answers");
            if round >= WARM_UP {
                plane_time += started.elapsed();
            }
            plane_bytes = text.len();
        }

        let mut call_time = Duration::ZERO;
        let mut answer_bytes = 0usize;
        for round in 0..WARM_UP + ROUNDS {
            // A server per call, as the endpoint builds one per request,
            // with its own limiter so the budget never answers instead.
            let server = McpServer::sharing(
                Identity {
                    public_id: "0123456789abcdef01234567".to_string(),
                    scopes: vec!["logs:read".to_string()],
                },
                Arc::new(lorica_mcp::server::InvocationLimiter::new()),
            )
            .expect("one tier");
            let request = jsonrpc::parse(call.clone()).expect("a request");
            let started = Instant::now();
            let handled = server.respond(&plane, request).await;
            // What the endpoint's `Json(answer)` writes.
            let written = serde_json::to_vec(&handled.answer.expect("an answer"))
                .expect("the answer serialises");
            if round >= WARM_UP {
                call_time += started.elapsed();
            }
            answer_bytes = written.len();
        }

        println!(
            "plane answer {plane_bytes} bytes, {:?} per call; whole MCP call {answer_bytes} \
             bytes, {:?} per call; over {ROUNDS} rounds",
            plane_time / ROUNDS,
            call_time / ROUNDS,
        );
    }

    #[tokio::test]
    async fn the_in_process_plane_runs_the_scope_gate_and_refuses_what_the_matrix_refuses() {
        // The property Story 11.2 bought by routing in process instead
        // of dispatching by hand: a call that reaches a handler through
        // this plane has passed `authorize_scope`, so a token lacking
        // the scope its path sits behind is refused by the plane with
        // the same 403 the listener would answer, whatever `lorica-mcp`
        // registered. The old dispatch ran no gate at all.
        use lorica_config::models::AutomationScope;

        let (state, _session_store, _rate_limiter) = crate::tests::test_state().await;

        let lacking = InProcessPlane::new(
            state.clone(),
            principal_carrying(vec![AutomationScope::WafRead]),
        );
        let refused = lacking
            .call(
                Verb::Get,
                "/automation/v1/logs",
                None,
                Reason::Tool("lorica_logs"),
            )
            .await
            .expect_err("a scope the principal lacks is refused in process");
        match refused {
            PlaneError::Refused { status, body } => {
                assert_eq!(status, 403);
                assert!(body.contains("logs:read"), "{body}");
            }
            PlaneError::Transport(reason) => panic!("not a refusal: {reason}"),
        }
        // A write behind a scope the principal lacks, the same way, and
        // before the handler could look at the body.
        let refused = lacking
            .call(
                Verb::Post,
                "/automation/v1/routes",
                Some(&json!({ "hostname": "app.write.example.com" })),
                Reason::Tool("lorica_route_create"),
            )
            .await
            .expect_err("a write scope the principal lacks is refused in process");
        assert!(
            matches!(refused, PlaneError::Refused { status: 403, .. }),
            "{refused}"
        );

        // With the scope, the same call reaches the handler, which
        // answers as it would over the socket.
        let holding = InProcessPlane::new(
            state.clone(),
            principal_carrying(vec![
                AutomationScope::LogsRead,
                AutomationScope::RoutesWrite,
            ]),
        );
        let answered = holding
            .call(
                Verb::Get,
                "/automation/v1/logs",
                None,
                Reason::Tool("lorica_logs"),
            )
            .await
            .expect("the read answers");
        let answered: Value = serde_json::from_str(&answered).expect("JSON");
        assert!(answered["data"]["items"].is_array(), "{answered}");

        // A write's body reaches the handler and its validators: the
        // refusal is the management plane's own, with its status.
        let refused = holding
            .call(
                Verb::Post,
                "/automation/v1/routes",
                Some(&json!({ "hostname": "app.write.example.com", "connect_timeout_s": 0 })),
                Reason::Tool("lorica_route_create"),
            )
            .await
            .expect_err("a validator refuses");
        match refused {
            PlaneError::Refused { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("connect_timeout_s"), "{body}");
            }
            PlaneError::Transport(reason) => panic!("not a refusal: {reason}"),
        }

        // And a path the matrix declares for nobody is refused for a
        // principal carrying every scope: the fail-closed default holds
        // in process as on the listener.
        let widest = InProcessPlane::new(state, principal_carrying(AutomationScope::ALL.to_vec()));
        let refused = widest
            .call(
                Verb::Post,
                "/automation/v1/certificates",
                Some(&json!({ "domain": "x" })),
                Reason::Tool("lorica_certificates"),
            )
            .await
            .expect_err("an undeclared path is refused");
        assert!(
            matches!(refused, PlaneError::Refused { status: 403, .. }),
            "{refused}"
        );
        // The MCP endpoint itself is not in the in-process router: a
        // tool cannot call the endpoint that is running it.
        let refused = widest
            .call(Verb::Post, MCP_PATH, Some(&json!({})), Reason::Tool("x"))
            .await
            .expect_err("the endpoint is not reachable from inside itself");
        assert!(
            matches!(refused, PlaneError::Refused { status: 404, .. }),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn every_declared_path_reaches_its_handler_in_process() {
        // In process equals the listener minus authentication and
        // audit, and that must hold by structure and not by memory:
        // `InProcessPlane::call` inserts the state, the principal and
        // the connection info by hand, so a handler that came to
        // extract something only a listener layer provides would work
        // over the socket and fail here with an extractor rejection,
        // a 500. Every path the matrix declares, walked with a
        // principal carrying every scope: no 500, and no 403, since
        // the scope gate has nothing to refuse it.
        use crate::automation::scope::{READ_SURFACE, WRITE_SURFACE};
        use lorica_config::models::AutomationScope;

        let (state, _session_store, _rate_limiter) = crate::tests::test_state().await;
        let plane = InProcessPlane::new(state, principal_carrying(AutomationScope::ALL.to_vec()));
        let mut walked = 0usize;
        let mut assert_reached = |what: String, answered: Result<String, PlaneError>| {
            walked += 1;
            match answered {
                Ok(_) => {}
                Err(PlaneError::Refused { status, body }) => {
                    assert!(
                        status < 500 && status != 403,
                        "{what} answered {status} in process: {body}"
                    );
                }
                Err(PlaneError::Transport(reason)) => panic!("{what}: {reason}"),
            }
        };
        for (path, _) in READ_SURFACE {
            let answered = plane
                .call(Verb::Get, path, None, Reason::Tool("walk"))
                .await;
            assert_reached(format!("GET {path}"), answered);
        }
        for (method, path, _) in WRITE_SURFACE {
            let verb = match *method {
                "POST" => Verb::Post,
                "PUT" => Verb::Put,
                "DELETE" => Verb::Delete,
                other => panic!("{other} is not a verb the seam carries"),
            };
            let body = (verb != Verb::Delete).then(|| json!({}));
            let answered = plane
                .call(verb, path, body.as_ref(), Reason::Tool("walk"))
                .await;
            assert_reached(format!("{method} {path}"), answered);
        }
        assert_eq!(walked, READ_SURFACE.len() + WRITE_SURFACE.len());
    }

    #[test]
    fn the_router_mounts_the_path_this_module_declares() {
        // The listener mounts this constant for `POST` and no other
        // verb, the shape the revision gives the endpoint.
        let verbs: Vec<http::Method> = crate::automation::route_table()
            .into_iter()
            .filter(|route| route.path == MCP_PATH)
            .map(|route| route.method)
            .collect();
        assert_eq!(
            verbs,
            vec![http::Method::POST],
            "{MCP_PATH} mounts {verbs:?}"
        );
    }
}
