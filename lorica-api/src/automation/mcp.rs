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

//! Story 11.1 AC #9: the Streamable HTTP binding of the MCP read tier,
//! as ONE path on the Story 10.3 automation listener.
//!
//! # Why it lives here and not in `lorica-mcp`
//!
//! PRD decision D1: an operator who has not enabled the automation
//! listener gains no MCP surface. So this is not a third management
//! plane, not a second port and not a second listener. It is a path on
//! the listener that already owns the TLS, the mandatory source-CIDR
//! allowlist, the connection caps, the per-IP limiter and the
//! per-request audit, and everything below inherits all six by being
//! mounted inside [`super::router::build_automation_router`].
//!
//! The protocol itself is not here. [`lorica_mcp::server::McpServer`] is
//! the shared core AC #10 asks for, the same one the stdio binary runs;
//! this module is the transport around it and decides nothing a method
//! means.
//!
//! # The read source does not dial its own listener
//!
//! [`InProcessReads`] implements [`ReadSource`] against
//! [`super::read`]'s handlers directly. Looping back over the socket
//! would be refused or throttled by the plane's own source allowlist and
//! per-source connection budget, and would be absurd if it were not: the
//! process holds the state the request is about.
//!
//! # Authorization is per tool, because the request carries the tool
//!
//! The scope matrix declares one requirement per path, and an MCP
//! request carries its own tool with its own scope, so the endpoint
//! cannot be declared behind any single scope. It is declared
//! [`super::ScopeRequirement::AnyLiveToken`], and the authorization that
//! matters happens per call: [`McpServer::over`] registers only the
//! tools the presented token's scopes cover, so a tool the caller cannot
//! reach is absent from its `tools/list` and unknown to its
//! `tools/call`. The specification blesses exactly this - a tool set
//! "MAY vary by the authorization presented on the request ... since
//! credentials are per-request input, not connection state" - while
//! forbidding variation per connection, which nothing here does: the
//! registry is built from the request's own principal and dropped with
//! it.
//!
//! The scope each tool names is `lorica-mcp`'s, and the scope each path
//! sits behind is [`super::scope::required_scope`]'s. They are two
//! statements of one rule, so `tests/mcp_catalogue_scopes.rs` pins them
//! against each other, one assertion per tool.
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

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use http::{HeaderMap, StatusCode, Uri};
use lorica_mcp::server::{Identity, McpServer, Outcome};
use lorica_mcp::{jsonrpc, tools, ReadError, ReadSource, Reason, MCP_PROTOCOL_REVISION};
use percent_encoding::percent_decode_str;
use serde_json::Value;

use super::auth::AutomationPrincipal;
use crate::error::ApiError;
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

/// The most bytes of a refusal body carried back across the read seam.
///
/// The plane's own error envelope is two short fields; this is here so a
/// handler that somehow answered a large body cannot choose this
/// process's memory on the way to a tool result.
const MAX_REFUSAL_BYTES: usize = 64 * 1024;

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
    // registry.
    let server = McpServer::sharing(identity_of(&principal), Arc::clone(&state.mcp_invocations));
    let source = InProcessReads { state };

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
/// only when the core ran: a POST refused by [`examine`] or by a gate
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
                .params()
                .iter()
                .map(|param| param.name)
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
        public_id: principal.grant_id.clone(),
        scopes: principal
            .scopes
            .iter()
            .filter_map(|scope| {
                serde_json::to_value(scope)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
            })
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
        Err(()) => return Err(unreadable(&id, PROTOCOL_VERSION_HEADER)),
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
        Err(()) => return Err(unreadable(&id, METHOD_HEADER)),
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
        Err(()) => return Err(unreadable(&id, NAME_HEADER)),
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
fn unreadable(id: &Value, header: &str) -> Refusal {
    Refusal::header_mismatch(
        id,
        &format!(
            "`{header}` carries characters this server cannot read as text, so it cannot be \
             compared to the body"
        ),
    )
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
/// `()` for a value that is not readable text, or a sentinel whose
/// payload is not Base64 of UTF-8.
pub(super) fn mirrored(headers: &HeaderMap, name: &str) -> Result<Option<String>, ()> {
    let Some(raw) = headers.get(name) else {
        return Ok(None);
    };
    let text = raw.to_str().map_err(|_| ())?;
    let Some(encoded) = text
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    else {
        return Ok(Some(text.to_string()));
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ())?;
    String::from_utf8(bytes).map(Some).map_err(|_| ())
}

/// The [`ReadSource`] the in-process binding runs, over the read
/// handlers themselves.
///
/// No client, no socket and no loopback. The alternative - this adapter
/// dialling the listener it is mounted on - would be refused by the
/// mandatory source-CIDR allowlist or throttled by the per-source
/// connection budget, and it would be spending a TLS handshake to ask
/// the process a question it already holds the answer to.
pub struct InProcessReads {
    state: AppState,
}

impl InProcessReads {
    /// A read source over `state`.
    pub fn new(state: AppState) -> InProcessReads {
        InProcessReads { state }
    }

    /// One read view, as the handler that owns it answers.
    ///
    /// The arms are the paths [`super::scope`] declares, reached through
    /// its own constants rather than through strings typed again here.
    /// A tool naming a path with no arm is a wiring fault and answers
    /// 500: the test that drives every registered tool through this
    /// source is what stops one reaching a release.
    ///
    /// # Errors
    ///
    /// Whatever the read handler answers, plus `BadRequest` for a query
    /// string the handler's own filter struct refuses.
    async fn read(&self, path: &str) -> Result<String, ApiError> {
        use super::scope::{
            BACKENDS_PATH, CERTIFICATES_PATH, CLUSTER_STATUS_PATH, LOGS_PATH, ROUTES_PATH,
            SLA_OVERVIEW_PATH, SLA_ROUTES_PATH, WAF_EVENTS_PATH, WAF_STATS_PATH,
        };

        let uri: Uri = path.parse().map_err(|_| {
            ApiError::Internal(format!(
                "automation MCP: a tool built a path that is not a URI: {path}"
            ))
        })?;
        let route = uri.path().to_string();
        let state = || Extension(self.state.clone());

        let answered = match route.as_str() {
            LOGS_PATH => super::read::list_logs(state(), query(&uri)?, query(&uri)?).await?,
            WAF_EVENTS_PATH => {
                super::read::list_waf_events(state(), query(&uri)?, query(&uri)?).await?
            }
            WAF_STATS_PATH => super::read::waf_stats(state()).await?,
            SLA_OVERVIEW_PATH => super::read::sla_overview(state(), query(&uri)?).await?,
            CLUSTER_STATUS_PATH => super::read::cluster_status(state()).await?,
            BACKENDS_PATH => super::read::list_backends(state(), query(&uri)?).await?,
            ROUTES_PATH => super::read::list_routes(state(), query(&uri)?, query(&uri)?).await?,
            CERTIFICATES_PATH => super::read::list_certificates(state(), query(&uri)?).await?,
            _ => match one_segment_under(&route, SLA_ROUTES_PATH) {
                Some(id) => super::read::route_sla(state(), Path(id), query(&uri)?).await?,
                None => {
                    return Err(ApiError::Internal(format!(
                        "automation MCP: no read is mounted in process at {route}"
                    )))
                }
            },
        };
        serde_json::to_string(&answered.0)
            .map_err(|reason| ApiError::Internal(format!("automation MCP: {reason}")))
    }
}

impl ReadSource for InProcessReads {
    async fn fetch(&self, path: &str, _reason: Reason<'_>) -> Result<String, ReadError> {
        // `reason` is unused here and that is the honest shape. It exists
        // so a source reaching a REMOTE plane can declare what the read
        // was for; this one IS the plane, and the audit row for the POST
        // that drove it is written by the layer wrapping this handler,
        // from the request that carried the tool name.
        match self.read(path).await {
            Ok(body) => Ok(body),
            Err(error) => Err(refusal(error).await),
        }
    }
}

/// The resource id one segment under `collection`, percent-decoded.
///
/// The tool layer encodes the segment whole, so the decoding here is
/// what the listener's own path extractor would have done. Nothing wider
/// than one segment is accepted, which is the property that keeps a
/// route id from moving a read onto another path.
fn one_segment_under(path: &str, collection: &str) -> Option<String> {
    let last = path
        .strip_prefix(collection)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|last| !last.is_empty() && !last.contains('/'))?;
    Some(percent_decode_str(last).decode_utf8_lossy().into_owned())
}

/// One typed query struct out of a built path.
///
/// # Errors
///
/// `BadRequest` carrying the extractor's own words, which is what the
/// listener would have answered for the same query string.
fn query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<Query<T>, ApiError> {
    Query::try_from_uri(uri).map_err(|rejection| ApiError::BadRequest(rejection.body_text()))
}

/// An API refusal as the seam carries it, status kept.
///
/// The status has to survive: `lorica-mcp` turns a refusal from the
/// plane into a tool EXECUTION error the model reads and stops on,
/// rather than a protocol error it would reword and retry, and that
/// distinction is made from the status.
async fn refusal(error: ApiError) -> ReadError {
    let response = error.into_response();
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), MAX_REFUSAL_BYTES)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    ReadError::Refused { status, body }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
        impl ReadSource for Nothing {
            async fn fetch(&self, _path: &str, _reason: Reason<'_>) -> Result<String, ReadError> {
                Ok("{\"data\":{}}".to_string())
            }
        }

        let server = McpServer::over(Identity {
            public_id: "0123456789abcdef01234567".to_string(),
            scopes: vec!["logs:read".to_string()],
        });
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
        // asserted through the whole stack in `crate::tests`.
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
        // The in-process source must not loop back over the listener it
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
        // And the scan is worth something: the handlers it is meant to
        // call instead really are called here.
        assert!(body.contains("super::read::list_logs"));
    }

    #[test]
    fn the_router_mounts_the_path_this_module_declares() {
        // The OpenAPI gate reads `router.rs` for string literals, so the
        // route is spelled there rather than referenced. This is what
        // keeps that literal and this constant one path.
        let router = include_str!("router.rs");
        assert!(
            router.contains(&format!("\"{MCP_PATH}\"")),
            "{MCP_PATH} is not mounted in router.rs"
        );
    }

    #[test]
    fn a_resource_segment_is_decoded_the_way_the_listener_would_have() {
        let collection = crate::automation::scope::SLA_ROUTES_PATH;
        assert_eq!(
            one_segment_under("/automation/v1/sla/routes/r%2D1", collection).as_deref(),
            Some("r-1")
        );
        // A traversal attempt was encoded whole by the tool layer, so it
        // decodes to one id that names no route rather than to a path.
        assert_eq!(
            one_segment_under(
                "/automation/v1/sla/routes/%2E%2E%2F%2E%2E%2Fwhoami",
                collection
            )
            .as_deref(),
            Some("../../whoami")
        );
        // The collection itself is not one segment under itself.
        assert_eq!(
            one_segment_under("/automation/v1/sla/routes", collection),
            None
        );
        assert_eq!(
            one_segment_under("/automation/v1/sla/routes/a/b", collection),
            None
        );
    }
}
