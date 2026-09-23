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

//! The protocol core: the methods revision 2026-07-28 defines, over the
//! tools the presented token turns out to be allowed.
//!
//! # It performs no I/O
//!
//! [`McpServer::handle`] takes a parsed message and answers a value.
//! Reading a line, writing a line, framing and every socket belong to
//! the adapters, and the one thing here that reaches the network does
//! it through [`ReadSource`], which is somebody else's implementation.
//! That is what makes AC #10's "one shared core, two bindings" a
//! property of the code rather than a promise.
//!
//! # Asks before it offers
//!
//! AC #3: on startup the server calls `whoami`, learns what its own
//! token carries, and registers the tools those scopes cover and no
//! others. The specification blesses this explicitly - a tool set "MAY
//! vary by the authorization presented on the request, for example
//! returning only the tools the caller's granted scopes permit" - so
//! the tier design is the sanctioned pattern rather than a deviation.
//!
//! The registry is built once, here, and never reconsulted. Nothing
//! re-reads scopes on a running server, which is what keeps Story
//! 11.4's one-process-one-tier check cheap to add later.
//!
//! # A token with no tool still starts
//!
//! Minting refuses an empty scope array, so the case AC #3 names is
//! never a scopeless token: it is a token carrying scopes none of which
//! this tier uses. Such a server starts, publishes an empty tool list
//! and says why in [`McpServer::startup_notice`], which an adapter puts
//! where an operator reads it. A server whose every call failed would
//! be the same fault reported once per call and never explained.
//!
//! # The invocation budget is the token's, not the server's
//!
//! Revision 2026-07-28 requires a server to rate limit tool
//! invocations. The budget is spent through an [`InvocationLimiter`]
//! keyed by the token's `public_id`, and the limiter is a value an
//! adapter may hold for longer than one server: stdio builds one server
//! for the life of the process and the limiter lives and dies with it,
//! while the Streamable HTTP binding builds a server per request and
//! hands every one of them the same process-wide limiter, so a token's
//! window survives the request that opened it. A budget that lived on
//! the server alone would count one call per request on that binding
//! and refuse nothing, which is what the first cut of it did.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::jsonrpc::{self, code, Request};
use crate::tools::{self, ToolSpec};
use crate::untrusted;
use crate::{ReadError, ReadSource, Reason, MCP_PROTOCOL_REVISION};

/// Where the automation plane reports the calling token back to it.
const WHOAMI_PATH: &str = "/automation/v1/whoami";

/// The most tool invocations one token runs in [`RATE_WINDOW`].
///
/// One of the four server MUSTs revision 2026-07-28 puts on tools is to
/// rate limit invocations, and the automation listener's own budgets do
/// not meet it: they count connections at accept, and a keep-alive or
/// HTTP/2 caller issues requests without opening one. So the budget is
/// here, in the core, spent per token through an [`InvocationLimiter`]
/// that both bindings pass through. It bounds a model in a retry loop,
/// not an operator: an operator reading a log does not make two calls
/// a second for a minute.
pub const RATE_BUDGET: u32 = 120;

/// The window [`RATE_BUDGET`] is spent over.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// The most tokens whose windows one [`InvocationLimiter`] holds.
///
/// A window is opened by a token that authenticated, so growing the map
/// takes a live credential per entry; the ceiling is there so that even
/// a stream of them cannot choose this process's memory. It is far above
/// the number of MCP tokens any one node is minted for. When it is
/// reached, windows that have already elapsed are dropped first, and a
/// token that still finds no room is refused for that call rather than
/// given somebody else's window: evicting a live window would hand a
/// caller holding more tokens than the ceiling a fresh budget per call.
pub const MAX_TRACKED_TOKENS: usize = 1024;

/// What the automation plane says this server's own token is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The id an operator withdraws the token by.
    ///
    /// The token's operator-facing NAME is deliberately not kept: it is
    /// operator-authored text and the only place this would print is a
    /// notice, where the id is what somebody acts on anyway.
    pub public_id: String,
    /// Every scope the token carries, as the plane spells them.
    pub scopes: Vec<String>,
}

/// Why the server could not work out what it is.
#[derive(Debug)]
pub enum StartupError {
    /// `whoami` could not be reached, or refused.
    ///
    /// A refusal here means the token is not live: `whoami` is the one
    /// path the plane lets any live token reach, whatever it carries.
    Introspection(ReadError),
    /// `whoami` answered something that is not a whoami answer.
    Unreadable,
}

impl core::fmt::Display for StartupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartupError::Introspection(reason) => write!(
                f,
                "cannot read {WHOAMI_PATH} to find out what this token may do: {reason}"
            ),
            StartupError::Unreadable => write!(
                f,
                "{WHOAMI_PATH} answered something with no string `data.public_id` and no \
                 array of strings at `data.scopes`. Check that the endpoint is a Lorica \
                 automation listener and not something in front of one."
            ),
        }
    }
}

impl std::error::Error for StartupError {}

/// A fixed window of tool invocations.
struct Budget {
    opened: Instant,
    spent: u32,
}

/// Tool-invocation windows, one per token, for every server built over
/// it.
///
/// See the module documentation for why this is a value of its own
/// rather than a field the server owns. The lock is held across integer
/// comparisons and never across an `await`.
#[derive(Default)]
pub struct InvocationLimiter {
    windows: Mutex<HashMap<String, Budget>>,
}

impl InvocationLimiter {
    /// A limiter with no window open.
    pub fn new() -> InvocationLimiter {
        InvocationLimiter::default()
    }

    /// Whether one more invocation by `public_id` fits in its current
    /// window, spending it when it does.
    ///
    /// `false` when the window is spent, and also when this token has
    /// no window yet and [`MAX_TRACKED_TOKENS`] live ones are already
    /// held: see that constant for why that refuses rather than evicts.
    pub fn allow(&self, public_id: &str) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if let Some(budget) = windows.get_mut(public_id) {
            if now.duration_since(budget.opened) >= RATE_WINDOW {
                budget.opened = now;
                budget.spent = 0;
            }
            if budget.spent >= RATE_BUDGET {
                return false;
            }
            budget.spent += 1;
            return true;
        }
        if windows.len() >= MAX_TRACKED_TOKENS {
            windows.retain(|_, budget| now.duration_since(budget.opened) < RATE_WINDOW);
            if windows.len() >= MAX_TRACKED_TOKENS {
                return false;
            }
        }
        windows.insert(
            public_id.to_string(),
            Budget {
                opened: now,
                spent: 1,
            },
        );
        true
    }

    /// How many tokens currently hold a window.
    pub fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// What one message came to, in a closed vocabulary an adapter can
/// audit and count without reading the answer back.
///
/// The Streamable HTTP binding answers every message the core produced
/// with a 200, so a transport that keyed its audit row on the status
/// would record a refused tool call as a success. This is the fact the
/// core knows and the answer alone does not always say: a rate-limit
/// refusal and a plane refusal are both `isError: true` results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A notification: nothing to answer and nothing ran.
    Silence,
    /// The method answered, and a tool that ran succeeded.
    Ok,
    /// A `tools/call` naming a tool this server does not register,
    /// whether the catalogue knows it or not. No read was attempted.
    ToolNotRegistered,
    /// The arguments did not fit the declared schema, or `tools/list`
    /// carried a cursor. No read was attempted.
    InvalidParams,
    /// The token is over [`RATE_BUDGET`] in this window, or the limiter
    /// holds no room for it. No read was attempted.
    RateLimited,
    /// The tool ran and the automation plane refused its read with this
    /// HTTP status.
    Refused(u16),
    /// The tool ran and the plane could not be reached, or answered
    /// something that is not JSON.
    Failed,
    /// A message too malformed to place, or one claiming a protocol
    /// revision this server does not speak.
    ProtocolError,
}

impl core::fmt::Display for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Outcome::Silence => f.write_str("silence"),
            Outcome::Ok => f.write_str("ok"),
            Outcome::ToolNotRegistered => f.write_str("tool_not_registered"),
            Outcome::InvalidParams => f.write_str("invalid_params"),
            Outcome::RateLimited => f.write_str("rate_limited"),
            Outcome::Refused(status) => write!(f, "refused:{status}"),
            Outcome::Failed => f.write_str("failed"),
            Outcome::ProtocolError => f.write_str("protocol_error"),
        }
    }
}

/// One message, answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    /// What to send back, or `None` for a notification.
    pub answer: Option<Value>,
    /// What it came to.
    pub outcome: Outcome,
}

/// The protocol core, over the tools this token turned out to allow.
pub struct McpServer {
    identity: Identity,
    registered: Vec<&'static ToolSpec>,
    limiter: Arc<InvocationLimiter>,
}

impl McpServer {
    /// Ask the plane what this token carries, then register the tools
    /// it covers.
    ///
    /// # Errors
    ///
    /// [`StartupError::Introspection`] when `whoami` could not be read,
    /// [`StartupError::Unreadable`] when what came back is not a whoami
    /// answer.
    pub async fn introspect<S: ReadSource>(source: &S) -> Result<McpServer, StartupError> {
        // `Reason::Introspection` and not a tool name: no tool has been
        // called yet and no client has spoken, so a row claiming one
        // ran would be false in the place that exists to tell a claim
        // from a fact. See [`crate::http`] for the whole of AC #6.
        let body = source
            .fetch(WHOAMI_PATH, Reason::Introspection)
            .await
            .map_err(StartupError::Introspection)?;
        let answer: Value = serde_json::from_str(&body).map_err(|_| StartupError::Unreadable)?;
        let identity = identity_of(&answer).ok_or(StartupError::Unreadable)?;
        Ok(McpServer::over(identity))
    }

    /// The same server, from an identity already known, with an
    /// invocation limiter of its own.
    ///
    /// The shape for one process serving one token: the limiter lives
    /// as long as the server and nothing else spends from it.
    pub fn over(identity: Identity) -> McpServer {
        McpServer::sharing(identity, Arc::new(InvocationLimiter::new()))
    }

    /// The same server, spending its invocations through `limiter`.
    ///
    /// The seam the Streamable HTTP adapter needs. Inside `lorica-api`
    /// the principal is already on the request, so asking `whoami` over
    /// a socket to learn what the process just authenticated would be
    /// absurd; and that adapter builds a server per request, so a
    /// limiter the server owned would count one call and reset. It
    /// holds one limiter for the process and hands it to every server
    /// it builds, which is what makes a token's window outlive the
    /// request that opened it.
    pub fn sharing(identity: Identity, limiter: Arc<InvocationLimiter>) -> McpServer {
        let registered = tools::CATALOGUE
            .iter()
            .filter(|spec| identity.scopes.iter().any(|held| held == spec.scope))
            .collect();
        McpServer {
            identity,
            registered,
            limiter,
        }
    }

    /// The token this server is running as.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The tools it registered, in catalogue order.
    pub fn tools(&self) -> &[&'static ToolSpec] {
        &self.registered
    }

    /// One line for the operator, naming what was registered and what
    /// was not.
    ///
    /// Written for a human reading stderr, not for the model: an
    /// adapter logs it and never puts it in a tool answer.
    pub fn startup_notice(&self) -> String {
        let tier = tier_scopes().join(", ");
        if self.registered.is_empty() {
            return format!(
                "Token {} carries no scope this MCP read tier uses, so no tool is registered \
                 and tools/list answers an empty set. It carries: {}. The read tier uses: \
                 {tier}. Mint a token carrying at least one of those.",
                self.identity.public_id,
                self.identity.scopes.join(", "),
            );
        }
        let missing: Vec<&'static str> = tools::CATALOGUE
            .iter()
            .map(|spec| spec.scope)
            .filter(|scope| !self.identity.scopes.iter().any(|held| held == *scope))
            .collect();
        let registered: Vec<&str> = self.registered.iter().map(|spec| spec.name).collect();
        if missing.is_empty() {
            format!(
                "Token {} registered every read tool: {}.",
                self.identity.public_id,
                registered.join(", "),
            )
        } else {
            format!(
                "Token {} registered {}. Not registered for want of a scope: {}.",
                self.identity.public_id,
                registered.join(", "),
                deduplicated(&missing).join(", "),
            )
        }
    }

    /// Answer one message, or `None` when it was a notification.
    ///
    /// `source` is where a tool's read goes. It is a parameter and not
    /// a field because the in-process binding holds a different one per
    /// request, while the registry is fixed for the life of the server.
    pub async fn handle<S: ReadSource>(&self, source: &S, message: Value) -> Option<Value> {
        self.handle_reporting(source, message).await.answer
    }

    /// [`Self::handle`], and what the message came to.
    ///
    /// For an adapter that audits or counts: the answer alone does not
    /// always say whether a tool ran, and a transport that answers every
    /// produced message with one status cannot tell from the status.
    pub async fn handle_reporting<S: ReadSource>(&self, source: &S, message: Value) -> Handled {
        match jsonrpc::parse(message) {
            Ok(request) => self.respond(source, request).await,
            // A message too malformed to place is answered under a null
            // id rather than swallowed: JSON-RPC prescribes silence for
            // a well-formed notification, and this was not one.
            Err(refused) => Handled {
                answer: Some(refused.into_response()),
                outcome: Outcome::ProtocolError,
            },
        }
    }

    /// Answer one request already read out of its envelope.
    ///
    /// The entry point for a transport that had to parse the message
    /// itself before it could let it through, so the same bytes are not
    /// read twice.
    pub async fn respond<S: ReadSource>(&self, source: &S, request: Request) -> Handled {
        if request.is_notification() {
            // `notifications/cancelled` is accepted and does nothing: a
            // read tier's calls are one fetch each, so by the time a
            // cancellation could be read the call it names has already
            // answered. The revision permits ignoring a cancellation
            // for a request that is unknown or already complete.
            return Handled {
                answer: None,
                outcome: Outcome::Silence,
            };
        }
        let id = request.id.clone().unwrap_or(Value::Null);

        // `server/discover` is how a client learns which revisions this
        // speaks, so refusing it on version grounds would be circular.
        if request.method != "server/discover" {
            if let Some(claimed) = request.protocol_version() {
                if claimed != MCP_PROTOCOL_REVISION {
                    return Handled {
                        answer: Some(jsonrpc::unsupported_protocol_version(
                            &id,
                            MCP_PROTOCOL_REVISION,
                        )),
                        outcome: Outcome::ProtocolError,
                    };
                }
            }
        }

        let (answer, outcome) = match request.method.as_str() {
            "server/discover" => (jsonrpc::result(&id, self.discovery()), Outcome::Ok),
            "tools/list" => match request.params.get("cursor") {
                Some(Value::Null) | None => (jsonrpc::result(&id, self.tool_list()), Outcome::Ok),
                Some(_) => (
                    jsonrpc::error(
                        &id,
                        code::INVALID_PARAMS,
                        "this server answers its whole tool list in one page and issues no \
                         cursor",
                    ),
                    Outcome::InvalidParams,
                ),
            },
            "tools/call" => self.call(source, &id, &request.params).await,
            _ => (
                jsonrpc::error(
                    &id,
                    code::METHOD_NOT_FOUND,
                    "this server implements server/discover, tools/list and tools/call",
                ),
                Outcome::ProtocolError,
            ),
        };
        Handled {
            answer: Some(answer),
            outcome,
        }
    }

    /// What `server/discover` answers.
    fn discovery(&self) -> Value {
        json!({
            "supportedVersions": [MCP_PROTOCOL_REVISION],
            "serverInfo": {
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
            },
        })
    }

    /// What `tools/list` answers.
    ///
    /// `resultType: "complete"` and no `nextCursor`: the catalogue is
    /// short and never paginated, so there is no cursor to issue and
    /// none to honour.
    fn tool_list(&self) -> Value {
        json!({
            "resultType": "complete",
            "tools": self
                .registered
                .iter()
                .map(|spec| spec.definition())
                .collect::<Vec<Value>>(),
        })
    }

    /// Run one tool.
    ///
    /// The two error channels part here. An unknown tool and arguments
    /// that do not fit the declared schema are PROTOCOL errors: the
    /// call was malformed and no tool ran. Everything after the fetch
    /// starts is an EXECUTION error carried in a normal result with
    /// `isError: true`, which is what a model reads and stops on. An
    /// authorization refusal from the plane is on that second channel
    /// deliberately: a model that met it as a protocol error would
    /// reword the call and try again.
    async fn call<S: ReadSource>(
        &self,
        source: &S,
        id: &Value,
        params: &Value,
    ) -> (Value, Outcome) {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return (
                jsonrpc::error(
                    id,
                    code::INVALID_PARAMS,
                    "tools/call takes the tool's `name`",
                ),
                Outcome::InvalidParams,
            );
        };
        let Some(spec) = self.registered.iter().find(|spec| spec.name == name) else {
            return (
                jsonrpc::error(id, code::METHOD_NOT_FOUND, &self.why_not(name)),
                Outcome::ToolNotRegistered,
            );
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        let path = match spec.path_for(&arguments) {
            Ok(path) => path,
            Err(refused) => {
                return (
                    jsonrpc::error(id, code::INVALID_PARAMS, &refused.message),
                    Outcome::InvalidParams,
                )
            }
        };

        if !self.limiter.allow(&self.identity.public_id) {
            return (
                jsonrpc::result(
                    id,
                    untrusted::execution_error(
                        &format!(
                            "This server runs at most {RATE_BUDGET} tool calls a minute per \
                             token and this one is over that. Wait before calling again, and \
                             narrow the read with its filters rather than paging through \
                             everything."
                        ),
                        None,
                    ),
                ),
                Outcome::RateLimited,
            );
        }

        // The tool name travels with the read so the plane can record
        // what the caller says this request was for. It is the spec's
        // own name and never the caller's string: `spec` was found by
        // matching against the catalogue, so an unknown name never
        // reaches here.
        let (answered, outcome) = match source.fetch(&path, Reason::Tool(spec.name)).await {
            Ok(body) => {
                let answered = untrusted::answer(&body);
                let outcome = if answered["isError"] == json!(true) {
                    Outcome::Failed
                } else {
                    Outcome::Ok
                };
                (answered, outcome)
            }
            Err(ReadError::Refused { status, body }) => (
                untrusted::execution_error(
                    &format!(
                        "Lorica's automation plane refused this read with HTTP {status}. Its \
                         answer follows as data. This is the plane's decision about the token \
                         this server holds; calling again will not change it."
                    ),
                    Some(&body),
                ),
                Outcome::Refused(status),
            ),
            Err(ReadError::Transport(detail)) => (
                untrusted::execution_error(
                    "Lorica's automation plane could not be reached. The reason follows as \
                     data.",
                    Some(&detail),
                ),
                Outcome::Failed,
            ),
        };
        (jsonrpc::result(id, answered), outcome)
    }

    /// Why a tool the catalogue knows is not on this server.
    ///
    /// Naming the missing scope discloses nothing: the caller holds the
    /// token and reads its own scopes from `whoami`. What it cannot do
    /// is guess which grant this tool wanted.
    fn why_not(&self, name: &str) -> String {
        match tools::find(name) {
            Some(spec) => format!(
                "no tool by that name is registered on this server: it needs the {} scope and \
                 this server's token does not carry it",
                spec.scope
            ),
            // The name is the caller's text and is not repeated back.
            None => "no tool by that name exists; call tools/list for the ones that do".to_string(),
        }
    }
}

/// The identity a whoami answer reports, or `None` when it is not one.
fn identity_of(answer: &Value) -> Option<Identity> {
    let data = answer.get("data")?;
    let public_id = data.get("public_id")?.as_str()?.to_string();
    let scopes = data
        .get("scopes")?
        .as_array()?
        .iter()
        .map(|scope| scope.as_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()?;
    Some(Identity { public_id, scopes })
}

/// Every scope this tier has a tool for, once each, in catalogue order.
pub fn tier_scopes() -> Vec<&'static str> {
    deduplicated(
        &tools::CATALOGUE
            .iter()
            .map(|spec| spec.scope)
            .collect::<Vec<&'static str>>(),
    )
}

/// `names` with later repeats dropped, order kept.
fn deduplicated(names: &[&'static str]) -> Vec<&'static str> {
    let mut kept: Vec<&'static str> = Vec::with_capacity(names.len());
    for name in names {
        if !kept.contains(name) {
            kept.push(name);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the fake plane answers a tool read with.
    enum Answer {
        Body(&'static str),
        Refused(u16, &'static str),
        Broken(&'static str),
    }

    /// A plane that answers `whoami` from one field and every other
    /// read from another, recording what it was asked for and what the
    /// server said the read was for.
    struct Plane {
        whoami: String,
        answer: Answer,
        asked: Mutex<Vec<String>>,
        declared: Mutex<Vec<Option<String>>>,
    }

    impl Plane {
        fn carrying(scopes: &[&str]) -> Plane {
            let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
            Plane {
                whoami: json!({
                    "data": { "name": "mcp-read", "public_id": "0123456789abcdef01234567",
                              "kind": "static_token", "scopes": scopes }
                })
                .to_string(),
                answer: Answer::Body("{\"data\":{\"items\":[],\"page\":{\"returned\":0}}}"),
                asked: Mutex::new(Vec::new()),
                declared: Mutex::new(Vec::new()),
            }
        }

        fn answering(mut self, answer: Answer) -> Plane {
            self.answer = answer;
            self
        }

        fn asked_for(&self) -> Vec<String> {
            self.asked
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn declared_for(&self) -> Vec<Option<String>> {
            self.declared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl ReadSource for Plane {
        async fn fetch(&self, path: &str, reason: Reason<'_>) -> Result<String, ReadError> {
            {
                let mut asked = self
                    .asked
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                asked.push(path.to_string());
                let mut declared = self
                    .declared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                declared.push(reason.tool().map(str::to_string));
            }
            if path == WHOAMI_PATH {
                return Ok(self.whoami.clone());
            }
            match self.answer {
                Answer::Body(body) => Ok(body.to_string()),
                Answer::Refused(status, body) => Err(ReadError::Refused {
                    status,
                    body: body.to_string(),
                }),
                Answer::Broken(detail) => Err(ReadError::Transport(detail.to_string())),
            }
        }
    }

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    async fn server_for(plane: &Plane) -> McpServer {
        McpServer::introspect(plane).await.expect("whoami answered")
    }

    #[tokio::test]
    async fn the_server_asks_what_its_token_can_do_before_it_offers_anything() {
        // AC #3. The first thing on the wire is the introspection, and
        // the tool set is what the answer permits.
        let plane = Plane::carrying(&["logs:read", "waf:read"]);
        let server = server_for(&plane).await;

        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);
        assert_eq!(
            server.tools().iter().map(|s| s.name).collect::<Vec<_>>(),
            vec!["lorica_logs", "lorica_waf_events", "lorica_waf_stats"]
        );
        assert_eq!(server.identity().public_id, "0123456789abcdef01234567");
    }

    #[tokio::test]
    async fn a_token_carrying_no_scope_of_this_tier_starts_with_no_tools_and_says_why() {
        // AC #3's other half. Minting refuses an empty scope array, so
        // the real case is a token carrying scopes none of which this
        // tier uses, and the answer is a running server with an empty
        // list rather than a server whose every call fails.
        let plane = Plane::carrying(&["environments:write"]);
        let server = server_for(&plane).await;
        assert!(server.tools().is_empty());

        let listed = server
            .handle(&plane, request(1, "tools/list", json!({})))
            .await
            .expect("a request is answered");
        assert_eq!(listed["result"]["tools"], json!([]));
        assert_eq!(listed["result"]["resultType"], json!("complete"));

        let notice = server.startup_notice();
        assert!(notice.contains("no tool is registered"), "{notice}");
        assert!(notice.contains("environments:write"), "{notice}");
        assert!(notice.contains("logs:read"), "{notice}");
        assert!(notice.contains("0123456789abcdef01234567"), "{notice}");
    }

    #[tokio::test]
    async fn the_notice_names_what_a_partial_token_did_not_get() {
        let plane = Plane::carrying(&["logs:read"]);
        let notice = server_for(&plane).await.startup_notice();
        assert!(notice.contains("lorica_logs"), "{notice}");
        assert!(notice.contains("waf:read"), "{notice}");

        let plane = Plane::carrying(&tier_scopes());
        let notice = server_for(&plane).await.startup_notice();
        assert!(notice.contains("every read tool"), "{notice}");
    }

    #[tokio::test]
    async fn a_whoami_that_is_not_one_stops_the_server_with_a_readable_reason() {
        for nonsense in [
            "not json at all",
            "{}",
            "{\"data\":{}}",
            "{\"data\":{\"public_id\":\"x\"}}",
            "{\"data\":{\"public_id\":\"x\",\"scopes\":[7]}}",
        ] {
            let plane = Plane {
                whoami: nonsense.to_string(),
                answer: Answer::Body("{}"),
                asked: Mutex::new(Vec::new()),
                declared: Mutex::new(Vec::new()),
            };
            let refused = McpServer::introspect(&plane)
                .await
                .err()
                .unwrap_or_else(|| panic!("{nonsense} is not a whoami answer"));
            assert!(matches!(refused, StartupError::Unreadable), "{nonsense}");
        }
    }

    #[tokio::test]
    async fn discovery_names_the_one_revision_this_crate_implements() {
        // There is no `initialize` in this revision: the handshake is
        // gone and this is what replaced it.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let discovered = server
            .handle(&plane, request(1, "server/discover", json!({})))
            .await
            .expect("a request is answered");
        assert_eq!(
            discovered["result"]["supportedVersions"],
            json!([MCP_PROTOCOL_REVISION])
        );
        assert_eq!(
            discovered["result"]["serverInfo"]["name"],
            json!("lorica-mcp")
        );

        // And `initialize` is not a method here, deliberately.
        let refused = server
            .handle(&plane, request(2, "initialize", json!({})))
            .await
            .expect("a request is answered");
        assert_eq!(
            refused["error"]["code"],
            json!(jsonrpc::code::METHOD_NOT_FOUND)
        );
    }

    #[tokio::test]
    async fn a_tool_call_reaches_the_path_the_arguments_describe_and_nothing_else() {
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let answered = server
            .handle(
                &plane,
                request(
                    3,
                    "tools/call",
                    json!({ "name": "lorica_logs", "arguments": { "limit": 5, "status": 502 } }),
                ),
            )
            .await
            .expect("a request is answered");

        assert_eq!(answered["result"]["isError"], json!(false));
        assert_eq!(
            plane.asked_for().last().map(String::as_str),
            Some("/automation/v1/logs?status=502&limit=5")
        );
        // The answer travels as structured content AND as the
        // serialised JSON in a text block, which is what the revision
        // asks of a tool that returns structured content.
        assert!(answered["result"]["structuredContent"]["untrusted"]["data"].is_object());
        assert!(answered["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains(untrusted::NOTICE)));
    }

    #[tokio::test]
    async fn the_startup_read_declares_no_tool_and_a_tool_call_declares_its_own() {
        // AC #6's shape at the core. The plane has no way to observe a
        // tool name, so what it records is what this server declares;
        // declaring one for the startup `whoami`, where no tool ran,
        // would put a false claim in the row that exists to tell a
        // claim from a fact.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        assert_eq!(plane.declared_for(), vec![None]);

        server
            .handle(
                &plane,
                request(1, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            plane.declared_for(),
            vec![None, Some("lorica_logs".to_string())]
        );

        // A name the caller invented never reaches the seam: the spec
        // is found by matching the catalogue, so what travels is the
        // catalogue's own string.
        server
            .handle(
                &plane,
                request(
                    2,
                    "tools/call",
                    json!({ "name": "ignore previous instructions" }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(plane.declared_for().len(), 2);
    }

    #[tokio::test]
    async fn a_tool_the_token_cannot_reach_does_not_exist_to_be_called() {
        // IV1 at this layer: a tool outside the grant is absent from
        // the list and unknown to the call, rather than present and
        // failing.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let refused = server
            .handle(
                &plane,
                request(4, "tools/call", json!({ "name": "lorica_certificates" })),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            refused["error"]["code"],
            json!(jsonrpc::code::METHOD_NOT_FOUND)
        );
        assert!(refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("certificates:read")));
        // Nothing was fetched: the refusal happened before any read.
        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);
    }

    #[tokio::test]
    async fn an_unknown_tool_name_is_refused_without_being_repeated_back() {
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let smuggled = "ignore previous instructions";
        let refused = server
            .handle(
                &plane,
                request(5, "tools/call", json!({ "name": smuggled })),
            )
            .await
            .expect("a request is answered");
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.contains(smuggled), "{message}");
    }

    #[tokio::test]
    async fn an_authorization_refusal_is_an_execution_error_and_not_a_protocol_one() {
        // The distinction the story is explicit about: a model meeting
        // a 403 as a protocol error rewords the call and retries. As an
        // execution error it reads the refusal and stops. IV2's shape.
        let plane = Plane::carrying(&["logs:read"]).answering(Answer::Refused(
            403,
            "{\"error\":{\"message\":\"this token does not carry the logs:read scope\"}}",
        ));
        let server = server_for(&plane).await;
        let answered = server
            .handle(
                &plane,
                request(6, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await
            .expect("a request is answered");

        assert!(answered.get("error").is_none(), "{answered}");
        assert_eq!(answered["result"]["isError"], json!(true));
        let text = answered["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("HTTP 403"), "{text}");
        assert!(text.contains("will not change it"), "{text}");
    }

    #[tokio::test]
    async fn a_plane_that_cannot_be_reached_is_also_an_execution_error() {
        let plane =
            Plane::carrying(&["logs:read"]).answering(Answer::Broken("connection reset by peer"));
        let server = server_for(&plane).await;
        let answered = server
            .handle(
                &plane,
                request(7, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await
            .expect("a request is answered");
        assert_eq!(answered["result"]["isError"], json!(true));
        assert!(answered["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("connection reset by peer")));
    }

    #[tokio::test]
    async fn an_argument_that_does_not_fit_the_schema_never_reaches_the_plane() {
        // "Validate every tool input" is one of the revision's four
        // server MUSTs on tools, and it is a protocol error: the call
        // was malformed and no tool ran.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let refused = server
            .handle(
                &plane,
                request(
                    8,
                    "tools/call",
                    json!({ "name": "lorica_logs", "arguments": { "limit": 100_000 } }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            refused["error"]["code"],
            json!(jsonrpc::code::INVALID_PARAMS)
        );
        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);
    }

    #[tokio::test]
    async fn a_notification_is_answered_by_silence() {
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let answered = server
            .handle(
                &plane,
                json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": { "requestId": 1 } }),
            )
            .await;
        assert!(answered.is_none());
    }

    #[tokio::test]
    async fn a_request_claiming_another_revision_is_refused_but_discovery_is_not() {
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let meta = json!({ "_meta": { jsonrpc::META_PROTOCOL_VERSION: "2025-11-25" } });

        let refused = server
            .handle(&plane, request(9, "tools/list", meta.clone()))
            .await
            .expect("a request is answered");
        assert_eq!(
            refused["error"]["code"],
            json!(jsonrpc::code::INVALID_REQUEST)
        );
        // The revision's named error with the machine-readable list,
        // the same shape the Streamable HTTP binding answers, so a
        // client negotiating from `supportedVersions` works on both.
        assert_eq!(
            refused["error"]["data"]["name"],
            json!(jsonrpc::UNSUPPORTED_PROTOCOL_VERSION)
        );
        assert_eq!(
            refused["error"]["data"]["supportedVersions"],
            json!([MCP_PROTOCOL_REVISION])
        );

        // Discovery is how a client learns what is supported, so
        // refusing it on version grounds would be circular.
        let discovered = server
            .handle(&plane, request(10, "server/discover", meta))
            .await
            .expect("a request is answered");
        assert_eq!(
            discovered["result"]["supportedVersions"],
            json!([MCP_PROTOCOL_REVISION])
        );
    }

    #[tokio::test]
    async fn tool_invocations_are_rate_limited_and_the_limit_is_an_execution_error() {
        // The third of the revision's four server MUSTs on tools. The
        // budget lives here, in the core, where both bindings pass:
        // the listener's own budgets count connections, not calls.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        let call = |n: i64| request(n, "tools/call", json!({ "name": "lorica_logs" }));

        for n in 0..i64::from(RATE_BUDGET) {
            let answered = server
                .handle(&plane, call(n))
                .await
                .expect("a request is answered");
            assert_eq!(answered["result"]["isError"], json!(false), "call {n}");
        }
        let over = server
            .handle_reporting(&plane, call(i64::from(RATE_BUDGET)))
            .await;
        assert_eq!(over.outcome, Outcome::RateLimited);
        let over = over.answer.expect("a request is answered");
        assert_eq!(over["result"]["isError"], json!(true));
        assert!(over["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("a minute")));
        // And the read never happened: one whoami plus the calls that
        // fitted in the budget.
        assert_eq!(plane.asked_for().len(), 1 + RATE_BUDGET as usize);
    }

    #[tokio::test]
    async fn a_shared_limiter_keeps_a_tokens_window_across_the_servers_built_over_it() {
        // The Streamable HTTP binding builds a server per request. A
        // budget the server owned counted one call and reset, which is
        // what the first cut of that binding did; the budget is the
        // token's, so a fresh server over the same limiter and the
        // same token finds the window already spent.
        let plane = Plane::carrying(&["logs:read"]);
        let limiter = Arc::new(InvocationLimiter::new());
        let identity = Identity {
            public_id: "0123456789abcdef01234567".to_string(),
            scopes: vec!["logs:read".to_string()],
        };
        let call = |n: i64| request(n, "tools/call", json!({ "name": "lorica_logs" }));

        for n in 0..i64::from(RATE_BUDGET) {
            let fresh = McpServer::sharing(identity.clone(), Arc::clone(&limiter));
            let handled = fresh.handle_reporting(&plane, call(n)).await;
            assert_eq!(handled.outcome, Outcome::Ok, "call {n}");
        }
        let fresh = McpServer::sharing(identity.clone(), Arc::clone(&limiter));
        let over = fresh
            .handle_reporting(&plane, call(i64::from(RATE_BUDGET)))
            .await;
        assert_eq!(over.outcome, Outcome::RateLimited);

        // Keyed by token: another token over the same limiter has its
        // own window and is not refused for this one's spending.
        let other = McpServer::sharing(
            Identity {
                public_id: "fedcba9876543210fedcba98".to_string(),
                scopes: vec!["logs:read".to_string()],
            },
            Arc::clone(&limiter),
        );
        let allowed = other.handle_reporting(&plane, call(1)).await;
        assert_eq!(allowed.outcome, Outcome::Ok);
        assert_eq!(limiter.tracked(), 2);
    }

    #[test]
    fn the_limiter_holds_a_bounded_number_of_windows_and_refuses_past_it() {
        // A window is opened per authenticated token, so growing the
        // map takes a live credential per entry; the ceiling is there
        // so that even a stream of them cannot choose this process's
        // memory. Past it, a token with no window is refused rather
        // than handed somebody else's: evicting a live window would
        // give a caller holding more tokens than the ceiling a fresh
        // budget per call.
        let limiter = InvocationLimiter::new();
        for n in 0..MAX_TRACKED_TOKENS {
            assert!(limiter.allow(&format!("token-{n}")), "token-{n}");
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_TOKENS);
        assert!(!limiter.allow("one-too-many"));
        assert_eq!(limiter.tracked(), MAX_TRACKED_TOKENS);
        // A token already holding a window keeps spending it.
        assert!(limiter.allow("token-0"));
    }

    #[tokio::test]
    async fn every_answer_reports_what_it_came_to() {
        // The vocabulary an adapter audits from. The HTTP binding
        // answers every produced message with a 200, so this is what
        // lets its audit row and its metric say `forbidden` for a tool
        // the token does not hold rather than `ok`.
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;

        let cases: Vec<(Value, Outcome)> = vec![
            (
                json!({ "jsonrpc": "2.0", "method": "notifications/cancelled" }),
                Outcome::Silence,
            ),
            (request(1, "tools/list", json!({})), Outcome::Ok),
            (
                request(2, "tools/call", json!({ "name": "lorica_logs" })),
                Outcome::Ok,
            ),
            (
                request(3, "tools/call", json!({ "name": "lorica_certificates" })),
                Outcome::ToolNotRegistered,
            ),
            (
                request(4, "tools/call", json!({ "name": "no such tool" })),
                Outcome::ToolNotRegistered,
            ),
            (
                request(
                    5,
                    "tools/call",
                    json!({ "name": "lorica_logs", "arguments": { "limit": 0 } }),
                ),
                Outcome::InvalidParams,
            ),
            (
                request(6, "tools/list", json!({ "cursor": "abc" })),
                Outcome::InvalidParams,
            ),
            (
                request(
                    7,
                    "tools/list",
                    json!({ "_meta": { jsonrpc::META_PROTOCOL_VERSION: "2025-11-25" } }),
                ),
                Outcome::ProtocolError,
            ),
            (
                json!({ "id": 8, "method": "tools/list" }),
                Outcome::ProtocolError,
            ),
        ];
        for (message, expected) in cases {
            let handled = server.handle_reporting(&plane, message.clone()).await;
            assert_eq!(handled.outcome, expected, "{message}");
            assert_eq!(handled.answer.is_none(), expected == Outcome::Silence);
        }

        // The plane's refusal keeps its status, so an adapter that IS
        // the plane can file it under the outcome word that status
        // already has on every other row.
        let refusing = Plane::carrying(&["logs:read"]).answering(Answer::Refused(
            403,
            "{\"error\":{\"message\":\"refused\"}}",
        ));
        let server = server_for(&refusing).await;
        let handled = server
            .handle_reporting(
                &refusing,
                request(9, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await;
        assert_eq!(handled.outcome, Outcome::Refused(403));

        let broken = Plane::carrying(&["logs:read"]).answering(Answer::Broken("reset"));
        let server = server_for(&broken).await;
        let handled = server
            .handle_reporting(
                &broken,
                request(10, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await;
        assert_eq!(handled.outcome, Outcome::Failed);
    }

    #[tokio::test]
    async fn no_answer_this_server_builds_carries_a_credential_field_name() {
        // AC #5 at this layer. The rows are the management plane's own
        // views and `lorica-api` sweeps those; what this crate owes is
        // that it adds nothing of its own, so the sweep walks every
        // registered tool's answer, the tool list and the refusals.
        let plane = Plane::carrying(&tier_scopes());
        let server = server_for(&plane).await;

        let mut swept: Vec<Value> = vec![
            server
                .handle(&plane, request(1, "tools/list", json!({})))
                .await
                .expect("a request is answered"),
            server
                .handle(&plane, request(2, "server/discover", json!({})))
                .await
                .expect("a request is answered"),
        ];
        assert!(!server.tools().is_empty());
        for spec in server.tools() {
            let arguments = spec.resource.map_or(json!({}), |param| {
                let mut map = serde_json::Map::new();
                map.insert(param.name.to_string(), json!("r-1"));
                Value::Object(map)
            });
            swept.push(
                server
                    .handle(
                        &plane,
                        request(
                            3,
                            "tools/call",
                            json!({ "name": spec.name, "arguments": arguments }),
                        ),
                    )
                    .await
                    .expect("a request is answered"),
            );
        }

        let mut names: Vec<String> = Vec::new();
        for answer in &swept {
            collect_keys(answer, &mut names);
        }
        assert!(names.len() > 20, "the sweep walked nothing: {names:?}");
        for name in &names {
            let lowered = name.to_lowercase();
            for forbidden in [
                "private_key",
                "privatekey",
                "secret",
                "password",
                "passphrase",
                "credential",
                "api_key",
                "apikey",
                "session_id",
                "cookie",
                "hmac",
                "token",
            ] {
                assert!(!lowered.contains(forbidden), "{name} carries {forbidden}");
            }
        }
    }

    /// Every key name anywhere in `value`.
    fn collect_keys(value: &Value, into: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    into.push(key.clone());
                    collect_keys(nested, into);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_keys(item, into);
                }
            }
            _ => {}
        }
    }
}
