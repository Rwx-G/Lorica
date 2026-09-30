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
//! it through [`AutomationPlane`], which is somebody else's
//! implementation. That is what makes AC #10's "one shared core, two
//! bindings" a property of the code rather than a promise.
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
//! re-reads scopes on a running server.
//!
//! # The tier is the token's scopes, on both bindings
//!
//! Story 11.2 AC #2: the catalogue holds every tier's tools, and
//! [`McpServer::sharing`] registers a tool for a scope the token holds
//! and no other. Over stdio that runs once at startup through
//! [`McpServer::over`]; over Streamable HTTP it runs per request
//! through [`McpServer::sharing`], from the token that request
//! presented. A config-tier token gets its write scopes' mutations with
//! their previews and the read tools of the reads its tier tolerates;
//! since Story 11.4 a token carrying any other read beside a write
//! scope is refused outright (see below) rather than given that read's
//! tool. A token carrying read scopes alone can never gain a write
//! tool, because every write tool declares a write scope, which `tools`
//! pins by construction rather than by exception.
//!
//! Story 11.3's admin tier is the same rule over one more scope:
//! `settings:write` registers the settings mutation and its preview and
//! nothing else, since no other tool declares it.
//!
//! # One process, one tier
//!
//! Story 11.4 AC #1: before anything registers, [`McpServer::sharing`]
//! resolves the token's scopes to ONE tier through
//! [`crate::tier::resolve`], and a token spanning two is refused with
//! the scopes named. The registry is then that tier's tools, and the
//! read tools whose scopes the tier tolerates, filtered by what the
//! token holds. Both bindings build their server through that one
//! constructor, so neither can serve a token the other refuses.
//!
//! # A token with no tool still starts
//!
//! Minting refuses an empty scope array, so the case AC #3 names is
//! never a scopeless token: it is a token carrying scopes of one tier
//! that no tool of it uses, `environments:write` alone for instance.
//! Such a server starts, publishes an empty tool list and says why in
//! [`McpServer::startup_notice`], which an adapter puts where an
//! operator reads it. A server whose every call failed would be the
//! same fault reported once per call and never explained.
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
use crate::tier::{self, Tier, TierError};
use crate::tools::{self, ToolSpec};
use crate::untrusted;
use crate::{AutomationPlane, PlaneError, Reason, Verb, MCP_PROTOCOL_REVISION};

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
    Introspection(PlaneError),
    /// `whoami` answered something that is not a whoami answer.
    Unreadable,
    /// The token's scopes span two tiers, or name no tier at all.
    ///
    /// A configuration fault and not an unreachable plane: the token
    /// was read, and it is the wrong token for one process.
    Tier(TierError),
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
            // Only the stdio binding introspects, and it runs on a
            // static token, so the static token's remedy is the one to
            // name.
            StartupError::Tier(refused) => {
                write!(f, "{refused} {}", refused.remedy_for_static_token())
            }
        }
    }
}

impl std::error::Error for StartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StartupError::Introspection(reason) => Some(reason),
            StartupError::Unreadable => None,
            StartupError::Tier(refused) => Some(refused),
        }
    }
}

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
    /// The token's scopes span two tiers, so no server was built for it
    /// and nothing ran. [`McpServer::handle`] never answers this: a
    /// server exists only for a token of one tier. The Streamable HTTP
    /// binding, which builds a server per request, records it for the
    /// request whose token [`McpServer::sharing`] refused.
    SpansTiers,
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
            Outcome::SpansTiers => f.write_str("spans_tiers"),
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
    tier: Tier,
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
    /// answer, [`StartupError::Tier`] when the token it describes spans
    /// two tiers.
    pub async fn introspect<S: AutomationPlane>(source: &S) -> Result<McpServer, StartupError> {
        // `Reason::Introspection` and not a tool name: no tool has been
        // called yet and no client has spoken, so a row claiming one
        // ran would be false in the place that exists to tell a claim
        // from a fact. See [`crate::http`] for the whole of AC #6.
        let body = source
            .call(Verb::Get, WHOAMI_PATH, None, Reason::Introspection)
            .await
            .map_err(StartupError::Introspection)?;
        let answer: Value = serde_json::from_str(&body).map_err(|_| StartupError::Unreadable)?;
        let identity = identity_of(&answer).ok_or(StartupError::Unreadable)?;
        McpServer::over(identity).map_err(StartupError::Tier)
    }

    /// The same server, from an identity already known, with an
    /// invocation limiter of its own.
    ///
    /// The shape for one process serving one token: the limiter lives
    /// as long as the server and nothing else spends from it.
    ///
    /// # Errors
    ///
    /// [`TierError`] when the token's scopes span two tiers; see
    /// [`Self::sharing`].
    pub fn over(identity: Identity) -> Result<McpServer, TierError> {
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
    ///
    /// This is also where Story 11.4 AC #1 is enforced, for both
    /// bindings at once: every server is built here, so a token whose
    /// scopes span two tiers never becomes one, whichever adapter
    /// asked.
    ///
    /// # Errors
    ///
    /// [`TierError`] naming the scopes that put the token in two tiers,
    /// or a scope no tier knows.
    pub fn sharing(
        identity: Identity,
        limiter: Arc<InvocationLimiter>,
    ) -> Result<McpServer, TierError> {
        let tier = tier::resolve(&identity.scopes)?;
        let registered = tools::catalogue()
            .iter()
            .filter(|spec| tier.registers(spec, &identity.scopes))
            .collect();
        Ok(McpServer {
            identity,
            tier,
            registered,
            limiter,
        })
    }

    /// The token this server is running as.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The tools it registered, in catalogue order.
    pub fn tools(&self) -> &[&'static ToolSpec] {
        &self.registered
    }

    /// The one tier this server is, which its token's scopes decided.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// One line for the operator, naming what was registered and what
    /// was not.
    ///
    /// Written for a human reading stderr, not for the model: an
    /// adapter logs it and never puts it in a tool answer. What it asks
    /// for is read from the tier's row of [`tier::TIERS`], never from a
    /// sentence written beside it: a tier is asked about its own tools'
    /// scopes and what it tolerates, and nothing a second tier owns.
    pub fn startup_notice(&self) -> String {
        let tier = self.tier;
        let lacking = |scopes: Vec<&'static str>| -> Vec<&'static str> {
            scopes
                .into_iter()
                .filter(|scope| !self.identity.scopes.iter().any(|held| held == scope))
                .collect()
        };
        if self.registered.is_empty() {
            return format!(
                "Token {} is a {tier} token and registers no tool, so tools/list answers an \
                 empty set. It carries: {}. The {tier}'s tools sit behind: {}. Mint a token \
                 carrying those, with `lorica mcp token create --tier {}`.",
                self.identity.public_id,
                self.identity.scopes.join(", "),
                tier.tool_scopes().join(", "),
                tier.as_str(),
            );
        }
        let registered: Vec<&str> = self.registered.iter().map(|spec| spec.name).collect();
        let missing_tools = lacking(tier.tool_scopes());
        let missing_tolerated = lacking(tier.tolerates().to_vec());
        if missing_tools.is_empty() && missing_tolerated.is_empty() {
            return format!(
                "Token {} registered every tool of the {tier}: {}.",
                self.identity.public_id,
                registered.join(", "),
            );
        }
        let mut notice = format!(
            "Token {} registered the {tier}: {}.",
            self.identity.public_id,
            registered.join(", "),
        );
        if !missing_tools.is_empty() {
            notice.push_str(&format!(
                " Not registered for want of a scope: {}.",
                missing_tools.join(", ")
            ));
        }
        if !missing_tolerated.is_empty() {
            notice.push_str(&format!(
                " The {tier} also allows {}, which its tools need to find the ids they act \
                 on and to preview a change; this token lacks {}.",
                tier.tolerates().join(", "),
                missing_tolerated.join(", "),
            ));
        }
        notice
    }

    /// Answer one message, or `None` when it was a notification.
    ///
    /// `source` is where a tool's call goes. It is a parameter and not
    /// a field because the in-process binding holds a different one per
    /// request, while the registry is fixed for the life of the server.
    pub async fn handle<S: AutomationPlane>(&self, source: &S, message: Value) -> Option<Value> {
        self.handle_reporting(source, message).await.answer
    }

    /// [`Self::handle`], and what the message came to.
    ///
    /// For an adapter that audits or counts: the answer alone does not
    /// always say whether a tool ran, and a transport that answers every
    /// produced message with one status cannot tell from the status.
    pub async fn handle_reporting<S: AutomationPlane>(
        &self,
        source: &S,
        message: Value,
    ) -> Handled {
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
    pub async fn respond<S: AutomationPlane>(&self, source: &S, request: Request) -> Handled {
        if request.is_notification() {
            // `notifications/cancelled` is accepted and does nothing:
            // every tool's call is one request each, so by the time a
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
    /// call was malformed and no tool ran. Everything after the call
    /// leaves is an EXECUTION error carried in a normal result with
    /// `isError: true`, which is what a model reads and stops on. An
    /// authorization refusal from the plane is on that second channel
    /// deliberately, and so is a validator's refusal of a write (Story
    /// 11.2 IV2): a model that met either as a protocol error would
    /// reword the call and try again, when what it should do is read
    /// the plane's words.
    async fn call<S: AutomationPlane>(
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
        let call = match spec.call_for(&arguments) {
            Ok(call) => call,
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
                             narrow a read with its filters rather than paging through \
                             everything."
                        ),
                        None,
                    ),
                ),
                Outcome::RateLimited,
            );
        }

        // The tool name travels with the call so the plane can record
        // what the caller says this request was for. It is the spec's
        // own name and never the caller's string: `spec` was found by
        // matching against the catalogue, so an unknown name never
        // reaches here.
        let (answered, outcome) = match source
            .call(
                call.verb,
                &call.path,
                call.body.as_ref(),
                Reason::Tool(spec.name),
            )
            .await
        {
            Ok(body) => {
                let answered = untrusted::answer(&body);
                let outcome = if answered["isError"] == json!(true) {
                    Outcome::Failed
                } else {
                    Outcome::Ok
                };
                (answered, outcome)
            }
            Err(PlaneError::Refused { status, body }) => (
                untrusted::execution_error(
                    &format!(
                        "Lorica's automation plane refused this call with HTTP {status}. Its \
                         answer follows as data: it is the plane's own refusal, in its own \
                         words, and calling again with the same arguments will not change it."
                    ),
                    Some(&body),
                ),
                Outcome::Refused(status),
            ),
            Err(PlaneError::Transport(detail)) => (
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
            Some(spec) if !self.tier.serves(spec) => format!(
                "no tool by that name is registered on this server: it belongs to the {}, \
                 behind the {} scope, and this server serves the {}; one process serves one \
                 tier",
                spec.tier, spec.scope, self.tier
            ),
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
    /// call from another, recording what it was asked for, what it was
    /// sent, and what the server said the call was for.
    struct Plane {
        whoami: String,
        answer: Answer,
        asked: Mutex<Vec<String>>,
        sent: Mutex<Vec<(Verb, String, Option<Value>)>>,
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
                sent: Mutex::new(Vec::new()),
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

        fn sent_calls(&self) -> Vec<(Verb, String, Option<Value>)> {
            self.sent
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

    impl AutomationPlane for Plane {
        async fn call(
            &self,
            verb: Verb,
            path: &str,
            body: Option<&Value>,
            reason: Reason<'_>,
        ) -> Result<String, PlaneError> {
            {
                let mut asked = self
                    .asked
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                asked.push(path.to_string());
                let mut sent = self
                    .sent
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                sent.push((verb, path.to_string(), body.cloned()));
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
                Answer::Refused(status, body) => Err(PlaneError::Refused {
                    status,
                    body: body.to_string(),
                }),
                Answer::Broken(detail) => Err(PlaneError::Transport(detail.to_string())),
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
        // the real case is a token carrying scopes of one tier that no
        // tool of it uses, and the answer is a running server with an
        // empty list rather than a server whose every call fails.
        let plane = Plane::carrying(&["environments:write"]);
        let server = server_for(&plane).await;
        assert!(server.tools().is_empty());
        assert_eq!(server.tier(), Tier::Config);

        let listed = server
            .handle(&plane, request(1, "tools/list", json!({})))
            .await
            .expect("a request is answered");
        assert_eq!(listed["result"]["tools"], json!([]));
        assert_eq!(listed["result"]["resultType"], json!("complete"));

        let notice = server.startup_notice();
        assert!(notice.contains("registers no tool"), "{notice}");
        assert!(notice.contains("environments:write"), "{notice}");
        assert!(notice.contains("--tier config"), "{notice}");
        for scope in Tier::Config.tool_scopes() {
            assert!(notice.contains(scope), "{notice}");
        }
        // Another tier's scopes are not advice this token should take.
        assert!(!notice.contains("logs:read"), "{notice}");
        assert!(!notice.contains("settings:write"), "{notice}");
        assert!(notice.contains("0123456789abcdef01234567"), "{notice}");
    }

    #[tokio::test]
    async fn iv1_a_token_spanning_two_tiers_never_becomes_a_server_on_either_constructor() {
        // Story 11.4 IV1 at the core. `introspect` is what the stdio
        // binding runs and `sharing` what the Streamable HTTP binding
        // runs per request; `over` is the one they both reach.
        let plane = Plane::carrying(&["logs:read", "routes:write"]);
        let refused = McpServer::introspect(&plane)
            .await
            .err()
            .expect("a token spanning two tiers is refused at startup");
        let refused = match refused {
            StartupError::Tier(refused) => refused,
            other => panic!("refused for another reason: {other}"),
        };
        assert_eq!(refused.offending, vec!["logs:read".to_string()]);
        assert_eq!(refused.anchoring, vec!["routes:write".to_string()]);
        let told = StartupError::Tier(refused).to_string();
        assert!(
            told.contains("logs:read") && told.contains("routes:write"),
            "{told}"
        );
        // Nothing but the introspection reached the plane.
        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);

        let identity = Identity {
            public_id: "0123456789abcdef01234567".to_string(),
            scopes: vec!["logs:read".to_string(), "routes:write".to_string()],
        };
        assert!(McpServer::sharing(identity.clone(), Arc::new(InvocationLimiter::new())).is_err());
        assert!(McpServer::over(identity).is_err());
    }

    #[tokio::test]
    async fn the_notice_names_the_tier_and_what_a_partial_token_did_not_get() {
        let plane = Plane::carrying(&["logs:read"]);
        let server = server_for(&plane).await;
        assert_eq!(server.tier(), Tier::Read);
        let notice = server.startup_notice();
        assert!(notice.contains("read tier"), "{notice}");
        assert!(notice.contains("lorica_logs"), "{notice}");
        assert!(notice.contains("waf:read"), "{notice}");
        // A read tier is complete without a write scope, so it is not
        // asked for one.
        assert!(!notice.contains("routes:write"), "{notice}");

        let plane = Plane::carrying(&Tier::Read.minted_scopes());
        let notice = server_for(&plane).await.startup_notice();
        assert!(notice.contains("every tool of the read tier"), "{notice}");

        // One write scope makes it the config tier, and that tier is
        // asked about the reads it tolerates and lacks, since its tools
        // use them for ids and previews, and never about a read it does
        // not tolerate.
        let plane = Plane::carrying(&["routes:write"]);
        let server = server_for(&plane).await;
        assert_eq!(server.tier(), Tier::Config);
        let notice = server.startup_notice();
        assert!(notice.contains("config tier"), "{notice}");
        assert!(notice.contains("lorica_route_create_preview"), "{notice}");
        assert!(notice.contains("backends:write"), "{notice}");
        for tolerated in Tier::Config.tolerates() {
            assert!(notice.contains(tolerated), "{notice}");
        }
        assert!(!notice.contains("logs:read"), "{notice}");

        let notice = server_for(&Plane::carrying(&Tier::Config.minted_scopes()))
            .await
            .startup_notice();
        assert!(notice.contains("every tool of the config tier"), "{notice}");

        // The admin tier is complete with its own scope and is asked for
        // nothing else: telling it which reads or config writes it lacks
        // would be advice to widen the one tier meant to stay narrow.
        let plane = Plane::carrying(&Tier::Admin.minted_scopes());
        let server = server_for(&plane).await;
        assert_eq!(server.tier(), Tier::Admin);
        let notice = server.startup_notice();
        assert!(notice.contains("every tool of the admin tier"), "{notice}");
        assert!(!notice.contains("routes:write"), "{notice}");
        assert!(!notice.contains("logs:read"), "{notice}");
    }

    #[tokio::test]
    async fn a_token_carrying_only_read_scopes_registers_no_write_tool_and_cannot_call_one() {
        // Story 11.2 AC #2: a read-tier token can never gain a write
        // tool. Every read scope there is, and not one mutation
        // registered, listed or callable.
        let plane = Plane::carrying(Tier::Read.requires());
        let server = server_for(&plane).await;
        assert!(!server.tools().is_empty());
        for spec in server.tools() {
            assert!(spec.changes_nothing(), "{} is registered", spec.name);
            assert!(spec.write().is_none(), "{} is registered", spec.name);
        }
        for mutation in tools::MUTATIONS {
            for name in [mutation.apply, mutation.preview] {
                let refused = server
                    .handle(
                        &plane,
                        request(1, "tools/call", json!({ "name": name, "arguments": {} })),
                    )
                    .await
                    .expect("a request is answered");
                assert_eq!(
                    refused["error"]["code"],
                    json!(jsonrpc::code::METHOD_NOT_FOUND),
                    "{name}"
                );
                let message = refused["error"]["message"].as_str().unwrap_or_default();
                assert!(message.contains(mutation.scope), "{name}: {refused}");
                // The tier answer, not the scope answer: adding the
                // scope would make this token span two tiers, so
                // "needs the scope" is advice it could never follow.
                assert!(
                    message.contains("belongs to the config tier"),
                    "{name}: {refused}"
                );
                assert!(
                    message.contains("one process serves one tier"),
                    "{name}: {refused}"
                );
                assert!(!message.contains("does not carry it"), "{name}: {refused}");
            }
        }
        // Nothing but the introspection reached the plane.
        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);
    }

    #[tokio::test]
    async fn a_missing_tool_is_named_by_tier_across_tiers_and_by_scope_within_one() {
        // A config token holding routes:write alone. A read-tier tool
        // its tier does not tolerate belongs to another tier; a config
        // tool behind a scope it does not hold is a scope it could add.
        let plane = Plane::carrying(&["routes:write", "routes:read"]);
        let server = server_for(&plane).await;
        let answered = |name: &'static str| {
            let server = &server;
            let plane = &plane;
            async move {
                let refused = server
                    .handle(
                        plane,
                        request(1, "tools/call", json!({ "name": name, "arguments": {} })),
                    )
                    .await
                    .expect("a request is answered");
                assert_eq!(
                    refused["error"]["code"],
                    json!(jsonrpc::code::METHOD_NOT_FOUND),
                    "{name}"
                );
                refused["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            }
        };
        let foreign = answered("lorica_logs").await;
        assert!(foreign.contains("belongs to the read tier"), "{foreign}");
        assert!(foreign.contains("serves the config tier"), "{foreign}");
        let same_tier = answered("lorica_backend_create").await;
        assert!(
            same_tier.contains("needs the backends:write scope"),
            "{same_tier}"
        );
        assert!(!same_tier.contains("belongs to"), "{same_tier}");
        let admin = answered("lorica_settings_update").await;
        assert!(admin.contains("belongs to the admin tier"), "{admin}");
        assert_eq!(plane.asked_for(), vec![WHOAMI_PATH.to_string()]);
    }

    #[tokio::test]
    async fn a_config_tier_token_registers_its_mutations_with_their_previews_and_the_reads_it_holds(
    ) {
        // Story 11.2 AC #2, the other half: a write scope registers
        // that scope's mutations and previews, and the read tools the
        // token's read scopes cover, and nothing behind a scope it does
        // not carry.
        let plane = Plane::carrying(&["routes:write", "routes:read"]);
        let server = server_for(&plane).await;
        let registered: Vec<&str> = server.tools().iter().map(|spec| spec.name).collect();
        assert_eq!(
            registered,
            vec![
                "lorica_routes",
                "lorica_route_create",
                "lorica_route_create_preview",
                "lorica_route_update",
                "lorica_route_update_preview",
                "lorica_route_delete",
                "lorica_route_delete_preview",
            ]
        );
        for spec in server.tools() {
            assert!(
                spec.scope == "routes:write" || spec.scope == "routes:read",
                "{}",
                spec.name
            );
        }
        // The binding sits behind certificates:write and is not here,
        // although its path is a route's.
        let refused = server
            .handle(
                &plane,
                request(
                    1,
                    "tools/call",
                    json!({ "name": "lorica_route_bind_certificate",
                            "arguments": { "id": "r-1", "binding": { "certificate_id": "c-1" } } }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            refused["error"]["code"],
            json!(jsonrpc::code::METHOD_NOT_FOUND)
        );
        assert!(refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("certificates:write")));
    }

    #[tokio::test]
    async fn a_write_tool_call_crosses_the_seam_with_its_verb_and_body_and_a_preview_with_dry_run()
    {
        // The seam carries what a mutation is: the verb, the path, the
        // body verbatim. The plane below is what validates it; this
        // proves the call arrived whole and the preview arrived marked.
        let plane = Plane::carrying(&["routes:write"]);
        let server = server_for(&plane).await;
        let route = json!({ "hostname": "app.example.com", "waf_enabled": true });

        let answered = server
            .handle(
                &plane,
                request(
                    1,
                    "tools/call",
                    json!({ "name": "lorica_route_create", "arguments": { "route": route } }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(answered["result"]["isError"], json!(false));
        assert_eq!(
            plane.sent_calls().last(),
            Some(&(
                Verb::Post,
                "/automation/v1/routes".to_string(),
                Some(route.clone())
            ))
        );
        assert_eq!(
            plane.declared_for().last(),
            Some(&Some("lorica_route_create".to_string()))
        );

        server
            .handle(
                &plane,
                request(
                    2,
                    "tools/call",
                    json!({ "name": "lorica_route_update_preview",
                            "arguments": { "id": "r-1", "route": route } }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            plane.sent_calls().last(),
            Some(&(
                Verb::Put,
                "/automation/v1/routes/r%2D1?dry_run=true".to_string(),
                Some(route.clone())
            ))
        );

        server
            .handle(
                &plane,
                request(
                    3,
                    "tools/call",
                    json!({ "name": "lorica_route_delete", "arguments": { "id": "r-1" } }),
                ),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            plane.sent_calls().last(),
            Some(&(
                Verb::Delete,
                "/automation/v1/routes/r%2D1".to_string(),
                None
            ))
        );
        // And a read still crosses as a GET with no body.
        let reader = Plane::carrying(&["logs:read"]);
        let server = server_for(&reader).await;
        server
            .handle(
                &reader,
                request(4, "tools/call", json!({ "name": "lorica_logs" })),
            )
            .await
            .expect("a request is answered");
        assert_eq!(
            reader.sent_calls().last(),
            Some(&(Verb::Get, "/automation/v1/logs".to_string(), None))
        );
    }

    #[tokio::test]
    async fn a_validators_refusal_of_a_write_is_an_execution_error_carrying_the_planes_words() {
        // Story 11.2 IV2 at this layer: the field-level error is the
        // plane's own, verbatim inside the fence, and it comes back as
        // an execution error so the model reads it and stops.
        let plane = Plane::carrying(&["routes:write"]).answering(Answer::Refused(
            400,
            "{\"error\":{\"message\":\"connect_timeout_s must be between 1 and 300\"}}",
        ));
        let server = server_for(&plane).await;
        let handled = server
            .handle_reporting(
                &plane,
                request(
                    1,
                    "tools/call",
                    json!({ "name": "lorica_route_create",
                            "arguments": { "route": { "hostname": "a", "connect_timeout_s": 0 } } }),
                ),
            )
            .await;
        assert_eq!(handled.outcome, Outcome::Refused(400));
        let answered = handled.answer.expect("a request is answered");
        assert!(answered.get("error").is_none(), "{answered}");
        assert_eq!(answered["result"]["isError"], json!(true));
        let text = answered["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(text.contains("HTTP 400"), "{text}");
        assert!(
            text.contains("connect_timeout_s must be between 1 and 300"),
            "{text}"
        );
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
                sent: Mutex::new(Vec::new()),
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
            let fresh =
                McpServer::sharing(identity.clone(), Arc::clone(&limiter)).expect("one tier");
            let handled = fresh.handle_reporting(&plane, call(n)).await;
            assert_eq!(handled.outcome, Outcome::Ok, "call {n}");
        }
        let fresh = McpServer::sharing(identity.clone(), Arc::clone(&limiter)).expect("one tier");
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
        )
        .expect("one tier");
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
        // registered tool's answer, the tool list and the refusals,
        // over one token per tier, each carrying every scope its tier
        // mints, which between them register the whole catalogue.
        let mut swept: Vec<Value> = Vec::new();
        let mut registered = 0usize;
        for tier in Tier::ALL {
            let plane = Plane::carrying(&tier.minted_scopes());
            let server = server_for(&plane).await;
            assert_eq!(server.tier(), tier);
            registered += server
                .tools()
                .iter()
                .filter(|spec| spec.tier == tier)
                .count();
            for message in [
                request(1, "tools/list", json!({})),
                request(2, "server/discover", json!({})),
            ] {
                swept.push(
                    server
                        .handle(&plane, message)
                        .await
                        .expect("a request is answered"),
                );
            }
            for spec in server.tools() {
                let mut map = serde_json::Map::new();
                if let Some(param) = spec.resource {
                    map.insert(param.name.to_string(), json!("r-1"));
                }
                if let Some(body) = spec.body() {
                    map.insert(body.argument.to_string(), json!({}));
                }
                let arguments = Value::Object(map);
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
        }
        assert_eq!(registered, tools::catalogue().len());

        let mut names: Vec<String> = Vec::new();
        for answer in &swept {
            collect_keys(answer, &mut names);
        }
        assert!(names.len() > 20, "the sweep walked nothing: {names:?}");
        for name in &names {
            if tools::NAMED_FOR_A_LIFETIME_NOT_A_CREDENTIAL.contains(&name.as_str()) {
                continue;
            }
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
