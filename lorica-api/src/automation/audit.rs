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

//! Audit for the automation plane: EVERY request lands a row, not only
//! the mutations.
//!
//! The management plane audits mutations because a read there is a
//! human looking at a page they are already allowed to see. Here the
//! caller is a credential, and the questions after an incident are
//! "which token was this" and "what was it reaching for", which a
//! read answers as much as a write. Refusals are audited too: a token
//! that stopped working, or one presenting itself from an address
//! nobody expected, is exactly what an operator needs to see.
//!
//! "Every request" includes one whose handler panics: the panic net in
//! [`super::router::with_audit_and_panic_net`] sits directly inside
//! this layer and turns an unwind into a 500 that returns normally, so
//! the row is written in the case an operator most wants it.
//!
//! # How the outcome reaches this layer
//!
//! This middleware is the OUTERMOST layer, so it sees requests the
//! bearer gate refuses. But it therefore also loses the request
//! extensions by the time the response comes back, and the principal
//! is only known inside the gate. On the way down it installs a
//! [`PrincipalSlot`]; the gate fills it with the principal on a
//! successful authentication and with the precise reason on a
//! refusal, and this layer reads its own handle afterwards. The slot
//! is write-once, so a later layer cannot rewrite who the row names.
//!
//! # The reason lives here and nowhere else
//!
//! A refused request answers one generic 401 on the wire (Story 10.5
//! AC #2). The audit row is the only place the precise cause is
//! written: `wrong_alg`, `unknown_kid`, `expired`,
//! `bound_claim_mismatch:<claim>`, `replayed`, `token_revoked` and the
//! rest of [`AUTOMATION_AUDIT_REASONS`], so an operator can tell a
//! pipeline what to fix without the wire telling an attacker what to
//! try next.
//!
//! It is written where an operator LOOKS, which is two places and not
//! one. `GET /api/v1/audit` returns the row, so the reason rides in
//! the row's `action` (`automation.request.unauthenticated:wrong_alg`);
//! syslog, OTLP and the file log carry the `lorica::audit` event, so
//! `crate::audit` lifts the same text into a `reason` field. What it
//! is NOT written into is a payload: Story 9.9 hashes those because
//! they may carry secrets, and that rule is not weakened here. The
//! reason vocabulary is a closed list of words the node chooses, never
//! caller-supplied material, which is precisely why it may travel in
//! clear where a payload may not.
//!
//! # The row is queued, not written here
//!
//! [`crate::audit::record`] used to take the store lock and commit one
//! chained-hash row before the response returned, so a pipeline burst
//! serialised there at about one SQLite commit per request. It now
//! offers the row to the bounded, single-consumer queue described in
//! [`crate::audit`], which the management plane shares: the chain hash
//! is only meaningful in write order, so one consumer is the only
//! shape that works, and one queue for both planes is what keeps their
//! durability promise identical for the same table.
//!
//! What a refusal costs the caller is now a `try_send`. What it costs
//! an operator is that the row is durable within the consumer's next
//! drain rather than before the 401, and that a queue full for long
//! enough sheds rows into `lorica_audit_rows_dropped_total`.
//!
//! # What the node established, and what the caller merely said
//!
//! Story 11.1 AC #6 asks that every MCP tool call be audited with the
//! token's `public_id`, the tool name, the arguments after redaction
//! and a marker identifying the transport as MCP. Over stdio, two of
//! those four are not things this layer can observe. The MCP server is
//! a separate process that reaches this plane over HTTP; at the HTTP
//! layer there is no tool, because a tool is a concept of the protocol
//! that process speaks and not of the one it speaks over.
//!
//! So the row says which is which, rather than flattening them into one
//! sentence that reads as if the node had checked both:
//!
//! - **Established.** The principal, from verifying the credential.
//!   The method, the path and the names of the query parameters, from
//!   the request line this node parsed. The status, from what this node
//!   answered. These anchor the row.
//! - **Asserted.** The transport and the tool name, from
//!   [`ASSERTED_TRANSPORT_HEADER`] and [`ASSERTED_TOOL_HEADER`], which
//!   are whatever the caller sent. They are recorded inside an
//!   `asserted[...]` clause and nowhere else, so nothing reads them as
//!   a fact the node checked.
//!
//! Over the Streamable HTTP binding, on [`MCP_PATH`], the situation is
//! not the stdio one and the row does not pretend it is. The transport
//! is established by the path itself: this node routed the request
//! there. When the core ran, the tool name is established too, because
//! the handler parsed the body, the mirror check proved `Mcp-Name`
//! equal to it, and the catalogue is what resolved the name; the
//! handler attaches an [`McpCallRecord`] to the response saying which
//! tool, which declared arguments and what the call came to, and the
//! row writes those outside any `asserted[...]` clause. The two
//! Lorica-specific assertion headers are ignored on that path entirely:
//! a caller could otherwise overwrite the tool the node itself
//! resolved. Only a POST the core never saw - refused by a gate or by
//! the transport rules - still records the decoded `Mcp-Name` as a
//! claim, because on that row it is one.
//!
//! The outcome word of an MCP row comes from that record and not from
//! the status. The core answers everything it produced with a `200`,
//! including a call on a tool the token does not hold and a result
//! carrying `isError: true`; keyed on the status, every one of those
//! would read `ok`. The vocabulary stays the plane's five words, with
//! the reason after the colon saying which of the MCP refusals it was.
//!
//! An audit trail that cannot tell a claim from a proof is telling a
//! story that is not true, which is the same reasoning Epic 11 gives
//! for distinguishing a model from a person in the first place.
//!
//! Header values are attacker-influenced in the general case - anyone
//! holding a live token can send any header they like - so
//! [`asserted_clause`] bounds both length and character set before
//! either reaches a row, and the request path and `User-Agent` are cut
//! to a fixed length for the same reason.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use lorica_config::models::AutomationScope;
use lorica_mcp::server::Outcome;
use lorica_mcp::tools;

use super::auth::AutomationPrincipal;
use super::mcp::{McpCallRecord, MCP_PATH, NAME_HEADER};
use super::scope::{scope_str, ScopeRequirement};
use crate::audit::AuditContext;
use crate::server::AppState;

/// `operator_role` stamped on every automation row.
///
/// The management plane puts the RBAC role here. An automation
/// principal has no role, it has scopes, so the column names the plane
/// instead: an operator filtering the audit log on `automation` gets
/// every machine-driven request and nothing else.
pub(super) const AUTOMATION_ROLE: &str = "automation";

/// `target_type` stamped on every automation row.
const AUTOMATION_TARGET_TYPE: &str = "automation_request";

/// What `operator_username` says when the request never authenticated.
const ANONYMOUS_PRINCIPAL: &str = "-";

/// The header a caller declares the transport it is bridging in.
///
/// Story 11.1 AC #6's "marker identifying the transport as MCP". The
/// emitter is `lorica-mcp`, which spells it in
/// `lorica-mcp/src/http.rs`; the two spellings are pinned against each
/// other by `lorica-api/tests/mcp_asserted_headers.rs`, which reads
/// that file rather than depending on the crate.
pub const ASSERTED_TRANSPORT_HEADER: &str = "lorica-asserted-transport";

/// The header a caller declares the tool name in.
///
/// See [`ASSERTED_TRANSPORT_HEADER`] for where the other end of this
/// spelling lives and what pins the two together.
pub const ASSERTED_TOOL_HEADER: &str = "lorica-asserted-tool";

/// The most bytes an asserted transport may weigh.
const ASSERTED_TRANSPORT_MAX_BYTES: usize = 32;

/// The most bytes an asserted tool name may weigh.
///
/// The MCP tool-name grammar's own ceiling, so a legitimate name always
/// fits and nothing longer than one can be stored.
const ASSERTED_TOOL_MAX_BYTES: usize = tools::TOOL_NAME_MAX_BYTES;

/// The most bytes of a request path that reach a row.
///
/// The path is the caller's own text, bounded until here only by what
/// hyper accepts on a request line. Long enough for any path this plane
/// declares many times over; the cut is on a char boundary and marks
/// nothing, since a path that long is a scan and not a request.
const PATH_MAX_BYTES: usize = 2048;

/// The most bytes of a `User-Agent` that reach a row.
const USER_AGENT_MAX_BYTES: usize = 512;

/// The reason a 403 carries when the path itself declares no scope.
///
/// Not a caller's mistake and not a token's: a route reachable through
/// this listener with no entry in the scope matrix. The scope gate
/// logs it at ERROR; the audit row says the same thing to whoever
/// reads the trail instead of the journal.
const NO_DECLARED_SCOPE: &str = "no_declared_scope";

/// The reason a 403 on [`MCP_PATH`] carries when the call named a tool
/// no catalogue entry has. A tool the catalogue knows and the token
/// does not hold names the scope it needed instead, as a read path's
/// 403 does.
const UNKNOWN_TOOL: &str = "unknown_tool";

/// The reason a refused MCP call carries when its arguments did not fit
/// the tool's declared schema, or a `tools/list` carried a cursor.
const INVALID_PARAMS: &str = "invalid_params";

/// The reason a refused MCP call carries when the token is over its
/// invocation budget for the window.
const RATE_LIMITED: &str = "rate_limited";

/// The reason a refused MCP message carries when it was malformed or
/// claimed a protocol revision this node does not speak.
const PROTOCOL_ERROR: &str = "protocol_error";

/// Every reason an automation audit row can name that is not a scope,
/// and with the scope spellings the vocabulary the "Reading a refusal"
/// section of `docs/automation.md` publishes.
///
/// ONE list, because the alternative is three (the bearer gate, the
/// scope gate, the document) and three is three chances for an
/// operator to meet a word no table explains. The test below asserts
/// the gates emit nothing that is not here.
///
/// Two of these carry a parameter after a second colon:
/// `missing_claim:jti`, `bound_claim_mismatch:project_path`. The scope
/// spellings a 403 names are NOT restated here: [`is_published_reason`]
/// reads them from [`AutomationScope::ALL`] through [`scope_str`], so a
/// scope added to the enum is published the day it exists rather than
/// the day somebody remembers this list.
pub const AUTOMATION_AUDIT_REASONS: &[&str] = &[
    // The bearer gate, before either credential path.
    "no_bearer",
    "bearer_too_long",
    "not_a_credential",
    "store_error",
    // The static-token path.
    "token_unknown_or_wrong_secret",
    "token_revoked",
    "token_expired",
    // The ID-token path, before the verifier.
    "too_many_audiences",
    // The ID-token verifier (`super::oidc::RefusalReason`).
    "malformed",
    "wrong_alg",
    "no_issuer",
    "unknown_kid",
    "jwks_unavailable",
    "invalid_key",
    "bad_signature",
    "expired",
    "not_yet_valid",
    "wrong_aud",
    "wrong_iss",
    "missing_claim",
    "bound_claim_mismatch",
    "replayed",
    // The scope gate: the path that declares no scope. The grant a
    // token did not carry is the scope's own spelling, derived.
    NO_DECLARED_SCOPE,
    // The MCP endpoint, from what the core said the call came to.
    UNKNOWN_TOOL,
    INVALID_PARAMS,
    RATE_LIMITED,
    PROTOCOL_ERROR,
];

/// Whether `reason` is in the published vocabulary: a listed word
/// exactly, a listed word carrying its parameter after a colon, or the
/// wire spelling of a scope.
///
/// ```
/// use lorica_api::automation::audit::is_published_reason;
/// assert!(is_published_reason("wrong_alg"));
/// assert!(is_published_reason("bound_claim_mismatch:project_path"));
/// assert!(is_published_reason("environments:write"));
/// assert!(is_published_reason("rate_limited"));
/// assert!(!is_published_reason("something_someone_invented"));
/// ```
pub fn is_published_reason(reason: &str) -> bool {
    AUTOMATION_AUDIT_REASONS.iter().any(|known| {
        reason == *known
            || reason
                .strip_prefix(known)
                .is_some_and(|rest| rest.starts_with(':'))
    }) || AutomationScope::ALL
        .iter()
        .any(|scope| scope_str(*scope) == reason)
}

/// What the bearer gate decided about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authenticated.
    Accepted {
        /// [`AutomationPrincipal::audit_identity`], what the row names.
        identity: String,
        /// The grant the credential carries. Kept so a 403 can say
        /// which scope was missing: the scope gate answers through the
        /// shared error type and this layer is outside it, so the only
        /// way to name the gap is to weigh the same two things the
        /// gate weighed.
        scopes: Vec<AutomationScope>,
    },
    /// Refused; carries the precise reason for the audit row.
    Refused(String),
}

/// Write-once handle the bearer gate uses to tell the audit layer who
/// the caller turned out to be, or why they were turned away.
///
/// Cloning shares the cell, which is the point: the audit layer keeps
/// one handle while the other travels down inside the request.
#[derive(Debug, Clone, Default)]
pub struct PrincipalSlot(Arc<OnceLock<AuthOutcome>>);

impl PrincipalSlot {
    /// Record the authenticated principal. The first write wins.
    pub fn accept(&self, principal: &AutomationPrincipal) {
        let _ = self.0.set(AuthOutcome::Accepted {
            identity: principal.audit_identity(),
            scopes: principal.scopes.clone(),
        });
    }

    /// Record why the request was refused. The first write wins.
    pub fn refuse(&self, reason: &str) {
        let _ = self.0.set(AuthOutcome::Refused(reason.to_string()));
    }

    /// The gate's decision, or `None` when the gate never ran.
    pub fn get(&self) -> Option<AuthOutcome> {
        self.0.get().cloned()
    }
}

/// The outcome word stamped into the action verb.
///
/// Derived from the status the chain produced rather than passed down,
/// so a future layer that refuses a request cannot forget to report
/// itself. A 5xx is `error` and not `refused`: the node broke, it did
/// not decide, and an operator scanning the trail for the node's own
/// faults must not have to read them out of the same bucket as the
/// requests it turned away on purpose.
fn outcome(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "forbidden",
        _ if status.is_success() => "ok",
        _ if status.is_server_error() => "error",
        _ => "refused",
    }
}

/// The reason to spell into the action verb, or `None` when the
/// outcome needs no explaining.
///
/// A 401 knows its own reason: the bearer gate wrote it into the slot.
/// A 403 does not, so it is recovered from the same matrix the scope
/// gate consulted, and only when the credential really lacks what the
/// path wanted. A 403 a HANDLER raised (an ownership rule, a hostname
/// outside the grant) names no scope on purpose: naming the path's
/// scope there would send an operator off to re-mint a token that was
/// never the problem. A path any live token reaches has no scope to
/// name at all, so a 403 on one is always a handler's.
fn refusal_reason(
    status: StatusCode,
    decision: Option<&AuthOutcome>,
    method: &Method,
    path: &str,
) -> Option<String> {
    match (status, decision) {
        (StatusCode::UNAUTHORIZED, Some(AuthOutcome::Refused(reason))) => Some(reason.clone()),
        (StatusCode::FORBIDDEN, Some(AuthOutcome::Accepted { scopes, .. })) => {
            match super::scope::required_scope(method, path) {
                None => Some(NO_DECLARED_SCOPE.to_string()),
                Some(ScopeRequirement::Scope(needed)) if !scopes.contains(&needed) => {
                    Some(scope_str(needed).to_string())
                }
                Some(_) => None,
            }
        }
        _ => None,
    }
}

/// The action verb for one request.
///
/// The reason rides INSIDE the verb rather than beside it because
/// `GET /api/v1/audit` returns the stored row, and of the row's
/// columns only `action` is both free-form and indexed: an operator
/// filtering on `automation.request.unauthenticated` still sees every
/// refusal, and now reads the cause without a second query.
fn action_for(outcome_word: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("automation.request.{outcome_word}:{reason}"),
        None => format!("automation.request.{outcome_word}"),
    }
}

/// The names of the query parameters one request carried, sorted, with
/// no value.
///
/// Story 9.9 forbids storing payloads and that decision stands, so the
/// values never reach a row. The names still answer the question a
/// reader of the trail has on a READ surface: `GET
/// /automation/v1/logs` alone says a token read the log, and nothing
/// about whether it read one route, one status band or every row in a
/// search. The names are a vocabulary the caller chooses, so they are
/// bounded on both counts: a long name cannot bloat the row and a flood
/// of them cannot lengthen it without limit.
fn query_parameter_names(query: Option<&str>) -> String {
    const MAX_NAMES: usize = 16;
    const MAX_NAME_BYTES: usize = 32;

    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut names: Vec<&str> = query
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .filter(|name| !name.is_empty())
        .map(|name| bounded(name, MAX_NAME_BYTES))
        .collect();
    names.sort_unstable();
    names.dedup();
    names.truncate(MAX_NAMES);
    format!("?{}", names.join(","))
}

/// One asserted value, or `None` when the caller sent nothing usable.
///
/// Usable means: present, non-empty, within `max_bytes`, and built from
/// the MCP tool-name character class, which is `lorica-mcp`'s own
/// [`tools::fits_tool_name_grammar`] so the two crates cannot disagree
/// about it. That set also happens to contain no byte that could end
/// the clause, break the target string or read as a field separator
/// further down. A value outside it is dropped whole rather than
/// trimmed: half of what somebody claimed is not a smaller claim, it is
/// a different one.
fn assertable(value: Option<&str>, max_bytes: usize) -> Option<String> {
    let value = value?;
    tools::fits_tool_name_grammar(value, max_bytes).then(|| value.to_string())
}

/// What the caller CLAIMED this request was, as a clause to append to
/// the audit target, or the empty string when it claimed nothing.
///
/// The word `asserted` is in the row itself and not only in this
/// module's documentation, because the row is what an operator reads
/// six months later with none of this in front of them. Everything
/// outside the clause is something the node established; everything
/// inside it is something the caller said.
///
/// Not read on [`MCP_PATH`]: see [`mcp_claimed_clause`].
fn asserted_clause(headers: &http::HeaderMap) -> String {
    let read = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
    };
    let transport = assertable(
        read(ASSERTED_TRANSPORT_HEADER),
        ASSERTED_TRANSPORT_MAX_BYTES,
    );
    let tool = assertable(read(ASSERTED_TOOL_HEADER), ASSERTED_TOOL_MAX_BYTES);

    let mut claims: Vec<String> = Vec::with_capacity(2);
    if let Some(transport) = transport {
        claims.push(format!("transport={transport}"));
    }
    if let Some(tool) = tool {
        claims.push(format!("tool={tool}"));
    }
    if claims.is_empty() {
        String::new()
    } else {
        format!(" asserted[{}]", claims.join(","))
    }
}

/// What the caller claimed on a POST to [`MCP_PATH`] the core never
/// saw: the decoded `Mcp-Name`, as a clause, or nothing.
///
/// The two Lorica-specific assertion headers are ignored here on
/// purpose. On this path the transport is the path, and the tool is
/// whatever the body names; a caller sending `lorica-asserted-tool`
/// could otherwise put a different tool in the row than the one the
/// node ran, and a caller sending `Mcp-Name` in a Base64 sentinel
/// would have left the row with nothing readable. The value is read
/// through the same decoder [`super::mcp`] compares with, so what is
/// recorded as claimed is what was compared.
///
/// A claim and not a fact, because this clause is only written when the
/// core did not run: the mirror check may have been the thing that
/// refused the POST, in which case the value is exactly what somebody
/// said and nothing more.
fn mcp_claimed_clause(headers: &http::HeaderMap) -> String {
    let claimed = super::mcp::mirrored(headers, NAME_HEADER)
        .ok()
        .flatten()
        .and_then(|name| assertable(Some(name.trim()), ASSERTED_TOOL_MAX_BYTES));
    match claimed {
        Some(tool) => format!(" asserted[tool={tool}]"),
        None => String::new(),
    }
}

/// What the node established about an MCP call, as a clause to append
/// to the audit target: the tool the body named and the declared
/// argument names it carried, in the same `?names` shape a read path's
/// row uses for its query parameters. Empty off a `tools/call`.
///
/// Outside any `asserted[...]` clause, because none of it is a claim:
/// the handler parsed the body, the mirror check proved the header
/// equal to it, and the names come from the tool's own vocabulary.
fn mcp_established_clause(record: &McpCallRecord) -> String {
    let Some(tool) = &record.tool else {
        return String::new();
    };
    if record.argument_names.is_empty() {
        format!(" tool={tool}")
    } else {
        format!(" tool={tool}?{}", record.argument_names.join(","))
    }
}

/// The outcome word and the reason for an MCP row, from what the core
/// said the call came to rather than from the `200` it was answered
/// with.
///
/// The words are the plane's own five. A tool the token does not hold
/// is `forbidden` naming the scope it needed, exactly what the scope
/// gate writes for the read path behind that tool; a tool no catalogue
/// entry has is `forbidden:unknown_tool`. The plane's refusal of the
/// read a tool made keeps the word its status has on every other row,
/// and names no scope, since a tool that ran was registered and the
/// token held it.
fn mcp_outcome(record: &McpCallRecord) -> (&'static str, Option<String>) {
    match record.outcome {
        Outcome::Silence | Outcome::Ok => ("ok", None),
        Outcome::ToolNotRegistered => {
            let needed = record
                .tool
                .as_deref()
                .and_then(tools::find)
                .and_then(|spec| {
                    serde_json::from_str::<AutomationScope>(&format!("\"{}\"", spec.scope)).ok()
                })
                .map_or(UNKNOWN_TOOL, scope_str);
            ("forbidden", Some(needed.to_string()))
        }
        Outcome::InvalidParams => ("refused", Some(INVALID_PARAMS.to_string())),
        Outcome::RateLimited => ("refused", Some(RATE_LIMITED.to_string())),
        Outcome::Refused(status) => (StatusCode::from_u16(status).map_or("error", outcome), None),
        Outcome::Failed => ("error", None),
        Outcome::ProtocolError => ("refused", Some(PROTOCOL_ERROR.to_string())),
    }
}

/// `text` cut to at most `max_bytes` on a char boundary.
fn bounded(text: &str, max_bytes: usize) -> &str {
    let cut = (0..=text.len().min(max_bytes))
        .rev()
        .find(|end| text.is_char_boundary(*end))
        .unwrap_or(0);
    &text[..cut]
}

/// Axum middleware recording one audit row per automation request.
pub async fn audit_automation_request(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let method: Method = req.method().clone();
    let path: String = req.uri().path().to_string();
    let is_mcp = path == MCP_PATH;
    let filters: String = query_parameter_names(req.uri().query());
    // Read on the way DOWN, like everything else here: a layer below
    // could otherwise strip or rewrite the headers and change what the
    // row says the caller claimed. On the MCP path the two assertion
    // headers are not read at all; the claim there is `Mcp-Name`, and
    // only for a POST the core turns out never to have seen.
    let claimed: String = if is_mcp {
        mcp_claimed_clause(req.headers())
    } else {
        asserted_clause(req.headers())
    };
    let ip: String = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_default();
    let user_agent: String = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|agent| bounded(agent, USER_AGENT_MAX_BYTES))
        .unwrap_or_default()
        .to_string();

    let slot = PrincipalSlot::default();
    req.extensions_mut().insert(slot.clone());

    let response = next.run(req).await;

    // What the MCP handler established, when it ran. Read from the
    // response because this layer is outermost and the request's
    // extensions are gone by now; absent on a POST a gate or the
    // transport rules refused, whose row is written from the status.
    let mcp: Option<McpCallRecord> = if is_mcp {
        response.extensions().get::<McpCallRecord>().cloned()
    } else {
        None
    };

    // Counted from the same word the audit row gets, so the scrape and
    // the log never disagree on what a request was. For an MCP call the
    // word comes from the core's outcome, since the core answers a
    // refused call with the same 200 as a served one.
    let decision = slot.get();
    let (outcome_word, reason): (&'static str, Option<String>) = match &mcp {
        Some(record) => mcp_outcome(record),
        None => {
            let word = outcome(response.status());
            (
                word,
                refusal_reason(response.status(), decision.as_ref(), &method, &path),
            )
        }
    };
    crate::metrics::inc_automation_request(outcome_word);
    // Labelled by the TEMPLATE the matrix declares, never the raw path:
    // a route id is the caller's own text and would be a new time
    // series per value. An undeclared path is one bucket, which is also
    // the shape a scan of the plane produces.
    crate::metrics::inc_automation_request_by_path(
        super::scope::path_template(&method, &path).unwrap_or("undeclared"),
        outcome_word,
    );

    // The principal's two halves share one column because the audit
    // row has one principal field and an automation principal has two
    // identities: the label an operator reads, and the id they revoke.
    // Splitting them would put one of them in a column that already
    // means something else. A refusal names nobody, and carries its
    // reason in the action verb instead.
    let username: String = match &decision {
        Some(AuthOutcome::Accepted { identity, .. }) => identity.clone(),
        _ => ANONYMOUS_PRINCIPAL.to_string(),
    };

    // Established beats claimed: a record means the node parsed the
    // body and ran the call, and the tool it names is a fact.
    let call: String = match &mcp {
        Some(record) => mcp_established_clause(record),
        None => claimed,
    };
    let target: String = format!("{method} {}{filters}{call}", bounded(&path, PATH_MAX_BYTES));

    let ctx = AuditContext {
        username,
        role: AUTOMATION_ROLE.to_string(),
        ip,
        user_agent,
    };
    // No `after` payload: it used to hold the reason, which the action
    // verb now carries in clear. A hash of one of two dozen known
    // words was never a secret, and a column an operator cannot read
    // is not worth the row it sits in.
    crate::audit::record(
        &state,
        &ctx,
        &action_for(outcome_word, reason.as_deref()),
        (AUTOMATION_TARGET_TYPE, &target),
        None,
        None,
    )
    .await;

    response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;
    use crate::audit::AuditQuery;
    use crate::automation::oidc::RefusalReason;
    use crate::logs::LogBuffer;
    use crate::metrics::gathered_counter;
    use crate::server::Mode;
    use crate::system::SystemCache;

    const REQUESTS: &str = "lorica_automation_requests_total";

    #[test]
    fn the_outcome_word_follows_the_status() {
        assert_eq!(outcome(StatusCode::OK), "ok");
        assert_eq!(outcome(StatusCode::NO_CONTENT), "ok");
        assert_eq!(outcome(StatusCode::UNAUTHORIZED), "unauthenticated");
        assert_eq!(outcome(StatusCode::FORBIDDEN), "forbidden");
        assert_eq!(outcome(StatusCode::NOT_FOUND), "refused");
        // The node's own fault reads as its own word.
        assert_eq!(outcome(StatusCode::INTERNAL_SERVER_ERROR), "error");
        assert_eq!(outcome(StatusCode::SERVICE_UNAVAILABLE), "error");
    }

    #[test]
    fn the_principal_slot_is_write_once() {
        let slot = PrincipalSlot::default();
        assert_eq!(slot.get(), None);
        slot.refuse("wrong_alg");
        slot.refuse("expired");
        assert_eq!(
            slot.get(),
            Some(AuthOutcome::Refused("wrong_alg".to_string()))
        );
    }

    // ---- the published vocabulary ----

    /// Every reason literal the bearer gate hands to the slot.
    ///
    /// Read out of the gate's own source, which is the only way to
    /// couple this list to a file this module does not own: a reason
    /// added there and not published here fails the test below instead
    /// of reaching an operator as a word no table explains.
    fn reasons_spelled_in_the_bearer_gate(source: &str) -> Vec<&str> {
        // The gate's own tests spell refusals too, and a test fixture
        // is not something an operator ever reads.
        let source = source.split("#[cfg(test)]").next().unwrap_or(source);
        source
            .match_indices("Err(\"")
            .filter_map(|(at, marker)| {
                let rest = &source[at + marker.len()..];
                rest.split_once('"').map(|(reason, _)| reason)
            })
            .collect()
    }

    #[test]
    fn every_reason_the_bearer_gate_can_emit_is_published() {
        let gate = include_str!("auth.rs");
        let spelled = reasons_spelled_in_the_bearer_gate(gate);
        // Cheap guard against the scan silently matching nothing the
        // day the gate is rewritten in another shape.
        assert!(
            spelled.len() >= 7,
            "the bearer gate's reason literals were not found: {spelled:?}"
        );
        for reason in spelled {
            assert!(
                is_published_reason(reason),
                "`{reason}` is emitted by the bearer gate and is not in AUTOMATION_AUDIT_REASONS"
            );
        }
        // `no_bearer` is passed to `refuse` directly rather than
        // through an `Err`, so the scan above does not see it.
        assert!(is_published_reason("no_bearer"));
    }

    #[test]
    fn every_reason_the_id_token_verifier_can_emit_is_published() {
        let every_variant = [
            RefusalReason::Malformed,
            RefusalReason::WrongAlg,
            RefusalReason::NoIssuer,
            RefusalReason::UnknownKid,
            RefusalReason::JwksUnavailable,
            RefusalReason::InvalidKey,
            RefusalReason::BadSignature,
            RefusalReason::Expired,
            RefusalReason::NotYetValid,
            RefusalReason::WrongAud,
            RefusalReason::WrongIss,
            RefusalReason::MissingClaim("jti".to_string()),
            RefusalReason::BoundClaimMismatch("environment_protected".to_string()),
            RefusalReason::Replayed,
        ];
        for variant in &every_variant {
            // Exhaustive on purpose: a new variant stops compiling
            // here, before it can reach a row as an unpublished word.
            match variant {
                RefusalReason::Malformed
                | RefusalReason::WrongAlg
                | RefusalReason::NoIssuer
                | RefusalReason::UnknownKid
                | RefusalReason::JwksUnavailable
                | RefusalReason::InvalidKey
                | RefusalReason::BadSignature
                | RefusalReason::Expired
                | RefusalReason::NotYetValid
                | RefusalReason::WrongAud
                | RefusalReason::WrongIss
                | RefusalReason::MissingClaim(_)
                | RefusalReason::BoundClaimMismatch(_)
                | RefusalReason::Replayed => {}
            }
            let reason = variant.audit_reason();
            assert!(
                is_published_reason(&reason),
                "`{reason}` is emitted by the verifier and is not in AUTOMATION_AUDIT_REASONS"
            );
        }
    }

    #[test]
    fn every_scope_a_403_can_name_is_published_and_every_mcp_reason_too() {
        // The spelling itself is pinned against serde in `scope.rs`,
        // beside the one function that spells it. What this asserts is
        // that the published vocabulary reaches every scope without a
        // list to keep in step, and every word the MCP outcome mapping
        // can write.
        for scope in AutomationScope::ALL {
            let wire = scope_str(*scope);
            assert!(
                is_published_reason(wire),
                "`{wire}` is a scope a 403 can name and is not published"
            );
        }
        for reason in [UNKNOWN_TOOL, INVALID_PARAMS, RATE_LIMITED, PROTOCOL_ERROR] {
            assert!(is_published_reason(reason), "{reason}");
        }
        // And the block that used to restate the scopes is gone: a
        // scope spelling in the list would be a second copy of the
        // enum, which is what the derivation replaced.
        assert!(
            !AUTOMATION_AUDIT_REASONS
                .iter()
                .any(|known| known.contains(':')),
            "a scope spelling is restated in AUTOMATION_AUDIT_REASONS"
        );
    }

    #[test]
    fn on_the_mcp_path_the_assertion_headers_are_ignored_and_mcp_name_is_decoded() {
        use base64::Engine as _;

        // A caller sending Lorica's own assertion headers to the MCP
        // endpoint could otherwise put a different tool in the row than
        // the one the node ran, or a transport the path already
        // establishes. Neither is read there.
        assert_eq!(
            mcp_claimed_clause(&headers_of(&[
                (ASSERTED_TRANSPORT_HEADER, "mcp-stdio"),
                (ASSERTED_TOOL_HEADER, "lorica_waf_stats"),
                (NAME_HEADER, "lorica_logs"),
            ])),
            " asserted[tool=lorica_logs]"
        );
        // A sentinel-encoded name is decoded, the way the mirror check
        // decodes it, rather than dropped for its `=` and `?`.
        let sentinel = format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode("lorica_logs")
        );
        assert_eq!(
            mcp_claimed_clause(&headers_of(&[(NAME_HEADER, &sentinel)])),
            " asserted[tool=lorica_logs]"
        );
        // Bounded like every claim: a value outside the grammar is
        // dropped whole, and a POST naming no tool claims nothing.
        assert_eq!(
            mcp_claimed_clause(&headers_of(&[(NAME_HEADER, "tool=x],transport=dashboard")])),
            ""
        );
        assert_eq!(mcp_claimed_clause(&http::HeaderMap::new()), "");
        assert_eq!(
            mcp_claimed_clause(&headers_of(&[(ASSERTED_TOOL_HEADER, "lorica_logs")])),
            ""
        );
    }

    #[test]
    fn what_the_node_established_about_an_mcp_call_is_written_outside_any_claim() {
        let record = |tool: Option<&str>, names: &[&'static str]| McpCallRecord {
            tool: tool.map(str::to_string),
            argument_names: names.to_vec(),
            outcome: Outcome::Ok,
        };
        assert_eq!(
            mcp_established_clause(&record(Some("lorica_logs"), &["limit", "search"])),
            " tool=lorica_logs?limit,search"
        );
        assert_eq!(
            mcp_established_clause(&record(Some("lorica_waf_stats"), &[])),
            " tool=lorica_waf_stats"
        );
        // A tools/list names no tool and adds nothing.
        assert_eq!(mcp_established_clause(&record(None, &[])), "");
    }

    #[test]
    fn an_mcp_row_takes_its_outcome_from_the_core_and_not_from_the_200() {
        let record = |tool: Option<&str>, outcome: Outcome| McpCallRecord {
            tool: tool.map(str::to_string),
            argument_names: Vec::new(),
            outcome,
        };
        let word = |tool: Option<&str>, outcome: Outcome| {
            let (word, reason) = mcp_outcome(&record(tool, outcome));
            action_for(word, reason.as_deref())
        };
        assert_eq!(
            word(Some("lorica_logs"), Outcome::Ok),
            "automation.request.ok"
        );
        assert_eq!(word(None, Outcome::Silence), "automation.request.ok");
        // A tool the catalogue knows and the token does not hold reads
        // like the read path's own 403: the scope it needed.
        assert_eq!(
            word(Some("lorica_certificates"), Outcome::ToolNotRegistered),
            "automation.request.forbidden:certificates:read"
        );
        assert_eq!(
            word(Some("lorica_routes_write"), Outcome::ToolNotRegistered),
            "automation.request.forbidden:unknown_tool"
        );
        assert_eq!(
            word(Some("lorica_logs"), Outcome::InvalidParams),
            "automation.request.refused:invalid_params"
        );
        assert_eq!(
            word(Some("lorica_logs"), Outcome::RateLimited),
            "automation.request.refused:rate_limited"
        );
        assert_eq!(
            word(None, Outcome::ProtocolError),
            "automation.request.refused:protocol_error"
        );
        // The plane's refusal of the read keeps the word its status has
        // on every other row, and names no scope: the tool ran, so the
        // token held it.
        assert_eq!(
            word(Some("lorica_sla_route"), Outcome::Refused(404)),
            "automation.request.refused"
        );
        assert_eq!(
            word(Some("lorica_logs"), Outcome::Refused(403)),
            "automation.request.forbidden"
        );
        assert_eq!(
            word(Some("lorica_logs"), Outcome::Refused(500)),
            "automation.request.error"
        );
        assert_eq!(
            word(Some("lorica_logs"), Outcome::Failed),
            "automation.request.error"
        );
        // Every word is one the plane already counts, so the metric's
        // label set does not grow.
        for outcome in [
            Outcome::Ok,
            Outcome::ToolNotRegistered,
            Outcome::InvalidParams,
            Outcome::RateLimited,
            Outcome::Refused(404),
            Outcome::Failed,
            Outcome::ProtocolError,
        ] {
            let (word, reason) = mcp_outcome(&record(Some("lorica_logs"), outcome));
            assert!(
                ["ok", "unauthenticated", "forbidden", "refused", "error"].contains(&word),
                "{word}"
            );
            if let Some(reason) = reason {
                assert!(is_published_reason(&reason), "{reason}");
            }
        }
    }

    #[test]
    fn a_path_and_a_user_agent_are_cut_before_they_reach_a_row() {
        assert_eq!(bounded("abc", 5), "abc");
        assert_eq!(bounded("abcdef", 3), "abc");
        // On a char boundary, never inside one.
        assert_eq!(bounded("éé", 3), "é");
        assert_eq!(bounded("", 3), "");
        assert!(PATH_MAX_BYTES > "/automation/v1/environments/".len() * 8);
    }

    #[test]
    fn the_longest_action_a_refusal_can_write_stays_short() {
        // `action` is SQLite TEXT with no length cap, so this is a
        // readability bound rather than a storage one: the longest
        // verb is still one line in a terminal.
        let longest = action_for(
            "unauthenticated",
            Some(
                &RefusalReason::BoundClaimMismatch("environment_protected".to_string())
                    .audit_reason(),
            ),
        );
        assert_eq!(
            longest,
            "automation.request.unauthenticated:bound_claim_mismatch:environment_protected"
        );
        assert_eq!(longest.len(), 77);
    }

    #[test]
    fn the_audit_target_names_the_filters_used_and_never_their_values() {
        // What separates two reads of the same path in the trail. The
        // values stay out (Story 9.9), so a search string an operator
        // typed and an attacker's payload are equally absent.
        assert_eq!(
            query_parameter_names(Some("limit=50&search=ignore%20previous&offset=0")),
            "?limit,offset,search"
        );
        assert_eq!(query_parameter_names(Some("category=xss")), "?category");
        // Repeats collapse; a bare flag still names itself.
        assert_eq!(query_parameter_names(Some("a=1&a=2&b")), "?a,b");
        assert_eq!(query_parameter_names(None), "");
        assert_eq!(query_parameter_names(Some("")), "");

        // The names are the caller's own text, so neither their length
        // nor their number can stretch the row.
        let flood: String = (0..64)
            .map(|n| format!("{}{n}=1&", "x".repeat(100)))
            .collect();
        let recorded = query_parameter_names(Some(&flood));
        assert!(recorded.len() < 600, "{} bytes", recorded.len());
        assert!(!recorded.contains(&"x".repeat(40)), "{recorded}");
    }

    /// A header map carrying `pairs`.
    fn headers_of(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                http::HeaderValue::from_str(value).expect("a header value"),
            );
        }
        headers
    }

    #[test]
    fn what_the_caller_claimed_is_recorded_as_a_claim_and_labelled_one() {
        // AC #6. The node cannot observe a tool name, because there is
        // no tool at this layer, so the only honest shape is to record
        // what the caller declared AS a declaration. The word
        // `asserted` is in the row and not only in the documentation,
        // because the row is what an operator reads with none of this
        // in front of them.
        assert_eq!(
            asserted_clause(&headers_of(&[
                (ASSERTED_TRANSPORT_HEADER, "mcp-stdio"),
                (ASSERTED_TOOL_HEADER, "lorica_logs"),
            ])),
            " asserted[transport=mcp-stdio,tool=lorica_logs]"
        );

        // The MCP server's startup `whoami` declares a transport and no
        // tool, because no tool ran.
        assert_eq!(
            asserted_clause(&headers_of(&[(ASSERTED_TRANSPORT_HEADER, "mcp-stdio")])),
            " asserted[transport=mcp-stdio]"
        );

        // A CI call claims nothing, which is the common case and must
        // add nothing to the row.
        assert_eq!(asserted_clause(&http::HeaderMap::new()), "");
    }

    #[test]
    fn an_asserted_value_is_bounded_before_it_can_become_a_row() {
        // Anyone holding a live token can send any header they like, so
        // the claim is attacker-influenced in the general case. An
        // unusable value is dropped WHOLE: half of what somebody
        // claimed is not a smaller claim, it is a different one.
        for hostile in [
            "a b",
            "tool=x],transport=dashboard",
            "lorica/logs",
            "GET /automation/v1/logs",
            "lorica_logs,tool=other",
            "",
            "   ",
        ] {
            let clause = asserted_clause(&headers_of(&[(ASSERTED_TOOL_HEADER, hostile)]));
            assert_eq!(clause, "", "{hostile:?} reached a row");
        }
        // A control character never gets this far: `HeaderValue` refuses
        // to hold one, so the transport is what stops it and this
        // filter is the belt behind that brace.
        assert!(http::HeaderValue::from_str("lorica_logs\u{7f}").is_err());
        assert!(assertable(Some("lorica_logs\u{7f}"), ASSERTED_TOOL_MAX_BYTES).is_none());

        // Length, on both fields, with the tool's ceiling being the MCP
        // grammar's own so a legitimate name always fits.
        assert_eq!(
            asserted_clause(&headers_of(&[(
                ASSERTED_TOOL_HEADER,
                &"t".repeat(ASSERTED_TOOL_MAX_BYTES)
            )])),
            format!(" asserted[tool={}]", "t".repeat(ASSERTED_TOOL_MAX_BYTES))
        );
        assert_eq!(
            asserted_clause(&headers_of(&[(
                ASSERTED_TOOL_HEADER,
                &"t".repeat(ASSERTED_TOOL_MAX_BYTES + 1)
            )])),
            ""
        );
        assert_eq!(
            asserted_clause(&headers_of(&[(
                ASSERTED_TRANSPORT_HEADER,
                &"m".repeat(ASSERTED_TRANSPORT_MAX_BYTES + 1)
            )])),
            ""
        );

        // And the whole clause stays short enough to read on one line
        // whatever arrives.
        let longest = asserted_clause(&headers_of(&[
            (
                ASSERTED_TRANSPORT_HEADER,
                &"m".repeat(ASSERTED_TRANSPORT_MAX_BYTES),
            ),
            (ASSERTED_TOOL_HEADER, &"t".repeat(ASSERTED_TOOL_MAX_BYTES)),
        ]));
        assert!(longest.len() < 200, "{} bytes", longest.len());
    }

    #[test]
    fn a_403_names_the_missing_scope_and_nothing_when_a_handler_raised_it() {
        let holds_read = AuthOutcome::Accepted {
            identity: "ci".to_string(),
            scopes: vec![AutomationScope::EnvironmentsRead],
        };
        // The scope gate refused: the verb names the grant the token
        // did not carry.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::PUT,
                "/automation/v1/environments/pr-42"
            )
            .as_deref(),
            Some("environments:write")
        );
        // A handler refused a token that DOES carry the scope: naming
        // it would send an operator to re-mint a working token.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/environments/pr-42"
            ),
            None
        );
        // A path with no entry in the matrix says so.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/tokens"
            )
            .as_deref(),
            Some(NO_DECLARED_SCOPE)
        );
        // A success explains nothing.
        assert_eq!(
            refusal_reason(
                StatusCode::OK,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/whoami"
            ),
            None
        );
        // A path any live token reaches has no scope to name, so a 403
        // on it can only be a handler's and must stay unexplained
        // rather than borrow a grant the caller already holds.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/whoami"
            ),
            None
        );
    }

    // ---- through the real layer stack ----

    /// Collects the `action` and `reason` fields of every
    /// `lorica::audit` event, without a subscriber crate: `lorica-api`
    /// does not depend on `tracing-subscriber` and this is not worth
    /// one.
    #[derive(Default)]
    struct AuditEventTap {
        seen: Mutex<Vec<TappedEvent>>,
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    struct TappedEvent {
        action: String,
        reason: String,
        target_id: String,
    }

    impl tracing::field::Visit for TappedEvent {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "action" => self.action = format!("{value:?}"),
                "reason" => self.reason = format!("{value:?}"),
                "target_id" => self.target_id = format!("{value:?}"),
                _ => {}
            }
        }
    }

    struct TapSubscriber(Arc<AuditEventTap>);

    impl tracing::Subscriber for TapSubscriber {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "lorica::audit"
        }

        /// Explicit, because the global max level is what the `info!`
        /// macro checks before it builds anything: no hint would leave
        /// it wherever the rest of the binary left it.
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }

        fn record(&self, _id: &tracing::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _id: &tracing::Id, _follows: &tracing::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "lorica::audit" {
                return;
            }
            let mut tapped = TappedEvent::default();
            event.record(&mut tapped);
            if let Ok(mut seen) = self.0.seen.lock() {
                seen.push(tapped);
            }
        }

        fn enter(&self, _id: &tracing::Id) {}

        fn exit(&self, _id: &tracing::Id) {}
    }

    /// The process-wide audit-event tap, installed on first use.
    ///
    /// A scoped subscriber would be tidier and does not work here.
    /// Callsite interest and the global max level are process-wide
    /// state cached on first use, and the eight hundred other tests in
    /// this binary run with no subscriber at all, so a guard installed
    /// mid-run races them: the `lorica::audit` callsite is sometimes
    /// already cached as "nobody is listening" and the event is never
    /// built. Installed once as the global default, before any request
    /// this test makes, it is deterministic. The tap therefore sees
    /// every test's audit events, which is why the assertion filters
    /// on a `target_id` no other test uses.
    fn audit_event_tap() -> &'static Arc<AuditEventTap> {
        static TAP: OnceLock<Arc<AuditEventTap>> = OnceLock::new();
        TAP.get_or_init(|| {
            let tap = Arc::new(AuditEventTap::default());
            let _ = tracing::subscriber::set_global_default(TapSubscriber(Arc::clone(&tap)));
            tap
        })
    }

    fn test_state(log_store: Arc<crate::log_store::LogStore>) -> AppState {
        let store = lorica_config::ConfigStore::open_in_memory().expect("test setup: store opens");
        AppState {
            store: Arc::new(tokio::sync::Mutex::new(store)),
            log_buffer: Arc::new(LogBuffer::new(100)),
            system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
            active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Instant::now(),
            data_dir: std::path::PathBuf::from("/var/lib/lorica"),
            http_port: 8080,
            https_port: 8443,
            config_reload_tx: None,
            mode: Mode::Test,
            waf_event_buffer: None,
            waf_engine: None,
            waf_rule_count: None,
            acme_challenge_store: None,
            pending_dns_challenges: Arc::new(dashmap::DashMap::new()),
            sla_collector: None,
            load_test_engine: None,
            notification_history: None,
            log_store: Some(log_store),
            log_writer: None,
            task_tracker: tokio_util::task::TaskTracker::new(),
            cluster: crate::cluster::ClusterRuntime::Standalone,
            oidc: crate::automation::oidc::test_support::verifier_without_issuer(),
            mcp_invocations: Arc::new(crate::automation::InvocationLimiter::new()),
            renewals: Arc::new(crate::acme::RenewalLedger::new()),
        }
    }

    /// Every automation row in the store, newest first.
    ///
    /// Flushes first: the layer only enqueues the row, so it is
    /// durable within the audit writer's next drain and not when the
    /// response came back.
    async fn automation_rows(
        log_store: &crate::log_store::LogStore,
    ) -> Vec<crate::audit::AuditRecord> {
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");
        let (rows, _) = log_store
            .query_audit(&AuditQuery {
                action_prefix: Some("automation.request.".to_string()),
                limit: 50,
                ..AuditQuery::default()
            })
            .expect("the audit query runs");
        rows
    }

    #[tokio::test]
    async fn a_long_path_and_a_long_user_agent_do_not_stretch_the_row() {
        // Both are the caller's own text, bounded until this layer only
        // by what hyper accepts, and this layer is outermost: the bound
        // applies to a request the bearer gate refuses as much as to
        // one it lets through.
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store =
            Arc::new(crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"));
        let state = test_state(Arc::clone(&log_store));
        let router = crate::automation::build_automation_router(state);

        let long_path = format!("/automation/v1/{}", "p".repeat(PATH_MAX_BYTES * 2));
        let long_agent = "a".repeat(USER_AGENT_MAX_BYTES * 4);
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method(Method::GET)
                    .uri(long_path)
                    .header(header::USER_AGENT, &long_agent)
                    .body(Body::empty())
                    .expect("test setup: request builds"),
            )
            .await
            .expect("test setup: request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let rows = automation_rows(&log_store).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            rows[0].target_id.len() <= PATH_MAX_BYTES + "GET ".len(),
            "{} bytes",
            rows[0].target_id.len()
        );
        assert_eq!(rows[0].user_agent.len(), USER_AGENT_MAX_BYTES);
    }

    #[tokio::test]
    async fn a_refusal_lands_a_row_whose_action_names_the_reason_and_an_event_carrying_it() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store =
            Arc::new(crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"));
        let state = test_state(Arc::clone(&log_store));
        let router = crate::automation::build_automation_router(state);

        // A path no other test asks for, because the tap is shared by
        // the whole binary and `target_id` is what tells this
        // request's event from everyone else's. The bearer gate
        // refuses before routing, so the path need not exist.
        const PROBE: &str = "/automation/v1/environments/audit-reason-probe";
        let tap = audit_event_tap();
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method(Method::GET)
                    .uri(PROBE)
                    .header(header::AUTHORIZATION, "Bearer definitely-not-a-credential")
                    .body(Body::empty())
                    .expect("test setup: request builds"),
            )
            .await
            .expect("test setup: request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 1. The stored row, which is what `GET /api/v1/audit` returns.
        let rows = automation_rows(&log_store).await;
        assert_eq!(rows.len(), 1, "one row per request: {rows:?}");
        assert_eq!(
            rows[0].action,
            "automation.request.unauthenticated:not_a_credential"
        );
        assert_eq!(rows[0].operator_username, ANONYMOUS_PRINCIPAL);
        assert_eq!(rows[0].operator_role, AUTOMATION_ROLE);

        // 2. The tracing event, which is what syslog and OTLP carry.
        let seen = tap.seen.lock().expect("the tap lock holds");
        let mine: Vec<&TappedEvent> = seen
            .iter()
            .filter(|event| event.target_id == format!("GET {PROBE}"))
            .collect();
        assert_eq!(mine.len(), 1, "one event for this request: {seen:?}");
        assert_eq!(
            mine[0].action,
            "automation.request.unauthenticated:not_a_credential"
        );
        assert_eq!(mine[0].reason, "not_a_credential");
    }

    /// The bug this stands in for: any handler that unwinds. Named
    /// rather than a closure so the return type is a real one and not
    /// the never type.
    async fn a_handler_that_unwinds() -> &'static str {
        panic!("a handler that unwinds")
    }

    #[tokio::test]
    async fn a_panicking_handler_answers_500_and_still_lands_a_row() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store =
            Arc::new(crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"));
        let state = test_state(Arc::clone(&log_store));

        // The production router mounts no panicking handler, so the
        // test supplies one; the layer pair under it is the real one,
        // built by the same function `build_automation_router` calls.
        let router = crate::automation::router::with_audit_and_panic_net(
            Router::new().route("/automation/v1/panic", get(a_handler_that_unwinds)),
            state,
        );

        let before = gathered_counter(REQUESTS, &[("outcome", "error")]);
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method(Method::GET)
                    .uri("/automation/v1/panic")
                    .body(Body::empty())
                    .expect("test setup: request builds"),
            )
            .await
            .expect("the panic never reaches the caller as a broken connection");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let rows = automation_rows(&log_store).await;
        assert_eq!(rows.len(), 1, "the row an operator most wants: {rows:?}");
        assert_eq!(rows[0].action, "automation.request.error");
        assert!(gathered_counter(REQUESTS, &[("outcome", "error")]) > before);
    }
}
