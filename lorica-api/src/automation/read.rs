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

//! The automation plane's read surface (Story 11.1): logs, WAF events
//! and stats, SLA, cluster status, backends, routes and certificate
//! metadata, each behind its own scope.
//!
//! # Why this exists at all
//!
//! The management API already serves every one of these answers, and
//! PRD decision D3 keeps the MCP server off that plane precisely so it
//! never holds a management credential. The answers therefore have to
//! be reachable from the automation listener, which until this story
//! mounted four paths: `whoami` and the environment resource.
//!
//! # Every handler here is a wrapper, never a second implementation
//!
//! Each one calls the management handler or the function that handler
//! was split out of, and re-wraps the rows it returns. Nothing in this
//! module computes a figure or serialises a record. Two surfaces that
//! compute the same answer independently drift, and the drift shows up
//! as a field one of them stopped stripping, which is a leak nobody's
//! test notices. What this module adds is the window around the rows,
//! the ordering the window walks, and two things the management plane
//! has no reason to do (fix pass of Story 11.4, 2026-09-30):
//!
//! - it withholds the values that can carry a credential, through
//!   [`super::redact`], and keeps every key, and the name of an
//!   environment the reader could not look up on the environment
//!   endpoint;
//! - for a principal whose grants mean something
//!   ([`AutomationPrincipal::carries_grants`]), it answers only the
//!   routes, backends and certificates inside those grants.
//!
//! # A granted principal sees what it may act on, and nothing else
//!
//! A config-tier token reads routes, backends and certificates to find
//! the ids its tools act on, and those listings used to be node-wide.
//! Their free-text fields (an error page, a rewrite, a backend name) are
//! written by every other principal holding a write scope, OIDC
//! pipelines included, so a config-tier model read text a lower-trust
//! writer planted and could act on it with a wider grant than that
//! writer's. The listing is therefore the set the write guard admits,
//! by the same predicates ([`super::write::route_names_granted`],
//! [`super::write::certificate_names_granted`] and the backend address
//! check), so what a granted token sees and what it may change are one
//! set. Paging walks the filtered set. A principal whose grants bound
//! nothing (the read tier) sees every row, as before.
//!
//! No read on this plane fetches a route, a backend or a certificate by
//! id; the single-row management paths are not mounted. The one place
//! an id outside the grant is named is a write or a preview, which is
//! refused with a `403` naming the id and nothing about the row.
//!
//! # The window is the server's, not the caller's
//!
//! Every collection answers `{"items": [...], "page": {...}}`, and the
//! page is bounded twice: by [`AUTOMATION_READ_MAX_ROWS`] whatever
//! `?limit=` says, and by [`AUTOMATION_READ_MAX_ANSWER_BYTES`] whatever
//! the rows weigh. The caller of this surface is a language model
//! asking on an operator's behalf, and a model that asks for everything
//! must not be able to pull the access log into a context window. A
//! ceiling the caller can raise is not a ceiling, and a ceiling that
//! counts rows does not bound an answer whose fields are
//! attacker-authored and unbounded.
//!
//! # A window this surface cannot reach is a refusal, never an empty
//! page
//!
//! Two of the sources clamp their own row budget
//! ([`crate::logs::LOGS_QUERY_MAX_ROWS`],
//! [`crate::waf::WAF_EVENTS_MAX_ROWS`]). Past that clamp an
//! offset-based read gets fewer rows than the window starts at, so the
//! honest-looking answer is `{"items": [], "has_more": false}` while
//! the table still holds thousands of rows. That is the one failure an
//! operator, or a model paginating on `has_more`, reads as "there was
//! nothing". Such an offset is a 400 naming the depth instead: see
//! [`PageQuery::page_within`].
//!
//! # No secret crosses this boundary
//!
//! Most of that is inherited from the management plane's views:
//! certificate key material never leaves [`crate::certificates`]'s list
//! view, and a route's Basic-auth hash never leaves [`crate::routes`]'s.
//! What those views do carry for the dashboard's sake, a route's
//! `proxy_headers` values above all, [`super::redact`] withholds. None
//! of it is a promise, so `read/plane_tests.rs` walks every path
//! [`super::scope`] declares - the list it walks is derived from that
//! matrix, not retyped beside it - for the field names that must never
//! appear (Story 11.1 AC #5), and pins the whole set of key names each
//! answer carries against a committed list, so a field added to a
//! management view reaches this plane only by someone deciding it
//! should.

use axum::extract::{Extension, Path, Query};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::auth::AutomationPrincipal;
use super::environments::{ensure_backend_address_granted, environments_visible_to};
use super::redact;
use super::write::{certificate_names_granted, route_names_granted};
use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// The most rows any automation read returns in one answer, whatever
/// the caller asks for.
///
/// Server-side and not negotiable: see the module comment.
pub const AUTOMATION_READ_MAX_ROWS: usize = 200;

/// The window size when the caller names none.
pub const AUTOMATION_READ_DEFAULT_ROWS: usize = 50;

/// The most bytes of row data one automation answer carries.
///
/// [`AUTOMATION_READ_MAX_ROWS`] counts rows, and the fields those rows
/// carry are attacker-authored and unbounded: a WAF event's matched
/// value is the raw regex match, truncated neither when it is recorded
/// nor when it is read. A row ceiling alone therefore does not bound
/// what AC #4 exists to bound. Rows are dropped whole rather than
/// truncated, so no field ever arrives mangled: the answer comes back
/// with `returned` short of `limit` and `has_more` true, which is the
/// signal a pager already reads.
pub const AUTOMATION_READ_MAX_ANSWER_BYTES: usize = 256 * 1024;

/// The most bytes a caller may put in one free-text filter.
///
/// `?search=` becomes five unanchored `LIKE` predicates over the
/// retained access log (this plane skips the match count the dashboard
/// pays for, but not the scan), so its length is a per-request cost the
/// caller chooses. The management plane takes it
/// from a dashboard field behind a session; this one takes it off-box
/// behind a token the router gives no per-request budget. Long enough
/// for a request id, a hostname or a user-agent fragment.
const AUTOMATION_READ_MAX_FILTER_BYTES: usize = 256;

/// `?limit=` and `?offset=` on any automation collection.
///
/// Extracted beside each endpoint's own filter struct rather than
/// merged into it, so the filters stay exactly the management plane's
/// and this surface never transcribes a filter vocabulary it does not
/// own.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    /// Rows wanted, clamped to [`AUTOMATION_READ_MAX_ROWS`].
    pub limit: Option<usize>,
    /// Rows to skip before the window starts.
    pub offset: Option<usize>,
}

/// One window over a collection, after the server-side ceiling.
#[derive(Debug, Clone, Copy)]
struct Page {
    limit: usize,
    offset: usize,
}

/// What a paginated automation read reports about its own window.
///
/// No total: the sources behind this surface count differently (the
/// log store counts every match, the WAF buffer counts what it
/// returned, a store listing counts rows), and one field meaning three
/// things is worse than no field.
///
/// `returned` and not `limit` is what a pager advances `offset` by. The
/// two are usually equal, and are not when the byte ceiling
/// ([`AUTOMATION_READ_MAX_ANSWER_BYTES`]) ended the answer early;
/// advancing by `limit` would then step over the rows that did not fit.
#[derive(Debug, Serialize)]
struct PageInfo {
    limit: usize,
    offset: usize,
    returned: usize,
    has_more: bool,
    /// On a read that pages by keyset (`/logs`), what to send as
    /// `before_id` for the next window: the id of the last row
    /// returned, or null when there is no next window. Absent on every
    /// other read.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<Option<u64>>,
}

impl PageQuery {
    /// This query's window over a source that answers its own full
    /// listing: routes, backends, certificates, SLA.
    ///
    /// An offset past the end of one of those is an empty window and an
    /// honest one, because the source really held nothing there.
    fn page(&self) -> Page {
        Page {
            limit: self
                .limit
                .unwrap_or(AUTOMATION_READ_DEFAULT_ROWS)
                .clamp(1, AUTOMATION_READ_MAX_ROWS),
            offset: self.offset.unwrap_or(0),
        }
    }

    /// This query's window over a source that clamps its own row budget
    /// at `depth`, refusing an offset that clamp cannot honour.
    ///
    /// Two things ride on the refusal. It is what makes `has_more`
    /// mean something on a clamped source: every window this returns is
    /// one the source can fill, so a `false` is the end of the data and
    /// not the end of the reach. And it is what bounds `offset`, which
    /// is otherwise the caller's lever on how much work the node does
    /// per request: `scan()` feeds the source's own limit, so an
    /// unbounded offset turns a 50-row answer into a 10 000-row fetch
    /// under the mutex the audit drain shares.
    ///
    /// # Errors
    ///
    /// `BadRequest` naming the deepest offset this limit can reach.
    fn page_within(&self, depth: usize) -> Result<Page, ApiError> {
        let page = self.page();
        if page.scan() > depth {
            let deepest = depth.saturating_sub(page.limit).saturating_sub(1);
            return Err(ApiError::BadRequest(format!(
                "this read reaches at most {depth} rows, so with limit={} the deepest \
                 window starts at offset={deepest}. Narrow the read with its filters \
                 rather than paging past that.",
                page.limit
            )));
        }
        Ok(page)
    }
}

impl Page {
    /// How many rows to ask a limit-taking source for: one past the
    /// window, so `has_more` is answered without a second query and the
    /// source is never read further than the window can hold.
    fn scan(self) -> usize {
        self.offset.saturating_add(self.limit).saturating_add(1)
    }

    /// Wrap `rows` in the paginated envelope this surface answers with.
    fn of(self, rows: Vec<Value>) -> Result<Response, ApiError> {
        self.of_window(self.window_of(rows))
    }

    /// The rows of a full listing this window answers: from `offset`
    /// on, one past the window when there is one.
    fn window_of(self, rows: Vec<Value>) -> Vec<Value> {
        rows.into_iter()
            .skip(self.offset)
            .take(self.limit.saturating_add(1))
            .collect()
    }

    /// [`Page::of`] for a source that already skipped `offset`: `window`
    /// holds the rows from `offset` on, one past the window when there
    /// is one, and is built by a source that computes nothing before
    /// the window.
    fn of_window(self, window: Vec<Value>) -> Result<Response, ApiError> {
        Ok(json_text_response(self.envelope(window, None)?))
    }

    /// The answer's JSON text: `{"data": {"items": [...], "page": {...}}}`
    /// with `cursor` read off the last row returned when it is given.
    ///
    /// Each row is serialised once, to weigh it against the byte
    /// ceiling, and that text is the row's text in the answer: the
    /// envelope is built around it rather than serialising every row a
    /// second time on the way out. The text is what `json_data` of the
    /// same items would serialise to, byte for byte (a test holds the
    /// two together), since `serde_json` writes an object's keys in
    /// sorted order either way.
    fn envelope(
        self,
        window: Vec<Value>,
        cursor: Option<fn(&Value) -> Option<u64>>,
    ) -> Result<String, ApiError> {
        let beyond_the_window = window.len() > self.limit;
        let mut budget = AUTOMATION_READ_MAX_ANSWER_BYTES;
        let mut short_of_the_window = false;
        let mut items = String::from("[");
        let mut returned = 0usize;
        let mut last_cursor = None;
        for row in window.into_iter().take(self.limit) {
            let text = serde_json::to_string(&row)
                .map_err(|e| ApiError::Internal(format!("automation read: a row: {e}")))?;
            // The first row crosses whatever it weighs. An answer with
            // nothing in it is the one shape a reader takes for "there
            // was nothing", and a single oversized row is exactly the
            // row an operator is looking for.
            if text.len() > budget && returned > 0 {
                short_of_the_window = true;
                break;
            }
            budget = budget.saturating_sub(text.len());
            if returned > 0 {
                items.push(',');
            }
            items.push_str(&text);
            returned += 1;
            last_cursor = cursor.and_then(|read| read(&row));
        }
        items.push(']');
        let has_more = beyond_the_window || short_of_the_window;
        let page = PageInfo {
            limit: self.limit,
            offset: self.offset,
            returned,
            has_more,
            next_cursor: cursor.map(|_| last_cursor.filter(|_| has_more)),
        };
        // Through `Value` so the page's keys are written in the order
        // `json_data` writes them, which is sorted, not declared.
        let page = serde_json::to_value(page)
            .and_then(|page| serde_json::to_string(&page))
            .map_err(|e| ApiError::Internal(format!("automation read: the page: {e}")))?;
        Ok(format!(r#"{{"data":{{"items":{items},"page":{page}}}}}"#))
    }
}

/// `text`, already JSON, as the response `Json` would have made of the
/// value it encodes.
fn json_text_response(text: String) -> Response {
    (
        [(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        )],
        text,
    )
        .into_response()
}

/// The array a management answer carries under `data.<field>`, or under
/// `data` itself when `field` is `None`.
///
/// A shape that does not match is a wiring fault in this crate, not a
/// caller's mistake, and it answers 500 rather than an empty page: an
/// empty page is the one failure an operator reads as "there was
/// nothing", which is exactly the wrong conclusion.
fn rows(answer: Json<Value>, field: Option<&str>) -> Result<Vec<Value>, ApiError> {
    let mut envelope = answer.0;
    let data = envelope.get_mut("data").map(Value::take);
    let array = match (data, field) {
        (Some(Value::Object(mut map)), Some(field)) => map.remove(field),
        (Some(value), None) => Some(value),
        _ => None,
    };
    match array {
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err(ApiError::Internal(format!(
            "automation read: the management answer carries no array at data.{}",
            field.unwrap_or("")
        ))),
    }
}

/// The string at `row[field]`, or the empty string when there is none.
fn text<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field).and_then(Value::as_str).unwrap_or_default()
}

/// Every string in the array at `row[field]`.
fn texts<'a>(row: &'a Value, field: &str) -> impl Iterator<Item = &'a str> {
    row.get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// `rows`, reduced to the ones `inside` admits when `principal` carries
/// grants, and every row otherwise.
///
/// A row missing the field its predicate reads is outside: a management
/// view that renamed a field fails closed here, and the field-set pin in
/// `read/plane_tests.rs` is what reports the rename.
fn within_the_grant(
    principal: &AutomationPrincipal,
    rows: Vec<Value>,
    inside: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    if !principal.carries_grants() {
        return rows;
    }
    rows.into_iter().filter(|row| inside(row)).collect()
}

/// `rows` with `mask` applied to each.
fn masked(mut rows: Vec<Value>, mask: fn(&mut Value)) -> Vec<Value> {
    rows.iter_mut().for_each(mask);
    rows
}

/// `rows` with every environment name their `managed_by` marks carry
/// withheld, unless `principal` may look that environment up
/// ([`environments_visible_to`]). The store is read only when a row
/// names one.
async fn without_foreign_environments(
    state: &AppState,
    principal: &AutomationPrincipal,
    mut rows: Vec<Value>,
) -> Result<Vec<Value>, ApiError> {
    let named: std::collections::BTreeSet<String> = rows
        .iter()
        .filter_map(redact::managed_by_environment)
        .map(str::to_string)
        .collect();
    if named.is_empty() {
        return Ok(rows);
    }
    let visible = environments_visible_to(state, principal, named).await?;
    for row in &mut rows {
        redact::environment_outside(row, &visible);
    }
    Ok(rows)
}

/// Refuse a free-text filter longer than this surface accepts.
///
/// `name` is this module's own vocabulary, never the caller's text, so
/// the refusal reflects nothing back at the model that reads it.
///
/// # Errors
///
/// `BadRequest` when `value` is over the ceiling.
fn within_the_filter_ceiling(name: &str, value: Option<&str>) -> Result<(), ApiError> {
    match value {
        Some(text) if text.len() > AUTOMATION_READ_MAX_FILTER_BYTES => Err(ApiError::BadRequest(
            format!("?{name}= accepts at most {AUTOMATION_READ_MAX_FILTER_BYTES} bytes here"),
        )),
        _ => Ok(()),
    }
}

/// The same refusal, with any identifier the caller supplied removed.
///
/// The management plane echoes the id back ("route `<id>`"), which is
/// the right answer for a dashboard toast. Here the reader is a
/// language model and the echoed span is whatever the caller put in the
/// path, so the refusal names the class of thing and nothing the caller
/// chose.
fn without_the_callers_echo(error: ApiError) -> ApiError {
    match error {
        ApiError::NotFound(_) => ApiError::NotFound("this node holds no route with that id".into()),
        other => other,
    }
}

/// `GET /automation/v1/logs` (scope `logs:read`).
///
/// The access log with the filters the dashboard already offers, taken
/// verbatim as [`crate::logs::LogsQuery`] so neither the filter names
/// nor their meaning is restated here. `limit` is this surface's, not
/// the query's: whatever the caller asks for, the store is read one row
/// past the window and no further.
///
/// Rows come back newest first, so page one is what just happened.
/// `before_id` is the keyset cursor that walks back in time: the answer
/// names the next one as `page.next_cursor`, and a window taken by it
/// reads only its own rows however deep it lies, where `offset` has the
/// store read and discard every row above the window. `offset` is kept
/// for the caller that wants a few windows and no cursor, as deep as
/// [`crate::logs::LOGS_QUERY_MAX_ROWS`] and no deeper; it applies
/// after `before_id` when both are sent. `after_id` bounds the other
/// end, for a caller tailing a log that is still growing.
///
/// # Errors
///
/// `BadRequest` for an unreachable offset or an oversized filter, then
/// whatever [`crate::logs::get_logs`] answers.
pub async fn list_logs(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::logs::LogsQuery>,
) -> Result<Response, ApiError> {
    let page = page.page_within(crate::logs::LOGS_QUERY_MAX_ROWS)?;
    within_the_filter_ceiling("search", filters.search.as_deref())?;
    within_the_filter_ceiling("route", filters.route.as_deref())?;
    within_the_filter_ceiling("client_ip", filters.client_ip.as_deref())?;
    let filters = crate::logs::LogsQuery {
        limit: Some(page.scan()),
        ..filters
    };
    // The rows alone: this surface answers no total, so the match count
    // the dashboard's answer carries is never computed.
    let mut rows = crate::logs::log_rows(&state, filters)
        .await?
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::Internal(format!("automation read: a log row: {e}")))?;
    // Both log sources fetch the NEWEST `scan` rows and hand them back
    // oldest first: the store runs `ORDER BY id DESC LIMIT ?` and then
    // reverses, the in-memory fallback returns the tail of a
    // chronological buffer. Walking that array from the front means
    // `offset` walks the window's OLDEST end, so every offset answered
    // nearly the same rows, the newest row was unreachable at any
    // offset, and `has_more` never went false. `/waf/events` answers
    // newest first and pages correctly; this makes the two agree.
    rows.reverse();
    let window = page.window_of(masked(rows, redact::access_log_row));
    Ok(json_text_response(page.envelope(
        window,
        Some(|row| row.get("id").and_then(Value::as_u64)),
    )?))
}

/// `GET /automation/v1/waf/events` (scope `waf:read`).
///
/// Recent WAF events, newest first, `?category=` narrowing them the way
/// the dashboard does. A matched payload is attacker-controlled text
/// and travels as the field the WAF recorded it in, unchanged and
/// uninterpreted. `offset` reaches as deep as
/// [`crate::waf::WAF_EVENTS_MAX_ROWS`] and no deeper.
///
/// # Errors
///
/// `BadRequest` for an unreachable offset, then whatever
/// [`crate::waf::get_waf_events`] answers.
pub async fn list_waf_events(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::waf::WafEventsQuery>,
) -> Result<Response, ApiError> {
    let page = page.page_within(crate::waf::WAF_EVENTS_MAX_ROWS)?;
    within_the_filter_ceiling("category", filters.category.as_deref())?;
    let filters = crate::waf::WafEventsQuery {
        limit: Some(page.scan()),
        ..filters
    };
    let answer = crate::waf::get_waf_events(Extension(state), Query(filters)).await?;
    page.of(rows(answer, Some("events"))?)
}

/// How old the WAF counters `/waf/stats` answers may be.
///
/// The persistent aggregates are whole-table passes under the log
/// store's one connection, and this plane gives a token no per-request
/// budget on reads, so a caller polling them in a loop scanned the
/// table on every call. Counters a few seconds old answer the question
/// this read exists for, and the table is scanned at most once per
/// window however often it is asked.
pub const WAF_STATS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(5);

/// `GET /automation/v1/waf/stats` (scope `waf:read`).
///
/// One summary object, the dashboard's, with its persistent counters
/// up to [`WAF_STATS_MAX_AGE`] old. Not paginated and not a collection:
/// its only array is the count per rule category, a fixed vocabulary of
/// rule families rather than a row set that grows with traffic.
///
/// # Errors
///
/// Whatever [`crate::waf::get_waf_stats`] answers.
pub async fn waf_stats(Extension(state): Extension<AppState>) -> Result<Json<Value>, ApiError> {
    crate::waf::waf_stats(&state, Some(WAF_STATS_MAX_AGE)).await
}

/// `GET /automation/v1/sla/overview` (scope `sla:read`).
///
/// The 1h and 24h passive summaries for every route this node holds,
/// two rows per route. `?node=` is deliberately absent: proxying a read
/// to a follower carries an operator floor a credential with no role
/// cannot be weighed against.
///
/// The window travels down into the computation rather than slicing
/// what it produced: each summary is two synchronous SQL passes under
/// the process-wide config-store mutex, so computing every route's
/// figures to answer `?limit=1` held that lock against every
/// configuration write for no one's benefit. The routes before the
/// window are skipped rather than computed, so `offset` costs nothing
/// either, however deep: an offset past the end answers an empty page
/// having computed no summary.
///
/// # Errors
///
/// Whatever [`crate::sla::local_sla_overview`] answers.
pub async fn sla_overview(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let page = page.page();
    let window = crate::sla::SlaWindow {
        skip: page.offset,
        take: page.limit.saturating_add(1),
    };
    let summaries = crate::sla::local_sla_overview(&state, Some(window)).await?;
    page.of_window(rows(json_data(summaries), None)?)
}

/// `GET /automation/v1/sla/routes/{id}` (scope `sla:read`).
///
/// One route's passive summaries over every standard window.
///
/// # Errors
///
/// Whatever [`crate::sla::local_route_sla`] answers, including a 404
/// for a route this node does not hold, with the caller's own id struck
/// out of the message.
pub async fn route_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let page = page.page();
    let summaries = crate::sla::local_route_sla(&state, route_id)
        .await
        .map_err(without_the_callers_echo)?;
    page.of(rows(json_data(summaries), None)?)
}

/// `GET /automation/v1/cluster/status` (scope `cluster:read`).
///
/// This node's role, build, applied configuration generation and, on a
/// control plane, the fleet summary. One object, answered unchanged.
///
/// The fleet ROSTER is deliberately not on this plane: it is the one
/// cluster read the management API gates at `Operator` rather than
/// `Viewer`, because it discloses each follower's source address and
/// the hostnames whose private keys it holds. Status is `Viewer` on
/// both planes and answers the question this surface exists for.
///
/// # Errors
///
/// Whatever [`crate::cluster::get_status`] answers.
pub async fn cluster_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<Value>, ApiError> {
    crate::cluster::get_status(Extension(state)).await
}

/// `GET /automation/v1/backends` (scope `backends:read`).
///
/// Every backend with its live EWMA score and connection count, the
/// same view the dashboard's backend table reads, with its health-check
/// query values withheld. A principal carrying grants sees the backends
/// whose address is inside its `allowed_backend_cidrs`, and no other. A
/// backend an environment owns names that environment only to a
/// principal the environment endpoint would answer for it.
///
/// # Errors
///
/// Whatever [`crate::backends::list_backends`] answers.
pub async fn list_backends(
    principal: AutomationPrincipal,
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let page = page.page();
    let answer = crate::backends::list_backends(Extension(state.clone())).await?;
    let rows = within_the_grant(&principal, rows(answer, Some("backends"))?, |row| {
        ensure_backend_address_granted(&principal, "address", text(row, "address")).is_ok()
    });
    let window = page.window_of(masked(rows, redact::backend_row));
    page.of_window(without_foreign_environments(&state, &principal, window).await?)
}

/// `GET /automation/v1/routes` (scope `routes:read`).
///
/// Every route with its linked backend ids, `?group=` narrowing them as
/// on the management plane. The view carries a Basic-auth username and
/// never its hash, because it is the management plane's own view, and
/// its `proxy_headers` names without their values. A principal carrying
/// grants sees the routes whose hostname and every alias are inside its
/// `allowed_hostnames`, and no other. A route an environment owns names
/// that environment only to a principal the environment endpoint would
/// answer for it, and every header rule's match value is withheld.
///
/// The grant and the window are applied to the stored rows, and only
/// the window's views are built, masked and serialised: the listing is
/// two queries under the config lock whatever the route count, and a
/// page costs its own rows rather than every route's.
///
/// # Errors
///
/// Whatever [`crate::routes::crud::routes_with_links`] answers.
pub async fn list_routes(
    principal: AutomationPrincipal,
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::routes::ListRoutesQuery>,
) -> Result<Response, ApiError> {
    let page = page.page();
    let bounded = principal.carries_grants();
    let window = crate::routes::crud::routes_with_links(&state, filters)
        .await?
        .into_iter()
        .filter(|(route, _)| {
            !bounded
                || route_names_granted(
                    &principal,
                    &route.hostname,
                    route.hostname_aliases.iter().map(String::as_str),
                )
        })
        .skip(page.offset)
        .take(page.limit.saturating_add(1))
        .map(|(route, backend_ids)| {
            serde_json::to_value(crate::routes::crud::route_to_response(&route, backend_ids))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::Internal(format!("automation read: a route view: {e}")))?;
    let window = masked(window, redact::route_row);
    page.of_window(without_foreign_environments(&state, &principal, window).await?)
}

/// `GET /automation/v1/certificates` (scope `certificates:read`).
///
/// Certificate metadata: domain, SANs, fingerprint, issuer, validity
/// window and ACME settings. Never a PEM body and never key material,
/// because this is the management plane's list view, which carries
/// neither. The single-certificate path, which does return the public
/// PEM, is deliberately not mounted here. A principal carrying grants
/// sees the certificates whose domain and every SAN are inside its
/// `allowed_hostnames`, and no other.
///
/// # Errors
///
/// Whatever [`crate::certificates::list_certificates`] answers.
pub async fn list_certificates(
    principal: AutomationPrincipal,
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let page = page.page();
    let answer = crate::certificates::list_certificates(Extension(state)).await?;
    let rows = within_the_grant(&principal, rows(answer, Some("certificates"))?, |row| {
        !text(row, "domain").is_empty()
            && certificate_names_granted(&principal, text(row, "domain"), texts(row, "san_domains"))
    });
    page.of(rows)
}

#[cfg(test)]
mod plane_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_free_text_argument_the_tools_accept_is_one_the_plane_reads() {
        // `lorica-mcp` bounds its free-text arguments to spare a round
        // trip; a bound looser than this surface's would be a value the
        // tool passes and the plane answers 400.
        const { assert!(lorica_mcp::tools::FREE_TEXT_MAX_BYTES <= AUTOMATION_READ_MAX_FILTER_BYTES) };
    }

    fn numbered(count: usize) -> Vec<Value> {
        (0..count).map(|n| serde_json::json!({ "n": n })).collect()
    }

    fn page_of(limit: Option<usize>, offset: Option<usize>) -> Page {
        PageQuery { limit, offset }.page()
    }

    impl Page {
        /// What [`Page::of`] answers, parsed back.
        fn answer(self, rows: Vec<Value>) -> Json<Value> {
            let text = self
                .envelope(self.window_of(rows), None)
                .expect("an envelope");
            Json(serde_json::from_str(&text).expect("the envelope is JSON"))
        }
    }

    /// The bytes the envelope used to be: every item serialised again
    /// inside the `json_data` value the handler answered.
    fn as_json_data_wrote_it(page: Page, rows: Vec<Value>) -> String {
        let parsed = page.answer(rows).0;
        let items = parsed["data"]["items"].clone();
        let info = parsed["data"]["page"].clone();
        serde_json::to_string(&json_data(serde_json::json!({ "items": items, "page": info })).0)
            .expect("a value serialises")
    }

    #[test]
    fn the_envelope_is_byte_for_byte_what_json_data_wrote() {
        // The rows are serialised once now and spliced; the answer must
        // not move by a byte for it, escapes and key order included.
        let awkward: Vec<Value> = (0..30)
            .map(|n| {
                serde_json::json!({
                    "zeta": n,
                    "alpha": "quote \" backslash \\ newline \n tab \t nul \u{0} emoji \u{1F600}",
                    "nested": { "b": [1, 2.5, null, true], "a": {} },
                    "path": "/p?a=[redacted]",
                })
            })
            .collect();
        for (limit, offset) in [
            (Some(10), None),
            (Some(10), Some(25)),
            (Some(200), Some(99)),
        ] {
            let page = page_of(limit, offset);
            let spliced = page
                .envelope(page.window_of(awkward.clone()), None)
                .expect("an envelope");
            assert_eq!(spliced, as_json_data_wrote_it(page, awkward.clone()));
        }
        // An answer the byte ceiling ended early, and an empty one.
        let heavy: Vec<Value> = (0..20)
            .map(|n| serde_json::json!({ "n": n, "payload": "x".repeat(40 * 1024) }))
            .collect();
        let page = page_of(Some(20), None);
        assert_eq!(
            page.envelope(page.window_of(heavy.clone()), None)
                .expect("an envelope"),
            as_json_data_wrote_it(page, heavy)
        );
        let page = page_of(Some(5), None);
        assert_eq!(
            page.envelope(Vec::new(), None).expect("an envelope"),
            as_json_data_wrote_it(page, Vec::new())
        );
    }

    #[test]
    fn a_keyset_read_names_the_next_cursor_and_only_when_there_is_a_next_window() {
        let id = |row: &Value| row.get("id").and_then(Value::as_u64);
        let newest_first: Vec<Value> = (1..=5u64)
            .rev()
            .map(|n| serde_json::json!({ "id": n }))
            .collect();
        let parsed = |page: Page, rows: Vec<Value>| -> Value {
            serde_json::from_str(
                &page
                    .envelope(page.window_of(rows), Some(id))
                    .expect("an envelope"),
            )
            .expect("the envelope is JSON")
        };

        // Rows 5 and 4 came back; the next window is below 4.
        let answered = parsed(page_of(Some(2), None), newest_first.clone());
        assert_eq!(answered["data"]["page"]["next_cursor"], 4);

        // The last window says so with a null, never an absent field.
        let answered = parsed(page_of(Some(10), None), newest_first.clone());
        assert_eq!(answered["data"]["page"]["has_more"], false);
        assert_eq!(answered["data"]["page"]["next_cursor"], Value::Null);
        assert!(answered["data"]["page"]
            .as_object()
            .is_some_and(|page| page.contains_key("next_cursor")));

        // The byte ceiling ending a window early names the last row that
        // did fit, so nothing is stepped over.
        let heavy: Vec<Value> = (1..=20u64)
            .rev()
            .map(|n| serde_json::json!({ "id": n, "payload": "x".repeat(40 * 1024) }))
            .collect();
        let answered = parsed(page_of(Some(20), None), heavy);
        let returned = answered["data"]["items"].as_array().map_or(0, Vec::len);
        assert!(returned > 0 && returned < 20, "{returned}");
        assert_eq!(
            answered["data"]["page"]["next_cursor"],
            answered["data"]["items"][returned - 1]["id"]
        );

        // A read that pages by offset alone says nothing of a cursor.
        let answered = page_of(Some(2), None).answer(newest_first);
        assert!(answered.0["data"]["page"].get("next_cursor").is_none());
    }

    #[test]
    fn the_ceiling_is_the_servers_and_the_caller_cannot_raise_it() {
        // The whole point of the cap: a caller asking for everything
        // gets the window, not the table.
        for asked in [
            AUTOMATION_READ_MAX_ROWS + 1,
            10_000,
            usize::MAX,
            usize::MAX - 1,
        ] {
            assert_eq!(
                page_of(Some(asked), None).limit,
                AUTOMATION_READ_MAX_ROWS,
                "{asked}"
            );
        }
        assert_eq!(page_of(None, None).limit, AUTOMATION_READ_DEFAULT_ROWS);
        // A caller asking for less than the default gets less.
        assert_eq!(page_of(Some(7), None).limit, 7);
        // Zero is not a window; the floor is one row.
        assert_eq!(page_of(Some(0), None).limit, 1);
    }

    #[test]
    fn the_scan_is_one_row_past_the_window_and_never_overflows() {
        assert_eq!(page_of(Some(10), Some(5)).scan(), 16);
        // An absurd offset saturates rather than wrapping into a small
        // scan, which would silently answer a full page of nothing.
        assert_eq!(page_of(Some(10), Some(usize::MAX)).scan(), usize::MAX);
    }

    #[test]
    fn an_offset_past_a_clamped_sources_reach_is_refused_and_not_answered_empty() {
        // The failure this replaces: the source clamps at `depth`, the
        // window starts past what it returned, and the answer is an
        // empty page with `has_more: false` while the table still holds
        // rows. A reader takes that for "there was nothing".
        let depth = crate::waf::WAF_EVENTS_MAX_ROWS;
        let refused = PageQuery {
            limit: Some(50),
            offset: Some(depth),
        }
        .page_within(depth)
        .expect_err("an offset at the clamp cannot be honoured");
        assert!(matches!(refused, ApiError::BadRequest(_)), "{refused:?}");
        // The message names the depth the caller can reach, or it sends
        // them guessing.
        let ApiError::BadRequest(message) = refused else {
            unreachable!("asserted above")
        };
        assert!(message.contains(&depth.to_string()), "{message}");
        assert!(message.contains("offset=449"), "{message}");

        // The deepest window the clamp can fill is allowed, and it is
        // exactly the one whose scan lands on the clamp.
        let deepest = PageQuery {
            limit: Some(50),
            offset: Some(449),
        }
        .page_within(depth)
        .expect("the deepest window is reachable");
        assert_eq!(deepest.scan(), depth);

        // An unclamped source takes any offset: an empty window there
        // is the truth, because the listing really held nothing.
        assert_eq!(page_of(Some(50), Some(10_000)).offset, 10_000);
    }

    #[test]
    fn has_more_is_true_exactly_when_a_row_was_left_behind() {
        // The source was asked for `scan()` rows: eleven back for a
        // window of ten means an eleventh exists.
        let answered = page_of(Some(10), None).answer(numbered(11));
        assert_eq!(answered.0["data"]["page"]["has_more"], true);
        assert_eq!(answered.0["data"]["page"]["returned"], 10);
        assert_eq!(
            answered.0["data"]["items"].as_array().map(Vec::len),
            Some(10)
        );

        let answered = page_of(Some(10), None).answer(numbered(10));
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
        assert_eq!(answered.0["data"]["page"]["returned"], 10);

        let answered = page_of(Some(10), None).answer(numbered(3));
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
        assert_eq!(answered.0["data"]["page"]["returned"], 3);
    }

    #[test]
    fn the_offset_walks_the_window_forward() {
        let answered = page_of(Some(2), Some(2)).answer(numbered(6));
        assert_eq!(
            answered.0["data"]["items"],
            serde_json::json!([{ "n": 2 }, { "n": 3 }])
        );
        assert_eq!(answered.0["data"]["page"]["offset"], 2);
        assert_eq!(answered.0["data"]["page"]["has_more"], true);

        // Past the end is an empty window, not an error and not a wrap.
        let answered = page_of(Some(2), Some(99)).answer(numbered(6));
        assert_eq!(answered.0["data"]["items"], serde_json::json!([]));
        assert_eq!(answered.0["data"]["page"]["returned"], 0);
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
    }

    #[test]
    fn the_byte_ceiling_ends_the_answer_early_and_says_so() {
        // One WAF matched value is the raw regex match, with no
        // truncation anywhere on the way here, so a row ceiling alone
        // bounds nothing. Rows are dropped whole and the shortfall is
        // reported, never truncated into a mangled field.
        let heavy: Vec<Value> = (0..20)
            .map(|n| serde_json::json!({ "n": n, "payload": "x".repeat(40 * 1024) }))
            .collect();
        let answered = page_of(Some(20), None).answer(heavy);
        let returned = answered.0["data"]["page"]["returned"]
            .as_u64()
            .expect("returned is a number") as usize;
        assert!(returned > 0, "a window is never empty on a full source");
        assert!(returned < 20, "the byte ceiling ended the answer early");
        assert_eq!(answered.0["data"]["page"]["has_more"], true);
        assert_eq!(
            answered.0["data"]["items"].as_array().map(Vec::len),
            Some(returned)
        );

        // A single row over the whole budget still crosses: an empty
        // answer is the one shape a reader takes for "there was
        // nothing".
        let one_huge = vec![serde_json::json!({
            "payload": "x".repeat(AUTOMATION_READ_MAX_ANSWER_BYTES + 1)
        })];
        let answered = page_of(Some(10), None).answer(one_huge);
        assert_eq!(answered.0["data"]["page"]["returned"], 1);
    }

    #[test]
    fn a_free_text_filter_is_bounded_and_the_refusal_reflects_nothing_back() {
        let too_long = "a".repeat(AUTOMATION_READ_MAX_FILTER_BYTES + 1);
        let refused = within_the_filter_ceiling("search", Some(&too_long))
            .expect_err("over the ceiling is refused");
        let ApiError::BadRequest(message) = refused else {
            panic!("the refusal is a 400")
        };
        assert!(message.contains("?search="), "{message}");
        assert!(!message.contains(&too_long), "{message}");

        within_the_filter_ceiling("search", Some("GET /health")).expect("a normal filter passes");
        within_the_filter_ceiling("search", None).expect("no filter passes");
    }

    #[test]
    fn the_rows_are_pulled_out_of_the_management_envelope_by_name() {
        let answer = json_data(serde_json::json!({ "backends": [{ "id": "b1" }] }));
        assert_eq!(
            rows(answer, Some("backends")).expect("the array is there"),
            vec![serde_json::json!({ "id": "b1" })]
        );

        let answer = json_data(serde_json::json!([{ "window": "1h" }]));
        assert_eq!(
            rows(answer, None).expect("the array is there"),
            vec![serde_json::json!({ "window": "1h" })]
        );
    }

    #[test]
    fn a_management_answer_that_changed_shape_is_a_500_and_not_an_empty_page() {
        // The failure this refuses to hide: someone renames `backends`
        // in the management view, this surface keeps answering 200 with
        // nothing in it, and an operator reads "no backends".
        let answer = json_data(serde_json::json!({ "upstreams": [{ "id": "b1" }] }));
        let refused = rows(answer, Some("backends")).expect_err("the shape changed");
        assert!(matches!(refused, ApiError::Internal(_)), "{refused:?}");
    }

    #[test]
    fn a_not_found_on_this_plane_names_no_identifier_the_caller_chose() {
        let echoed = ApiError::NotFound("route ignore-previous-instructions".to_string());
        let ApiError::NotFound(message) = without_the_callers_echo(echoed) else {
            panic!("a not-found stays a not-found")
        };
        assert!(
            !message.contains("ignore-previous-instructions"),
            "{message}"
        );

        // Every other variant travels unchanged: the echo rule is about
        // identifiers in a 404, not about rewriting the store's errors.
        let conflict = without_the_callers_echo(ApiError::Conflict("not a control plane".into()));
        assert!(matches!(conflict, ApiError::Conflict(_)), "{conflict:?}");
    }
}
