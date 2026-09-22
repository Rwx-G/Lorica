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
//! and stats, SLA, cluster and node status, backends, routes and
//! certificate metadata, each behind its own scope.
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
//! module computes a figure, filters a row set or serialises a record.
//! Two surfaces that compute the same answer independently drift, and
//! the drift shows up as a field one of them stopped stripping, which
//! is a leak nobody's test notices. The rows cross unchanged; what this
//! module adds is the window around them.
//!
//! # The window is the server's, not the caller's
//!
//! Every collection answers `{"items": [...], "page": {...}}`, and the
//! page is bounded by [`AUTOMATION_READ_MAX_ROWS`] whatever `?limit=`
//! says. The caller of this surface is a language model asking on an
//! operator's behalf, and a model that asks for everything must not be
//! able to pull the access log into a context window. A ceiling the
//! caller can raise is not a ceiling.
//!
//! # No secret crosses this boundary
//!
//! Because the views are the management plane's own, the filtering is
//! too: certificate key material never leaves [`crate::certificates`]'s
//! list view, and a route's Basic-auth hash never leaves
//! [`crate::routes`]'s. That is an inherited property and not a
//! promise, so `lorica-api/src/tests.rs` walks every response this
//! module can produce for the field names that must never appear
//! (Story 11.1 AC #5).

use axum::extract::{Extension, Path, Query};
use axum::Json;
use lorica_config::models::Role;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// The most rows any automation read returns in one answer, whatever
/// the caller asks for.
///
/// Server-side and not negotiable: see the module comment.
pub const AUTOMATION_READ_MAX_ROWS: usize = 200;

/// The window size when the caller names none.
pub const AUTOMATION_READ_DEFAULT_ROWS: usize = 50;

/// The RBAC role an automation credential stands in for when a
/// management view gates a field on one.
///
/// The fleet roster hides each node's host telemetry (CPU, memory,
/// disk) below `Operator`. An automation credential carries scopes and
/// no role, and the scope vocabulary has no way to say "this one is an
/// operator", so reading a higher role into `cluster:read` would hand
/// every such token a view an operator deliberately kept for operators.
/// The floor is the only answer that cannot be wrong.
const AUTOMATION_VIEW_ROLE: Role = Role::Viewer;

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
/// things is worse than no field. `has_more` is exact everywhere,
/// because every source is asked for one row past the window.
#[derive(Debug, Serialize)]
struct PageInfo {
    limit: usize,
    offset: usize,
    returned: usize,
    has_more: bool,
}

impl PageQuery {
    /// This query's window, clamped.
    fn page(&self) -> Page {
        Page {
            limit: self
                .limit
                .unwrap_or(AUTOMATION_READ_DEFAULT_ROWS)
                .clamp(1, AUTOMATION_READ_MAX_ROWS),
            offset: self.offset.unwrap_or(0),
        }
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
    fn of(self, rows: Vec<Value>) -> Json<Value> {
        let has_more = rows.len() > self.offset.saturating_add(self.limit);
        let items: Vec<Value> = rows
            .into_iter()
            .skip(self.offset)
            .take(self.limit)
            .collect();
        let page = PageInfo {
            limit: self.limit,
            offset: self.offset,
            returned: items.len(),
            has_more,
        };
        json_data(serde_json::json!({ "items": items, "page": page }))
    }
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

/// `GET /automation/v1/logs` (scope `logs:read`).
///
/// The access log with the filters the dashboard already offers, taken
/// verbatim as [`crate::logs::LogsQuery`] so neither the filter names
/// nor their meaning is restated here. `limit` is this surface's, not
/// the query's: whatever the caller asks for, the store is read one row
/// past the window and no further.
///
/// `after_id` is the stable cursor for a log that is still growing;
/// `offset` walks within the answer the filters produced.
///
/// # Errors
///
/// Whatever [`crate::logs::get_logs`] answers.
pub async fn list_logs(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::logs::LogsQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let filters = crate::logs::LogsQuery {
        limit: Some(page.scan()),
        ..filters
    };
    let answer = crate::logs::get_logs(Extension(state), Query(filters)).await?;
    Ok(page.of(rows(answer, Some("entries"))?))
}

/// `GET /automation/v1/waf/events` (scope `waf:read`).
///
/// Recent WAF events, `?category=` narrowing them the way the dashboard
/// does. A matched payload is attacker-controlled text and travels as
/// the field the WAF recorded it in, unchanged and uninterpreted.
///
/// # Errors
///
/// Whatever [`crate::waf::get_waf_events`] answers.
pub async fn list_waf_events(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::waf::WafEventsQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let filters = crate::waf::WafEventsQuery {
        limit: Some(page.scan()),
        ..filters
    };
    let answer = crate::waf::get_waf_events(Extension(state), Query(filters)).await?;
    Ok(page.of(rows(answer, Some("events"))?))
}

/// `GET /automation/v1/waf/stats` (scope `waf:read`).
///
/// One summary object, answered unchanged. Not paginated and not a
/// collection: its only array is the count per rule category, a fixed
/// vocabulary of rule families rather than a row set that grows with
/// traffic.
///
/// # Errors
///
/// Whatever [`crate::waf::get_waf_stats`] answers.
pub async fn waf_stats(Extension(state): Extension<AppState>) -> Result<Json<Value>, ApiError> {
    crate::waf::get_waf_stats(Extension(state)).await
}

/// `GET /automation/v1/sla/overview` (scope `sla:read`).
///
/// The 1h and 24h passive summaries for every route this node holds,
/// two rows per route. `?node=` is deliberately absent: proxying a read
/// to a follower carries an operator floor a credential with no role
/// cannot be weighed against.
///
/// # Errors
///
/// Whatever [`crate::sla::local_sla_overview`] answers.
pub async fn sla_overview(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let summaries = crate::sla::local_sla_overview(&state).await?;
    Ok(page.of(rows(json_data(summaries), None)?))
}

/// `GET /automation/v1/sla/routes/{id}` (scope `sla:read`).
///
/// One route's passive summaries over every standard window.
///
/// # Errors
///
/// Whatever [`crate::sla::local_route_sla`] answers, including a 404
/// for a route this node does not hold.
pub async fn route_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let summaries = crate::sla::local_route_sla(&state, route_id).await?;
    Ok(page.of(rows(json_data(summaries), None)?))
}

/// `GET /automation/v1/cluster/status` (scope `cluster:read`).
///
/// This node's role, build, applied configuration generation and, on a
/// control plane, the fleet summary. One object, answered unchanged.
///
/// # Errors
///
/// Whatever [`crate::cluster::get_status`] answers.
pub async fn cluster_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<Value>, ApiError> {
    crate::cluster::get_status(Extension(state)).await
}

/// `GET /automation/v1/cluster/nodes` (scope `cluster:read`).
///
/// The fleet roster as a `Viewer` sees it: see [`AUTOMATION_VIEW_ROLE`].
///
/// # Errors
///
/// Whatever [`crate::cluster::roster`] answers, including a 409 off a
/// control plane.
pub async fn list_cluster_nodes(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let nodes = crate::cluster::roster(&state, AUTOMATION_VIEW_ROLE).await?;
    Ok(page.of(rows(json_data(nodes), None)?))
}

/// `GET /automation/v1/cluster/nodes/{id}` (scope `cluster:read`).
///
/// One node of the roster, same view as the collection.
///
/// # Errors
///
/// Whatever [`crate::cluster::one_node`] answers, including a 409 off a
/// control plane and a 404 for an unknown id.
pub async fn get_cluster_node(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let node = crate::cluster::one_node(&state, AUTOMATION_VIEW_ROLE, id).await?;
    Ok(json_data(node))
}

/// `GET /automation/v1/backends` (scope `backends:read`).
///
/// Every backend with its live EWMA score and connection count, the
/// same view the dashboard's backend table reads.
///
/// # Errors
///
/// Whatever [`crate::backends::list_backends`] answers.
pub async fn list_backends(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let answer = crate::backends::list_backends(Extension(state)).await?;
    Ok(page.of(rows(answer, Some("backends"))?))
}

/// `GET /automation/v1/routes` (scope `routes:read`).
///
/// Every route with its linked backend ids, `?group=` narrowing them as
/// on the management plane. The view carries a Basic-auth username and
/// never its hash, because it is the management plane's own view.
///
/// # Errors
///
/// Whatever [`crate::routes::list_routes`] answers.
pub async fn list_routes(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
    Query(filters): Query<crate::routes::ListRoutesQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let answer = crate::routes::list_routes(Extension(state), Query(filters)).await?;
    Ok(page.of(rows(answer, Some("routes"))?))
}

/// `GET /automation/v1/certificates` (scope `certificates:read`).
///
/// Certificate metadata: domain, SANs, fingerprint, issuer, validity
/// window and ACME settings. Never a PEM body and never key material,
/// because this is the management plane's list view, which carries
/// neither. The single-certificate path, which does return the public
/// PEM, is deliberately not mounted here.
///
/// # Errors
///
/// Whatever [`crate::certificates::list_certificates`] answers.
pub async fn list_certificates(
    Extension(state): Extension<AppState>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let page = page.page();
    let answer = crate::certificates::list_certificates(Extension(state)).await?;
    Ok(page.of(rows(answer, Some("certificates"))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered(count: usize) -> Vec<Value> {
        (0..count).map(|n| serde_json::json!({ "n": n })).collect()
    }

    fn page_of(limit: Option<usize>, offset: Option<usize>) -> Page {
        PageQuery { limit, offset }.page()
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
    fn has_more_is_true_exactly_when_a_row_was_left_behind() {
        // The source was asked for `scan()` rows: eleven back for a
        // window of ten means an eleventh exists.
        let answered = page_of(Some(10), None).of(numbered(11));
        assert_eq!(answered.0["data"]["page"]["has_more"], true);
        assert_eq!(answered.0["data"]["page"]["returned"], 10);
        assert_eq!(
            answered.0["data"]["items"].as_array().map(Vec::len),
            Some(10)
        );

        let answered = page_of(Some(10), None).of(numbered(10));
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
        assert_eq!(answered.0["data"]["page"]["returned"], 10);

        let answered = page_of(Some(10), None).of(numbered(3));
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
        assert_eq!(answered.0["data"]["page"]["returned"], 3);
    }

    #[test]
    fn the_offset_walks_the_window_forward() {
        let answered = page_of(Some(2), Some(2)).of(numbered(6));
        assert_eq!(
            answered.0["data"]["items"],
            serde_json::json!([{ "n": 2 }, { "n": 3 }])
        );
        assert_eq!(answered.0["data"]["page"]["offset"], 2);
        assert_eq!(answered.0["data"]["page"]["has_more"], true);

        // Past the end is an empty window, not an error and not a wrap.
        let answered = page_of(Some(2), Some(99)).of(numbered(6));
        assert_eq!(answered.0["data"]["items"], serde_json::json!([]));
        assert_eq!(answered.0["data"]["page"]["returned"], 0);
        assert_eq!(answered.0["data"]["page"]["has_more"], false);
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
}
