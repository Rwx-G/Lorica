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

//! Route protection records on the management plane (backlog #93): the
//! operator's listing and clear, and the clearing an operator's route
//! write does.
//!
//! The automation plane writes a record when a token deletes a route
//! carrying a protection in force, and holds its later writes to it
//! (`crate::automation::records`). An operator is held to none of it,
//! as everywhere else on the dashboard, and a record says what a token
//! may not do in the operator's absence, so the operator ends it: by
//! clearing it here, or by writing a route that serves one of its
//! names, which is the operator deciding that name's protections.
//!
//! # Paths and roles
//!
//! `GET /api/v1/automation/route-protection-records` and
//! `DELETE /api/v1/automation/route-protection-records/{id}`, both at
//! the Operator floor (`middleware::authorize::required_role`): an
//! operator who may delete a route and create it bare may decide that a
//! token may too, and a listing that names which token deleted what is
//! the audit log's floor. A follower holds no record (the table never
//! replicates and no automation listener runs there), and its read-only
//! gate refuses the clear like any other configuration write.

use axum::extract::{Extension, Path};
use axum::Json;
use lorica_config::models::{Route, RouteProtectionRecord};
use lorica_config::ConfigStore;
use serde::Serialize;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;
use crate::target::{RouteGuard, RouteTarget, SettledRow};

/// `target_type` of every record audit row.
pub const RECORD_TARGET_TYPE: &str = "route_protection_record";

/// A token deleted a protected route and the record was written.
pub const RECORD_CREATE_ACTION: &str = "route_protection_record.create";

/// A newer record of the same names and path, at least as strong on
/// every control, replaced this one.
pub const RECORD_SUPERSEDE_ACTION: &str = "route_protection_record.supersede";

/// An operator cleared the record explicitly.
pub const RECORD_CLEAR_ACTION: &str = "route_protection_record.clear";

/// An operator's route write served one of the record's names.
pub const RECORD_CLEAR_BY_ROUTE_WRITE_ACTION: &str = "route_protection_record.clear_by_route_write";

/// One control a record holds, as the rule names it: the fields and the
/// safe direction, never a value.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RecordedControl {
    /// The fields the rule weighs, as the request bodies spell them.
    pub fields: Vec<&'static str>,
    /// The safe direction a token's route is held to.
    pub rule: &'static str,
}

/// A record as the management API and the audit trail render it: what
/// it serves, who deleted the route and when, and which controls it
/// holds. Never the snapshot, which carries the recorded values and the
/// Basic-auth password hash.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RouteProtectionRecordView {
    /// The record's id.
    pub id: String,
    /// The id the deleted route had.
    pub route_id: String,
    /// The deleted route's hostname.
    pub hostname: String,
    /// The deleted route's aliases.
    pub hostname_aliases: Vec<String>,
    /// The deleted route's path prefix.
    pub path_prefix: String,
    /// The actor who deleted the route, as its audit row names it.
    pub deleted_by: String,
    /// When the route was deleted, RFC 3339.
    pub deleted_at: String,
    /// The controls in force on the deleted route, in the order a
    /// refusal weighs them. Empty when the snapshot does not read.
    pub controls: Vec<RecordedControl>,
    /// Whether the snapshot reads. An unreadable record refuses every
    /// token route create and update, and every environment write, until
    /// it is cleared.
    pub readable: bool,
}

/// The view of `record`.
pub fn view(record: &RouteProtectionRecord) -> RouteProtectionRecordView {
    let controls = record
        .route()
        .ok()
        .and_then(|route| crate::automation::protections::controls_in_force(&route).ok());
    RouteProtectionRecordView {
        id: record.id.clone(),
        route_id: record.route_id.clone(),
        hostname: record.hostname.clone(),
        hostname_aliases: record.hostname_aliases.clone(),
        path_prefix: record.path_prefix.clone(),
        deleted_by: record.deleted_by.clone(),
        deleted_at: record.deleted_at.to_rfc3339(),
        readable: controls.is_some(),
        controls: controls
            .unwrap_or_default()
            .into_iter()
            .map(|protection| RecordedControl {
                fields: protection.fields.to_vec(),
                rule: protection.rule,
            })
            .collect(),
    }
}

/// [`view`] as the JSON an audit row carries.
pub fn record_view(record: &RouteProtectionRecord) -> serde_json::Value {
    serde_json::to_value(view(record)).unwrap_or_default()
}

/// The guard the management route writes pass: every row reachable, as
/// the session's role was checked at the door, and the records of every
/// name the written route serves cleared with the write.
pub fn management_guard() -> RouteGuard {
    RouteGuard::unbounded().settling(clear_records_served_by_operator_write)
}

/// Whether `route` answers to one of the names `record` holds.
fn serves_a_recorded_name(route: &Route, record: &RouteProtectionRecord) -> bool {
    std::iter::once(route.hostname.as_str())
        .chain(route.hostname_aliases.iter().map(String::as_str))
        .any(|name| record.names().any(|held| held.eq_ignore_ascii_case(name)))
}

/// The management guard's settle: an operator's route create or update
/// clears every record holding a name the route answers to, in the
/// transaction that writes the route. A delete clears nothing and
/// records nothing.
///
/// The match is by name as spelled, a wildcard by its pattern: an
/// operator's route on `a.example.com` says nothing of what a token may
/// do to `b.example.com` under a recorded `*.example.com`.
fn clear_records_served_by_operator_write(
    store: &ConfigStore,
    _actor: &str,
    target: RouteTarget<'_>,
) -> Result<Vec<SettledRow>, ApiError> {
    let Some(written) = target.after else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for record in store.list_route_protection_records()? {
        if !serves_a_recorded_name(written, &record) {
            continue;
        }
        store.delete_route_protection_record(&record.id)?;
        rows.push(SettledRow {
            action: RECORD_CLEAR_BY_ROUTE_WRITE_ACTION,
            target_type: RECORD_TARGET_TYPE,
            target_id: record.id.clone(),
            before: Some(record_view(&record)),
            after: Some(serde_json::json!({ "route_id": written.id })),
        });
    }
    Ok(rows)
}

/// `GET /api/v1/automation/route-protection-records` (Operator).
///
/// Every record, the most recent deletion first, as
/// [`RouteProtectionRecordView`]s under `records`.
///
/// # Errors
///
/// A store failure.
pub async fn list_route_protection_records(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let records = db_blocking(&state.store, |store| {
        Ok::<_, ApiError>(store.list_route_protection_records()?)
    })
    .await?;
    let views: Vec<RouteProtectionRecordView> = records.iter().map(view).collect();
    Ok(json_data(serde_json::json!({ "records": views })))
}

/// `DELETE /api/v1/automation/route-protection-records/{id}` (Operator).
///
/// Clears one record: a token's route may then serve its names weaker
/// than the deleted route did. Answers the record as it was, and writes
/// a `route_protection_record.clear` audit row carrying it.
///
/// # Errors
///
/// `NotFound` when no record has that id, or a store failure.
pub async fn clear_route_protection_record(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    let cleared = db_blocking(&state.store, move |store| {
        let record = store
            .get_route_protection_record(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("route protection record {id}")))?;
        store.delete_route_protection_record(&id)?;
        Ok::<_, ApiError>(record)
    })
    .await?;
    let before = record_view(&cleared);
    crate::audit::record(
        &state,
        &actor,
        RECORD_CLEAR_ACTION,
        (RECORD_TARGET_TYPE, &cleared.id),
        Some(&before),
        None,
    )
    .await;
    Ok(json_data(before))
}
