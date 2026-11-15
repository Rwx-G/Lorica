//! CRUD endpoints for upstream backends, including graceful drain on delete.
//!
//! A backend the automation API owns (Story 10.4 AC #8) is refused
//! both `PUT` and `DELETE` here: an environment's backend set belongs
//! to the pipeline, and removing one member by hand is an edit of that
//! set as much as changing its address is. The route side differs (a
//! managed route may be deleted, taking the environment with it);
//! see `routes::crud::delete_route`.
//!
//! The active check is typed since 1.11.0 (Story 12.1, D-2):
//! `health_check` names its kind. The deprecated `health_check_path` is
//! still accepted on input and still answered, kept equal to the typed
//! check's path; a request sending both must send them agreeing
//! ([`requested_health_check`]).
//!
//! A custom check's payload (`health_check.send` of a `tcp_send_expect`
//! check, Story 12.7 D-8) is shown to Operator and SuperAdmin and
//! withheld from a Viewer session, as the automation plane withholds
//! it from every token: a payload is where a credential would go, and
//! the Viewer role's contract is that secrets are scrubbed. The two
//! reads that answer a backend to a Viewer, [`list_backends`] and
//! [`get_backend`], mask it; the writes are Operator and above, and put
//! the stored payload back for a mask sent back unchanged
//! (`crate::automation::redact::restore_health_check_payload`), so the
//! mask is never stored.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_config::models::{HealthCheck, Role};
use serde::{Deserialize, Serialize};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::routes::crud::{managed_row_conflict, refuse_client_managed_by};
use crate::server::AppState;

/// JSON view of a backend enriched with live EWMA score and active connection count.
#[derive(Serialize)]
pub struct BackendResponse {
    /// Backend row id.
    pub id: String,
    /// `host:port` target, or a host without a port for a backend of
    /// port-range streams only.
    pub address: String,
    /// Human-readable label.
    pub name: String,
    /// Free-form classification (prod / staging / ...).
    pub group_name: String,
    /// Load-balancing weight.
    pub weight: i32,
    /// Last observed health status (lowercase name).
    pub health_status: String,
    /// Lifecycle state (normal / closing / closed).
    pub lifecycle_state: String,
    /// Live count of active connections to this backend.
    pub active_connections: i32,
    /// Whether the health-check loop probes this backend.
    pub health_check_enabled: bool,
    /// Health-check interval (s).
    pub health_check_interval_s: i32,
    /// What one probe is, by `kind`.
    pub health_check: HealthCheck,
    /// Deprecated since 1.11.0: `health_check`'s path when it is an
    /// `http` check, `None` otherwise. Answered for clients written
    /// before the typed check.
    pub health_check_path: Option<String>,
    /// Whether the upstream expects TLS. HTTP routes only; streams
    /// ignore it.
    pub tls_upstream: bool,
    /// Whether the TLS cert chain is validated ; `true` accepts
    /// self-signed / invalid certs. HTTP routes only; streams ignore it.
    pub tls_skip_verify: bool,
    /// SNI override ; `None` reuses the route hostname. HTTP routes
    /// only; streams ignore it.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg. HTTP routes only; streams
    /// ignore it.
    pub h2_upstream: bool,
    /// Live EWMA latency score for the Peak-EWMA LB policy (μs).
    pub ewma_score_us: f64,
    /// Who manages this backend when it is not the operator (Story 10.4
    /// AC #8). Absent on an operator-managed row. A `Some` is badged by
    /// the dashboard and refused in-place edits and deletes by this API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<lorica_config::models::ManagedBy>,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
}

/// JSON body for `POST /api/v1/backends`. Optional fields fall back to defaults.
#[derive(Deserialize)]
pub struct CreateBackendRequest {
    /// `host:port` upstream address, or a host without a port (a
    /// bracketed IPv6 literal for IPv6) for a backend that serves
    /// port-range streams only, with its health check disabled.
    /// Required.
    pub address: String,
    /// Human-readable label.
    pub name: Option<String>,
    /// Free-form classification label.
    pub group_name: Option<String>,
    /// LB weight.
    pub weight: Option<i32>,
    /// Enable the health-check loop.
    pub health_check_enabled: Option<bool>,
    /// Health-check interval (s); the stored
    /// `default_health_check_interval_s` when absent.
    pub health_check_interval_s: Option<i32>,
    /// What one probe is; `tcp_connect` when neither this nor
    /// `health_check_path` is sent.
    pub health_check: Option<HealthCheck>,
    /// Deprecated since 1.11.0 in favour of `health_check`: a path
    /// reads as an `http` check of that path, the empty string as
    /// `tcp_connect`. Sent beside `health_check`, it must agree with it.
    pub health_check_path: Option<String>,
    /// Whether the upstream expects TLS. HTTP routes only.
    pub tls_upstream: Option<bool>,
    /// Skip upstream cert validation. HTTP routes only.
    pub tls_skip_verify: Option<bool>,
    /// SNI override for the upstream handshake. HTTP routes only.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg. HTTP routes only.
    pub h2_upstream: Option<bool>,
    /// Refused with 422 when present: the mark is server-owned (see
    /// [`refuse_client_managed_by`]).
    #[serde(default)]
    pub managed_by: Option<serde_json::Value>,
}

/// JSON body for `PUT /api/v1/backends/:id`. Only the supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateBackendRequest {
    /// New upstream address, `host:port` or portless as on create.
    pub address: Option<String>,
    /// New human-readable label.
    pub name: Option<String>,
    /// New free-form classification label.
    pub group_name: Option<String>,
    /// New LB weight.
    pub weight: Option<i32>,
    /// Toggle the health-check loop.
    pub health_check_enabled: Option<bool>,
    /// New health-check interval (s).
    pub health_check_interval_s: Option<i32>,
    /// New active check, replacing the stored one whole.
    pub health_check: Option<HealthCheck>,
    /// Deprecated since 1.11.0 in favour of `health_check`, read as on
    /// create: a path sets an `http` check, the empty string
    /// `tcp_connect`. Sent alone, the empty string speaks of the HTTP
    /// path only: on a backend whose check has no path (a TCP connect,
    /// a template, a custom send/expect check) it changes nothing.
    pub health_check_path: Option<String>,
    /// Upstream TLS toggle. HTTP routes only.
    pub tls_upstream: Option<bool>,
    /// Skip upstream cert validation. HTTP routes only.
    pub tls_skip_verify: Option<bool>,
    /// SNI override. HTTP routes only.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg. HTTP routes only.
    pub h2_upstream: Option<bool>,
    /// Refused with 422 when present: the mark is server-owned (see
    /// [`refuse_client_managed_by`]).
    #[serde(default)]
    pub managed_by: Option<serde_json::Value>,
}

fn backend_to_response(
    b: &lorica_config::models::Backend,
    ewma_score: f64,
    active_connections: i32,
) -> BackendResponse {
    BackendResponse {
        id: b.id.clone(),
        address: b.address.clone(),
        name: b.name.clone(),
        group_name: b.group_name.clone(),
        weight: b.weight,
        health_status: b.health_status.as_str().to_string(),
        lifecycle_state: b.lifecycle_state.as_str().to_string(),
        active_connections,
        health_check_enabled: b.health_check_enabled,
        health_check_interval_s: b.health_check_interval_s,
        health_check: b.health_check.clone(),
        health_check_path: b.health_check.legacy_path().map(str::to_string),
        tls_upstream: b.tls_upstream,
        tls_skip_verify: b.tls_skip_verify,
        tls_sni: b.tls_sni.clone(),
        h2_upstream: b.h2_upstream,
        ewma_score_us: ewma_score,
        managed_by: b.managed_by.clone(),
        created_at: b.created_at.to_rfc3339(),
        updated_at: b.updated_at.to_rfc3339(),
    }
}

/// `response` as a session of `role` may read it: below Operator, a
/// custom check's payload withheld
/// (`crate::automation::redact::health_check_payload_withheld`, the
/// mask the automation plane answers with).
fn as_read_by(mut response: BackendResponse, role: Role) -> BackendResponse {
    if role < Role::Operator {
        response.health_check =
            crate::automation::redact::health_check_payload_withheld(&response.health_check);
    }
    response
}

/// The active check a create or an update asks for, from the typed
/// `health_check` and the deprecated `health_check_path`, or `None`
/// when the request names neither.
///
/// The path reads as it always has: a path is an `http` check of it,
/// the empty string a TCP connect. Sent together, the two must agree,
/// the path being the typed check's ([`HealthCheck::legacy_path`]):
/// a client copying a backend it read sends both, and when they differ
/// nothing says which one it meant.
///
/// # Errors
///
/// `BadRequest` naming both fields when they disagree;
/// `Unprocessable` for an `http` check with an empty path.
fn requested_health_check(
    typed: Option<HealthCheck>,
    legacy_path: Option<&str>,
) -> Result<Option<HealthCheck>, ApiError> {
    if let Some(HealthCheck::Http { path }) = &typed {
        if path.is_empty() {
            return Err(ApiError::Unprocessable(
                "health_check.path: an `http` check needs a path; a check without one is \
                 `{\"kind\": \"tcp_connect\"}`"
                    .into(),
            ));
        }
    }
    // Compared through the projection, not as checks, so a kind with no
    // path (every kind but `http`) agrees with an empty legacy path.
    let legacy: Option<Option<&str>> = legacy_path.map(|path| Some(path).filter(|p| !p.is_empty()));
    match (typed, legacy) {
        (Some(typed), Some(legacy)) if typed.legacy_path() != legacy => Err(ApiError::BadRequest(
            "health_check and health_check_path disagree: health_check_path is deprecated and, \
             sent beside health_check, must be its path (or empty for a check without one); \
             send health_check alone"
                .into(),
        )),
        (Some(typed), _) => Ok(Some(typed)),
        (None, legacy) => Ok(legacy.map(|path| HealthCheck::reconcile(None, path))),
    }
}

/// Look up active connections for a backend address from shared state.
async fn get_backend_connections_async(state: &crate::server::AppState, addr: &str) -> i32 {
    // Direct counters (single-process mode)
    if let Some(bc) = state.backend_connections() {
        return bc.get(addr) as i32;
    }
    // Aggregated from workers (supervisor mode)
    if let Some(agg) = state.aggregated_metrics() {
        if let Some(count) = agg.merged_backend_connections().await.get(addr).copied() {
            return count as i32;
        }
    }
    0
}

/// Look up the EWMA score for a backend address from shared state.
/// In single-process mode, reads from the direct ewma_scores map.
/// In supervisor mode, reads from aggregated worker metrics.
async fn get_ewma_score_async(state: &crate::server::AppState, addr: &str) -> f64 {
    // Direct scores (single-process mode)
    if let Some(score) = state
        .ewma_scores()
        .and_then(|scores| scores.get(addr).map(|s| *s))
    {
        return score;
    }
    // Aggregated from workers (supervisor mode)
    if let Some(agg) = state.aggregated_metrics() {
        if let Some(score) = agg.merged_ewma_scores().await.get(addr).copied() {
            return score;
        }
    }
    0.0
}

/// Every worker's EWMA scores and connection counts, merged once.
///
/// The per-backend lookups above each rebuild one of these maps from
/// every worker's own map, so a listing of `B` backends used to run the
/// merge `2B` times over the same data, behind `2B` sequential
/// acquisitions of the worker-metrics lock. Built once and read `B`
/// times instead. Empty in single-process mode, where the direct
/// counters answer and no merge is needed.
struct MergedWorkerMetrics {
    ewma: std::collections::HashMap<String, f64>,
    connections: std::collections::HashMap<String, u64>,
}

impl MergedWorkerMetrics {
    async fn collect(state: &AppState) -> Self {
        match state.aggregated_metrics() {
            Some(agg) => Self {
                ewma: agg.merged_ewma_scores().await,
                connections: agg.merged_backend_connections().await,
            },
            None => Self {
                ewma: std::collections::HashMap::new(),
                connections: std::collections::HashMap::new(),
            },
        }
    }
}

/// GET /api/v1/backends - list every backend with its live EWMA score and active connection count.
///
/// A Viewer session reads a custom check's payload masked (see the
/// module doc).
pub async fn list_backends(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    list_backends_as(&state, session.role).await
}

/// The whole of [`list_backends`] as read by `reader`: the automation
/// plane's listing reads it as a Viewer would, below Operator, and
/// masks the rows again for everything else a token is not shown.
pub(crate) async fn list_backends_as(
    state: &AppState,
    reader: Role,
) -> Result<Json<serde_json::Value>, ApiError> {
    let backends = db_blocking(&state.store, move |store| store.list_backends()).await?;
    let merged = MergedWorkerMetrics::collect(state).await;
    let responses: Vec<BackendResponse> = backends
        .iter()
        .map(|b| {
            // Same precedence as the single-backend lookups: the direct
            // counters when this process owns them, the supervisor's
            // merged view otherwise, zero when neither knows the
            // address.
            let score = state
                .ewma_scores()
                .and_then(|scores| scores.get(&b.address).map(|s| *s))
                .or_else(|| merged.ewma.get(&b.address).copied())
                .unwrap_or(0.0);
            let conns = state
                .backend_connections()
                .map(|bc| bc.get(&b.address) as i32)
                .or_else(|| merged.connections.get(&b.address).map(|c| *c as i32))
                .unwrap_or(0);
            as_read_by(backend_to_response(b, score, conns), reader)
        })
        .collect();
    Ok(json_data(serde_json::json!({ "backends": responses })))
}

/// POST /api/v1/backends - register a new upstream backend.
pub async fn create_backend(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateBackendRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    create_backend_as(
        &state,
        &audit_ctx,
        body,
        crate::preview::WriteMode::Apply,
        crate::target::BackendGuard::unbounded(),
    )
    .await
}

/// The whole of [`create_backend`] as `actor`: the validation, the
/// row, the reload signal and the `backend.create` audit row.
///
/// Split from the handler so the automation plane (Story 11.2) can run
/// exactly this with a token as the actor rather than a session; see
/// `crate::routes::crud::create_route_as` for the rule, and for what
/// [`crate::preview::WriteMode::Preview`] answers instead of the row.
/// `guard` sees the row about to be inserted with no row before it, in
/// the store closure that inserts it, the preview included.
pub(crate) async fn create_backend_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    body: CreateBackendRequest,
    mode: crate::preview::WriteMode,
    guard: crate::target::BackendGuard,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    refuse_client_managed_by(body.managed_by.as_ref())?;
    if body.address.is_empty() {
        return Err(ApiError::BadRequest("address is required".into()));
    }
    let health_check =
        requested_health_check(body.health_check, body.health_check_path.as_deref())?
            .unwrap_or_default();
    let requested_interval = body.health_check_interval_s;

    let now = Utc::now();
    let backend = lorica_config::models::Backend {
        id: uuid::Uuid::new_v4().to_string(),
        address: body.address,
        name: body.name.unwrap_or_default(),
        // The same rule the route path applies. Its doc has said "both
        // routes and backends" since v1.2 while this path never called
        // it, which is how a backend could carry a group name no route
        // may have, `automation:<name>` included.
        group_name: match body.group_name.as_deref() {
            Some(raw) => crate::routes::crud::validate_group_name(raw)?,
            None => String::new(),
        },
        weight: body.weight.unwrap_or(100),
        health_status: lorica_config::models::HealthStatus::Unknown,
        health_check_enabled: body.health_check_enabled.unwrap_or(true),
        // Set from the stored setting in the store closure below when
        // the body names none.
        health_check_interval_s: requested_interval.unwrap_or_default(),
        health_check_path: health_check.legacy_path().map(str::to_string),
        health_check,
        lifecycle_state: lorica_config::models::LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: body.tls_upstream.unwrap_or(false),
        tls_skip_verify: body.tls_skip_verify.unwrap_or(false),
        tls_sni: body.tls_sni.clone().filter(|s| !s.is_empty()),
        h2_upstream: body.h2_upstream.unwrap_or(false),
        // The dashboard and the operator API only ever create
        // operator-managed rows; the automation API sets the mark.
        managed_by: None,
        created_at: now,
        updated_at: now,
    };

    let backend = db_blocking(&state.store, move |store| {
        let mut backend = backend;
        if requested_interval.is_none() {
            backend.health_check_interval_s =
                store.get_global_settings()?.default_health_check_interval_s;
        }
        crate::automation::redact::restore_health_check_payload(None, &mut backend)?;
        guard.restore_withheld(None, &mut backend)?;
        guard.check(
            store,
            crate::target::BackendTarget {
                before: None,
                after: Some(&backend),
            },
        )?;
        if !mode.previews() {
            store.create_backend(&backend)?;
        }
        Ok::<_, ApiError>(backend)
    })
    .await?;
    if mode.previews() {
        return Ok((
            StatusCode::OK,
            crate::preview::previewed(
                "create",
                None,
                serde_json::to_value(backend_to_response(&backend, 0.0, 0)).ok(),
            ),
        ));
    }
    state.notify_config_changed();

    let response = backend_to_response(&backend, 0.0, 0);
    let after = serde_json::to_value(&response).ok();
    crate::audit::record(
        state,
        actor,
        "backend.create",
        ("backend", &backend.id),
        None,
        after.as_ref(),
    )
    .await;

    Ok(json_data_with_status(StatusCode::CREATED, response))
}

/// GET /api/v1/backends/:id - fetch a single backend by id.
///
/// A Viewer session reads a custom check's payload masked (see the
/// module doc).
pub async fn get_backend(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let backend = db_blocking(&state.store, move |store| {
        store
            .get_backend(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))
    })
    .await?;
    let score = get_ewma_score_async(&state, &backend.address).await;
    let conns = get_backend_connections_async(&state, &backend.address).await;
    Ok(json_data(as_read_by(
        backend_to_response(&backend, score, conns),
        session.role,
    )))
}

/// PUT /api/v1/backends/:id - patch backend fields and trigger a proxy reload.
pub async fn update_backend(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(body): Json<UpdateBackendRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    update_backend_as(
        &state,
        &audit_ctx,
        id,
        body,
        crate::preview::WriteMode::Apply,
        crate::target::BackendGuard::unbounded(),
    )
    .await
}

/// The whole of [`update_backend`] as `actor`; see
/// [`create_backend_as`] for why the split exists and what `guard` is.
/// The managed-row refusal (409) runs here, so it holds on every plane
/// that reaches this function. The guard runs under the lock on the
/// row as read, before that refusal so a caller outside the grant
/// learns nothing from it, and again on the row as it would be
/// written.
pub(crate) async fn update_backend_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
    body: UpdateBackendRequest,
    mode: crate::preview::WriteMode,
    guard: crate::target::BackendGuard,
) -> Result<Json<serde_json::Value>, ApiError> {
    refuse_client_managed_by(body.managed_by.as_ref())?;
    let legacy_only = body.health_check.is_none();
    let health_check =
        requested_health_check(body.health_check, body.health_check_path.as_deref())?;
    let role = crate::streams::LocalRole::of(state);
    let reserved = state.reserved_ports;
    let (before_backend, backend) = db_blocking(&state.store, move |store| {
        let mut backend = store
            .get_backend(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))?;
        guard.check(
            store,
            crate::target::BackendTarget {
                before: Some(&backend),
                after: None,
            },
        )?;
        if let Some(managed_by) = &backend.managed_by {
            return Err(managed_row_conflict(
                "update",
                "backend",
                managed_by,
                "Update the environment through the pipeline instead.",
            ));
        }
        let before_backend = backend.clone();

        if let Some(address) = body.address {
            backend.address = address;
        }
        if let Some(name) = body.name {
            backend.name = name;
        }
        if let Some(group_name) = body.group_name.as_deref() {
            backend.group_name = crate::routes::crud::validate_group_name(group_name)?;
        }
        if let Some(weight) = body.weight {
            backend.weight = weight;
        }
        if let Some(hc) = body.health_check_enabled {
            backend.health_check_enabled = hc;
            if !hc {
                backend.health_status = lorica_config::models::HealthStatus::Unknown;
            }
        }
        if let Some(interval) = body.health_check_interval_s {
            backend.health_check_interval_s = interval;
        }
        if let Some(check) = health_check {
            // The deprecated field speaks of the HTTP path alone: emptied
            // on a backend whose check has no path, it asks for nothing,
            // and replacing a template or a custom check with a TCP
            // connect would answer a question the client never asked.
            let clears_an_absent_path = legacy_only
                && check == HealthCheck::TcpConnect
                && backend.health_check.legacy_path().is_none();
            if !clears_an_absent_path {
                backend.set_health_check(check);
            }
        }
        if let Some(tls) = body.tls_upstream {
            backend.tls_upstream = tls;
        }
        if let Some(skip) = body.tls_skip_verify {
            backend.tls_skip_verify = skip;
        }
        if let Some(sni) = body.tls_sni {
            backend.tls_sni = if sni.is_empty() { None } else { Some(sni) };
        }
        if let Some(h2) = body.h2_upstream {
            backend.h2_upstream = h2;
        }
        backend.updated_at = Utc::now();
        crate::automation::redact::restore_health_check_payload(
            Some(&before_backend),
            &mut backend,
        )?;
        guard.restore_withheld(Some(&before_backend), &mut backend)?;
        guard.check(
            store,
            crate::target::BackendTarget {
                before: Some(&before_backend),
                after: Some(&backend),
            },
        )?;
        // A stream's local backend may not be moved onto a node's port
        // (Story 12.3 D-m, rule B); the preview answers what the write
        // would.
        crate::streams::refuse_local_backend_on_its_streams(store, &role, reserved, &backend)?;

        if mode.previews() {
            return Ok::<_, ApiError>((before_backend, backend));
        }
        store.update_backend(&backend)?;
        Ok::<_, ApiError>((before_backend, backend))
    })
    .await?;
    if mode.previews() {
        return Ok(crate::preview::previewed(
            "update",
            serde_json::to_value(backend_to_response(&before_backend, 0.0, 0)).ok(),
            serde_json::to_value(backend_to_response(&backend, 0.0, 0)).ok(),
        ));
    }
    state.notify_config_changed();
    let score = get_ewma_score_async(state, &backend.address).await;
    let conns = get_backend_connections_async(state, &backend.address).await;

    let before = serde_json::to_value(&before_backend).ok();
    let after = serde_json::to_value(&backend).ok();
    crate::audit::record(
        state,
        actor,
        "backend.update",
        ("backend", &backend.id),
        before.as_ref(),
        after.as_ref(),
    )
    .await;

    Ok(json_data(backend_to_response(&backend, score, conns)))
}

/// DELETE /api/v1/backends/:id - graceful drain delete.
///
/// Initiates graceful drain: sets lifecycle_state to Closing so no new
/// requests are routed to this backend, then spawns a background task
/// that waits for active connections to reach 0 (or a 60s timeout)
/// before deleting the backend from the database.
pub async fn delete_backend(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    delete_backend_as(
        &state,
        &audit_ctx,
        id,
        crate::preview::WriteMode::Apply,
        crate::target::BackendGuard::unbounded(),
    )
    .await
}

/// The whole of [`delete_backend`] as `actor`, the drain included; see
/// [`create_backend_as`] for why the split exists and what `guard` is.
/// The guard runs under the lock on the row as read.
///
/// In [`crate::preview::WriteMode::Preview`] it answers what the apply
/// would do to the row, and does neither: for a backend in normal
/// service, the row marked closing, since the apply drains it and the
/// row stays until the drain ends; for one already closing or closed,
/// no `after`, since the apply removes it at once.
pub(crate) async fn delete_backend_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
    mode: crate::preview::WriteMode,
    guard: crate::target::BackendGuard,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id_db = id.clone();
    let (backend, force_deleted) = db_blocking(&state.store, move |store| {
        let mut backend = store
            .get_backend(&id_db)?
            .ok_or_else(|| ApiError::NotFound(format!("backend {id_db}")))?;
        guard.check(
            store,
            crate::target::BackendTarget {
                before: Some(&backend),
                after: None,
            },
        )?;
        // Removing one backend from an environment's set is an edit of
        // that set, which only the pipeline owns. Whole-environment
        // removal goes through the route (its delete cascades) or the
        // automation API.
        if let Some(managed_by) = &backend.managed_by {
            return Err(managed_row_conflict(
                "delete",
                "backend",
                managed_by,
                "Delete the environment, or update it through the pipeline, instead.",
            ));
        }
        // A backend already closing or closed goes at once; one in
        // normal service is marked closing and drained first.
        let force_deleted =
            backend.lifecycle_state != lorica_config::models::LifecycleState::Normal;
        if mode.previews() {
            return Ok((backend, force_deleted));
        }
        if force_deleted {
            store.delete_backend(&id_db)?;
            return Ok((backend, true));
        }

        // Transition to Closing - proxy stops routing new requests to this backend
        backend.lifecycle_state = lorica_config::models::LifecycleState::Closing;
        backend.updated_at = Utc::now();
        store.update_backend(&backend)?;
        Ok::<_, ApiError>((backend, false))
    })
    .await?;
    if mode.previews() {
        let after = (!force_deleted).then(|| {
            let mut closing = backend.clone();
            closing.lifecycle_state = lorica_config::models::LifecycleState::Closing;
            serde_json::to_value(backend_to_response(&closing, 0.0, 0)).ok()
        });
        return Ok(crate::preview::previewed(
            "delete",
            serde_json::to_value(backend_to_response(&backend, 0.0, 0)).ok(),
            after.flatten(),
        ));
    }
    state.notify_config_changed();

    let before = serde_json::to_value(&backend).ok();
    crate::audit::record(
        state,
        actor,
        "backend.delete",
        ("backend", &backend.id),
        before.as_ref(),
        None,
    )
    .await;

    if force_deleted {
        return Ok(json_data(serde_json::json!({"message": "backend deleted"})));
    }

    // Spawn background drain task under the shared tracker so
    // shutdown waits (up to the supervisor drain timeout) for any
    // in-flight drain to complete rather than ripping the DB row out
    // with connections still bound to it.
    let drain_state = state.clone();
    let drain_addr = backend.address.clone();
    let drain_id = id.clone();
    state.task_tracker.spawn(async move {
        const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;

        loop {
            let conns = get_backend_connections_async(&drain_state, &drain_addr).await;
            if conns <= 0 {
                tracing::info!(backend_id = %drain_id, "backend drained, deleting");
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    backend_id = %drain_id,
                    remaining_connections = conns,
                    "drain timeout exceeded, force deleting backend"
                );
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        // Delete from DB (blocking pool ; this task is plain
        // `tokio::spawn`, so log the error instead of propagating).
        let delete_id = drain_id.clone();
        let deleted = db_blocking(&drain_state.store, move |store| {
            store.delete_backend(&delete_id)
        })
        .await;
        if let Err(e) = deleted {
            tracing::warn!(backend_id = %drain_id, error = %e, "failed to delete drained backend");
        }
        drain_state.notify_config_changed();
    });

    Ok(json_data(serde_json::json!({
        "message": "backend draining",
        "lifecycle_state": "closing",
    })))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    use crate::server::AppState;
    use crate::tests::{body_json, send, setup_admin_and_login, test_state};

    /// A logged-in operator on a fresh in-memory node, and a way to
    /// call the management API as it.
    struct Node {
        state: AppState,
        sessions: crate::middleware::auth::SessionStore,
        limiter: crate::middleware::rate_limit::RateLimiter,
        cookie: String,
    }

    impl Node {
        async fn new() -> Self {
            let (state, sessions, limiter) = test_state().await;
            let cookie = setup_admin_and_login(&state, &sessions, &limiter).await;
            Self {
                state,
                sessions,
                limiter,
                cookie,
            }
        }

        /// `(status, whole answer)`.
        async fn call(&self, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
            let response = send(
                &self.state,
                &self.sessions,
                &self.limiter,
                method,
                uri,
                &self.cookie,
                Some(body),
            )
            .await;
            let status = response.status();
            (status, body_json(response).await)
        }

        async fn create(&self, body: Value) -> (StatusCode, Value) {
            self.call("POST", "/api/v1/backends", body).await
        }

        async fn update(&self, id: &str, body: Value) -> (StatusCode, Value) {
            self.call("PUT", &format!("/api/v1/backends/{id}"), body)
                .await
        }

        async fn stored(&self, id: &str) -> lorica_config::models::Backend {
            self.state
                .store
                .lock()
                .await
                .get_backend(id)
                .expect("store read")
                .expect("the backend is stored")
        }
    }

    fn http(path: &str) -> Value {
        json!({ "kind": "http", "path": path })
    }

    /// The answer carries both shapes, agreeing, and the store holds
    /// the same pair.
    async fn assert_checked_by(node: &Node, answer: &Value, check: Value, path: Option<&str>) {
        let data = &answer["data"];
        assert_eq!(data["health_check"], check, "{answer}");
        assert_eq!(data["health_check_path"], json!(path), "{answer}");
        let stored = node.stored(data["id"].as_str().expect("an id")).await;
        assert_eq!(
            serde_json::to_value(&stored.health_check).expect("serialises"),
            check
        );
        assert_eq!(stored.health_check_path.as_deref(), path);
    }

    #[tokio::test]
    async fn a_create_takes_the_typed_check_the_deprecated_path_or_both_agreeing() {
        let node = Node::new().await;
        for (what, body, check, path) in [
            (
                "typed http only",
                json!({ "address": "192.0.2.10:8080", "health_check": http("/healthz") }),
                http("/healthz"),
                Some("/healthz"),
            ),
            (
                "typed tcp_connect only",
                json!({ "address": "192.0.2.11:8080", "health_check": { "kind": "tcp_connect" } }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
            (
                "deprecated path only",
                json!({ "address": "192.0.2.12:8080", "health_check_path": "/ready" }),
                http("/ready"),
                Some("/ready"),
            ),
            (
                "both agreeing",
                json!({
                    "address": "192.0.2.13:8080",
                    "health_check": http("/ready"),
                    "health_check_path": "/ready",
                }),
                http("/ready"),
                Some("/ready"),
            ),
            (
                "tcp_connect beside an empty path",
                json!({
                    "address": "192.0.2.14:8080",
                    "health_check": { "kind": "tcp_connect" },
                    "health_check_path": "",
                }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
            (
                "neither",
                json!({ "address": "192.0.2.15:8080" }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
        ] {
            let (status, answer) = node.create(body).await;
            assert_eq!(status, StatusCode::CREATED, "{what}: {answer}");
            assert_checked_by(&node, &answer, check, path).await;
        }
    }

    #[tokio::test]
    async fn the_two_shapes_disagreeing_are_refused_naming_both_fields() {
        let node = Node::new().await;
        for body in [
            json!({ "health_check": http("/a"), "health_check_path": "/b" }),
            json!({ "health_check": { "kind": "tcp_connect" }, "health_check_path": "/b" }),
            json!({ "health_check": http("/a"), "health_check_path": "" }),
        ] {
            let mut create = body.clone();
            create["address"] = json!("192.0.2.10:8080");
            let (status, answer) = node.create(create).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
            let message = answer["error"]["message"].as_str().expect("a message");
            assert!(
                message.contains("health_check and health_check_path"),
                "{message}"
            );
        }
        assert!(node
            .state
            .store
            .lock()
            .await
            .list_backends()
            .expect("store read")
            .is_empty());

        let (_, created) = node
            .create(json!({ "address": "192.0.2.10:8080", "health_check_path": "/kept" }))
            .await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        let (status, _) = node
            .update(
                &id,
                json!({ "health_check": http("/a"), "health_check_path": "/b" }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            node.stored(&id).await.health_check_path.as_deref(),
            Some("/kept")
        );
    }

    #[tokio::test]
    async fn an_http_check_without_a_path_is_refused() {
        let node = Node::new().await;
        let (status, answer) = node
            .create(json!({ "address": "192.0.2.10:8080", "health_check": http("") }))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert!(answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("health_check.path: an `http` check needs a path")));
    }

    #[tokio::test]
    async fn an_update_moves_from_the_legacy_path_to_the_typed_check_and_back() {
        let node = Node::new().await;
        let (_, created) = node
            .create(json!({ "address": "192.0.2.10:8080", "health_check_path": "/legacy" }))
            .await;
        assert_checked_by(&node, &created, http("/legacy"), Some("/legacy")).await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();

        for (body, check, path) in [
            (
                json!({ "health_check": { "kind": "tcp_connect" } }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
            (
                json!({ "health_check": http("/typed") }),
                http("/typed"),
                Some("/typed"),
            ),
            (
                json!({ "health_check_path": "/legacy-again" }),
                http("/legacy-again"),
                Some("/legacy-again"),
            ),
            (
                json!({ "health_check_path": "" }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
            // A patch naming neither leaves the check alone.
            (
                json!({ "weight": 50 }),
                json!({ "kind": "tcp_connect" }),
                None,
            ),
        ] {
            let (status, answer) = node.update(&id, body.clone()).await;
            assert_eq!(status, StatusCode::OK, "{body}: {answer}");
            assert_checked_by(&node, &answer, check, path).await;
        }
    }

    #[tokio::test]
    async fn enabling_checks_on_a_backend_of_a_udp_stream_is_refused_naming_the_stream() {
        let node = Node::new().await;
        let (_, created) = node
            .create(json!({ "address": "192.0.2.10:5353", "health_check_enabled": false }))
            .await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        {
            let store = node.state.store.lock().await;
            let now = chrono::Utc::now();
            let stream = lorica_config::models::Stream::new(
                uuid::Uuid::new_v4().to_string(),
                "dns-udp".to_string(),
                lorica_config::models::StreamProtocol::Udp,
                "0.0.0.0".parse().expect("an address"),
                5353,
                5353,
                now,
            );
            store.create_stream(&stream).expect("the stream is stored");
            store
                .set_stream_backends(&stream.id, std::slice::from_ref(&id))
                .expect("a backend with checks off may serve a UDP stream");
        }

        for body in [
            json!({ "health_check_enabled": true }),
            json!({ "health_check_enabled": true, "health_check": { "kind": "tcp_connect" } }),
        ] {
            let (status, answer) = node.update(&id, body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
            let message = answer["error"]["message"].as_str().expect("a message");
            assert!(message.contains("`dns-udp`"), "{message}");
        }
        assert!(!node.stored(&id).await.health_check_enabled);
    }

    /// A custom send/expect check sending `send`, as a body spells it.
    fn custom(send: &str) -> Value {
        json!({
            "kind": "tcp_send_expect",
            "send": { "text": send },
            "expect": [{ "match": "prefix", "bytes": { "hex": "2b504f4e47" } }],
            "timeout_ms": 2000,
        })
    }

    fn template(name: &str) -> Value {
        json!({ "kind": "tcp_template", "template": name, "timeout_ms": 2000 })
    }

    impl Node {
        /// A session of `role` on this node, as its cookie.
        async fn session_of(&self, username: &str, role: lorica_config::models::Role) -> String {
            crate::tests::create_user_and_login(
                &self.state,
                &self.sessions,
                &self.limiter,
                username,
                role,
            )
            .await
        }

        /// `GET uri` as the session `cookie`, its whole answer.
        async fn read_as(&self, cookie: &str, uri: &str) -> Value {
            let response = send(
                &self.state,
                &self.sessions,
                &self.limiter,
                "GET",
                uri,
                cookie,
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            body_json(response).await
        }

        /// `(status, whole answer)` of a write as the session `cookie`.
        async fn write_as(
            &self,
            cookie: &str,
            method: &str,
            uri: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            let response = send(
                &self.state,
                &self.sessions,
                &self.limiter,
                method,
                uri,
                cookie,
                Some(body),
            )
            .await;
            let status = response.status();
            (status, body_json(response).await)
        }
    }

    #[tokio::test]
    async fn an_operator_creates_every_kind_and_each_check_limit_is_a_422_naming_its_field() {
        // The store's validation (Story 12.7 D-6) is a refusal on the
        // merits, the 422 every store rule answers (`ApiError` from
        // `ConfigError::Validation`).
        let node = Node::new().await;
        let operator = node
            .session_of("operator01", lorica_config::models::Role::Operator)
            .await;
        for (index, check) in [
            http("/healthz"),
            json!({ "kind": "tcp_connect" }),
            template("redis_ping"),
            custom("PING\r\n"),
            json!({ "kind": "tcp_send_expect",
                    "expect": [{ "match": "contains", "bytes": { "text": "220" } }] }),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, answer) = node
                .write_as(
                    &operator,
                    "POST",
                    "/api/v1/backends",
                    json!({ "address": format!("192.0.2.{}:6379", 20 + index), "health_check": check }),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{check}: {answer}");
            let stored = node
                .stored(answer["data"]["id"].as_str().expect("an id"))
                .await;
            let mut expected = check.clone();
            if expected["kind"] == "tcp_send_expect" && expected.get("timeout_ms").is_none() {
                expected["timeout_ms"] = json!(lorica_config::models::PROBE_TIMEOUT_MS_DEFAULT);
            }
            assert_eq!(
                serde_json::to_value(&stored.health_check).expect("serialises"),
                expected
            );
        }

        let over_send = "a".repeat(lorica_config::models::SEND_MAX_BYTES + 1);
        let alternatives: Vec<Value> = (0..=lorica_config::models::EXPECT_MAX_ALTERNATIVES)
            .map(|_| json!({ "match": "prefix", "bytes": { "text": "+" } }))
            .collect();
        let over_answer = "a".repeat(lorica_config::models::EXPECT_MAX_BYTES + 1);
        for (field, check, tls_upstream) in [
            ("health_check.send", custom(&over_send), false),
            ("health_check.send", custom(""), false),
            (
                "health_check.expect",
                json!({ "kind": "tcp_send_expect", "expect": alternatives }),
                false,
            ),
            (
                "health_check.expect",
                json!({ "kind": "tcp_send_expect", "expect": [] }),
                false,
            ),
            (
                "health_check.expect[0].bytes",
                json!({ "kind": "tcp_send_expect",
                        "expect": [{ "match": "prefix", "bytes": { "text": over_answer } }] }),
                false,
            ),
            (
                "health_check.expect[0].bytes",
                json!({ "kind": "tcp_send_expect",
                        "expect": [{ "match": "prefix", "bytes": { "hex": "abc" } }] }),
                false,
            ),
            (
                "health_check.timeout_ms",
                json!({ "kind": "tcp_template", "template": "smtp_banner",
                        "timeout_ms": lorica_config::models::PROBE_TIMEOUT_MS_MAX + 1 }),
                false,
            ),
            ("tls_upstream", template("redis_ping"), true),
        ] {
            let (status, answer) = node
                .write_as(
                    &operator,
                    "POST",
                    "/api/v1/backends",
                    json!({
                        "address": "192.0.2.40:6379",
                        "health_check": check,
                        "tls_upstream": tls_upstream,
                    }),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{field}: {answer}"
            );
            let message = answer["error"]["message"].as_str().expect("a message");
            assert!(message.contains(field), "{field}: {message}");
            assert!(!message.contains("aaaa"), "{field}: the payload is echoed");
        }
        assert!(node
            .state
            .store
            .lock()
            .await
            .list_backends()
            .expect("store read")
            .iter()
            .all(|backend| backend.address != "192.0.2.40:6379"));
    }

    #[tokio::test]
    async fn a_viewer_reads_a_custom_payload_masked_and_an_operator_reads_it_whole() {
        let node = Node::new().await;
        let (status, created) = node
            .create(
                json!({ "address": "192.0.2.10:6379", "health_check": custom("AUTH s3cr3t\r\n") }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        let (_, templated) = node
            .create(json!({ "address": "192.0.2.11:6379", "health_check": template("redis_ping") }))
            .await;
        let template_id = templated["data"]["id"].as_str().expect("an id").to_string();

        let viewer = node
            .session_of("viewer01", lorica_config::models::Role::Viewer)
            .await;
        let operator = node
            .session_of("operator01", lorica_config::models::Role::Operator)
            .await;
        let whole = custom("AUTH s3cr3t\r\n");
        let mut masked = whole.clone();
        masked["send"] = json!({ "text": crate::automation::redact::REDACTED });

        for (who, cookie, expected) in [
            ("viewer", viewer.as_str(), &masked),
            ("operator", operator.as_str(), &whole),
            ("superadmin", node.cookie.as_str(), &whole),
        ] {
            let one = node
                .read_as(cookie, &format!("/api/v1/backends/{id}"))
                .await;
            assert_eq!(&one["data"]["health_check"], expected, "{who}: GET one");
            let listed = node.read_as(cookie, "/api/v1/backends").await;
            let rows = listed["data"]["backends"].as_array().expect("a list");
            let row = |wanted: &str| {
                rows.iter()
                    .find(|row| row["id"] == wanted)
                    .map(|row| row["health_check"].clone())
                    .expect("the backend is listed")
            };
            assert_eq!(&row(&id), expected, "{who}: the listing");
            assert_eq!(
                row(&template_id),
                template("redis_ping"),
                "{who}: a template"
            );
            if who == "viewer" {
                assert!(!listed.to_string().contains("s3cr3t"), "{listed}");
                assert!(!one.to_string().contains("s3cr3t"), "{one}");
            }
        }
    }

    #[tokio::test]
    async fn a_masked_payload_sent_back_by_an_operator_keeps_the_stored_one_and_is_never_stored() {
        // A Viewer's masked view can reach an Operator's form; the mask
        // sent back with the rest of the check unchanged keeps the
        // stored payload, anything else carrying it is a 400.
        let node = Node::new().await;
        let (_, created) = node
            .create(
                json!({ "address": "192.0.2.10:6379", "health_check": custom("AUTH s3cr3t\r\n") }),
            )
            .await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        let stored_check = node.stored(&id).await.health_check;
        let viewer = node
            .session_of("viewer01", lorica_config::models::Role::Viewer)
            .await;
        let as_read = node
            .read_as(&viewer, &format!("/api/v1/backends/{id}"))
            .await["data"]["health_check"]
            .clone();

        let (status, answer) = node
            .update(&id, json!({ "health_check": as_read, "weight": 70 }))
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let kept = node.stored(&id).await;
        assert_eq!(kept.health_check, stored_check);
        assert_eq!(kept.weight, 70);

        let mut changed_answer = as_read.clone();
        changed_answer["expect"][0]["bytes"] = json!({ "text": "-NOAUTH" });
        for (what, status_and_answer) in [
            (
                "the mask with another answer",
                node.update(&id, json!({ "health_check": changed_answer }))
                    .await,
            ),
            (
                "the mask on a create",
                node.create(json!({ "address": "192.0.2.12:6379", "health_check": as_read }))
                    .await,
            ),
        ] {
            let (status, answer) = status_and_answer;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {answer}");
            assert!(answer["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("health_check.send:")));
        }
        assert_eq!(node.stored(&id).await.health_check, stored_check);
        let stored = node
            .state
            .store
            .lock()
            .await
            .list_backends()
            .expect("store read");
        assert!(stored
            .iter()
            .all(|backend| backend.address != "192.0.2.12:6379"));
        assert!(stored
            .iter()
            .all(|backend| !serde_json::to_string(&backend.health_check)
                .expect("serialises")
                .contains(crate::automation::redact::REDACTED)));
    }

    #[tokio::test]
    async fn an_empty_legacy_path_speaks_of_the_http_path_only_and_leaves_a_template_alone() {
        let node = Node::new().await;
        let (_, created) = node
            .create(json!({ "address": "192.0.2.10:6379", "health_check": template("redis_ping") }))
            .await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        let (status, answer) = node.update(&id, json!({ "health_check_path": "" })).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["data"]["health_check"], template("redis_ping"));

        // On an HTTP check it still clears the path, as it always has.
        let (_, answer) = node
            .update(&id, json!({ "health_check": http("/ready") }))
            .await;
        assert_eq!(answer["data"]["health_check"], http("/ready"));
        let (_, answer) = node.update(&id, json!({ "health_check_path": "" })).await;
        assert_eq!(
            answer["data"]["health_check"],
            json!({ "kind": "tcp_connect" })
        );
    }

    #[tokio::test]
    async fn a_custom_check_exports_and_imports_through_the_management_api() {
        // The TOML import row of Story 12.7 D-7: an operator's file is the
        // management plane's, so a payload in it is allowed, validated.
        let node = Node::new().await;
        let (_, created) = node
            .create(json!({ "address": "192.0.2.10:6379", "health_check": custom("PING\r\n") }))
            .await;
        let id = created["data"]["id"].as_str().expect("an id").to_string();
        let stored_check = node.stored(&id).await.health_check;
        let response = send(
            &node.state,
            &node.sessions,
            &node.limiter,
            "POST",
            "/api/v1/config/export",
            &node.cookie,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let exported = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("the export reads")
                .to_vec(),
        )
        .expect("the export is text");
        // The users section carries a redacted hash an import refuses,
        // and the export writes it last.
        let exported: String = exported
            .lines()
            .take_while(|line| !line.starts_with("[[users]]"))
            .collect::<Vec<_>>()
            .join("\n");
        {
            let store = node.state.store.lock().await;
            store.delete_backend(&id).expect("the row leaves");
        }
        let (status, answer) = node
            .call(
                "POST",
                "/api/v1/config/import",
                json!({ "toml_content": exported }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(node.stored(&id).await.health_check, stored_check);
    }

    #[tokio::test]
    async fn a_portless_backend_is_stored_only_with_its_checks_off() {
        let node = Node::new().await;
        let (status, answer) = node
            .create(json!({ "address": "backend.example.com", "health_check_enabled": true }))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert!(answer["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no port to probe")));

        let (status, answer) = node
            .create(json!({ "address": "backend.example.com", "health_check_enabled": false }))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        let id = answer["data"]["id"].as_str().expect("an id").to_string();
        let (status, answer) = node
            .update(&id, json!({ "health_check_enabled": true }))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    }
}
