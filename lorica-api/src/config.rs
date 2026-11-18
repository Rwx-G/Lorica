//! Endpoints to export the running configuration as TOML and import a new
//! one (with optional dry-run diff preview).

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use lorica_config::import::ImportData;
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// JSON body wrapping a TOML configuration document.
#[derive(Deserialize)]
pub struct ImportRequest {
    /// Full TOML document produced by `/config/export`.
    pub toml_content: String,
}

/// POST /api/v1/config/export - serialize the current configuration as a TOML download.
pub async fn export_config(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<
    (
        StatusCode,
        [(http::header::HeaderName, &'static str); 2],
        String,
    ),
    ApiError,
> {
    let toml_content = db_blocking(&state.store, move |store| {
        lorica_config::export::export_to_toml(&*store)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    // The export body carries private keys and credentials: not even a
    // hash lands in the audit row.
    crate::audit::record(
        &state,
        &audit_ctx,
        "config.export",
        ("config", ""),
        None,
        None,
    )
    .await;

    Ok((
        StatusCode::OK,
        [
            (http::header::CONTENT_TYPE, "application/toml"),
            (
                http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"lorica-config.toml\"",
            ),
        ],
        toml_content,
    ))
}

/// Maximum TOML import size: 1 MB.
const MAX_IMPORT_SIZE: usize = 1_048_576;

/// The checks of a stream write, on every stream of an import file
/// against the nodes that would bind it and the file's other streams,
/// since an import replaces the stored ones: the port check (Story 12.1
/// D-9), the local backend rule over the file's own backends and links
/// (Story 12.3 D-m, rule B), the TLS checks against the file's own
/// certificates (Story 12.4 D-k), then the fd budget check (Story 12.2
/// D-e) under the file's own `stream_listen_socket_cap`, which the
/// import writes. A stream the file carries unchanged from a stored row
/// of the same id is judged as an update of that row, so re-importing
/// an export never refuses what the node already holds. Refuses with the
/// first conflict or refusal, as a stream write does, and answers the
/// TLS and budget warnings, each budget warning once.
///
/// One function for the import and its preview, so a preview that
/// comes back clean is an import that will not be refused for a port,
/// a local backend or a budget.
fn check_imported_streams(
    store: &ConfigStore,
    role: &crate::streams::LocalRole,
    budget: &crate::streams::BudgetInputs,
    import: &ImportData,
) -> Result<Vec<String>, ApiError> {
    let streams = &import.streams;
    for stream in streams {
        if let Some(conflict) =
            crate::streams::first_port_conflict(store, role, budget.reserved, stream, streams)?
        {
            return Err(crate::streams::port_conflict_error(stream, &conflict));
        }
    }
    for stream in streams {
        let backends: Vec<lorica_config::models::Backend> = import
            .stream_backends
            .iter()
            .filter(|link| link.stream_id == stream.id)
            .filter_map(|link| import.backends.iter().find(|b| b.id == link.backend_id))
            .cloned()
            .collect();
        if let Some(conflict) = crate::streams::first_local_backend_conflict(
            store,
            role,
            budget.reserved,
            stream,
            &backends,
            streams,
        )? {
            return Err(crate::streams::local_backend_error(stream, &conflict));
        }
    }
    let cap = import.global_settings.stream_listen_socket_cap;
    let mut warnings: Vec<String> = Vec::new();
    // The TLS checks of a stream write (Story 12.4), against the file's
    // certificates, which replace the stored ones.
    for stream in streams {
        let mut candidate = stream.clone();
        warnings.extend(crate::streams::tls_checks::check_bundles(&mut candidate)?);
        warnings.extend(crate::streams::tls_checks::check_certificates(
            &candidate,
            &import.certificates,
        )?);
    }
    for stream in streams {
        let stored = store.get_stream(&stream.id)?;
        for warning in crate::streams::budget_warnings(
            store,
            role,
            budget,
            cap,
            stream,
            stored.as_ref(),
            streams,
        )? {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    Ok(warnings)
}

/// One stream an import created, changed or removed, as the audit row
/// a stream handler writes for the same change.
struct ImportedStreamChange {
    /// `stream.create`, `stream.update` or `stream.delete`.
    action: &'static str,
    stream_id: String,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
}

/// The streams whose view an import moved, by id: present only after
/// (created), only before (removed), or on both sides with a view that
/// differs in anything but its timestamps (changed).
///
/// The timestamps are left out for the reason the import preview's
/// stream diff leaves them out: an export round trip carries them and a
/// hand edit of a file moves them, and neither changes the stream. The
/// view covers the stream's backend links too, so a change of links
/// alone is a changed stream, which is what the stream handlers'
/// `stream.update` row says of the same change.
fn imported_stream_changes(
    before: &BTreeMap<String, crate::streams::StreamResponse>,
    after: &BTreeMap<String, crate::streams::StreamResponse>,
) -> Vec<ImportedStreamChange> {
    let view = |stream: Option<&crate::streams::StreamResponse>| {
        stream.and_then(|stream| serde_json::to_value(stream).ok())
    };
    let ids: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    ids.into_iter()
        .filter_map(|id| {
            let (before, after) = (view(before.get(id)), view(after.get(id)));
            let action = match (&before, &after) {
                (None, Some(_)) => "stream.create",
                (Some(_), None) => "stream.delete",
                (Some(old), Some(new)) if !same_but_timestamps(old, new) => "stream.update",
                _ => return None,
            };
            Some(ImportedStreamChange {
                action,
                stream_id: id.clone(),
                before,
                after,
            })
        })
        .collect()
}

/// Whether two stream views are equal once both timestamps are left out.
fn same_but_timestamps(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let without = |view: &serde_json::Value| {
        let mut view = view.clone();
        if let Some(fields) = view.as_object_mut() {
            fields.remove("created_at");
            fields.remove("updated_at");
        }
        view
    };
    without(a) == without(b)
}

/// POST /api/v1/config/import - replace the entire configuration from a TOML payload (max 1 MB).
pub async fn import_config(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.toml_content.len() > MAX_IMPORT_SIZE {
        return Err(ApiError::BadRequest(format!(
            "TOML content too large: {} bytes (max {} bytes)",
            body.toml_content.len(),
            MAX_IMPORT_SIZE
        )));
    }

    let import_data = lorica_config::import::parse_toml(&body.toml_content)
        .map_err(|e| ApiError::BadRequest(format!("invalid TOML: {e}")))?;

    // Validate every cert+key bundle with the worker's loader before
    // touching the store so a single bad row in a bulk import cannot
    // land in the database and poison subsequent
    // `cert_resolver.reload(...)` batches at runtime, *and* so an
    // import where the cert and key come from two different keypairs
    // is rejected at the boundary rather than surfacing as a TLS
    // `DecryptError` alert at handshake time. Same invariant as
    // POST/PUT /certificates.
    for cert in &import_data.certificates {
        crate::certificates::validate_certificate_bundle(&cert.cert_pem, &cert.key_pem).map_err(
            |e| match e {
                ApiError::BadRequest(msg) => {
                    ApiError::BadRequest(format!("certificate {:?}: {}", cert.domain, msg))
                }
                other => other,
            },
        )?;
    }

    let role = crate::streams::LocalRole::of(&state);
    let budget = crate::streams::BudgetInputs::of(&state);
    // What the import changed on its own initiative, such as an AD CS
    // certificate made manual because its authority is not on this
    // node (Epic 13 D14), and the nodes whose fd budget it could not
    // check. The caller learns it here or not at all.
    let (warnings, stream_changes) = db_blocking(&state.store, move |store| {
        // Before `import_to_store`, which clears the store first, and in
        // the same closure, so no stream write lands between the check
        // and the import, nor between either view and the import.
        let mut warnings = check_imported_streams(store, &role, &budget, &import_data)?;
        let before = crate::streams::stream_views(store)?;
        warnings.extend(
            lorica_config::import::import_to_store(&*store, &import_data)
                .map_err(|e| ApiError::Internal(e.to_string()))?,
        );
        let after = crate::streams::stream_views(store)?;
        Ok::<_, ApiError>((warnings, imported_stream_changes(&before, &after)))
    })
    .await?;
    state.notify_config_changed();

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    // The import body carries private keys and credentials: not even a
    // hash lands in the audit row.
    crate::audit::record(
        &state,
        &audit_ctx,
        "config.import",
        ("config", ""),
        None,
        None,
    )
    .await;
    // A stream view carries no secret (`STREAM_WITHHELD_FIELDS` is
    // empty), so each stream the import moved gets the row a stream
    // handler would have written, payloads included (Story 12.10 D-h).
    // Routes keep the single row above (Resolved 5).
    for change in &stream_changes {
        crate::audit::record(
            &state,
            &audit_ctx,
            change.action,
            ("stream", &change.stream_id),
            change.before.as_ref(),
            change.after.as_ref(),
        )
        .await;
    }

    Ok(json_data(serde_json::json!({
        "message": "configuration imported successfully",
        "warnings": warnings,
    })))
}

/// POST /api/v1/config/import/preview - parse a TOML payload and return its diff without applying it.
pub async fn import_preview(
    Extension(state): Extension<AppState>,
    Json(body): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.toml_content.len() > MAX_IMPORT_SIZE {
        return Err(ApiError::BadRequest(format!(
            "TOML content too large: {} bytes (max {} bytes)",
            body.toml_content.len(),
            MAX_IMPORT_SIZE
        )));
    }

    let import_data = lorica_config::import::parse_toml_for_preview(&body.toml_content)
        .map_err(|e| ApiError::BadRequest(format!("invalid TOML: {e}")))?;

    let role = crate::streams::LocalRole::of(&state);
    let budget = crate::streams::BudgetInputs::of(&state);
    let (diff, warnings) = db_blocking(&state.store, move |store| {
        // The import answers 409 on a port conflict and 422 on a budget
        // it breaks; the preview must say so too, or it reads clean for
        // a file the import refuses.
        let warnings = check_imported_streams(store, &role, &budget, &import_data)?;
        let diff = lorica_config::diff::compute_diff(&*store, &import_data)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>((diff, warnings))
    })
    .await?;

    Ok(json_data(PreviewResponse { diff, warnings }))
}

/// What `POST /api/v1/config/import/preview` answers: the diff, and the
/// nodes whose fd budget the import could not check, which the import
/// would answer too.
#[derive(Serialize)]
struct PreviewResponse {
    #[serde(flatten)]
    diff: lorica_config::diff::ConfigDiff,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}
