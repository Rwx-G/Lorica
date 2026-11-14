//! Endpoints to export the running configuration as TOML and import a new
//! one (with optional dry-run diff preview).

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
/// D-9), then the fd budget check (Story 12.2 D-e) under the file's own
/// `stream_listen_socket_cap`, which the import writes. A stream the
/// file carries unchanged from a stored row of the same id is judged
/// as an update of that row, so re-importing an export never refuses
/// what the node already holds. Refuses with the first conflict or
/// budget refusal, as a stream write does, and answers the budget
/// warnings, each once.
///
/// One function for the import and its preview, so a preview that
/// comes back clean is an import that will not be refused for a port
/// or a budget.
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
    let cap = import.global_settings.stream_listen_socket_cap;
    let mut warnings: Vec<String> = Vec::new();
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
    let warnings: Vec<String> = db_blocking(&state.store, move |store| {
        // Before `import_to_store`, which clears the store first, and in
        // the same closure, so no stream write lands between the check
        // and the import.
        let mut warnings = check_imported_streams(store, &role, &budget, &import_data)?;
        warnings.extend(
            lorica_config::import::import_to_store(&*store, &import_data)
                .map_err(|e| ApiError::Internal(e.to_string()))?,
        );
        Ok::<_, ApiError>(warnings)
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
