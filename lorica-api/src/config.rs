//! Endpoints to export the running configuration as TOML and import a new
//! one (with optional dry-run diff preview).

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::Stream;
use lorica_config::ConfigStore;
use serde::Deserialize;

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

/// The port check of a stream write (Story 12.1 D-9), on every stream
/// of an import file against the nodes that would bind it and the
/// file's other streams, since an import replaces the stored ones.
/// Refuses with the first conflict, as a stream write does.
///
/// One function for the import and its preview, so a preview that
/// comes back clean is an import that will not be refused for a port.
fn refuse_imported_port_conflicts(
    store: &ConfigStore,
    role: &crate::streams::LocalRole,
    reserved: ReservedPorts,
    streams: &[Stream],
) -> Result<(), ApiError> {
    for stream in streams {
        if let Some(conflict) =
            crate::streams::first_port_conflict(store, role, reserved, stream, streams)?
        {
            return Err(crate::streams::port_conflict_error(stream, &conflict));
        }
    }
    Ok(())
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
    let reserved = state.reserved_ports;
    // What the import changed on its own initiative, such as an AD CS
    // certificate made manual because its authority is not on this
    // node (Epic 13 D14). The caller learns it here or not at all.
    let warnings: Vec<String> = db_blocking(&state.store, move |store| {
        // Before `import_to_store`, which clears the store first, and in
        // the same closure, so no stream write lands between the check
        // and the import.
        refuse_imported_port_conflicts(store, &role, reserved, &import_data.streams)?;
        lorica_config::import::import_to_store(&*store, &import_data)
            .map_err(|e| ApiError::Internal(e.to_string()))
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
    let reserved = state.reserved_ports;
    let diff = db_blocking(&state.store, move |store| {
        // The import answers 409 on a port conflict; the preview must
        // say so too, or it reads clean for a file the import refuses.
        refuse_imported_port_conflicts(store, &role, reserved, &import_data.streams)?;
        lorica_config::diff::compute_diff(&*store, &import_data)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    Ok(json_data(diff))
}
