//! Endpoints to export the running configuration as TOML and import a new
//! one (with optional dry-run diff preview).

use axum::extract::{ConnectInfo, Extension};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::net::SocketAddr;

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
    connect_info: Option<ConnectInfo<SocketAddr>>,
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

/// POST /api/v1/config/import - replace the entire configuration from a TOML payload (max 1 MB).
pub async fn import_config(
    connect_info: Option<ConnectInfo<SocketAddr>>,
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

    db_blocking(&state.store, move |store| {
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

    Ok(json_data(
        serde_json::json!({"message": "configuration imported successfully"}),
    ))
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

    let diff = db_blocking(&state.store, move |store| {
        lorica_config::diff::compute_diff(&*store, &import_data)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    Ok(json_data(diff))
}
