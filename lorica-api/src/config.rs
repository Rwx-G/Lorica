//! Endpoints to export the running configuration as TOML and import a new
//! one (with optional dry-run diff preview).

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// JSON body wrapping a TOML configuration document.
#[derive(Deserialize)]
pub struct ImportRequest {
    /// Full TOML document produced by `/config/export`.
    pub toml_content: String,
}

/// POST /api/v1/config/export - serialize the current configuration as a TOML download.
pub async fn export_config(
    Extension(state): Extension<AppState>,
) -> Result<
    (
        StatusCode,
        [(http::header::HeaderName, &'static str); 2],
        String,
    ),
    ApiError,
> {
    let store = state.store.lock().await;
    let toml_content = lorica_config::export::export_to_toml(&store)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

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

    let import_data = lorica_config::import::parse_toml(&body.toml_content)
        .map_err(|e| ApiError::BadRequest(format!("invalid TOML: {e}")))?;

    let store = state.store.lock().await;
    lorica_config::import::import_to_store(&store, &import_data)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    drop(store);
    state.notify_config_changed();

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

    let store = state.store.lock().await;
    let diff = lorica_config::diff::compute_diff(&store, &import_data)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(diff))
}
