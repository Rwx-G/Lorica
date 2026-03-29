use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ImportRequest {
    pub toml_content: String,
}

/// POST /api/v1/config/export
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

/// POST /api/v1/config/import
pub async fn import_config(
    Extension(state): Extension<AppState>,
    Json(body): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let import_data = lorica_config::import::parse_toml(&body.toml_content)
        .map_err(|e| ApiError::BadRequest(format!("invalid TOML: {e}")))?;

    let store = state.store.lock().await;
    lorica_config::import::import_to_store(&store, &import_data)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(
        serde_json::json!({"message": "configuration imported successfully"}),
    ))
}
