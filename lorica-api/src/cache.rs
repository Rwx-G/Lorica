use axum::extract::Path;
use axum::http::StatusCode;
use axum::Json;

use crate::error::{json_data_with_status, ApiError};

/// DELETE /api/v1/cache/routes/:id
///
/// Purge cached responses for a specific route. This is a stub that will be
/// wired to the actual cache engine in a later Epic 7 milestone.
pub async fn purge_route_cache(
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Stub - cache engine integration will be added later
    Ok(json_data_with_status(
        StatusCode::OK,
        serde_json::json!({ "message": format!("cache purged for route {id}") }),
    ))
}
