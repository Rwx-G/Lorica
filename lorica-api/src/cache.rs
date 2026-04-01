use std::sync::atomic::Ordering;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// DELETE /api/v1/cache/routes/:id
///
/// Purge cached responses for a specific route.
/// Since cache keys are composed of host+path+query (not route ID), a
/// per-route purge is not feasible without a secondary index. This endpoint
/// clears **all** cached entries as a pragmatic alternative and resets the
/// hit/miss counters.
pub async fn purge_route_cache(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let entries_cleared = state
        .cache_backend
        .map(|backend| backend.clear_all())
        .unwrap_or(0);

    // Reset hit/miss counters so dashboard stats reflect the purge
    if let Some(ref hits) = state.cache_hits {
        hits.store(0, Ordering::Relaxed);
    }
    if let Some(ref misses) = state.cache_misses {
        misses.store(0, Ordering::Relaxed);
    }

    Ok(json_data_with_status(
        StatusCode::OK,
        serde_json::json!({
            "message": format!("cache purged (requested route {id}, all {entries_cleared} entries cleared)"),
            "entries_cleared": entries_cleared,
        }),
    ))
}

/// GET /api/v1/cache/stats
///
/// Returns cache hit/miss counters from the proxy engine.
pub async fn get_cache_stats(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let hits = state
        .cache_hits
        .as_ref()
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0);
    let misses = state
        .cache_misses
        .as_ref()
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0);
    let total = hits + misses;
    let hit_rate = if total > 0 {
        (hits as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    Ok(json_data(serde_json::json!({
        "hits": hits,
        "misses": misses,
        "total": total,
        "hit_rate": (hit_rate * 100.0).round() / 100.0,
    })))
}

/// GET /api/v1/bans
///
/// Returns the list of currently banned IPs with remaining ban time.
pub async fn list_bans(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bans = match &state.ban_list {
        Some(bl) => bl
            .iter()
            .filter_map(|entry| {
                let elapsed = entry.value().elapsed().as_secs();
                // Default ban duration is 3600s; only show non-expired
                if elapsed < 3600 {
                    Some(serde_json::json!({
                        "ip": entry.key(),
                        "banned_seconds_ago": elapsed,
                        "remaining_seconds": 3600 - elapsed,
                    }))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };

    Ok(json_data(serde_json::json!({
        "bans": bans,
        "total": bans.len(),
    })))
}

/// DELETE /api/v1/bans/:ip
///
/// Remove a specific IP from the ban list.
pub async fn delete_ban(
    Extension(state): Extension<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    match &state.ban_list {
        Some(bl) => {
            if bl.remove(&ip).is_some() {
                Ok(json_data(serde_json::json!({
                    "unbanned": true,
                    "ip": ip,
                })))
            } else {
                Err(ApiError::NotFound(format!("IP {ip} not in ban list")))
            }
        }
        None => Err(ApiError::NotFound("ban list not available".to_string())),
    }
}
