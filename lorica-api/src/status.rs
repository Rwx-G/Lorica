//! Aggregate counts of routes, backends, and certificates for the dashboard
//! landing page.

use axum::extract::Extension;
use axum::Json;
use serde::Serialize;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// Snapshot returned by `GET /api/v1/status` summarizing the proxy fleet.
#[derive(Serialize)]
pub struct StatusResponse {
    pub routes_count: usize,
    pub backends_count: usize,
    pub backends_healthy: usize,
    pub backends_degraded: usize,
    pub backends_down: usize,
    pub certificates_count: usize,
    pub certificates_expiring_soon: usize,
}

/// GET /api/v1/status - return aggregate counts of routes, backends (by health), and certificates.
pub async fn get_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let routes = store.list_routes()?;
    let backends = store.list_backends()?;
    let certs = store.list_certificates()?;

    let now = chrono::Utc::now();
    let expiry_threshold = now + chrono::Duration::days(30);

    let response = StatusResponse {
        routes_count: routes.len(),
        backends_count: backends.len(),
        backends_healthy: backends
            .iter()
            .filter(|b| b.health_status == lorica_config::models::HealthStatus::Healthy)
            .count(),
        backends_degraded: backends
            .iter()
            .filter(|b| b.health_status == lorica_config::models::HealthStatus::Degraded)
            .count(),
        backends_down: backends
            .iter()
            .filter(|b| b.health_status == lorica_config::models::HealthStatus::Down)
            .count(),
        certificates_count: certs.len(),
        certificates_expiring_soon: certs
            .iter()
            .filter(|c| c.not_after < expiry_threshold)
            .count(),
    };

    Ok(json_data(response))
}
