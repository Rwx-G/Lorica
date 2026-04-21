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
    /// Number of routes in the `routes` table.
    pub routes_count: usize,
    /// Number of backends in the `backends` table.
    pub backends_count: usize,
    /// Backends with `health_status == Healthy`.
    pub backends_healthy: usize,
    /// Backends with `health_status == Degraded`.
    pub backends_degraded: usize,
    /// Backends with `health_status == Down`.
    pub backends_down: usize,
    /// Number of certificates in the `certificates` table.
    pub certificates_count: usize,
    /// Certificates whose `not_after` is within 30 days.
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
