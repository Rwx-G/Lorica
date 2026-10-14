//! Aggregate counts of routes, backends, and certificates for the dashboard
//! landing page.

use axum::extract::Extension;
use axum::Json;
use serde::Serialize;

use crate::db::db_blocking;
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
    /// Whether this node is persisting its audit trail, access logs and
    /// WAF events; the dashboard shows a banner on every page while not.
    pub log_store: LogStoreStatus,
}

/// The node's access-log store, as `GET /api/v1/status` reports it.
#[derive(Serialize)]
pub struct LogStoreStatus {
    /// `false` while this process, or any worker, has no open store.
    pub persisting: bool,
    /// Why not, while `persisting` is `false`.
    pub cause: Option<String>,
}

/// Why this node is not persisting to its access-log store, or `None`
/// when every process holds one.
///
/// Reads this process's registered slot and, in supervisor mode, the
/// state each worker last reported. One answer for the status
/// endpoint, the dashboard banner and the log-store alerts, so the
/// three cannot disagree on whether the node is degraded.
pub fn log_store_failure() -> Option<String> {
    describe_log_store_failure(
        crate::server::process_log_store().and_then(crate::server::LogStoreSlot::failure),
        &crate::metrics::workers_without_log_store(),
    )
}

/// Combine this process's failure and the failed workers into one cause.
///
/// A worker's cause stays in that worker's own log: the report it sends
/// carries the state, not the error text.
pub fn describe_log_store_failure(own: Option<String>, failed_workers: &[u32]) -> Option<String> {
    let workers = (!failed_workers.is_empty()).then(|| {
        let ids: Vec<String> = failed_workers.iter().map(u32::to_string).collect();
        let noun = if ids.len() == 1 { "worker" } else { "workers" };
        format!(
            "{noun} {} could not open access-log.db (the cause is in the worker log)",
            ids.join(", ")
        )
    });
    match (own, workers) {
        (Some(own), Some(workers)) => Some(format!("{own}; {workers}")),
        (own, workers) => own.or(workers),
    }
}

/// GET /api/v1/status - return aggregate counts of routes, backends (by health), and certificates.
pub async fn get_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (routes, backends, certs) = db_blocking(&state.store, move |store| {
        let routes = store.list_routes()?;
        let backends = store.list_backends()?;
        let certs = store.list_certificates()?;
        Ok::<_, ApiError>((routes, backends, certs))
    })
    .await?;

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
        log_store: {
            let cause = log_store_failure();
            LogStoreStatus {
                persisting: cause.is_none(),
                cause,
            }
        },
    };

    Ok(json_data(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cause_names_this_process_then_the_failed_workers() {
        assert_eq!(describe_log_store_failure(None, &[]), None);
        assert_eq!(
            describe_log_store_failure(Some("disk full".to_string()), &[]).as_deref(),
            Some("disk full")
        );
        assert_eq!(
            describe_log_store_failure(None, &[2]).as_deref(),
            Some("worker 2 could not open access-log.db (the cause is in the worker log)")
        );
        assert_eq!(
            describe_log_store_failure(Some("disk full".to_string()), &[0, 3]).as_deref(),
            Some(
                "disk full; workers 0, 3 could not open access-log.db (the cause is in the worker log)"
            )
        );
    }

    #[tokio::test]
    async fn the_status_reports_the_log_store() {
        let (state, _, _) = crate::tests::test_state().await;
        let Json(body) = get_status(Extension(state)).await.expect("status answers");
        let log_store = &body["data"]["log_store"];
        // The worker states are process globals other tests move, so
        // the assertion is on the contract, not on one value: a cause
        // exactly when not persisting.
        let persisting = log_store["persisting"]
            .as_bool()
            .expect("`persisting` is a boolean");
        assert_eq!(log_store["cause"].is_string(), !persisting);
        assert!(log_store["cause"].is_string() || log_store["cause"].is_null());
    }
}
