//! Aggregate counts of routes, backends, and certificates for the dashboard
//! landing page.

use axum::extract::Extension;
use axum::Json;
use lorica_config::models::Role;
use serde::Serialize;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
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
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct LogStoreStatus {
    /// `false` while this process, or any worker, has no open store.
    pub persisting: bool,
    /// Why not, while `persisting` is `false`. The open error itself
    /// only for Operator and above; see [`log_store_status`].
    pub cause: Option<String>,
}

/// What a Viewer reads in place of this process's open error.
const WITHHELD_CAUSE: &str =
    "this node could not open access-log.db (the cause is in its journal, and shown to Operators)";

/// Why this node is not persisting to its access-log store, or `None`
/// when every process holds one.
///
/// Reads this process's registered slot and, in supervisor mode, the
/// state each worker last reported. One answer for the status
/// endpoint, the dashboard banner and the log-store alerts, so the
/// three cannot disagree on whether the node is degraded.
pub fn log_store_failure() -> Option<String> {
    describe_log_store_failure(
        own_log_store_failure(),
        &crate::metrics::workers_without_log_store(),
    )
}

fn own_log_store_failure() -> Option<String> {
    crate::server::process_log_store().and_then(crate::server::LogStoreSlot::failure)
}

/// The log-store part of the status, as `role` may read it.
///
/// The open error is SQLite's text, which names the data directory and
/// can name tables and columns: system internals, which the API withholds
/// from a Viewer elsewhere too (`GET /settings` blanks the log pipeline's
/// topology below Operator). A Viewer still learns that the node is not
/// persisting and which process failed, which is what the banner is for.
pub fn log_store_status(
    role: Role,
    own_failure: Option<String>,
    failed_workers: &[u32],
) -> LogStoreStatus {
    let own_failure = if role < Role::Operator {
        own_failure.map(|_| WITHHELD_CAUSE.to_string())
    } else {
        own_failure
    };
    let cause = describe_log_store_failure(own_failure, failed_workers);
    LogStoreStatus {
        persisting: cause.is_none(),
        cause,
    }
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
    Extension(session): Extension<Session>,
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
        log_store: log_store_status(
            session.role,
            own_log_store_failure(),
            &crate::metrics::workers_without_log_store(),
        ),
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

    /// The text rusqlite gives for a file it cannot open, path included.
    const OPEN_ERROR: &str = "failed to open access log database: unable to open database \
                              file: /var/lib/lorica/access-log.db";

    const ROLES: [Role; 3] = [Role::Viewer, Role::Operator, Role::SuperAdmin];

    #[test]
    fn a_viewer_learns_the_node_is_down_but_not_the_open_error() {
        let viewer = log_store_status(Role::Viewer, Some(OPEN_ERROR.to_string()), &[]);
        assert!(!viewer.persisting);
        let cause = viewer.cause.expect("the banner still has something to say");
        assert!(!cause.contains("/var/lib"), "{cause}");
        assert!(!cause.contains("unable to open"), "{cause}");
        assert!(cause.contains("access-log.db"), "{cause}");
    }

    #[test]
    fn operators_and_above_read_the_open_error() {
        for role in ROLES.into_iter().filter(|role| *role >= Role::Operator) {
            let status = log_store_status(role, Some(OPEN_ERROR.to_string()), &[]);
            assert!(!status.persisting, "{role:?}");
            assert_eq!(status.cause.as_deref(), Some(OPEN_ERROR), "{role:?}");
        }
    }

    #[test]
    fn every_role_reads_which_workers_failed() {
        for role in ROLES {
            let status = log_store_status(role, None, &[2]);
            assert!(!status.persisting, "{role:?}");
            assert_eq!(
                status.cause,
                describe_log_store_failure(None, &[2]),
                "{role:?}"
            );
        }
    }

    #[test]
    fn a_healthy_node_reports_persisting_to_every_role() {
        for role in ROLES {
            assert_eq!(
                log_store_status(role, None, &[]),
                LogStoreStatus {
                    persisting: true,
                    cause: None
                },
                "{role:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_status_endpoint_answers_with_the_log_store() {
        let (state, _, _) = crate::tests::test_state().await;
        let now = chrono::Utc::now();
        let session = Session {
            user_id: "user01".into(),
            username: "user01".into(),
            role: Role::Viewer,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
        };
        let Json(body) = get_status(Extension(state), Extension(session))
            .await
            .expect("status answers");
        let persisting = body["data"]["log_store"]["persisting"]
            .as_bool()
            .expect("`persisting` is a boolean");
        assert_eq!(body["data"]["log_store"]["cause"].is_string(), !persisting);
    }
}
