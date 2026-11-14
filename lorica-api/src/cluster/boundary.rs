//! Where the management API meets the fleet runtime of `lorica-fleet`.
//!
//! The runtime knows nothing of HTTP, of the audit chain or of the
//! Prometheus counters, all three of which this crate owns (backlog
//! #52). What it needs from them is supplied here:
//!
//! - the runtime's error becomes an [`ApiError`] at the handler
//!   boundary, with the store errors keeping their status;
//! - a unit that owes an audit row when it panics goes through
//!   [`detached_audited`], which hands the runtime a hook writing the
//!   row with this crate's audit log;
//! - [`distribute_certificate`] stays with the issuance paths that call
//!   it, because it counts each push in this crate's metrics.

use std::sync::Arc;

use lorica_config::{ConfigError, ConfigStore};
use lorica_fleet::runtime::{cert_bundle, detached_with_panic_hook, store_op};
use lorica_fleet::{ClusterRuntime, ClusterRuntimeError};
use tokio::sync::Mutex;

use crate::error::ApiError;

impl From<ClusterRuntimeError> for ApiError {
    fn from(err: ClusterRuntimeError) -> Self {
        match err {
            ClusterRuntimeError::Store(inner) => inner.into(),
            ClusterRuntimeError::Refresh(shared) => shared_api_error(&shared),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

/// The status a shared refresh error answers with: the same one the
/// bare error would get.
///
/// The error sits behind an `Arc` every caller the refresh covered
/// holds, so it cannot be moved into `From<ConfigError>`, which owns
/// the variant-to-status mapping. The store error is re-materialised
/// instead and handed to that mapping, rather than mapped a second time
/// here. The match is exhaustive on purpose: a new `ConfigError` variant
/// fails to compile here instead of silently answering 500.
fn shared_api_error(err: &ClusterRuntimeError) -> ApiError {
    let store = match err {
        ClusterRuntimeError::Store(store) => store,
        ClusterRuntimeError::Refresh(inner) => return shared_api_error(inner),
        other => return ApiError::Internal(other.to_string()),
    };
    let rebuilt = match store {
        ConfigError::NotFound(m) => ConfigError::NotFound(m.clone()),
        ConfigError::Validation(m) => ConfigError::Validation(m.clone()),
        ConfigError::Malformed(m) => ConfigError::Malformed(m.clone()),
        ConfigError::Corrupt(m) => ConfigError::Corrupt(m.clone()),
        ConfigError::Serialization(m) => ConfigError::Serialization(m.clone()),
        // Neither payload can be cloned, and `From<ConfigError>` answers
        // both with a 500 carrying the error's text.
        ConfigError::Database(_) | ConfigError::Io(_) => {
            return ApiError::Internal(store.to_string())
        }
    };
    rebuilt.into()
}

/// The audit row a unit owes for its change, written as
/// `<action>.incomplete` when the unit panics instead of finishing.
///
/// A panic can land after the commit and before the row the commit is
/// owed, and the change then took effect with nothing in the
/// tamper-evident trail. The unit cannot write that row itself once it
/// has unwound, so it is described up front and written for it.
pub struct OwedAudit {
    /// Where the row goes; `None` when the audit log is not open.
    pub log_store: Option<Arc<crate::log_store::LogStore>>,
    /// Who asked for the change.
    pub ctx: crate::audit::AuditContext,
    /// The action the unit records when it finishes.
    pub action: &'static str,
    /// `(target_type, target_id)` as far as it is known before the
    /// unit runs.
    pub target: (&'static str, String),
}

/// `lorica_fleet::runtime::detached` for a unit that commits a change
/// and owes it an audit row: when the unit panics, `owed` is written as
/// `<action>.incomplete` on the unit's own task, so the row does not
/// depend on the caller still being there.
pub async fn detached_audited<T, Fut>(
    what: &'static str,
    owed: OwedAudit,
    work: Fut,
) -> Result<T, ClusterRuntimeError>
where
    Fut: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let on_panic: lorica_fleet::PanicHook = Box::new(move || {
        Box::pin(async move {
            crate::audit::record_with_store(
                owed.log_store,
                &owed.ctx,
                &format!("{}.incomplete", owed.action),
                (owed.target.0, &owed.target.1),
                None,
                Some(&serde_json::json!({ "task": what, "outcome": "panicked" })),
            )
            .await;
        })
    });
    detached_with_panic_hook(what, on_panic, work).await
}

/// Push a certificate's key to the nodes entitled to it (Story 9.5
/// AC #7).
///
/// Best effort by decision D2, and that is the whole design: this is
/// the latency optimisation, not the guarantee. A node that is down,
/// slow or not yet connected is simply absent from the round and asks
/// for what it lacks after its next configuration apply. So every
/// failure here is counted and logged, and none of them fails the
/// issuance that triggered it.
///
/// Does nothing on a node that is not a control plane, which is what
/// makes it safe to call unconditionally from the issuance paths.
pub async fn distribute_certificate(
    cluster: &ClusterRuntime,
    store: &Arc<Mutex<ConfigStore>>,
    cert_id: &str,
) {
    let ClusterRuntime::ControlPlane(runtime) = cluster else {
        return;
    };
    let id = cert_id.to_string();
    let resolved = store_op(store, move |store| {
        let recipients = store.cert_key_recipients(&id)?;
        let cert = store.get_certificate(&id)?;
        Ok((recipients, cert))
    })
    .await;
    let (recipients, cert) = match resolved {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::error!(cert_id, error = %e,
                "could not resolve certificate recipients; the fleet converges by pull");
            return;
        }
    };
    // Three ways to have nothing to push, told apart because they mean
    // very different things to an operator watching an issuance.
    let Some(cert) = cert else {
        tracing::warn!(
            cert_id,
            "certificate vanished between issuance and distribution"
        );
        return;
    };
    if cert.key_pem.is_empty() {
        tracing::error!(
            cert_id,
            "certificate carries no private key; nothing to distribute"
        );
        return;
    }
    if recipients.is_empty() {
        tracing::info!(cert_id, domain = %cert.domain,
            "no node is selected for this certificate; nothing to distribute");
        return;
    }
    let report = runtime
        .control
        .distribute_certificates(&recipients, vec![cert_bundle(&cert)])
        .await;
    for (node_id, count) in &report.installed {
        crate::metrics::inc_cluster_cert_push_by(node_id, "pushed", *count);
        tracing::info!(
            node_id,
            cert_id,
            installed = count,
            "certificate key pushed"
        );
    }
    for (node_id, reason) in &report.failed {
        // One certificate went into this round, so one certificate is
        // what failed to reach the node.
        crate::metrics::inc_cluster_cert_push(node_id, "push_failed");
        tracing::warn!(node_id, cert_id, %reason,
            "certificate push failed; the node asks for it after its next apply");
    }
}

#[cfg(test)]
mod tests {
    use lorica_cluster::ClusterTlsError;

    use super::*;

    #[test]
    fn store_errors_keep_their_http_identity_through_the_runtime_error() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let status = |err: ClusterRuntimeError| ApiError::from(err).into_response().status();
        let shared = |err: ClusterRuntimeError| ClusterRuntimeError::Refresh(Arc::new(err));
        let absent = || ClusterRuntimeError::Store(ConfigError::NotFound("node".into()));
        let refused = || ClusterRuntimeError::Store(ConfigError::Validation("cap".into()));
        let unreadable = || ClusterRuntimeError::Store(ConfigError::Malformed("json".into()));
        let acceptor = || ClusterRuntimeError::Acceptor(ClusterTlsError::Rustls("crl".into()));

        assert_eq!(status(absent()), StatusCode::NOT_FOUND);
        assert_eq!(status(acceptor()), StatusCode::INTERNAL_SERVER_ERROR);
        // A refresh error reaches its callers wrapped and shared since
        // the refreshes coalesce (backlog #79). The wrapper must not
        // turn a store refusal into a 500.
        for (bare, wrapped) in [
            (absent(), shared(absent())),
            (refused(), shared(refused())),
            (unreadable(), shared(unreadable())),
            (acceptor(), shared(acceptor())),
        ] {
            let message = bare.to_string();
            assert_eq!(status(wrapped), status(bare), "{message}");
        }
        let held_by_two = Arc::new(absent());
        let _other_caller = Arc::clone(&held_by_two);
        assert_eq!(
            status(ClusterRuntimeError::Refresh(held_by_two)),
            StatusCode::NOT_FOUND
        );
    }
}
