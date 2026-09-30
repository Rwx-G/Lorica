//! Blocking-pool helpers for SQLite access from async handlers.
//!
//! SQLite calls are synchronous; under a contended WAL a single call
//! can hold the connection for up to `busy_timeout` (5 s). Running
//! them inline in an async handler stalls the tokio reactor thread
//! for that whole window. These helpers move every store call onto
//! the blocking thread pool so the reactor keeps serving other
//! requests (audit H-3 + M-16, backlog #31; extends the v1.5.2 M-7
//! pass that covered six `LogStore` sites only).

use std::sync::Arc;

use lorica_config::ConfigStore;

use crate::error::ApiError;
use crate::log_store::LogStore;

/// Run a closure against the [`ConfigStore`] on the blocking pool.
///
/// Acquires the cross-task store mutex as an owned guard (so the
/// queueing semantics seen by other handlers are unchanged), then
/// executes `f` via `spawn_blocking`. Everything that previously ran
/// under the guard belongs inside `f`; reload notifications and
/// response building stay outside.
///
/// The closure error type only needs `Into<ApiError>`, so pure store
/// closures return `ConfigError` while mixed closures (store calls +
/// business validation) return `ApiError` directly and use `?` on
/// store calls.
pub async fn db_blocking<T, E, F>(
    store: &Arc<tokio::sync::Mutex<ConfigStore>>,
    f: F,
) -> Result<T, ApiError>
where
    F: FnOnce(&mut ConfigStore) -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Into<ApiError> + Send + 'static,
{
    let mut guard = Arc::clone(store).lock_owned().await;
    tokio::task::spawn_blocking(move || f(&mut guard).map_err(Into::into))
        .await
        .map_err(|e| ApiError::Internal(format!("store task join failed: {e}")))?
}

/// Run a write to its end whether or not the request that asked for
/// it is still awaiting.
///
/// A write's store closure runs on the blocking pool and commits
/// whether or not anyone still awaits it; what the body does after the
/// commit, the reload signal and the audit row, runs on the request
/// future, which hyper drops when the peer goes away. Awaited there, a
/// client that hung up at the wrong moment left a stored row the
/// proxy had not loaded and the trail did not show. Spawned, the body
/// runs to its end and the request only waits for it: dropping a
/// `JoinHandle` does not cancel its task. The management handlers of
/// every `_as` body the automation plane shares run through this; the
/// automation plane detaches the whole request, its own row included,
/// in `crate::automation::audit`.
///
/// # Errors
///
/// Whatever `write` answers, or `Internal` when the runtime cancelled
/// the task, which is a shutdown. A panic is resumed on the caller, so
/// the panic net sees it as it always did.
pub async fn run_detached<T, F>(write: F) -> Result<T, ApiError>
where
    F: std::future::Future<Output = Result<T, ApiError>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(write).await {
        Ok(answer) => answer,
        Err(failed) if failed.is_panic() => std::panic::resume_unwind(failed.into_panic()),
        Err(failed) => Err(ApiError::Internal(format!(
            "the write task was cancelled: {failed}"
        ))),
    }
}

/// Run a closure against the access-log [`LogStore`] on the blocking
/// pool. Same rationale as [`db_blocking`]; `LogStore` is internally
/// synchronized so only the `Arc` is cloned, no async mutex involved.
pub async fn log_db_blocking<T, F>(store: &Arc<LogStore>, f: F) -> Result<T, ApiError>
where
    F: FnOnce(&LogStore) -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| ApiError::Internal(format!("log store task join failed: {e}")))?
        .map_err(ApiError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_detached_write_runs_to_its_end_after_its_caller_is_dropped() {
        // The caller stands for a request future hyper drops when the
        // peer goes away; the write stands for a commit followed by its
        // reload signal and audit row.
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        let (done, finished) = tokio::sync::oneshot::channel::<()>();
        let caller = run_detached(async move {
            let _ = wait.await;
            let _ = done.send(());
            Ok::<_, ApiError>(())
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), caller)
                .await
                .is_err(),
            "the write waits for its go"
        );
        // The caller is gone; the write is not.
        go.send(()).expect("the detached write still listens");
        tokio::time::timeout(std::time::Duration::from_secs(5), finished)
            .await
            .expect("the detached write finished")
            .expect("and said so");
    }
}
