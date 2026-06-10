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
