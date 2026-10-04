//! Blocking-pool helpers for SQLite access from async handlers.
//!
//! SQLite calls are synchronous; under a contended WAL a single call
//! can hold the connection for up to `busy_timeout` (5 s). Running
//! them inline in an async handler stalls the tokio reactor thread
//! for that whole window. These helpers move every store call onto
//! the blocking thread pool so the reactor keeps serving other
//! requests (audit H-3 + M-16, backlog #31; extends the v1.5.2 M-7
//! pass that covered six `LogStore` sites only).
//!
//! # Request units
//!
//! A write commits on the blocking pool whether or not its request is
//! still awaited, and hyper drops the request future when the peer goes
//! away: awaited there, the reload signal and the audit row that follow
//! the commit were lost with the client. So each plane runs a request
//! that may write as one task the request awaits but does not own, a
//! [`DetachedUnits`] unit: the management plane every request that is
//! not a read ([`detach_mutations`]), the automation plane every
//! request, its own audit row included (`crate::automation::audit`).
//!
//! A unit outlives its connection, so the connection caps no longer
//! bound it: each plane's units are bounded by a semaphore of their
//! own, acquired before the unit starts, so a client that hangs up
//! while it waits for a slot starts nothing, and one that hangs up
//! after leaves a unit that still counts until it ends. The units run
//! on the [`crate::server::AppState::task_tracker`] both binaries drain
//! on shutdown, so a unit between its commit and its audit row is
//! waited for rather than cut, within the drain's own deadline.
//! `lorica_detached_request_units{plane}` is the number in flight.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use lorica_config::ConfigStore;
use tokio::sync::Semaphore;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use crate::error::ApiError;
use crate::log_store::LogStore;
use crate::server::AppState;

/// The most mutating management requests that run at once, each as a
/// detached unit. Past it a request waits for a slot on its own
/// connection, where a client that gives up cancels nothing that ran.
pub const MANAGEMENT_DETACHED_UNITS_MAX: usize = 256;

/// A plane's bound on the request units it runs detached from their
/// connections. See the module docs.
#[derive(Debug)]
pub struct DetachedUnits {
    plane: &'static str,
    permits: Arc<Semaphore>,
}

impl DetachedUnits {
    /// A bound of `capacity` units in flight at once, reported under
    /// `plane` in `lorica_detached_request_units`.
    pub fn new(plane: &'static str, capacity: usize) -> DetachedUnits {
        DetachedUnits {
            plane,
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// The number of units that may still start without waiting.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Run `unit` to its end as a task on `tracker` that the caller
    /// awaits but does not own, once a slot is free.
    ///
    /// The slot is taken on the caller, before the task exists, and
    /// released when the task ends: dropping the caller while it waits
    /// starts nothing, and dropping it after cancels nothing.
    ///
    /// `None` when the runtime cancelled the task, which is a shutdown
    /// past the drain's deadline. A panic in `unit` is resumed on the
    /// caller, so the panic net above sees it as it always did.
    pub async fn run<F>(&self, tracker: &TaskTracker, unit: F) -> Option<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let slot = Arc::clone(&self.permits).acquire_owned().await.ok()?;
        let plane = self.plane;
        let task = tracker.spawn(async move {
            let _slot = slot;
            let _in_flight = InFlight::enter(plane);
            unit.await
        });
        match task.await {
            Ok(answer) => Some(answer),
            Err(failed) if failed.is_panic() => std::panic::resume_unwind(failed.into_panic()),
            Err(_) => None,
        }
    }
}

/// One unit counted in flight for as long as it lives.
struct InFlight(&'static str);

impl InFlight {
    fn enter(plane: &'static str) -> InFlight {
        crate::metrics::adjust_detached_request_units(plane, 1);
        InFlight(plane)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        crate::metrics::adjust_detached_request_units(self.0, -1);
    }
}

/// The management plane's units, bounded by
/// [`MANAGEMENT_DETACHED_UNITS_MAX`].
pub fn management_units() -> &'static DetachedUnits {
    static UNITS: OnceLock<DetachedUnits> = OnceLock::new();
    UNITS.get_or_init(|| DetachedUnits::new("management", MANAGEMENT_DETACHED_UNITS_MAX))
}

/// Axum middleware: every management request that is not a read runs
/// as one detached unit ([`management_units`]), from the session check
/// to the audit row, so a client that hangs up after the commit cannot
/// cost the reload signal or the row.
///
/// One layer rather than one call per handler: a guarantee placed by
/// hand covered the four handler families someone remembered, and the
/// token mint, the OIDC issuers, the users and every other mutation
/// that writes an audit row were left on the request future.
pub async fn detach_mutations(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let unit = next.run(request).instrument(tracing::Span::current());
    management_units()
        .run(&state.task_tracker, unit)
        .await
        .unwrap_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_more_units_run_at_once_than_the_bound_and_a_freed_slot_starts_the_next() {
        let units = Arc::new(DetachedUnits::new("bound_probe", 2));
        let tracker = TaskTracker::new();
        let mut releases = Vec::new();
        let mut callers = Vec::new();
        let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel::<usize>();
        for unit_id in 0..3 {
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            releases.push(Some(release));
            let started_tx = started_tx.clone();
            let units = Arc::clone(&units);
            let tracker = tracker.clone();
            callers.push(tokio::spawn(async move {
                units
                    .run(&tracker, async move {
                        let _ = started_tx.send(unit_id);
                        let _ = released.await;
                        unit_id
                    })
                    .await
            }));
        }
        drop(started_tx);
        let first = started.recv().await.expect("a unit starts");
        let second = started.recv().await.expect("a second unit starts");
        assert_eq!(units.available(), 0);
        // Every caller is either running or queued for a slot: the
        // third has had every chance to start, and must not have.
        tokio::task::yield_now().await;
        assert!(
            started.try_recv().is_err(),
            "a third unit ran past the bound"
        );
        assert_eq!(tracker.len(), 2, "only the admitted units exist as tasks");

        if let Some(release) = releases[first].take() {
            let _ = release.send(());
        }
        let third = started
            .recv()
            .await
            .expect("the freed slot starts the third");
        assert_eq!([first, second, third].iter().sum::<usize>(), 3);
        for release in releases.into_iter().flatten() {
            let _ = release.send(());
        }
        for caller in callers {
            assert!(caller.await.expect("the caller ends").is_some());
        }
        assert_eq!(units.available(), 2, "every slot comes back");
    }

    #[tokio::test]
    async fn a_unit_whose_caller_is_dropped_runs_to_its_end_and_a_queued_one_never_starts() {
        let units = Arc::new(DetachedUnits::new("drop_probe", 1));
        let tracker = TaskTracker::new();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let (done, finished) = tokio::sync::oneshot::channel::<()>();
        let (entered, has_entered) = tokio::sync::oneshot::channel::<()>();
        let running = {
            let units = Arc::clone(&units);
            let tracker = tracker.clone();
            tokio::spawn(async move {
                units
                    .run(&tracker, async move {
                        let _ = entered.send(());
                        let _ = released.await;
                        let _ = done.send(());
                    })
                    .await
            })
        };
        has_entered.await.expect("the first unit starts");
        let queued_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let queued = {
            let units = Arc::clone(&units);
            let tracker = tracker.clone();
            let queued_ran = Arc::clone(&queued_ran);
            tokio::spawn(async move {
                units
                    .run(&tracker, async move {
                        queued_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        // Both callers go away: the running unit stays, the queued one
        // never took a slot and never becomes a task.
        running.abort();
        queued.abort();
        let _ = running.await;
        let _ = queued.await;
        assert_eq!(tracker.len(), 1);
        let _ = release.send(());
        finished.await.expect("the running unit finished");
        tracker.close();
        tracker.wait().await;
        assert!(!queued_ran.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(units.available(), 1);
    }
}
