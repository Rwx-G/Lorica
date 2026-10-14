// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! What a process does when `access-log.db` will not open: serve, but
//! shout.
//!
//! From 1.7.0 to 1.9.1 a store written by 1.6.0 failed to open, and a
//! production node served traffic for over a month with no audit
//! trail, no access logs and no WAF events, announced by one WARN line
//! per process at start. Refusing to serve would turn a forensics loss
//! into an outage, so the proxy keeps serving; what changes is that the
//! failure can no longer go unseen, and that it heals on its own once
//! the cause is fixed:
//!
//! - every process logs the failure at ERROR, with the cause;
//! - `lorica_log_store_up` reads 0 for that process (a worker's value
//!   reaches the supervisor's scrape through its metrics report);
//! - the process serving the management API raises
//!   `log_store_unavailable` when the node stops persisting, sends it
//!   again until a notification channel has taken it, then reminds every
//!   [`LOG_STORE_REMINDER_INTERVAL`] for as long as the outage lasts, and
//!   raises `log_store_recovered` when it ends; the dashboard shows a
//!   banner on every page in between;
//! - every process that failed retries the open every
//!   [`LOG_STORE_RETRY_INTERVAL`] and, on success, installs the store in
//!   its [`LogStoreSlot`], which every consumer reads at use time, so
//!   persistence resumes without a restart.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use lorica_api::log_store::LogStore;
use lorica_api::server::LogStoreSlot;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::DeliveryRecord;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// How often a process whose store is not open tries again.
pub(crate) const LOG_STORE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How often the management process re-reads the node's state for the
/// alerts. Shorter than the retry interval, because a worker's state
/// reaches the supervisor on its own schedule, not on the retry's.
pub(crate) const LOG_STORE_WATCH_INTERVAL: Duration = Duration::from_secs(15);

/// While the outage lasts and the last `log_store_unavailable` reached
/// a channel, how long until it is sent again as a reminder.
pub(crate) const LOG_STORE_REMINDER_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long after a `log_store_unavailable` that reached no channel (a
/// lagged broadcast, a rate limit, every channel failing) it is sent
/// again. Doubles on each further miss, up to
/// [`LOG_STORE_REMINDER_INTERVAL`], so a channel that is broken for good
/// is not hammered.
const UNDELIVERED_ALERT_RETRY: Duration = Duration::from_secs(60);

/// While the store stays down with the same cause, one retry in this
/// many logs the ERROR again, so the journal carries a reminder every
/// `REMINDER_EVERY_ATTEMPTS` retry intervals rather than a line per
/// retry.
const REMINDER_EVERY_ATTEMPTS: u64 = 15;

/// Fired when the process starts shutting down: the retry and watch
/// loops stop at once instead of holding the shutdown up.
static SHUTDOWN: LazyLock<CancellationToken> = LazyLock::new(CancellationToken::new);

/// Stop every log-store retry and watch loop of this process. Called
/// when the shutdown signal arrives.
pub(crate) fn begin_shutdown() {
    SHUTDOWN.cancel();
}

/// Which kind of process holds the store, for the logs and the gauge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogStoreRole {
    /// Single-process mode: the API and the proxy in one process.
    Single,
    /// The supervisor: the API, the audit trail, no proxy.
    Supervisor,
    /// A worker: the proxy, which writes access logs and WAF events.
    Worker,
}

impl LogStoreRole {
    /// The `role` label value of `lorica_log_store_up`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Supervisor => "supervisor",
            Self::Worker => "worker",
        }
    }

    /// Whether this process runs the proxy, and so needs the background
    /// writer the proxy persists through.
    fn runs_proxy(self) -> bool {
        !matches!(self, Self::Supervisor)
    }
}

/// Open this process's store at boot and register its slot for the
/// process. Never fails: a store that will not open yields a slot that
/// records the cause, for [`spawn_log_store_retry`] to fill later.
pub(crate) fn open_log_store(data_dir: &Path, role: LogStoreRole) -> LogStoreSlot {
    let slot = match LogStore::open(data_dir) {
        Ok(store) => {
            let store = Arc::new(store);
            let writer = writer_for(role, &store);
            LogStoreSlot::opened(store, writer)
        }
        Err(cause) => {
            error!(
                role = role.as_str(),
                data_dir = %data_dir.display(),
                error = %cause,
                retry_s = LOG_STORE_RETRY_INTERVAL.as_secs(),
                "the access-log database could not be opened: the audit trail, access logs \
                 and WAF events are NOT being persisted; traffic is still served and the open \
                 is retried"
            );
            LogStoreSlot::failed(cause)
        }
    };
    lorica_api::metrics::set_log_store_up(role.as_str(), slot.store().is_some());
    slot.register_for_process();
    slot
}

/// The proxy's background writer for `store`, in a process that runs
/// the proxy.
fn writer_for(
    role: LogStoreRole,
    store: &Arc<LogStore>,
) -> Option<lorica_api::log_writer::LogWriteHandle> {
    role.runs_proxy()
        .then(|| lorica_api::log_writer::spawn_log_writer(Arc::clone(store)))
}

/// One retry: open the store and install it in `slot`. Returns whether
/// the slot now holds a store. `attempt` counts from 1 and only paces
/// the reminder lines.
///
/// Blocking: SQLite opens the file and runs the schema migrations.
pub(crate) fn retry_log_store_once(
    slot: &LogStoreSlot,
    data_dir: &Path,
    role: LogStoreRole,
    attempt: u64,
) -> bool {
    if slot.store().is_some() {
        return true;
    }
    match LogStore::open(data_dir) {
        Ok(store) => {
            let store = Arc::new(store);
            let writer = writer_for(role, &store);
            if slot.install(store, writer) {
                info!(
                    role = role.as_str(),
                    data_dir = %data_dir.display(),
                    attempt,
                    "the access-log database is open again: the audit trail, access logs and \
                     WAF events are being persisted"
                );
            }
            lorica_api::metrics::set_log_store_up(role.as_str(), true);
            true
        }
        Err(cause) => {
            let changed = slot.failure().as_deref() != Some(cause.as_str());
            if changed || attempt.is_multiple_of(REMINDER_EVERY_ATTEMPTS) {
                error!(
                    role = role.as_str(),
                    data_dir = %data_dir.display(),
                    error = %cause,
                    attempt,
                    "the access-log database still cannot be opened: the audit trail, access \
                     logs and WAF events are NOT being persisted"
                );
            }
            slot.record_failure(cause);
            lorica_api::metrics::set_log_store_up(role.as_str(), false);
            false
        }
    }
}

/// An attempt that panicked: logged and recorded as the slot's cause,
/// so neither the journal nor the status endpoint keeps showing the
/// previous attempt's cause as if it were current.
fn record_panicked_attempt(slot: &LogStoreSlot, role: LogStoreRole, attempt: u64, panic: &str) {
    error!(
        role = role.as_str(),
        attempt,
        panic,
        "opening the access-log database panicked: the audit trail, access logs and WAF \
         events are NOT being persisted; the open is retried"
    );
    slot.record_failure(format!("opening the access-log database panicked: {panic}"));
    lorica_api::metrics::set_log_store_up(role.as_str(), false);
}

/// Run `attempt` on a thread of its own and hand back its result, or
/// the panic message if it panicked.
///
/// Not `spawn_blocking`: dropping a tokio runtime waits for its blocking
/// tasks, so an open stuck on SQLite's busy timeout would hold the
/// process's shutdown up. A plain thread is abandoned at exit instead,
/// which is safe because every step of `LogStore::open` is idempotent
/// and transactional and resumes on the next start.
fn run_off_runtime<F>(attempt: F) -> tokio::sync::oneshot::Receiver<Result<bool, String>>
where
    F: FnOnce() -> bool + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("log-store-retry".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt))
                .map_err(|payload| panic_message(payload.as_ref()));
            let _ = tx.send(outcome);
        });
    if let Err(e) = spawned {
        // The sender went down with the closure, so the receiver
        // reports the attempt as gone; the cause is logged here.
        error!(error = %e, "could not start a thread to retry the access-log database");
    }
    rx
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no message".to_string())
}

/// Retry the open every `interval` until it succeeds or the process
/// shuts down, then stop. Returns `None`, spawning nothing, when the
/// store is already open. Must be called from within a tokio runtime
/// context.
pub(crate) fn spawn_log_store_retry(
    slot: LogStoreSlot,
    data_dir: PathBuf,
    role: LogStoreRole,
    interval: Duration,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_log_store_retry_until(slot, data_dir, role, interval, SHUTDOWN.clone())
}

fn spawn_log_store_retry_until(
    slot: LogStoreSlot,
    data_dir: PathBuf,
    role: LogStoreRole,
    interval: Duration,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if slot.store().is_some() {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // the boot attempt just failed
        let mut attempt: u64 = 0;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            attempt += 1;
            let (attempt_slot, attempt_dir) = (slot.clone(), data_dir.clone());
            let running = run_off_runtime(move || {
                retry_log_store_once(&attempt_slot, &attempt_dir, role, attempt)
            });
            let outcome = tokio::select! {
                _ = shutdown.cancelled() => return,
                outcome = running => outcome,
            };
            match outcome {
                Ok(Ok(true)) => return,
                Ok(Ok(false)) => {}
                Ok(Err(panic)) => record_panicked_attempt(&slot, role, attempt, &panic),
                Err(_) => record_panicked_attempt(
                    &slot,
                    role,
                    attempt,
                    "the retry thread ended without a result",
                ),
            }
        }
    }))
}

/// An outage the alerts are tracking.
#[derive(Debug)]
struct Outage {
    /// When it was first seen, for the reminders.
    since: String,
    /// When `log_store_unavailable` was last sent.
    sent_at: Instant,
    /// Whether that send reached a channel (or there is none to reach).
    delivered: bool,
    /// How long to wait before sending again while not delivered.
    retry_after: Duration,
}

/// The alert half of the failure mode.
///
/// `log_store_unavailable` when the node stops persisting; sent again
/// [`UNDELIVERED_ALERT_RETRY`] later (doubling) while no channel has
/// taken it, and every [`LOG_STORE_REMINDER_INTERVAL`] once one has, for
/// as long as the outage lasts, however many retries fail or however
/// the cause changes; `log_store_recovered` when it ends.
#[derive(Debug, Default)]
pub(crate) struct LogStoreAlerts {
    outage: Option<Outage>,
}

impl LogStoreAlerts {
    /// Feed the node's current failure (see
    /// [`lorica_api::status::log_store_failure`]), the time, and the last
    /// dispatch of a `log_store_unavailable` (see
    /// [`lorica_notify::AlertLedger::last_delivery`]), and get the alert
    /// owed, if any.
    pub(crate) fn observe(
        &mut self,
        failure: Option<&str>,
        now: Instant,
        last_delivery: Option<DeliveryRecord>,
    ) -> Option<AlertEvent> {
        let Some(cause) = failure else {
            return self.outage.take().map(|_| {
                AlertEvent::new(
                    AlertType::LogStoreRecovered,
                    "Audit trail, access logs and WAF events are being persisted again",
                )
            });
        };
        let Some(outage) = &mut self.outage else {
            let outage = self.outage.insert(Outage {
                since: chrono::Utc::now().to_rfc3339(),
                sent_at: now,
                delivered: false,
                retry_after: UNDELIVERED_ALERT_RETRY,
            });
            return Some(unavailable_alert(cause, &outage.since, false));
        };
        if !outage.delivered {
            outage.delivered = last_delivery
                .is_some_and(|record| record.at >= outage.sent_at && record.outcome.settled());
        }
        let wait = if outage.delivered {
            LOG_STORE_REMINDER_INTERVAL
        } else {
            outage.retry_after
        };
        if now.duration_since(outage.sent_at) < wait {
            return None;
        }
        outage.retry_after = if outage.delivered {
            UNDELIVERED_ALERT_RETRY
        } else {
            (outage.retry_after * 2).min(LOG_STORE_REMINDER_INTERVAL)
        };
        outage.sent_at = now;
        outage.delivered = false;
        Some(unavailable_alert(cause, &outage.since, true))
    }
}

fn unavailable_alert(cause: &str, since: &str, again: bool) -> AlertEvent {
    let summary = if again {
        "Audit trail, access logs and WAF events are still not being persisted"
    } else {
        "Audit trail, access logs and WAF events are not being persisted"
    };
    AlertEvent::new(AlertType::LogStoreUnavailable, summary)
        .with_detail("cause", cause)
        .with_detail("down_since", since)
        .with_detail(
            "retry_interval_s",
            LOG_STORE_RETRY_INTERVAL.as_secs().to_string(),
        )
}

/// Watch the node's log-store state from the process serving the
/// management API and raise the alerts, until the process shuts down.
/// The first check runs at once, so a store that failed at boot alerts
/// within the minute rather than after the first retry.
pub(crate) fn spawn_log_store_watch(
    alert_sender: lorica_notify::AlertSender,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let shutdown = SHUTDOWN.clone();
    tokio::spawn(async move {
        let mut alerts = LogStoreAlerts::default();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let failure = lorica_api::status::log_store_failure();
            let delivery = alert_sender
                .ledger()
                .last_delivery(&AlertType::LogStoreUnavailable);
            if let Some(event) = alerts.observe(failure.as_deref(), Instant::now(), delivery) {
                alert_sender.send(event);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_notify::DispatchOutcome;

    /// A data directory whose `access-log.db` is a directory, which
    /// SQLite refuses to open: the shape of a store that will not open,
    /// fixed by removing that directory.
    fn blocked_data_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        std::fs::create_dir(dir.path().join("access-log.db")).expect("test setup: blocker");
        dir
    }

    fn unblock(dir: &tempfile::TempDir) {
        std::fs::remove_dir(dir.path().join("access-log.db")).expect("test setup: unblock");
    }

    fn delivered_at(at: Instant) -> Option<DeliveryRecord> {
        Some(DeliveryRecord {
            at,
            outcome: DispatchOutcome {
                subscribed: 1,
                delivered: 1,
            },
        })
    }

    fn refused_at(at: Instant) -> Option<DeliveryRecord> {
        Some(DeliveryRecord {
            at,
            outcome: DispatchOutcome {
                subscribed: 1,
                delivered: 0,
            },
        })
    }

    const CAUSE: &str = "failed to open access log database: disk full";

    #[test]
    fn an_outage_alerts_then_reminds_until_its_end_alerts_once() {
        let start = Instant::now();
        let mut alerts = LogStoreAlerts::default();
        assert!(
            alerts.observe(None, start, None).is_none(),
            "a healthy node is quiet"
        );

        let down = alerts
            .observe(Some(CAUSE), start, None)
            .expect("the outage alerts");
        assert_eq!(down.alert_type, AlertType::LogStoreUnavailable);
        assert_eq!(down.details.get("cause").map(String::as_str), Some(CAUSE));

        // Delivered: every failed retry, a changed cause included, is the
        // same outage and stays quiet until the reminder is due.
        let delivered = delivered_at(start + Duration::from_secs(1));
        let almost = start + LOG_STORE_REMINDER_INTERVAL - Duration::from_secs(1);
        for (at, cause) in [
            (start + Duration::from_secs(15), CAUSE),
            (start + UNDELIVERED_ALERT_RETRY * 4, "permission denied"),
            (almost, CAUSE),
        ] {
            assert!(
                alerts.observe(Some(cause), at, delivered).is_none(),
                "{cause}"
            );
        }
        let reminder = alerts
            .observe(Some(CAUSE), start + LOG_STORE_REMINDER_INTERVAL, delivered)
            .expect("an hour on, the operator is reminded");
        assert_eq!(reminder.alert_type, AlertType::LogStoreUnavailable);
        assert_eq!(
            reminder.details.get("down_since"),
            down.details.get("down_since")
        );

        let up = alerts
            .observe(None, start + LOG_STORE_REMINDER_INTERVAL * 2, delivered)
            .expect("the recovery alerts");
        assert_eq!(up.alert_type, AlertType::LogStoreRecovered);
        assert!(alerts
            .observe(None, start + LOG_STORE_REMINDER_INTERVAL * 3, delivered)
            .is_none());
    }

    #[test]
    fn an_alert_that_reached_no_channel_is_sent_again_with_backoff() {
        let start = Instant::now();
        let mut alerts = LogStoreAlerts::default();
        alerts
            .observe(Some(CAUSE), start, None)
            .expect("first send");

        // Lost on the way: no record at all.
        assert!(alerts
            .observe(Some(CAUSE), start + UNDELIVERED_ALERT_RETRY / 2, None)
            .is_none());
        let first_retry = start + UNDELIVERED_ALERT_RETRY;
        assert!(alerts.observe(Some(CAUSE), first_retry, None).is_some());

        // Rate limited or failed on every channel: a record that settled
        // nothing. The wait doubles.
        let refused = refused_at(first_retry + Duration::from_secs(1));
        assert!(alerts
            .observe(
                Some(CAUSE),
                first_retry + UNDELIVERED_ALERT_RETRY * 2 - Duration::from_secs(1),
                refused
            )
            .is_none());
        let second_retry = first_retry + UNDELIVERED_ALERT_RETRY * 2;
        assert!(alerts.observe(Some(CAUSE), second_retry, refused).is_some());

        // A record older than the last send says nothing about it.
        let stale = delivered_at(first_retry);
        assert!(alerts
            .observe(
                Some(CAUSE),
                second_retry + UNDELIVERED_ALERT_RETRY * 4,
                stale
            )
            .is_some());
    }

    #[test]
    fn the_retry_backoff_stops_at_the_reminder_interval() {
        let start = Instant::now();
        let mut alerts = LogStoreAlerts::default();
        alerts
            .observe(Some(CAUSE), start, None)
            .expect("first send");
        let mut at = start;
        let mut waits = Vec::new();
        for _ in 0..16 {
            let mut next = at + Duration::from_secs(1);
            while alerts.observe(Some(CAUSE), next, None).is_none() {
                next += Duration::from_secs(15);
            }
            waits.push(next.duration_since(at));
            at = next;
        }
        assert!(waits.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            waits
                .iter()
                .all(|wait| *wait < LOG_STORE_REMINDER_INTERVAL + Duration::from_secs(15)),
            "{waits:?}"
        );
    }

    #[test]
    fn no_channel_to_reach_settles_the_alert() {
        let start = Instant::now();
        let mut alerts = LogStoreAlerts::default();
        alerts
            .observe(Some(CAUSE), start, None)
            .expect("first send");
        let nobody = Some(DeliveryRecord {
            at: start + Duration::from_secs(1),
            outcome: DispatchOutcome::default(),
        });
        assert!(alerts
            .observe(Some(CAUSE), start + UNDELIVERED_ALERT_RETRY * 8, nobody)
            .is_none());
    }

    #[test]
    fn a_failed_retry_keeps_the_slot_down_and_a_later_one_installs_the_store() {
        let dir = blocked_data_dir();
        let slot = LogStoreSlot::failed("boot failure".to_string());

        assert!(!retry_log_store_once(
            &slot,
            dir.path(),
            LogStoreRole::Single,
            1
        ));
        assert!(slot.store().is_none());
        let cause = slot.failure().expect("still down");
        assert!(cause.contains("access log database"), "{cause}");

        unblock(&dir);
        assert!(retry_log_store_once(
            &slot,
            dir.path(),
            LogStoreRole::Single,
            2
        ));
        assert!(slot.store().is_some(), "the store is installed");
        assert!(slot.writer().is_some(), "with the proxy's writer");
        assert!(slot.failure().is_none());
    }

    #[test]
    fn the_supervisor_installs_a_store_and_no_proxy_writer() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let slot = LogStoreSlot::failed("boot failure".to_string());
        assert!(retry_log_store_once(
            &slot,
            dir.path(),
            LogStoreRole::Supervisor,
            1
        ));
        assert!(slot.store().is_some());
        assert!(slot.writer().is_none());
    }

    #[tokio::test]
    async fn the_retry_loop_resumes_persistence_once_the_cause_is_fixed() {
        let dir = blocked_data_dir();
        let slot = LogStoreSlot::failed("boot failure".to_string());
        let held_by_a_consumer = slot.clone();
        let retry = spawn_log_store_retry_until(
            slot,
            dir.path().to_path_buf(),
            LogStoreRole::Worker,
            Duration::from_millis(20),
            CancellationToken::new(),
        )
        .expect("a down store is retried");

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(held_by_a_consumer.store().is_none(), "still blocked");

        unblock(&dir);
        tokio::time::timeout(Duration::from_secs(5), retry)
            .await
            .expect("the loop ends once the store is installed")
            .expect("the loop does not panic");
        assert!(held_by_a_consumer.store().is_some());
        assert!(held_by_a_consumer.writer().is_some());
    }

    #[tokio::test]
    async fn the_retry_loop_stops_at_shutdown() {
        let dir = blocked_data_dir();
        let shutdown = CancellationToken::new();
        let retry = spawn_log_store_retry_until(
            LogStoreSlot::failed("boot failure".to_string()),
            dir.path().to_path_buf(),
            LogStoreRole::Worker,
            Duration::from_secs(3600),
            shutdown.clone(),
        )
        .expect("a down store is retried");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), retry)
            .await
            .expect("the loop ends at shutdown, not at its next tick")
            .expect("the loop does not panic");
    }

    #[tokio::test]
    async fn a_panicking_attempt_is_reported_not_swallowed() {
        let outcome = run_off_runtime(|| panic!("migration exploded"))
            .await
            .expect("the thread reports back");
        let panic = outcome.expect_err("the panic comes back as an error");
        assert!(panic.contains("migration exploded"), "{panic}");

        let slot = LogStoreSlot::failed("an earlier cause".to_string());
        record_panicked_attempt(&slot, LogStoreRole::Worker, 3, &panic);
        let cause = slot.failure().expect("still down");
        assert!(cause.contains("panicked"), "{cause}");
        assert!(cause.contains("migration exploded"), "{cause}");
    }

    #[test]
    fn an_open_store_is_not_retried() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let store = Arc::new(LogStore::open(dir.path()).expect("test setup: log store"));
        let slot = LogStoreSlot::opened(store, None);
        assert!(spawn_log_store_retry(
            slot,
            dir.path().to_path_buf(),
            LogStoreRole::Single,
            LOG_STORE_RETRY_INTERVAL
        )
        .is_none());
    }
}
