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
//! - the process serving the management API raises one
//!   `log_store_unavailable` alert per outage and one
//!   `log_store_recovered` when it ends, and the dashboard shows a
//!   banner on every page in between;
//! - every process that failed retries the open every
//!   [`LOG_STORE_RETRY_INTERVAL`] and, on success, installs the store in
//!   its [`LogStoreSlot`], which every consumer reads at use time, so
//!   persistence resumes without a restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lorica_api::log_store::LogStore;
use lorica_api::server::LogStoreSlot;
use lorica_notify::events::{AlertEvent, AlertType};
use tracing::{error, info};

/// How often a process whose store is not open tries again.
pub(crate) const LOG_STORE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How often the management process re-reads the node's state for the
/// alerts. Shorter than the retry interval, because a worker's state
/// reaches the supervisor on its own schedule, not on the retry's.
pub(crate) const LOG_STORE_WATCH_INTERVAL: Duration = Duration::from_secs(15);

/// While the store stays down with the same cause, one retry in this
/// many logs the ERROR again: a reminder in the journal every quarter
/// hour, rather than a line a minute for as long as the outage lasts.
const REMINDER_EVERY_ATTEMPTS: u64 = 15;

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

/// Retry the open every `interval` until it succeeds, then stop.
/// Returns `None`, spawning nothing, when the store is already open.
/// Must be called from within a tokio runtime context.
pub(crate) fn spawn_log_store_retry(
    slot: LogStoreSlot,
    data_dir: PathBuf,
    role: LogStoreRole,
    interval: Duration,
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
            ticker.tick().await;
            attempt += 1;
            let (slot, data_dir) = (slot.clone(), data_dir.clone());
            let installed = tokio::task::spawn_blocking(move || {
                retry_log_store_once(&slot, &data_dir, role, attempt)
            })
            .await
            .unwrap_or(false);
            if installed {
                return;
            }
        }
    }))
}

/// The alert half of the failure mode: one alert when the node stops
/// persisting, one when it resumes, nothing in between however many
/// retries fail or however the cause changes.
#[derive(Debug, Default)]
pub(crate) struct LogStoreAlerts {
    down: bool,
}

impl LogStoreAlerts {
    /// Feed the node's current failure (see
    /// [`lorica_api::status::log_store_failure`]) and get the alert the
    /// transition owes, if any.
    pub(crate) fn observe(&mut self, failure: Option<&str>) -> Option<AlertEvent> {
        match (self.down, failure) {
            (false, Some(cause)) => {
                self.down = true;
                Some(
                    AlertEvent::new(
                        AlertType::LogStoreUnavailable,
                        "Audit trail, access logs and WAF events are not being persisted",
                    )
                    .with_detail("cause", cause)
                    .with_detail(
                        "retry_interval_s",
                        LOG_STORE_RETRY_INTERVAL.as_secs().to_string(),
                    ),
                )
            }
            (true, None) => {
                self.down = false;
                Some(AlertEvent::new(
                    AlertType::LogStoreRecovered,
                    "Audit trail, access logs and WAF events are being persisted again",
                ))
            }
            _ => None,
        }
    }
}

/// Watch the node's log-store state from the process serving the
/// management API and raise the transition alerts. The first check
/// runs at once, so a store that failed at boot alerts within the
/// minute rather than after the first retry.
pub(crate) fn spawn_log_store_watch(
    alert_sender: lorica_notify::AlertSender,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut alerts = LogStoreAlerts::default();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let failure = lorica_api::status::log_store_failure();
            if let Some(event) = alerts.observe(failure.as_deref()) {
                alert_sender.send(event);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn an_outage_raises_one_alert_and_its_end_one_more() {
        let mut alerts = LogStoreAlerts::default();
        assert!(alerts.observe(None).is_none(), "a healthy node is quiet");

        let down = alerts
            .observe(Some("failed to open access log database: disk full"))
            .expect("the outage alerts");
        assert_eq!(down.alert_type, AlertType::LogStoreUnavailable);
        assert_eq!(
            down.details.get("cause").map(String::as_str),
            Some("failed to open access log database: disk full")
        );

        // Every failed retry, including one whose cause changed, is the
        // same outage and must not page again.
        for cause in ["disk full", "disk full", "permission denied"] {
            assert!(alerts.observe(Some(cause)).is_none(), "{cause}");
        }

        let up = alerts.observe(None).expect("the recovery alerts");
        assert_eq!(up.alert_type, AlertType::LogStoreRecovered);
        assert!(alerts.observe(None).is_none(), "and only once");

        let again = alerts
            .observe(Some("disk full"))
            .expect("a new outage alerts");
        assert_eq!(again.alert_type, AlertType::LogStoreUnavailable);
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
        let retry = spawn_log_store_retry(
            slot,
            dir.path().to_path_buf(),
            LogStoreRole::Worker,
            Duration::from_millis(20),
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
