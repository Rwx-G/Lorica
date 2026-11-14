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

//! The worker's connection tracker (Story 12.2 D-g).
//!
//! Every TCP connection or UDP session registers here with its stream
//! id, `bind_gen`, the backend its engine chose, and the `Arc<Stream>`
//! it was accepted with. A drain marks entries with a deadline and a
//! pending end reason (`config_removed` for a configuration change,
//! `node_shutdown` for a stop). At the deadline the tracker signals the
//! connection to close with that reason, so the end reason is written
//! by the worker and never left to a SIGKILL; a connection that ends on
//! its own first keeps its natural reason.
//!
//! An entry already draining keeps its reason and the earlier of its two
//! deadlines when drained again: a connection the configuration already
//! removed stays `config_removed` if the node then stops.
//!
//! The tracker only signals. Closing the socket is the engine's job, on
//! [`TrackedConnection::closed`]; the entry leaves the tracker when the
//! engine drops its [`TrackedConnection`], which is what
//! [`ConnectionTracker::is_empty`] (the drain watcher's test) waits for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use lorica_config::models::{Stream, StreamEndReason};
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Drain {
    deadline: Instant,
    reason: StreamEndReason,
    signalled: bool,
}

#[derive(Debug)]
struct Entry {
    stream_id: String,
    bind_gen: u64,
    backend_id: Option<String>,
    snapshot: Arc<Stream>,
    drain: Option<Drain>,
    close: watch::Sender<Option<StreamEndReason>>,
}

#[derive(Debug, Default)]
struct State {
    next_id: u64,
    entries: HashMap<u64, Entry>,
}

#[derive(Debug, Default)]
struct Inner {
    state: Mutex<State>,
    drains_changed: Notify,
}

/// What a drain predicate sees of one tracked connection.
#[derive(Debug, Clone, Copy)]
pub struct EntryView<'a> {
    /// The stream the connection was accepted on.
    pub stream_id: &'a str,
    /// The binding it was accepted on.
    pub bind_gen: u64,
    /// The backend its engine chose, once chosen.
    pub backend_id: Option<&'a str>,
    /// The stream as it was when the connection was accepted.
    pub snapshot: &'a Arc<Stream>,
}

/// The worker's registry of live stream connections and sessions.
/// Cloning shares it.
#[derive(Debug, Clone, Default)]
pub struct ConnectionTracker {
    inner: Arc<Inner>,
}

impl ConnectionTracker {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        // Every critical section is a few map operations that leave the
        // map consistent, so a poisoned lock is still a usable one.
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    /// Register a connection accepted on binding `bind_gen` of
    /// `snapshot`'s stream. The returned guard deregisters it on drop.
    pub fn register(&self, bind_gen: u64, snapshot: Arc<Stream>) -> TrackedConnection {
        let (close, close_rx) = watch::channel(None);
        let id = self.with_state(|s| {
            let id = s.next_id;
            s.next_id = s.next_id.wrapping_add(1);
            s.entries.insert(
                id,
                Entry {
                    stream_id: snapshot.id.clone(),
                    bind_gen,
                    backend_id: None,
                    snapshot: Arc::clone(&snapshot),
                    drain: None,
                    close,
                },
            );
            id
        });
        TrackedConnection {
            id,
            tracker: self.clone(),
            snapshot,
            close_rx,
        }
    }

    /// Mark draining every connection `pred` selects, closing at
    /// `deadline` with `reason`. Returns how many were not draining yet.
    pub fn drain_where(
        &self,
        mut pred: impl FnMut(&EntryView<'_>) -> bool,
        deadline: Instant,
        reason: StreamEndReason,
    ) -> usize {
        let marked = self.with_state(|s| {
            let mut marked = 0;
            for entry in s.entries.values_mut() {
                let view = EntryView {
                    stream_id: &entry.stream_id,
                    bind_gen: entry.bind_gen,
                    backend_id: entry.backend_id.as_deref(),
                    snapshot: &entry.snapshot,
                };
                if !pred(&view) {
                    continue;
                }
                match &mut entry.drain {
                    Some(d) => {
                        if deadline < d.deadline && !d.signalled {
                            d.deadline = deadline;
                        }
                    }
                    None => {
                        entry.drain = Some(Drain {
                            deadline,
                            reason,
                            signalled: false,
                        });
                        marked += 1;
                    }
                }
            }
            marked
        });
        self.inner.drains_changed.notify_one();
        marked
    }

    /// Drain the connections of binding `bind_gen` of `stream_id`.
    pub fn drain_binding(
        &self,
        stream_id: &str,
        bind_gen: u64,
        deadline: Instant,
        reason: StreamEndReason,
    ) -> usize {
        self.drain_where(
            |e| e.stream_id == stream_id && e.bind_gen == bind_gen,
            deadline,
            reason,
        )
    }

    /// Drain every connection.
    pub fn drain_all(&self, deadline: Instant, reason: StreamEndReason) -> usize {
        self.drain_where(|_| true, deadline, reason)
    }

    /// Signal every draining connection whose deadline is at or before
    /// `now` to close with its pending reason. Returns how many were
    /// signalled.
    pub fn close_expired(&self, now: Instant) -> usize {
        self.with_state(|s| {
            let mut closed = 0;
            for entry in s.entries.values_mut() {
                if let Some(d) = &mut entry.drain {
                    if !d.signalled && d.deadline <= now {
                        d.signalled = true;
                        entry.close.send_replace(Some(d.reason));
                        closed += 1;
                    }
                }
            }
            closed
        })
    }

    /// The earliest deadline not signalled yet.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.with_state(|s| {
            s.entries
                .values()
                .filter_map(|e| e.drain.filter(|d| !d.signalled).map(|d| d.deadline))
                .min()
        })
    }

    /// Wait until a drain is set after the last wait returned. A drain
    /// set while nobody waits is remembered for the next waiter.
    pub async fn drains_changed(&self) {
        self.inner.drains_changed.notified().await;
    }

    /// Live connections and sessions.
    pub fn len(&self) -> usize {
        self.with_state(|s| s.entries.len())
    }

    /// Whether no connection or session is live, the drain watcher's
    /// test.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn set_backend(&self, id: u64, backend_id: &str) {
        self.with_state(|s| {
            if let Some(e) = s.entries.get_mut(&id) {
                e.backend_id = Some(backend_id.to_string());
            }
        });
    }

    fn deregister(&self, id: u64) {
        self.with_state(|s| s.entries.remove(&id));
    }
}

/// One tracked connection or session, held by its engine for its whole
/// life. Dropping it deregisters the entry.
#[derive(Debug)]
pub struct TrackedConnection {
    id: u64,
    tracker: ConnectionTracker,
    snapshot: Arc<Stream>,
    close_rx: watch::Receiver<Option<StreamEndReason>>,
}

impl TrackedConnection {
    /// The stream as it was when the connection was accepted. A later
    /// edit never changes it.
    pub fn snapshot(&self) -> &Arc<Stream> {
        &self.snapshot
    }

    /// Record the backend the engine chose, which a `refresh` that
    /// unlinks it drains.
    pub fn set_backend(&self, backend_id: &str) {
        self.tracker.set_backend(self.id, backend_id);
    }

    /// The reason the tracker closed this connection with, if it did.
    pub fn close_reason(&self) -> Option<StreamEndReason> {
        *self.close_rx.borrow()
    }

    /// Resolve when the tracker closes this connection, with the reason.
    /// Cancel-safe, so an engine can `select!` on it beside its I/O.
    pub async fn closed(&mut self) -> StreamEndReason {
        loop {
            if let Some(reason) = *self.close_rx.borrow_and_update() {
                return reason;
            }
            if self.close_rx.changed().await.is_err() {
                // The sender lives in the entry this guard keeps
                // registered, so it cannot go first; never resolve.
                std::future::pending::<()>().await;
            }
        }
    }

    /// End the connection: the tracker's reason if it closed it,
    /// otherwise `natural`, the way the connection ended by itself.
    pub fn finish(self, natural: StreamEndReason) -> StreamEndReason {
        self.close_reason().unwrap_or(natural)
    }
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        self.tracker.deregister(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::StreamProtocol;
    use std::time::Duration;

    fn stream(id: &str) -> Arc<Stream> {
        Arc::new(Stream {
            id: id.into(),
            name: id.into(),
            group_name: String::new(),
            protocol: StreamProtocol::Tcp,
            enabled: true,
            listen_address: "127.0.0.1".parse().unwrap(),
            port_first: 5432,
            port_last: 5432,
            node_selector: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    #[test]
    fn an_edited_snapshot_leaves_a_live_entry_untouched() {
        let tracker = ConnectionTracker::new();
        let accepted = stream("s");
        let conn = tracker.register(1, Arc::clone(&accepted));
        let mut edited = (*accepted).clone();
        edited.name = "edited".into();
        let _table_now = Arc::new(edited);
        assert!(Arc::ptr_eq(conn.snapshot(), &accepted));
        assert_eq!(conn.snapshot().name, "s");
        let mut seen = None;
        tracker.drain_where(
            |e| {
                seen = Some(Arc::as_ptr(e.snapshot));
                false
            },
            Instant::now(),
            StreamEndReason::ConfigRemoved,
        );
        assert_eq!(seen, Some(Arc::as_ptr(&accepted)));
    }

    #[tokio::test]
    async fn a_draining_entry_closes_at_its_deadline_with_config_removed() {
        let tracker = ConnectionTracker::new();
        let mut conn = tracker.register(4, stream("s"));
        let other = tracker.register(5, stream("s"));
        let now = Instant::now();
        let deadline = now + Duration::from_millis(100);
        assert_eq!(
            tracker.drain_binding("s", 4, deadline, StreamEndReason::ConfigRemoved),
            1
        );
        assert_eq!(tracker.next_deadline(), Some(deadline));
        assert_eq!(tracker.close_expired(now), 0);
        assert_eq!(conn.close_reason(), None);
        assert_eq!(tracker.close_expired(deadline), 1);
        assert_eq!(conn.closed().await, StreamEndReason::ConfigRemoved);
        assert_eq!(other.close_reason(), None);
        assert_eq!(tracker.next_deadline(), None);
        assert_eq!(
            conn.finish(StreamEndReason::ClientClose),
            StreamEndReason::ConfigRemoved
        );
        assert_eq!(tracker.len(), 1);
        drop(other);
        assert!(tracker.is_empty());
    }

    #[tokio::test]
    async fn a_quiesced_entry_closes_with_node_shutdown() {
        let tracker = ConnectionTracker::new();
        let mut conn = tracker.register(1, stream("s"));
        let now = Instant::now();
        assert_eq!(tracker.drain_all(now, StreamEndReason::NodeShutdown), 1);
        assert_eq!(tracker.close_expired(now), 1);
        assert_eq!(conn.closed().await, StreamEndReason::NodeShutdown);
    }

    #[test]
    fn an_entry_ending_before_its_deadline_keeps_its_own_reason() {
        let tracker = ConnectionTracker::new();
        let conn = tracker.register(1, stream("s"));
        let now = Instant::now();
        tracker.drain_all(
            now + Duration::from_secs(30),
            StreamEndReason::ConfigRemoved,
        );
        assert_eq!(
            conn.finish(StreamEndReason::BackendClose),
            StreamEndReason::BackendClose
        );
        assert!(tracker.is_empty());
        assert_eq!(tracker.next_deadline(), None);
    }

    #[test]
    fn a_second_drain_keeps_the_first_reason_and_the_earlier_deadline() {
        let tracker = ConnectionTracker::new();
        let conn = tracker.register(1, stream("s"));
        let now = Instant::now();
        let late = now + Duration::from_secs(30);
        let early = now + Duration::from_secs(5);
        assert_eq!(tracker.drain_all(late, StreamEndReason::ConfigRemoved), 1);
        assert_eq!(tracker.drain_all(early, StreamEndReason::NodeShutdown), 0);
        assert_eq!(tracker.next_deadline(), Some(early));
        tracker.close_expired(early);
        assert_eq!(conn.close_reason(), Some(StreamEndReason::ConfigRemoved));
    }

    #[test]
    fn drain_where_selects_by_backend() {
        let tracker = ConnectionTracker::new();
        let on_b1 = tracker.register(1, stream("s"));
        on_b1.set_backend("b1");
        let on_b2 = tracker.register(1, stream("s"));
        on_b2.set_backend("b2");
        let undecided = tracker.register(1, stream("s"));
        let now = Instant::now();
        assert_eq!(
            tracker.drain_where(
                |e| e.backend_id == Some("b1"),
                now,
                StreamEndReason::ConfigRemoved
            ),
            1
        );
        tracker.close_expired(now);
        assert_eq!(on_b1.close_reason(), Some(StreamEndReason::ConfigRemoved));
        assert_eq!(on_b2.close_reason(), None);
        assert_eq!(undecided.close_reason(), None);
    }

    #[tokio::test]
    async fn a_drain_set_while_nobody_waits_wakes_the_next_waiter() {
        let tracker = ConnectionTracker::new();
        let _conn = tracker.register(1, stream("s"));
        tracker.drain_all(Instant::now(), StreamEndReason::NodeShutdown);
        tokio::time::timeout(Duration::from_secs(1), tracker.drains_changed())
            .await
            .expect("the permit was kept");
    }
}
