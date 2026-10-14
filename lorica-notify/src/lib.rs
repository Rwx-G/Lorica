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

#![deny(unsafe_code)]

//! Notification channels for Lorica alert events.
//!
//! Supports stdout (always on), SMTP email, Slack/Discord webhooks, and
//! generic HTTP webhook delivery. Producers emit [`AlertEvent`] values
//! through an [`AlertSender`] (a non-blocking broadcast channel); a
//! background task spawned via [`spawn_alert_dispatcher`] drains the
//! channel and fans events out through a [`NotifyDispatcher`].

pub mod channels;
pub mod coalesce;
pub mod events;
pub mod metrics;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use channels::{DispatchOutcome, NotifyDispatcher, NotifyError, RateLimitConfig};
pub use events::AlertEvent;

use events::AlertType;

/// How often a dispatcher task asks its [`AlertSender`] for the
/// coalesced summaries that are due: a fraction of the coalescing
/// window, so a summary is never late by more than that fraction.
pub const COALESCE_FLUSH_INTERVAL: Duration =
    Duration::from_secs(coalesce::WAF_ALERT_WINDOW.as_secs() / 4);

/// What the dispatcher reported for the last event of one alert type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// When the dispatch finished.
    pub at: Instant,
    /// What it achieved.
    pub outcome: DispatchOutcome,
}

/// The state an [`AlertSender`] shares with the task that dispatches
/// its events: the `waf_alert` coalescer (see [`coalesce`]) and the
/// delivery ledger. Holding it does not keep the broadcast open, so a
/// dispatcher task still ends when the last sender is dropped.
#[derive(Clone, Default)]
pub struct AlertLedger {
    coalescer: Arc<parking_lot::Mutex<coalesce::WafAlertCoalescer>>,
    deliveries: Arc<parking_lot::Mutex<HashMap<&'static str, DeliveryRecord>>>,
}

impl AlertLedger {
    /// The coalesced summaries that are due, to dispatch directly.
    /// Called by the dispatcher task every [`COALESCE_FLUSH_INTERVAL`].
    pub fn due_summaries(&self) -> Vec<AlertEvent> {
        self.coalescer.lock().flush(Instant::now())
    }

    /// Record what the dispatch of an event of `alert_type` achieved.
    pub fn record_delivery(&self, alert_type: &AlertType, outcome: DispatchOutcome) {
        self.deliveries.lock().insert(
            alert_type.as_str(),
            DeliveryRecord {
                at: Instant::now(),
                outcome,
            },
        );
    }

    /// The last dispatch of an event of `alert_type`, if any reached the
    /// dispatcher. An event dropped on the way (the broadcast lagged)
    /// leaves no record, which a caller reads as "not delivered".
    pub fn last_delivery(&self, alert_type: &AlertType) -> Option<DeliveryRecord> {
        self.deliveries.lock().get(alert_type.as_str()).copied()
    }
}

/// Non-blocking alert sender for the proxy hot path.
///
/// Wraps a `tokio::sync::broadcast::Sender<AlertEvent>` so the proxy can
/// emit alert events (waf_alert, ip_banned, backend_down, etc.) without
/// blocking. A background task subscribes and dispatches via NotifyDispatcher.
///
/// Clones share one [`AlertLedger`], which the dispatcher task fills so
/// a producer that must not lose its alert can tell whether it reached
/// anyone.
#[derive(Clone)]
pub struct AlertSender {
    tx: tokio::sync::broadcast::Sender<AlertEvent>,
    ledger: AlertLedger,
}

impl AlertSender {
    /// Create a new alert sender backed by a bounded broadcast channel.
    ///
    /// `capacity` is the per-receiver buffer size. Slow subscribers that
    /// fall behind will observe `RecvError::Lagged` and skip events rather
    /// than block producers.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            tx,
            ledger: AlertLedger::default(),
        }
    }

    /// Send an alert event, fire-and-forget.
    ///
    /// Never blocks and never returns an error: if no receivers are
    /// subscribed (or the channel is closed), the event is silently dropped.
    /// A `waf_alert` goes through the coalescer first and may be folded
    /// into a later summary instead (see [`coalesce`]).
    pub fn send(&self, event: AlertEvent) {
        let admitted = self.ledger.coalescer.lock().admit(event, Instant::now());
        if let Some(event) = admitted {
            let _ = self.tx.send(event);
        }
    }

    /// The state shared with the dispatcher task.
    pub fn ledger(&self) -> &AlertLedger {
        &self.ledger
    }

    /// Subscribe a new receiver to the alert channel.
    ///
    /// Each subscriber gets its own bounded buffer of size `capacity`
    /// (see [`AlertSender::new`]).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AlertEvent> {
        self.tx.subscribe()
    }
}

/// Spawn a background task that drains an [`AlertSender`] and dispatches
/// each event through the shared [`NotifyDispatcher`], recording each
/// outcome on the sender and flushing its coalesced summaries.
///
/// The task exits when the broadcast channel is closed. `Lagged` errors are
/// logged at warn level and the dropped count is reported, but the task
/// keeps running.
pub fn spawn_alert_dispatcher(
    alert_sender: &AlertSender,
    dispatcher: Arc<tokio::sync::Mutex<NotifyDispatcher>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = alert_sender.subscribe();
    let ledger = alert_sender.ledger().clone();
    tokio::spawn(async move {
        let mut flush = tokio::time::interval(COALESCE_FLUSH_INTERVAL);
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let events = tokio::select! {
                received = rx.recv() => match received {
                    Ok(event) => vec![event],
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            dropped = n,
                            "alert dispatcher lagged, some notifications were dropped"
                        );
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = flush.tick() => ledger.due_summaries(),
            };
            if events.is_empty() {
                continue;
            }
            let d = dispatcher.lock().await;
            for event in &events {
                let outcome = d.dispatch(event).await;
                ledger.record_delivery(&event.alert_type, outcome);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AlertEvent, AlertType};

    #[test]
    fn send_without_subscriber_is_dropped() {
        // Fire-and-forget: sending with no receivers must never panic.
        let sender = AlertSender::new(4);
        sender.send(AlertEvent::new(AlertType::WafAlert, "no subscriber"));
    }

    #[tokio::test]
    async fn subscribe_then_receives_event() {
        let sender = AlertSender::new(8);
        let mut rx = sender.subscribe();
        sender.send(AlertEvent::new(AlertType::IpBanned, "1.2.3.4 banned"));
        let got = rx.recv().await.expect("event should be delivered");
        assert_eq!(got.alert_type.as_str(), "ip_banned");
        assert_eq!(got.summary, "1.2.3.4 banned");
    }

    #[tokio::test]
    async fn dispatcher_task_drains_then_exits_on_channel_close() {
        // spawn_alert_dispatcher drains queued events through an (empty)
        // dispatcher and exits cleanly once the sender is dropped and the
        // broadcast channel closes.
        let sender = AlertSender::new(8);
        let dispatcher = std::sync::Arc::new(tokio::sync::Mutex::new(NotifyDispatcher::new()));
        let handle = spawn_alert_dispatcher(&sender, dispatcher);

        sender.send(AlertEvent::new(AlertType::BackendDown, "b-1 down"));
        drop(sender);

        handle
            .await
            .expect("dispatcher task must exit cleanly when the channel closes");
    }

    #[tokio::test]
    async fn a_waf_flood_reaches_the_broadcast_once() {
        let sender = AlertSender::new(8);
        let mut rx = sender.subscribe();
        for _ in 0..1_000 {
            sender.send(
                AlertEvent::new(AlertType::WafAlert, "xss")
                    .with_detail("category", "xss")
                    .with_detail("client_ip", "192.0.2.10"),
            );
        }
        sender.send(AlertEvent::new(AlertType::LogStoreUnavailable, "down"));
        assert_eq!(
            rx.recv().await.expect("first").alert_type,
            AlertType::WafAlert
        );
        assert_eq!(
            rx.recv().await.expect("second").alert_type,
            AlertType::LogStoreUnavailable,
            "the flood did not crowd the broadcast"
        );
    }

    #[tokio::test]
    async fn the_dispatcher_task_records_each_outcome_on_the_ledger() {
        let sender = AlertSender::new(8);
        let dispatcher = std::sync::Arc::new(tokio::sync::Mutex::new(NotifyDispatcher::new()));
        let _task = spawn_alert_dispatcher(&sender, dispatcher);
        assert!(sender
            .ledger()
            .last_delivery(&AlertType::LogStoreUnavailable)
            .is_none());

        sender.send(AlertEvent::new(AlertType::LogStoreUnavailable, "down"));
        let record = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(record) = sender
                    .ledger()
                    .last_delivery(&AlertType::LogStoreUnavailable)
                {
                    return record;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the dispatch is recorded");
        assert_eq!(
            record.outcome,
            DispatchOutcome {
                subscribed: 0,
                delivered: 0
            }
        );
        assert!(record.outcome.settled(), "nobody to reach is settled");
    }
}
