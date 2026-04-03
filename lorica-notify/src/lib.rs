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

//! Notification channels for Lorica alert events.
//!
//! Supports stdout (always on), SMTP email, and HTTP webhook delivery.

pub mod channels;
pub mod events;

pub use channels::{NotifyDispatcher, NotifyError, RateLimitConfig};
pub use events::AlertEvent;

/// Non-blocking alert sender for the proxy hot path.
///
/// Wraps a `tokio::sync::broadcast::Sender<AlertEvent>` so the proxy can
/// emit alert events (waf_alert, ip_banned, backend_down, etc.) without
/// blocking. A background task subscribes and dispatches via NotifyDispatcher.
#[derive(Clone)]
pub struct AlertSender {
    tx: tokio::sync::broadcast::Sender<AlertEvent>,
}

impl AlertSender {
    /// Create a new alert sender with a bounded broadcast channel.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        Self { tx }
    }

    /// Send an alert event (fire-and-forget, never blocks).
    pub fn send(&self, event: AlertEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to the alert channel (for the background dispatcher).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<AlertEvent> {
        self.tx.subscribe()
    }
}

/// Spawn a background task that reads from the AlertSender channel and
/// dispatches events via the NotifyDispatcher.
pub fn spawn_alert_dispatcher(
    alert_sender: &AlertSender,
    dispatcher: std::sync::Arc<tokio::sync::Mutex<NotifyDispatcher>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = alert_sender.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let d = dispatcher.lock().await;
                    d.dispatch(&event).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "alert dispatcher lagged, some notifications were dropped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}
