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

//! The two stream notifications a node raises itself (Story 12.9 D-h),
//! where the evidence of the whole node is: the supervisor in worker
//! mode, the process in single-process mode, never a worker.
//!
//! - `stream_backend_down`: a stream's breaker opened for a backend
//!   (Closed to Open; a HalfOpen re-trip is the same incident), at most
//!   once per (stream, backend) per [`STREAM_BACKEND_ALERT_HOLD`], so a
//!   flapping backend cannot become an alert storm.
//! - `stream_udp_ceiling_reached`: the node's count of a UDP stream's
//!   ceiling edges grew while the stream was not at its ceiling. Each
//!   process sees its own edge, so the count is the aggregate of every
//!   process's; the state re-arms when the node's own read of the
//!   stream's sessions falls below [`CEILING_REARM_PERCENT`] of
//!   `udp.max_sessions`.
//!
//! Names and limits are read from the last table the stream plane
//! loaded ([`StreamAlerts::table_changed`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lorica_notify::events::AlertType;
use lorica_notify::{AlertEvent, AlertSender};
use lorica_stream::budget::CeilingBound;
use lorica_stream::counters::CEILING_REARM_PERCENT;
use lorica_stream::StreamTable;
use parking_lot::Mutex;

/// The least time between two `stream_backend_down` alerts of one
/// (stream, backend).
pub const STREAM_BACKEND_ALERT_HOLD: Duration = Duration::from_secs(300);

/// One stream's ceiling state, as the node sees it.
#[derive(Debug, Default, Clone, Copy)]
struct CeilingState {
    /// The node's count of ceiling edges at the last check.
    seen: u64,
    /// Whether the stream is at its ceiling: an alert was raised and the
    /// sessions have not fallen below the re-arm share since.
    reached: bool,
}

/// The node's stream alerts. See the module doc.
pub struct StreamAlerts {
    sender: AlertSender,
    node: String,
    breaker_threshold: u32,
    table: Mutex<Arc<StreamTable>>,
    ceiling_bound: Mutex<Option<CeilingBound>>,
    /// The last `stream_backend_down` per (stream id, backend address).
    backend_alerts: Mutex<HashMap<(String, String), Instant>>,
    ceilings: Mutex<HashMap<String, CeilingState>>,
}

impl std::fmt::Debug for StreamAlerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamAlerts")
            .field("node", &self.node)
            .field("breaker_threshold", &self.breaker_threshold)
            .finish_non_exhaustive()
    }
}

impl StreamAlerts {
    /// Alerts sent through `sender`, naming the node `node`; the breaker
    /// opens after `breaker_threshold` consecutive failures, which the
    /// backend alert reports.
    pub fn new(sender: AlertSender, node: impl Into<String>, breaker_threshold: u32) -> Self {
        StreamAlerts {
            sender,
            node: node.into(),
            breaker_threshold,
            table: Mutex::new(Arc::new(StreamTable::default())),
            ceiling_bound: Mutex::new(None),
            backend_alerts: Mutex::new(HashMap::new()),
            ceilings: Mutex::new(HashMap::new()),
        }
    }

    /// The stream plane loaded `table`; `ceiling_bound` is the limit
    /// that bound the node's UDP session ceiling when it did. The state
    /// of a stream the table no longer holds goes with it.
    pub fn table_changed(&self, table: Arc<StreamTable>, ceiling_bound: Option<CeilingBound>) {
        self.backend_alerts
            .lock()
            .retain(|(stream_id, _), _| table.stream(stream_id).is_some());
        self.ceilings
            .lock()
            .retain(|stream_id, _| table.stream(stream_id).is_some());
        *self.ceiling_bound.lock() = ceiling_bound;
        *self.table.lock() = table;
    }

    /// The breaker of `stream_id` opened for the backend at
    /// `backend_address` (Closed to Open): raise `stream_backend_down`
    /// unless one was raised for the pair within the hold.
    pub fn breaker_opened(&self, stream_id: &str, backend_address: &str) {
        if let Some(alert) = self.breaker_opened_at(stream_id, backend_address, Instant::now()) {
            self.sender.send(alert);
        }
    }

    fn breaker_opened_at(
        &self,
        stream_id: &str,
        backend_address: &str,
        now: Instant,
    ) -> Option<AlertEvent> {
        {
            let mut last = self.backend_alerts.lock();
            let key = (stream_id.to_string(), backend_address.to_string());
            if last
                .get(&key)
                .is_some_and(|at| now.saturating_duration_since(*at) < STREAM_BACKEND_ALERT_HOLD)
            {
                return None;
            }
            last.insert(key, now);
        }
        let table = Arc::clone(&self.table.lock());
        let stream_name = table
            .stream(stream_id)
            .map(|s| s.name.clone())
            .unwrap_or_default();
        let backend = table
            .linked_backends(stream_id)
            .iter()
            .map(|linked| &linked.backend)
            .find(|b| b.address == backend_address);
        let shown = if stream_name.is_empty() {
            stream_id
        } else {
            &stream_name
        };
        // Named as the dashboard lists the backend, as `backend_down` is.
        let backend_shown = match backend.map(|b| b.name.as_str()) {
            Some(name) if !name.is_empty() => format!("{name} ({backend_address})"),
            _ => backend_address.to_string(),
        };
        Some(
            AlertEvent::new(
                AlertType::StreamBackendDown,
                format!(
                    "stream `{shown}`: backend {backend_shown} is down on {}, its circuit breaker opened",
                    self.node
                ),
            )
            .with_detail("stream_id", stream_id)
            .with_detail("stream_name", stream_name.as_str())
            .with_detail(
                "backend_id",
                backend.map(|b| b.id.clone()).unwrap_or_default(),
            )
            .with_detail(
                "backend_name",
                backend.map(|b| b.name.clone()).unwrap_or_default(),
            )
            .with_detail("address", backend_address)
            .with_detail("node", self.node.as_str())
            .with_detail("threshold", self.breaker_threshold.to_string()),
        )
    }

    /// The node counts `reached_total` ceiling edges for `stream_id` and
    /// holds `node_sessions` of its sessions: raise
    /// `stream_udp_ceiling_reached` when the count grew while the stream
    /// was not at its ceiling.
    pub fn ceiling(&self, stream_id: &str, reached_total: u64, node_sessions: u64) {
        if let Some(alert) = self.ceiling_check(stream_id, reached_total, node_sessions) {
            self.sender.send(alert);
        }
    }

    fn ceiling_check(
        &self,
        stream_id: &str,
        reached_total: u64,
        node_sessions: u64,
    ) -> Option<AlertEvent> {
        let table = Arc::clone(&self.table.lock());
        let stream = table.stream(stream_id)?;
        let max_sessions = u64::from(stream.udp.as_ref()?.max_sessions);
        let raise = {
            let mut ceilings = self.ceilings.lock();
            let state = ceilings.entry(stream_id.to_string()).or_default();
            if state.reached
                && node_sessions.saturating_mul(100)
                    < max_sessions.saturating_mul(CEILING_REARM_PERCENT)
            {
                state.reached = false;
            }
            let raise = reached_total > state.seen && !state.reached;
            if raise {
                state.reached = true;
            }
            state.seen = reached_total;
            raise
        };
        if !raise {
            return None;
        }
        let bound = (*self.ceiling_bound.lock())
            .and_then(|bound| serde_json::to_value(bound).ok())
            .and_then(|word| word.as_str().map(str::to_string))
            .unwrap_or_default();
        Some(
            AlertEvent::new(
                AlertType::StreamUdpCeilingReached,
                format!(
                    "UDP stream `{}` reached its {max_sessions} sessions on {}",
                    stream.name, self.node
                ),
            )
            .with_detail("stream_id", stream_id)
            .with_detail("stream_name", stream.name.as_str())
            .with_detail("node", self.node.as_str())
            .with_detail("max_sessions", max_sessions.to_string())
            .with_detail("ceiling_bound_by", bound),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::{Stream, StreamProtocol, UdpSettings};

    const ADDRESS: &str = "192.0.2.10:53";

    fn alerts() -> StreamAlerts {
        StreamAlerts::new(AlertSender::new(16), "node01", 5)
    }

    fn udp_stream(id: &str, max_sessions: u32) -> Stream {
        let mut stream = Stream::new(
            id.into(),
            format!("{id}-name"),
            StreamProtocol::Udp,
            "127.0.0.1".parse().expect("an address"),
            5353,
            5353,
            Utc::now(),
        );
        stream.udp = Some(UdpSettings {
            max_sessions,
            ..UdpSettings::default()
        });
        stream
    }

    fn with_table(alerts: &StreamAlerts, streams: Vec<Stream>) {
        alerts.table_changed(
            Arc::new(StreamTable::new(streams, &[])),
            Some(CeilingBound::FdBudget),
        );
    }

    #[test]
    fn a_backend_alert_names_the_backend_by_its_label() {
        let alerts = alerts();
        let backend: lorica_config::models::Backend = serde_json::from_value(serde_json::json!({
            "id": "b1",
            "address": ADDRESS,
            "name": "dns-1",
            "weight": 100,
            "health_status": "healthy",
            "health_check_enabled": false,
            "health_check_interval_s": 10,
            "lifecycle_state": "normal",
            "active_connections": 0,
            "tls_upstream": false,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a backend");
        alerts.table_changed(
            Arc::new(StreamTable::with_backends(
                vec![udp_stream("s1", 100)],
                &[lorica_config::models::StreamBackend::primary("s1", "b1")],
                vec![backend],
            )),
            Some(CeilingBound::FdBudget),
        );
        let alert = alerts
            .breaker_opened_at("s1", ADDRESS, Instant::now())
            .expect("the first incident alerts");
        assert_eq!(
            alert.summary,
            format!(
                "stream `s1-name`: backend dns-1 ({ADDRESS}) is down on node01, \
                 its circuit breaker opened"
            )
        );
        // An address no linked backend holds is named by the address.
        let unknown = alerts
            .breaker_opened_at("s1", "192.0.2.11:53", Instant::now())
            .expect("another pair alerts");
        assert!(unknown.summary.contains("backend 192.0.2.11:53 is down"));
    }

    #[test]
    fn a_backend_alert_is_raised_once_per_hold_and_again_after_it() {
        let alerts = alerts();
        with_table(&alerts, vec![udp_stream("s1", 100)]);
        let start = Instant::now();
        let first = alerts
            .breaker_opened_at("s1", ADDRESS, start)
            .expect("the first incident alerts");
        assert_eq!(first.alert_type, AlertType::StreamBackendDown);
        assert_eq!(first.details["stream_name"], "s1-name");
        assert_eq!(first.details["address"], ADDRESS);
        assert_eq!(first.details["node"], "node01");
        assert_eq!(first.details["threshold"], "5");

        // The circuit closed and opened again: a new incident, held.
        assert!(alerts
            .breaker_opened_at("s1", ADDRESS, start + Duration::from_secs(60))
            .is_none());
        // Another backend of the stream is its own pair.
        assert!(alerts
            .breaker_opened_at("s1", "192.0.2.11:53", start + Duration::from_secs(60))
            .is_some());
        assert!(alerts
            .breaker_opened_at("s1", ADDRESS, start + STREAM_BACKEND_ALERT_HOLD)
            .is_some());
    }

    #[test]
    fn a_removed_stream_forgets_its_hold() {
        let alerts = alerts();
        with_table(&alerts, vec![udp_stream("s1", 100)]);
        let start = Instant::now();
        assert!(alerts.breaker_opened_at("s1", ADDRESS, start).is_some());
        with_table(&alerts, Vec::new());
        with_table(&alerts, vec![udp_stream("s1", 100)]);
        assert!(alerts.breaker_opened_at("s1", ADDRESS, start).is_some());
    }

    #[test]
    fn two_workers_edges_raise_one_ceiling_alert_until_the_sessions_fall() {
        let alerts = alerts();
        with_table(&alerts, vec![udp_stream("s1", 100)]);
        // Nothing reached yet.
        assert!(alerts.ceiling_check("s1", 0, 40).is_none());
        // Worker 1's edge, then worker 2's: one incident on the node.
        let alert = alerts
            .ceiling_check("s1", 1, 100)
            .expect("the first edge alerts");
        assert_eq!(alert.alert_type, AlertType::StreamUdpCeilingReached);
        assert_eq!(alert.details["max_sessions"], "100");
        assert_eq!(alert.details["ceiling_bound_by"], "fd_budget");
        assert!(alerts.ceiling_check("s1", 2, 100).is_none());
        // Still at 90 % of the cap: not re-armed.
        assert!(alerts.ceiling_check("s1", 2, 90).is_none());
        // Below it: re-armed, but nothing new reached.
        assert!(alerts.ceiling_check("s1", 2, 89).is_none());
        assert!(alerts.ceiling_check("s1", 3, 100).is_some());
    }

    #[test]
    fn a_stream_without_udp_settings_raises_no_ceiling_alert() {
        let alerts = alerts();
        let mut tcp = udp_stream("t1", 10);
        tcp.protocol = StreamProtocol::Tcp;
        tcp.udp = None;
        with_table(&alerts, vec![tcp]);
        assert!(alerts.ceiling_check("t1", 5, 10).is_none());
        assert!(alerts.ceiling_check("unknown", 5, 10).is_none());
    }
}
