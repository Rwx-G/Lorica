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

//! The node's stream observability as the plane feeds it (Story 12.9).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use lorica::stream_alerts::StreamAlerts;
use lorica_api::stream_metrics::{NodeStreamGauges, StreamMetricsCollector};
use lorica_config::models::StreamProtocol;
use lorica_stream::budget::CeilingBound;
use lorica_stream::StreamTable;

use super::caps::{lock_caps, SharedCaps};

/// What the stream plane feeds the node's stream observability (Story
/// 12.9), from the one process that sees the whole node:
///
/// - every table it loads goes to the metrics collector (series of a
///   removed stream, link or backend pruned, `lorica_stream_info`
///   rendered), to the stream alerts, and drops the SLA breach series of
///   a stream that left;
/// - every caps tick reads the regions for the node-exact gauges (UDP
///   sessions, pending connections) and checks each UDP stream's ceiling
///   against the node's count of ceiling edges, `ceiling_total`.
pub(crate) struct PlaneWatch {
    alerts: Arc<StreamAlerts>,
    metrics: StreamMetricsCollector,
    ceiling_total: Box<dyn Fn(&str) -> u64 + Send + Sync>,
    table: StdMutex<Arc<StreamTable>>,
    known: StdMutex<BTreeSet<String>>,
}

impl PlaneWatch {
    /// A watch publishing to `metrics` and `alerts`, reading a stream's
    /// count of ceiling edges on the node with `ceiling_total`.
    pub(crate) fn new(
        alerts: Arc<StreamAlerts>,
        metrics: StreamMetricsCollector,
        ceiling_total: impl Fn(&str) -> u64 + Send + Sync + 'static,
    ) -> Self {
        PlaneWatch {
            alerts,
            metrics,
            ceiling_total: Box::new(ceiling_total),
            table: StdMutex::new(Arc::new(StreamTable::default())),
            known: StdMutex::new(BTreeSet::new()),
        }
    }

    pub(super) fn table_changed(&self, table: StreamTable, bound: Option<CeilingBound>) {
        let ids: BTreeSet<String> = table.streams().map(|s| s.id.clone()).collect();
        {
            let mut known = self.known.lock().unwrap_or_else(PoisonError::into_inner);
            for gone in known.difference(&ids) {
                lorica_bench::metrics::forget_stream_sla_breaches(gone);
            }
            lorica_api::metrics::retain_hot_upgrade_stream_connections(|id| ids.contains(id));
            *known = ids;
        }
        self.metrics.retain(&table);
        let table = Arc::new(table);
        self.alerts.table_changed(Arc::clone(&table), bound);
        *self.table.lock().unwrap_or_else(PoisonError::into_inner) = table;
    }

    pub(super) fn tick(&self, caps: &SharedCaps) {
        let table = Arc::clone(&self.table.lock().unwrap_or_else(PoisonError::into_inner));
        let read: Vec<(String, StreamProtocol, u64, u64)> = {
            let caps = lock_caps(caps);
            table
                .streams()
                .filter(|s| caps.holds(&s.id))
                .map(|s| {
                    (
                        s.id.clone(),
                        s.protocol,
                        caps.sessions(&s.id),
                        caps.pending(&s.id),
                    )
                })
                .collect()
        };
        let mut gauges = Vec::with_capacity(read.len());
        for (id, protocol, sessions, pending) in read {
            match protocol {
                StreamProtocol::Udp => {
                    self.alerts
                        .ceiling(&id, (self.ceiling_total)(&id), sessions);
                    gauges.push((id, NodeStreamGauges::udp(sessions, pending)));
                }
                StreamProtocol::Tcp => gauges.push((id, NodeStreamGauges::tcp(pending))),
            }
        }
        self.metrics.set_node_gauges(gauges);
    }
}
