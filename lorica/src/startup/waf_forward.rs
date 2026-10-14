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

//! The two ends of the worker-to-supervisor WAF event stream (`waf.sock`).
//!
//! A worker drains its engine's forwarding outbox and writes one JSON
//! line per event, plus one line per source whose events the outbox had
//! to drop. The supervisor reads the lines, records them in its own
//! engine and acts on them (WAF alert, global auto-ban check). The
//! worker has no notification sender of its own, so a source that never
//! crosses this stream raises no alert and triggers no auto-ban check.
//!
//! Residual loss: a drop is reported per source only up to
//! [`lorica_waf::LOST_SOURCES_CAPACITY`] sources between two reads. A
//! burst spread over more sources than that within one
//! [`FORWARD_INTERVAL`] leaves the excess counted in the worker's WARN
//! line only: no alert and no auto-ban check for those sources until one
//! of their later events is forwarded.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_waf::{LostEvents, RuleCategory, WafEngine, WafEvent};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// How often a worker drains its new WAF events to the supervisor.
///
/// The outbox holds [`lorica_waf::FORWARD_OUTBOX_CAPACITY`] events
/// between two drains, so nothing is dropped while fewer than that many
/// arrive per interval. Past that, the drop is counted per source and
/// forwarded as such, see [`WafForwardCursor::take_batch`].
pub(crate) const FORWARD_INTERVAL: Duration = Duration::from_millis(100);

/// One line of the stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum ForwardedLine {
    /// One event, as the worker recorded it.
    Event(WafEvent),
    /// Events of one source the worker dropped before forwarding them.
    Lost {
        /// Who and how many.
        lost: LostEvents,
    },
}

/// What one drain yields.
#[derive(Debug, Default)]
pub(crate) struct ForwardBatch {
    pub(crate) events: Vec<WafEvent>,
    pub(crate) lost: Vec<LostEvents>,
}

impl ForwardBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty() && self.lost.is_empty()
    }

    /// The batch as stream lines, newline included, events first.
    pub(crate) fn into_lines(self) -> impl Iterator<Item = String> {
        self.events
            .into_iter()
            .map(ForwardedLine::Event)
            .chain(
                self.lost
                    .into_iter()
                    .map(|lost| ForwardedLine::Lost { lost }),
            )
            .filter_map(|line| serde_json::to_string(&line).ok().map(|json| json + "\n"))
    }
}

/// A worker's position in its engine's event numbering.
#[derive(Debug, Default)]
pub(crate) struct WafForwardCursor {
    next: u64,
    lost: u64,
}

impl WafForwardCursor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The events `engine` recorded since the last call, oldest first,
    /// and the sources of those its outbox dropped. `engine` must have
    /// forwarding enabled.
    ///
    /// Dropped events are logged at WARN with the running total. Their
    /// sources still reach the supervisor, which alerts on them and
    /// checks them against the auto-ban threshold.
    pub(crate) fn take_batch(&mut self, engine: &WafEngine) -> ForwardBatch {
        let after = engine.events_after(self.next);
        self.next = after.next;
        if after.lost > 0 {
            self.lost += after.lost;
            warn!(
                lost = after.lost,
                lost_total = self.lost,
                sources = after.lost_by_source.len(),
                "worker: WAF events dropped from the forwarding outbox; their sources are \
                 forwarded with a count"
            );
        }
        ForwardBatch {
            events: after.events,
            lost: after.lost_by_source,
        }
    }

    /// Events dropped before they could be forwarded, since the cursor
    /// was created.
    #[cfg(test)]
    fn lost(&self) -> u64 {
        self.lost
    }
}

/// The global WAF auto-ban settings, as the supervisor applies them to
/// each forwarded event. Cached so the per-event path reads no store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WafBanPolicy {
    /// Violations from one address that trigger a ban; 0 disables.
    pub(crate) threshold: u64,
    /// How long the ban lasts.
    pub(crate) duration_s: u64,
}

impl WafBanPolicy {
    /// The policy `settings` describe.
    pub(crate) fn from_settings(settings: &lorica_config::models::GlobalSettings) -> Self {
        // A negative value is not a policy anyone meant; read it as off.
        Self {
            threshold: u64::try_from(settings.waf_ban_threshold).unwrap_or(0),
            duration_s: u64::try_from(settings.waf_ban_duration_s).unwrap_or(0),
        }
    }

    /// The policy in `store`, or no auto-ban when the settings cannot be
    /// read, which is what a per-event read used to fall back to.
    pub(crate) fn load(store: &lorica_config::ConfigStore) -> Self {
        match store.get_global_settings() {
            Ok(settings) => Self::from_settings(&settings),
            Err(e) => {
                warn!(error = %e, "WAF auto-ban settings unreadable; auto-ban off until the next reload");
                Self {
                    threshold: 0,
                    duration_s: 0,
                }
            }
        }
    }
}

/// The supervisor end of the stream: what it does with each line.
pub(crate) struct SupervisorWafIngest {
    pub(crate) engine: Arc<WafEngine>,
    pub(crate) alerts: lorica_notify::AlertSender,
    pub(crate) ban_tx: tokio::sync::broadcast::Sender<(String, u64, i32)>,
    pub(crate) policy: Arc<ArcSwap<WafBanPolicy>>,
    pub(crate) shmem: &'static lorica_shmem::SharedRegion,
}

impl SupervisorWafIngest {
    /// Act on one line a worker forwarded. A line that is neither shape
    /// is ignored.
    ///
    /// No store and no lock beyond the engine's: the line rate is the
    /// attack rate.
    pub(crate) fn handle_line(&self, line: &str) {
        match serde_json::from_str::<ForwardedLine>(line) {
            Ok(ForwardedLine::Event(event)) => self.handle_event(event),
            Ok(ForwardedLine::Lost { lost }) => self.handle_lost(lost),
            Err(_) => {}
        }
    }

    fn handle_event(&self, event: WafEvent) {
        // Workers insert WAF events into the DB directly (with
        // route_hostname and action stamped), so the supervisor only
        // records them in memory.
        if alerts_on(&event.category) {
            self.alerts.send(
                AlertEvent::new(
                    AlertType::WafAlert,
                    format!(
                        "WAF {}: {} (rule {})",
                        event.category.as_str(),
                        event.description,
                        event.rule_id
                    ),
                )
                .with_detail("rule_id", event.rule_id.to_string())
                .with_detail("category", event.category.as_str())
                .with_detail("severity", event.severity.to_string())
                .with_detail("client_ip", event.client_ip.clone()),
            );
        }
        self.check_auto_ban(&event.client_ip);
        self.engine.record_events(vec![event]);
    }

    fn handle_lost(&self, lost: LostEvents) {
        self.engine.record_lost_events(&lost.category, lost.count);
        if alerts_on(&lost.category) {
            self.alerts.send(
                AlertEvent::new(
                    AlertType::WafAlert,
                    format!(
                        "WAF {}: {} events from {} a worker dropped before forwarding",
                        lost.category.as_str(),
                        lost.count,
                        lost.client_ip
                    ),
                )
                .with_detail("category", lost.category.as_str())
                .with_detail("client_ip", lost.client_ip.clone())
                .with_detail(
                    lorica_notify::coalesce::EVENTS_DETAIL,
                    lost.count.to_string(),
                ),
            );
        }
        self.check_auto_ban(&lost.client_ip);
    }

    /// Global WAF auto-ban: compare the cross-worker shmem counter the
    /// workers bump in their hot path against the threshold and, on the
    /// first crossing, broadcast BanIp and reset the slot so the next
    /// round starts at zero.
    ///
    /// Two lines for the same address can race: both read the counter
    /// at or above the threshold before either resets it, and both
    /// broadcast. The duplicate is idempotent (same address, same
    /// duration) and costs one extra `ip_banned` alert.
    fn check_auto_ban(&self, client_ip: &str) {
        if client_ip.is_empty() || client_ip == "-" {
            return;
        }
        let policy = **self.policy.load();
        if policy.threshold == 0 {
            return;
        }
        let tagged = self
            .shmem
            .tagged(lorica::proxy_wiring::ip_to_shmem_key(client_ip));
        let count = self.shmem.waf_auto_ban.read(tagged).unwrap_or(0);
        if count < policy.threshold {
            return;
        }
        // A failed reset means another line raced this one and banned.
        let _ = self.shmem.waf_auto_ban.reset(tagged);
        warn!(
            ip = %client_ip,
            violations = %count,
            ban_duration_s = %policy.duration_s,
            "global WAF auto-ban: IP banned for repeated violations"
        );
        let _ = self.ban_tx.send((
            client_ip.to_string(),
            policy.duration_s,
            lorica_api::ban::BanReason::WafCriticalRule.as_i32(),
        ));
        self.alerts.send(
            AlertEvent::new(
                AlertType::IpBanned,
                format!("IP {client_ip} auto-banned for repeated WAF violations"),
            )
            .with_detail("ip", client_ip)
            .with_detail("violations", count.to_string())
            .with_detail("ban_duration_s", policy.duration_s.to_string()),
        );
    }
}

/// Whether events of `category` raise a `waf_alert`. Blocklist hits do
/// not: the address is already refused by a list the operator chose,
/// and single-process mode never alerted on them either.
fn alerts_on(category: &RuleCategory) -> bool {
    *category != RuleCategory::IpBlocklist
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn event(rule_id: u32) -> WafEvent {
        WafEvent {
            rule_id,
            description: "test".into(),
            category: RuleCategory::Xss,
            severity: 3,
            matched_field: "uri".into(),
            matched_value: "x".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: "192.0.2.10".into(),
            route_hostname: "example.com".into(),
            action: "blocked".into(),
        }
    }

    fn forwarding_engine() -> WafEngine {
        let engine = WafEngine::new();
        engine.enable_forwarding();
        engine
    }

    struct Harness {
        ingest: SupervisorWafIngest,
        alerts: tokio::sync::broadcast::Receiver<AlertEvent>,
        bans: tokio::sync::broadcast::Receiver<(String, u64, i32)>,
    }

    fn harness(policy: WafBanPolicy) -> Harness {
        let (shmem, fd) =
            lorica_shmem::SharedRegion::create_supervisor().expect("test setup: shmem region");
        // The mapping is 'static and outlives the fd.
        drop(fd);
        let alerts = lorica_notify::AlertSender::new(1024);
        let alert_rx = alerts.subscribe();
        let (ban_tx, ban_rx) = tokio::sync::broadcast::channel(16);
        Harness {
            ingest: SupervisorWafIngest {
                engine: Arc::new(WafEngine::new()),
                alerts,
                ban_tx,
                policy: Arc::new(ArcSwap::from_pointee(policy)),
                shmem,
            },
            alerts: alert_rx,
            bans: ban_rx,
        }
    }

    fn violations(ingest: &SupervisorWafIngest, ip: &str, count: u64) {
        let tagged = ingest
            .shmem
            .tagged(lorica::proxy_wiring::ip_to_shmem_key(ip));
        ingest
            .shmem
            .waf_auto_ban
            .increment(tagged, count, lorica_shmem::now_ns());
    }

    fn drain<T: Clone>(rx: &mut tokio::sync::broadcast::Receiver<T>) -> Vec<T> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    fn line(forwarded: &ForwardedLine) -> String {
        serde_json::to_string(forwarded).expect("a line encodes") + "\n"
    }

    const NO_BAN: WafBanPolicy = WafBanPolicy {
        threshold: 0,
        duration_s: 0,
    };

    #[test]
    fn an_event_recorded_past_the_ring_and_outbox_capacity_is_still_forwarded() {
        let engine = forwarding_engine();
        let mut cursor = WafForwardCursor::new();
        let mut forwarded = Vec::new();
        let total = lorica_waf::FORWARD_OUTBOX_CAPACITY as u32 + 1;
        for rule_id in 1..=total {
            engine.record_events(vec![event(rule_id)]);
            forwarded.extend(cursor.take_batch(&engine).events);
        }
        assert_eq!(forwarded.len() as u32, total);
        assert_eq!(forwarded.last().map(|e| e.rule_id), Some(total));
    }

    #[test]
    fn events_the_outbox_dropped_between_two_ticks_are_forwarded_as_a_count() {
        let engine = forwarding_engine();
        let mut cursor = WafForwardCursor::new();
        let recorded = lorica_waf::FORWARD_OUTBOX_CAPACITY as u32 + 700;
        engine.record_events((1..=recorded).map(event).collect());

        let batch = cursor.take_batch(&engine);
        assert_eq!(
            batch.events.len() as u64 + cursor.lost(),
            u64::from(recorded)
        );
        assert_eq!(batch.events.last().map(|e| e.rule_id), Some(recorded));
        assert_eq!(batch.lost.len(), 1);
        assert_eq!(batch.lost[0].count, cursor.lost());

        engine.record_events(vec![event(recorded + 1)]);
        let batch = cursor.take_batch(&engine);
        assert_eq!(
            batch.events.iter().map(|e| e.rule_id).collect::<Vec<_>>(),
            vec![recorded + 1]
        );
        assert!(batch.lost.is_empty());
    }

    #[test]
    fn the_supervisor_counts_every_event_forwarded_or_dropped_in_its_windows() {
        let worker = forwarding_engine();
        let h = harness(NO_BAN);
        let mut cursor = WafForwardCursor::new();
        let one_by_one = 1300;
        for rule_id in 1..=one_by_one {
            worker.record_events(vec![event(rule_id)]);
            for line in cursor.take_batch(&worker).into_lines() {
                h.ingest.handle_line(&line);
            }
        }
        let burst = lorica_waf::FORWARD_OUTBOX_CAPACITY as u32 * 2;
        worker.record_events((1..=burst).map(event).collect());
        for line in cursor.take_batch(&worker).into_lines() {
            h.ingest.handle_line(&line);
        }

        let hour = h.ingest.engine.event_counts_within(HOUR);
        let total = u64::from(one_by_one + burst);
        assert_eq!(hour.total, total);
        assert_eq!(hour.by_category, vec![("xss".to_string(), total)]);
        assert_eq!(h.ingest.engine.recent_events(1)[0].rule_id, burst);
    }

    #[test]
    fn a_flood_from_one_address_raises_one_alert() {
        let mut h = harness(NO_BAN);
        for rule_id in 1..=2_000 {
            h.ingest
                .handle_line(&line(&ForwardedLine::Event(event(rule_id))));
        }
        let alerts = drain(&mut h.alerts);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].alert_type, AlertType::WafAlert);
        assert_eq!(
            alerts[0].details.get("client_ip").map(String::as_str),
            Some("192.0.2.10")
        );
    }

    #[test]
    fn blocklist_hits_are_counted_but_not_alerted() {
        let mut h = harness(NO_BAN);
        let hit = WafEvent {
            category: RuleCategory::IpBlocklist,
            ..event(0)
        };
        h.ingest.handle_line(&line(&ForwardedLine::Event(hit)));
        assert!(drain(&mut h.alerts).is_empty());
        assert_eq!(h.ingest.engine.event_counts_within(HOUR).total, 1);
    }

    #[test]
    fn an_address_seen_only_in_a_dropped_count_is_still_alerted_and_banned() {
        let mut h = harness(WafBanPolicy {
            threshold: 5,
            duration_s: 600,
        });
        let quiet = "192.0.2.77";
        violations(&h.ingest, quiet, 5);
        h.ingest.handle_line(&line(&ForwardedLine::Lost {
            lost: LostEvents {
                client_ip: quiet.into(),
                category: RuleCategory::SqlInjection,
                count: 3,
            },
        }));

        let bans = drain(&mut h.bans);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, quiet);
        assert_eq!(bans[0].1, 600);
        let alerts = drain(&mut h.alerts);
        assert!(alerts.iter().any(|a| a.alert_type == AlertType::WafAlert
            && a.details.get("client_ip").map(String::as_str) == Some(quiet)));
        assert!(alerts.iter().any(|a| a.alert_type == AlertType::IpBanned));
        assert_eq!(h.ingest.engine.event_counts_within(HOUR).total, 3);
    }

    #[test]
    fn the_ban_decision_reads_the_cached_policy() {
        let mut h = harness(NO_BAN);
        let ip = "192.0.2.10";
        violations(&h.ingest, ip, 50);
        h.ingest.handle_line(&line(&ForwardedLine::Event(event(1))));
        assert!(
            drain(&mut h.bans).is_empty(),
            "a zero threshold bans nobody"
        );

        h.ingest.policy.store(Arc::new(WafBanPolicy {
            threshold: 10,
            duration_s: 60,
        }));
        h.ingest.handle_line(&line(&ForwardedLine::Event(event(2))));
        let bans = drain(&mut h.bans);
        assert_eq!(bans.len(), 1);
        assert_eq!((bans[0].0.as_str(), bans[0].1), (ip, 60));

        h.ingest.handle_line(&line(&ForwardedLine::Event(event(3))));
        assert!(
            drain(&mut h.bans).is_empty(),
            "the crossing reset the counter"
        );
    }

    #[test]
    fn a_line_that_is_neither_shape_is_ignored() {
        let h = harness(NO_BAN);
        h.ingest.handle_line("not json\n");
        h.ingest.handle_line("{\"lost\":{\"client_ip\":\"x\"}}\n");
        assert_eq!(h.ingest.engine.event_count(), 0);
        assert_eq!(h.ingest.engine.event_counts_within(HOUR).total, 0);
    }

    #[test]
    fn the_policy_follows_the_settings() {
        let settings = lorica_config::models::GlobalSettings {
            waf_ban_threshold: 7,
            waf_ban_duration_s: 120,
            ..Default::default()
        };
        assert_eq!(
            WafBanPolicy::from_settings(&settings),
            WafBanPolicy {
                threshold: 7,
                duration_s: 120
            }
        );
    }
}
