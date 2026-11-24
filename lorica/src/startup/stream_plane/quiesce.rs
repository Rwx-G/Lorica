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

//! Quiescing the workers, for a stop (D-f) or for a hot upgrade
//! (Story 12.11), and the drain reports an upgrade quiesce reads back.

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::future::join_all;
use lorica_stream::ReleaseCause;
use lorica_worker::stream_ctl::{DrainEnd, DrainedEntry, QuiesceReason, StreamCtlMsg};
use tracing::warn;

use super::exchange::WorkerSlot;
use super::{LinkError, PlaneEvent, StreamPlane, WorkerLink};
use crate::startup::hot_upgrade::{DrainReport, GenerationDrainEnd, StreamDrainCounts};

/// What one worker's drain report said (Story 12.11 D-g).
#[derive(Debug, Default)]
struct WorkerReport {
    entries: Vec<DrainedEntry>,
    /// The `drained_end`, absent for an unreported worker.
    end: Option<ReportEnd>,
}

#[derive(Debug, Clone, Copy)]
struct ReportEnd {
    end: DrainEnd,
    http_cut: u64,
    entries: u64,
    truncated: bool,
}

impl WorkerReport {
    /// Take `msg` into the report answering quiesce `seq`; `true` once
    /// its end marker is in.
    fn take(&mut self, worker: u32, seq: u64, msg: StreamCtlMsg) -> bool {
        match msg {
            StreamCtlMsg::Drained { seq: s, entries } if s == seq => {
                self.entries.extend(entries);
                false
            }
            StreamCtlMsg::DrainedEnd {
                seq: s,
                end,
                http_cut,
                entries,
                truncated,
            } if s == seq => {
                self.end = Some(ReportEnd {
                    end,
                    http_cut,
                    entries,
                    truncated,
                });
                true
            }
            // Answers to earlier messages, the quiesce's own ack among
            // them when it came after its timeout.
            StreamCtlMsg::Ack { .. } | StreamCtlMsg::Nack { .. } => false,
            other => {
                warn!(
                    worker_id = worker,
                    seq = other.seq(),
                    quiesce_seq = seq,
                    "stream control message that answers no upgrade quiesce ignored"
                );
                false
            }
        }
    }
}

impl<L: WorkerLink> WorkerSlot<L> {
    /// Read the drain report answering quiesce `seq`: what was kept
    /// aside, then the channel until the end marker, the channel's close
    /// (the worker exited), or `timeout`.
    async fn read_report(&mut self, worker: u32, seq: u64, timeout: Duration) -> WorkerReport {
        let mut report = WorkerReport::default();
        for msg in std::mem::take(&mut self.reports) {
            if report.take(worker, seq, msg) {
                return report;
            }
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let Some(link) = self.link.as_mut() else {
                return report;
            };
            match tokio::time::timeout_at(deadline, link.recv()).await {
                Err(_) => {
                    warn!(
                        worker_id = worker,
                        "no drain report end from the worker in time"
                    );
                    return report;
                }
                Ok(Ok(msg)) => {
                    if report.take(worker, seq, msg) {
                        return report;
                    }
                }
                Ok(Err(LinkError::Lost(_))) => {
                    self.link = None;
                    return report;
                }
                Ok(Err(e @ LinkError::Refused(_))) => {
                    warn!(worker_id = worker, error = %e, "garbled drain report message dropped");
                }
            }
        }
    }
}

/// The workers' drain reports answering an upgrade quiesce, summed over
/// the workers (Story 12.11 D-g).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpgradeDrainReports {
    /// Workers whose `drained_end` arrived.
    pub(crate) reported: u32,
    /// Workers with no `drained_end`: killed, crashed, never quiesced,
    /// or whose end marker did not fit their channel. What they sent
    /// before is counted.
    pub(crate) unreported: u32,
    /// Reported workers whose report lost entries to a full channel.
    pub(crate) truncated: u32,
    /// Whether a worker reached its deadline with traffic left.
    pub(crate) deadline: bool,
    /// HTTP requests the workers' exits cut.
    pub(crate) http_cut: u64,
    /// Per stream id.
    pub(crate) streams: BTreeMap<String, StreamDrainCounts>,
}

impl UpgradeDrainReports {
    fn add(&mut self, worker: u32, report: WorkerReport) {
        let received = u64::try_from(report.entries.len()).unwrap_or(u64::MAX);
        for entry in report.entries {
            let counts = self.streams.entry(entry.stream_id).or_default();
            counts.closed = counts.closed.saturating_add(entry.closed);
            counts.finished = counts.finished.saturating_add(entry.finished);
        }
        let Some(end) = report.end else {
            warn!(
                worker_id = worker,
                entries = received,
                "no upgrade drain report end from the worker; counted as unreported"
            );
            self.unreported += 1;
            return;
        };
        if end.entries != received {
            warn!(
                worker_id = worker,
                declared = end.entries,
                received,
                "upgrade drain report entries lost on the way"
            );
        }
        self.reported += 1;
        self.truncated += u32::from(end.truncated);
        self.deadline |= end.end == DrainEnd::Deadline;
        self.http_cut = self.http_cut.saturating_add(end.http_cut);
    }
}

/// What an old generation's upgrade drain did, as its supervisor saw it
/// (Story 12.11 D-b steps 4 to 6).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UpgradeDrain {
    /// Every worker exited by itself within the bound.
    pub(crate) clean: bool,
    /// From the SIGTERM to the last worker's exit.
    pub(crate) drain_secs: f64,
    /// The workers' reports.
    pub(crate) reports: UpgradeDrainReports,
}

impl UpgradeDrain {
    /// How the generation's drain ended: `killed` when a worker had to
    /// be, `deadline` when one reached it, `idle` otherwise.
    pub(crate) fn end(&self) -> GenerationDrainEnd {
        if !self.clean {
            GenerationDrainEnd::Killed
        } else if self.reports.deadline {
            GenerationDrainEnd::Deadline
        } else {
            GenerationDrainEnd::Idle
        }
    }

    /// The report the generation writes for `new_pid`, its drain having
    /// been `drain`.
    pub(crate) fn report(&self, old_pid: u32, new_pid: u32, drain: Duration) -> DrainReport {
        DrainReport {
            old_pid,
            new_pid,
            drain_timeout_s: drain.as_secs(),
            drain_secs: self.drain_secs,
            end: self.end(),
            workers_unreported: self.reports.unreported,
            http_cut: self.reports.http_cut,
            streams: self.reports.streams.clone(),
        }
    }
}

impl<L: WorkerLink> StreamPlane<L> {
    /// Send every worker `quiesce reason=<reason>` for `drain`, and take
    /// no binding afterwards. Returns the seq each worker was sent.
    async fn quiesce_workers(
        &mut self,
        reason: QuiesceReason,
        drain: Duration,
    ) -> BTreeMap<u32, u64> {
        let drain_ms = u64::try_from(drain.as_millis()).unwrap_or(u64::MAX);
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        let mut seqs = BTreeMap::new();
        for id in self.workers.keys().copied().collect::<Vec<_>>() {
            let seq = self.seq();
            seqs.insert(id, seq);
            per_worker.insert(
                id,
                vec![StreamCtlMsg::Quiesce {
                    seq,
                    reason,
                    drain_ms,
                }],
            );
        }
        self.quiesced = true;
        self.send_all(per_worker).await;
        seqs
    }

    /// D-b step 4 of a hot upgrade (Story 12.11): quiesce every worker
    /// for `drain` with reason `upgrade`. Nothing is released and no
    /// `stream.release` row is written: the ports stay open through the
    /// new generation, which holds them. Each worker answers with its
    /// drain report once its drain ends, read by
    /// [`Self::collect_drain_reports`].
    pub(crate) async fn quiesce_for_upgrade(&mut self, drain: Duration) {
        self.upgrade_quiesce = self.quiesce_workers(QuiesceReason::Upgrade, drain).await;
    }

    /// Read every worker's drain report answering the upgrade quiesce,
    /// once the workers have exited (Story 12.11 D-g): their messages
    /// wait in this end of each channel. A worker is read until its end
    /// marker, its channel's close, or the ack timeout; one with no end
    /// marker is unreported.
    pub(crate) async fn collect_drain_reports(&mut self) -> UpgradeDrainReports {
        let timeout = self.ack_timeout;
        let quiesce = std::mem::take(&mut self.upgrade_quiesce);
        let reads: Vec<(u32, WorkerReport)> =
            join_all(self.workers.iter_mut().map(|(id, slot)| {
                let seq = quiesce.get(id).copied();
                async move {
                    let report = match seq {
                        Some(seq) => slot.read_report(*id, seq, timeout).await,
                        None => WorkerReport::default(),
                    };
                    (*id, report)
                }
            }))
            .await;
        let mut reports = UpgradeDrainReports::default();
        for (worker, report) in reads {
            reports.add(worker, report);
        }
        reports
    }

    /// The stop path (D-f): quiesce every worker for `drain` and release
    /// every binding with cause `shutdown`.
    pub(crate) async fn quiesce(&mut self, drain: Duration) -> Vec<PlaneEvent> {
        self.quiesce_workers(QuiesceReason::Shutdown, drain).await;
        let mut events = Vec::new();
        for (id, b) in std::mem::take(&mut self.held) {
            self.states.remove(&id);
            events.push(PlaneEvent::Released {
                key: b.key,
                bind_gen: b.bind_gen,
                cause: ReleaseCause::Shutdown,
            });
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use lorica_config::ConfigStore;
    use lorica_stream::{BindState, FdBudget, StreamBindStates};
    use lorica_worker::stream_ctl;
    use tokio::sync::Mutex;

    use super::*;
    use crate::startup::drain::WORKER_KILL_MARGIN;
    use crate::startup::stream_plane::test_support::{
        bindable, free_ports, plane, reserved, seen, tcp, FakeLink, FixedTable, Reply, Seen, PASS,
        STANDALONE,
    };
    use crate::startup::stream_plane::{
        PlaneRole, SeqpacketLink, StreamPlaneHandle, Trigger, STREAM_CTL_ACK_TIMEOUT,
    };

    fn entry(stream_id: &str, closed: u64, finished: u64) -> DrainedEntry {
        DrainedEntry {
            stream_id: stream_id.to_string(),
            closed,
            finished,
        }
    }

    #[tokio::test]
    async fn quiesce_reaches_every_worker_and_releases_with_shutdown() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = tcp("s1", free_ports(1));
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        let events = plane.quiesce(Duration::from_secs(20)).await;

        for log in [&seen0, &seen1] {
            assert_eq!(
                seen(log).last(),
                Some(&Seen::Quiesce {
                    drain_ms: 20_000,
                    reason: QuiesceReason::Shutdown
                })
            );
        }
        assert!(matches!(
            events.as_slice(),
            [PlaneEvent::Released {
                cause: ReleaseCause::Shutdown,
                ..
            }]
        ));
        assert!(states.snapshot().is_empty());
    }

    fn plane_handle(plane: StreamPlane<FakeLink>) -> StreamPlaneHandle<FakeLink> {
        StreamPlaneHandle::new(
            plane,
            Arc::new(Mutex::new(
                ConfigStore::open_in_memory().expect("test setup: store"),
            )),
            PlaneRole::Standalone,
            None,
            lorica_notify::AlertSender::new(16),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upgrade_drain_quiesces_before_the_sigterm_waits_drain_plus_margin_and_sums_the_reports(
    ) {
        let (w0, seen0) = FakeLink::reporting(
            &[],
            vec![entry("db", 2, 3), entry("dns", 1, 0)],
            DrainEnd::Deadline,
            4,
        );
        // Its quiesce ack never comes: the report still counts, read
        // from where the quiesce exchange set it aside.
        let (w1, seen1) = FakeLink::reporting(
            &[Reply::Ack, Reply::Ack, Reply::Ack, Reply::Silent],
            vec![entry("db", 5, 1)],
            DrainEnd::Idle,
            0,
        );
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = tcp("s1", free_ports(1));
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        let handle = plane_handle(plane);
        let drain = Duration::from_secs(120);

        /// The bound `terminate` was given, and what each worker had
        /// seen by then.
        type AtTerminate = Option<(Duration, Vec<Seen>, Vec<Seen>)>;
        let at_terminate: Arc<StdMutex<AtTerminate>> = Arc::default();
        let terminate_saw = Arc::clone(&at_terminate);
        let (log0, log1) = (Arc::clone(&seen0), Arc::clone(&seen1));
        let drained = handle
            .drain_for_upgrade(drain, move |bound| {
                *terminate_saw.lock().unwrap() = Some((bound, seen(&log0), seen(&log1)));
                true
            })
            .await;

        let (bound, before0, before1) = at_terminate.lock().unwrap().take().expect("terminated");
        assert_eq!(bound, drain + WORKER_KILL_MARGIN);
        for before in [before0, before1] {
            assert_eq!(
                before.last(),
                Some(&Seen::Quiesce {
                    drain_ms: 120_000,
                    reason: QuiesceReason::Upgrade
                }),
                "every worker is quiesced for the upgrade before the SIGTERM"
            );
        }
        assert_eq!(
            drained.reports,
            UpgradeDrainReports {
                reported: 2,
                unreported: 0,
                truncated: 0,
                deadline: true,
                http_cut: 4,
                streams: BTreeMap::from([
                    (
                        "db".to_string(),
                        StreamDrainCounts {
                            closed: 7,
                            finished: 4
                        }
                    ),
                    (
                        "dns".to_string(),
                        StreamDrainCounts {
                            closed: 1,
                            finished: 0
                        }
                    ),
                ]),
            }
        );
        assert!(drained.clean);
        assert_eq!(drained.end(), GenerationDrainEnd::Deadline);
        let report = drained.report(10, 20, drain);
        assert_eq!(
            (report.old_pid, report.new_pid, report.drain_timeout_s),
            (10, 20, 120)
        );
        assert_eq!(report.streams, drained.reports.streams);
        assert!(
            matches!(states.get("s1"), Some(BindState::Bound { .. })),
            "an upgrade releases nothing: the new generation holds the ports"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_worker_without_its_report_end_is_unreported_and_a_kill_says_killed() {
        let (w0, _) = FakeLink::reporting(&[], vec![entry("db", 1, 0)], DrainEnd::Idle, 0);
        let (w1, _) = FakeLink::new(&[]);
        let (plane, _) = plane(vec![w0, w1]);
        let handle = plane_handle(plane);

        let drained = handle
            .drain_for_upgrade(Duration::from_secs(1), |_| false)
            .await;

        assert_eq!(
            (drained.reports.reported, drained.reports.unreported),
            (1, 1)
        );
        assert!(!drained.reports.deadline);
        assert_eq!(drained.end(), GenerationDrainEnd::Killed);
        assert_eq!(
            drained
                .report(1, 2, Duration::from_secs(1))
                .workers_unreported,
            1
        );
    }

    #[tokio::test]
    async fn a_plane_quiesced_for_an_upgrade_binds_nothing_more() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        plane.quiesce_for_upgrade(Duration::from_secs(5)).await;
        let port = free_ports(1);

        let events = plane
            .bind_desired(&[tcp("late", port)], &[], STANDALONE, PASS, Trigger::Change)
            .await;
        plane.refresh_all(PASS).await;

        assert!(events.is_empty());
        assert!(states.snapshot().is_empty());
        assert!(bindable(port));
        assert_eq!(
            seen(&seen0),
            vec![Seen::Quiesce {
                drain_ms: 5_000,
                reason: QuiesceReason::Upgrade
            }]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_real_worker_runtime_reports_its_upgrade_drain_through_the_seqpacket_link() {
        let (supervisor_end, worker_end) = stream_ctl::create_seqpacket_pair().unwrap();
        let runtime = lorica_stream::StreamRuntime::spawn(
            lorica_stream::ControlTransport::Seqpacket(worker_end),
            lorica_stream::Engines::default(),
            Arc::new(FixedTable(Vec::new())),
        )
        .unwrap();
        let mut plane = StreamPlane::new(
            vec![(0, SeqpacketLink::new(supervisor_end).unwrap())],
            1,
            FdBudget::from_limit(65536),
            reserved(),
            StreamBindStates::new(),
            STREAM_CTL_ACK_TIMEOUT,
        );

        plane.quiesce_for_upgrade(Duration::from_secs(1)).await;
        let mut quiesced = runtime.quiesced();
        let q = *quiesced.wait_for(Option::is_some).await.unwrap();
        assert_eq!(q.map(|q| q.reason), Some(QuiesceReason::Upgrade));
        // What a worker's drain watcher does before its exit, then the
        // exit closing its end of the channel.
        let worker_exit = tokio::task::spawn_blocking(move || {
            let sent = runtime.send_drain_report(DrainEnd::Deadline, 2).unwrap();
            assert!(!sent.truncated);
            runtime.stop();
        });
        worker_exit.await.unwrap();

        let reports = plane.collect_drain_reports().await;

        assert_eq!((reports.reported, reports.unreported), (1, 0));
        assert!(reports.deadline);
        assert_eq!(reports.http_cut, 2);
    }
}
