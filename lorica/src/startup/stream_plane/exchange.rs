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

//! The driver's side of the message exchange: stop-and-wait per
//! worker, every worker at once, and the answers that arrive after
//! their timeout, credited when they are read.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use futures_util::future::join_all;
use lorica_stream::BindState;
use lorica_worker::stream_ctl::{NackReason, StreamCtlMsg};
use tracing::{debug, warn};

use super::{LinkError, StreamPlane, WorkerLink};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pending {
    Attach { stream_id: String, bind_gen: u64 },
    Caps { stream_id: String },
    Other,
}

impl Pending {
    fn of(msg: &StreamCtlMsg) -> Self {
        match msg {
            StreamCtlMsg::Attach {
                stream_id,
                bind_gen,
                ..
            } => Pending::Attach {
                stream_id: stream_id.clone(),
                bind_gen: *bind_gen,
            },
            StreamCtlMsg::Caps { stream_id, .. } => Pending::Caps {
                stream_id: stream_id.clone(),
            },
            _ => Pending::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Ack,
    Nack(NackReason),
    Timeout,
    Lost,
    Refused(String),
    NoLink,
}

#[derive(Debug)]
struct Sent {
    seq: u64,
    pending: Pending,
    answer: Answer,
}

#[derive(Debug, Default)]
struct SlotRun {
    sent: Vec<Sent>,
    stale: Vec<Stale>,
}

/// A worker message read while the answer to another was awaited, kept
/// for the end of the pass. Only what a worker may send is kept: a
/// message of any other kind is dropped on receipt, closing the fds it
/// carries.
#[derive(Debug)]
enum Stale {
    /// A late `ack` (`acked`) or `nack`.
    Answer { seq: u64, acked: bool },
    /// A drain report message.
    Report(StreamCtlMsg),
}

pub(super) struct WorkerSlot<L> {
    pub(super) link: Option<L>,
    /// Attaches that timed out, by sequence number, credited if their
    /// answer arrives later.
    pub(super) outstanding: HashMap<u64, Pending>,
    /// Drain report messages read while waiting for another answer, kept
    /// for [`StreamPlane::collect_drain_reports`].
    pub(super) reports: Vec<StreamCtlMsg>,
}

impl<L: WorkerLink> WorkerSlot<L> {
    pub(super) fn new(link: L) -> Self {
        WorkerSlot {
            link: Some(link),
            outstanding: HashMap::new(),
            reports: Vec::new(),
        }
    }

    async fn run(&mut self, worker: u32, msgs: Vec<StreamCtlMsg>, timeout: Duration) -> SlotRun {
        let mut run = SlotRun::default();
        for msg in msgs {
            let seq = msg.seq();
            let pending = Pending::of(&msg);
            let answer = self.exchange(worker, msg, timeout, &mut run.stale).await;
            run.sent.push(Sent {
                seq,
                pending,
                answer,
            });
        }
        run
    }

    async fn exchange(
        &mut self,
        worker: u32,
        msg: StreamCtlMsg,
        timeout: Duration,
        stale: &mut Vec<Stale>,
    ) -> Answer {
        let seq = msg.seq();
        let Some(link) = self.link.as_mut() else {
            return Answer::NoLink;
        };
        match link.send(msg).await {
            Ok(()) => {}
            Err(LinkError::Refused(reason)) => return Answer::Refused(reason),
            Err(e @ LinkError::Lost(_)) => {
                warn!(worker_id = worker, error = %e, "stream control channel lost");
                self.link = None;
                return Answer::Lost;
            }
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let Some(link) = self.link.as_mut() else {
                return Answer::Lost;
            };
            let received = tokio::time::timeout_at(deadline, link.recv()).await;
            match received {
                Err(_) => return Answer::Timeout,
                Ok(Ok(StreamCtlMsg::Ack { seq: s, .. })) if s == seq => return Answer::Ack,
                Ok(Ok(StreamCtlMsg::Nack { seq: s, reason })) if s == seq => {
                    return Answer::Nack(reason)
                }
                Ok(Ok(StreamCtlMsg::Ack { seq: late, .. })) => stale.push(Stale::Answer {
                    seq: late,
                    acked: true,
                }),
                Ok(Ok(StreamCtlMsg::Nack { seq: late, .. })) => stale.push(Stale::Answer {
                    seq: late,
                    acked: false,
                }),
                Ok(Ok(
                    report @ (StreamCtlMsg::Drained { .. } | StreamCtlMsg::DrainedEnd { .. }),
                )) => stale.push(Stale::Report(report)),
                Ok(Ok(other)) => {
                    warn!(
                        worker_id = worker,
                        seq = other.seq(),
                        "unexpected message from a worker on the stream control channel dropped"
                    );
                }
                Ok(Err(e @ LinkError::Lost(_))) => {
                    warn!(worker_id = worker, error = %e, "stream control channel lost");
                    self.link = None;
                    return Answer::Lost;
                }
                Ok(Err(e @ LinkError::Refused(_))) => {
                    warn!(worker_id = worker, error = %e, "garbled stream control answer dropped");
                }
            }
        }
    }
}

impl<L: WorkerLink> StreamPlane<L> {
    /// Run each worker's messages, stop-and-wait per worker and every
    /// worker at once, then credit the acknowledged attaches, the late
    /// ones included.
    pub(super) async fn send_all(&mut self, mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>>) {
        let timeout = self.ack_timeout;
        let runs: Vec<(u32, SlotRun)> =
            join_all(self.workers.iter_mut().filter_map(|(id, slot)| {
                let msgs = per_worker.remove(id)?;
                Some(async move { (*id, slot.run(*id, msgs, timeout).await) })
            }))
            .await;
        for (worker, run) in runs {
            if let Some(slot) = self.workers.get_mut(&worker) {
                for sent in &run.sent {
                    if sent.answer == Answer::Timeout {
                        slot.outstanding.insert(sent.seq, sent.pending.clone());
                    }
                }
            }
            for sent in run.sent {
                match sent.answer {
                    Answer::Ack => self.credit(worker, &sent.pending),
                    Answer::Nack(reason) => {
                        self.caps_not_adopted(worker, &sent.pending);
                        if let Pending::Caps { stream_id } = &sent.pending {
                            warn!(
                                worker_id = worker,
                                %stream_id,
                                reason = reason.as_str(),
                                "stream caps region refused by the worker; it admits no connection or session of the stream"
                            );
                        } else {
                            debug!(
                                worker_id = worker,
                                seq = sent.seq,
                                reason = reason.as_str(),
                                "stream control message refused by the worker"
                            );
                        }
                    }
                    Answer::Timeout => {
                        // Not serving until its late answer says so.
                        self.caps_not_adopted(worker, &sent.pending);
                        warn!(
                            worker_id = worker,
                            seq = sent.seq,
                            "stream control message not answered in time"
                        );
                    }
                    Answer::Refused(reason) => {
                        warn!(worker_id = worker, seq = sent.seq, %reason,
                              "stream control message could not be sent");
                    }
                    Answer::Lost | Answer::NoLink => {}
                }
            }
            for msg in run.stale {
                self.late_answer(worker, msg);
            }
        }
    }

    fn credit(&mut self, worker: u32, pending: &Pending) {
        match pending {
            Pending::Attach {
                stream_id,
                bind_gen,
            } => {
                if let Some(b) = self.held.get_mut(stream_id) {
                    if b.bind_gen == *bind_gen {
                        *b.acked.entry(worker).or_default() += 1;
                    }
                }
            }
            Pending::Caps { stream_id } => {
                if let Some(b) = self.held.get_mut(stream_id) {
                    b.caps_refused.remove(&worker);
                }
            }
            Pending::Other => {}
        }
    }

    /// A `caps` that `worker` refused or left unanswered: the worker
    /// holds the stream's sockets but admits no connection or session of it.
    fn caps_not_adopted(&mut self, worker: u32, pending: &Pending) {
        if let Pending::Caps { stream_id } = pending {
            if let Some(b) = self.held.get_mut(stream_id) {
                b.caps_refused.insert(worker);
            }
        }
    }

    fn late_answer(&mut self, worker: u32, stale: Stale) {
        let (seq, acked) = match stale {
            Stale::Answer { seq, acked } => (seq, acked),
            // A drain report read while another answer was awaited: kept
            // for the collection that follows the workers' exit.
            Stale::Report(report) => {
                if let Some(slot) = self.workers.get_mut(&worker) {
                    slot.reports.push(report);
                }
                return;
            }
        };
        let Some(pending) = self
            .workers
            .get_mut(&worker)
            .and_then(|slot| slot.outstanding.remove(&seq))
        else {
            return;
        };
        if !acked {
            return;
        }
        self.credit(worker, &pending);
        if let Pending::Attach { stream_id, .. } | Pending::Caps { stream_id } = &pending {
            if let Some(b) = self.held.get(stream_id) {
                if matches!(self.states.get(stream_id), Some(BindState::Bound { .. })) {
                    self.states
                        .set_bound(stream_id, b.serving(), self.worker_count);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use lorica_worker::fd_passing::StreamProto;
    use lorica_worker::stream_ctl::StreamSocket;

    use super::*;
    use crate::startup::stream_plane::test_support::{
        free_ports, plane, tcp, FakeLink, Reply, PASS, STANDALONE, TEST_ACK_TIMEOUT,
    };
    use crate::startup::stream_plane::Trigger;

    #[tokio::test]
    async fn a_silent_worker_times_out_and_the_binding_counts_the_others() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[Reply::Silent, Reply::Silent]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = tcp("s1", free_ports(1));

        let start = std::time::Instant::now();
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        // One ack timeout for the attach and one for the refresh, the
        // workers waited on together.
        assert!(start.elapsed() < TEST_ACK_TIMEOUT * 4);
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 2
            })
        );
    }

    #[tokio::test]
    async fn an_attach_acknowledged_after_its_timeout_is_credited_when_read() {
        let (w0, _) = FakeLink::new(&[Reply::Late]);
        let (mut plane, states) = plane(vec![w0]);
        let s = tcp("s1", free_ports(1));

        // The attach times out; its answer reaches the driver while it
        // waits for the refresh's.
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 1
            })
        );
    }

    /// A worker sends answers and drain reports only: anything else read
    /// while an answer is awaited is dropped at once, which closes the
    /// fds it carries, instead of being held until the pass ends.
    #[tokio::test]
    async fn a_worker_message_that_answers_nothing_is_dropped_with_its_fds() {
        use std::io::Read;

        let (carried, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut link, _) = FakeLink::new(&[]);
        link.outbox.push_back(StreamCtlMsg::Attach {
            seq: 7,
            stream_id: "a".into(),
            bind_gen: 1,
            sockets: vec![StreamSocket {
                proto: StreamProto::Tcp,
                addr: "127.0.0.1:1".parse().unwrap(),
                fd: OwnedFd::from(carried),
            }],
        });
        let mut slot = WorkerSlot::new(link);
        let mut stale = Vec::new();

        let answer = slot
            .exchange(
                0,
                StreamCtlMsg::Refresh {
                    seq: 1,
                    drain_ms: 0,
                },
                TEST_ACK_TIMEOUT,
                &mut stale,
            )
            .await;

        assert_eq!(answer, Answer::Ack);
        peer.set_nonblocking(true).unwrap();
        let read = (&peer).read(&mut [0u8; 1]);
        assert!(
            matches!(read, Ok(0)),
            "the carried fd is still open: {read:?}"
        );
        assert!(stale.is_empty());
    }
}
