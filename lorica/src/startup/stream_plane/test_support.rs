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

//! The fakes and fixtures the stream plane's tests share.

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{NodeRole, Stream, StreamProtocol};
use lorica_stream::{FdBudget, StreamBindStates};
use lorica_worker::stream_ctl::{DrainEnd, DrainedEntry, NackReason, QuiesceReason, StreamCtlMsg};

use super::{LinkError, PassSettings, StreamPlane, WorkerLink};

pub(super) const TEST_ACK_TIMEOUT: Duration = Duration::from_millis(200);
pub(super) const PASS: PassSettings = PassSettings {
    drain: Duration::from_secs(30),
    listen_socket_cap: 2048,
};
pub(super) const STANDALONE: NodeRole<'static> = NodeRole::Standalone;

/// What a fake worker saw, fds left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Seen {
    Attach {
        stream_id: String,
        bind_gen: u64,
        addrs: Vec<SocketAddr>,
    },
    Detach {
        stream_id: String,
        drain_ms: u64,
    },
    Refresh {
        drain_ms: u64,
    },
    Quiesce {
        drain_ms: u64,
        reason: QuiesceReason,
    },
    /// `total` is the region's session total when the message
    /// arrived.
    Caps {
        stream_id: String,
        caps_gen: u64,
        slot: u32,
        total: u64,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Reply {
    Ack,
    /// Never answers.
    Silent,
    /// Answers when the next message arrives.
    Late,
    /// Refuses with `adopt_failed`.
    Refuse,
}

/// A worker that answers from a script (acks once it runs out), and
/// holds the sockets it was attached until they are detached, as a
/// worker does. Quiesced for an upgrade, it leaves its drain report,
/// if it has one, and exits: its channel then reads as closed.
#[derive(Default)]
pub(super) struct FakeLink {
    script: VecDeque<Reply>,
    seen: Arc<StdMutex<Vec<Seen>>>,
    pub(super) outbox: VecDeque<StreamCtlMsg>,
    late: Vec<StreamCtlMsg>,
    holding: HashMap<(String, u64), Vec<OwnedFd>>,
    report: Option<(Vec<DrainedEntry>, DrainEnd, u64)>,
    exited: bool,
}

impl FakeLink {
    pub(super) fn new(script: &[Reply]) -> (Self, Arc<StdMutex<Vec<Seen>>>) {
        let link = FakeLink {
            script: script.iter().copied().collect(),
            ..FakeLink::default()
        };
        let seen = Arc::clone(&link.seen);
        (link, seen)
    }

    /// A worker whose upgrade drain ends with `end` and reports
    /// `entries` and `http_cut`.
    pub(super) fn reporting(
        script: &[Reply],
        entries: Vec<DrainedEntry>,
        end: DrainEnd,
        http_cut: u64,
    ) -> (Self, Arc<StdMutex<Vec<Seen>>>) {
        let (mut link, seen) = FakeLink::new(script);
        link.report = Some((entries, end, http_cut));
        (link, seen)
    }

    /// The fds it holds for binding `bind_gen` of `stream_id`.
    pub(super) fn held(&self, stream_id: &str, bind_gen: u64) -> &[OwnedFd] {
        self.holding
            .get(&(stream_id.to_string(), bind_gen))
            .map_or(&[], Vec::as_slice)
    }
}

impl WorkerLink for FakeLink {
    async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
        self.outbox.extend(self.late.drain(..));
        let seq = msg.seq();
        let seen = match msg {
            StreamCtlMsg::Attach {
                stream_id,
                bind_gen,
                sockets,
                ..
            } => {
                let addrs = sockets.iter().map(|s| s.addr).collect();
                self.holding
                    .entry((stream_id.clone(), bind_gen))
                    .or_default()
                    .extend(sockets.into_iter().map(|s| s.fd));
                Seen::Attach {
                    stream_id,
                    bind_gen,
                    addrs,
                }
            }
            StreamCtlMsg::Detach {
                stream_id,
                bind_gen,
                drain_ms,
                ..
            } => {
                self.holding.remove(&(stream_id.clone(), bind_gen));
                Seen::Detach {
                    stream_id,
                    drain_ms,
                }
            }
            StreamCtlMsg::Refresh { drain_ms, .. } => Seen::Refresh { drain_ms },
            StreamCtlMsg::Quiesce {
                drain_ms, reason, ..
            } => {
                self.holding.clear();
                if reason == QuiesceReason::Upgrade {
                    self.exited = true;
                }
                Seen::Quiesce { drain_ms, reason }
            }
            StreamCtlMsg::Caps {
                stream_id,
                caps_gen,
                slot,
                region,
                ..
            } => {
                let region = lorica_shmem::StreamCapsRegion::open(region).expect("a caps region");
                Seen::Caps {
                    stream_id,
                    caps_gen,
                    slot,
                    total: region.total(),
                }
            }
            other => panic!("a driver never sends {other:?}"),
        };
        self.seen.lock().unwrap().push(seen);
        let answer = StreamCtlMsg::Ack { seq, count: 1 };
        match self.script.pop_front().unwrap_or(Reply::Ack) {
            Reply::Ack => self.outbox.push_back(answer),
            Reply::Silent => {}
            Reply::Late => self.late.push(answer),
            Reply::Refuse => self.outbox.push_back(StreamCtlMsg::Nack {
                seq,
                reason: NackReason::AdoptFailed,
            }),
        }
        if self.exited {
            if let Some((entries, end, http_cut)) = self.report.take() {
                let sent = u64::try_from(entries.len()).unwrap();
                if !entries.is_empty() {
                    self.outbox
                        .push_back(StreamCtlMsg::Drained { seq, entries });
                }
                self.outbox.push_back(StreamCtlMsg::DrainedEnd {
                    seq,
                    end,
                    http_cut,
                    entries: sent,
                    truncated: false,
                });
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
        match self.outbox.pop_front() {
            Some(msg) => Ok(msg),
            None if self.exited => Err(LinkError::Lost("the worker exited".into())),
            None => std::future::pending().await,
        }
    }
}

pub(super) fn reserved() -> ReservedPorts {
    // Ports a test never draws: the ephemeral range starts above.
    ReservedPorts {
        management: 9443,
        http: 8080,
        https: 8443,
        cluster: None,
        enrollment: None,
        automation: None,
    }
}

pub(super) fn plane(links: Vec<FakeLink>) -> (StreamPlane<FakeLink>, StreamBindStates) {
    let states = StreamBindStates::new();
    let count = u32::try_from(links.len()).unwrap();
    let plane = StreamPlane::new(
        links
            .into_iter()
            .enumerate()
            .map(|(i, l)| (u32::try_from(i).unwrap(), l))
            .collect(),
        count,
        FdBudget::from_limit(65536),
        reserved(),
        states.clone(),
        TEST_ACK_TIMEOUT,
    )
    .with_source_ports(Box::new(|| Some(DEFAULT_RANGE_USABLE_PORTS)));
    (plane, states)
}

/// `U` at the default `ip_local_port_range` and no reserved port.
pub(super) const DEFAULT_RANGE_USABLE_PORTS: u64 = 27_208;

pub(super) fn udp(id: &str, port: u16) -> Stream {
    stream(id, StreamProtocol::Udp, port, port)
}

/// A UDP port free on 127.0.0.1 right now.
pub(super) fn free_udp_port() -> u16 {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

pub(super) fn stream(id: &str, protocol: StreamProtocol, first: u16, last: u16) -> Stream {
    Stream::new(
        id.into(),
        id.into(),
        protocol,
        "127.0.0.1".parse().unwrap(),
        first,
        last,
        Utc::now(),
    )
}

pub(super) fn tcp(id: &str, port: u16) -> Stream {
    stream(id, StreamProtocol::Tcp, port, port)
}

/// `n` consecutive TCP ports free on 127.0.0.1 right now.
pub(super) fn free_ports(n: u16) -> u16 {
    loop {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let first = probe.local_addr().unwrap().port();
        drop(probe);
        if first.checked_add(n).is_none() {
            continue;
        }
        let all_free = (first..first + n).all(|p| TcpListener::bind(("127.0.0.1", p)).is_ok());
        if all_free {
            return first;
        }
    }
}

pub(super) fn bindable(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub(super) fn seen(log: &Arc<StdMutex<Vec<Seen>>>) -> Vec<Seen> {
    log.lock().unwrap().clone()
}

pub(super) struct FixedTable(pub(super) Vec<Stream>);

impl lorica_stream::StreamTableSource for FixedTable {
    fn load(&self) -> Result<lorica_stream::StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(lorica_stream::StreamTable::new(self.0.clone(), &[]))
    }
}
