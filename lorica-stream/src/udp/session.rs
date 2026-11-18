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

//! One UDP session's shared state and the bounds of D-b, written by the
//! receive loop (client datagrams) and by the session's task (backend
//! datagrams), plus the two sends: to the backend with the session's
//! PROXY header, and to the client from the address it targeted.
//!
//! Per session: `taken` client datagrams accepted, `q` of them forwarded
//! with `qb` bytes, `r` responses forwarded with `rb` bytes. With `R`
//! requests per session, `K` responses per request and the byte `ratio`:
//!
//! - a client datagram is accepted until `taken == R`, which retires the
//!   session (it takes no more; the client's next datagram opens a new
//!   one);
//! - a response is forwarded while `r < K x q` and `rb + len <= ratio x
//!   qb`, unless `unbounded_responses`;
//! - the session ends when `r == K x q` with `K >= 1`
//!   (`request_bound_reached` once retired, `response_bound_reached`
//!   before), on a response dropped for the byte bound
//!   (`response_bound_reached`), and right after its last request when
//!   `K == 0` or responses are unbounded (`request_bound_reached`).

use std::io::{self, IoSlice};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lorica_config::models::{DatagramDropReason, StreamEndReason, UdpSettings};
use lorica_shmem::{now_ns, RateLimits, RateVerdict, SourceKey, StreamCapsRegion};
use nix::libc;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockaddrStorage};
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::debug;

use super::{MAX_UDP_PAYLOAD, OPENING_QUEUE_DATAGRAMS};
use crate::counters::{ConnectFailureKind, LinkStats, StreamStats};

/// What identifies a session (D-a): the binding, the local address the
/// client targeted and the client, both canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionKey {
    pub(crate) bind_gen: u64,
    pub(crate) local: SocketAddr,
    pub(crate) client: SocketAddr,
}

/// The bounds of D-b a session applies, read once from its snapshot.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    requests: Option<u64>,
    responses_per_request: u64,
    bytes_ratio: u64,
    unbounded: bool,
    expects_responses: bool,
    max_datagram: usize,
}

impl Bounds {
    pub(crate) fn of(udp: &UdpSettings) -> Self {
        Bounds {
            requests: udp.requests_per_session.map(u64::from),
            responses_per_request: u64::from(udp.responses_per_request),
            bytes_ratio: u64::from(udp.response_bytes_ratio),
            unbounded: udp.unbounded_responses,
            expects_responses: udp.expects_responses(),
            max_datagram: udp.max_datagram_bytes as usize,
        }
    }

    /// Whether a session must hear back: a silent backend is then a
    /// failure at the idle timeout (D-i). The settings' own
    /// [`UdpSettings::expects_responses`], which the stream SLA reads too.
    pub(crate) fn expects_responses(&self) -> bool {
        self.expects_responses
    }

    /// Whether the session ends right after its last request, there being
    /// no owed response to wait for.
    fn ends_at_last_request(&self) -> bool {
        self.unbounded || self.responses_per_request == 0
    }
}

/// The per-source rates of a stream, as the region charges them.
pub(crate) fn rate_limits(udp: &UdpSettings) -> RateLimits {
    RateLimits {
        datagrams_per_s: u64::from(udp.source_datagram_rate),
        bytes_per_s: u64::from(udp.source_byte_rate),
    }
}

/// Whether a payload of `len` bytes still fits a UDP datagram once
/// `header` prefixes it (D-j).
pub(crate) fn fits(header: Option<&[u8]>, len: usize) -> bool {
    header.map_or(0, <[u8]>::len) + len <= MAX_UDP_PAYLOAD
}

/// The connect failure an error on a connected UDP socket reports, when
/// it is an ICMP error from the backend (D-i).
pub(crate) fn icmp_kind(error: &io::Error) -> Option<ConnectFailureKind> {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Some(ConnectFailureKind::Refused),
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            Some(ConnectFailureKind::Unreachable)
        }
        _ => None,
    }
}

/// How a session ends when something other than its own task decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ending {
    /// Its last request was forwarded and no response is owed.
    Natural(StreamEndReason),
    /// A send to the backend met an ICMP error.
    Icmp(ConnectFailureKind),
}

#[derive(Debug)]
enum Phase {
    /// The task is selecting a backend; the client datagrams wait here.
    Opening(Vec<Box<[u8]>>),
    /// Datagrams go out on the upstream socket.
    Open(Arc<UdpSocket>),
    /// The task has ended the session: a datagram of its key opens a new
    /// one.
    Ended,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    taken: u64,
    q: u64,
    qb: u64,
    r: u64,
    rb: u64,
    received: u64,
}

#[derive(Debug)]
struct State {
    phase: Phase,
    counts: Counts,
    retired: bool,
    last_activity: Instant,
    pending_end: Option<Ending>,
    /// The backend's link once the session has one: its bytes are
    /// counted there too (Story 12.9 D-e).
    link: Option<Arc<LinkStats>>,
}

/// What became of a client datagram offered to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    /// The session handled it (forwarded, held or dropped and counted);
    /// `retired` once it took its last request.
    Taken { retired: bool },
    /// The session takes no more requests: open a new one.
    Gone,
}

/// What became of a backend datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Response {
    /// The session's first backend datagram, forwarded or not: the
    /// breaker's success (D-i).
    pub(crate) first: bool,
    /// The session ends with this reason.
    pub(crate) end: Option<StreamEndReason>,
}

/// What a session forwarded, for its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Forwarded {
    pub(crate) datagrams_upload: u64,
    pub(crate) bytes_upload: u64,
    pub(crate) datagrams_download: u64,
    pub(crate) bytes_download: u64,
}

/// One session, shared by the receive loop and its task.
#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) key: SessionKey,
    bounds: Bounds,
    /// The PROXY v2 header, encoded once (D-j).
    header: Option<Box<[u8]>>,
    /// The region the session's source is charged in: the one it was
    /// admitted in, whose rate cell its held shard cell keeps.
    rates: Arc<StreamCapsRegion>,
    source: SourceKey,
    limits: RateLimits,
    stats: Arc<StreamStats>,
    state: Mutex<State>,
    /// Wakes the task when [`Session::take_pending_end`] has something.
    pub(crate) wake: Notify,
}

impl Session {
    /// A session opening with `first`, its first client datagram,
    /// already charged and admitted.
    #[allow(clippy::too_many_arguments)] // one call site, each argument a distinct part of D-a
    pub(crate) fn new(
        key: SessionKey,
        bounds: Bounds,
        header: Option<Box<[u8]>>,
        rates: Arc<StreamCapsRegion>,
        source: SourceKey,
        limits: RateLimits,
        stats: Arc<StreamStats>,
        first: &[u8],
    ) -> Self {
        let counts = Counts {
            taken: 1,
            ..Counts::default()
        };
        Session {
            key,
            bounds,
            header,
            rates,
            source,
            limits,
            stats,
            state: Mutex::new(State {
                phase: Phase::Opening(vec![Box::from(first)]),
                counts,
                retired: bounds.requests.is_some_and(|r| counts.taken >= r),
                last_activity: Instant::now(),
                pending_end: None,
                link: None,
            }),
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Every critical section leaves the counts consistent, so a
        // poisoned lock is still a usable one.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the session took its last request.
    pub(crate) fn retired(&self) -> bool {
        self.lock().retired
    }

    /// The bounds it applies.
    pub(crate) fn bounds(&self) -> &Bounds {
        &self.bounds
    }

    /// The region its source is charged and counted in.
    pub(crate) fn region(&self) -> &Arc<StreamCapsRegion> {
        &self.rates
    }

    /// Take one more client datagram: charge its source, then forward it
    /// (or hold it while the session opens). Synchronous: the receive
    /// loop calls it.
    pub(crate) fn offer(&self, payload: &[u8]) -> Offer {
        let mut st = self.lock();
        if st.retired || matches!(st.phase, Phase::Ended) {
            return Offer::Gone;
        }
        let verdict =
            self.rates
                .charge_rate(self.source, payload.len() as u64, self.limits, now_ns());
        match verdict {
            // `TableFull` cannot come back for a source holding a session:
            // its shard cell keeps its rate cell from eviction.
            RateVerdict::Allowed | RateVerdict::TableFull => {}
            RateVerdict::DatagramRate => {
                self.stats.dropped(DatagramDropReason::SourceDatagramRate);
                return Offer::Taken { retired: false };
            }
            RateVerdict::ByteRate => {
                self.stats.dropped(DatagramDropReason::SourceByteRate);
                return Offer::Taken { retired: false };
            }
        }
        if !fits(self.header.as_deref(), payload.len()) {
            self.stats.dropped(DatagramDropReason::RequestOversize);
            return Offer::Taken { retired: false };
        }
        if matches!(&st.phase, Phase::Opening(queue) if queue.len() >= OPENING_QUEUE_DATAGRAMS) {
            self.stats.dropped(DatagramDropReason::SendFailed);
            return Offer::Taken { retired: false };
        }
        st.counts.taken += 1;
        st.retired = self.bounds.requests.is_some_and(|r| st.counts.taken >= r);
        let open = match &mut st.phase {
            Phase::Opening(queue) => {
                queue.push(Box::from(payload));
                None
            }
            Phase::Open(socket) => Some(Arc::clone(socket)),
            Phase::Ended => None,
        };
        if let Some(socket) = open {
            self.forward_request(&mut st, &socket, payload);
            self.end_if_last_request(&mut st);
        }
        Offer::Taken {
            retired: st.retired,
        }
    }

    /// Count the bytes forwarded from now on on `link` too, the
    /// backend's: called before [`Session::opened`] sends what was held.
    pub(crate) fn counting_link(&self, link: Arc<LinkStats>) {
        self.lock().link = Some(link);
    }

    /// The upstream socket is connected: send what was held, in order,
    /// and from now on forward at once.
    pub(crate) fn opened(&self, socket: &Arc<UdpSocket>) {
        let mut st = self.lock();
        let held = match std::mem::replace(&mut st.phase, Phase::Open(Arc::clone(socket))) {
            Phase::Opening(held) => held,
            other => {
                st.phase = other;
                return;
            }
        };
        for payload in &held {
            self.forward_request(&mut st, socket, payload);
        }
        self.end_if_last_request(&mut st);
    }

    fn forward_request(&self, st: &mut State, socket: &UdpSocket, payload: &[u8]) {
        match send_upstream(socket, self.header.as_deref(), payload) {
            Ok(_) => {
                let len = payload.len() as u64;
                st.counts.q += 1;
                st.counts.qb += len;
                st.last_activity = Instant::now();
                self.stats.datagram_upload(len);
                if let Some(link) = &st.link {
                    link.add_upload(len);
                }
            }
            Err(e) => match icmp_kind(&e) {
                Some(kind) => {
                    st.pending_end.get_or_insert(Ending::Icmp(kind));
                    self.wake.notify_one();
                }
                None => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!(error = %e, "UDP session datagram not sent to its backend");
                    }
                    self.stats.dropped(DatagramDropReason::SendFailed);
                }
            },
        }
    }

    fn end_if_last_request(&self, st: &mut State) {
        if st.retired && self.bounds.ends_at_last_request() {
            st.pending_end
                .get_or_insert(Ending::Natural(StreamEndReason::RequestBoundReached));
            self.wake.notify_one();
        }
    }

    /// Take one backend datagram: apply the response bounds and hand
    /// what passes to `send`, the send to the client.
    pub(crate) fn on_response(
        &self,
        payload: &[u8],
        send: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> Response {
        let mut st = self.lock();
        st.counts.received += 1;
        let mut response = Response {
            first: st.counts.received == 1,
            end: None,
        };
        let len = payload.len() as u64;
        if payload.len() > self.bounds.max_datagram {
            self.stats.dropped(DatagramDropReason::ResponseOversize);
            return response;
        }
        let c = st.counts;
        if !self.bounds.unbounded {
            if c.r >= self.bounds.responses_per_request.saturating_mul(c.q) {
                self.stats.dropped(DatagramDropReason::ResponseCountBound);
                return response;
            }
            if c.rb.saturating_add(len) > self.bounds.bytes_ratio.saturating_mul(c.qb) {
                self.stats.dropped(DatagramDropReason::ResponseByteBound);
                response.end = Some(StreamEndReason::ResponseBoundReached);
                st.phase = Phase::Ended;
                return response;
            }
        }
        match send(payload) {
            Ok(_) => {
                st.counts.r += 1;
                st.counts.rb += len;
                st.last_activity = Instant::now();
                self.stats.datagram_download(len);
                if let Some(link) = &st.link {
                    link.add_download(len);
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    debug!(error = %e, "UDP session response not sent to its client");
                }
                self.stats.dropped(DatagramDropReason::SendFailed);
            }
        }
        let owed = self
            .bounds
            .responses_per_request
            .saturating_mul(st.counts.q);
        if self.bounds.expects_responses() && st.counts.r == owed {
            response.end = Some(if st.retired {
                StreamEndReason::RequestBoundReached
            } else {
                StreamEndReason::ResponseBoundReached
            });
            // Ended under the same lock as the send: a client that sends
            // again the moment its answer lands opens a new session,
            // rather than joining this one in the instant before its
            // task ends it, where its datagram would be forwarded and
            // its answer lost.
            st.phase = Phase::Ended;
        }
        response
    }

    /// The ending a client datagram's path decided, if any.
    pub(crate) fn take_pending_end(&self) -> Option<Ending> {
        self.lock().pending_end.take()
    }

    /// The last datagram forwarded either way, or the session's start.
    pub(crate) fn last_activity(&self) -> Instant {
        self.lock().last_activity
    }

    /// Whether any backend datagram arrived.
    pub(crate) fn received_any(&self) -> bool {
        self.lock().counts.received > 0
    }

    /// Stop taking datagrams: the next one of the key opens a new session.
    /// Drops the session's own handle on the upstream socket.
    pub(crate) fn end(&self) {
        self.lock().phase = Phase::Ended;
    }

    /// What it forwarded.
    pub(crate) fn forwarded(&self) -> Forwarded {
        let c = self.lock().counts;
        Forwarded {
            datagrams_upload: c.q,
            bytes_upload: c.qb,
            datagrams_download: c.r,
            bytes_download: c.rb,
        }
    }
}

// Both sends below go straight to the kernel rather than through tokio's
// `try_send`: tokio answers `WouldBlock` on a socket whose write readiness
// its reactor has not observed yet, which is every session socket at its
// first send. Nothing ever awaits these sockets' write readiness, so no
// readiness state needs clearing; a `WouldBlock` here is the kernel's,
// a full send buffer.

/// Send `payload` on the connected upstream socket, after `header` when
/// the stream sends PROXY v2: one `sendmsg` with two iovecs, nothing
/// copied (D-j). Never waits.
pub(crate) fn send_upstream(
    socket: &UdpSocket,
    header: Option<&[u8]>,
    payload: &[u8],
) -> io::Result<usize> {
    let socket = SockRef::from(socket);
    match header {
        None => socket.send(payload),
        Some(header) => socket.send_vectored(&[IoSlice::new(header), IoSlice::new(payload)]),
    }
}

/// Send `payload` to `client` from the slot socket. `reply_from` is the
/// address the client targeted on a wildcard socket, set as the source
/// through `IP_PKTINFO` / `IPV6_PKTINFO` (D-g); both it and `client` are
/// in the socket's family, as the receive path reported them. Never
/// waits.
pub(crate) fn send_to_client(
    slot: &UdpSocket,
    payload: &[u8],
    client: SocketAddr,
    reply_from: Option<IpAddr>,
) -> io::Result<usize> {
    let Some(from) = reply_from else {
        return SockRef::from(slot).send_to(payload, &client.into());
    };
    let iov = [IoSlice::new(payload)];
    let to = SockaddrStorage::from(client);
    let fd = slot.as_raw_fd();
    let sent = match from {
        IpAddr::V4(from) => {
            let info = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from(from).to_be(),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            let cmsg = [ControlMessage::Ipv4PacketInfo(&info)];
            sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), Some(&to))
        }
        IpAddr::V6(from) => {
            let info = libc::in6_pktinfo {
                ipi6_addr: libc::in6_addr {
                    s6_addr: from.octets(),
                },
                ipi6_ifindex: 0,
            };
            let cmsg = [ControlMessage::Ipv6PacketInfo(&info)];
            sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), Some(&to))
        }
    };
    sent.map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_core::protocols::proxy_protocol::{encode_v2_dgram, V2_SIGNATURE};

    fn session(udp: &UdpSettings, first: &[u8]) -> Session {
        let (region, _fd) = StreamCapsRegion::create(64, 1, 1).unwrap();
        Session::new(
            SessionKey {
                bind_gen: 1,
                local: "192.0.2.1:53".parse().unwrap(),
                client: "192.0.2.10:5000".parse().unwrap(),
            },
            Bounds::of(udp),
            None,
            Arc::new(region),
            SourceKey::of("192.0.2.10".parse().unwrap()),
            rate_limits(udp),
            Arc::new(StreamStats::default()),
            first,
        )
    }

    /// A connected socket towards a sink nobody reads.
    async fn upstream() -> (Arc<UdpSocket>, UdpSocket) {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(sink.local_addr().unwrap()).await.unwrap();
        (Arc::new(socket), sink)
    }

    fn sent(payload: &[u8]) -> io::Result<usize> {
        Ok(payload.len())
    }

    #[tokio::test]
    async fn one_answer_per_query_ends_the_session_on_its_answer() {
        let udp = UdpSettings::default();
        let s = session(&udp, &[0u8; 50]);
        let (socket, _sink) = upstream().await;
        s.opened(&socket);
        let first = s.on_response(&[0u8; 1_200], sent);
        assert_eq!(
            first,
            Response {
                first: true,
                end: Some(StreamEndReason::ResponseBoundReached)
            }
        );
        assert_eq!(s.forwarded().datagrams_download, 1);
        assert_eq!(
            s.offer(&[0u8; 50]),
            Offer::Gone,
            "the next query, sent the moment the answer lands, opens a new session"
        );
        assert_eq!(s.forwarded().datagrams_upload, 1);
    }

    #[tokio::test]
    async fn the_byte_allowance_is_the_ratio_of_the_request_bytes() {
        let udp = UdpSettings {
            responses_per_request: 4,
            response_bytes_ratio: 2,
            ..UdpSettings::default()
        };
        let s = session(&udp, &[0u8; 100]);
        let (socket, _sink) = upstream().await;
        s.opened(&socket);
        assert_eq!(s.on_response(&[0u8; 150], sent).end, None);
        assert_eq!(s.on_response(&[0u8; 50], sent).end, None, "exactly 200");
        let over = s.on_response(&[0u8; 1], sent);
        assert_eq!(over.end, Some(StreamEndReason::ResponseBoundReached));
        assert_eq!(s.forwarded().bytes_download, 200);
        assert_eq!(s.offer(&[0u8; 100]), Offer::Gone, "the allowance is spent");
    }

    #[tokio::test]
    async fn responses_past_the_count_are_dropped_and_retirement_names_the_request_bound() {
        let udp = UdpSettings {
            requests_per_session: Some(2),
            responses_per_request: 1,
            ..UdpSettings::default()
        };
        let s = session(&udp, b"q1");
        let (socket, _sink) = upstream().await;
        s.opened(&socket);
        assert_eq!(s.offer(b"q2"), Offer::Taken { retired: true });
        assert_eq!(
            s.offer(b"q3"),
            Offer::Gone,
            "a retired session takes no more"
        );
        assert_eq!(s.on_response(b"a1", sent).end, None);
        assert_eq!(
            s.on_response(b"a2", sent).end,
            Some(StreamEndReason::RequestBoundReached)
        );
    }

    #[tokio::test]
    async fn no_response_expected_ends_right_after_the_last_request() {
        let udp = UdpSettings {
            requests_per_session: Some(2),
            responses_per_request: 0,
            ..UdpSettings::default()
        };
        let s = session(&udp, b"m1");
        let (socket, _sink) = upstream().await;
        s.opened(&socket);
        assert_eq!(s.take_pending_end(), None);
        assert_eq!(s.on_response(b"x", sent).end, None, "dropped, counted");
        assert_eq!(s.offer(b"m2"), Offer::Taken { retired: true });
        assert_eq!(
            s.take_pending_end(),
            Some(Ending::Natural(StreamEndReason::RequestBoundReached))
        );
        assert_eq!(s.forwarded().datagrams_upload, 2);
        assert_eq!(s.forwarded().datagrams_download, 0);
    }

    #[tokio::test]
    async fn unbounded_responses_apply_neither_bound() {
        let udp = UdpSettings {
            responses_per_request: 1,
            response_bytes_ratio: 1,
            unbounded_responses: true,
            requests_per_session: None,
            ..UdpSettings::default()
        };
        let s = session(&udp, b"q");
        let (socket, _sink) = upstream().await;
        s.opened(&socket);
        for _ in 0..10 {
            assert_eq!(s.on_response(&[0u8; 500], sent).end, None);
        }
        assert_eq!(s.forwarded().datagrams_download, 10);
    }

    #[tokio::test]
    async fn the_opening_queue_holds_a_few_datagrams_then_drops() {
        let udp = UdpSettings {
            requests_per_session: None,
            ..UdpSettings::default()
        };
        let s = session(&udp, b"q0");
        for n in 1..OPENING_QUEUE_DATAGRAMS {
            assert_eq!(
                s.offer(format!("q{n}").as_bytes()),
                Offer::Taken { retired: false }
            );
        }
        assert_eq!(s.offer(b"over"), Offer::Taken { retired: false });
        assert_eq!(
            s.stats.snapshot().dropped[&DatagramDropReason::SendFailed],
            1,
            "the datagram past the queue"
        );
        let (socket, sink) = upstream().await;
        s.opened(&socket);
        assert_eq!(
            s.forwarded().datagrams_upload,
            OPENING_QUEUE_DATAGRAMS as u64
        );
        let mut buf = [0u8; 16];
        for n in 0..OPENING_QUEUE_DATAGRAMS {
            let len = sink.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], format!("q{n}").as_bytes(), "in order");
        }
    }

    #[test]
    fn the_largest_payload_with_a_header_is_the_udp_maximum() {
        let header = encode_v2_dgram(
            "192.0.2.10:5000".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
        );
        assert!(fits(Some(&header), MAX_UDP_PAYLOAD - header.len()));
        assert!(!fits(Some(&header), MAX_UDP_PAYLOAD - header.len() + 1));
        assert!(fits(None, MAX_UDP_PAYLOAD));
    }

    #[test]
    fn the_ipv6_header_carries_both_addresses_over_dgram() {
        let header = encode_v2_dgram(
            "[2001:db8::10]:5000".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        );
        let mut expected = V2_SIGNATURE.to_vec();
        expected.extend_from_slice(&[0x21, 0x22, 0x00, 36]);
        expected.extend_from_slice(
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        expected.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        expected.extend_from_slice(&5000u16.to_be_bytes());
        expected.extend_from_slice(&53u16.to_be_bytes());
        assert_eq!(header, expected);
        assert_eq!(header.len(), 52);
    }

    #[test]
    fn icmp_errors_map_to_their_failure_kinds() {
        for (kind, expected) in [
            (
                io::ErrorKind::ConnectionRefused,
                Some(ConnectFailureKind::Refused),
            ),
            (
                io::ErrorKind::HostUnreachable,
                Some(ConnectFailureKind::Unreachable),
            ),
            (
                io::ErrorKind::NetworkUnreachable,
                Some(ConnectFailureKind::Unreachable),
            ),
            (io::ErrorKind::WouldBlock, None),
        ] {
            assert_eq!(icmp_kind(&io::Error::from(kind)), expected, "{kind:?}");
        }
    }
}
