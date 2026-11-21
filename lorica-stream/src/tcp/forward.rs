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

//! The forwarding loop (Story 12.3 D-c): one task, two directions, one
//! fixed buffer each, no queue.
//!
//! A direction reads only into its empty buffer, then writes the whole
//! chunk before it reads again. A slow reader on one side leaves its
//! direction writing, so the other side's socket is not read, its
//! kernel receive buffer fills and TCP flow control pushes back on the
//! sender: memory per connection is the two buffers whatever the peers
//! do.
//!
//! The loop runs over any `AsyncRead + AsyncWrite` pair (Story 12.4
//! Interface edit I2): a plain socket, a TLS stream Lorica terminates, a
//! TLS stream it originates. It owns neither side and splits neither:
//! each turn polls both directions in one future, each direction reading
//! from one side and writing to the other through the same `&mut`, so no
//! lock is taken and no half is handed out.
//!
//! Every step is one read or one write, and a direction's state changes
//! only once that call has completed. A step is therefore cancel-safe,
//! and [`Forwarder::run`] can be dropped at any await and called again
//! with nothing lost or repeated: between a completed write and the next
//! read, with both directions [`DirectionState::Reading`] or
//! [`DirectionState::Closed`], no forwarded byte is in userspace. That
//! is the quiesce point Story 12.16 parks a connection on.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use lorica_config::models::{Stream, StreamEndReason};
use lorica_core::protocols::proxy_protocol::{classify_prefix, Prefix};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};

use super::bandwidth::TokenBucket;
use super::FORWARD_BUFFER_SIZE;
use crate::counters::{LinkStats, ProxyHeaderOutcome, StreamStats};
use crate::tracker::TrackedConnection;

/// Where one direction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionState {
    /// The buffer is empty; the next step reads.
    Reading,
    /// An untrusted client's first bytes, held until they are known not
    /// to open a PROXY signature (at most the 11 bytes of an unfinished
    /// one); the next step reads more.
    Classifying {
        /// Bytes held.
        filled: usize,
    },
    /// `filled` bytes were read and `written` of them sent on; the next
    /// step writes.
    Writing {
        /// Bytes in the buffer.
        filled: usize,
        /// Bytes of them already written.
        written: usize,
    },
    /// The direction has ended: its reader sent FIN and the FIN was
    /// passed on.
    Closed,
}

impl DirectionState {
    /// Forwarded bytes the direction holds in userspace.
    pub fn held_bytes(&self) -> usize {
        match *self {
            Self::Reading | Self::Closed => 0,
            Self::Classifying { filled } => filled,
            Self::Writing { filled, written } => filled - written,
        }
    }

    /// Whether the direction holds nothing and waits on a read or on
    /// nothing at all.
    pub fn is_at_rest(&self) -> bool {
        matches!(self, Self::Reading | Self::Closed)
    }
}

/// One end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The client socket.
    Client,
    /// The backend socket.
    Backend,
}

impl Side {
    fn end_reason(self) -> StreamEndReason {
        match self {
            Self::Client => StreamEndReason::ClientClose,
            Self::Backend => StreamEndReason::BackendClose,
        }
    }

    fn other(self) -> Side {
        match self {
            Self::Client => Self::Backend,
            Self::Backend => Self::Client,
        }
    }
}

enum Step {
    Progress,
    Finished,
    ProxySignature,
}

/// One direction of a connection.
pub struct Direction {
    /// Its length is the buffer's, fixed for the connection's life.
    buf: Vec<u8>,
    state: DirectionState,
    bucket: Option<TokenBucket>,
    /// A throttled direction's timer, allocated at its first wait for
    /// tokens and reset for every later one. It lives in the direction,
    /// so a wait survives a dropped [`Forwarder::run`].
    throttle: Option<Pin<Box<Sleep>>>,
    fin_after_write: bool,
    /// The reader's FIN was read and the writer's shutdown has started;
    /// the direction is [`DirectionState::Closed`] once it completes.
    shutting_down: bool,
    classify: bool,
    reads_from: Side,
    writes_to: Side,
    forwarded: u64,
}

impl std::fmt::Debug for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Direction")
            .field("state", &self.state)
            .field("reads_from", &self.reads_from)
            .field("forwarded", &self.forwarded)
            .finish_non_exhaustive()
    }
}

impl Direction {
    fn new(reads_from: Side, rate: Option<u64>, buf: Vec<u8>) -> Self {
        Direction {
            buf,
            state: DirectionState::Reading,
            bucket: rate.map(TokenBucket::new),
            throttle: None,
            fin_after_write: false,
            shutting_down: false,
            classify: false,
            reads_from,
            writes_to: reads_from.other(),
            forwarded: 0,
        }
    }

    /// Where the direction stands.
    pub fn state(&self) -> DirectionState {
        self.state
    }

    /// The size of its buffer, fixed for the connection's life.
    pub fn buffer_len(&self) -> usize {
        self.buf.len()
    }

    /// Bytes it has written on.
    pub fn forwarded(&self) -> u64 {
        self.forwarded
    }

    fn is_closed(&self) -> bool {
        self.state == DirectionState::Closed
    }

    /// Ready once the bucket, if any, allows a read. A bucket with
    /// tokens answers on the spot; one that must wait arms the
    /// direction's timer for the instant it will, which a timer already
    /// running keeps: nothing is spent while a direction waits, so that
    /// instant does not move.
    fn poll_throttle(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(bucket) = self.bucket.as_mut() else {
            return Poll::Ready(());
        };
        while let Some(at) = bucket.ready_at(Instant::now()) {
            let timer = match self.throttle.as_mut() {
                Some(timer) => {
                    if timer.is_elapsed() {
                        timer.as_mut().reset(at);
                    }
                    timer
                }
                None => self.throttle.insert(Box::pin(tokio::time::sleep_until(at))),
            };
            ready!(timer.as_mut().poll(cx));
        }
        Poll::Ready(())
    }

    fn poll_step<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<Result<Step, Side>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if self.shutting_down {
                // The peer may already be gone (`ENOTCONN`): that is an
                // end, not an error worth reporting.
                let _ = ready!(Pin::new(&mut *writer).poll_shutdown(cx));
                self.shutting_down = false;
                self.state = DirectionState::Closed;
                return Poll::Ready(Ok(Step::Finished));
            }
            match self.state {
                DirectionState::Closed => return Poll::Pending,
                DirectionState::Writing { filled, written } => {
                    let n = match ready!(
                        Pin::new(&mut *writer).poll_write(cx, &self.buf[written..filled])
                    ) {
                        Ok(0) | Err(_) => return Poll::Ready(Err(self.writes_to)),
                        Ok(n) => n,
                    };
                    self.forwarded += n as u64;
                    if written + n < filled {
                        self.state = DirectionState::Writing {
                            filled,
                            written: written + n,
                        };
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    self.state = DirectionState::Reading;
                    if self.fin_after_write {
                        self.shutting_down = true;
                        continue;
                    }
                    return Poll::Ready(Ok(Step::Progress));
                }
                DirectionState::Reading | DirectionState::Classifying { .. } => {
                    ready!(self.poll_throttle(cx));
                    let offset = self.state.held_bytes();
                    let room = self.buf.len() - offset;
                    let max = self
                        .bucket
                        .as_mut()
                        .map_or(room, |b| b.available().clamp(1, room));
                    let mut read = ReadBuf::new(&mut self.buf[offset..offset + max]);
                    let n = match ready!(Pin::new(&mut *reader).poll_read(cx, &mut read)) {
                        Ok(()) => read.filled().len(),
                        // A TLS peer that closed its socket without
                        // `close_notify`: an end, the FIN it is.
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                        Err(_) => return Poll::Ready(Err(self.reads_from)),
                    };
                    if n == 0 {
                        if offset == 0 {
                            self.shutting_down = true;
                            continue;
                        }
                        // A client that closes inside an unfinished
                        // signature sent no PROXY header: its bytes go
                        // on, then its FIN.
                        self.fin_after_write = true;
                        self.state = DirectionState::Writing {
                            filled: offset,
                            written: 0,
                        };
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    if let Some(bucket) = self.bucket.as_mut() {
                        bucket.spend(n);
                    }
                    let filled = offset + n;
                    if self.classify {
                        match classify_prefix(&self.buf[..filled]) {
                            Prefix::V1 | Prefix::V2 => {
                                return Poll::Ready(Ok(Step::ProxySignature))
                            }
                            Prefix::NeedMore => {
                                self.state = DirectionState::Classifying { filled };
                                return Poll::Ready(Ok(Step::Progress));
                            }
                            Prefix::NotProxy => self.classify = false,
                        }
                    }
                    self.state = DirectionState::Writing { filled, written: 0 };
                    return Poll::Ready(Ok(Step::Progress));
                }
            }
        }
    }
}

/// The most steps one turn of the loop takes before it looks at the
/// close signal and the timers again. tokio's cooperative budget, which
/// every socket call spends, ends a turn sooner on a busy runtime.
const STEPS_PER_TURN: usize = 32;

/// Where forwarded bytes are counted: the stream, and the backend's link
/// (Story 12.9 D-e) when the forwarder was given it.
#[derive(Clone, Copy)]
struct Tally<'a> {
    stream: &'a StreamStats,
    link: Option<&'a LinkStats>,
}

impl Tally<'_> {
    fn upload(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.stream.add_upload(bytes);
        if let Some(link) = self.link {
            link.add_upload(bytes);
        }
    }

    fn download(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.stream.add_download(bytes);
        if let Some(link) = self.link {
            link.add_download(bytes);
        }
    }
}

/// A step that ends a turn early.
enum Event {
    /// The direction reading from this side has ended.
    Finished(Side),
    /// An untrusted client opened with a PROXY signature.
    ProxySignature,
    /// A read or write on this side failed.
    Failed(Side),
}

/// What one turn of the two directions did.
struct Turn {
    /// At least one step completed.
    progressed: bool,
    event: Option<Event>,
}

/// Step the open directions in turn, alternating which goes first, until
/// neither can step, one ends the turn, or [`STEPS_PER_TURN`] passes;
/// then count what was written. Pending only when no step completed, so
/// a dropped turn loses nothing: every completed step is in its
/// direction's state.
fn poll_directions<C, B>(
    cx: &mut Context<'_>,
    upload: &mut Direction,
    download: &mut Direction,
    first: &mut Side,
    client: &mut C,
    backend: &mut B,
    tally: Tally<'_>,
) -> Poll<Turn>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (uploaded, downloaded) = (upload.forwarded, download.forwarded);
    let mut progressed = false;
    let mut event = None;
    'turn: for _ in 0..STEPS_PER_TURN {
        // Alternating which direction is polled first keeps a direction
        // that is always ready from starving the other.
        let order = [*first, first.other()];
        *first = first.other();
        let mut stepped = false;
        for side in order {
            let polled = match side {
                Side::Client if !upload.is_closed() => upload.poll_step(cx, client, backend),
                Side::Backend if !download.is_closed() => download.poll_step(cx, backend, client),
                _ => Poll::Pending,
            };
            match polled {
                Poll::Pending => {}
                Poll::Ready(Ok(Step::Progress)) => {
                    progressed = true;
                    stepped = true;
                }
                Poll::Ready(Ok(Step::Finished)) => {
                    event = Some(Event::Finished(side));
                    break 'turn;
                }
                Poll::Ready(Ok(Step::ProxySignature)) => {
                    event = Some(Event::ProxySignature);
                    break 'turn;
                }
                Poll::Ready(Err(failed)) => {
                    event = Some(Event::Failed(failed));
                    break 'turn;
                }
            }
        }
        if !stepped {
            break;
        }
    }
    tally.upload(upload.forwarded - uploaded);
    tally.download(download.forwarded - downloaded);
    if progressed || event.is_some() {
        Poll::Ready(Turn { progressed, event })
    } else {
        Poll::Pending
    }
}

/// The two directions of one connection and its timers.
#[derive(Debug)]
pub struct Forwarder {
    upload: Direction,
    download: Direction,
    first: Side,
    idle: Duration,
    total_deadline: Option<Instant>,
    last_activity: Instant,
    first_end: Option<Side>,
    stats: Arc<StreamStats>,
    link: Option<Arc<LinkStats>>,
}

impl Forwarder {
    /// A forwarder for a connection of `stream`, accepted at
    /// `accepted_at`. `preamble` (the client bytes the pre-forwarding
    /// phase read past what it needed) is the upload direction's first
    /// chunk. `classify` holds the client's first bytes until they are
    /// known not to open a PROXY signature (an untrusted peer on an
    /// accepting stream, D-k).
    ///
    /// The upload buffer is [`FORWARD_BUFFER_SIZE`], or the preamble's
    /// length when that is larger: a passthrough ClientHello with what
    /// followed it fills up to the 17 KiB of the ClientHello buffer
    /// (Story 12.4 D-b), and is replayed as one chunk, never split
    /// across a queue. The preamble's own allocation becomes that
    /// buffer, so a connection never holds the ClientHello buffer beside
    /// its two forwarding buffers.
    pub fn new(
        stream: &Stream,
        accepted_at: Instant,
        preamble: Vec<u8>,
        classify: bool,
        stats: Arc<StreamStats>,
    ) -> Self {
        let filled = preamble.len();
        let mut buf = preamble;
        buf.resize(FORWARD_BUFFER_SIZE.max(filled), 0);
        let mut upload = Direction::new(Side::Client, stream.upload_rate_bps, buf);
        upload.classify = classify;
        if filled > 0 {
            upload.state = DirectionState::Writing { filled, written: 0 };
        }
        Forwarder {
            upload,
            download: Direction::new(
                Side::Backend,
                stream.download_rate_bps,
                vec![0u8; FORWARD_BUFFER_SIZE],
            ),
            first: Side::Client,
            idle: Duration::from_secs(u64::from(stream.idle_timeout_s)),
            total_deadline: stream
                .total_timeout_s
                .map(|s| accepted_at + Duration::from_secs(u64::from(s))),
            last_activity: Instant::now(),
            first_end: None,
            stats,
            link: None,
        }
    }

    /// Count the forwarded bytes on the backend's link too (Story 12.9
    /// D-e), as they are written, beside the stream's.
    pub fn counting_link(mut self, link: Arc<LinkStats>) -> Self {
        self.link = Some(link);
        self
    }

    /// Client to backend.
    pub fn upload(&self) -> &Direction {
        &self.upload
    }

    /// Backend to client.
    pub fn download(&self) -> &Direction {
        &self.download
    }

    /// Whether no forwarded byte is in userspace: both directions at
    /// rest (D-c).
    pub fn at_quiesce_point(&self) -> bool {
        self.upload.state.is_at_rest() && self.download.state.is_at_rest()
    }

    fn natural_end(&self) -> StreamEndReason {
        self.first_end.unwrap_or(Side::Client).end_reason()
    }

    /// The next instant a timer may end the connection: the idle
    /// deadline from the last activity, or the total deadline when that
    /// comes first.
    fn next_deadline(&self) -> Instant {
        let idle_at = self.last_activity + self.idle;
        self.total_deadline
            .map_or(idle_at, |total| total.min(idle_at))
    }

    /// Forward between `client` and `backend` until both directions have
    /// ended, a timer fires, or the tracker closes the connection;
    /// returns the end reason. Dropping the future at any await leaves
    /// the forwarder consistent and callable again.
    ///
    /// One timer and one close wait serve the whole call, polled by
    /// reference on every turn: nothing is registered per read or write.
    /// The timer is set to [`Forwarder::next_deadline`]; when it fires on
    /// a connection that was active since, it is set again from the last
    /// activity, so an idle connection wakes once per idle window, not on
    /// a periodic check.
    pub async fn run<C, B>(
        &mut self,
        client: &mut C,
        backend: &mut B,
        tracked: &mut TrackedConnection,
    ) -> StreamEndReason
    where
        C: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let closed = tracked.closed();
        tokio::pin!(closed);
        let timer = tokio::time::sleep_until(self.next_deadline());
        tokio::pin!(timer);
        loop {
            if self.upload.is_closed() && self.download.is_closed() {
                return self.natural_end();
            }
            let (upload, download, first) = (&mut self.upload, &mut self.download, &mut self.first);
            let tally = Tally {
                stream: &self.stats,
                link: self.link.as_deref(),
            };
            let turn = tokio::select! {
                biased;
                reason = &mut closed => return reason,
                () = &mut timer => {
                    let now = Instant::now();
                    if self.total_deadline.is_some_and(|total| total <= now) {
                        return StreamEndReason::TotalTimeout;
                    }
                    if self.last_activity + self.idle <= now {
                        return StreamEndReason::IdleTimeout;
                    }
                    timer.as_mut().reset(self.next_deadline());
                    continue;
                }
                turn = std::future::poll_fn(|cx| {
                    poll_directions(cx, upload, download, first, client, backend, tally)
                }) => turn,
            };
            if turn.progressed {
                self.last_activity = Instant::now();
            }
            match turn.event {
                None => {}
                Some(Event::Finished(side)) => {
                    self.first_end.get_or_insert(side);
                }
                Some(Event::ProxySignature) => {
                    self.stats
                        .proxy_header(ProxyHeaderOutcome::RefusedUntrustedPeer);
                    return StreamEndReason::ProxyHeaderInvalid;
                }
                Some(Event::Failed(side)) => {
                    return self.first_end.get_or_insert(side).end_reason();
                }
            }
        }
    }
}

/// Close a socket so its peer sees a FIN: `shutdown(Both)`, errors
/// ignored (the peer may be gone).
pub fn close(socket: &TcpStream) {
    let _ = SockRef::from(socket).shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker::ConnectionTracker;
    use chrono::Utc;
    use lorica_config::models::StreamProtocol;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connected, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (connected.unwrap(), accepted.unwrap().0)
    }

    fn stream() -> Arc<Stream> {
        Arc::new(Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            1,
            1,
            Utc::now(),
        ))
    }

    #[tokio::test]
    async fn a_paused_reader_holds_the_forwarder_at_one_buffer() {
        const TOTAL: usize = 64 * 1024 * 1024;
        let (mut client_peer, mut client) = pair().await;
        let (mut backend, mut backend_peer) = pair().await;
        let snapshot = stream();
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::clone(&snapshot));
        let stats = Arc::new(StreamStats::default());
        let mut forwarder = Forwarder::new(&snapshot, Instant::now(), Vec::new(), false, stats);

        let writer = tokio::spawn(async move {
            let chunk = vec![7u8; 1024 * 1024];
            for _ in 0..TOTAL / chunk.len() {
                backend_peer.write_all(&chunk).await.unwrap();
            }
            backend_peer.shutdown().await.unwrap();
            backend_peer
        });

        // The client reads nothing: the download direction must stall
        // in `Writing`, never holding more than its one buffer.
        let mut stalled_rounds = 0;
        for _ in 0..40 {
            let ran = tokio::time::timeout(
                Duration::from_millis(25),
                forwarder.run(&mut client, &mut backend, &mut tracked),
            )
            .await;
            assert!(ran.is_err(), "the connection must not end while stalled");
            let down = forwarder.download().state();
            assert!(down.held_bytes() <= FORWARD_BUFFER_SIZE, "{down:?}");
            assert_eq!(forwarder.download().buffer_len(), FORWARD_BUFFER_SIZE);
            assert_eq!(forwarder.upload().state().held_bytes(), 0);
            if matches!(down, DirectionState::Writing { .. }) {
                stalled_rounds += 1;
            }
        }
        assert!(
            stalled_rounds > 30,
            "the writer stalled {stalled_rounds} rounds"
        );
        assert!(!writer.is_finished(), "backpressure reached the sender");
        assert!((forwarder.download().forwarded() as usize) < TOTAL);

        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 256 * 1024];
            let mut got = 0usize;
            loop {
                match client_peer.read(&mut buf).await.unwrap() {
                    0 => break,
                    n => got += n,
                }
            }
            got
        });
        let reason = loop {
            let ran = tokio::time::timeout(
                Duration::from_millis(25),
                forwarder.run(&mut client, &mut backend, &mut tracked),
            )
            .await;
            assert!(forwarder.download().state().held_bytes() <= FORWARD_BUFFER_SIZE);
            if let Ok(reason) = ran {
                break reason;
            }
        };
        assert_eq!(reader.await.unwrap(), TOTAL);
        assert_eq!(reason, StreamEndReason::BackendClose);
        assert!(forwarder.at_quiesce_point());
        assert_eq!(forwarder.download().forwarded() as usize, TOTAL);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn a_preamble_is_the_first_chunk_and_held_until_written() {
        let (_client_peer, client) = pair().await;
        drop(client);
        let snapshot = stream();
        let forwarder = Forwarder::new(
            &snapshot,
            Instant::now(),
            b"hello".to_vec(),
            false,
            Arc::new(StreamStats::default()),
        );
        assert_eq!(
            forwarder.upload().state(),
            DirectionState::Writing {
                filled: 5,
                written: 0
            }
        );
        assert_eq!(forwarder.upload().state().held_bytes(), 5);
        assert_eq!(forwarder.upload().buffer_len(), FORWARD_BUFFER_SIZE);
        assert!(!forwarder.at_quiesce_point());
    }

    #[tokio::test]
    async fn a_preamble_past_one_buffer_is_held_whole() {
        let preamble = vec![3u8; FORWARD_BUFFER_SIZE + 1_024];
        let forwarder = Forwarder::new(
            &stream(),
            Instant::now(),
            preamble.clone(),
            false,
            Arc::new(StreamStats::default()),
        );
        assert_eq!(forwarder.upload().buffer_len(), preamble.len());
        assert_eq!(forwarder.upload().state().held_bytes(), preamble.len());
        assert_eq!(forwarder.download().buffer_len(), FORWARD_BUFFER_SIZE);
    }

    /// A passthrough ClientHello, read into a buffer larger than one
    /// forwarding buffer, is forwarded from that same allocation: the
    /// connection does not keep it beside a copy.
    #[tokio::test]
    async fn a_preamble_buffer_becomes_the_upload_buffer() {
        let mut hello = vec![0u8; crate::tls::client_hello::CLIENTHELLO_BUFFER];
        hello.truncate(512);
        let allocation = hello.as_ptr();
        let forwarder = Forwarder::new(
            &stream(),
            Instant::now(),
            hello,
            false,
            Arc::new(StreamStats::default()),
        );
        assert_eq!(forwarder.upload.buf.as_ptr(), allocation);
        assert_eq!(forwarder.upload().buffer_len(), FORWARD_BUFFER_SIZE);
        assert_eq!(forwarder.upload().state().held_bytes(), 512);
    }

    /// The loop over streams that are not sockets, both half-closes
    /// carried in order: the client's end first, then the backend's.
    #[tokio::test]
    async fn any_stream_pair_is_forwarded_with_both_half_closes() {
        let (mut client_peer, mut client) = tokio::io::duplex(64);
        let (mut backend, mut backend_peer) = tokio::io::duplex(64);
        let snapshot = stream();
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::clone(&snapshot));
        let stats = Arc::new(StreamStats::default());
        let mut forwarder = Forwarder::new(
            &snapshot,
            Instant::now(),
            b"pre-".to_vec(),
            false,
            Arc::clone(&stats),
        );
        let run = tokio::spawn(async move {
            let reason = forwarder.run(&mut client, &mut backend, &mut tracked).await;
            (
                reason,
                forwarder.upload().forwarded(),
                forwarder.download().forwarded(),
            )
        });

        client_peer.write_all(b"amble").await.unwrap();
        client_peer.shutdown().await.unwrap();
        let mut uploaded = Vec::new();
        backend_peer.read_to_end(&mut uploaded).await.unwrap();
        assert_eq!(uploaded, b"pre-amble");

        backend_peer.write_all(b"answer").await.unwrap();
        backend_peer.shutdown().await.unwrap();
        let mut downloaded = Vec::new();
        client_peer.read_to_end(&mut downloaded).await.unwrap();
        assert_eq!(downloaded, b"answer");

        let (reason, up, down) = run.await.unwrap();
        assert_eq!(reason, StreamEndReason::ClientClose);
        assert_eq!((up, down), (9, 6));
    }

    /// A stream for the paused-clock tests below, `edit` applied.
    fn stream_with(edit: impl FnOnce(&mut Stream)) -> Stream {
        let mut s = Arc::unwrap_or_clone(stream());
        edit(&mut s);
        s
    }

    /// How late a timer may fire on a paused clock: tokio rounds a
    /// deadline up to its next millisecond tick.
    const TIMER_TICK: Duration = Duration::from_millis(1);

    /// A quiet connection ends `idle_timeout` at its idle timeout. On a
    /// paused clock the host's load cannot stretch the bound.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_ends_at_its_idle_timeout() {
        let (_client_peer, mut client) = tokio::io::duplex(64);
        let (mut backend, _backend_peer) = tokio::io::duplex(64);
        let snapshot = stream_with(|s| s.idle_timeout_s = 2);
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::new(snapshot.clone()));
        let started = Instant::now();
        let mut forwarder = Forwarder::new(
            &snapshot,
            started,
            Vec::new(),
            false,
            Arc::new(StreamStats::default()),
        );
        let reason = forwarder.run(&mut client, &mut backend, &mut tracked).await;
        let took = started.elapsed();
        assert_eq!(reason, StreamEndReason::IdleTimeout);
        assert!(
            took >= Duration::from_secs(2) && took <= Duration::from_secs(2) + TIMER_TICK,
            "{took:?}"
        );
    }

    /// Activity before the idle deadline moves it: the timer that fires
    /// at the first deadline finds the connection active since and is set
    /// again from the last activity, where the connection then ends.
    #[tokio::test(start_paused = true)]
    async fn activity_moves_the_idle_deadline_to_the_last_activity() {
        let (mut client_peer, mut client) = tokio::io::duplex(64);
        let (mut backend, mut backend_peer) = tokio::io::duplex(64);
        let snapshot = stream_with(|s| s.idle_timeout_s = 2);
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::new(snapshot.clone()));
        let started = Instant::now();
        let mut forwarder = Forwarder::new(
            &snapshot,
            started,
            Vec::new(),
            false,
            Arc::new(StreamStats::default()),
        );
        let late_word = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            client_peer.write_all(b"still here").await.unwrap();
            let mut got = [0u8; 10];
            backend_peer.read_exact(&mut got).await.unwrap();
            (client_peer, backend_peer)
        });
        let reason = forwarder.run(&mut client, &mut backend, &mut tracked).await;
        let took = started.elapsed();
        assert_eq!(reason, StreamEndReason::IdleTimeout);
        assert!(
            took >= Duration::from_millis(3_500)
                && took <= Duration::from_millis(3_500) + TIMER_TICK * 2,
            "{took:?}"
        );
        drop(late_word.await.unwrap());
    }

    /// A stream that counts the reads polled on it.
    struct CountingReads<S> {
        inner: S,
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CountingReads<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CountingReads<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A quiet connection under a long idle timeout is not woken until
    /// that timeout: its sockets are polled once, when the loop starts,
    /// and never again by a periodic check.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_connection_is_not_woken_before_its_idle_timeout() {
        let (_client_peer, client) = tokio::io::duplex(64);
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut client = CountingReads {
            inner: client,
            polls: Arc::clone(&polls),
        };
        let (mut backend, _backend_peer) = tokio::io::duplex(64);
        let snapshot = stream_with(|s| s.idle_timeout_s = 3_600);
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::new(snapshot.clone()));
        let mut forwarder = Forwarder::new(
            &snapshot,
            Instant::now(),
            Vec::new(),
            false,
            Arc::new(StreamStats::default()),
        );
        // The ten seconds are looked at first, so their end polls nothing.
        tokio::select! {
            biased;
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
            reason = forwarder.run(&mut client, &mut backend, &mut tracked) => {
                panic!("the connection is far from its idle timeout, ended {reason:?}")
            }
        }
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the quiet client was polled again before its idle timeout"
        );
    }

    /// A busy connection ends `total_timeout` at its total timeout,
    /// counted from the accept, whatever its traffic.
    #[tokio::test(start_paused = true)]
    async fn a_busy_connection_ends_at_its_total_timeout() {
        let (mut client_peer, mut client) = tokio::io::duplex(1_024);
        let (mut backend, mut backend_peer) = tokio::io::duplex(1_024);
        let snapshot = stream_with(|s| {
            s.idle_timeout_s = 1;
            s.total_timeout_s = Some(3);
        });
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::new(snapshot.clone()));
        let chatter = tokio::spawn(async move {
            while client_peer.write_all(b"tick").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while matches!(backend_peer.read(&mut buf).await, Ok(n) if n > 0) {}
        });
        let accepted_at = Instant::now();
        let mut forwarder = Forwarder::new(
            &snapshot,
            accepted_at,
            Vec::new(),
            false,
            Arc::new(StreamStats::default()),
        );
        let reason = forwarder.run(&mut client, &mut backend, &mut tracked).await;
        let took = accepted_at.elapsed();
        assert_eq!(reason, StreamEndReason::TotalTimeout);
        assert!(
            took >= Duration::from_secs(3) && took <= Duration::from_secs(3) + TIMER_TICK,
            "{took:?}"
        );
        assert!(
            forwarder.upload().forwarded() > 0,
            "the connection was busy"
        );
        chatter.abort();
        drain.abort();
    }

    /// 64 KiB at 16 KiB/s through the forwarder: one second of burst,
    /// then three seconds at the rate.
    #[tokio::test(start_paused = true)]
    async fn sixty_four_kib_at_sixteen_kib_per_second_take_three_seconds_through_the_forwarder() {
        const SIZE: usize = 64 * 1024;
        let (mut client_peer, mut client) = tokio::io::duplex(SIZE);
        let (mut backend, mut backend_peer) = tokio::io::duplex(SIZE);
        let snapshot = stream_with(|s| s.upload_rate_bps = Some(16 * 1024));
        let tracker = ConnectionTracker::new();
        let mut tracked = tracker.register(1, Arc::new(snapshot.clone()));
        let started = Instant::now();
        let mut forwarder = Forwarder::new(
            &snapshot,
            started,
            Vec::new(),
            false,
            Arc::new(StreamStats::default()),
        );
        let run =
            tokio::spawn(
                async move { forwarder.run(&mut client, &mut backend, &mut tracked).await },
            );
        client_peer.write_all(&vec![1u8; SIZE]).await.unwrap();
        client_peer.shutdown().await.unwrap();
        let mut got = Vec::new();
        backend_peer.read_to_end(&mut got).await.unwrap();
        let took = started.elapsed();
        assert_eq!(got.len(), SIZE);
        assert!(
            took >= Duration::from_millis(2_990) && took <= Duration::from_millis(3_100),
            "{took:?}"
        );
        backend_peer.shutdown().await.unwrap();
        assert_eq!(run.await.unwrap(), StreamEndReason::ClientClose);
    }
}
