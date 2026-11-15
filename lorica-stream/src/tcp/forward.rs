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
//! Every step is one read or one write, and a direction's state changes
//! only once that call has completed. A step is therefore cancel-safe,
//! and [`Forwarder::run`] can be dropped at any await and called again
//! with nothing lost or repeated: between a completed write and the next
//! read, with both directions [`DirectionState::Reading`] or
//! [`DirectionState::Closed`], no forwarded byte is in userspace. That
//! is the quiesce point Story 12.16 parks a connection on.

use std::time::Duration;

use lorica_config::models::{Stream, StreamEndReason};
use lorica_core::protocols::proxy_protocol::{classify_prefix, Prefix};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, MissedTickBehavior};

use super::bandwidth::TokenBucket;
use super::FORWARD_BUFFER_SIZE;
use crate::counters::{ProxyHeaderOutcome, StreamStats};
use crate::tracker::TrackedConnection;

/// How often the idle timeout is checked against the last activity: it
/// fires within this much of its value, with no timer re-armed per read.
pub const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

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
}

enum Step {
    Progress,
    Finished,
    ProxySignature,
}

/// One direction of a connection.
pub struct Direction {
    buf: Box<[u8]>,
    state: DirectionState,
    bucket: Option<TokenBucket>,
    fin_after_write: bool,
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
    fn new(reads_from: Side, writes_to: Side, rate: Option<u64>) -> Self {
        Direction {
            buf: vec![0u8; FORWARD_BUFFER_SIZE].into_boxed_slice(),
            state: DirectionState::Reading,
            bucket: rate.map(TokenBucket::new),
            fin_after_write: false,
            classify: false,
            reads_from,
            writes_to,
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

    async fn finish<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) {
        // The peer may already be gone (`ENOTCONN`): that is an end, not
        // an error worth reporting.
        let _ = writer.shutdown().await;
        self.state = DirectionState::Closed;
    }

    async fn step<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        count: impl Fn(u64),
    ) -> Result<Step, Side>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match self.state {
            DirectionState::Closed => std::future::pending().await,
            DirectionState::Writing { filled, written } => {
                let n = match writer.write(&self.buf[written..filled]).await {
                    Ok(0) | Err(_) => return Err(self.writes_to),
                    Ok(n) => n,
                };
                self.forwarded += n as u64;
                count(n as u64);
                if written + n < filled {
                    self.state = DirectionState::Writing {
                        filled,
                        written: written + n,
                    };
                    return Ok(Step::Progress);
                }
                if self.fin_after_write {
                    self.finish(writer).await;
                    return Ok(Step::Finished);
                }
                self.state = DirectionState::Reading;
                Ok(Step::Progress)
            }
            DirectionState::Reading | DirectionState::Classifying { .. } => {
                let offset = self.state.held_bytes();
                if let Some(bucket) = self.bucket.as_mut() {
                    bucket.ready().await;
                }
                let room = self.buf.len() - offset;
                let max = self
                    .bucket
                    .as_mut()
                    .map_or(room, |b| b.available().clamp(1, room));
                let n = match reader.read(&mut self.buf[offset..offset + max]).await {
                    Ok(n) => n,
                    Err(_) => return Err(self.reads_from),
                };
                if n == 0 {
                    if offset == 0 {
                        self.finish(writer).await;
                        return Ok(Step::Finished);
                    }
                    // A client that closes inside an unfinished
                    // signature sent no PROXY header: its bytes go on,
                    // then its FIN.
                    self.fin_after_write = true;
                    self.state = DirectionState::Writing {
                        filled: offset,
                        written: 0,
                    };
                    return Ok(Step::Progress);
                }
                if let Some(bucket) = self.bucket.as_mut() {
                    bucket.spend(n);
                }
                let filled = offset + n;
                if self.classify {
                    match classify_prefix(&self.buf[..filled]) {
                        Prefix::V1 | Prefix::V2 => return Ok(Step::ProxySignature),
                        Prefix::NeedMore => {
                            self.state = DirectionState::Classifying { filled };
                            return Ok(Step::Progress);
                        }
                        Prefix::NotProxy => self.classify = false,
                    }
                }
                self.state = DirectionState::Writing { filled, written: 0 };
                Ok(Step::Progress)
            }
        }
    }
}

/// Wait until `deadline`, or forever without one.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// The two directions of one connection and its timers.
#[derive(Debug)]
pub struct Forwarder {
    upload: Direction,
    download: Direction,
    idle: Duration,
    total_deadline: Option<Instant>,
    last_activity: Instant,
    first_end: Option<Side>,
    stats: std::sync::Arc<StreamStats>,
}

impl Forwarder {
    /// A forwarder for a connection of `stream`, accepted at
    /// `accepted_at`. `preamble` (the client bytes the pre-forwarding
    /// phase read past what it needed) is the upload direction's first
    /// chunk. `classify` holds the client's first bytes until they are
    /// known not to open a PROXY signature (an untrusted peer on an
    /// accepting stream, D-k).
    pub fn new(
        stream: &Stream,
        accepted_at: Instant,
        preamble: &[u8],
        classify: bool,
        stats: std::sync::Arc<StreamStats>,
    ) -> Self {
        let mut upload = Direction::new(Side::Client, Side::Backend, stream.upload_rate_bps);
        upload.classify = classify;
        if !preamble.is_empty() {
            upload.buf[..preamble.len()].copy_from_slice(preamble);
            upload.state = DirectionState::Writing {
                filled: preamble.len(),
                written: 0,
            };
        }
        Forwarder {
            upload,
            download: Direction::new(Side::Backend, Side::Client, stream.download_rate_bps),
            idle: Duration::from_secs(u64::from(stream.idle_timeout_s)),
            total_deadline: stream
                .total_timeout_s
                .map(|s| accepted_at + Duration::from_secs(u64::from(s))),
            last_activity: Instant::now(),
            first_end: None,
            stats,
        }
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

    /// Forward until both directions have ended, a timer fires, or the
    /// tracker closes the connection; returns the end reason. Dropping
    /// the future at any await leaves the forwarder consistent and
    /// callable again.
    pub async fn run(
        &mut self,
        client: &mut TcpStream,
        backend: &mut TcpStream,
        tracked: &mut TrackedConnection,
    ) -> StreamEndReason {
        let (mut client_read, mut client_write) = client.split();
        let (mut backend_read, mut backend_write) = backend.split();
        let mut idle_check =
            tokio::time::interval_at(Instant::now() + IDLE_CHECK_INTERVAL, IDLE_CHECK_INTERVAL);
        idle_check.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            if self.upload.is_closed() && self.download.is_closed() {
                return self.natural_end();
            }
            let stats = &self.stats;
            let (stepped, from) = tokio::select! {
                biased;
                reason = tracked.closed() => return reason,
                _ = sleep_until_opt(self.total_deadline) => return StreamEndReason::TotalTimeout,
                _ = idle_check.tick() => {
                    if self.last_activity.elapsed() >= self.idle {
                        return StreamEndReason::IdleTimeout;
                    }
                    continue;
                }
                stepped = self.upload.step(&mut client_read, &mut backend_write,
                                           |n| stats.add_upload(n)),
                    if !self.upload.is_closed() => (stepped, Side::Client),
                stepped = self.download.step(&mut backend_read, &mut client_write,
                                             |n| stats.add_download(n)),
                    if !self.download.is_closed() => (stepped, Side::Backend),
            };
            match stepped {
                Ok(Step::Progress) => self.last_activity = Instant::now(),
                Ok(Step::Finished) => {
                    self.first_end.get_or_insert(from);
                }
                Ok(Step::ProxySignature) => {
                    self.stats
                        .proxy_header(ProxyHeaderOutcome::RefusedUntrustedPeer);
                    return StreamEndReason::ProxyHeaderInvalid;
                }
                Err(side) => {
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
    use std::sync::Arc;
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
        let mut forwarder = Forwarder::new(&snapshot, Instant::now(), &[], false, stats);

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
            b"hello",
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
        assert!(!forwarder.at_quiesce_point());
    }
}
