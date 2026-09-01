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

//! Pipelined RPC endpoint layered over any async byte stream.
//!
//! Implements the RPC framework described in
//! `docs/architecture/worker-shared-state.md` § 4. Each endpoint:
//!
//! - owns one `AsyncRead + AsyncWrite` stream split into a reader and
//!   a writer half via [`tokio::io::split`] (Story 9.1 AC #1: any
//!   transport - the worker plane keeps its `UnixStream`, the cluster
//!   plane brings a TLS stream);
//! - is generic over a [`Frame`] type (Story 9.1 AC #2) so the
//!   cluster message set can live in a separate proto package and
//!   version independently of the worker `Envelope`;
//! - spawns a background reader task that decodes frames and
//!   demultiplexes responses against an in-flight map keyed by
//!   `sequence`, routing incoming requests to the caller via an mpsc
//!   channel;
//! - spawns a background writer task that drains a bounded
//!   `tokio::sync::mpsc` queue into the stream.
//!
//! `RpcEndpoint::request` is the hot-path entry point. It allocates a
//! monotonically increasing sequence, installs a oneshot in the in-flight
//! map, enqueues the request, and awaits the matching response with a
//! per-request timeout. The in-flight entry is always removed on exit
//! (Ok, Closed, or Timeout) so dead senders do not linger.
//!
//! Transport limits are per-endpoint ([`RpcLimits`], Story 9.1 AC #3):
//! the historical crate constants were tuned for a same-host UDS and
//! are wrong for a WAN. An oversize outbound frame is a typed
//! [`ChannelError::MessageTooLarge`] at enqueue time, never a silent
//! drop (AC #4), and the in-flight map is bounded
//! ([`ChannelError::InflightFull`]).
//!
//! Wire format: `[8 bytes LE length][prost-encoded frame]`.
//! The legacy bare `Command`/`Response` wire format used by
//! [`crate::CommandChannel`] is *not* compatible with `RpcEndpoint`; a
//! given socket pair must use one or the other.

use std::collections::HashMap;
use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::messages::{command, envelope, Command, CommandType, Envelope, Response};
use crate::ChannelError;

/// Default per-request timeout when the caller does not specify one.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-endpoint transport limits (Story 9.1 AC #3). The defaults are
/// the historical crate constants, tuned for a same-host Unix stream;
/// a WAN endpoint (cluster plane) overrides them.
#[derive(Debug, Clone)]
pub struct RpcLimits {
    /// Maximum frame size on the wire, both directions. An outbound
    /// frame over the limit is a typed [`ChannelError::MessageTooLarge`]
    /// at enqueue; an inbound frame over the limit kills the
    /// connection (a peer that ignores the limit is misbehaving).
    pub max_message_size: u64,
    /// Bounded outbound queue capacity. Under backpressure `request`
    /// awaits `tx_out.send(...)`, which the per-request timeout
    /// bounds; a stuck peer cannot blow the queue.
    pub outbound_queue_cap: usize,
    /// If enqueuing to the outbound channel takes longer than this,
    /// log a warning so operators can spot a stuck peer. Advisory
    /// only - the per-request timeout stays the authoritative bound.
    pub slow_enqueue_warn: Duration,
    /// Default per-request timeout for callers that use it.
    pub default_request_timeout: Duration,
    /// Upper bound on concurrently in-flight requests (Story 9.1
    /// AC #4). A request past the cap fails with
    /// [`ChannelError::InflightFull`] instead of growing the map
    /// unboundedly against a peer that stopped replying.
    pub max_inflight: usize,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024,
            outbound_queue_cap: 256,
            slow_enqueue_warn: Duration::from_millis(10),
            default_request_timeout: DEFAULT_REQUEST_TIMEOUT,
            // Generous versus the documented reload-frequency volume
            // of the worker plane, small enough that a dead peer
            // cannot hold more than ~a few MB of oneshot senders.
            max_inflight: 1024,
        }
    }
}

/// A decoded frame split into its routing kind (Story 9.1 AC #2).
pub enum FrameKind<Q, R> {
    /// A request from the peer, routed to the incoming queue.
    Request(Q),
    /// A response to one of our requests, demuxed by sequence.
    Response(R),
    /// A frame carrying neither (empty oneof); logged and dropped.
    Empty,
}

/// The message set an [`RpcEndpoint`] speaks (Story 9.1 AC #2).
///
/// The worker plane's [`Envelope`] is the canonical implementation;
/// the cluster plane (Story 9.2) brings its own proto package with a
/// disjoint message set that versions independently. A frame exposes
/// `sequence` accessors for both halves so the endpoint can pipeline
/// and demultiplex without knowing the concrete types.
pub trait Frame: Message + Default + Send + Sync + 'static {
    /// The request half routed to [`IncomingRequests`].
    type Request: Send + 'static;
    /// The response half demuxed against the in-flight map.
    type Response: Send + 'static;

    /// Split a decoded frame into its routing kind.
    fn into_kind(self) -> FrameKind<Self::Request, Self::Response>;
    /// Wrap a request into a wire frame.
    fn from_request(req: Self::Request) -> Self;
    /// Wrap a response into a wire frame.
    fn from_response(resp: Self::Response) -> Self;
    /// Sequence of a request.
    fn request_sequence(req: &Self::Request) -> u64;
    /// Stamp the sequence on an outgoing request.
    fn set_request_sequence(req: &mut Self::Request, seq: u64);
    /// Sequence of a response.
    fn response_sequence(resp: &Self::Response) -> u64;
    /// Stamp the sequence on an outgoing response.
    fn set_response_sequence(resp: &mut Self::Response, seq: u64);
}

impl Frame for Envelope {
    type Request = Command;
    type Response = Response;

    fn into_kind(self) -> FrameKind<Command, Response> {
        match self.kind {
            Some(envelope::Kind::Command(cmd)) => FrameKind::Request(cmd),
            Some(envelope::Kind::Response(resp)) => FrameKind::Response(resp),
            None => FrameKind::Empty,
        }
    }

    fn from_request(req: Command) -> Self {
        Envelope::command(req)
    }

    fn from_response(resp: Response) -> Self {
        Envelope::response(resp)
    }

    fn request_sequence(req: &Command) -> u64 {
        req.sequence
    }

    fn set_request_sequence(req: &mut Command, seq: u64) {
        req.sequence = seq;
    }

    fn response_sequence(resp: &Response) -> u64 {
        resp.sequence
    }

    fn set_response_sequence(resp: &mut Response, seq: u64) {
        resp.sequence = seq;
    }
}

// Inflight map: std::sync::Mutex<HashMap> (not DashMap) is deliberate.
// Volume on supervisor/worker channels is O(reloads + rpc-per-request),
// well under the frequency where DashMap's lock-striping pays off.
// `HashMap::{insert, remove}` cannot panic (no user closures, no
// allocator exceptions on modern glibc), so `expect("inflight map
// poisoned")` on the lock guards is effectively infallible; were it to
// fire, it surfaces a corruption bug at the earliest moment instead of
// silently leaving the map in an inconsistent state. The lone Drop on
// `Inner` uses `if let Ok(...)` because panicking in Drop is UB-adjacent.
// Since Story 9.1 the map is additionally bounded by
// `RpcLimits::max_inflight`; if this framework ever hosts a
// high-frequency path (per-request RPC fan-out > 100 kHz) the Mutex is
// still the first structure to revisit.
type InflightMap<R> = Arc<Mutex<HashMap<u64, oneshot::Sender<R>>>>;

/// A pipelined, duplex RPC endpoint, generic over the transport
/// (any `AsyncRead + AsyncWrite` stream) and the [`Frame`] type.
///
/// Clone-safe: the handle is cheap to clone, and clones share the same
/// in-flight map and outbound queue. The reader and writer background
/// tasks live as long as any clone; once the last clone is dropped, the
/// outbound queue closes, the writer task exits, the peer notices EOF,
/// and the reader task exits as well.
pub struct RpcEndpoint<F: Frame = Envelope> {
    inner: Arc<Inner<F>>,
}

impl<F: Frame> Clone for RpcEndpoint<F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct Inner<F: Frame> {
    /// Monotonically increasing per-endpoint sequence for outgoing requests.
    next_seq: AtomicU64,
    /// Oneshot senders awaiting the response for a given sequence.
    inflight: InflightMap<F::Response>,
    /// Bounded outbound queue drained by the writer task.
    tx_out: mpsc::Sender<F>,
    /// Per-endpoint transport limits.
    limits: RpcLimits,
    /// Writer and reader task handles; aborted when Inner drops.
    _tasks: [JoinHandle<()>; 2],
}

/// A request received from the peer, awaiting a reply.
///
/// The caller must eventually reply (via [`Self::reply_frame`], or the
/// `Envelope`-specific `reply` / `reply_ok` / `reply_error`) — dropping
/// without replying lets the peer's `request` time out naturally.
pub struct IncomingRequest<F: Frame> {
    req: F::Request,
    tx_out: mpsc::Sender<F>,
    max_message_size: u64,
}

/// Historical name for the worker-plane incoming request.
pub type IncomingCommand = IncomingRequest<Envelope>;

impl<F: Frame> IncomingRequest<F> {
    /// Sequence of the originating request.
    pub fn sequence(&self) -> u64 {
        F::request_sequence(&self.req)
    }

    /// Borrow the raw request.
    pub fn request(&self) -> &F::Request {
        &self.req
    }

    /// Consume and take ownership of the raw request.
    pub fn into_request(self) -> F::Request {
        self.req
    }

    /// Reply with a pre-built response. The response's `sequence` is
    /// overwritten with the originating request's sequence as a safety.
    ///
    /// In debug builds we assert that any caller-provided `sequence`
    /// is either zero (the conventional sentinel) or already matches
    /// the incoming request - passing a mismatched non-zero sequence
    /// is almost always a wiring bug (audit L-3).
    pub async fn reply_frame(self, mut resp: F::Response) -> Result<(), ChannelError> {
        debug_assert!(
            F::response_sequence(&resp) == 0
                || F::response_sequence(&resp) == F::request_sequence(&self.req),
            "IncomingRequest::reply received a response with sequence {} which does not match \
             the originating request's sequence {}; pass 0 as the sentinel sequence when the \
             response sequence is not yet known.",
            F::response_sequence(&resp),
            F::request_sequence(&self.req)
        );
        F::set_response_sequence(&mut resp, F::request_sequence(&self.req));
        send_frame(&self.tx_out, F::from_response(resp), self.max_message_size).await
    }
}

impl IncomingRequest<Envelope> {
    /// Typed command variant (worker plane).
    pub fn command_type(&self) -> CommandType {
        self.req.typed_command()
    }

    /// Borrow the raw command.
    pub fn command(&self) -> &Command {
        &self.req
    }

    /// Consume and take ownership of the raw command.
    pub fn into_command(self) -> Command {
        self.req
    }

    /// Reply with a pre-built `Response` (see [`Self::reply_frame`]).
    pub async fn reply(self, resp: Response) -> Result<(), ChannelError> {
        self.reply_frame(resp).await
    }

    /// Reply with a bare `Response::ok(seq)` (no typed payload).
    pub async fn reply_ok(self) -> Result<(), ChannelError> {
        let seq = self.sequence();
        self.reply_frame(Response::ok(seq)).await
    }

    /// Reply with a bare `Response::error(seq, msg)`.
    pub async fn reply_error(self, msg: impl Into<String>) -> Result<(), ChannelError> {
        let seq = self.sequence();
        self.reply_frame(Response::error(seq, msg)).await
    }

    /// Build an `IncomingCommand` for test fixtures that need to drive
    /// handlers without a real RPC pipeline. Marked `#[doc(hidden)]`
    /// because it bypasses the normal `RpcEndpoint` dispatch path -
    /// production code must construct `IncomingRequest` only via the
    /// reader loop.
    ///
    /// The supplied `tx_out` channel receives whatever the handler
    /// passes to `reply` / `reply_ok` / `reply_error` ; the test reads
    /// from the matching `mpsc::Receiver<Envelope>` to assert what the
    /// handler sent.
    #[doc(hidden)]
    pub fn for_test(cmd: Command, tx_out: mpsc::Sender<Envelope>) -> Self {
        IncomingRequest {
            req: cmd,
            tx_out,
            max_message_size: RpcLimits::default().max_message_size,
        }
    }
}

/// Receiver of incoming requests. The caller typically runs a loop like:
///
/// ```ignore
/// while let Some(inc) = rx.recv().await {
///     tokio::spawn(route_and_reply(inc));
/// }
/// ```
pub struct IncomingRequests<F: Frame>(pub mpsc::Receiver<IncomingRequest<F>>);

/// Historical name for the worker-plane receiver.
pub type IncomingCommands = IncomingRequests<Envelope>;

impl<F: Frame> IncomingRequests<F> {
    /// Receive the next incoming request, or `None` when the endpoint
    /// is gone.
    pub async fn recv(&mut self) -> Option<IncomingRequest<F>> {
        self.0.recv().await
    }
}

impl<F: Frame> RpcEndpoint<F> {
    /// Build an endpoint over any async byte stream with explicit
    /// per-endpoint limits (Story 9.1 AC #1/#3). The cluster plane
    /// passes its TLS stream and WAN-tuned limits here.
    pub fn with_limits<S>(stream: S, limits: RpcLimits) -> (Self, IncomingRequests<F>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let inflight: InflightMap<F::Response> = Arc::new(Mutex::new(HashMap::new()));
        let (tx_out, rx_out) = mpsc::channel::<F>(limits.outbound_queue_cap);
        let (tx_in, rx_in) = mpsc::channel::<IncomingRequest<F>>(limits.outbound_queue_cap);

        let max = limits.max_message_size;
        let writer = tokio::spawn(writer_task::<F, _>(write_half, rx_out, max));
        let reader = tokio::spawn(reader_task::<F, _>(
            read_half,
            inflight.clone(),
            tx_in,
            tx_out.clone(),
            max,
        ));

        let endpoint = Self {
            inner: Arc::new(Inner {
                next_seq: AtomicU64::new(1),
                inflight,
                tx_out,
                limits,
                _tasks: [reader, writer],
            }),
        };
        (endpoint, IncomingRequests(rx_in))
    }

    /// Build an endpoint over any async byte stream with the default
    /// (same-host) limits.
    pub fn from_stream<S>(stream: S) -> (Self, IncomingRequests<F>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::with_limits(stream, RpcLimits::default())
    }

    /// This endpoint's transport limits.
    pub fn limits(&self) -> &RpcLimits {
        &self.inner.limits
    }

    /// Allocate the next outgoing sequence number.
    pub fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a request and await the matching response with a
    /// per-request timeout. The in-flight entry is always removed on
    /// exit (Ok, Closed, or Timeout); the outgoing queue is bounded so
    /// backpressure propagates as the overall timeout firing.
    ///
    /// # Errors
    ///
    /// [`ChannelError::MessageTooLarge`] when the encoded frame
    /// exceeds this endpoint's `max_message_size` (Story 9.1 AC #4:
    /// typed, immediate, never a silent drop);
    /// [`ChannelError::InflightFull`] when `max_inflight` requests are
    /// already pending; [`ChannelError::Timeout`] / `Closed` as before.
    pub async fn request(
        &self,
        mut req: F::Request,
        timeout: Duration,
    ) -> Result<F::Response, ChannelError> {
        let seq = self.next_seq();
        F::set_request_sequence(&mut req, seq);

        // Size check BEFORE any state is installed, so an oversize
        // frame is a clean typed error with nothing to unwind.
        let frame = F::from_request(req);
        let encoded_len = frame.encoded_len() as u64;
        if encoded_len > self.inner.limits.max_message_size {
            return Err(ChannelError::MessageTooLarge(encoded_len));
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut map = self.inner.inflight.lock().expect("inflight map poisoned");
            if map.len() >= self.inner.limits.max_inflight {
                return Err(ChannelError::InflightFull);
            }
            map.insert(seq, resp_tx);
        }

        let tx_out = self.inner.tx_out.clone();
        let slow_enqueue_warn = self.inner.limits.slow_enqueue_warn;
        let start = Instant::now();

        // Cover both enqueue and response wait under a single timeout so
        // that a stuck peer surfaces as Timeout, not an indefinite hang.
        //
        // Cancel-safety: if the outer `timeout` fires while `send_fut`
        // is still pending (queue full, peer stuck), dropping `full`
        // drops `send_fut` before the frame leaves the process — no
        // request is enqueued, no spurious response can arrive, and
        // `forget(seq)` below then removes the inflight oneshot. If the
        // timeout fires after enqueue but before `resp_rx` resolves, a
        // late response from the peer will be dropped by `reader_task`
        // because the inflight entry is gone (logged at debug level as
        // "response for unknown sequence"), and the oneshot sender is
        // simply discarded. Either way, no leak, no double-send.
        let full = async move {
            // Enqueue. Emit a warning if the send future is still pending
            // after `slow_enqueue_warn`; keep awaiting on the same future
            // so the request is not duplicated.
            {
                let send_fut = tx_out.send(frame);
                tokio::pin!(send_fut);
                let warn_delay = tokio::time::sleep(slow_enqueue_warn);
                tokio::pin!(warn_delay);
                let mut warned = false;
                loop {
                    tokio::select! {
                        res = &mut send_fut => {
                            res.map_err(|_| ChannelError::Closed)?;
                            break;
                        }
                        _ = &mut warn_delay, if !warned => {
                            warned = true;
                            tracing::warn!(
                                elapsed_ms = start.elapsed().as_millis() as u64,
                                "rpc: outbound queue backpressure; peer may be stuck",
                            );
                        }
                    }
                }
            }
            // Await the matching response.
            resp_rx.await.map_err(|_| ChannelError::Closed)
        };

        let result = tokio::time::timeout(timeout, full).await;
        self.forget(seq);
        match result {
            Ok(inner) => inner,
            Err(_) => Err(ChannelError::Timeout),
        }
    }

    /// Remove the in-flight entry for `seq`, if present.
    fn forget(&self, seq: u64) {
        let mut map = self.inner.inflight.lock().expect("inflight map poisoned");
        map.remove(&seq);
    }
}

impl RpcEndpoint<Envelope> {
    /// Build a worker-plane endpoint from a raw file descriptor (e.g.
    /// one half of a `socketpair`). The fd becomes owned by the
    /// returned endpoint. Deliberately `UnixStream`-only (Story 9.1
    /// AC #1): fd passing is a worker-plane establishment concern.
    ///
    /// # Safety
    /// The fd must be a valid, open Unix stream socket not owned by anything
    /// else. The caller must not close it concurrently.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<(Self, IncomingCommands), ChannelError> {
        let std_stream = std::os::unix::net::UnixStream::from_raw_fd(fd);
        std_stream.set_nonblocking(true).map_err(ChannelError::Io)?;
        let stream = UnixStream::from_std(std_stream).map_err(ChannelError::Io)?;
        Ok(Self::new(stream))
    }

    /// Build a worker-plane endpoint from any already-configured async
    /// stream with the default same-host limits. Kept on the
    /// `Envelope` impl so historical bare-`RpcEndpoint` call sites
    /// infer unchanged.
    pub fn new<S>(stream: S) -> (Self, IncomingCommands)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::from_stream(stream)
    }

    /// Like `request` but builds the command from a typed RPC payload.
    pub async fn request_rpc(
        &self,
        command_type: CommandType,
        payload: command::Payload,
        timeout: Duration,
    ) -> Result<Response, ChannelError> {
        let cmd = Command::rpc(0, command_type, payload); // seq filled by request()
        self.request(cmd, timeout).await
    }
}

/// When the last `Arc<Inner>` drops we need to actively abort the reader
/// and writer tasks. A naive `_tasks: [JoinHandle; 2]` does NOT suffice
/// because tokio's `JoinHandle::drop` is detach, not abort - and the
/// reader task holds a clone of `tx_out` (for building `IncomingRequest`
/// replies), which keeps the writer's `rx_out` alive indefinitely. The
/// socket halves stay owned by those tasks, so the peer never sees EOF
/// and its own reader blocks forever. This was observable as a hung
/// worker RPC listener after supervisor shutdown (audit gap).
///
/// We also drain `inflight` on drop so any outstanding `request` callers
/// wake promptly with `ChannelError::Closed`.
impl<F: Frame> Drop for Inner<F> {
    fn drop(&mut self) {
        for handle in self._tasks.iter() {
            handle.abort();
        }
        if let Ok(mut map) = self.inflight.lock() {
            map.clear();
        }
    }
}

// Shared helper used by incoming replies: size-checked, typed error on
// oversize (Story 9.1 AC #4).
async fn send_frame<F: Frame>(
    tx: &mpsc::Sender<F>,
    frame: F,
    max_message_size: u64,
) -> Result<(), ChannelError> {
    let len = frame.encoded_len() as u64;
    if len > max_message_size {
        return Err(ChannelError::MessageTooLarge(len));
    }
    tx.send(frame).await.map_err(|_| ChannelError::Closed)
}

async fn writer_task<F: Frame, W>(mut write_half: W, mut rx: mpsc::Receiver<F>, max: u64)
where
    W: AsyncWrite + Unpin + Send,
{
    while let Some(frame) = rx.recv().await {
        let encoded = frame.encode_to_vec();
        let len = encoded.len() as u64;
        if len > max {
            // Defensive only: every enqueue path is size-checked with
            // a typed error before the frame reaches this queue, so a
            // frame landing here over the limit indicates a bug.
            tracing::error!(
                bytes = len,
                "rpc: outbound frame exceeds max_message_size past the enqueue guard (bug)"
            );
            continue;
        }
        if let Err(e) = write_half.write_all(&len.to_le_bytes()).await {
            tracing::debug!(error = %e, "rpc: writer failed on length prefix");
            break;
        }
        if let Err(e) = write_half.write_all(&encoded).await {
            tracing::debug!(error = %e, "rpc: writer failed on body");
            break;
        }
        if let Err(e) = write_half.flush().await {
            tracing::debug!(error = %e, "rpc: writer flush failed");
            break;
        }
    }
    tracing::debug!("rpc: writer task exiting");
}

async fn reader_task<F: Frame, R>(
    mut read_half: R,
    inflight: InflightMap<F::Response>,
    tx_in: mpsc::Sender<IncomingRequest<F>>,
    tx_out: mpsc::Sender<F>,
    max: u64,
) where
    R: AsyncRead + Unpin + Send,
{
    loop {
        let mut len_buf = [0u8; 8];
        if let Err(e) = read_half.read_exact(&mut len_buf).await {
            if e.kind() != io::ErrorKind::UnexpectedEof {
                tracing::debug!(error = %e, "rpc: reader failed on length prefix");
            }
            break;
        }
        let len = u64::from_le_bytes(len_buf);
        if len > max {
            tracing::error!(bytes = len, "rpc: inbound frame exceeds max_message_size");
            break;
        }
        let mut buf = vec![0u8; len as usize];
        if let Err(e) = read_half.read_exact(&mut buf).await {
            tracing::debug!(error = %e, "rpc: reader failed on body");
            break;
        }
        let frame = match F::decode(&buf[..]) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "rpc: frame decode failed");
                continue;
            }
        };
        match frame.into_kind() {
            FrameKind::Response(resp) => {
                let seq = F::response_sequence(&resp);
                let tx = {
                    let mut map = inflight.lock().expect("inflight map poisoned");
                    map.remove(&seq)
                };
                if let Some(tx) = tx {
                    // oneshot::send returns Err if the receiver is gone
                    // (timeout already fired). That is expected and benign.
                    let _ = tx.send(resp);
                } else {
                    tracing::debug!(
                        sequence = seq,
                        "rpc: response for unknown sequence (caller likely timed out)"
                    );
                }
            }
            FrameKind::Request(req) => {
                let inc = IncomingRequest {
                    req,
                    tx_out: tx_out.clone(),
                    max_message_size: max,
                };
                // If the caller's receiver is gone we drop silently;
                // peer's request will time out.
                if tx_in.send(inc).await.is_err() {
                    tracing::debug!("rpc: incoming requests channel closed; dropping");
                }
            }
            FrameKind::Empty => {
                tracing::warn!("rpc: received empty frame");
            }
        }
    }
    tracing::debug!("rpc: reader task exiting");
    // Best-effort: close out in-flight requests so they don't hang on
    // timeout. Dropping the oneshot senders signals Closed to their rx.
    //
    // Asymmetric with the hot-path `expect("inflight map poisoned")`:
    // here we use `if let Ok(...)` because we must not panic while a
    // task is exiting (it would leave dependent tasks and Arc counts in
    // an awkward state). In the impossible-in-practice case where the
    // mutex is already poisoned, pending requesters fall back to their
    // per-request timeout instead of a prompt Closed — acceptable
    // degradation for a pathological situation we don't actually expect
    // to hit.
    if let Ok(mut map) = inflight.lock() {
        map.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{command, CommandType, RateLimitQuery};
    use std::os::fd::IntoRawFd;

    fn make_socketpair() -> (RawFd, RawFd) {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        let (fd1, fd2) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair failed");
        (fd1.into_raw_fd(), fd2.into_raw_fd())
    }

    fn endpoints() -> (
        (RpcEndpoint, IncomingCommands),
        (RpcEndpoint, IncomingCommands),
    ) {
        let (fd_a, fd_b) = make_socketpair();
        let a = unsafe { RpcEndpoint::from_raw_fd(fd_a).expect("endpoint a") };
        let b = unsafe { RpcEndpoint::from_raw_fd(fd_b).expect("endpoint b") };
        (a, b)
    }

    #[tokio::test]
    async fn roundtrip_single_request_reply() {
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();

        // B side: accept one command and reply ok.
        let responder = tokio::spawn(async move {
            let inc = b_rx.recv().await.expect("one incoming");
            assert_eq!(inc.command_type(), CommandType::Heartbeat);
            inc.reply_ok().await.expect("reply ok");
            b_ep // keep b alive until responder finishes
        });

        let cmd = Command::new(CommandType::Heartbeat, 0);
        let resp = a
            .request(cmd, Duration::from_secs(1))
            .await
            .expect("request ok");
        assert_eq!(resp.typed_status(), crate::messages::ResponseStatus::Ok);
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn concurrent_requests_matched_by_sequence() {
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();

        // B side: echo sequence back in the response's `message` field.
        let responder = tokio::spawn(async move {
            // Expect 10 commands.
            for _ in 0..10 {
                let inc = b_rx.recv().await.expect("inc");
                let seq = inc.sequence();
                let resp = Response {
                    status: crate::messages::ResponseStatus::Ok as i32,
                    sequence: seq,
                    message: format!("seq={seq}"),
                    payload: None,
                };
                inc.reply(resp).await.expect("reply");
            }
            b_ep
        });

        // Fire 10 requests concurrently.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let a_c = a.clone();
            handles.push(tokio::spawn(async move {
                let cmd = Command::new(CommandType::Heartbeat, 0);
                a_c.request(cmd, Duration::from_secs(2)).await
            }));
        }
        for h in handles {
            let resp = h.await.unwrap().expect("request");
            assert_eq!(resp.message, format!("seq={}", resp.sequence));
        }
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn per_request_timeout_does_not_cancel_adjacent_request() {
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();

        // B side: reply to seq=2 immediately, never reply to seq=1.
        let responder = tokio::spawn(async move {
            let first = b_rx.recv().await.expect("first");
            let second = b_rx.recv().await.expect("second");
            // Reply to whichever came second (arrival order).
            // Delay first forever by dropping without reply (peer times out).
            second.reply_ok().await.expect("reply second");
            drop(first);
            b_ep
        });

        let a_c = a.clone();
        let slow = tokio::spawn(async move {
            let cmd = Command::new(CommandType::Heartbeat, 0);
            a_c.request(cmd, Duration::from_millis(150)).await
        });
        let a_c2 = a.clone();
        let fast = tokio::spawn(async move {
            let cmd = Command::new(CommandType::Heartbeat, 0);
            a_c2.request(cmd, Duration::from_secs(2)).await
        });

        let slow_res = slow.await.unwrap();
        let fast_res = fast.await.unwrap();

        assert!(matches!(slow_res, Err(ChannelError::Timeout)));
        assert!(fast_res.is_ok(), "adjacent request must not be cancelled");
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn inflight_cleaned_up_on_timeout() {
        let ((a, _a_rx), (_b_ep, mut _b_rx)) = endpoints();
        let cmd = Command::new(CommandType::Heartbeat, 0);
        let res = a.request(cmd, Duration::from_millis(50)).await;
        assert!(matches!(res, Err(ChannelError::Timeout)));
        let map = a.inner.inflight.lock().unwrap();
        assert!(map.is_empty(), "inflight must be empty after timeout");
    }

    #[tokio::test]
    async fn rpc_payload_round_trips() {
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();

        let responder = tokio::spawn(async move {
            let inc = b_rx.recv().await.expect("inc");
            assert_eq!(inc.command_type(), CommandType::RateLimitQuery);
            match &inc.command().payload {
                Some(command::Payload::RateLimitQuery(q)) => {
                    assert_eq!(q.key, "route-a:10.0.0.1");
                    assert_eq!(q.cost, 2);
                }
                _ => panic!("expected RateLimitQuery payload"),
            }
            inc.reply_ok().await.expect("reply");
            b_ep
        });

        let resp = a
            .request_rpc(
                CommandType::RateLimitQuery,
                command::Payload::RateLimitQuery(RateLimitQuery {
                    key: "route-a:10.0.0.1".into(),
                    cost: 2,
                }),
                Duration::from_secs(1),
            )
            .await
            .expect("request");
        assert_eq!(resp.typed_status(), crate::messages::ResponseStatus::Ok);
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn high_volume_concurrency_all_matched() {
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();

        // B replies ok with the sequence echoed in `message`.
        let responder = tokio::spawn(async move {
            let tx_out = b_ep.inner.tx_out.clone();
            let mut spawned = 0usize;
            while spawned < 200 {
                let inc = b_rx.recv().await.expect("inc");
                spawned += 1;
                let tx_out = tx_out.clone();
                tokio::spawn(async move {
                    let seq = inc.sequence();
                    let resp = Response {
                        status: crate::messages::ResponseStatus::Ok as i32,
                        sequence: seq,
                        message: seq.to_string(),
                        payload: None,
                    };
                    let _ = tx_out.send(Envelope::response(resp)).await;
                });
            }
            b_ep
        });

        let mut handles = Vec::new();
        for _ in 0..200 {
            let a_c = a.clone();
            handles.push(tokio::spawn(async move {
                a_c.request(
                    Command::new(CommandType::Heartbeat, 0),
                    Duration::from_secs(3),
                )
                .await
            }));
        }
        for h in handles {
            let resp = h.await.unwrap().expect("request");
            assert_eq!(resp.message, resp.sequence.to_string());
        }
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn request_timeout_when_peer_never_replies() {
        // One endpoint, peer accepts commands but never replies.
        let ((a, _a_rx), (b_ep, mut b_rx)) = endpoints();
        let drainer = tokio::spawn(async move {
            // Accept and drop forever.
            while let Some(inc) = b_rx.recv().await {
                drop(inc);
            }
            b_ep
        });

        let cmd = Command::new(CommandType::Heartbeat, 0);
        let res = a.request(cmd, Duration::from_millis(80)).await;
        assert!(matches!(res, Err(ChannelError::Timeout)));

        // The outbound queue should not have grown unbounded; verify by
        // firing 50 more requests and checking they all time out cleanly.
        let mut handles = Vec::new();
        for _ in 0..50 {
            let a_c = a.clone();
            handles.push(tokio::spawn(async move {
                a_c.request(
                    Command::new(CommandType::Heartbeat, 0),
                    Duration::from_millis(50),
                )
                .await
            }));
        }
        for h in handles {
            assert!(matches!(h.await.unwrap(), Err(ChannelError::Timeout)));
        }
        // Inflight must be empty again after all timeouts fire.
        let map = a.inner.inflight.lock().unwrap();
        assert!(map.is_empty());
        drop(map);
        drop(drainer);
    }

    #[tokio::test]
    async fn peer_drop_closes_pending_requests() {
        let ((a, _a_rx), b_pair) = endpoints();

        let cmd = Command::new(CommandType::Heartbeat, 0);
        let a_c = a.clone();
        let req = tokio::spawn(async move { a_c.request(cmd, Duration::from_secs(5)).await });

        // Let the request get enqueued, then drop the peer.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(b_pair);

        let res = req.await.unwrap();
        assert!(
            matches!(res, Err(ChannelError::Closed) | Err(ChannelError::Timeout)),
            "got {res:?}"
        );
    }

    // --- Story 9.1 additions ---

    #[tokio::test]
    async fn in_memory_duplex_transport_round_trips() {
        // IV1: the same endpoint drives an in-memory duplex stream,
        // proving the transport generalisation without touching the
        // UDS paths above.
        let (d_a, d_b) = tokio::io::duplex(64 * 1024);
        let (a, _a_rx) = RpcEndpoint::new(d_a);
        let (b_ep, mut b_rx) = RpcEndpoint::new(d_b);

        let responder = tokio::spawn(async move {
            let inc = b_rx.recv().await.expect("one incoming");
            assert_eq!(inc.command_type(), CommandType::Heartbeat);
            inc.reply_ok().await.expect("reply ok");
            b_ep
        });

        let resp = a
            .request(
                Command::new(CommandType::Heartbeat, 0),
                Duration::from_secs(1),
            )
            .await
            .expect("request ok");
        assert_eq!(resp.typed_status(), crate::messages::ResponseStatus::Ok);
        drop(responder.await.expect("responder"));
    }

    #[tokio::test]
    async fn oversize_outbound_frame_is_a_typed_error() {
        // AC #4: the caller gets MessageTooLarge immediately, not an
        // unexplained Timeout indistinguishable from a dead peer.
        let (d_a, d_b) = tokio::io::duplex(64 * 1024);
        let limits = RpcLimits {
            max_message_size: 64,
            ..RpcLimits::default()
        };
        let (a, _a_rx) = RpcEndpoint::<Envelope>::with_limits(d_a, limits);
        let (_b_ep, _b_rx) = RpcEndpoint::<Envelope>::from_stream(d_b);

        let cmd = Command::rpc(
            0,
            CommandType::RateLimitQuery,
            command::Payload::RateLimitQuery(RateLimitQuery {
                key: "x".repeat(1024),
                cost: 1,
            }),
        );
        let started = Instant::now();
        let res = a.request(cmd, Duration::from_secs(5)).await;
        assert!(
            matches!(res, Err(ChannelError::MessageTooLarge(_))),
            "got {res:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "typed error must be immediate, not a timeout"
        );
        // No in-flight entry may linger.
        assert!(a.inner.inflight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn inflight_map_is_bounded() {
        // AC #4: a peer that stopped replying cannot grow the map
        // unboundedly; requests past the cap fail typed.
        let (d_a, d_b) = tokio::io::duplex(64 * 1024);
        let limits = RpcLimits {
            max_inflight: 2,
            ..RpcLimits::default()
        };
        let (a, _a_rx) = RpcEndpoint::<Envelope>::with_limits(d_a, limits);
        // Peer accepts but never replies.
        let (_b_ep, mut b_rx) = RpcEndpoint::<Envelope>::from_stream(d_b);
        let _drainer = tokio::spawn(async move { while b_rx.recv().await.is_some() {} });

        let a1 = a.clone();
        let h1 = tokio::spawn(async move {
            a1.request(
                Command::new(CommandType::Heartbeat, 0),
                Duration::from_millis(500),
            )
            .await
        });
        let a2 = a.clone();
        let h2 = tokio::spawn(async move {
            a2.request(
                Command::new(CommandType::Heartbeat, 0),
                Duration::from_millis(500),
            )
            .await
        });
        // Let both requests install their in-flight entries.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let res = a
            .request(
                Command::new(CommandType::Heartbeat, 0),
                Duration::from_millis(500),
            )
            .await;
        assert!(matches!(res, Err(ChannelError::InflightFull)), "got {res:?}");
        assert!(matches!(h1.await.unwrap(), Err(ChannelError::Timeout)));
        assert!(matches!(h2.await.unwrap(), Err(ChannelError::Timeout)));
    }

    /// AC #2 proof: a frame type distinct from `Envelope` drives the
    /// endpoint. `TestFrame` delegates its prost encoding to
    /// `Envelope` but is a different Rust type with its own `Frame`
    /// impl, which is exactly the property the cluster proto package
    /// relies on (same framing machinery, disjoint message set).
    #[derive(Clone, PartialEq, Debug, Default)]
    struct TestFrame(Envelope);

    impl prost::Message for TestFrame {
        fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut)
        where
            Self: Sized,
        {
            self.0.encode_raw(buf);
        }

        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: prost::encoding::WireType,
            buf: &mut impl prost::bytes::Buf,
            ctx: prost::encoding::DecodeContext,
        ) -> Result<(), prost::DecodeError>
        where
            Self: Sized,
        {
            self.0.merge_field(tag, wire_type, buf, ctx)
        }

        fn encoded_len(&self) -> usize {
            self.0.encoded_len()
        }

        fn clear(&mut self) {
            self.0.clear();
        }
    }

    impl Frame for TestFrame {
        type Request = Command;
        type Response = Response;

        fn into_kind(self) -> FrameKind<Command, Response> {
            self.0.into_kind()
        }

        fn from_request(req: Command) -> Self {
            TestFrame(Envelope::command(req))
        }

        fn from_response(resp: Response) -> Self {
            TestFrame(Envelope::response(resp))
        }

        fn request_sequence(req: &Command) -> u64 {
            req.sequence
        }

        fn set_request_sequence(req: &mut Command, seq: u64) {
            req.sequence = seq;
        }

        fn response_sequence(resp: &Response) -> u64 {
            resp.sequence
        }

        fn set_response_sequence(resp: &mut Response, seq: u64) {
            resp.sequence = seq;
        }
    }

    #[tokio::test]
    async fn custom_frame_type_round_trips() {
        let (d_a, d_b) = tokio::io::duplex(64 * 1024);
        let (a, _a_rx) = RpcEndpoint::<TestFrame>::from_stream(d_a);
        let (b_ep, mut b_rx) = RpcEndpoint::<TestFrame>::from_stream(d_b);

        let responder = tokio::spawn(async move {
            let inc = b_rx.recv().await.expect("one incoming");
            let seq = inc.sequence();
            inc.reply_frame(Response::ok(seq)).await.expect("reply");
            b_ep
        });

        let resp = a
            .request(
                Command::new(CommandType::Heartbeat, 0),
                Duration::from_secs(1),
            )
            .await
            .expect("request ok");
        assert_eq!(resp.typed_status(), crate::messages::ResponseStatus::Ok);
        drop(responder.await.expect("responder"));
    }
}
