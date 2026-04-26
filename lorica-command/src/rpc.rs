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

//! Pipelined RPC endpoint layered over a Unix stream socket.
//!
//! Implements the RPC framework described in
//! `docs/architecture/worker-shared-state.md` § 4. Each endpoint:
//!
//! - owns one `UnixStream` split into a reader and a writer half;
//! - spawns a background reader task that decodes `Envelope` frames and
//!   demultiplexes incoming `Response`s against an in-flight map keyed
//!   by `sequence`, and routes incoming `Command`s to the caller via
//!   an mpsc channel;
//! - spawns a background writer task that drains a bounded
//!   `tokio::sync::mpsc` queue into the stream.
//!
//! `RpcEndpoint::request` is the hot-path entry point. It allocates a
//! monotonically increasing sequence, installs a oneshot in the in-flight
//! map, enqueues the command, and awaits the matching response with a
//! per-request timeout. The in-flight entry is always removed on exit
//! (Ok, Closed, or Timeout) so dead senders do not linger.
//!
//! Wire format: `[8 bytes LE length][prost-encoded Envelope]`.
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::messages::{command, envelope, Command, CommandType, Envelope, Response};
use crate::ChannelError;

/// Maximum `Envelope` frame size on the wire. Mirrors `CommandChannel`.
const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Bounded outbound queue capacity. Under backpressure, `request` awaits
/// `tx_out.send(...)` which drives the per-request timeout. The cap
/// intentionally does NOT cause a hard error path: the per-request
/// timeout passed to `request(...)` is the single wall-clock bound on
/// the entire RPC (enqueue + write + peer processing + reply). A stuck
/// peer cannot blow the queue because backpressure stalls the caller
/// there, and the caller's timeout eventually wakes up and removes the
/// in-flight entry on exit.
const OUTBOUND_QUEUE_CAP: usize = 256;

/// If enqueuing to the outbound channel takes longer than this, log a
/// warning so operators can spot a stuck peer. Advisory only - the
/// per-request `timeout` passed to `request(...)` remains the
/// authoritative bound on total RPC latency. Tuning this down turns up
/// the log volume; tuning it up hides the slowdown from ops.
const SLOW_ENQUEUE_WARN: Duration = Duration::from_millis(10);

/// Default per-request timeout when the caller does not specify one.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// Inflight map: std::sync::Mutex<HashMap> (not DashMap) is deliberate.
// Volume on supervisor/worker channels is O(reloads + rpc-per-request),
// well under the frequency where DashMap's lock-striping pays off.
// `HashMap::{insert, remove}` cannot panic (no user closures, no
// allocator exceptions on modern glibc), so `expect("inflight map
// poisoned")` on the lock guards is effectively infallible; were it to
// fire, it surfaces a corruption bug at the earliest moment instead of
// silently leaving the map in an inconsistent state. The lone Drop on
// `Inner` uses `if let Ok(...)` because panicking in Drop is UB-adjacent.
// If this framework ever hosts a high-frequency path (e.g. per-request
// RPC fan-out > 100 kHz), this is the first structure to revisit.
type InflightMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

/// A pipelined, duplex RPC endpoint.
///
/// Clone-safe: the handle is cheap to clone, and clones share the same
/// in-flight map and outbound queue. The reader and writer background
/// tasks live as long as any clone; once the last clone is dropped, the
/// outbound queue closes, the writer task exits, the peer notices EOF,
/// and the reader task exits as well.
pub struct RpcEndpoint {
    inner: Arc<Inner>,
}

impl Clone for RpcEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct Inner {
    /// Monotonically increasing per-endpoint sequence for outgoing commands.
    next_seq: AtomicU64,
    /// Oneshot senders awaiting the response for a given sequence.
    inflight: InflightMap,
    /// Bounded outbound queue drained by the writer task.
    tx_out: mpsc::Sender<Envelope>,
    /// Writer and reader task handles; dropped when Inner drops, which
    /// aborts the tasks if they have not already finished.
    _tasks: [JoinHandle<()>; 2],
}

/// A command received from the peer, awaiting a reply.
///
/// The caller must eventually reply (via `reply_ok`, `reply_error`, or
/// `reply`) — dropping without replying lets the peer's `request` time
/// out naturally.
pub struct IncomingCommand {
    cmd: Command,
    tx_out: mpsc::Sender<Envelope>,
}

impl IncomingCommand {
    /// Sequence of the originating command.
    pub fn sequence(&self) -> u64 {
        self.cmd.sequence
    }

    /// Typed command variant.
    pub fn command_type(&self) -> CommandType {
        self.cmd.typed_command()
    }

    /// Borrow the raw command.
    pub fn command(&self) -> &Command {
        &self.cmd
    }

    /// Consume and take ownership of the raw command.
    pub fn into_command(self) -> Command {
        self.cmd
    }

    /// Reply with a pre-built `Response`. The response's `sequence` is
    /// overwritten with the originating command's sequence as a safety.
    ///
    /// In debug builds we assert that any caller-provided `sequence`
    /// is either zero (the conventional sentinel used by
    /// `Response::ok_with(0, ...)`) or already matches the incoming
    /// command - passing a mismatched non-zero sequence is almost
    /// always a wiring bug (audit L-3).
    pub async fn reply(self, mut resp: Response) -> Result<(), ChannelError> {
        debug_assert!(
            resp.sequence == 0 || resp.sequence == self.cmd.sequence,
            "IncomingCommand::reply received a response with sequence {} which does not match \
             the originating command's sequence {}; pass 0 as the sentinel sequence when the \
             response sequence is not yet known.",
            resp.sequence,
            self.cmd.sequence
        );
        resp.sequence = self.cmd.sequence;
        send_envelope(&self.tx_out, Envelope::response(resp)).await
    }

    /// Reply with a bare `Response::ok(seq)` (no typed payload).
    pub async fn reply_ok(self) -> Result<(), ChannelError> {
        let resp = Response::ok(self.cmd.sequence);
        send_envelope(&self.tx_out, Envelope::response(resp)).await
    }

    /// Reply with a bare `Response::error(seq, msg)`.
    pub async fn reply_error(self, msg: impl Into<String>) -> Result<(), ChannelError> {
        let resp = Response::error(self.cmd.sequence, msg);
        send_envelope(&self.tx_out, Envelope::response(resp)).await
    }

    /// Build an `IncomingCommand` for test fixtures that need to drive
    /// handlers without a real RPC pipeline. Marked `#[doc(hidden)]`
    /// because it bypasses the normal `RpcEndpoint` dispatch path -
    /// production code must construct `IncomingCommand` only via the
    /// reader loop in `RpcEndpoint::new`.
    ///
    /// The supplied `tx_out` channel receives whatever the handler
    /// passes to `reply` / `reply_ok` / `reply_error` ; the test reads
    /// from the matching `mpsc::Receiver<Envelope>` to assert what the
    /// handler sent.
    #[doc(hidden)]
    pub fn for_test(cmd: Command, tx_out: mpsc::Sender<Envelope>) -> Self {
        IncomingCommand { cmd, tx_out }
    }
}

/// Receiver of incoming commands. The caller typically runs a loop like:
///
/// ```ignore
/// while let Some(inc) = rx.recv().await {
///     tokio::spawn(route_and_reply(inc));
/// }
/// ```
pub struct IncomingCommands(pub mpsc::Receiver<IncomingCommand>);

impl IncomingCommands {
    pub async fn recv(&mut self) -> Option<IncomingCommand> {
        self.0.recv().await
    }
}

impl RpcEndpoint {
    /// Build an endpoint from a raw file descriptor (e.g. one half of a
    /// `socketpair`). The fd becomes owned by the returned endpoint.
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

    /// Build an endpoint from an already-configured `tokio::net::UnixStream`.
    pub fn new(stream: UnixStream) -> (Self, IncomingCommands) {
        let (read_half, write_half) = stream.into_split();
        let inflight: InflightMap = Arc::new(Mutex::new(HashMap::new()));
        let (tx_out, rx_out) = mpsc::channel::<Envelope>(OUTBOUND_QUEUE_CAP);
        let (tx_in, rx_in) = mpsc::channel::<IncomingCommand>(OUTBOUND_QUEUE_CAP);

        let writer = tokio::spawn(writer_task(write_half, rx_out));
        let reader = tokio::spawn(reader_task(
            read_half,
            inflight.clone(),
            tx_in,
            tx_out.clone(),
        ));

        let endpoint = Self {
            inner: Arc::new(Inner {
                next_seq: AtomicU64::new(1),
                inflight,
                tx_out,
                _tasks: [reader, writer],
            }),
        };
        (endpoint, IncomingCommands(rx_in))
    }

    /// Allocate the next outgoing sequence number.
    pub fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a `Command` and await the matching `Response` with a
    /// per-request timeout. The in-flight entry is always removed on
    /// exit (Ok, Closed, or Timeout); the outgoing queue is bounded so
    /// backpressure propagates as the overall timeout firing.
    pub async fn request(
        &self,
        mut cmd: Command,
        timeout: Duration,
    ) -> Result<Response, ChannelError> {
        let seq = self.next_seq();
        cmd.sequence = seq;

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut map = self.inner.inflight.lock().expect("inflight map poisoned");
            map.insert(seq, resp_tx);
        }

        let tx_out = self.inner.tx_out.clone();
        let start = Instant::now();

        // Cover both enqueue and response wait under a single timeout so
        // that a stuck peer surfaces as Timeout, not an indefinite hang.
        //
        // Cancel-safety: if the outer `timeout` fires while `send_fut`
        // is still pending (queue full, peer stuck), dropping `full`
        // drops `send_fut` before the envelope leaves the process — no
        // command is enqueued, no spurious response can arrive, and
        // `forget(seq)` below then removes the inflight oneshot. If the
        // timeout fires after enqueue but before `resp_rx` resolves, a
        // late response from the peer will be dropped by `reader_task`
        // because the inflight entry is gone (logged at debug level as
        // "response for unknown sequence"), and the oneshot sender is
        // simply discarded. Either way, no leak, no double-send.
        let full = async move {
            // Enqueue. Emit a warning if the send future is still pending
            // after SLOW_ENQUEUE_WARN; keep awaiting on the same future
            // so the command is not duplicated.
            {
                let send_fut = tx_out.send(Envelope::command(cmd));
                tokio::pin!(send_fut);
                let warn_delay = tokio::time::sleep(SLOW_ENQUEUE_WARN);
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

    /// Remove the in-flight entry for `seq`, if present.
    fn forget(&self, seq: u64) {
        let mut map = self.inner.inflight.lock().expect("inflight map poisoned");
        map.remove(&seq);
    }
}

/// When the last `Arc<Inner>` drops we need to actively abort the reader
/// and writer tasks. A naive `_tasks: [JoinHandle; 2]` does NOT suffice
/// because tokio's `JoinHandle::drop` is detach, not abort - and the
/// reader task holds a clone of `tx_out` (for building `IncomingCommand`
/// replies), which keeps the writer's `rx_out` alive indefinitely. The
/// socket halves stay owned by those tasks, so the peer never sees EOF
/// and its own reader blocks forever. This was observable as a hung
/// worker RPC listener after supervisor shutdown (audit gap).
///
/// We also drain `inflight` on drop so any outstanding `request` callers
/// wake promptly with `ChannelError::Closed`.
impl Drop for Inner {
    fn drop(&mut self) {
        for handle in self._tasks.iter() {
            handle.abort();
        }
        if let Ok(mut map) = self.inflight.lock() {
            map.clear();
        }
    }
}

// Shared helper used by both outgoing requests and incoming replies.
async fn send_envelope(tx: &mpsc::Sender<Envelope>, env: Envelope) -> Result<(), ChannelError> {
    tx.send(env).await.map_err(|_| ChannelError::Closed)
}

async fn writer_task(mut write_half: OwnedWriteHalf, mut rx: mpsc::Receiver<Envelope>) {
    while let Some(env) = rx.recv().await {
        let encoded = env.encode_to_vec();
        let len = encoded.len() as u64;
        if len > MAX_MESSAGE_SIZE {
            tracing::error!(
                bytes = len,
                "rpc: outbound envelope exceeds MAX_MESSAGE_SIZE"
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

async fn reader_task(
    mut read_half: OwnedReadHalf,
    inflight: InflightMap,
    tx_in: mpsc::Sender<IncomingCommand>,
    tx_out: mpsc::Sender<Envelope>,
) {
    loop {
        let mut len_buf = [0u8; 8];
        if let Err(e) = read_half.read_exact(&mut len_buf).await {
            if e.kind() != io::ErrorKind::UnexpectedEof {
                tracing::debug!(error = %e, "rpc: reader failed on length prefix");
            }
            break;
        }
        let len = u64::from_le_bytes(len_buf);
        if len > MAX_MESSAGE_SIZE {
            tracing::error!(
                bytes = len,
                "rpc: inbound envelope exceeds MAX_MESSAGE_SIZE"
            );
            break;
        }
        let mut buf = vec![0u8; len as usize];
        if let Err(e) = read_half.read_exact(&mut buf).await {
            tracing::debug!(error = %e, "rpc: reader failed on body");
            break;
        }
        let env = match Envelope::decode(&buf[..]) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(error = %e, "rpc: envelope decode failed");
                continue;
            }
        };
        match env.kind {
            Some(envelope::Kind::Response(resp)) => {
                let seq = resp.sequence;
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
            Some(envelope::Kind::Command(cmd)) => {
                let inc = IncomingCommand {
                    cmd,
                    tx_out: tx_out.clone(),
                };
                // If the caller's receiver is gone we drop silently;
                // peer's request will time out.
                if tx_in.send(inc).await.is_err() {
                    tracing::debug!("rpc: incoming commands channel closed; dropping");
                }
            }
            None => {
                tracing::warn!("rpc: received empty envelope");
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
}
