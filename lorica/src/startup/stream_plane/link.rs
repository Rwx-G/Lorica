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

//! The driver's transports to its workers: the supervisor's
//! `SOCK_SEQPACKET` channels and single-process mode's in-process one.

use std::io;
use std::os::fd::OwnedFd;

use lorica_stream::InProcessPeer;
use lorica_worker::stream_ctl::{self, StreamCtlError, StreamCtlMsg};
use tokio::io::unix::AsyncFd;

/// Why a message could not be exchanged with a worker.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LinkError {
    /// The channel is unusable: the worker is gone.
    #[error("stream control channel lost: {0}")]
    Lost(String),
    /// One message was refused or garbled; the channel still works.
    #[error("stream control message refused: {0}")]
    Refused(String),
}

/// The driver's end of one worker's stream control channel. The futures
/// are `Send` so the driver runs from spawned tasks.
pub(crate) trait WorkerLink: Send {
    /// Send one message.
    fn send(
        &mut self,
        msg: StreamCtlMsg,
    ) -> impl std::future::Future<Output = Result<(), LinkError>> + Send;
    /// Receive the next answer.
    fn recv(&mut self)
        -> impl std::future::Future<Output = Result<StreamCtlMsg, LinkError>> + Send;
}

/// The supervisor's end of a worker's `SOCK_SEQPACKET` channel.
pub(crate) struct SeqpacketLink {
    fd: AsyncFd<OwnedFd>,
}

fn would_block(e: &StreamCtlError) -> bool {
    match e {
        StreamCtlError::Send(errno) | StreamCtlError::Recv(errno) => {
            io::Error::from(*errno).kind() == io::ErrorKind::WouldBlock
        }
        _ => false,
    }
}

impl SeqpacketLink {
    /// Register `fd`, the supervisor end a [`WorkerHandle`] hands over.
    /// Must run inside the runtime that will poll it.
    ///
    /// [`WorkerHandle`]: lorica_worker::manager::WorkerHandle
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        // `set_nonblocking` is a plain `fcntl(O_NONBLOCK)` whatever the
        // socket type; the std wrapper only borrows the descriptor for it.
        let socket = std::os::unix::net::UnixDatagram::from(fd);
        socket.set_nonblocking(true)?;
        let fd = OwnedFd::from(socket);
        // SAFETY: an `OwnedFd` is a valid open descriptor that it alone
        // closes, and `as_raw_fd` returns the same number for its whole
        // life; the `AsyncFd` owns it from here, so it stays open for as
        // long as it is registered.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(SeqpacketLink { fd })
    }
}

impl WorkerLink for SeqpacketLink {
    async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| LinkError::Lost(e.to_string()))?;
            match stream_ctl::send_msg(guard.get_inner(), &msg) {
                Ok(()) => return Ok(()),
                Err(e) if would_block(&e) => guard.clear_ready(),
                Err(e @ StreamCtlError::Send(_)) => return Err(LinkError::Lost(e.to_string())),
                Err(e) => return Err(LinkError::Refused(e.to_string())),
            }
        }
    }

    async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(|e| LinkError::Lost(e.to_string()))?;
            match stream_ctl::recv_msg(guard.get_inner()) {
                Ok(msg) => return Ok(msg),
                Err(e) if would_block(&e) => guard.clear_ready(),
                Err(e @ (StreamCtlError::Closed | StreamCtlError::Recv(_))) => {
                    return Err(LinkError::Lost(e.to_string()))
                }
                Err(e) => return Err(LinkError::Refused(e.to_string())),
            }
        }
    }
}

/// Single-process mode's end of the in-process channel to its own stream
/// runtime (D-k): the same messages, with owned fds instead of
/// `SCM_RIGHTS`.
pub(crate) struct InProcessLink(pub(crate) InProcessPeer);

impl WorkerLink for InProcessLink {
    async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
        self.0
            .to_runtime
            .send(msg)
            .await
            .map_err(|_| LinkError::Lost("the stream runtime is gone".into()))
    }

    async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
        self.0
            .from_runtime
            .recv()
            .await
            .ok_or_else(|| LinkError::Lost("the stream runtime is gone".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use lorica_stream::{FdBudget, StreamBindStates};
    use lorica_worker::stream_ctl::QuiesceReason;

    use super::*;
    use crate::startup::stream_plane::test_support::{
        bindable, free_ports, reserved, tcp, FixedTable, PASS, STANDALONE,
    };
    use crate::startup::stream_plane::{StreamPlane, Trigger, STREAM_CTL_ACK_TIMEOUT};
    use lorica_stream::BindState;

    #[tokio::test]
    async fn the_in_process_link_drives_a_real_stream_runtime() {
        let port = free_ports(1);
        let s = tcp("s1", port);
        let (peer, transport) = lorica_stream::ControlTransport::in_process_pair(8);
        let runtime = lorica_stream::StreamRuntime::spawn(
            transport,
            lorica_stream::Engines::default(),
            Arc::new(FixedTable(vec![s.clone()])),
        )
        .unwrap();
        let states = StreamBindStates::new();
        let mut plane = StreamPlane::new(
            vec![(0, InProcessLink(peer))],
            1,
            FdBudget::from_limit(65536),
            reserved(),
            states.clone(),
            STREAM_CTL_ACK_TIMEOUT,
        );

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
        plane.quiesce(Duration::from_secs(1)).await;
        assert_eq!(
            runtime.quiesced().borrow().map(|q| (q.drain, q.reason)),
            Some((Duration::from_secs(1), QuiesceReason::Shutdown))
        );
        runtime.stop();
    }

    #[tokio::test]
    async fn the_seqpacket_link_drives_a_real_stream_runtime() {
        let port = free_ports(1);
        let s = tcp("s1", port);
        let (supervisor_end, worker_end) = stream_ctl::create_seqpacket_pair().unwrap();
        let runtime = lorica_stream::StreamRuntime::spawn(
            lorica_stream::ControlTransport::Seqpacket(worker_end),
            lorica_stream::Engines::default(),
            Arc::new(FixedTable(vec![s.clone()])),
        )
        .unwrap();
        let states = StreamBindStates::new();
        let mut plane = StreamPlane::new(
            vec![(0, SeqpacketLink::new(supervisor_end).unwrap())],
            1,
            FdBudget::from_limit(65536),
            reserved(),
            states.clone(),
            STREAM_CTL_ACK_TIMEOUT,
        );

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

        plane.release_stale(&[], STANDALONE, PASS).await;
        assert!(bindable(port), "the worker closed its copy before acking");
        runtime.stop();
    }
}
