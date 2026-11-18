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

//! How a [`crate::runtime::StreamRuntime`] receives its control messages:
//! the `SOCK_SEQPACKET` stream control end a worker got in its fork bundle,
//! or, in single-process mode (D-k), an in-process channel carrying the
//! same [`StreamCtlMsg`] type with owned fds.

use std::io;
use std::os::fd::OwnedFd;

use lorica_worker::stream_ctl::{self, DrainReport, ReportSent, StreamCtlError, StreamCtlMsg};
use nix::errno::Errno;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

/// The control channel a runtime is built on.
#[derive(Debug)]
pub enum ControlTransport {
    /// The worker's end of its stream control socketpair.
    Seqpacket(OwnedFd),
    /// One end of an in-process channel; see [`ControlTransport::in_process_pair`].
    InProcess {
        /// Messages from the driver.
        from_driver: mpsc::Receiver<StreamCtlMsg>,
        /// Answers to the driver.
        to_driver: mpsc::Sender<StreamCtlMsg>,
    },
}

/// The driver's end of an in-process control channel.
#[derive(Debug)]
pub struct InProcessPeer {
    /// Messages to the runtime.
    pub to_runtime: mpsc::Sender<StreamCtlMsg>,
    /// The runtime's answers.
    pub from_runtime: mpsc::Receiver<StreamCtlMsg>,
}

impl ControlTransport {
    /// An in-process channel of `capacity` messages each way: the
    /// driver's end and the runtime's.
    pub fn in_process_pair(capacity: usize) -> (InProcessPeer, ControlTransport) {
        let (to_runtime, from_driver) = mpsc::channel(capacity);
        let (to_driver, from_runtime) = mpsc::channel(capacity);
        (
            InProcessPeer {
                to_runtime,
                from_runtime,
            },
            ControlTransport::InProcess {
                from_driver,
                to_driver,
            },
        )
    }
}

/// Why the runtime could not exchange a message.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportError {
    /// The channel refused or garbled one message; the next may be fine.
    #[error(transparent)]
    Message(StreamCtlError),
    /// The channel is unusable: the peer is gone or the socket failed.
    #[error("stream control channel lost: {0}")]
    Lost(String),
}

/// A [`ControlTransport`] registered with the runtime's reactor.
pub(crate) enum ActiveTransport {
    Seqpacket(AsyncFd<OwnedFd>),
    InProcess {
        from_driver: mpsc::Receiver<StreamCtlMsg>,
        to_driver: mpsc::Sender<StreamCtlMsg>,
    },
}

fn would_block(e: &StreamCtlError) -> bool {
    match e {
        StreamCtlError::Recv(errno) | StreamCtlError::Send(errno) => {
            io::Error::from(*errno).kind() == io::ErrorKind::WouldBlock
        }
        _ => false,
    }
}

impl ActiveTransport {
    /// Register `transport`. Must run inside the runtime that will poll it.
    pub(crate) fn activate(transport: ControlTransport) -> io::Result<Self> {
        match transport {
            ControlTransport::Seqpacket(fd) => {
                let socket = socket2::Socket::from(fd);
                socket.set_nonblocking(true)?;
                let fd = OwnedFd::from(socket);
                // The one `unsafe` of the crate: tokio's registration
                // (the safe constructors are deprecated as unsound for an
                // arbitrary `AsRawFd`).
                #[allow(unsafe_code)]
                // SAFETY: an `OwnedFd` is a valid open descriptor that it
                // alone closes, on drop, and `as_raw_fd` returns the same
                // number for its whole life; the `AsyncFd` owns it from
                // here, so it stays open for as long as it is registered.
                let registered = unsafe { AsyncFd::register(fd) }?;
                Ok(ActiveTransport::Seqpacket(registered))
            }
            ControlTransport::InProcess {
                from_driver,
                to_driver,
            } => Ok(ActiveTransport::InProcess {
                from_driver,
                to_driver,
            }),
        }
    }

    pub(crate) async fn recv(&mut self) -> Result<StreamCtlMsg, TransportError> {
        match self {
            ActiveTransport::Seqpacket(fd) => loop {
                let mut guard = fd
                    .readable()
                    .await
                    .map_err(|e| TransportError::Lost(e.to_string()))?;
                match stream_ctl::recv_msg(guard.get_inner()) {
                    Err(e) if would_block(&e) => guard.clear_ready(),
                    Err(StreamCtlError::Closed) => {
                        return Err(TransportError::Lost("closed by the peer".into()))
                    }
                    Err(e @ StreamCtlError::Recv(_)) => {
                        return Err(TransportError::Lost(e.to_string()))
                    }
                    Err(e) => return Err(TransportError::Message(e)),
                    Ok(msg) => return Ok(msg),
                }
            },
            ActiveTransport::InProcess { from_driver, .. } => from_driver
                .recv()
                .await
                .ok_or_else(|| TransportError::Lost("driver gone".into())),
        }
    }

    /// Send drain report `report` under `seq` without ever waiting
    /// (Story 12.11 D-g): a full socket buffer or channel truncates it.
    pub(crate) fn try_send_report(
        &self,
        seq: u64,
        report: DrainReport,
    ) -> Result<ReportSent, StreamCtlError> {
        match self {
            ActiveTransport::Seqpacket(fd) => {
                stream_ctl::send_drain_report(fd.get_ref(), seq, report)
            }
            ActiveTransport::InProcess { to_driver, .. } => {
                stream_ctl::deliver_drain_report(seq, report, |msg| {
                    to_driver.try_send(msg).map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => StreamCtlError::Send(Errno::EAGAIN),
                        mpsc::error::TrySendError::Closed(_) => StreamCtlError::Closed,
                    })
                })
            }
        }
    }

    pub(crate) async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), TransportError> {
        match self {
            ActiveTransport::Seqpacket(fd) => loop {
                let mut guard = fd
                    .writable()
                    .await
                    .map_err(|e| TransportError::Lost(e.to_string()))?;
                match stream_ctl::send_msg(guard.get_inner(), &msg) {
                    Err(e) if would_block(&e) => guard.clear_ready(),
                    Err(e @ StreamCtlError::Send(_)) => {
                        return Err(TransportError::Lost(e.to_string()))
                    }
                    Err(e) => return Err(TransportError::Message(e)),
                    Ok(()) => return Ok(()),
                }
            },
            ActiveTransport::InProcess { to_driver, .. } => to_driver
                .send(msg)
                .await
                .map_err(|_| TransportError::Lost("driver gone".into())),
        }
    }
}
