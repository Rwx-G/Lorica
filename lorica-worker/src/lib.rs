// Copyright 2026 Romain G. (Lorica)
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

//! Process-based worker isolation for Lorica.
//!
//! This crate implements a supervisor/worker model where the main process
//! forks worker processes that each run the proxy engine independently.
//! Listening socket FDs are passed to workers via SCM_RIGHTS.

#![warn(clippy::all)]
#![cfg(unix)]

pub mod fd_passing;
pub mod manager;

/// Errors from the worker isolation subsystem.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("failed to create socketpair: {0}")]
    SocketPair(nix::Error),

    #[error("failed to send FDs: {0}")]
    SendFds(nix::Error),

    #[error("failed to receive FDs: {0}")]
    RecvFds(nix::Error),

    #[error("invalid UTF-8 in address payload")]
    InvalidPayload,

    #[error("FD/address count mismatch: {fds} FDs but {addrs} addresses")]
    FdAddrMismatch { fds: usize, addrs: usize },

    #[error("failed to clear CLOEXEC: {0}")]
    ClearCloexec(nix::Error),

    #[error("invalid bind address '{0}': {1}")]
    BadAddress(String, std::net::AddrParseError),

    #[error("failed to create TCP socket: {0}")]
    CreateSocket(std::io::Error),

    #[error("fork failed: {0}")]
    Fork(nix::Error),

    #[error("execv failed: {0}")]
    Exec(nix::Error),

    #[error("failed to get current executable path: {0}")]
    CurrentExe(std::io::Error),

    #[error("worker {id} (pid {pid}) exited with status {status}")]
    WorkerExited { id: u32, pid: i32, status: i32 },

    #[error("worker {id} (pid {pid}) killed by signal {signal}")]
    WorkerSignaled {
        id: u32,
        pid: i32,
        signal: nix::sys::signal::Signal,
    },
}
