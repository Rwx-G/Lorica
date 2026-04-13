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

//! Command channel for communication between Lorica supervisor and worker processes.
//!
//! Uses Unix socketpairs with protobuf-encoded messages and 8-byte LE size-prefix framing.
//! The supervisor sends commands (config reload, heartbeat, shutdown) and workers respond
//! with a three-state protocol (Ok, Error, Processing).

#![warn(clippy::all)]
// Note: unsafe code needed for from_raw_fd (Unix socket FD passing between processes)

pub mod channel;
pub mod coalesce;
pub mod generation;
pub mod messages;
pub mod rpc;

pub use coalesce::Coalescer;
pub use generation::{GenerationGate, StaleGeneration};

pub use channel::CommandChannel;
pub use messages::{
    command, envelope, response, BackendConnEntry, BanReportEntry, BreakerDecision, BreakerQuery,
    BreakerReport, BreakerResult, Command, CommandType, ConfigReloadCommit, ConfigReloadPrepare,
    Envelope, EwmaReportEntry, MetricsReport, RateLimitDelta, RateLimitDeltaResult, RateLimitEntry,
    RateLimitQuery, RateLimitResult, RateLimitSnapshot, RequestCountEntry, Response,
    ResponseStatus, Verdict, VerdictLookup, VerdictPush, VerdictResult, WafCountEntry,
};
pub use rpc::{IncomingCommand, IncomingCommands, RpcEndpoint, DEFAULT_REQUEST_TIMEOUT};

/// Errors from the command channel.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("I/O error: {0}")]
    Io(std::io::Error),

    #[error("protobuf decode error: {0}")]
    Decode(prost::DecodeError),

    #[error("message too large: {0} bytes (max 1MB)")]
    MessageTooLarge(u64),

    #[error("channel operation timed out")]
    Timeout,

    #[error("channel closed by peer or shutdown")]
    Closed,
}
