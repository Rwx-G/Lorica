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

pub mod channel;
pub mod messages;

pub use channel::CommandChannel;
pub use messages::{
    BackendConnEntry, BanReportEntry, Command, CommandType, EwmaReportEntry, MetricsReport,
    Response, ResponseStatus,
};

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
}
