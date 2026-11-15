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

//! The TCP stream engine (Story 12.3): [`TcpEngine`], a
//! [`crate::StreamHandler`] that forwards an accepted connection to one
//! of its stream's backends.
//!
//! What it needs from the binary goes through the protocol-neutral
//! [`crate::seams`]; the local check is [`crate::local`], the host-name
//! cache [`crate::resolver`], the counters [`crate::counters`], all
//! shared with the UDP engine of Story 12.5.

pub mod bandwidth;
pub mod cap;
mod connect;
mod engine;
pub mod forward;
pub mod proxy_header;

pub use cap::{held_fds, TCP_FDS_PER_CONNECTION};
pub use connect::{BACKEND_KEEPALIVE_INTERVAL, BACKEND_KEEPALIVE_PROBES};
pub use engine::{TcpEngine, TcpEngineParts};
pub use forward::{DirectionState, Forwarder};

/// The size of each direction's forwarding buffer, nginx's
/// `proxy_buffer_size` default: two per connection, allocated once when
/// forwarding starts and never grown (D-c).
pub const FORWARD_BUFFER_SIZE: usize = 16 * 1024;
