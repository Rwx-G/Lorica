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

//! The UDP stream engine (Story 12.5): [`UdpEngine`], a
//! [`crate::DatagramHandler`] that serves a UDP stream's datagrams as
//! sessions, each bound to one backend through one connected upstream
//! socket.
//!
//! - A session is keyed by the binding, the local address the client
//!   targeted and the client address, both canonical (D-a), in a map this
//!   process owns: the `SO_REUSEPORT` group sends a client to one worker
//!   for that worker's life.
//! - The receive loop's call is synchronous (D-c): the size, rate and cap
//!   checks are atomics on the stream-caps region (D-d), a datagram of an
//!   open session is one non-blocking `send`, and a new session is a
//!   spawned task. Selection, the breaker admission (an async seam that
//!   may wait on the supervisor) and the upstream socket run in that
//!   task, which holds the session's first datagrams until it is open.
//! - The task forwards responses within the bounds of D-b, replies from
//!   the address the client targeted (D-g), and ends the session with
//!   its reason, its record and its breaker report.
//!
//! What it needs from the binary is the [`crate::seams`] the TCP engine
//! uses, and the same [`crate::resolver`] cache, [`crate::local`] check
//! and [`crate::counters`].

mod engine;
mod session;

pub use engine::{UdpEngine, UdpEngineParts};

/// The largest UDP payload over IPv4, PROXY header included: a client
/// datagram the header would push past it is dropped as
/// `request_oversize` (D-j).
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// `SO_RCVBUF` asked for on each upstream socket (the kernel doubles
/// it): a session never queues more than its response bound allows, and
/// the default buffer times the node's sessions is memory an amplifying
/// backend could fill (D-a).
pub const UPSTREAM_RECEIVE_BUFFER: usize = 32 * 1024;

/// Client datagrams a session holds while its task selects a backend and
/// opens the upstream socket, its first one included. A stub resolver
/// sending its A and AAAA queries back to back from one port loses
/// neither; past it a datagram is dropped as `send_failed`, the session's
/// send path being full.
pub const OPENING_QUEUE_DATAGRAMS: usize = 4;
