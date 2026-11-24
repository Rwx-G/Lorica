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

#![cfg(unix)]
#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The stream data plane (Epic 12, Story 12.2): layer-4 listeners served
//! outside Pingora.
//!
//! The supervisor binds every stream socket (D4) and hands it to the
//! workers over the stream control channel of `lorica-worker`. What runs
//! on each side lives here:
//!
//! - worker side: [`runtime::StreamRuntime`], on its own thread and its
//!   own tokio runtime, applies the control messages, runs the TCP accept
//!   and UDP receive loops of [`listener`], hands what they accept to the
//!   engines through the [`handler`] traits, and registers every
//!   connection in the [`tracker`], which drains and closes them with an
//!   end reason;
//! - supervisor side: the pure [`reconcile::diff`] between the streams
//!   this node binds and the bindings it holds, the [`budget`] arithmetic
//!   that keeps the stream plane off the HTTP reserve, and the bind
//!   [`state`] registry the API, the audit chain and the fleet view read.
//!
//! The TCP engine of Story 12.3 is [`tcp`], the UDP engine of Story 12.5
//! is [`udp`]; what a TLS stream reads before forwarding (Story 12.4) is
//! [`tls`]. What they share sits beside them: the [`seams`] the binary
//! implements (selection, breaker, resolution, the node's source
//! controls), the backend selection both engines run around them
//! (`selection`), the connect-time [`local`] check, the host-name
//! [`resolver`] cache and the [`counters`]. Every stream's per-node caps
//! and open rates live on the stream-caps regions of [`caps`] (Story
//! 12.5 D-d, Story 12.6 D-e): created by the supervisor, mapped by every
//! worker. Both engines admit through one sequence (Story 12.6 D-a), and
//! report refusals through the [`refusal_log`] limiter.
//!
//! The crate opens no store and spawns nothing on its own: the binary
//! composes it (Story 12.2 Lot D), the API reads its types (Lot E3).

mod admission;
pub mod budget;
pub mod caps;
pub mod counters;
pub mod handler;
pub mod listener;
pub mod local;
pub mod reconcile;
pub mod refusal_log;
pub mod resolver;
pub mod runtime;
pub mod seams;
mod selection;
pub mod state;
pub mod table;
pub mod tcp;
pub mod tls;
pub mod tracker;
pub mod transport;
pub mod udp;

pub use budget::{
    held_fds, BudgetUsage, BudgetViolation, CeilingBound, FdBudget, HeldFds, SessionCeiling,
    SourcePool, StreamDemand,
};
pub use caps::{CapsRegistry, NodeCapsRegions, StreamCaps};
pub use counters::{CountersSnapshot, StreamCounters};
pub use handler::{
    AcceptedConnection, ClientCertificateOutcome, ConnectOutcome, ConnectionObserver,
    ConnectionRecord, Datagram, DatagramHandler, Engines, LogObserver, RefusalRecord,
    StreamHandler, StreamLogKey, SuppressedRecord, TlsRecord,
};
pub use local::BoundPorts;
pub use reconcile::{diff, Actions, BindKey, BoundBinding, Detach, ReleaseCause, UdpOverlap};
pub use refusal_log::{RefusalLogDecision, RefusalLogLimiter, REFUSAL_LOG_WINDOW};
pub use resolver::ResolverCache;
pub use runtime::{
    quiesce_end_reason, DrainReportError, Quiesced, StreamDeath, StreamRuntime, StreamRuntimeError,
    StreamRuntimeHandle,
};
pub use seams::{
    Admission, BackendSelector, BreakerGate, Candidate, Resolve, ResolveError, Resolved,
    SelectionRequest, SourceGate,
};
pub use state::{BindFailure, BindFailureKind, BindState, BindStateKind, StreamBindStates};
pub use table::{ClientIdentity, StreamTable, StreamTableSource};
pub use tcp::{TcpEngine, TcpEngineParts};
pub use tls::TlsParts;
pub use tracker::{ConnectionTracker, TrackedConnection, UpgradeDrainCounts};
pub use transport::{ControlTransport, InProcessPeer};
pub use udp::{UdpEngine, UdpEngineParts};

/// `address` without its IPv4-mapped form: a dual-stack `[::]` socket
/// reports an IPv4 client as `::ffff:192.0.2.10`, which the engines'
/// keys, records and source controls read as `192.0.2.10`.
pub(crate) fn canonical(address: std::net::SocketAddr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Wait until `deadline`, or forever without one.
pub(crate) async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}
