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
//! The TCP engine of Story 12.3 is [`tcp`]. What it shares with the UDP
//! engine of Story 12.5 sits beside it: the [`seams`] the binary
//! implements (selection, breaker, resolution), the connect-time
//! [`local`] check, the host-name [`resolver`] cache and the
//! [`counters`].
//!
//! The crate opens no store and spawns nothing on its own: the binary
//! composes it (Story 12.2 Lot D), the API reads its types (Lot E3).

pub mod budget;
pub mod counters;
pub mod handler;
pub mod listener;
pub mod local;
pub mod reconcile;
pub mod resolver;
pub mod runtime;
pub mod seams;
pub mod state;
pub mod table;
pub mod tcp;
pub mod tracker;
pub mod transport;

pub use budget::{BudgetUsage, BudgetViolation, FdBudget, HeldFds, StreamDemand};
pub use counters::{CountersSnapshot, StreamCounters};
pub use handler::{
    AcceptedConnection, ConnectionObserver, ConnectionRecord, Datagram, DatagramHandler, Engines,
    LogObserver, StreamHandler,
};
pub use local::BoundPorts;
pub use reconcile::{diff, Actions, BindKey, BoundBinding, Detach, ReleaseCause, UdpOverlap};
pub use resolver::ResolverCache;
pub use runtime::{StreamRuntime, StreamRuntimeError, StreamRuntimeHandle};
pub use seams::{
    Admission, BackendSelector, BreakerGate, Candidate, Resolve, ResolveError, Resolved,
    SelectionRequest,
};
pub use state::{BindFailure, BindFailureKind, BindState, BindStateKind, StreamBindStates};
pub use table::{StreamTable, StreamTableSource};
pub use tcp::{TcpEngine, TcpEngineParts};
pub use tracker::{ConnectionTracker, TrackedConnection};
pub use transport::{ControlTransport, InProcessPeer};
