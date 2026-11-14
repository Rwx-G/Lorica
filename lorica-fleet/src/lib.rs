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

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The fleet runtime: what this process is in a Lorica cluster, and
//! the rules the control plane applies to what its fleet sends it.
//!
//! # Why a crate of its own (backlog #52)
//!
//! This code lived in the management API crate only because `AppState`
//! needed it, so the binary linked `lorica-api` for its cluster work
//! alone. It has two consumers: `lorica-api`, whose handlers act
//! through it, and `lorica`, which composes it at startup. It depends on
//! the transport (`lorica-cluster`) and the configuration store
//! (`lorica-config`) and on neither consumer.
//!
//! It is deliberately not part of `lorica-cluster`. That would drag
//! `lorica-config` into the transport crate, whose wire layer treats
//! the replicated blob as opaque bytes, which is the property that kept
//! the cluster stories from tangling.
//!
//! Three things the management API owns stay there, and reach this
//! crate inverted or not at all: the error type a handler answers with
//! (each runtime error converts at the handler boundary), the audit
//! chain (a unit's owed row is a [`runtime::PanicHook`] built by the
//! API), and the Prometheus counters (the ingest handler counts what
//! [`ingest::admit`] reports).
//!
//! - [`runtime`]: the control-plane and follower runtimes, the refresh
//!   rule, drift, revocation, and the detached units every committed
//!   change runs in.
//! - [`telemetry_store`]: the control plane's fan-in database.
//! - [`ingest`]: what the control plane stores of one telemetry push.

pub mod ingest;
pub mod runtime;
pub mod telemetry_store;

pub use runtime::{
    ClusterRuntime, ClusterRuntimeError, ControlPlaneRuntime, FollowerRuntime, PanicHook,
};
pub use telemetry_store::ClusterTelemetryStore;
