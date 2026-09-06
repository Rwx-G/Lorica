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

//! The two cluster listeners (Story 9.2 AC #2/#3/#10).
//!
//! - The **operational** listener ([`operational`]) accepts only peers
//!   that pass the mandatory-mTLS acceptor
//!   ([`crate::tls::operational_server_config`] via
//!   [`crate::tls::SwappableAcceptor`], so Story 9.3's revocation can
//!   rebuild the config with CRLs without dropping the socket). The
//!   flow per connection: handshake permit + per-source slot (before a
//!   task exists) -> TLS under `handshake_timeout` -> ALPN check ->
//!   opener read (bounded) -> session slot -> [`crate::admission`]
//!   (bounded queued wait) -> handshake -> steady state with every
//!   inbound request routed through the [`crate::bridge`] whitelist.
//! - The **enrollment** listener ([`enrollment`]) is the only
//!   unauthenticated surface in the product. It exists ONLY while at
//!   least one join token is live: the socket binds when the
//!   [`TokenLiveness`] watch goes above zero and is dropped, along
//!   with every in-flight pre-authentication connection, the moment it
//!   returns to zero. Every connection is boxed in by the
//!   [`PreAuthBudgets`] BEFORE any token logic runs.
//!
//! Both accept loops obey the permit rule in [`crate::preauth`], pause
//! on `accept()` errors instead of spinning, and count everything in
//! plain atomics ([`EnrollmentStats`] / [`OperationalStats`]) that the
//! binary bridges into the Prometheus registry (AC #12).

mod enrollment;
mod operational;

use tokio::sync::watch;

pub use crate::preauth::PreAuthBudgets;
pub use crate::session::SessionContext;
pub use enrollment::{EnrollmentHandle, EnrollmentListener, EnrollmentStats};
pub use operational::{
    OperationalConfig, OperationalHandle, OperationalListener, OperationalStats,
    DEFAULT_ADMISSION_MAX_CONCURRENT, DEFAULT_ADMISSION_QUEUE_DEPTH,
    DEFAULT_ADMISSION_RETRY_AFTER_S, DEFAULT_MAX_SESSIONS, DEFAULT_OPENER_TIMEOUT,
};

/// Live-join-token signal driving the enrollment listener's lifecycle
/// (Story 9.2 AC #2). The value is the count of currently live
/// (unburned, unexpired) join tokens; the sender is owned by the
/// caller. Story 9.3 wires it to the token table; until then the
/// binary holds a sender that never rises, which keeps the listener
/// closed.
pub type TokenLiveness = watch::Receiver<u32>;
