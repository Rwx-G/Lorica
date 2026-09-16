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

//! The automation plane (Story 10.3): a second HTTPS listener whose
//! only credential is a scoped bearer token.
//!
//! # Why a separate listener and not a path on the management API
//!
//! The management API authenticates a human through a session cookie
//! and authorises them by RBAC role. An automation authenticates a
//! machine through a bearer token and is authorised by scope. Serving
//! both on one socket would mean one router where every layer has to
//! ask which kind of caller it is looking at, and the failure mode of
//! getting that wrong is a dashboard session reaching an automation
//! endpoint or the reverse.
//!
//! The two planes therefore share no credential at all. A request on
//! this listener carrying a perfectly valid `lorica_session` cookie
//! and no `Authorization` header is a 401, and the cookie is never
//! read. There is no cookie layer, no CSRF layer and no session store
//! anywhere in [`build_automation_router`].
//!
//! # Layout
//!
//! - [`listener`] - the bind address, the mandatory source allowlist,
//!   the pre-authentication budgets, and the accept loop.
//! - [`auth`] - the bearer check and the [`auth::AutomationPrincipal`]
//!   it installs.
//! - [`scope`] - the per-path scope floor and the gate enforcing it.
//! - [`audit`] - the outermost layer, which records every request.
//! - [`router`] - the router and the `whoami` endpoint.
//!
//! # Not in the OpenAPI document
//!
//! `openapi.yaml` describes the management plane: one server, one
//! security scheme (the session cookie). The automation plane is a
//! different socket with a different scheme, so its paths are not
//! management-API operations and documenting them there would say
//! something false about both. The `openapi_contract` drift gate scans
//! `src/server.rs` only, so this router is outside its scope by
//! construction rather than by an allowlist entry.

pub mod audit;
pub mod auth;
pub mod listener;
pub mod router;
pub mod scope;

pub use auth::AutomationPrincipal;
pub use listener::{start_automation_server, AutomationListenerConfig, AutomationListenerError};
pub use router::build_automation_router;
pub use scope::required_scope;
