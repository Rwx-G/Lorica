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
//! - [`environments`] - the environment resource (Story 10.4): the
//!   handlers, the one-transaction write, and the reaper's sweep.
//! - [`oidc`] - the GitLab ID-token verifier (Story 10.5): the pinned
//!   algorithm, the JWKS cache and the bounded replay set.
//!
//! # Two credentials, one gate
//!
//! Since Story 10.5 the bearer value is either a static token
//! (`<public_id>.<secret>`) or a GitLab ID token (a JWT). [`auth`]
//! picks the mode by the shape of the value and never by anything the
//! caller can choose separately, and every refusal on either path
//! answers the same 401 body, so a caller cannot learn which mode was
//! tried. The precise reason goes to the audit row alone.
//!
//! # Its own OpenAPI document
//!
//! `openapi.yaml` describes the management plane: one server, one
//! security scheme (the session cookie). The automation plane is a
//! different socket with a different scheme, so its paths are not
//! management-API operations and documenting them there would say
//! something false about both. They live in `openapi-automation.yaml`
//! instead, which declares `bearerAuth` and, per operation, the scope
//! [`required_scope`] enforces.
//!
//! Each document has its own drift gate in `tests/openapi_contract.rs`:
//! the management one scans `src/server.rs`, the automation one scans
//! [`router`] and additionally checks that every documented scope is
//! the scope the gate actually applies.

pub mod audit;
pub mod auth;
pub mod environments;
pub mod listener;
pub mod oidc;
pub mod router;
pub mod scope;

pub use auth::{
    AutomationPrincipal, AUTOMATION_BEARER_MAX_BYTES, AUTOMATION_LAST_USED_WRITE_INTERVAL,
    OIDC_MAX_AUDIENCES,
};
pub use environments::{
    delete_environment_rows, publish_environment_gauges, reap_expired_environments,
    reresolve_auto_certificates, DeletedEnvironment, EnvironmentCounts, ReresolvedCertificate,
    ENVIRONMENT_EXPIRED_ACTION,
};
pub use listener::{start_automation_server, AutomationListenerConfig, AutomationListenerError};
pub use oidc::{OidcVerifier, RefusalReason, OIDC_REPLAY_SET_CAP};
pub use router::build_automation_router;
pub use scope::required_scope;
