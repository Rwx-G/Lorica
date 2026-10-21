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

//! The AD CS authority on the management API (Story 13.2, Epic 13 PRD
//! D3, D11, D13, D15): read it, write it, delete it, and test that
//! Lorica can authenticate to it. Issuing a certificate from it (Story
//! 13.3) lives in the `issue` submodule, renewing one (Story 13.4) in
//! `renew`, and adopting or reverting one (Story 13.5) in `adopt`.
//!
//! # Who may do what
//!
//! Writes are SuperAdmin and the connection test is Operator, both in
//! [`crate::middleware::authorize::required_role`] (D11): whoever can
//! edit the realm or the KDC list decides where pre-authentication
//! derived from the service account's password is sent, and whoever can
//! edit the suffixes and the templates decides which names Lorica may
//! request and what the authority signs for them (D17). A read is open
//! to every role, but only Operators and above see how the authority is
//! reached (D18).
//!
//! # The password
//!
//! Write-only. It arrives as [`WritePassword`], which wraps a
//! [`lorica_adcs::Secret`] and prints as redacted, goes straight into
//! the store's encrypted column, and is never returned: a read reports
//! `password_set` only. A change to the endpoint, realm, KDC list,
//! principal or endpoint trust bundle is refused unless the same request
//! carries a new password, because the stored one was given for the old
//! identity (D11). The
//! check, the row, the password and the generated `krb5.conf` are
//! written inside one store transaction, so a refusal or a failure at
//! any step leaves the stored password as it was.
//!
//! # The breaker (D15)
//!
//! A KDC refusing the credential ([`TicketFailure::CredentialRejected`])
//! puts the authority in the persisted failed state, raises one
//! `adcs_authority_failed` alert on entry, and every later operation is
//! refused until a password write clears it. Every operation, and every
//! write of the authority, runs under [`AdcsGuard`]; see there for why a
//! second one is refused rather than queued.
//!
//! # Control plane only (D13)
//!
//! The authority never replicates, so a follower has none. Its writes
//! are refused by the follower read-only gate and again here (a
//! break-glass window does not make a follower an AD CS client), and
//! its read answers `managed_on_control_plane`.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_adcs::{
    kdc_error_meaning, AdcsError, CesEndpoint, CesParams, CesTimeouts, EnrollOutcome, KdcAddress,
    KdcTiming, Krb5Config, Principal, Realm, Secret, TicketFailure,
};
use lorica_config::models::{
    validate_template_name, AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults, AllowedSuffix, Role,
    ADCS_ALLOWED_TEMPLATES_MAX,
};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditContext, ClientConnectInfo};
use crate::cluster::ClusterRuntime;
use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

mod adopt;
mod issue;
mod renew;

pub use adopt::{
    adopt_certificate, list_adoption_candidates, revert_certificate, AdcsAdoptRequest,
    AdoptionCandidate, AdoptionCandidates, AdoptionUnavailable,
};
pub use issue::{issue_certificate, AdcsIssueRequest, PendingIssuance, MAX_SANS};
pub(crate) use renew::{renew_due, renew_manually, AdcsRenewalMemory};
pub use renew::{ADCS_RENEWAL_ACTOR, ADCS_RENEWAL_BACKOFF_HOURS};

/// The target type of every audit row this module writes.
const AUDIT_TARGET: &str = "adcs_authority";

/// `request_timeout` of the generated `krb5.conf`, in seconds: the
/// bound of one KDC exchange on MIT krb5 1.22 and later. It sits well
/// inside the operation timeout of [`CesTimeouts::default`] (Epic 13
/// D3, D8), so a silent KDC is reported as unreachable before the
/// outer guard fires, and leaves room for MIT to try a second KDC.
pub const KDC_REQUEST_TIMEOUT_SECS: u32 = 30;

/// How long the renewal loop waits for a busy guard before trying its
/// AD CS batch again. A tick that gave up at the first refusal could be
/// skipped, for 12 hours, by anyone keeping the guard busy with
/// connection tests or issuances at the right moment.
const BUSY_RETRY_DELAY: Duration = Duration::from_secs(30);

/// The message of every refusal by [`AdcsGuard`].
const BUSY_MESSAGE: &str = "an AD CS operation is already running; try again once it has finished";

/// What a handler waits for its operation beyond the client's own
/// operation timeout, for the audit and breaker writes that follow it.
/// An operation that ends on that timeout is then reported by the
/// handler as it ended; only one whose GSS-API step outlived it (MIT's
/// own schedule, see [`CesTimeouts::operation`]) is answered 504.
const HANDLER_GRACE: Duration = Duration::from_secs(15);

/// How long a handler waits for its AD CS operation before answering
/// 504: [`CesTimeouts::default`]'s operation timeout, the one every
/// operation runs with, plus [`HANDLER_GRACE`].
fn handler_deadline() -> Duration {
    CesTimeouts::default().operation + HANDLER_GRACE
}

/// The message of the 504 a handler answers when its operation outlives
/// [`handler_deadline`].
const STILL_RUNNING_MESSAGE: &str = "the AD CS operation is still finishing: a Kerberos exchange \
     outlived the operation timeout. Its outcome is recorded in the audit log when it ends, and \
     every other AD CS operation is refused until then";

/// One authenticated conversation with the authority: one ticket for
/// every request of one API operation or one renewal tick (Epic 13 D3,
/// D15). It holds the service account's ticket, so it never outlives
/// the operation or the tick that opened it.
#[async_trait::async_trait]
pub(crate) trait AdcsSession: Send {
    /// Authenticate without requesting anything.
    async fn test(&mut self) -> Result<(), AdcsError>;

    /// Request a certificate for the DER PKCS#10 `csr_der`: an issuance
    /// at the authority.
    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError>;
}

/// The calls into the authority the API makes, behind a seam so tests
/// drive the handlers without a KDC. Production opens a
/// [`lorica_adcs::CesSession`].
#[async_trait::async_trait]
pub(crate) trait AdcsClient: Send + Sync {
    /// Authenticate to the CES described by `params` without
    /// requesting anything, on a session of its own.
    async fn test_connection(&self, params: &CesParams, password: &Secret)
        -> Result<(), AdcsError>;

    /// Request a certificate for `csr_der` on a session of its own.
    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError>;

    /// Open a session. The default makes every request of it a call of
    /// its own, which is what a stand-in authority needs; the real
    /// client acquires one ticket for the whole session.
    async fn open<'a>(
        &'a self,
        params: &CesParams,
        password: Secret,
    ) -> Result<Box<dyn AdcsSession + 'a>, AdcsError> {
        Ok(per_request_session(self, params, password))
    }
}

/// A session on `client` whose requests each go through its one-shot
/// calls.
pub(crate) fn per_request_session<'a, C: AdcsClient + ?Sized>(
    client: &'a C,
    params: &CesParams,
    password: Secret,
) -> Box<dyn AdcsSession + 'a> {
    Box::new(PerRequest {
        client,
        params: params.clone(),
        password,
    })
}

/// See [`per_request_session`].
struct PerRequest<'a, C: ?Sized> {
    client: &'a C,
    params: CesParams,
    password: Secret,
}

#[async_trait::async_trait]
impl<C: AdcsClient + ?Sized> AdcsSession for PerRequest<'_, C> {
    async fn test(&mut self) -> Result<(), AdcsError> {
        self.client
            .test_connection(&self.params, &self.password)
            .await
    }

    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.client
            .enroll(&self.params, &self.password, csr_der)
            .await
    }
}

/// The real client: the `lorica-adcs` crate.
struct LibAdcsClient;

/// A [`lorica_adcs::CesSession`] behind the seam.
struct LibSession(lorica_adcs::CesSession);

#[async_trait::async_trait]
impl AdcsSession for LibSession {
    async fn test(&mut self) -> Result<(), AdcsError> {
        self.0.test().await
    }

    async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.0.enroll(csr_der).await
    }
}

#[async_trait::async_trait]
impl AdcsClient for LibAdcsClient {
    async fn test_connection(
        &self,
        params: &CesParams,
        password: &Secret,
    ) -> Result<(), AdcsError> {
        lorica_adcs::test_connection(params, password).await
    }

    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError> {
        lorica_adcs::enroll(params, password, csr_der).await
    }

    async fn open<'a>(
        &'a self,
        params: &CesParams,
        password: Secret,
    ) -> Result<Box<dyn AdcsSession + 'a>, AdcsError> {
        let session = lorica_adcs::CesSession::open(params, &password).await?;
        Ok(Box::new(LibSession(session)))
    }
}

/// A session opened on its first request, so an operation refused
/// before it reaches the authority (a name, a template) builds nothing,
/// and a renewal tick shares one session across its certificates.
///
/// Opening contacts nothing (see [`lorica_adcs::CesSession::open`]), so
/// a failed open is retried on the next request at no cost to the
/// account.
pub(crate) struct LazySession<'a> {
    client: &'a dyn AdcsClient,
    params: CesParams,
    password: Secret,
    session: Option<Box<dyn AdcsSession + 'a>>,
}

impl<'a> LazySession<'a> {
    /// A session on `client` for the authority `params` describes.
    pub(crate) fn new(client: &'a dyn AdcsClient, params: CesParams, password: Secret) -> Self {
        LazySession {
            client,
            params,
            password,
            session: None,
        }
    }

    async fn opened(&mut self) -> Result<&mut Box<dyn AdcsSession + 'a>, AdcsError> {
        let session: Box<dyn AdcsSession + 'a> = match self.session.take() {
            Some(session) => session,
            None => {
                self.client
                    .open(&self.params, self.password.clone())
                    .await?
            }
        };
        Ok(self.session.insert(session))
    }

    /// See [`AdcsSession::test`].
    pub(crate) async fn test(&mut self) -> Result<(), AdcsError> {
        self.opened().await?.test().await
    }

    /// See [`AdcsSession::enroll`].
    pub(crate) async fn enroll(&mut self, csr_der: &[u8]) -> Result<EnrollOutcome, AdcsError> {
        self.opened().await?.enroll(csr_der).await
    }
}

/// The single-flight guard of every AD CS operation (Epic 13 D15).
///
/// One per process, shared by every clone of [`AppState`]. A second
/// operation is refused at once instead of waiting its turn: the
/// GSS-API calls behind an operation are blocking FFI on the blocking
/// pool, and an operation blocked on a silent KDC holds its thread
/// until MIT krb5 gives up, so a queue of callers would turn one silent
/// KDC into a pile of blocked threads, each about to spend another
/// pre-authentication attempt against the service account.
///
/// The permit lives in the task [`run_exclusive`] spawns, not in the
/// handler, and `lorica-adcs` resolves an operation only once its
/// blocking GSS-API calls have returned: so the guard is held until no
/// thread of the operation is left, even when the handler has already
/// answered 504 or its client has gone.
///
/// Authority writes take it too, so a password saved while a test is
/// in flight cannot be followed by that test's verdict on the old one.
#[derive(Clone, Default)]
pub(crate) struct AdcsGuard {
    slot: Arc<tokio::sync::Mutex<()>>,
}

/// Proof that the holder is the one AD CS operation running; the guard
/// is released when it is dropped.
pub(crate) struct AdcsPermit {
    _held: tokio::sync::OwnedMutexGuard<()>,
}

impl AdcsGuard {
    /// The permit, or `None` while another operation holds it.
    pub(crate) fn try_acquire(&self) -> Option<AdcsPermit> {
        Arc::clone(&self.slot)
            .try_lock_owned()
            .ok()
            .map(|held| AdcsPermit { _held: held })
    }
}

/// Why [`run_exclusive`] returned no output.
#[derive(Debug)]
pub(crate) enum NotRun {
    /// Another AD CS operation is running; this one never started.
    Busy,
    /// The operation started and outlived the handler's deadline. It
    /// keeps running, and the guard, until it ends.
    StillRunning,
    /// The operation's task panicked or was cancelled by the runtime.
    Lost(String),
}

/// The error of an AD CS handler, and of the certificate renewal
/// handlers, which renew AD CS certificates too: an [`ApiError`], the
/// 504 of an operation that is still finishing, or a refusal with a
/// code of its own, neither of which `ApiError` has a variant for.
#[derive(Debug)]
pub enum AdcsHandlerError {
    /// Any other refusal or failure.
    Api(ApiError),
    /// 504: the operation outlived the handler's deadline and keeps the
    /// single-flight guard until it ends.
    StillRunning,
    /// A refusal or failure the issuance endpoint names with its own
    /// code (`adcs_san_refused`, `adcs_error`, ...), so a client can
    /// tell the cases apart without reading the message.
    Coded {
        /// The HTTP status.
        status: StatusCode,
        /// The envelope's `code`.
        code: &'static str,
        /// The envelope's `message`.
        message: String,
        /// The failing step's closed name, for a failure that has one.
        step: Option<String>,
    },
}

impl From<ApiError> for AdcsHandlerError {
    fn from(err: ApiError) -> AdcsHandlerError {
        AdcsHandlerError::Api(err)
    }
}

impl From<NotRun> for AdcsHandlerError {
    fn from(not_run: NotRun) -> AdcsHandlerError {
        match not_run {
            NotRun::Busy => AdcsHandlerError::Api(ApiError::Conflict(BUSY_MESSAGE.to_string())),
            NotRun::StillRunning => AdcsHandlerError::StillRunning,
            NotRun::Lost(reason) => AdcsHandlerError::Api(ApiError::Internal(format!(
                "the AD CS operation task failed: {reason}"
            ))),
        }
    }
}

impl axum::response::IntoResponse for AdcsHandlerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AdcsHandlerError::Api(err) => err.into_response(),
            // The envelope of every other error, so a client reads it
            // the same way.
            AdcsHandlerError::StillRunning => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": {
                        "code": "gateway_timeout",
                        "message": STILL_RUNNING_MESSAGE,
                    }
                })),
            )
                .into_response(),
            AdcsHandlerError::Coded {
                status,
                code,
                message,
                step,
            } => {
                let mut error = serde_json::json!({ "code": code, "message": message });
                if let Some(step) = step {
                    error["step"] = serde_json::Value::String(step);
                }
                (status, Json(serde_json::json!({ "error": error }))).into_response()
            }
        }
    }
}

/// The process's AD CS runtime: the [`AdcsGuard`], the client the
/// handlers call, where `adcs_authority_failed` alerts go, how long a
/// handler waits for its operation, and what the renewal paths
/// remember about each certificate's failures.
#[derive(Clone)]
pub struct AdcsRuntime {
    guard: AdcsGuard,
    client: Arc<dyn AdcsClient>,
    alerts: Option<lorica_notify::AlertSender>,
    handler_deadline: Duration,
    /// How long the renewal loop waits before trying again when another
    /// AD CS operation holds the guard.
    busy_retry_delay: Duration,
    pub(crate) renewals: Arc<AdcsRenewalMemory>,
}

impl AdcsRuntime {
    /// The production runtime. `alerts` is the process's alert channel;
    /// `None` raises nothing (tests and one-shot commands).
    pub fn new(alerts: Option<lorica_notify::AlertSender>) -> AdcsRuntime {
        AdcsRuntime {
            guard: AdcsGuard::default(),
            client: Arc::new(LibAdcsClient),
            alerts,
            handler_deadline: handler_deadline(),
            busy_retry_delay: BUSY_RETRY_DELAY,
            renewals: Arc::default(),
        }
    }

    /// A runtime calling `client` instead of the authority.
    #[cfg(test)]
    pub(crate) fn with_client(
        client: Arc<dyn AdcsClient>,
        alerts: Option<lorica_notify::AlertSender>,
    ) -> AdcsRuntime {
        AdcsRuntime {
            guard: AdcsGuard::default(),
            client,
            alerts,
            handler_deadline: handler_deadline(),
            busy_retry_delay: BUSY_RETRY_DELAY,
            renewals: Arc::default(),
        }
    }

    /// The same runtime with a handler deadline short enough for a test.
    #[cfg(test)]
    pub(crate) fn with_handler_deadline(mut self, deadline: Duration) -> AdcsRuntime {
        self.handler_deadline = deadline;
        self
    }

    /// The same runtime with a renewal-loop busy retry short enough for
    /// a test.
    #[cfg(test)]
    pub(crate) fn with_busy_retry_delay(mut self, delay: Duration) -> AdcsRuntime {
        self.busy_retry_delay = delay;
        self
    }

    /// How long the renewal loop waits before retrying a busy guard.
    pub(crate) fn busy_retry_delay(&self) -> Duration {
        self.busy_retry_delay
    }

    /// The single-flight guard, for a test to hold it.
    #[cfg(test)]
    pub(crate) fn guard(&self) -> &AdcsGuard {
        &self.guard
    }
}

/// Run `operation` as the one AD CS operation of the process, or return
/// [`NotRun::Busy`] at once when another one is running (see
/// [`AdcsGuard`]).
///
/// The operation runs in a task of its own that holds the permit for
/// its whole life, so neither the handler's deadline nor a client that
/// disconnects can release the guard while it runs. When the deadline
/// passes first the handler gets [`NotRun::StillRunning`] and the task
/// carries on: whatever the operation records on completion (its audit
/// row, the D15 breaker) is therefore written by the task, never lost.
pub(crate) async fn run_exclusive<T, F>(runtime: &AdcsRuntime, operation: F) -> Result<T, NotRun>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let permit: AdcsPermit = runtime.guard.try_acquire().ok_or(NotRun::Busy)?;
    let task: tokio::task::JoinHandle<T> = tokio::spawn(async move {
        let _permit: AdcsPermit = permit;
        operation.await
    });
    match tokio::time::timeout(runtime.handler_deadline, task).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(NotRun::Lost(err.to_string())),
        Err(_) => Err(NotRun::StillRunning),
    }
}

/// Run `operation` as the one AD CS operation of the process and wait
/// for its end, or return [`NotRun::Busy`] at once when another one is
/// running. For the renewal loop, which has no client to answer: the
/// operation is a whole tick's batch, bounded per request by the
/// client's operation timeout rather than by a handler's deadline.
pub(crate) async fn run_exclusive_to_end<T, F>(
    runtime: &AdcsRuntime,
    operation: F,
) -> Result<T, NotRun>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let permit: AdcsPermit = runtime.guard.try_acquire().ok_or(NotRun::Busy)?;
    tokio::spawn(async move {
        let _permit: AdcsPermit = permit;
        operation.await
    })
    .await
    .map_err(|err| NotRun::Lost(err.to_string()))
}

/// Why no AD CS operation may start now.
#[derive(Debug)]
pub(crate) enum AdcsUnavailable {
    /// No authority is configured.
    NotConfigured,
    /// The authority is in the D15 failed state.
    Failed {
        /// The step that opened the breaker.
        step: String,
    },
    /// The authority has no password stored.
    NoPassword,
    /// The store, or the `krb5.conf` write, failed.
    Error(ApiError),
}

impl AdcsUnavailable {
    /// The closed word an audit reason spells this refusal with.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            AdcsUnavailable::NotConfigured => "not_configured",
            AdcsUnavailable::Failed { .. } => "failed_state",
            AdcsUnavailable::NoPassword => "no_password",
            AdcsUnavailable::Error(_) => "error",
        }
    }
}

impl From<ApiError> for AdcsUnavailable {
    fn from(err: ApiError) -> AdcsUnavailable {
        AdcsUnavailable::Error(err)
    }
}

impl From<lorica_config::ConfigError> for AdcsUnavailable {
    fn from(err: lorica_config::ConfigError) -> AdcsUnavailable {
        AdcsUnavailable::Error(err.into())
    }
}

impl From<AdcsUnavailable> for ApiError {
    fn from(unavailable: AdcsUnavailable) -> ApiError {
        match unavailable {
            AdcsUnavailable::NotConfigured => {
                ApiError::NotFound("no AD CS authority is configured".to_string())
            }
            AdcsUnavailable::Failed { step } => ApiError::Conflict(format!(
                "the AD CS authority is in the failed state (the KDC rejected its credential \
                 at {step}); every AD CS operation is suspended until a SuperAdmin saves a new \
                 password"
            )),
            AdcsUnavailable::NoPassword => ApiError::Unprocessable(
                "the AD CS authority has no password set; a SuperAdmin must save one".to_string(),
            ),
            AdcsUnavailable::Error(err) => err,
        }
    }
}

/// Everything one AD CS operation needs, read from the store.
pub(crate) struct AdcsOperation {
    /// The authority as stored.
    pub(crate) authority: AdcsAuthority,
    /// Its connection parameters.
    pub(crate) params: CesParams,
    /// The service account password.
    pub(crate) password: Secret,
}

/// Read the authority and its password, refuse when no operation may
/// run against it, and rewrite the `krb5.conf` from the stored row so
/// the file the library reads is the one this operation's parameters
/// came from. Call it under the [`AdcsGuard`].
pub(crate) async fn prepare_operation(state: &AppState) -> Result<AdcsOperation, AdcsUnavailable> {
    let data_dir: std::path::PathBuf = state.data_dir.clone();
    db_blocking(&state.store, move |store| {
        Ok::<_, ApiError>(prepare_operation_in(store, &data_dir))
    })
    .await?
}

fn prepare_operation_in(
    store: &ConfigStore,
    data_dir: &Path,
) -> Result<AdcsOperation, AdcsUnavailable> {
    let authority: AdcsAuthority = store
        .get_adcs_authority()?
        .ok_or(AdcsUnavailable::NotConfigured)?;
    if authority.is_failed() {
        return Err(AdcsUnavailable::Failed {
            step: authority.failed_step.clone().unwrap_or_default(),
        });
    }
    let password: Secret = store
        .get_adcs_password()?
        .map(Secret::new)
        .ok_or(AdcsUnavailable::NoPassword)?;
    let config: Krb5Config = krb5_config_of(&authority)?;
    write_krb5_conf(data_dir, &config)?;
    let params: CesParams = CesParams {
        endpoint: authority.endpoint.clone(),
        realm: config.realm,
        principal: authority.principal.clone(),
        trust_bundle_pem: authority.endpoint_ca_pem.clone(),
        timeouts: CesTimeouts::default(),
    };
    Ok(AdcsOperation {
        authority,
        params,
        password,
    })
}

/// The `krb5.conf` of a stored authority. The values were validated by
/// the same types when they were written, so a refusal here means the
/// row was changed behind the API's back.
fn krb5_config_of(authority: &AdcsAuthority) -> Result<Krb5Config, ApiError> {
    let corrupt = |err: AdcsError| ApiError::Internal(format!("stored AD CS authority: {err}"));
    Ok(Krb5Config {
        realm: Realm::new(&authority.realm).map_err(corrupt)?,
        kdcs: authority
            .kdcs
            .iter()
            .map(|kdc: &String| KdcAddress::new(kdc))
            .collect::<Result<Vec<KdcAddress>, AdcsError>>()
            .map_err(corrupt)?,
        timing: KdcTiming::new(KDC_REQUEST_TIMEOUT_SECS).map_err(corrupt)?,
    })
}

fn write_krb5_conf(data_dir: &Path, config: &Krb5Config) -> Result<(), ApiError> {
    config
        .write_to(&lorica_adcs::krb5_config_path(data_dir))
        .map_err(|err: AdcsError| ApiError::Internal(err.to_string()))
}

/// Regenerate the `krb5.conf` from the stored authority, once, when the
/// management API starts on a node that runs AD CS operations. The file
/// is rewritten on every authority write and before every operation;
/// this covers a data directory restored without it, or an upgrade that
/// changed what the renderer writes. A failure is logged, not fatal:
/// the next operation writes the file again and reports its own error.
pub async fn write_krb5_conf_at_startup(state: &AppState) {
    let data_dir: std::path::PathBuf = state.data_dir.clone();
    let written = db_blocking(&state.store, move |store| {
        let Some(authority) = store.get_adcs_authority()? else {
            return Ok::<bool, ApiError>(false);
        };
        write_krb5_conf(&data_dir, &krb5_config_of(&authority)?)?;
        Ok(true)
    })
    .await;
    match written {
        Ok(true) => tracing::info!("AD CS krb5.conf regenerated from the stored authority"),
        Ok(false) => {}
        Err(err) => tracing::warn!(
            error = %err,
            "could not regenerate the AD CS krb5.conf at startup; the next AD CS operation \
             writes it again"
        ),
    }
}

/// Open the D15 breaker when `err` is a credential the KDC rejected.
///
/// Returns `true` when this call is the entry into the failed state; it
/// then audits the entry under `ctx` and raises the one
/// `adcs_authority_failed` alert the entry is owed. Any other error, or
/// an authority already failed, changes nothing.
pub(crate) async fn record_credential_rejection(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    err: &AdcsError,
) -> Result<bool, ApiError> {
    let AdcsError::Ticket {
        failure: TicketFailure::CredentialRejected,
        kdc_error_code,
        ..
    } = err
    else {
        return Ok(false);
    };
    let step: &'static str = err.step().as_str();
    let kdc_code: Option<i32> = kdc_error_code.and_then(|code: u32| i32::try_from(code).ok());
    let entered: bool = db_blocking(&state.store, move |store| {
        store.set_adcs_failed(step, kdc_code)
    })
    .await?;
    if !entered {
        return Ok(false);
    }
    crate::audit::record(
        state,
        ctx,
        &format!("adcs.authority.failed_state.enter:{step}"),
        (AUDIT_TARGET, authority_id),
        None,
        None,
    )
    .await;
    if let Some(alerts) = &state.adcs.alerts {
        let mut event = lorica_notify::AlertEvent::new(
            lorica_notify::events::AlertType::AdcsAuthorityFailed,
            "The KDC rejected the AD CS service account's credential; every AD CS operation \
             is suspended until a SuperAdmin saves a new password",
        )
        .with_detail("authority_id", authority_id)
        .with_detail("step", step)
        .with_detail("message", err.to_string());
        if let Some(code) = kdc_code {
            event = event.with_detail("kdc_code", code.to_string());
        }
        alerts.send(event);
    }
    Ok(true)
}

/// A follower holds no authority and runs no AD CS operation (D13),
/// break-glass window or not.
fn refuse_on_follower(state: &AppState) -> Result<(), ApiError> {
    if let ClusterRuntime::Follower(follower) = &state.cluster {
        return Err(ApiError::Conflict(format!(
            "this node is a follower of {}: the AD CS authority is managed on the control plane",
            follower.control_plane
        )));
    }
    Ok(())
}

/// The service account password of a write, accepted and never shown:
/// its `Debug` is redacted and it has no `Serialize`.
pub struct WritePassword(Secret);

impl<'de> Deserialize<'de> for WritePassword {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text: String| WritePassword(Secret::new(text)))
    }
}

impl std::fmt::Debug for WritePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WritePassword(<redacted>)")
    }
}

/// Body of `PUT /api/v1/adcs/authority`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsAuthorityRequest {
    /// The CES endpoint, `https://` with a DNS host name.
    pub endpoint: String,
    /// The Kerberos realm, `^[A-Z0-9][A-Z0-9.-]*$`.
    pub realm: String,
    /// Explicit KDCs as `host[:port]`, at most [`MAX_KDCS`]; empty means
    /// DNS SRV discovery.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// The service account, `user` or `user@REALM`.
    pub principal: String,
    /// The service account password. Required on creation and with any
    /// change of `endpoint`, `realm`, `kdcs`, `principal` or
    /// `endpoint_ca_pem`; optional otherwise, where it replaces the
    /// stored one. Never returned.
    #[serde(default)]
    pub password: Option<WritePassword>,
    /// PEM certificates trusted, alone, for the endpoint's TLS
    /// certificate.
    #[serde(default)]
    pub endpoint_ca_pem: Option<String>,
    /// The issuing CA certificate, PEM.
    #[serde(default)]
    pub issuing_ca_pem: Option<String>,
    /// The template's common name.
    pub default_template: String,
    /// The other template common names an issuance may request (D17);
    /// the default template is always permitted.
    #[serde(default)]
    pub allowed_templates: Vec<String>,
    /// The key type of a new certificate.
    #[serde(default)]
    pub default_key_type: AdcsKeyType,
    /// The fixed part of every subject.
    #[serde(default)]
    pub subject: AdcsSubjectDefaults,
    /// DNS suffixes Lorica may request names under; at least one.
    pub allowed_suffixes: Vec<String>,
    /// The auto-renew setting a newly issued certificate starts with.
    pub auto_renew_default: bool,
}

/// The most explicit KDCs an authority may list. MIT tries them in
/// turn, each silent one costing its own retry schedule while the
/// operation holds the single-flight guard, so the list is bounded.
pub const MAX_KDCS: usize = 10;

/// The configuration part of a request once every field is valid.
struct ValidatedRequest {
    endpoint: String,
    realm: String,
    kdcs: Vec<String>,
    principal: String,
    endpoint_ca_pem: Option<String>,
    issuing_ca_pem: Option<String>,
    default_template: String,
    allowed_templates: Vec<String>,
    default_key_type: AdcsKeyType,
    subject: AdcsSubjectDefaults,
    allowed_suffixes: Vec<AllowedSuffix>,
    auto_renew_default: bool,
}

fn refuse(reason: String) -> ApiError {
    ApiError::Unprocessable(reason)
}

fn has_control_characters(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// A PEM bundle of at least one certificate, every block a certificate
/// x509-parser reads. `None` and blank stay unset.
fn validate_pem_bundle(field: &str, raw: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(text) = raw.map(|text: String| text.trim().to_string()) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    let blocks: Vec<pem::Pem> =
        pem::parse_many(&text).map_err(|err| refuse(format!("{field}: not PEM ({err})")))?;
    if blocks.is_empty() {
        return Err(refuse(format!("{field}: no PEM certificate found")));
    }
    for block in &blocks {
        if block.tag() != "CERTIFICATE" {
            return Err(refuse(format!(
                "{field}: every PEM block must be a CERTIFICATE, found {}",
                block.tag()
            )));
        }
        x509_parser::parse_x509_certificate(block.contents())
            .map_err(|err| refuse(format!("{field}: unreadable certificate ({err})")))?;
    }
    Ok(Some(text))
}

/// Trimmed, blank as unset, and free of control characters: every
/// subject field is written into a CSR's distinguished name.
fn validate_subject(subject: AdcsSubjectDefaults) -> Result<AdcsSubjectDefaults, ApiError> {
    let clean = |field: &str, value: Option<String>| -> Result<Option<String>, ApiError> {
        let value: Option<String> = value
            .map(|text: String| text.trim().to_string())
            .filter(|text: &String| !text.is_empty());
        if value.as_deref().is_some_and(has_control_characters) {
            return Err(refuse(format!(
                "subject.{field}: control characters are refused"
            )));
        }
        Ok(value)
    };
    let country: Option<String> = clean("country", subject.country)?;
    if let Some(code) = &country {
        if code.len() != 2 || !code.chars().all(|c: char| c.is_ascii_alphabetic()) {
            return Err(refuse(
                "subject.country: must be a two-letter ISO 3166 code".to_string(),
            ));
        }
    }
    Ok(AdcsSubjectDefaults {
        country: country.map(|code: String| code.to_ascii_uppercase()),
        state: clean("state", subject.state)?,
        locality: clean("locality", subject.locality)?,
        organization: clean("organization", subject.organization)?,
        organizational_unit: clean("organizational_unit", subject.organizational_unit)?,
        email: clean("email", subject.email)?,
    })
}

/// The allowed template list as stored: each name trimmed and checked,
/// the default first, no name twice (ignoring ASCII case, as the
/// authority does).
fn allowed_template_list(
    default_template: &str,
    requested: &[String],
) -> Result<Vec<String>, ApiError> {
    let mut list: Vec<String> = vec![default_template.to_string()];
    for raw in requested {
        let name: &str = raw.trim();
        validate_template_name("allowed_templates", name)?;
        if !list
            .iter()
            .any(|kept: &String| kept.eq_ignore_ascii_case(name))
        {
            list.push(name.to_string());
        }
    }
    if list.len() > ADCS_ALLOWED_TEMPLATES_MAX {
        return Err(refuse(format!(
            "allowed_templates: at most {ADCS_ALLOWED_TEMPLATES_MAX} templates, the default \
             included"
        )));
    }
    Ok(list)
}

impl AdcsAuthorityRequest {
    /// Validate every field, splitting the password off. The endpoint,
    /// realm, KDC and principal rules are `lorica_adcs`'s own, the ones
    /// the client applies before it connects, so a value refused at the
    /// first operation is refused here instead.
    fn validate(self) -> Result<(ValidatedRequest, Option<Secret>), ApiError> {
        let endpoint: &str = self.endpoint.trim();
        CesEndpoint::new(endpoint).map_err(|err: AdcsError| refuse(format!("endpoint: {err}")))?;
        let realm: Realm =
            Realm::new(self.realm.trim()).map_err(|err: AdcsError| refuse(err.to_string()))?;
        if self.kdcs.len() > MAX_KDCS {
            return Err(refuse(format!(
                "kdcs: at most {MAX_KDCS} KDCs, {} given",
                self.kdcs.len()
            )));
        }
        let kdcs: Vec<String> = self
            .kdcs
            .iter()
            .map(|kdc: &String| {
                KdcAddress::new(kdc.trim())
                    .map(|address: KdcAddress| address.to_string())
                    .map_err(|err: AdcsError| refuse(err.to_string()))
            })
            .collect::<Result<Vec<String>, ApiError>>()?;
        let principal: &str = self.principal.trim();
        Principal::new(principal, &realm)
            .map_err(|err: AdcsError| refuse(format!("principal: {err}")))?;
        let default_template: String = self.default_template.trim().to_string();
        validate_template_name("default_template", &default_template)?;
        let allowed_templates: Vec<String> =
            allowed_template_list(&default_template, &self.allowed_templates)?;
        if self.allowed_suffixes.is_empty() {
            return Err(refuse(
                "allowed_suffixes: at least one DNS suffix is required".to_string(),
            ));
        }
        let allowed_suffixes: Vec<AllowedSuffix> = self
            .allowed_suffixes
            .iter()
            .map(|suffix: &String| AllowedSuffix::new(suffix.trim()))
            .collect::<Result<Vec<AllowedSuffix>, lorica_config::ConfigError>>()?;
        let validated: ValidatedRequest = ValidatedRequest {
            endpoint: endpoint.to_string(),
            realm: realm.as_str().to_string(),
            kdcs,
            principal: principal.to_string(),
            endpoint_ca_pem: validate_pem_bundle("endpoint_ca_pem", self.endpoint_ca_pem)?,
            issuing_ca_pem: validate_pem_bundle("issuing_ca_pem", self.issuing_ca_pem)?,
            default_template,
            allowed_templates,
            default_key_type: self.default_key_type,
            subject: validate_subject(self.subject)?,
            allowed_suffixes,
            auto_renew_default: self.auto_renew_default,
        };
        Ok((
            validated,
            self.password.map(|password: WritePassword| password.0),
        ))
    }
}

/// The authority as Operators and SuperAdmins read it: every stored
/// field except the password, which is reported as set or not.
#[derive(Debug, Serialize)]
pub struct AdcsAuthorityView {
    /// The stored authority.
    #[serde(flatten)]
    pub authority: AdcsAuthority,
    /// Whether a service account password is stored.
    pub password_set: bool,
}

/// What every role may read of the authority (D18): that it exists,
/// which names it may issue, and whether it is in the failed state. The
/// endpoint, realm, KDCs, principal, CA certificates and templates map
/// the domain's PKI, so they are in [`AdcsAuthorityView`] only.
#[derive(Debug, Serialize)]
pub struct AdcsAuthoritySummary {
    /// DNS suffixes Lorica may request names under.
    pub allowed_suffixes: Vec<AllowedSuffix>,
    /// When the authority entered the D15 failed state, `null` when it
    /// is not failed.
    pub failed_since: Option<chrono::DateTime<Utc>>,
    /// The step that opened the breaker.
    pub failed_step: Option<String>,
    /// The KDC error code that opened it.
    pub failed_kdc_code: Option<i32>,
    /// What that code means for the service account, when it is one
    /// that rejects the credential.
    pub failed_reason: Option<&'static str>,
}

impl AdcsAuthoritySummary {
    fn of(authority: &AdcsAuthority) -> AdcsAuthoritySummary {
        AdcsAuthoritySummary {
            allowed_suffixes: authority.allowed_suffixes.clone(),
            failed_since: authority.failed_since,
            failed_step: authority.failed_step.clone(),
            failed_kdc_code: authority.failed_kdc_code,
            failed_reason: authority
                .failed_kdc_code
                .and_then(|code: i32| u32::try_from(code).ok())
                .and_then(kdc_error_meaning),
        }
    }
}

/// Body of `GET /api/v1/adcs/authority`.
#[derive(Debug, Serialize)]
pub struct AdcsAuthorityState {
    /// Whether an authority is configured on this node; `false` on a
    /// follower.
    pub configured: bool,
    /// `true` on a follower: the authority lives on the control plane
    /// only (D13), so this node has none to show.
    pub managed_on_control_plane: bool,
    /// What every role may read, `null` when no authority is
    /// configured.
    pub summary: Option<AdcsAuthoritySummary>,
    /// The whole authority, for Operators and SuperAdmins only (D18);
    /// `null` for a Viewer, when none is configured, or on a follower.
    pub authority: Option<AdcsAuthorityView>,
}

/// GET /api/v1/adcs/authority - the authority without its password; its
/// connection details only to Operators and above (D18).
pub async fn get_adcs_authority(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if matches!(state.cluster, ClusterRuntime::Follower(_)) {
        return Ok(json_data(AdcsAuthorityState {
            configured: false,
            managed_on_control_plane: true,
            summary: None,
            authority: None,
        }));
    }
    let (authority, password_set) = db_blocking(&state.store, |store| {
        let authority: Option<AdcsAuthority> = store.get_adcs_authority()?;
        let password_set: bool = store.has_adcs_password()?;
        Ok::<_, lorica_config::ConfigError>((authority, password_set))
    })
    .await?;
    let sees_details: bool = session.role >= Role::Operator;
    Ok(json_data(AdcsAuthorityState {
        configured: authority.is_some(),
        managed_on_control_plane: false,
        summary: authority.as_ref().map(AdcsAuthoritySummary::of),
        authority: authority
            .filter(|_| sees_details)
            .map(|authority: AdcsAuthority| AdcsAuthorityView {
                authority,
                password_set,
            }),
    }))
}

/// Fields of the stored model that are not configuration an operator
/// edits, left out of the changed-field list of an update's audit row.
const NON_CONFIGURATION_FIELDS: &[&str] = &[
    "id",
    "created_at",
    "updated_at",
    "failed_since",
    "failed_step",
    "failed_kdc_code",
];

/// The serialised names of the configuration fields that differ, in
/// name order. Derived from the model's own serialisation, so a field
/// added to [`AdcsAuthority`] is reported without touching this.
fn changed_fields(before: &AdcsAuthority, after: &AdcsAuthority) -> Result<Vec<String>, ApiError> {
    let as_object = |authority: &AdcsAuthority| -> Result<serde_json::Map<String, serde_json::Value>, ApiError> {
        match serde_json::to_value(authority) {
            Ok(serde_json::Value::Object(map)) => Ok(map),
            Ok(_) => Err(ApiError::Internal(
                "the AD CS authority does not serialise as an object".to_string(),
            )),
            Err(err) => Err(ApiError::Internal(format!(
                "cannot serialise the AD CS authority: {err}"
            ))),
        }
    };
    let before = as_object(before)?;
    let after = as_object(after)?;
    Ok(after
        .iter()
        .filter(|(name, _)| !NON_CONFIGURATION_FIELDS.contains(&name.as_str()))
        .filter(|(name, value)| before.get(name.as_str()) != Some(*value))
        .map(|(name, _)| name.clone())
        .collect())
}

/// What a write did, for the response and the audit rows.
struct WriteOutcome {
    view: AdcsAuthorityView,
    created: bool,
    changed: Vec<String>,
    left_failed_state: bool,
}

/// PUT /api/v1/adcs/authority - create or update the authority
/// (SuperAdmin).
pub async fn put_adcs_authority(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<AdcsAuthorityRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AdcsHandlerError> {
    refuse_on_follower(&state)?;
    let (request, password): (ValidatedRequest, Option<Secret>) = body.validate()?;
    let data_dir: std::path::PathBuf = state.data_dir.clone();
    let store = Arc::clone(&state.store);
    let outcome: WriteOutcome = run_exclusive(&state.adcs, async move {
        db_blocking(&store, move |store| {
            store.in_transaction(|store: &ConfigStore| {
                write_authority(store, &data_dir, request, password)
            })
        })
        .await
    })
    .await??;

    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    let target: (&str, &str) = (AUDIT_TARGET, outcome.view.authority.id.as_str());
    // Field names only: the body carries the password, and the audit
    // row hashes whatever payload it is given.
    let action: String = if outcome.created {
        "adcs.authority.create".to_string()
    } else if outcome.changed.is_empty() {
        "adcs.authority.update".to_string()
    } else {
        format!("adcs.authority.update:{}", outcome.changed.join(","))
    };
    crate::audit::record(&state, &ctx, &action, target, None, None).await;
    if outcome.left_failed_state {
        crate::audit::record(
            &state,
            &ctx,
            "adcs.authority.failed_state.exit",
            target,
            None,
            None,
        )
        .await;
    }

    let status: StatusCode = if outcome.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok(json_data_with_status(status, outcome.view))
}

/// The store side of a write, inside one transaction.
fn write_authority(
    store: &ConfigStore,
    data_dir: &Path,
    request: ValidatedRequest,
    password: Option<Secret>,
) -> Result<WriteOutcome, ApiError> {
    let existing: Option<AdcsAuthority> = store.get_adcs_authority()?;
    let now: chrono::DateTime<Utc> = Utc::now();
    let authority: AdcsAuthority = AdcsAuthority {
        id: existing
            .as_ref()
            .map_or_else(lorica_config::store::new_id, |a: &AdcsAuthority| {
                a.id.clone()
            }),
        endpoint: request.endpoint,
        realm: request.realm,
        kdcs: request.kdcs,
        principal: request.principal,
        endpoint_ca_pem: request.endpoint_ca_pem,
        issuing_ca_pem: request.issuing_ca_pem,
        default_template: request.default_template,
        allowed_templates: request.allowed_templates,
        default_key_type: request.default_key_type,
        subject: request.subject,
        allowed_suffixes: request.allowed_suffixes,
        auto_renew_default: request.auto_renew_default,
        failed_since: existing.as_ref().and_then(|a| a.failed_since),
        failed_step: existing.as_ref().and_then(|a| a.failed_step.clone()),
        failed_kdc_code: existing.as_ref().and_then(|a| a.failed_kdc_code),
        created_at: existing
            .as_ref()
            .map_or(now, |a: &AdcsAuthority| a.created_at),
        updated_at: now,
    };

    // A creation is an identity change from nothing: an authority with
    // no credential could only fail its first test. The trust bundle is
    // part of the identity: it decides which TLS endpoint the
    // credential's tokens are sent to.
    let identity_changed: bool = existing.as_ref().is_none_or(|stored: &AdcsAuthority| {
        stored.endpoint != authority.endpoint
            || stored.realm != authority.realm
            || stored.kdcs != authority.kdcs
            || stored.principal != authority.principal
            || stored.endpoint_ca_pem != authority.endpoint_ca_pem
    });
    if identity_changed && password.is_none() {
        return Err(ApiError::Unprocessable(if existing.is_none() {
            "password: required when creating the AD CS authority".to_string()
        } else {
            "password: changing the endpoint, realm, KDC list, principal or endpoint trust \
             bundle clears the stored password, so the same request must supply a new one"
                .to_string()
        }));
    }

    store.upsert_adcs_authority(&authority)?;
    let mut changed: Vec<String> = match &existing {
        Some(stored) => changed_fields(stored, &authority)?,
        None => Vec::new(),
    };
    let left_failed_state: bool = match &password {
        Some(secret) => {
            secret.expose(|text: &str| store.set_adcs_password(Some(text)))?;
            changed.push("password".to_string());
            store.clear_adcs_failed()?
        }
        None => false,
    };
    // Inside the transaction: a file that cannot be written rolls the
    // row back, so the stored authority and the file never disagree.
    write_krb5_conf(data_dir, &krb5_config_of(&authority)?)?;

    let stored: AdcsAuthority = store.get_adcs_authority()?.ok_or_else(|| {
        ApiError::Internal("the AD CS authority vanished inside its own write".to_string())
    })?;
    Ok(WriteOutcome {
        view: AdcsAuthorityView {
            authority: stored,
            password_set: store.has_adcs_password()?,
        },
        created: existing.is_none(),
        changed,
        left_failed_state,
    })
}

/// DELETE /api/v1/adcs/authority - remove the authority (SuperAdmin),
/// refused while any certificate references it.
pub async fn delete_adcs_authority(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, AdcsHandlerError> {
    refuse_on_follower(&state)?;
    let store = Arc::clone(&state.store);
    let id: String = run_exclusive(&state.adcs, async move {
        db_blocking(&store, |store| {
            let authority: AdcsAuthority = store.get_adcs_authority()?.ok_or_else(|| {
                ApiError::NotFound("no AD CS authority is configured".to_string())
            })?;
            let referencing: Vec<String> = store.adcs_authority_certificate_ids(&authority.id)?;
            if !referencing.is_empty() {
                return Err(ApiError::Conflict(format!(
                    "the AD CS authority is used by certificates {}; revert them to manual or \
                     delete them first",
                    referencing.join(", ")
                )));
            }
            store.delete_adcs_authority(&authority.id)?;
            Ok::<String, ApiError>(authority.id)
        })
        .await
    })
    .await??;

    // A file left behind would describe a realm nothing uses any more.
    let krb5_conf: std::path::PathBuf = lorica_adcs::krb5_config_path(&state.data_dir);
    if let Err(err) = std::fs::remove_file(&krb5_conf) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                error = %err,
                path = %krb5_conf.display(),
                "AD CS authority deleted, but its krb5.conf could not be removed"
            );
        }
    }

    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &ctx,
        "adcs.authority.delete",
        (AUDIT_TARGET, &id),
        None,
        None,
    )
    .await;
    Ok(json_data(serde_json::json!({
        "message": "AD CS authority deleted"
    })))
}

/// Body of a connection test's answer.
#[derive(Debug, Serialize)]
pub struct ConnectionTestResult {
    /// Whether Lorica authenticated to the endpoint, mutual
    /// authentication included.
    pub ok: bool,
    /// The failing step's closed name (`ticket_acquisition`,
    /// `kdc_discovery`, `tls`, `channel_binding`, `spnego`,
    /// `mutual_authentication`, ...), `null` on success.
    pub step: Option<&'static str>,
    /// The client's error text, which names the step in words, `null`
    /// on success.
    pub message: Option<String>,
    /// Whether this test put the authority in the failed state.
    pub authority_failed: bool,
}

/// POST /api/v1/adcs/authority/test - authenticate to the authority
/// without requesting a certificate (Operator).
///
/// A test that outlives the handler's deadline is answered 504 and
/// finishes in its own task, which writes its audit row and, for a
/// rejected credential, opens the breaker when it ends.
pub async fn test_adcs_authority(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, AdcsHandlerError> {
    refuse_on_follower(&state)?;
    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    let task_state: AppState = state.clone();
    let task_ctx: AuditContext = ctx.clone();
    let test = async move { run_connection_test(&task_state, &task_ctx).await };
    match run_exclusive(&state.adcs, test).await {
        Ok(outcome) => Ok(json_data(outcome?)),
        Err(NotRun::Busy) => {
            crate::audit::record(
                &state,
                &ctx,
                "adcs.authority.test.refused:busy",
                (AUDIT_TARGET, ""),
                None,
                None,
            )
            .await;
            Err(NotRun::Busy.into())
        }
        Err(not_run) => Err(not_run.into()),
    }
}

async fn run_connection_test(
    state: &AppState,
    ctx: &AuditContext,
) -> Result<ConnectionTestResult, ApiError> {
    let operation: AdcsOperation = match prepare_operation(state).await {
        Ok(operation) => operation,
        Err(unavailable) => {
            crate::audit::record(
                state,
                ctx,
                &format!("adcs.authority.test.refused:{}", unavailable.audit_reason()),
                (AUDIT_TARGET, ""),
                None,
                None,
            )
            .await;
            return Err(unavailable.into());
        }
    };
    let AdcsOperation {
        authority,
        params,
        password,
    } = operation;
    let authority_id: &str = authority.id.as_str();
    let mut session: LazySession<'_> =
        LazySession::new(state.adcs.client.as_ref(), params, password);
    let result: Result<(), AdcsError> = session.test().await;
    drop(session);

    let err: AdcsError = match result {
        Ok(()) => {
            crate::audit::record(
                state,
                ctx,
                "adcs.authority.test.ok",
                (AUDIT_TARGET, authority_id),
                None,
                None,
            )
            .await;
            return Ok(ConnectionTestResult {
                ok: true,
                step: None,
                message: None,
                authority_failed: false,
            });
        }
        Err(err) => err,
    };
    let step: &'static str = err.step().as_str();
    crate::audit::record(
        state,
        ctx,
        &format!("adcs.authority.test.failed:{step}"),
        (AUDIT_TARGET, authority_id),
        None,
        None,
    )
    .await;
    let authority_failed: bool =
        record_credential_rejection(state, ctx, authority_id, &err).await?;
    Ok(ConnectionTestResult {
        ok: false,
        step: Some(step),
        message: Some(err.to_string()),
        authority_failed,
    })
}

#[cfg(test)]
mod tests;
