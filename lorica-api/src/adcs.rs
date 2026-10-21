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
//! edit the suffixes decides which names Lorica may request.
//!
//! # The password
//!
//! Write-only. It arrives as [`WritePassword`], which wraps a
//! [`lorica_adcs::Secret`] and prints as redacted, goes straight into
//! the store's encrypted column, and is never returned: a read reports
//! `password_set` only. A change to the endpoint, realm, KDC list or
//! principal is refused unless the same request carries a new password,
//! because the stored one was given for the old identity (D11). The
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
    AdcsError, CesParams, CesTimeouts, EnrollOutcome, KdcAddress, KdcTiming, Krb5Config, Realm,
    Secret, TicketFailure,
};
use lorica_config::models::{AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults, AllowedSuffix};
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

/// The calls into the authority the API makes, behind a seam so tests
/// drive the handlers without a KDC. Production uses
/// [`lorica_adcs::test_connection`] and [`lorica_adcs::enroll`].
#[async_trait::async_trait]
pub(crate) trait AdcsClient: Send + Sync {
    /// Authenticate to the CES described by `params` without
    /// requesting anything.
    async fn test_connection(&self, params: &CesParams, password: &Secret)
        -> Result<(), AdcsError>;

    /// Request a certificate for the DER PKCS#10 `csr_der`: an issuance
    /// at the authority.
    async fn enroll(
        &self,
        params: &CesParams,
        password: &Secret,
        csr_der: &[u8],
    ) -> Result<EnrollOutcome, AdcsError>;
}

/// The real client: the `lorica-adcs` crate.
struct LibAdcsClient;

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
            renewals: Arc::default(),
        }
    }

    /// The same runtime with a handler deadline short enough for a test.
    #[cfg(test)]
    pub(crate) fn with_handler_deadline(mut self, deadline: Duration) -> AdcsRuntime {
        self.handler_deadline = deadline;
        self
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

/// The closed step word an AD CS error is audited and persisted under.
/// The operator reads the error's own text, which names the step in
/// words (Story 13.1 AC #8); this is the field a filter matches on.
pub(crate) fn failure_step(err: &AdcsError) -> &'static str {
    match err {
        AdcsError::Ticket { failure, .. } => match failure {
            TicketFailure::KdcUnreachable => "kdc_discovery",
            TicketFailure::CredentialRejected => "ticket_acquisition",
        },
        AdcsError::ServiceName { .. } | AdcsError::Spnego { .. } => "spnego",
        AdcsError::MutualAuth { .. } => "mutual_authentication",
        AdcsError::ChannelBindingCertificate { .. } | AdcsError::ChannelBindingAlgorithm { .. } => {
            "channel_binding"
        }
        AdcsError::Tls { .. } => "tls",
        AdcsError::Http { .. } => "http",
        AdcsError::InvalidRealm { .. }
        | AdcsError::InvalidKdc { .. }
        | AdcsError::InvalidKdcTiming { .. }
        | AdcsError::Krb5ConfWrite { .. } => "krb5_conf",
        AdcsError::InvalidParams { .. } => "configuration",
        AdcsError::Csr { .. } => "csr",
        AdcsError::SoapEnvelope { .. } | AdcsError::SoapResponse { .. } => "soap",
        AdcsError::Chain { .. } => "chain",
        AdcsError::Timeout { .. } => "timeout",
        AdcsError::GssTask { .. } => "gss_task",
        _ => "other",
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
    let step: &'static str = failure_step(err);
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
    /// Explicit KDCs as `host[:port]`; empty means DNS SRV discovery.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// The service account, `user` or `user@REALM`.
    pub principal: String,
    /// The service account password. Required on creation and with any
    /// change of `endpoint`, `realm`, `kdcs` or `principal`; optional
    /// otherwise, where it replaces the stored one. Never returned.
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

/// The configuration part of a request once every field is valid.
struct ValidatedRequest {
    endpoint: String,
    realm: String,
    kdcs: Vec<String>,
    principal: String,
    endpoint_ca_pem: Option<String>,
    issuing_ca_pem: Option<String>,
    default_template: String,
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

/// The endpoint's rules, those `lorica_adcs` applies before connecting:
/// `https://`, no credentials in the URL, and a DNS host name, since the
/// service ticket is for `HTTP/<host>`.
fn validate_endpoint(raw: &str) -> Result<String, ApiError> {
    let endpoint: &str = raw.trim();
    let url: reqwest::Url = reqwest::Url::parse(endpoint)
        .map_err(|err| refuse(format!("endpoint: not a URL ({err})")))?;
    if url.scheme() != "https" {
        return Err(refuse("endpoint: must be an https:// URL".to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse(
            "endpoint: must not carry credentials in the URL".to_string(),
        ));
    }
    if url.domain().is_none() {
        return Err(refuse(
            "endpoint: the host must be a DNS name, the service ticket is for HTTP/<host>"
                .to_string(),
        ));
    }
    Ok(endpoint.to_string())
}

/// `user` or `user@REALM` with the authority's realm, as the client
/// builds the principal name.
fn validate_principal(raw: &str, realm: &Realm) -> Result<String, ApiError> {
    let principal: &str = raw.trim();
    if principal.is_empty()
        || principal
            .chars()
            .any(|c: char| c.is_control() || c.is_whitespace())
    {
        return Err(refuse(
            "principal: required, with no spaces or control characters".to_string(),
        ));
    }
    match principal.split_once('@') {
        None => Ok(principal.to_string()),
        Some((user, principal_realm)) if !user.is_empty() && principal_realm == realm.as_str() => {
            Ok(principal.to_string())
        }
        Some(_) => Err(refuse(format!(
            "principal: must be a user name or user@{realm}"
        ))),
    }
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

impl AdcsAuthorityRequest {
    /// Validate every field, splitting the password off.
    fn validate(self) -> Result<(ValidatedRequest, Option<Secret>), ApiError> {
        let endpoint: String = validate_endpoint(&self.endpoint)?;
        let realm: Realm =
            Realm::new(self.realm.trim()).map_err(|err: AdcsError| refuse(err.to_string()))?;
        let kdcs: Vec<String> = self
            .kdcs
            .iter()
            .map(|kdc: &String| {
                KdcAddress::new(kdc.trim())
                    .map(|address: KdcAddress| address.to_string())
                    .map_err(|err: AdcsError| refuse(err.to_string()))
            })
            .collect::<Result<Vec<String>, ApiError>>()?;
        let principal: String = validate_principal(&self.principal, &realm)?;
        let default_template: String = self.default_template.trim().to_string();
        if default_template.is_empty() || has_control_characters(&default_template) {
            return Err(refuse(
                "default_template: the template's common name is required".to_string(),
            ));
        }
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
            endpoint,
            realm: realm.as_str().to_string(),
            kdcs,
            principal,
            endpoint_ca_pem: validate_pem_bundle("endpoint_ca_pem", self.endpoint_ca_pem)?,
            issuing_ca_pem: validate_pem_bundle("issuing_ca_pem", self.issuing_ca_pem)?,
            default_template,
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

/// The authority as a read returns it: every stored field except the
/// password, which is reported as set or not.
#[derive(Debug, Serialize)]
pub struct AdcsAuthorityView {
    /// The stored authority.
    #[serde(flatten)]
    pub authority: AdcsAuthority,
    /// Whether a service account password is stored.
    pub password_set: bool,
}

/// Body of `GET /api/v1/adcs/authority`.
#[derive(Debug, Serialize)]
pub struct AdcsAuthorityState {
    /// The authority, `null` when none is configured or on a follower.
    pub authority: Option<AdcsAuthorityView>,
    /// `true` on a follower: the authority lives on the control plane
    /// only (D13), so this node has none to show.
    pub managed_on_control_plane: bool,
}

/// Whether a password is stored. The decrypted text goes into a
/// [`Secret`] at once so its buffer is wiped.
fn password_is_set(store: &ConfigStore) -> Result<bool, lorica_config::ConfigError> {
    Ok(store.get_adcs_password()?.map(Secret::new).is_some())
}

/// GET /api/v1/adcs/authority - the authority without its password.
pub async fn get_adcs_authority(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if matches!(state.cluster, ClusterRuntime::Follower(_)) {
        return Ok(json_data(AdcsAuthorityState {
            authority: None,
            managed_on_control_plane: true,
        }));
    }
    let authority: Option<AdcsAuthorityView> = db_blocking(&state.store, |store| {
        let Some(authority) = store.get_adcs_authority()? else {
            return Ok::<_, lorica_config::ConfigError>(None);
        };
        Ok(Some(AdcsAuthorityView {
            authority,
            password_set: password_is_set(store)?,
        }))
    })
    .await?;
    Ok(json_data(AdcsAuthorityState {
        authority,
        managed_on_control_plane: false,
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
    // no credential could only fail its first test.
    let identity_changed: bool = existing.as_ref().is_none_or(|stored: &AdcsAuthority| {
        stored.endpoint != authority.endpoint
            || stored.realm != authority.realm
            || stored.kdcs != authority.kdcs
            || stored.principal != authority.principal
    });
    if identity_changed && password.is_none() {
        return Err(ApiError::Unprocessable(if existing.is_none() {
            "password: required when creating the AD CS authority".to_string()
        } else {
            "password: changing the endpoint, realm, KDC list or principal clears the stored \
             password, so the same request must supply a new one"
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
            password_set: password_is_set(store)?,
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
    let authority_id: &str = operation.authority.id.as_str();
    let result: Result<(), AdcsError> = state
        .adcs
        .client
        .test_connection(&operation.params, &operation.password)
        .await;
    drop(operation.password);

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
    let step: &'static str = failure_step(&err);
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
