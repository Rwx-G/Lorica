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

//! Issuing a certificate from the AD CS authority (Story 13.3, Epic 13
//! PRD D4, D5, D6, D12, D14, D15, D17).
//!
//! One function, [`issue_with`], builds the CSR, calls the authority and
//! stores the result; the endpoint, "Renew now" and the renewal loop all
//! reach it, so there is one code path from a request to a stored row.
//! [`issue`] runs it as one operation of its own; the loop runs it for
//! every certificate of a tick on one session.
//!
//! It runs in four steps: [`prepare_attempt`] (the checks that need no
//! authority), [`generate_csr`], the enrollment, and [`record_outcome`].
//! Every outcome that stores nothing is reported by [`report`], one audit
//! row and one alert, so what an outcome carries (its step, its message,
//! the authority's request identifier) is decided in one place.
//!
//! # What is checked before the authority is contacted
//!
//! Every SAN, against the authority's allowlist with
//! [`lorica_config::models::AllowedSuffix::permits`] (D5): names are
//! trimmed, lowercased and deduplicated, a wildcard is refused, an empty
//! list and a list over [`MAX_SANS`] are refused. Then the template,
//! against the authority's allowed templates (D17). A refusal names what
//! it refused and costs no Kerberos attempt.
//!
//! # What an issued certificate must be (D17)
//!
//! A server certificate: it carries the Server Authentication extended
//! key usage and not Any Purpose, and it is not a CA. Its subject
//! alternative names are exactly the requested DNS names, none missing
//! and none added, of any type. The leaf and the generated key must
//! match, the check every upload goes through. A certificate failing
//! any of this is not stored; it exists at the authority all the same,
//! so the audit row and the alert carry the authority's request
//! identifier for its administrators to revoke it. A stored row holds
//! leaf then chain in `cert_pem`, the key in the store's encrypted
//! column.
//!
//! # Outcomes that store nothing
//!
//! Pending, denied and every fault or client failure store nothing,
//! discard the generated key, raise `cert_issuance_failed` and are
//! audited. A credential the KDC rejects also opens the D15 breaker,
//! through the same path as the connection test.

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_adcs::{
    AdcsError, EnrollOutcome, FailureScope, FailureStep, FaultKind, GeneratedCsr, KeyType,
    SubjectFields,
};
use lorica_config::models::{
    canonical_dns_name, validate_template_name, AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults,
    Certificate,
};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};

use super::error::{
    IssuanceStep, BUSY, BUSY_MESSAGE, DENIED, FAILED, SAN_REFUSED, STILL_RUNNING,
    STILL_RUNNING_MESSAGE, TEMPLATE_REFUSED,
};
use super::leaf::{leaf_facts, pem_certificate, quoted, verified_issuing_ca, LeafFacts};
use super::{
    prepare_operation, record_credential_rejection, refuse_on_follower, run_exclusive,
    subject_fields, validate_subject, AdcsOperation, AdcsUnavailable, LazySession, NotRun,
};
use crate::audit::{AuditContext, ClientConnectInfo};
use crate::certificates::{cert_to_response, parse_cert_pem};
use crate::db::db_blocking;
use crate::error::{json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// The most names one request may carry. A CSR is not bounded by the
/// specification, but a certificate with more names than this is not a
/// service certificate, and every name is checked and logged.
pub const MAX_SANS: usize = 100;

/// The target type of the issuance audit rows.
const CERT_AUDIT_TARGET: &str = "certificate";

/// The audit action prefix of every issuance attempt.
const ISSUE_ACTION: &str = "adcs.certificate.issue";

/// The longest request identifier an audit action carries.
const REQUEST_ID_AUDIT_MAX: usize = 64;

/// Body of `POST /api/v1/certificates/adcs`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsIssueRequest {
    /// The names to request; the first is the `CN`.
    pub sans: Vec<String>,
    /// The template's common name, one the authority allows (D17); the
    /// authority's default when unset.
    #[serde(default)]
    pub template: Option<String>,
    /// The key type; the authority's default when unset.
    #[serde(default)]
    pub key_type: Option<AdcsKeyType>,
    /// Subject fields replacing the authority's defaults; a field left
    /// unset keeps the default.
    #[serde(default)]
    pub subject: Option<AdcsSubjectDefaults>,
    /// The certificate's auto-renew setting; the authority's default
    /// when unset.
    #[serde(default)]
    pub auto_renew: Option<bool>,
}

/// Body of the 202 a pending answer gets.
#[derive(Debug, Serialize)]
pub struct PendingIssuance {
    /// Always `pending`.
    pub outcome: &'static str,
    /// The authority's request identifier, to follow up there.
    pub request_id: String,
    /// What happened and that nothing was stored.
    pub message: String,
}

/// How the subject of a request is assembled.
#[derive(Debug, Clone)]
pub(crate) enum IssueSubject {
    /// The authority's defaults, each set field of these replacing its
    /// default: a new certificate.
    OverDefaults(AdcsSubjectDefaults),
    /// Exactly these fields, the authority's defaults ignored: a
    /// renewal reuses the current certificate's subject.
    Exact(AdcsSubjectDefaults),
}

/// One issuance, from the endpoint or from a renewal.
#[derive(Debug, Clone)]
pub(crate) struct IssueRequest {
    /// The names; the first is the `CN` and the stored `domain`.
    pub(crate) sans: Vec<String>,
    /// The template's common name; the authority's default when `None`.
    pub(crate) template: Option<String>,
    /// The key type; the authority's default when `None`.
    pub(crate) key_type: Option<AdcsKeyType>,
    /// The subject.
    pub(crate) subject: IssueSubject,
    /// The auto-renew setting; when `None`, the authority's default for
    /// a new row and the current value for a replaced one.
    pub(crate) auto_renew: Option<bool>,
    /// The certificate to replace in place (same id, route bindings
    /// kept), or `None` for a new row.
    pub(crate) replace: Option<String>,
}

/// What a completed issuance produced.
#[derive(Debug)]
pub(crate) enum IssueOutcome {
    /// The certificate was issued and stored.
    Issued(Box<Certificate>),
    /// The authority holds the request for approval; nothing stored.
    Pending {
        /// The authority's request identifier.
        request_id: String,
        /// What happened, for the operator.
        message: String,
    },
}

/// Why a SAN list is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SanRefusal {
    /// No name at all.
    Empty,
    /// More than [`MAX_SANS`] distinct names.
    TooMany,
    /// At least one wildcard name (D5).
    Wildcard,
    /// At least one name under no allowed suffix, or not a DNS name.
    OutsideAllowlist,
}

impl SanRefusal {
    fn audit_reason(self) -> &'static str {
        match self {
            SanRefusal::Empty => "san_empty",
            SanRefusal::TooMany => "san_too_many",
            SanRefusal::Wildcard => "san_wildcard",
            SanRefusal::OutsideAllowlist => "san_outside_allowlist",
        }
    }
}

/// Why an issuance did not produce a certificate.
#[derive(Debug)]
pub(crate) enum IssueError {
    /// The SAN list was refused before anything was sent.
    SanRefused {
        /// Which rule refused it.
        reason: SanRefusal,
        /// The names that broke it; empty for a count rule.
        names: Vec<String>,
        /// The refusal in words, naming them.
        message: String,
    },
    /// The template is not one the authority allows (D17); nothing was
    /// sent.
    TemplateRefused {
        /// The refusal in words, naming the template.
        message: String,
    },
    /// No AD CS operation may run now.
    Unavailable(AdcsUnavailable),
    /// Another AD CS operation is running.
    Busy,
    /// The operation outlived the handler's deadline and keeps running.
    StillRunning,
    /// The authority denied the request.
    Denied {
        /// The authority's message.
        message: String,
    },
    /// A fault, a client failure, or a certificate that does not answer
    /// the request.
    Failed {
        /// The failing step's closed name.
        step: String,
        /// The failure in words, naming the step.
        message: String,
        /// Whether this failure opened the D15 breaker.
        authority_failed: bool,
        /// Whether the next request to the authority would fail the same
        /// way, which ends a renewal tick (D15).
        scope: FailureScope,
    },
    /// A request field refused, or a store failure.
    Api(ApiError),
}

impl From<IssueError> for ApiError {
    fn from(err: IssueError) -> ApiError {
        match err {
            IssueError::SanRefused { message, .. } => SAN_REFUSED.error(message),
            IssueError::TemplateRefused { message } => TEMPLATE_REFUSED.error(message),
            IssueError::Unavailable(unavailable) => unavailable.into(),
            IssueError::Busy => BUSY.error(BUSY_MESSAGE),
            IssueError::StillRunning => STILL_RUNNING.error(STILL_RUNNING_MESSAGE),
            IssueError::Denied { message } => DENIED.error(message),
            IssueError::Failed {
                step,
                message,
                authority_failed,
                ..
            } => FAILED.error_at(
                &step,
                if authority_failed {
                    format!(
                        "{message}; the authority is now in the failed state and every AD CS \
                         operation is suspended until a SuperAdmin saves a new password"
                    )
                } else {
                    message
                },
            ),
            IssueError::Api(err) => err,
        }
    }
}

/// POST /api/v1/certificates/adcs - issue a new certificate from the
/// AD CS authority (Operator, control plane only).
///
/// The call is an issuance: it is logged by the authority and undone
/// only by revocation, which Lorica cannot perform. The dashboard
/// confirms the full request before sending it.
pub async fn issue_certificate(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<AdcsIssueRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    refuse_on_follower(&state)?;
    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    let request: IssueRequest = IssueRequest {
        sans: body.sans,
        template: body.template,
        key_type: body.key_type,
        subject: IssueSubject::OverDefaults(body.subject.unwrap_or_default()),
        auto_renew: body.auto_renew,
        replace: None,
    };
    match issue(&state, &ctx, request).await? {
        IssueOutcome::Issued(cert) => Ok(json_data_with_status(
            StatusCode::CREATED,
            cert_to_response(&cert),
        )),
        IssueOutcome::Pending {
            request_id,
            message,
        } => Ok(json_data_with_status(
            StatusCode::ACCEPTED,
            PendingIssuance {
                outcome: "pending",
                request_id,
                message,
            },
        )),
    }
}

/// Issue a certificate as the one AD CS operation of the process.
///
/// Refusals before the authority is contacted (an invalid field, the
/// SANs, the template, no authority, the failed state, another
/// operation running) are audited as
/// `adcs.certificate.issue.refused:<reason>`; every answer of the
/// authority and every client failure is audited, and every one that
/// stores nothing raises `cert_issuance_failed` with the step, the
/// message and, when `request.replace` is set, the certificate id. A
/// credential the KDC rejects opens the D15 breaker.
///
/// The operation runs under [`run_exclusive`], so it is single-flight
/// with the connection test and every authority write, and an
/// operation that outlives the handler's deadline finishes, audits and
/// stores in its own task while the caller gets
/// [`IssueError::StillRunning`].
pub(crate) async fn issue(
    state: &AppState,
    ctx: &AuditContext,
    request: IssueRequest,
) -> Result<IssueOutcome, IssueError> {
    let target_id: String = request.replace.clone().unwrap_or_default();
    let request: IssueRequest = match validate_request(request) {
        Ok(request) => request,
        Err(err) => {
            audit(state, ctx, "refused:invalid_request", &target_id, None).await;
            return Err(IssueError::Api(err));
        }
    };
    let task_state: AppState = state.clone();
    let task_ctx: AuditContext = ctx.clone();
    let operation = async move { issue_exclusive(&task_state, &task_ctx, request).await };
    match run_exclusive(&state.adcs, operation).await {
        Ok(outcome) => outcome,
        Err(NotRun::Busy) => {
            audit(state, ctx, "refused:busy", &target_id, None).await;
            Err(IssueError::Busy)
        }
        Err(NotRun::StillRunning) => Err(IssueError::StillRunning),
        Err(NotRun::Lost(reason)) => Err(IssueError::Api(ApiError::Internal(format!(
            "the AD CS issuance task failed: {reason}"
        )))),
    }
}

/// The request's own fields, checked before the guard is taken: the
/// template's common name and the subject overrides.
pub(super) fn validate_request(mut request: IssueRequest) -> Result<IssueRequest, ApiError> {
    if let Some(template) = &request.template {
        let template: String = template.trim().to_string();
        validate_template_name("template", &template)?;
        request.template = Some(template);
    }
    request.subject = match request.subject {
        IssueSubject::OverDefaults(subject) => {
            IssueSubject::OverDefaults(validate_subject(subject)?)
        }
        IssueSubject::Exact(subject) => IssueSubject::Exact(validate_subject(subject)?),
    };
    Ok(request)
}

/// The SANs as they are requested: trimmed, in the allowlist's own
/// spelling ([`canonical_dns_name`]), duplicates removed in first-seen
/// order, so the first name stays the `CN`.
pub(crate) fn normalize_sans(raw: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(raw.len());
    for name in raw {
        let name: String = canonical_dns_name(name.trim());
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Refuse `sans` (already normalised) unless every name may be
/// requested from `authority` (D5).
pub(crate) fn check_sans(authority: &AdcsAuthority, sans: &[String]) -> Result<(), IssueError> {
    let refused =
        |reason: SanRefusal, names: Vec<String>, message: String| IssueError::SanRefused {
            reason,
            names,
            message,
        };
    if sans.is_empty() {
        return Err(refused(
            SanRefusal::Empty,
            Vec::new(),
            "sans: at least one name is required".to_string(),
        ));
    }
    if sans.len() > MAX_SANS {
        return Err(refused(
            SanRefusal::TooMany,
            Vec::new(),
            format!(
                "sans: at most {MAX_SANS} names per certificate, {} given",
                sans.len()
            ),
        ));
    }
    let wildcards: Vec<String> = sans
        .iter()
        .filter(|name: &&String| name.contains('*'))
        .cloned()
        .collect();
    if !wildcards.is_empty() {
        return Err(refused(
            SanRefusal::Wildcard,
            wildcards.clone(),
            format!("sans: wildcard names are refused: {}", quoted(&wildcards)),
        ));
    }
    // A name still ending in a dot had two root dots: `permits` would
    // drop the second one and accept it, and the CSR builder would then
    // refuse it under the guard, reported as a CSR failure.
    let outside: Vec<String> = sans
        .iter()
        .filter(|name: &&String| name.ends_with('.') || !authority.permits(name))
        .cloned()
        .collect();
    if !outside.is_empty() {
        let suffixes: Vec<&str> = authority
            .allowed_suffixes
            .iter()
            .map(|suffix| suffix.as_str())
            .collect();
        return Err(refused(
            SanRefusal::OutsideAllowlist,
            outside.clone(),
            format!(
                "sans: not a DNS name under an allowed suffix of the authority ({}): {}",
                suffixes.join(", "),
                quoted(&outside)
            ),
        ));
    }
    Ok(())
}

/// The subject sent: the authority's defaults with the request's set
/// fields over them, or the request's fields alone.
pub(crate) fn assemble_subject(
    authority: &AdcsAuthority,
    subject: &IssueSubject,
) -> AdcsSubjectDefaults {
    match subject {
        IssueSubject::Exact(exact) => exact.clone(),
        IssueSubject::OverDefaults(over) => {
            let defaults: &AdcsSubjectDefaults = &authority.subject;
            let pick = |over: &Option<String>, default: &Option<String>| {
                over.clone().or_else(|| default.clone())
            };
            AdcsSubjectDefaults {
                country: pick(&over.country, &defaults.country),
                state: pick(&over.state, &defaults.state),
                locality: pick(&over.locality, &defaults.locality),
                organization: pick(&over.organization, &defaults.organization),
                organizational_unit: pick(&over.organizational_unit, &defaults.organizational_unit),
                email: pick(&over.email, &defaults.email),
            }
        }
    }
}

fn key_type_of(key_type: AdcsKeyType) -> KeyType {
    match key_type {
        AdcsKeyType::Rsa2048 => KeyType::Rsa2048,
        AdcsKeyType::Rsa3072 => KeyType::Rsa3072,
        AdcsKeyType::EcdsaP256 => KeyType::EcdsaP256,
    }
}

/// What one attempt asked for, carried by every audit row and alert of
/// it. Names and choices only: no key, no password, no CSR.
#[derive(Debug, Clone, Serialize)]
struct Attempt {
    sans: Vec<String>,
    template: String,
    key_type: AdcsKeyType,
    replace: Option<String>,
}

impl Attempt {
    fn target_id(&self) -> &str {
        self.replace.as_deref().unwrap_or("")
    }

    fn payload(&self, outcome: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut payload: serde_json::Value = serde_json::json!({
            "sans": self.sans,
            "template": self.template,
            "key_type": self.key_type,
            "outcome": outcome,
        });
        if let (Some(target), serde_json::Value::Object(extra)) = (payload.as_object_mut(), extra) {
            target.extend(extra);
        }
        payload
    }
}

async fn audit(
    state: &AppState,
    ctx: &AuditContext,
    suffix: &str,
    target_id: &str,
    after: Option<&serde_json::Value>,
) {
    crate::audit::record(
        state,
        ctx,
        &format!("{ISSUE_ACTION}.{suffix}"),
        (CERT_AUDIT_TARGET, target_id),
        None,
        after,
    )
    .await;
}

/// Audit a renewal refused before an issuance could be attempted (the
/// stored certificate cannot be read back into a request), as
/// `adcs.certificate.issue.refused:<reason>` on `cert_id`: every
/// renewal attempt leaves a row (Story 13.4 AC #7).
pub(super) async fn audit_refusal(
    state: &AppState,
    ctx: &AuditContext,
    reason: &str,
    cert_id: &str,
    message: &str,
) {
    let payload = serde_json::json!({ "message": message });
    audit(
        state,
        ctx,
        &format!("refused:{reason}"),
        cert_id,
        Some(&payload),
    )
    .await;
}

/// A request identifier as an audit action may carry it: the
/// authority's text, reduced to the characters an identifier has.
fn request_id_for_audit(request_id: &str) -> String {
    request_id
        .chars()
        .filter(|c: &char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(REQUEST_ID_AUDIT_MAX)
        .collect()
}

fn alert_issuance_failed(
    state: &AppState,
    authority_id: &str,
    attempt: &Attempt,
    step: &str,
    message: &str,
    request_id: Option<&str>,
) {
    send_issuance_failed(
        state,
        authority_id,
        &attempt.sans,
        attempt.replace.as_deref(),
        step,
        message,
        request_id,
    );
}

/// Raise `cert_issuance_failed` for an attempt on `sans`.
///
/// For a replacement, a renewal, the alert is sent once per failure
/// state of the certificate (Story 13.4 AC #5): a failure at the step
/// last alerted for `cert_id` is silent, so a certificate failing the
/// same way on every loop tick alerts once, and a different step or a
/// renewal in between re-arms it. A new certificate has no state to
/// repeat and always alerts.
pub(super) fn send_issuance_failed(
    state: &AppState,
    authority_id: &str,
    sans: &[String],
    cert_id: Option<&str>,
    step: &str,
    message: &str,
    request_id: Option<&str>,
) {
    if let Some(cert_id) = cert_id {
        if !state.adcs.renewals.is_new_failure_state(cert_id, step) {
            return;
        }
    }
    let Some(alerts) = &state.adcs.alerts else {
        return;
    };
    let mut event = lorica_notify::AlertEvent::new(
        lorica_notify::events::AlertType::CertIssuanceFailed,
        format!(
            "AD CS issuance for {} produced no certificate ({step})",
            sans.first().map_or("", String::as_str)
        ),
    )
    .with_detail("authority_id", authority_id)
    .with_detail("step", step)
    .with_detail("message", message)
    .with_detail("sans", sans.join(","));
    if let Some(cert_id) = cert_id {
        event = event.with_detail("cert_id", cert_id);
    }
    if let Some(request_id) = request_id {
        event = event.with_detail("request_id", request_id);
    }
    alerts.send(event);
}

/// How an attempt that stored nothing ended.
#[derive(Debug, Clone, Copy)]
enum UnstoredKind {
    /// A fault, a client failure, or an issued certificate Lorica
    /// refused.
    Failed,
    /// The authority holds the request for approval.
    Pending,
    /// The authority denied the request.
    Denied,
}

/// An attempt that stored nothing, as [`report`] audits and alerts it.
struct Unstored<'a> {
    kind: UnstoredKind,
    /// The closed step word the alert carries.
    step: &'a str,
    /// The outcome in words.
    message: &'a str,
    /// The authority's request identifier, when it gave one: what its
    /// administrators find the request by, and revoke an issued
    /// certificate Lorica refused by.
    request_id: Option<&'a str>,
}

impl<'a> Unstored<'a> {
    fn failed(step: &'a str, message: &'a str, request_id: Option<&'a str>) -> Unstored<'a> {
        Unstored {
            kind: UnstoredKind::Failed,
            step,
            message,
            request_id,
        }
    }

    /// The audit action, after `adcs.certificate.issue.`: the readable
    /// part of an audit row (payloads are kept as hashes), so it carries
    /// the request identifier whenever there is one.
    fn action(&self) -> String {
        match (self.kind, self.request_id) {
            (UnstoredKind::Failed, Some(id)) => {
                format!("error:{}:{}", self.step, request_id_for_audit(id))
            }
            (UnstoredKind::Failed, None) => format!("error:{}", self.step),
            (UnstoredKind::Pending, id) => {
                format!("pending:{}", request_id_for_audit(id.unwrap_or_default()))
            }
            (UnstoredKind::Denied, _) => "denied".to_string(),
        }
    }

    fn payload(&self, attempt: &Attempt) -> serde_json::Value {
        match self.kind {
            UnstoredKind::Failed => attempt.payload(
                "error",
                serde_json::json!({
                    "step": self.step,
                    "message": self.message,
                    "request_id": self.request_id,
                }),
            ),
            UnstoredKind::Pending => attempt.payload(
                "pending",
                serde_json::json!({ "request_id": self.request_id, "message": self.message }),
            ),
            UnstoredKind::Denied => attempt.payload(
                "denied",
                serde_json::json!({ "request_id": self.request_id, "message": self.message }),
            ),
        }
    }
}

/// Audit and alert an attempt that stored nothing: the one place every
/// such outcome is reported from.
async fn report(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    attempt: &Attempt,
    unstored: &Unstored<'_>,
) {
    let payload: serde_json::Value = unstored.payload(attempt);
    audit(
        state,
        ctx,
        &unstored.action(),
        attempt.target_id(),
        Some(&payload),
    )
    .await;
    alert_issuance_failed(
        state,
        authority_id,
        attempt,
        unstored.step,
        unstored.message,
        unstored.request_id,
    );
}

/// [`report`] a failure that concerns this request only, and its error.
async fn fail(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    attempt: &Attempt,
    step: &str,
    message: String,
    request_id: Option<&str>,
) -> IssueError {
    report(
        state,
        ctx,
        authority_id,
        attempt,
        &Unstored::failed(step, &message, request_id),
    )
    .await;
    IssueError::Failed {
        step: step.to_string(),
        message,
        authority_failed: false,
        scope: FailureScope::Request,
    }
}

/// The message of a certificate the authority issued and Lorica did not
/// store: it is valid until the authority's administrators revoke it,
/// which the request identifier lets them do.
fn not_stored(reason: &str, request_id: Option<&str>) -> String {
    let request: String = request_id.map_or_else(
        || "its request identifier was not returned".to_string(),
        |id: &str| format!("request {id}"),
    );
    format!(
        "{reason}; it was not stored, and it remains valid at the authority until revoked there \
         ({request})"
    )
}

/// The step of an authority fault that is not a denial.
fn fault_step(kind: FaultKind) -> IssuanceStep {
    match kind {
        FaultKind::Permission => IssuanceStep::FaultPermission,
        FaultKind::Template => IssuanceStep::FaultTemplate,
        FaultKind::Other => IssuanceStep::FaultOther,
    }
}

fn hresult(code: Option<u32>) -> String {
    code.map_or_else(String::new, |code: u32| format!(" (0x{code:08X})"))
}

/// The body of [`issue`], under the guard: read the authority, then
/// [`issue_with`] on a session of its own.
async fn issue_exclusive(
    state: &AppState,
    ctx: &AuditContext,
    request: IssueRequest,
) -> Result<IssueOutcome, IssueError> {
    let target_id: String = request.replace.clone().unwrap_or_default();
    let AdcsOperation {
        authority,
        params,
        password,
    } = match prepare_operation(state).await {
        Ok(operation) => operation,
        Err(unavailable) => {
            audit(
                state,
                ctx,
                &format!("refused:{}", unavailable.audit_reason()),
                &target_id,
                None,
            )
            .await;
            return Err(IssueError::Unavailable(unavailable));
        }
    };
    let mut session: LazySession<'_> =
        LazySession::new(state.adcs.client.as_ref(), params, password);
    issue_with(state, ctx, &authority, &mut session, request).await
}

/// One issuance against `authority` on `session`, under the guard: the
/// checks that need no authority, the CSR, the enrollment, and what
/// came of it. `request` went through [`validate_request`].
pub(super) async fn issue_with(
    state: &AppState,
    ctx: &AuditContext,
    authority: &AdcsAuthority,
    session: &mut LazySession<'_>,
    request: IssueRequest,
) -> Result<IssueOutcome, IssueError> {
    let (attempt, subject): (Attempt, AdcsSubjectDefaults) =
        prepare_attempt(state, ctx, authority, &request).await?;
    let csr: GeneratedCsr = match generate_csr(&attempt, &subject).await {
        Ok(csr) => csr,
        Err((step, message)) => {
            return Err(fail(state, ctx, &authority.id, &attempt, step, message, None).await)
        }
    };
    let enrolled: Result<EnrollOutcome, AdcsError> = session.enroll(&csr.csr_der).await;
    record_outcome(state, ctx, authority, &attempt, &request, csr, enrolled).await
}

/// Audit a refusal before the authority is contacted, as
/// `refused:<reason>`.
async fn refused(
    state: &AppState,
    ctx: &AuditContext,
    reason: &str,
    target_id: &str,
    payload: Option<&serde_json::Value>,
) {
    audit(state, ctx, &format!("refused:{reason}"), target_id, payload).await;
}

/// The checks that need no authority, each refusal audited: a
/// replacement names a row that still exists (checked before the
/// authority issues anything that would then have nowhere to go), every
/// name may be requested (D5), and the template is allowed (D17). The
/// attempt and the subject it sends, when all pass.
async fn prepare_attempt(
    state: &AppState,
    ctx: &AuditContext,
    authority: &AdcsAuthority,
    request: &IssueRequest,
) -> Result<(Attempt, AdcsSubjectDefaults), IssueError> {
    let target_id: String = request.replace.clone().unwrap_or_default();

    if let Some(id) = request.replace.clone() {
        let exists = db_blocking(&state.store, move |store| {
            Ok::<bool, ApiError>(store.get_certificate(&id)?.is_some())
        })
        .await;
        match exists {
            Ok(true) => {}
            Ok(false) => {
                refused(state, ctx, "not_found", &target_id, None).await;
                return Err(IssueError::Api(ApiError::NotFound(format!(
                    "certificate {target_id}"
                ))));
            }
            Err(err) => return Err(IssueError::Api(err)),
        }
    }

    let sans: Vec<String> = normalize_sans(&request.sans);
    if let Err(refusal) = check_sans(authority, &sans) {
        if let IssueError::SanRefused { reason, names, .. } = &refusal {
            let payload = serde_json::json!({ "sans": sans, "refused": names });
            refused(
                state,
                ctx,
                reason.audit_reason(),
                &target_id,
                Some(&payload),
            )
            .await;
        }
        return Err(refusal);
    }

    let template: String = request
        .template
        .clone()
        .unwrap_or_else(|| authority.default_template.clone());
    if !authority.permits_template(&template) {
        let payload = serde_json::json!({ "sans": sans, "template": template });
        refused(state, ctx, "template", &target_id, Some(&payload)).await;
        return Err(IssueError::TemplateRefused {
            message: format!(
                "template: {template:?} is not one the AD CS authority allows; a SuperAdmin \
                 lists the templates an issuance may request"
            ),
        });
    }

    let attempt: Attempt = Attempt {
        sans,
        template,
        key_type: request.key_type.unwrap_or(authority.default_key_type),
        replace: request.replace.clone(),
    };
    Ok((attempt, assemble_subject(authority, &request.subject)))
}

/// The CSR and its new key, or the step and the message of why not. Key
/// generation is CPU work (RSA 3072 takes a noticeable fraction of a
/// second), kept off the async workers.
async fn generate_csr(
    attempt: &Attempt,
    subject: &AdcsSubjectDefaults,
) -> Result<GeneratedCsr, (&'static str, String)> {
    let sans: Vec<String> = attempt.sans.clone();
    let template: String = attempt.template.clone();
    let key_type: KeyType = key_type_of(attempt.key_type);
    let subject: SubjectFields = subject_fields(subject);
    let built = tokio::task::spawn_blocking(move || {
        lorica_adcs::build_csr(&sans, &subject, &template, key_type)
    })
    .await;
    match built {
        Ok(Ok(csr)) => Ok(csr),
        Ok(Err(err)) => Err((err.step().as_str(), err.to_string())),
        Err(join) => Err((
            FailureStep::Csr.as_str(),
            format!("CSR: the key generation task failed: {join}"),
        )),
    }
}

/// What came of the enrollment: a client failure (which may open the
/// D15 breaker), a pending answer, a denial, a fault, or a certificate
/// to check and store.
async fn record_outcome(
    state: &AppState,
    ctx: &AuditContext,
    authority: &AdcsAuthority,
    attempt: &Attempt,
    request: &IssueRequest,
    csr: GeneratedCsr,
    enrolled: Result<EnrollOutcome, AdcsError>,
) -> Result<IssueOutcome, IssueError> {
    match enrolled {
        Err(err) => {
            let step: &'static str = err.step().as_str();
            let message: String = err.to_string();
            report(
                state,
                ctx,
                &authority.id,
                attempt,
                &Unstored::failed(step, &message, None),
            )
            .await;
            let authority_failed: bool =
                record_credential_rejection(state, ctx, &authority.id, &err)
                    .await
                    .map_err(IssueError::Api)?;
            Err(IssueError::Failed {
                step: step.to_string(),
                message,
                authority_failed,
                scope: err.scope(),
            })
        }
        Ok(EnrollOutcome::Pending { request_id }) => {
            let message: String = format!(
                "the authority holds request {request_id} for a certificate manager's approval; \
                 templates that need approval are not supported, so nothing was stored and the \
                 generated key was discarded"
            );
            report(
                state,
                ctx,
                &authority.id,
                attempt,
                &Unstored {
                    kind: UnstoredKind::Pending,
                    step: IssuanceStep::Pending.as_str(),
                    message: &message,
                    request_id: Some(&request_id),
                },
            )
            .await;
            Ok(IssueOutcome::Pending {
                request_id,
                message,
            })
        }
        Ok(EnrollOutcome::Denied {
            error_code,
            request_id,
            message,
        }) => {
            let message: String = format!(
                "the authority denied the request{}: {message}",
                hresult(error_code)
            );
            report(
                state,
                ctx,
                &authority.id,
                attempt,
                &Unstored {
                    kind: UnstoredKind::Denied,
                    step: IssuanceStep::Denied.as_str(),
                    message: &message,
                    request_id: request_id.as_deref(),
                },
            )
            .await;
            Err(IssueError::Denied { message })
        }
        Ok(EnrollOutcome::Error {
            kind,
            error_code,
            message,
        }) => {
            let message: String = format!(
                "SOAP fault: the authority refused the request{}: {message}",
                hresult(error_code)
            );
            Err(fail(
                state,
                ctx,
                &authority.id,
                attempt,
                fault_step(kind).as_str(),
                message,
                None,
            )
            .await)
        }
        Ok(EnrollOutcome::Issued {
            leaf_der,
            chain_der,
            request_id,
            ..
        }) => {
            let issued: Issued = Issued {
                leaf_der,
                chain_der,
                request_id,
                private_key_pem: csr.private_key_pem,
            };
            store_issued(state, ctx, authority, attempt, request, issued).await
        }
    }
}

/// An issued answer, with the key its CSR was made for.
struct Issued {
    leaf_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
    request_id: Option<String>,
    private_key_pem: String,
}

/// What the store transaction did.
struct Stored {
    cert: Certificate,
    learned_issuing_ca: bool,
    export_snapshot: Option<(
        lorica_config::models::GlobalSettings,
        Vec<lorica_config::models::CertExportAcl>,
    )>,
}

/// Check an issued answer against the request and store it.
async fn store_issued(
    state: &AppState,
    ctx: &AuditContext,
    authority: &AdcsAuthority,
    attempt: &Attempt,
    request: &IssueRequest,
    issued: Issued,
) -> Result<IssueOutcome, IssueError> {
    let request_id: Option<&str> = issued.request_id.as_deref();
    let rejected = |step: IssuanceStep, reason: String| async move {
        fail(
            state,
            ctx,
            &authority.id,
            attempt,
            step.as_str(),
            not_stored(&reason, request_id),
            request_id,
        )
        .await
    };

    let facts: LeafFacts = match leaf_facts(&issued.leaf_der) {
        Ok(facts) => facts,
        Err(reason) => return Err(rejected(IssuanceStep::Certificate, reason).await),
    };
    if let Some(reason) = facts.profile_problem() {
        return Err(rejected(IssuanceStep::CertificateProfile, reason.to_string()).await);
    }
    if let Some(reason) = facts.names_problem(&attempt.sans) {
        return Err(rejected(IssuanceStep::SanCoverage, reason).await);
    }

    let mut cert_pem: String = pem_certificate(&issued.leaf_der);
    for der in &issued.chain_der {
        cert_pem.push_str(&pem_certificate(der));
    }
    if let Err(err) = lorica_tls::validate_certificate_bundle(&cert_pem, &issued.private_key_pem) {
        return Err(rejected(
            IssuanceStep::Certificate,
            format!("the issued certificate cannot be served with its key: {err}"),
        )
        .await);
    }
    let issuing_ca_pem: Option<String> = verified_issuing_ca(&issued.leaf_der, &issued.chain_der);
    let parsed = parse_cert_pem(&cert_pem);
    let now = Utc::now();
    let cert: Certificate = Certificate {
        id: request
            .replace
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        domain: attempt.sans[0].clone(),
        san_domains: parsed.san_domains,
        fingerprint: parsed.fingerprint,
        cert_pem,
        key_pem: issued.private_key_pem,
        issuer: parsed.issuer,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
        is_acme: false,
        acme_auto_renew: request.auto_renew.unwrap_or(authority.auto_renew_default),
        created_at: now,
        acme_method: None,
        acme_dns_provider_id: None,
        adcs_authority_id: Some(authority.id.clone()),
        adcs_template: Some(attempt.template.clone()),
        adcs_template_oid: facts.template_oid,
        adcs_request_id: issued.request_id.clone(),
    };

    let authority_id: String = authority.id.clone();
    let replacing: bool = request.replace.is_some();
    let auto_renew_given: bool = request.auto_renew.is_some();
    let written = db_blocking(&state.store, move |store| {
        store.in_transaction(|store: &ConfigStore| {
            write_issued(
                store,
                cert,
                WriteMode {
                    replacing,
                    auto_renew_given,
                },
                &authority_id,
                issuing_ca_pem,
            )
        })
    })
    .await;
    let stored: Stored = match written {
        Ok(stored) => stored,
        Err(err) => {
            let message: String = not_stored(
                &format!("the issued certificate could not be stored: {err}"),
                request_id,
            );
            report(
                state,
                ctx,
                &authority.id,
                attempt,
                &Unstored::failed(IssuanceStep::Store.as_str(), &message, request_id),
            )
            .await;
            return Err(IssueError::Api(err));
        }
    };

    if let Some((settings, acls)) = stored.export_snapshot {
        crate::cert_export::export_after_release(settings, acls, stored.cert.clone()).await;
    }
    if replacing {
        state.adcs.renewals.forget_failures(&stored.cert.id);
    }
    crate::acme::after_certificate_issued(state, &stored.cert.id).await;

    let response = serde_json::to_value(cert_to_response(&stored.cert)).ok();
    let payload = attempt.payload(
        "issued",
        serde_json::json!({ "request_id": issued.request_id, "certificate": response }),
    );
    audit(
        state,
        ctx,
        &format!("ok:{}", stored.cert.id),
        &stored.cert.id,
        Some(&payload),
    )
    .await;
    if stored.learned_issuing_ca {
        crate::audit::record(
            state,
            ctx,
            "adcs.authority.issuing_ca.learned",
            (super::AUDIT_TARGET, authority.id.as_str()),
            None,
            None,
        )
        .await;
    }
    Ok(IssueOutcome::Issued(Box::new(stored.cert)))
}

/// The DER of the first certificate in the PEM `text`, the one adoption
/// verifies against.
fn first_certificate_der(text: &str) -> Option<Vec<u8>> {
    pem::parse_many(text)
        .ok()?
        .into_iter()
        .find(|block: &pem::Pem| block.tag() == "CERTIFICATE")
        .map(|block: pem::Pem| block.contents().to_vec())
}

/// How [`write_issued`] treats the row.
struct WriteMode {
    /// Replace the row with the certificate's id in place, keeping its
    /// creation time; otherwise insert a new row.
    replacing: bool,
    /// The request set the auto-renew value; otherwise a replaced row
    /// keeps its own.
    auto_renew_given: bool,
}

/// The store side of an issued certificate, inside one transaction:
/// the row, created or replaced in place, and the issuing CA
/// certificate on the authority when it has none yet and the leaf
/// verifies under it (D12).
///
/// A replacement is written only while the row is still managed by
/// this authority: a reversion, or a PEM replaced through the generic
/// update, that landed while the renewal was at the authority is the
/// operator's decision, and the renewal must not undo it.
fn write_issued(
    store: &ConfigStore,
    mut cert: Certificate,
    mode: WriteMode,
    authority_id: &str,
    issuing_ca_pem: Option<String>,
) -> Result<Stored, ApiError> {
    if mode.replacing {
        let current: Certificate = store
            .get_certificate(&cert.id)?
            .ok_or_else(|| ApiError::NotFound(format!("certificate {}", cert.id)))?;
        if current.is_acme || current.adcs_authority_id.as_deref() != Some(authority_id) {
            return Err(ApiError::Conflict(format!(
                "certificate {} stopped being managed by the AD CS authority while it was being \
                 renewed",
                cert.id
            )));
        }
        cert.created_at = current.created_at;
        if !mode.auto_renew_given {
            cert.acme_auto_renew = current.acme_auto_renew;
        }
        store.update_certificate(&cert)?;
    } else {
        store.create_certificate(&cert)?;
    }

    let mut learned_issuing_ca: bool = false;
    if let (Some(pem), Some(mut authority)) = (issuing_ca_pem, store.get_adcs_authority()?) {
        if authority.id == authority_id {
            match authority.issuing_ca_pem.as_deref() {
                None => {
                    authority.issuing_ca_pem = Some(pem);
                    store.upsert_adcs_authority(&authority)?;
                    learned_issuing_ca = true;
                }
                // A renewed CA certificate, or a stored one pasted for
                // another CA: adoption verifies against the stored one
                // only, so it would stop recognising what this CA signs.
                // Replacing it is a SuperAdmin's decision, not an
                // issuance's.
                Some(stored) if first_certificate_der(stored) != first_certificate_der(&pem) => {
                    tracing::warn!(
                    authority_id = %authority.id,
                    "AD CS issuance: the issued certificate verifies under an issuing CA \
                     certificate other than the authority's stored one; adoption keeps verifying \
                     against the stored one until a SuperAdmin replaces it"
                    )
                }
                Some(_) => {}
            }
        }
    }
    let export_snapshot = crate::cert_export::snapshot_export_inputs(store);
    Ok(Stored {
        cert,
        learned_issuing_ca,
        export_snapshot,
    })
}

#[cfg(test)]
pub(in crate::adcs) mod tests;
