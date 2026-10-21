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

use std::collections::BTreeSet;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_adcs::{
    AdcsError, EnrollOutcome, FailureScope, FaultKind, GeneratedCsr, KeyType, SubjectFields,
};
use lorica_config::models::{
    validate_template_name, AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults, Certificate,
};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Any, FromDer, Oid, Tag};
use x509_parser::extensions::GeneralName;

use super::{
    prepare_operation, record_credential_rejection, refuse_on_follower, run_exclusive,
    validate_subject, AdcsHandlerError, AdcsOperation, AdcsUnavailable, LazySession, NotRun,
    BUSY_MESSAGE,
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

/// Version 2 and later templates (MS-WCCE 2.2.2.7.7.2): a SEQUENCE
/// whose first element is the template OID.
const TEMPLATE_V2_EXTENSION_OID: &str = "1.3.6.1.4.1.311.21.7";

/// Version 1 templates (MS-WCCE 2.2.2.7.7.1): the template name as a
/// string, BMPString in practice.
const TEMPLATE_V1_EXTENSION_OID: &str = "1.3.6.1.4.1.311.20.2";

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

impl From<IssueError> for AdcsHandlerError {
    fn from(err: IssueError) -> AdcsHandlerError {
        let coded =
            |status: StatusCode, code: &'static str, message: String| AdcsHandlerError::Coded {
                status,
                code,
                message,
                step: None,
            };
        match err {
            IssueError::SanRefused { message, .. } => coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                "adcs_san_refused",
                message,
            ),
            IssueError::TemplateRefused { message } => coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                "adcs_template_refused",
                message,
            ),
            IssueError::Unavailable(unavailable) => match unavailable {
                AdcsUnavailable::NotConfigured => coded(
                    StatusCode::CONFLICT,
                    "adcs_not_configured",
                    "no AD CS authority is configured; a SuperAdmin must declare one".to_string(),
                ),
                AdcsUnavailable::NoPassword => coded(
                    StatusCode::CONFLICT,
                    "adcs_not_configured",
                    "the AD CS authority has no password set; a SuperAdmin must save one"
                        .to_string(),
                ),
                failed @ AdcsUnavailable::Failed { .. } => coded(
                    StatusCode::CONFLICT,
                    "adcs_failed_state",
                    ApiError::from(failed).to_string(),
                ),
                AdcsUnavailable::Error(err) => AdcsHandlerError::Api(err),
            },
            IssueError::Busy => coded(StatusCode::CONFLICT, "adcs_busy", BUSY_MESSAGE.to_string()),
            IssueError::StillRunning => AdcsHandlerError::StillRunning,
            IssueError::Denied { message } => {
                coded(StatusCode::UNPROCESSABLE_ENTITY, "adcs_denied", message)
            }
            IssueError::Failed {
                step,
                message,
                authority_failed,
                ..
            } => AdcsHandlerError::Coded {
                status: StatusCode::BAD_GATEWAY,
                code: "adcs_error",
                message: if authority_failed {
                    format!(
                        "{message}; the authority is now in the failed state and every AD CS \
                         operation is suspended until a SuperAdmin saves a new password"
                    )
                } else {
                    message
                },
                step: Some(step),
            },
            IssueError::Api(err) => AdcsHandlerError::Api(err),
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
) -> Result<(StatusCode, Json<serde_json::Value>), AdcsHandlerError> {
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

/// The SANs as they are requested: trimmed, lowercased, one root dot
/// dropped, duplicates removed in first-seen order, so the first name
/// stays the `CN`.
pub(crate) fn normalize_sans(raw: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(raw.len());
    for name in raw {
        let lowered: String = name.trim().to_ascii_lowercase();
        let name: String = lowered.strip_suffix('.').unwrap_or(&lowered).to_string();
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

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name: &String| format!("{name:?}"))
        .collect::<Vec<String>>()
        .join(", ")
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

fn subject_fields(subject: &AdcsSubjectDefaults) -> SubjectFields {
    SubjectFields {
        country: subject.country.clone(),
        state: subject.state.clone(),
        locality: subject.locality.clone(),
        organization: subject.organization.clone(),
        organizational_unit: subject.organizational_unit.clone(),
        email: subject.email.clone(),
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

/// Audit and alert an attempt that stores nothing, as
/// `adcs.certificate.issue.error:<step>`, or
/// `adcs.certificate.issue.error:<step>:<request id>` when the authority
/// issued a certificate Lorica refused: the action is the part of an
/// audit row that is kept readable (payloads are kept as hashes), and
/// the identifier is what the authority's administrators revoke by.
async fn record_failure(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    attempt: &Attempt,
    step: &str,
    message: &str,
    request_id: Option<&str>,
) {
    let payload = attempt.payload(
        "error",
        serde_json::json!({ "step": step, "message": message, "request_id": request_id }),
    );
    let action: String = match request_id {
        Some(id) => format!("error:{step}:{}", request_id_for_audit(id)),
        None => format!("error:{step}"),
    };
    audit(state, ctx, &action, attempt.target_id(), Some(&payload)).await;
    alert_issuance_failed(state, authority_id, attempt, step, message, request_id);
}

/// [`record_failure`], and the error of a failure that concerns this
/// request only.
async fn fail(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    attempt: &Attempt,
    step: &str,
    message: String,
    request_id: Option<&str>,
) -> IssueError {
    record_failure(
        state,
        ctx,
        authority_id,
        attempt,
        step,
        &message,
        request_id,
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

/// The closed step word of an authority fault that is not a denial.
fn fault_step(kind: FaultKind) -> &'static str {
    match kind {
        FaultKind::Permission => "fault_permission",
        FaultKind::Template => "fault_template",
        FaultKind::Other => "fault_other",
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
/// checks that need no authority, the CSR, the enrollment, and the
/// stored row. `request` went through [`validate_request`].
pub(super) async fn issue_with(
    state: &AppState,
    ctx: &AuditContext,
    authority: &AdcsAuthority,
    session: &mut LazySession<'_>,
    request: IssueRequest,
) -> Result<IssueOutcome, IssueError> {
    let target_id: String = request.replace.clone().unwrap_or_default();

    // A replacement names a row that must still exist, checked before
    // the authority issues anything that would then have nowhere to go.
    if let Some(id) = request.replace.clone() {
        let exists = db_blocking(&state.store, move |store| {
            Ok::<bool, ApiError>(store.get_certificate(&id)?.is_some())
        })
        .await;
        match exists {
            Ok(true) => {}
            Ok(false) => {
                audit(state, ctx, "refused:not_found", &target_id, None).await;
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
            audit(
                state,
                ctx,
                &format!("refused:{}", reason.audit_reason()),
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
        audit(state, ctx, "refused:template", &target_id, Some(&payload)).await;
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
    let subject: AdcsSubjectDefaults = assemble_subject(authority, &request.subject);

    // Key generation is CPU work (RSA 3072 takes a noticeable fraction
    // of a second), kept off the async workers.
    let csr_sans: Vec<String> = attempt.sans.clone();
    let csr_template: String = attempt.template.clone();
    let csr_key_type: KeyType = key_type_of(attempt.key_type);
    let csr_subject: SubjectFields = subject_fields(&subject);
    let built = tokio::task::spawn_blocking(move || {
        lorica_adcs::build_csr(&csr_sans, &csr_subject, &csr_template, csr_key_type)
    })
    .await;
    let csr: GeneratedCsr = match built {
        Ok(Ok(csr)) => csr,
        Ok(Err(err)) => {
            return Err(fail(
                state,
                ctx,
                &authority.id,
                &attempt,
                err.step().as_str(),
                err.to_string(),
                None,
            )
            .await);
        }
        Err(join) => {
            return Err(fail(
                state,
                ctx,
                &authority.id,
                &attempt,
                lorica_adcs::FailureStep::Csr.as_str(),
                format!("CSR: the key generation task failed: {join}"),
                None,
            )
            .await);
        }
    };

    let result: Result<EnrollOutcome, AdcsError> = session.enroll(&csr.csr_der).await;

    match result {
        Err(err) => {
            let step: &'static str = err.step().as_str();
            let message: String = err.to_string();
            record_failure(state, ctx, &authority.id, &attempt, step, &message, None).await;
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
            let payload = attempt.payload(
                "pending",
                serde_json::json!({ "request_id": request_id, "message": message }),
            );
            audit(
                state,
                ctx,
                &format!("pending:{}", request_id_for_audit(&request_id)),
                attempt.target_id(),
                Some(&payload),
            )
            .await;
            alert_issuance_failed(
                state,
                &authority.id,
                &attempt,
                "pending",
                &message,
                Some(&request_id),
            );
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
            let payload = attempt.payload(
                "denied",
                serde_json::json!({ "request_id": request_id, "message": message }),
            );
            audit(state, ctx, "denied", attempt.target_id(), Some(&payload)).await;
            alert_issuance_failed(
                state,
                &authority.id,
                &attempt,
                "denied",
                &message,
                request_id.as_deref(),
            );
            Err(IssueError::Denied { message })
        }
        Ok(EnrollOutcome::Error {
            kind,
            error_code,
            message,
        }) => {
            let step: &'static str = fault_step(kind);
            let message: String = format!(
                "SOAP fault: the authority refused the request{}: {message}",
                hresult(error_code)
            );
            Err(fail(state, ctx, &authority.id, &attempt, step, message, None).await)
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
            store_issued(state, ctx, authority, &attempt, &request, issued).await
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

/// What the leaf says, read once.
struct LeafFacts {
    /// Its `dNSName` entries, lowercased.
    dns_names: Vec<String>,
    /// Every other subject alternative name, described.
    other_names: Vec<String>,
    /// Whether its extended key usage includes Server Authentication.
    server_auth: bool,
    /// Whether its extended key usage includes Any Purpose.
    any_purpose: bool,
    /// Whether `basicConstraints` makes it a CA.
    is_ca: bool,
    template_oid: Option<String>,
}

impl LeafFacts {
    /// Why the leaf is not a server certificate (D17), or `None`.
    fn profile_problem(&self) -> Option<&'static str> {
        if self.is_ca {
            Some("the authority issued a CA certificate (basicConstraints cA true)")
        } else if !self.server_auth {
            Some(
                "the authority issued a certificate without the Server Authentication extended \
                 key usage",
            )
        } else if self.any_purpose {
            Some("the authority issued a certificate with the Any Purpose extended key usage")
        } else {
            None
        }
    }

    /// Why the leaf's names are not exactly `requested`, or `None`.
    /// Both sides are lowercase DNS names here, so the comparison is
    /// case-insensitive.
    fn names_problem(&self, requested: &[String]) -> Option<String> {
        let issued: BTreeSet<&str> = self.dns_names.iter().map(String::as_str).collect();
        let asked: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let missing: Vec<String> = asked
            .difference(&issued)
            .map(|name: &&str| (*name).to_string())
            .collect();
        let mut extra: Vec<String> = issued
            .difference(&asked)
            .map(|name: &&str| (*name).to_string())
            .collect();
        extra.extend(self.other_names.iter().cloned());
        if missing.is_empty() && extra.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if !missing.is_empty() {
            parts.push(format!("does not cover {}", quoted(&missing)));
        }
        if !extra.is_empty() {
            parts.push(format!("names what was not requested: {}", quoted(&extra)));
        }
        Some(format!(
            "the authority issued a certificate that {}",
            parts.join(" and ")
        ))
    }
}

/// A subject alternative name that is not a DNS name, in words.
fn describe_other_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::RFC822Name(address) => format!("email {address}"),
        GeneralName::URI(uri) => format!("URI {uri}"),
        GeneralName::IPAddress(_) => "an IP address".to_string(),
        GeneralName::OtherName(oid, _) => format!("other name {}", oid.to_id_string()),
        GeneralName::RegisteredID(oid) => format!("registered ID {}", oid.to_id_string()),
        _ => "a name that is not a DNS name".to_string(),
    }
}

/// The leaf's facts. An extension present twice, which x509-parser
/// refuses to choose between, fails the read: what the certificate may
/// do must not be guessed.
fn leaf_facts(leaf_der: &[u8]) -> Result<LeafFacts, String> {
    let (_, leaf): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|err| format!("the issued certificate does not parse: {err}"))?;
    let mut dns_names: Vec<String> = Vec::new();
    let mut other_names: Vec<String> = Vec::new();
    let san = leaf.subject_alternative_name().map_err(|err| {
        format!("the issued certificate's subject alternative names cannot be read: {err}")
    })?;
    if let Some(san) = san {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => dns_names.push(dns.to_ascii_lowercase()),
                other => other_names.push(describe_other_name(other)),
            }
        }
    }
    let eku = leaf.extended_key_usage().map_err(|err| {
        format!("the issued certificate's extended key usage cannot be read: {err}")
    })?;
    let is_ca: bool = leaf
        .basic_constraints()
        .map_err(|err| format!("the issued certificate's basic constraints cannot be read: {err}"))?
        .is_some_and(|constraints| constraints.value.ca);
    Ok(LeafFacts {
        dns_names,
        other_names,
        server_auth: eku.as_ref().is_some_and(|usage| usage.value.server_auth),
        any_purpose: eku.as_ref().is_some_and(|usage| usage.value.any),
        is_ca,
        template_oid: template_oid_of(&leaf),
    })
}

/// The first certificate of the issued chain, as PEM, when the leaf's
/// signature verifies under its key: the only issuing CA the authority
/// may learn from an issuance (D12). Names and key identifiers are
/// copied at will, so they alone prove nothing.
fn verified_issuing_ca(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> Option<String> {
    let issuer_der: &Vec<u8> = chain_der.first()?;
    let (_, leaf) = x509_parser::parse_x509_certificate(leaf_der).ok()?;
    let (_, issuer) = x509_parser::parse_x509_certificate(issuer_der).ok()?;
    lorica_adcs::issued_by(&leaf, &issuer).then(|| pem_certificate(issuer_der))
}

/// The template an issued certificate names: the OID of extension
/// 1.3.6.1.4.1.311.21.7 (version 2 and later templates), else the name
/// in 1.3.6.1.4.1.311.20.2 (version 1), else `None`.
pub(crate) fn template_oid_of(leaf: &X509Certificate<'_>) -> Option<String> {
    let extension_value = |oid: &str| -> Option<&[u8]> {
        leaf.extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == oid)
            .map(|extension| extension.value)
    };
    extension_value(TEMPLATE_V2_EXTENSION_OID)
        .and_then(template_v2_oid)
        .or_else(|| extension_value(TEMPLATE_V1_EXTENSION_OID).and_then(template_v1_name))
}

/// `CertificateTemplate ::= SEQUENCE { templateID OBJECT IDENTIFIER,
/// templateMajorVersion INTEGER, templateMinorVersion INTEGER OPTIONAL }`.
fn template_v2_oid(value: &[u8]) -> Option<String> {
    let (_, sequence): (&[u8], Any<'_>) = Any::from_der(value).ok()?;
    if sequence.header.tag() != Tag::Sequence {
        return None;
    }
    let (_, oid): (&[u8], Oid<'_>) = Oid::from_der(sequence.data).ok()?;
    Some(oid.to_id_string())
}

/// The version 1 template name, a BMPString in practice and a
/// UTF8String from some issuers.
fn template_v1_name(value: &[u8]) -> Option<String> {
    let (_, string): (&[u8], Any<'_>) = Any::from_der(value).ok()?;
    let name: String = match string.header.tag() {
        Tag::BmpString => {
            if string.data.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> = string
                .data
                .chunks_exact(2)
                .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).ok()?
        }
        Tag::Utf8String => std::str::from_utf8(string.data).ok()?.to_string(),
        _ => return None,
    };
    (!name.is_empty()).then_some(name)
}

fn pem_certificate(der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
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
    let rejected = |step: &'static str, reason: String| async move {
        fail(
            state,
            ctx,
            &authority.id,
            attempt,
            step,
            not_stored(&reason, request_id),
            request_id,
        )
        .await
    };

    let facts: LeafFacts = match leaf_facts(&issued.leaf_der) {
        Ok(facts) => facts,
        Err(reason) => return Err(rejected("certificate", reason).await),
    };
    if let Some(reason) = facts.profile_problem() {
        return Err(rejected("certificate_profile", reason.to_string()).await);
    }
    if let Some(reason) = facts.names_problem(&attempt.sans) {
        return Err(rejected("san_coverage", reason).await);
    }

    let mut cert_pem: String = pem_certificate(&issued.leaf_der);
    for der in &issued.chain_der {
        cert_pem.push_str(&pem_certificate(der));
    }
    if let Err(err) = lorica_tls::validate_certificate_bundle(&cert_pem, &issued.private_key_pem) {
        return Err(rejected(
            "certificate",
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
            record_failure(
                state,
                ctx,
                &authority.id,
                attempt,
                "store",
                &message,
                request_id,
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
        if authority.id == authority_id && authority.issuing_ca_pem.is_none() {
            authority.issuing_ca_pem = Some(pem);
            store.upsert_adcs_authority(&authority)?;
            learned_issuing_ca = true;
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
