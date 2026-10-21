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
//! PRD D4, D5, D6, D12, D14, D15).
//!
//! One function, [`issue`], builds the CSR, calls the authority and
//! stores the result; the endpoint and Story 13.4's renewal both call
//! it, so there is one code path from a request to a stored row.
//!
//! # What is checked before the authority is contacted
//!
//! Every SAN, against the authority's allowlist with
//! [`lorica_config::models::AllowedSuffix::permits`] (D5): names are
//! trimmed, lowercased and deduplicated, a wildcard is refused, an empty
//! list and a list over [`MAX_SANS`] are refused. A refusal names the
//! offending names and costs no Kerberos attempt.
//!
//! # What an issued certificate must be
//!
//! The leaf must cover every requested name: an authority that issued
//! something else is an error, alerted, and nothing is stored. The leaf
//! and the generated key must match, the check every upload goes
//! through. The row is then stored as an upload is: leaf then chain in
//! `cert_pem`, the key in the store's encrypted column.
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
use lorica_adcs::{AdcsError, EnrollOutcome, FaultKind, GeneratedCsr, KeyType, SubjectFields};
use lorica_config::models::{AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults, Certificate};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Any, FromDer, Oid, Tag};
use x509_parser::extensions::GeneralName;

use super::{
    failure_step, prepare_operation, record_credential_rejection, refuse_on_follower,
    run_exclusive, validate_subject, AdcsHandlerError, AdcsOperation, AdcsUnavailable, NotRun,
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
    /// The template's common name; the authority's default when unset.
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
    // Constructed by Story 13.4's renewal, which is not wired yet; the
    // tests here exercise it so the path it will take is proven now.
    #[cfg_attr(not(test), allow(dead_code))]
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
    /// At least one name under no allowed suffix.
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
/// SANs, no authority, the failed state, another operation running)
/// are audited as `adcs.certificate.issue.refused:<reason>`; every
/// answer of the authority and every client failure is audited, and
/// every one that stores nothing raises `cert_issuance_failed` with the
/// step, the message and, when `request.replace` is set, the
/// certificate id. A credential the KDC rejects opens the D15 breaker.
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
fn validate_request(mut request: IssueRequest) -> Result<IssueRequest, ApiError> {
    if let Some(template) = &request.template {
        let template: String = template.trim().to_string();
        if template.is_empty() || template.chars().any(char::is_control) {
            return Err(ApiError::Unprocessable(
                "template: the template's common name must be non-empty, without control \
                 characters"
                    .to_string(),
            ));
        }
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
    let outside: Vec<String> = sans
        .iter()
        .filter(|name: &&String| !authority.permits(name))
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
                "sans: not under an allowed DNS suffix of the authority ({}): {}",
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
    let Some(alerts) = &state.adcs.alerts else {
        return;
    };
    let mut event = lorica_notify::AlertEvent::new(
        lorica_notify::events::AlertType::CertIssuanceFailed,
        format!(
            "AD CS issuance for {} produced no certificate ({step})",
            attempt.sans.first().map_or("", String::as_str)
        ),
    )
    .with_detail("authority_id", authority_id)
    .with_detail("step", step)
    .with_detail("message", message)
    .with_detail("sans", attempt.sans.join(","));
    if let Some(cert_id) = &attempt.replace {
        event = event.with_detail("cert_id", cert_id.clone());
    }
    if let Some(request_id) = request_id {
        event = event.with_detail("request_id", request_id);
    }
    alerts.send(event);
}

/// Audit, alert and build the error of an attempt that stores nothing.
async fn fail(
    state: &AppState,
    ctx: &AuditContext,
    authority_id: &str,
    attempt: &Attempt,
    step: &str,
    message: String,
    authority_failed: bool,
) -> IssueError {
    let payload = attempt.payload(
        "error",
        serde_json::json!({ "step": step, "message": message }),
    );
    audit(
        state,
        ctx,
        &format!("error:{step}"),
        attempt.target_id(),
        Some(&payload),
    )
    .await;
    alert_issuance_failed(state, authority_id, attempt, step, &message, None);
    IssueError::Failed {
        step: step.to_string(),
        message,
        authority_failed,
    }
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

/// The body of [`issue`], under the guard.
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
                drop(password);
                audit(state, ctx, "refused:not_found", &target_id, None).await;
                return Err(IssueError::Api(ApiError::NotFound(format!(
                    "certificate {target_id}"
                ))));
            }
            Err(err) => return Err(IssueError::Api(err)),
        }
    }

    let sans: Vec<String> = normalize_sans(&request.sans);
    if let Err(refusal) = check_sans(&authority, &sans) {
        drop(password);
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

    let attempt: Attempt = Attempt {
        sans,
        template: request
            .template
            .clone()
            .unwrap_or_else(|| authority.default_template.clone()),
        key_type: request.key_type.unwrap_or(authority.default_key_type),
        replace: request.replace.clone(),
    };
    let subject: AdcsSubjectDefaults = assemble_subject(&authority, &request.subject);

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
            drop(password);
            let step: &'static str = failure_step(&err);
            return Err(fail(
                state,
                ctx,
                &authority.id,
                &attempt,
                step,
                err.to_string(),
                false,
            )
            .await);
        }
        Err(join) => {
            drop(password);
            return Err(fail(
                state,
                ctx,
                &authority.id,
                &attempt,
                "csr",
                format!("CSR: the key generation task failed: {join}"),
                false,
            )
            .await);
        }
    };

    let result: Result<EnrollOutcome, AdcsError> = state
        .adcs
        .client
        .enroll(&params, &password, &csr.csr_der)
        .await;
    drop(password);

    match result {
        Err(err) => {
            let step: &'static str = failure_step(&err);
            let message: String = err.to_string();
            let target: &str = attempt.target_id();
            let payload = attempt.payload(
                "error",
                serde_json::json!({ "step": step, "message": message }),
            );
            audit(state, ctx, &format!("error:{step}"), target, Some(&payload)).await;
            alert_issuance_failed(state, &authority.id, &attempt, step, &message, None);
            let authority_failed: bool =
                record_credential_rejection(state, ctx, &authority.id, &err)
                    .await
                    .map_err(IssueError::Api)?;
            Err(IssueError::Failed {
                step: step.to_string(),
                message,
                authority_failed,
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
            Err(fail(state, ctx, &authority.id, &attempt, step, message, false).await)
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
            store_issued(state, ctx, &authority, &attempt, &request, issued).await
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
    dns_names: Vec<String>,
    template_oid: Option<String>,
}

fn leaf_facts(leaf_der: &[u8]) -> Result<LeafFacts, String> {
    let (_, leaf): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|err| format!("the issued certificate does not parse: {err}"))?;
    let mut dns_names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = leaf.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                dns_names.push(dns.to_ascii_lowercase());
            }
        }
    }
    Ok(LeafFacts {
        dns_names,
        template_oid: template_oid_of(&leaf),
    })
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
    let facts: LeafFacts = match leaf_facts(&issued.leaf_der) {
        Ok(facts) => facts,
        Err(message) => {
            return Err(fail(
                state,
                ctx,
                &authority.id,
                attempt,
                "certificate",
                message,
                false,
            )
            .await)
        }
    };
    let uncovered: Vec<String> = attempt
        .sans
        .iter()
        .filter(|name: &&String| !facts.dns_names.contains(name))
        .cloned()
        .collect();
    if !uncovered.is_empty() {
        let message: String = format!(
            "the authority issued a certificate that does not cover {} (it names {}); it was \
             not stored, and it remains valid at the authority until revoked there",
            quoted(&uncovered),
            if facts.dns_names.is_empty() {
                "no DNS name".to_string()
            } else {
                quoted(&facts.dns_names)
            }
        );
        return Err(fail(
            state,
            ctx,
            &authority.id,
            attempt,
            "san_coverage",
            message,
            false,
        )
        .await);
    }

    let mut cert_pem: String = pem_certificate(&issued.leaf_der);
    for der in &issued.chain_der {
        cert_pem.push_str(&pem_certificate(der));
    }
    if let Err(err) = lorica_tls::validate_certificate_bundle(&cert_pem, &issued.private_key_pem) {
        return Err(fail(
            state,
            ctx,
            &authority.id,
            attempt,
            "certificate",
            format!("the issued certificate cannot be served with its key: {err}"),
            false,
        )
        .await);
    }
    let issuing_ca_pem: Option<String> = issued.chain_der.first().map(|der| pem_certificate(der));
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
            let message: String = format!("the issued certificate could not be stored: {err}");
            let payload = attempt.payload(
                "error",
                serde_json::json!({ "step": "store", "message": message }),
            );
            audit(
                state,
                ctx,
                "error:store",
                attempt.target_id(),
                Some(&payload),
            )
            .await;
            alert_issuance_failed(
                state,
                &authority.id,
                attempt,
                "store",
                &message,
                issued.request_id.as_deref(),
            );
            return Err(IssueError::Api(err));
        }
    };

    if let Some((settings, acls)) = stored.export_snapshot {
        crate::cert_export::export_after_release(settings, acls, stored.cert.clone()).await;
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
/// certificate on the authority when it has none yet (D12).
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
mod tests;
