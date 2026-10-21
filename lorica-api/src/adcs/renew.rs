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

//! Renewing AD CS certificates (Story 13.4, Epic 13 PRD D6, D14, D15).
//!
//! The background loop (`crate::acme::renewal`) selects the AD CS
//! certificates due for renewal and hands them to [`renew_due`]; the
//! dashboard's "Renew now" reaches [`renew_manually`] through
//! `renew_certificate_as`. Both renew in place through
//! [`super::issue::issue`], with the certificate's current names and
//! subject and its recorded template, under the `RenewalLedger`
//! in-flight mark the ACME renewals share.
//!
//! # Failures
//!
//! A failure keeps the current certificate in service. A credential
//! the KDC rejects opens the D15 breaker and ends the tick: the
//! renewals left are not attempted, so they cost no Kerberos exchange,
//! write no audit row and raise no alert of their own. Any other
//! failure, a pending answer included, backs that certificate off for
//! [`ADCS_RENEWAL_BACKOFF_HOURS`] in a map of its own, apart from the
//! ACME rate-limit cooldown, which a CA's message drives and a token's
//! budget reads.
//!
//! `cert_issuance_failed` is raised once per failure state of a
//! certificate, not once per attempt: [`AdcsRenewalMemory`] keeps the
//! step last alerted for each certificate, a repeat of it is silent,
//! and a different step or a success in between re-arms it.
//!
//! # Expiry alerts (AC #6)
//!
//! `check_cert_expiry` speaks for an AD CS certificate, as it does for
//! an uploaded one: it alerts on every certificate in the operator's
//! warning window, with the warning and critical thresholds the
//! operator set. The loop's own `CertExpiring` is the ACME arm's and is
//! never sent for an AD CS certificate, so an operator receives one
//! expiry alert per certificate per check, not two; what the loop adds
//! for an AD CS certificate is `cert_issuance_failed` when its renewal
//! fails, which is the alert an operator acts on.

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_config::models::{AdcsSubjectDefaults, Certificate};
use parking_lot::Mutex;
use tracing::{info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::x509::{AttributeTypeAndValue, X509Name};

use super::issue::{
    issue, send_issuance_failed, IssueError, IssueOutcome, IssueRequest, IssueSubject,
    PendingIssuance,
};
use super::{refuse_on_follower, AdcsHandlerError};
use crate::audit::AuditContext;
use crate::certificates::cert_to_response;
use crate::db::db_blocking;
use crate::error::{json_data_with_status, ApiError};
use crate::server::AppState;

/// How long a certificate whose AD CS renewal failed for any reason
/// but a rejected credential is left alone by the loop. Longer than
/// the loop's 12 hour tick, so a certificate the authority refuses is
/// asked about once a day rather than on every tick, and short enough
/// against a 30 day window that a transient failure leaves many
/// attempts before expiry.
pub const ADCS_RENEWAL_BACKOFF_HOURS: i64 = 24;

/// The actor of every loop renewal's audit rows.
pub const ADCS_RENEWAL_ACTOR: &str = "adcs-renewal";

/// What the renewal paths remember about each AD CS certificate's
/// failures between attempts. In memory, one per process: a restart
/// forgets it, which costs at most one attempt and one alert per
/// certificate, while the D15 failed state, the one that protects the
/// service account, is persisted on the authority.
#[derive(Debug, Default)]
pub(crate) struct AdcsRenewalMemory {
    /// Per certificate, the instant before which the loop does not try
    /// again.
    backoff: Mutex<HashMap<String, DateTime<Utc>>>,
    /// Per certificate, the step of the last `cert_issuance_failed`.
    alerted: Mutex<HashMap<String, String>>,
}

impl AdcsRenewalMemory {
    /// The instant `id`'s back-off ends, when one is active at `now`.
    pub(crate) fn backoff_until(&self, id: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.backoff
            .lock()
            .get(id)
            .copied()
            .filter(|until| *until > now)
    }

    fn back_off(&self, id: &str, now: DateTime<Utc>) {
        self.backoff.lock().insert(
            id.to_string(),
            now + chrono::Duration::hours(ADCS_RENEWAL_BACKOFF_HOURS),
        );
    }

    /// Whether a failure of `id` at `step` is a new failure state, and
    /// so owed an alert. Records `step` as the state alerted.
    pub(crate) fn is_new_failure_state(&self, id: &str, step: &str) -> bool {
        self.alerted
            .lock()
            .insert(id.to_string(), step.to_string())
            .is_none_or(|previous| previous != step)
    }

    /// Forget `id`'s back-off and alerted state, after it was renewed.
    pub(crate) fn forget_failures(&self, id: &str) {
        self.backoff.lock().remove(id);
        self.alerted.lock().remove(id);
    }

    /// Keep only the certificates in `live` and the back-offs still
    /// running at `now`, so the maps stay bounded by the certificates
    /// that exist and fail.
    pub(crate) fn retain(&self, live: &HashSet<&str>, now: DateTime<Utc>) {
        self.backoff
            .lock()
            .retain(|id, until| *until > now && live.contains(id.as_str()));
        self.alerted
            .lock()
            .retain(|id, _| live.contains(id.as_str()));
    }
}

/// The subject fields of `cert`'s leaf, the first certificate of its
/// `cert_pem`, as a renewal requests them again. The `CN` is not one of
/// them: it is the first SAN, the certificate's domain.
fn current_subject(cert: &Certificate) -> Result<AdcsSubjectDefaults, String> {
    let blocks: Vec<pem::Pem> = pem::parse_many(&cert.cert_pem)
        .map_err(|err| format!("the stored certificate is not PEM: {err}"))?;
    let leaf_der: &[u8] = blocks
        .iter()
        .find(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.contents())
        .ok_or_else(|| "the stored certificate holds no CERTIFICATE block".to_string())?;
    let (_, leaf): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|err| format!("the stored certificate does not parse: {err}"))?;
    let subject: &X509Name<'_> = leaf.subject();
    Ok(AdcsSubjectDefaults {
        country: first_value(subject.iter_country()),
        state: first_value(subject.iter_state_or_province()),
        locality: first_value(subject.iter_locality()),
        organization: first_value(subject.iter_organization()),
        organizational_unit: first_value(subject.iter_organizational_unit()),
        email: first_value(subject.iter_email()),
    })
}

fn first_value<'a, 'b: 'a>(
    mut values: impl Iterator<Item = &'a AttributeTypeAndValue<'b>>,
) -> Option<String> {
    values
        .next()
        .and_then(|value| value.as_str().ok())
        .map(str::to_string)
}

/// The in-place issuance that renews `cert`: its names with the domain
/// first, its current subject, its recorded template (the authority's
/// default only when none is recorded), the authority's key type, and
/// its auto-renew setting kept.
fn renewal_request(cert: &Certificate) -> Result<IssueRequest, String> {
    let mut sans: Vec<String> = vec![cert.domain.clone()];
    for name in &cert.san_domains {
        if !sans.contains(name) {
            sans.push(name.clone());
        }
    }
    Ok(IssueRequest {
        sans,
        template: cert.adcs_template.clone(),
        key_type: None,
        subject: IssueSubject::Exact(current_subject(cert)?),
        auto_renew: None,
        replace: Some(cert.id.clone()),
    })
}

/// Whether an AD CS operation may run at all now: an authority with a
/// password, not in the failed state. Read before a tick's first
/// renewal so a tick that cannot succeed attempts nothing.
async fn authority_ready(state: &AppState) -> Result<bool, ApiError> {
    db_blocking(&state.store, |store| {
        let Some(authority) = store.get_adcs_authority()? else {
            return Ok::<bool, ApiError>(false);
        };
        Ok(!authority.is_failed() && super::password_is_set(store)?)
    })
    .await
}

/// A failure the issuance did not alert itself (a refusal before the
/// authority was contacted), alerted through the same per-state memory.
fn alert_unsent_failure(state: &AppState, cert: &Certificate, step: &str, message: &str) {
    let sans: Vec<String> = std::iter::once(cert.domain.clone())
        .chain(cert.san_domains.iter().cloned())
        .collect();
    send_issuance_failed(
        state,
        cert.adcs_authority_id.as_deref().unwrap_or_default(),
        &sans,
        Some(&cert.id),
        step,
        message,
        None,
    );
}

/// Whether the loop goes on to the next certificate of the tick.
enum Next {
    Continue,
    EndTick,
}

/// Renew every certificate of `due`, the AD CS certificates the loop
/// found bound, opted in and inside the window, one at a time.
///
/// Each attempt is audited by the issuance under
/// [`AuditContext::node`] with [`ADCS_RENEWAL_ACTOR`]. The tick ends at
/// the first answer that says no AD CS operation can succeed now: a
/// rejected credential (the breaker is then open), the failed state,
/// another AD CS operation running, or one still finishing.
pub(crate) async fn renew_due(state: &AppState, due: &[&Certificate], now: DateTime<Utc>) {
    if due.is_empty() {
        return;
    }
    match authority_ready(state).await {
        Ok(true) => {}
        Ok(false) => {
            info!(
                due = due.len(),
                "AD CS renewal skipped: no usable authority (none, no password, or in the \
                 failed state)"
            );
            return;
        }
        Err(err) => {
            warn!(error = %err, "AD CS renewal: failed to read the authority");
            return;
        }
    }
    let ctx: AuditContext = AuditContext::node(ADCS_RENEWAL_ACTOR);
    for cert in due {
        if let Some(until) = state.adcs.renewals.backoff_until(&cert.id, now) {
            info!(
                domain = %cert.domain,
                cert_id = %cert.id,
                retry_after = %until,
                "skipping AD CS renewal: back-off after a failure"
            );
            continue;
        }
        let Some(_in_flight) = state.renewals.begin(&cert.id) else {
            info!(
                domain = %cert.domain,
                cert_id = %cert.id,
                "skipping AD CS renewal: a renewal of this certificate is in flight"
            );
            continue;
        };
        if let Next::EndTick = renew_one(state, &ctx, cert, now).await {
            break;
        }
    }
}

async fn renew_one(
    state: &AppState,
    ctx: &AuditContext,
    cert: &Certificate,
    now: DateTime<Utc>,
) -> Next {
    let memory = &state.adcs.renewals;
    let request: IssueRequest = match renewal_request(cert) {
        Ok(request) => request,
        Err(message) => {
            warn!(cert_id = %cert.id, error = %message, "AD CS renewal: no request to send");
            alert_unsent_failure(state, cert, "subject", &message);
            memory.back_off(&cert.id, now);
            return Next::Continue;
        }
    };
    match issue(state, ctx, request).await {
        Ok(IssueOutcome::Issued(_)) => {
            info!(domain = %cert.domain, cert_id = %cert.id, "AD CS certificate renewed");
            Next::Continue
        }
        Ok(IssueOutcome::Pending { request_id, .. }) => {
            warn!(
                domain = %cert.domain,
                cert_id = %cert.id,
                request_id = %request_id,
                "AD CS renewal held pending at the authority; the current certificate stays"
            );
            memory.back_off(&cert.id, now);
            Next::Continue
        }
        Err(IssueError::Failed {
            step,
            authority_failed: true,
            ..
        }) => {
            warn!(
                cert_id = %cert.id,
                step = %step,
                "AD CS credential rejected; the authority is failed and the tick ends"
            );
            Next::EndTick
        }
        Err(IssueError::Unavailable(unavailable)) => {
            info!(
                reason = unavailable.audit_reason(),
                "AD CS renewal: the authority refuses operations; the tick ends"
            );
            Next::EndTick
        }
        Err(IssueError::Busy | IssueError::StillRunning) => {
            info!("AD CS renewal: another AD CS operation is running; the tick ends");
            Next::EndTick
        }
        Err(IssueError::Api(ApiError::NotFound(_))) => Next::Continue,
        Err(IssueError::SanRefused { message, .. }) => {
            warn!(cert_id = %cert.id, error = %message, "AD CS renewal refused its names");
            alert_unsent_failure(state, cert, "san_refused", &message);
            memory.back_off(&cert.id, now);
            Next::Continue
        }
        Err(IssueError::Api(err)) => {
            warn!(cert_id = %cert.id, error = %err, "AD CS renewal failed before the authority");
            alert_unsent_failure(state, cert, "request", &err.to_string());
            memory.back_off(&cert.id, now);
            Next::Continue
        }
        Err(err @ (IssueError::Failed { .. } | IssueError::Denied { .. })) => {
            warn!(
                domain = %cert.domain,
                cert_id = %cert.id,
                error = ?err,
                "AD CS renewal failed; the current certificate stays"
            );
            memory.back_off(&cert.id, now);
            Next::Continue
        }
    }
}

/// "Renew now" for an AD CS certificate, as the dashboard's operator
/// `actor`: in place, under the in-flight mark (409 when the loop or
/// another request holds it), under the D15 guard and breaker.
///
/// Answers 200 with the renewed certificate's view, or 202 with the
/// authority's request identifier when it held the request pending:
/// nothing was stored, the current certificate stays in service, and
/// the attempt was alerted as a failure. A successful renewal writes a
/// `certificate.renew` row beside the issuance's own rows.
pub(crate) async fn renew_manually(
    state: &AppState,
    actor: &AuditContext,
    cert: &Certificate,
    mode: crate::preview::WriteMode,
) -> Result<(StatusCode, Json<serde_json::Value>), AdcsHandlerError> {
    refuse_on_follower(state)?;
    if mode.previews() {
        return Ok((
            StatusCode::OK,
            crate::preview::previewed(
                "renew",
                serde_json::to_value(cert_to_response(cert)).ok(),
                None,
            ),
        ));
    }
    let Some(_in_flight) = state.renewals.begin(&cert.id) else {
        return Err(ApiError::Conflict(format!(
            "certificate `{}`: a renewal is in flight; one renewal per certificate at a time",
            cert.id
        ))
        .into());
    };
    let request: IssueRequest = renewal_request(cert).map_err(|message| {
        AdcsHandlerError::Api(ApiError::Unprocessable(format!(
            "certificate `{}` cannot be renewed: {message}",
            cert.id
        )))
    })?;
    match issue(state, actor, request).await? {
        IssueOutcome::Issued(renewed) => {
            let payload = serde_json::json!({
                "renewed": true,
                "cert_id": renewed.id,
                "domain": renewed.domain,
            });
            crate::audit::record(
                state,
                actor,
                "certificate.renew",
                ("certificate", &renewed.id),
                None,
                Some(&payload),
            )
            .await;
            Ok(json_data_with_status(
                StatusCode::OK,
                cert_to_response(&renewed),
            ))
        }
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

#[cfg(test)]
mod tests;
