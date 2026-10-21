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
//! write of the authority, runs under [`runtime::AdcsGuard`]; see there
//! for why a second one is refused rather than queued. What each refusal
//! answers is in [`error`].
//!
//! # Control plane only (D13)
//!
//! The authority never replicates, so a follower has none. Its writes
//! are refused by the follower read-only gate and again here (a
//! break-glass window does not make a follower an AD CS client), and
//! its read answers `managed_on_control_plane`.

use std::path::Path;
use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_adcs::{
    kdc_error_meaning, AdcsError, CesParams, CesTimeouts, KdcAddress, KdcTiming, Krb5Config, Realm,
    Secret, TicketFailure,
};
use lorica_config::models::{AdcsAuthority, AllowedSuffix, Role};
use lorica_config::ConfigStore;
use serde::Serialize;

use crate::audit::{AuditContext, ClientConnectInfo};
use crate::cluster::ClusterRuntime;
use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

mod adopt;
mod error;
mod issue;
mod leaf;
mod renew;
mod runtime;
mod validate;

pub(crate) use adopt::AdoptionVerdicts;
pub use adopt::{
    adopt_certificate, list_adoption_candidates, revert_certificate, AdcsAdoptRequest,
    AdoptionCandidate, AdoptionCandidates, AdoptionUnavailable,
};
pub(crate) use error::{
    refuse_on_follower, AdcsUnavailable, CERTIFICATE_MANAGED, KEY_NOT_EXPORTABLE,
    NOT_ON_AUTOMATION_PLANE,
};
pub use error::{AdcsCode, IssuanceStep, ADCS_CODES};
pub use issue::{issue_certificate, AdcsIssueRequest, PendingIssuance, MAX_SANS};
pub(crate) use renew::{renew_due, renew_manually, AdcsRenewalMemory};
pub use renew::{ADCS_RENEWAL_ACTOR, ADCS_RENEWAL_BACKOFF_HOURS};
pub use runtime::AdcsRuntime;
#[cfg(test)]
pub(crate) use runtime::{per_request_session, AdcsClient, AdcsSession};
pub(crate) use runtime::{run_exclusive, run_exclusive_to_end, LazySession, NotRun};
use validate::ValidatedRequest;
pub(crate) use validate::{subject_fields, validate_subject};
pub use validate::{AdcsAuthorityRequest, WritePassword, MAX_KDCS};

/// The target type of every audit row this module writes.
const AUDIT_TARGET: &str = "adcs_authority";

/// `request_timeout` of the generated `krb5.conf`, in seconds: the
/// bound of one KDC exchange on MIT krb5 1.22 and later. It sits well
/// inside the operation timeout of [`CesTimeouts::default`] (Epic 13
/// D3, D8), so a silent KDC is reported as unreachable before the
/// outer guard fires, and leaves room for MIT to try a second KDC.
pub const KDC_REQUEST_TIMEOUT_SECS: u32 = 30;

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
/// run against it, and make the `krb5.conf` the one the stored row
/// renders, so the file the library reads is the one this operation's
/// parameters came from. Call it under the single-flight guard, which
/// every writer of the file holds.
///
/// The file is compared and written after the store lock is released:
/// every other store-bound request waits on that lock, and the file
/// changes only with the authority, so an operation usually writes
/// nothing at all.
pub(crate) async fn prepare_operation(state: &AppState) -> Result<AdcsOperation, AdcsUnavailable> {
    let (operation, config): (AdcsOperation, Krb5Config) = db_blocking(&state.store, |store| {
        Ok::<_, ApiError>(read_operation(store))
    })
    .await??;
    let path: std::path::PathBuf = lorica_adcs::krb5_config_path(&state.data_dir);
    tokio::task::spawn_blocking(move || config.write_if_changed(&path))
        .await
        .map_err(|err| AdcsUnavailable::Krb5Conf(format!("the krb5.conf task failed: {err}")))?
        .map_err(|err: AdcsError| AdcsUnavailable::Krb5Conf(err.to_string()))?;
    Ok(operation)
}

/// The store side of [`prepare_operation`]: the operation and the
/// `krb5.conf` it needs.
fn read_operation(store: &ConfigStore) -> Result<(AdcsOperation, Krb5Config), AdcsUnavailable> {
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
    let params: CesParams = CesParams {
        endpoint: authority.endpoint.clone(),
        realm: config.realm.clone(),
        principal: authority.principal.clone(),
        trust_bundle_pem: authority.endpoint_ca_pem.clone(),
        timeouts: CesTimeouts::default(),
    };
    Ok((
        AdcsOperation {
            authority,
            params,
            password,
        },
        config,
    ))
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
        .map_err(|err: AdcsError| ApiError::from(AdcsUnavailable::Krb5Conf(err.to_string())))
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
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
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
        issuing_ca_pem: match request.issuing_ca_pem {
            Some(given) => given,
            None => existing
                .as_ref()
                .and_then(|a: &AdcsAuthority| a.issuing_ca_pem.clone()),
        },
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
) -> Result<Json<serde_json::Value>, ApiError> {
    refuse_on_follower(&state)?;
    let store = Arc::clone(&state.store);
    let id: String = run_exclusive(&state.adcs, async move {
        db_blocking(&store, |store| {
            let authority: AdcsAuthority = store
                .get_adcs_authority()?
                .ok_or_else(|| ApiError::from(AdcsUnavailable::NotConfigured))?;
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
    /// The failing step's closed name, one of
    /// [`lorica_adcs::FailureStep`]'s, `null` on success.
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
) -> Result<Json<serde_json::Value>, ApiError> {
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
