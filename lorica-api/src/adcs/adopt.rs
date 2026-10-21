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

//! Adopting certificates issued before Lorica could, and reverting AD
//! CS certificates to manual (Story 13.5, Epic 13 PRD D9, D12, D14).
//!
//! # Candidacy
//!
//! A candidate is a manual certificate whose leaf the authority's
//! issuing CA certificate signed, and whose names a renewal could
//! request: every one of them under an allowed suffix, none a wildcard
//! (the rule issuance applies, [`check_sans`]). "Signed" means the
//! leaf's signature verifies against the issuing CA certificate's
//! public key, the leaf's issuer name is that certificate's subject,
//! and, when the leaf carries an authority key identifier and the CA a
//! subject key identifier, the two are equal. The issuer name alone
//! proves nothing (anyone can mint a CA with the same name), and a root
//! would match every issuing CA under it, so only the first certificate
//! of the authority's `issuing_ca_pem` is ever used.
//!
//! Detection is a pure read, computed on every request: nothing about a
//! candidate is stored, so there is nothing to keep in sync when the
//! certificates or the issuing CA change. Adoption re-checks the
//! candidacy of the one certificate it is asked about, inside the store
//! transaction that writes it.
//!
//! # What adoption and reversion change
//!
//! Adoption issues nothing and contacts no authority. It sets the
//! `adcs_*` references so the next renewal, in the loop's window or on
//! "Renew now", goes to the authority. Reverting clears
//! `adcs_authority_id` only: the certificate becomes manual, stays in
//! service, and keeps the other `adcs_*` fields as history.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_config::models::{AdcsAuthority, Certificate, CertificateSource};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;

use super::issue::{check_sans, normalize_sans, template_oid_of, IssueError};
use super::renew::{renewal_names, stored_leaf_der};
use super::{refuse_on_follower, AdcsHandlerError};
use crate::audit::{AuditContext, ClientConnectInfo};
use crate::certificates::{cert_to_response, subject_of, CertificateResponse};
use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// The target type of the adoption and reversion audit rows.
const CERT_AUDIT_TARGET: &str = "certificate";

/// Why the candidate listing is empty without looking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionUnavailable {
    /// No authority is configured on this node.
    NotConfigured,
    /// The authority does not know its issuing CA certificate, so no
    /// signature can be verified.
    NoIssuingCa,
}

/// A manual certificate the authority's issuing CA signed.
#[derive(Debug, Serialize)]
pub struct AdoptionCandidate {
    /// The certificate's id.
    pub certificate_id: String,
    /// Its domain, the first name a renewal requests.
    pub domain: String,
    /// The DNS names of its leaf.
    pub san_domains: Vec<String>,
    /// The leaf's subject, RFC 4514, as a renewal requests it again.
    pub subject: String,
    /// RFC 3339 expiry of the leaf.
    pub not_after: String,
    /// The template the leaf names: the OID of extension
    /// 1.3.6.1.4.1.311.21.7, else the name of 1.3.6.1.4.1.311.20.2.
    pub issued_template: Option<String>,
    /// The template observed on the most recent certificate Lorica
    /// issued with the authority's default template; `null` when it has
    /// issued none.
    pub observed_template: Option<String>,
    /// Both templates known and different: a renewal requests the
    /// authority's template, which may not be the one this certificate
    /// was issued with.
    pub template_mismatch: bool,
}

/// Body of `GET /api/v1/adcs/adoption-candidates`.
#[derive(Debug, Serialize)]
pub struct AdoptionCandidates {
    /// Why nothing was looked at, `null` when the listing is real.
    pub reason: Option<AdoptionUnavailable>,
    /// The candidates, by domain.
    pub candidates: Vec<AdoptionCandidate>,
}

/// Body of `POST /api/v1/certificates/{id}/adcs/adopt`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsAdoptRequest {
    /// The adopted certificate's auto-renew setting; the authority's
    /// `auto_renew_default` when absent.
    #[serde(default)]
    pub auto_renew: Option<bool>,
}

/// Why a certificate is not a candidate.
#[derive(Debug)]
pub(crate) enum NotCandidate {
    /// It is not a manual certificate.
    NotManual(CertificateSource),
    /// Its stored certificate cannot be read.
    Unreadable(String),
    /// The issuing CA certificate did not sign it.
    NotSignedByIssuingCa,
    /// A name a renewal would request is refused (D5).
    Names(String),
}

impl NotCandidate {
    fn message(&self, id: &str) -> String {
        match self {
            NotCandidate::NotManual(CertificateSource::Acme) => {
                format!("certificate `{id}` is not manual: it is issued and renewed by ACME")
            }
            NotCandidate::NotManual(_) => {
                format!("certificate `{id}` is not manual: it is already managed by AD CS")
            }
            NotCandidate::Unreadable(reason) => {
                format!("certificate `{id}` cannot be checked: {reason}")
            }
            NotCandidate::NotSignedByIssuingCa => format!(
                "certificate `{id}` was not signed by the authority's issuing CA certificate"
            ),
            NotCandidate::Names(reason) => {
                format!("certificate `{id}` cannot be renewed by the authority: {reason}")
            }
        }
    }
}

/// The DER of the first certificate in `issuing_ca_pem`, or `None` when
/// there is none to verify against.
fn issuing_ca_der(authority: &AdcsAuthority) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(text) = authority.issuing_ca_pem.as_deref() else {
        return Ok(None);
    };
    // Validated when it was written or learned, so a refusal here means
    // the row was changed behind the API's back.
    let blocks: Vec<pem::Pem> = pem::parse_many(text)
        .map_err(|err| ApiError::Internal(format!("stored AD CS issuing CA certificate: {err}")))?;
    Ok(blocks
        .iter()
        .find(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.contents().to_vec()))
}

fn parse_issuing_ca(der: &[u8]) -> Result<X509Certificate<'_>, ApiError> {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, ca)| ca)
        .map_err(|err| ApiError::Internal(format!("stored AD CS issuing CA certificate: {err}")))
}

fn authority_key_id<'c>(cert: &'c X509Certificate<'_>) -> Option<&'c [u8]> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0)
            }
            _ => None,
        })
}

fn subject_key_id<'c>(cert: &'c X509Certificate<'_>) -> Option<&'c [u8]> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
            _ => None,
        })
}

/// Whether `ca` signed `leaf` (see the module documentation).
pub(crate) fn signed_by(leaf: &X509Certificate<'_>, ca: &X509Certificate<'_>) -> bool {
    if leaf.issuer().as_raw() != ca.subject().as_raw() {
        return false;
    }
    if leaf.verify_signature(Some(ca.public_key())).is_err() {
        return false;
    }
    match (authority_key_id(leaf), subject_key_id(ca)) {
        (Some(authority_key), Some(subject_key)) => authority_key == subject_key,
        _ => true,
    }
}

/// The template `cert`'s leaf names, when `cert` is a candidate for
/// `authority`, whose issuing CA certificate is `ca`.
pub(crate) fn assess(
    authority: &AdcsAuthority,
    ca: &X509Certificate<'_>,
    cert: &Certificate,
) -> Result<Option<String>, NotCandidate> {
    let source: CertificateSource = cert.source();
    if source != CertificateSource::Manual {
        return Err(NotCandidate::NotManual(source));
    }
    let leaf_der: Vec<u8> = stored_leaf_der(cert).map_err(NotCandidate::Unreadable)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).map_err(|err| {
        NotCandidate::Unreadable(format!("the stored certificate does not parse: {err}"))
    })?;
    if !signed_by(&leaf, ca) {
        return Err(NotCandidate::NotSignedByIssuingCa);
    }
    let names: Vec<String> = normalize_sans(&renewal_names(cert));
    if let Err(IssueError::SanRefused { message, .. }) = check_sans(authority, &names) {
        return Err(NotCandidate::Names(message));
    }
    Ok(template_oid_of(&leaf))
}

/// The template observed on the most recent certificate Lorica issued
/// for `authority` with its default template.
///
/// Only a certificate carrying the authority's request identifier
/// counts: adoption clears it, because an adopted certificate's
/// observed template is the one of its manual issuance until Lorica
/// renews it, and a renewal records the identifier again.
fn observed_template(authority: &AdcsAuthority, certs: &[Certificate]) -> Option<String> {
    certs
        .iter()
        .filter(|cert| {
            cert.source() == CertificateSource::Adcs
                && cert.adcs_authority_id.as_deref() == Some(authority.id.as_str())
                && cert.adcs_template.as_deref() == Some(authority.default_template.as_str())
                && cert.adcs_request_id.is_some()
        })
        .filter_map(|cert| {
            cert.adcs_template_oid
                .as_ref()
                .map(|oid: &String| (cert.not_before, oid))
        })
        .max_by_key(|(not_before, _): &(DateTime<Utc>, &String)| *not_before)
        .map(|(_, oid)| oid.clone())
}

/// The candidate listing over `certs` (see the module documentation).
fn list_candidates(
    authority: Option<&AdcsAuthority>,
    certs: &[Certificate],
) -> Result<AdoptionCandidates, ApiError> {
    let unavailable = |reason: AdoptionUnavailable| AdoptionCandidates {
        reason: Some(reason),
        candidates: Vec::new(),
    };
    let Some(authority) = authority else {
        return Ok(unavailable(AdoptionUnavailable::NotConfigured));
    };
    let Some(ca_der) = issuing_ca_der(authority)? else {
        return Ok(unavailable(AdoptionUnavailable::NoIssuingCa));
    };
    let ca: X509Certificate<'_> = parse_issuing_ca(&ca_der)?;
    let observed: Option<String> = observed_template(authority, certs);
    let candidates: Vec<AdoptionCandidate> = certs
        .iter()
        .filter_map(|cert| {
            let issued: Option<String> = assess(authority, &ca, cert).ok()?;
            let template_mismatch: bool = matches!(
                (&issued, &observed),
                (Some(issued), Some(observed)) if issued != observed
            );
            Some(AdoptionCandidate {
                certificate_id: cert.id.clone(),
                domain: cert.domain.clone(),
                san_domains: cert.san_domains.clone(),
                subject: subject_of(&cert.cert_pem),
                not_after: cert.not_after.to_rfc3339(),
                issued_template: issued,
                observed_template: observed.clone(),
                template_mismatch,
            })
        })
        .collect();
    Ok(AdoptionCandidates {
        reason: None,
        candidates,
    })
}

/// GET /api/v1/adcs/adoption-candidates - the manual certificates the
/// authority's issuing CA signed (Viewer).
pub async fn list_adoption_candidates(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (authority, certs) = db_blocking(&state.store, |store| {
        Ok::<_, ApiError>((
            store.get_adcs_authority()?,
            store.list_certificates_without_private_keys()?,
        ))
    })
    .await?;
    // Parsing and verifying every certificate is CPU work, done after
    // the store lock is released.
    let listing: AdoptionCandidates =
        tokio::task::spawn_blocking(move || list_candidates(authority.as_ref(), &certs))
            .await
            .map_err(|err| ApiError::Internal(format!("adoption listing task failed: {err}")))??;
    Ok(json_data(listing))
}

/// What a refused adoption or reversion answers.
#[derive(Debug)]
enum Refusal {
    NotConfigured(String),
    NotCandidate(String),
    Api(ApiError),
}

impl From<ApiError> for Refusal {
    fn from(err: ApiError) -> Refusal {
        Refusal::Api(err)
    }
}

impl From<lorica_config::ConfigError> for Refusal {
    fn from(err: lorica_config::ConfigError) -> Refusal {
        Refusal::Api(err.into())
    }
}

impl From<Refusal> for AdcsHandlerError {
    fn from(refusal: Refusal) -> AdcsHandlerError {
        let coded =
            |status: StatusCode, code: &'static str, message: String| AdcsHandlerError::Coded {
                status,
                code,
                message,
                step: None,
            };
        match refusal {
            Refusal::NotConfigured(message) => {
                coded(StatusCode::CONFLICT, "adcs_not_configured", message)
            }
            Refusal::NotCandidate(message) => coded(
                StatusCode::UNPROCESSABLE_ENTITY,
                "adcs_not_candidate",
                message,
            ),
            Refusal::Api(err) => AdcsHandlerError::Api(err),
        }
    }
}

/// A certificate as it was and as it was written.
struct Written {
    before: Certificate,
    after: Certificate,
}

/// The store side of an adoption, inside one transaction: the authority
/// and the row are read, the candidacy re-checked and the row written
/// under the same lock, so neither can change in between.
fn write_adoption(
    store: &ConfigStore,
    id: &str,
    auto_renew: Option<bool>,
) -> Result<Written, Refusal> {
    let authority: AdcsAuthority = store.get_adcs_authority()?.ok_or_else(|| {
        Refusal::NotConfigured(
            "no AD CS authority is configured; a SuperAdmin must declare one".to_string(),
        )
    })?;
    let before: Certificate = store
        .get_certificate(id)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;
    let ca_der: Vec<u8> = issuing_ca_der(&authority)?.ok_or_else(|| {
        Refusal::NotConfigured(
            "the AD CS authority does not know its issuing CA certificate, so no certificate \
             can be verified as its own; issue one certificate through Lorica, or have a \
             SuperAdmin paste the issuing CA certificate in the authority settings"
                .to_string(),
        )
    })?;
    let ca: X509Certificate<'_> = parse_issuing_ca(&ca_der)?;
    let issued_template: Option<String> = assess(&authority, &ca, &before)
        .map_err(|not_candidate| Refusal::NotCandidate(not_candidate.message(id)))?;

    let mut after: Certificate = before.clone();
    after.adcs_authority_id = Some(authority.id.clone());
    after.adcs_template = Some(authority.default_template.clone());
    after.adcs_template_oid = issued_template;
    // The identifier names a request Lorica made; this leaf came from
    // none (see `observed_template`).
    after.adcs_request_id = None;
    after.acme_auto_renew = auto_renew.unwrap_or(authority.auto_renew_default);
    store.update_certificate(&after)?;
    Ok(Written { before, after })
}

fn write_reversion(store: &ConfigStore, id: &str) -> Result<Written, ApiError> {
    let before: Certificate = store
        .get_certificate(id)?
        .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;
    if before.source() != CertificateSource::Adcs {
        return Err(ApiError::Conflict(format!(
            "certificate `{id}` is not managed by AD CS; only an AD CS certificate can be \
             reverted to manual"
        )));
    }
    let mut after: Certificate = before.clone();
    after.adcs_authority_id = None;
    store.update_certificate(&after)?;
    Ok(Written { before, after })
}

/// Audit a write under `action:<id>` with both views, and answer the
/// new one.
async fn finish(
    state: &AppState,
    ctx: &AuditContext,
    action: &str,
    written: Written,
) -> Json<serde_json::Value> {
    // The `adcs_*` columns are part of the canonical blob, so followers
    // must see the changed row like any other certificate write.
    state.notify_config_changed();
    let response: CertificateResponse = cert_to_response(&written.after);
    // Response views only: the stored model carries `key_pem`.
    let before = serde_json::to_value(cert_to_response(&written.before)).ok();
    let after = serde_json::to_value(&response).ok();
    crate::audit::record(
        state,
        ctx,
        &format!("{action}:{}", written.after.id),
        (CERT_AUDIT_TARGET, written.after.id.as_str()),
        before.as_ref(),
        after.as_ref(),
    )
    .await;
    json_data(response)
}

/// POST /api/v1/certificates/{id}/adcs/adopt - hand a manual certificate
/// the authority's issuing CA signed to the authority (Operator,
/// control plane only). Issues nothing.
pub async fn adopt_certificate(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    body: Option<Json<AdcsAdoptRequest>>,
) -> Result<Json<serde_json::Value>, AdcsHandlerError> {
    refuse_on_follower(&state)?;
    let auto_renew: Option<bool> = body.and_then(|Json(request)| request.auto_renew);
    let written: Written = db_blocking(&state.store, move |store| {
        Ok::<_, ApiError>(
            store.in_transaction(|store: &ConfigStore| write_adoption(store, &id, auto_renew)),
        )
    })
    .await??;
    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    Ok(finish(&state, &ctx, "adcs.certificate.adopt", written).await)
}

/// POST /api/v1/certificates/{id}/adcs/revert - make an AD CS
/// certificate manual again (Operator, control plane only). The current
/// certificate stays in service and nothing renews it any more.
pub async fn revert_certificate(
    connect_info: ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AdcsHandlerError> {
    refuse_on_follower(&state)?;
    // A renewal in flight would write the row back with the authority
    // set when it completes, undoing the reversion.
    let Some(_in_flight) = state.renewals.begin(&id) else {
        return Err(ApiError::Conflict(format!(
            "certificate `{id}`: a renewal is in flight; revert it once the renewal ends"
        ))
        .into());
    };
    let reverted_id: String = id.clone();
    let written: Written = db_blocking(&state.store, move |store| {
        store.in_transaction(|store: &ConfigStore| write_reversion(store, &reverted_id))
    })
    .await?;
    state.adcs.renewals.forget_failures(&id);
    let ctx: AuditContext = AuditContext::new(&session, connect_info.as_ref(), &headers);
    Ok(finish(&state, &ctx, "adcs.certificate.revert", written).await)
}

#[cfg(test)]
mod tests;
