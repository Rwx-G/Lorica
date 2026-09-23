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

//! The automation plane's write surface (Story 11.2): routes, backends
//! and certificate bindings, each behind its own write scope.
//!
//! # The reversal this module is
//!
//! Story 10.3 decided that the automation surface is the environment
//! resource and never the management API behind a different door, and
//! left `routes:write` and `certificates:write` out of the scope enum
//! on purpose. This module is the reversal of that decision for three
//! scopes, taken for the MCP config tier, whose whole point is that a
//! change an operator would make in the dashboard takes one sentence.
//! The reversal is recorded beside the decision it reverses, in the
//! Epic 10 PRD at Story 10.3 AC #5, so the two files do not silently
//! contradict each other.
//!
//! # Every handler here is the management handler, never a second one
//!
//! Each write calls the `_as` body its management twin was split into
//! (`crate::routes::crud::create_route_as` and its siblings), with the
//! token as the actor where the dashboard's session would be. The
//! validators, the defaults, the managed-row refusal, the reload
//! signal and the management-side audit row are therefore the same
//! function's, and a route created through either plane is the same
//! stored row. Nothing in this module checks a field of a route, a
//! backend or a certificate: that is what keeps the two surfaces from
//! drifting on a rule, which on a write surface would mean one plane
//! accepting what the other refuses.
//!
//! # What this module adds is the token's grant, on the claim and on the target
//!
//! Authorization, not validation. Every hostname a route write claims
//! must be inside the token's `allowed_hostnames`, and every address a
//! backend write points at must be an `ip:port` inside its
//! `allowed_backend_cidrs`; both are refused with 403 before the
//! handler runs and before anything is written. They are the same two
//! grants the environment resource applies, through the same
//! functions, so a token minted for one shape of write is bounded the
//! same way on the other.
//!
//! The row a write NAMES is held to the same grant, and that is the
//! part a body cannot carry. A patch naming no host still names a
//! route, and a token granted `*.review.example.com` reached any route
//! on the node by id: it could disable the WAF on a production route,
//! redirect it, unbind its certificate, drain a production backend or
//! renew any certificate, because only what the body claimed was ever
//! checked. So each `_as` body takes a guard from
//! [`crate::target`], built here from the token, and runs it inside the
//! store closure that performs the write, on the row it is about to
//! write: the check and the write see one row and nothing can move
//! between them. A route's current hostname and every current alias,
//! and after a patch its new ones, must be inside the hostname grant; a
//! backend's stored address, and a new one, inside the CIDR grant; a
//! certificate's `domain` and every SAN inside the hostname grant; and
//! a route or a backend an environment owns is reachable only when the
//! environment resource's own ownership rule would let this token
//! reach that environment. Every backend a route write links anew, at
//! the top level or inside `path_rules`, `header_rules` or
//! `traffic_splits`, must point inside the CIDR grant and belong to no
//! other principal's environment. A refusal names the row by its id
//! and echoes none of its values, so a token probing ids outside its
//! grant reads no production hostname off the answer, and a preview is
//! refused exactly where the apply would be.
//!
//! Two route fields are refused from a token outright, whatever their
//! value: `forward_auth`, whose address is a URL the CIDR grant cannot
//! weigh and to which the proxy forwards every downstream `Cookie` and
//! `Authorization` header, and `mirror`, which ships a copy of every
//! request to a second set of backends. The config tier's tools do not
//! offer either.
//!
//! # One named resource per call
//!
//! Every write names one route, one backend or one certificate by id
//! in its path, or creates one. There is no pattern, no selector and
//! no bulk verb, and the scope matrix declares none: a path that would
//! delete what matches does not exist to be reached.
//!
//! # `?dry_run=true` is the preview, and the plane owns it
//!
//! Story 11.2 AC #3 asks every mutating MCP tool for a counterpart that
//! answers the change it would make without making it, and AC #5 says
//! the validators are the API's alone. So the preview is not computed
//! by the MCP server: every write here takes `?dry_run=true`, hands
//! [`crate::preview::WriteMode::Preview`] to the same management body,
//! and that body runs its validators and the guard, builds the row it
//! would store and stops before the store, the reload signal and the
//! audit row. The grant checks run first either way, since an apply the
//! grant refuses is a change the preview must not show as possible. A
//! preview sits behind the write's own scope by construction, because
//! the matrix reads the path and not the query, and its request row
//! records `?dry_run` beside the verb.
//!
//! # No key material, anywhere
//!
//! A certificate can be bound to a route here and an ACME one renewed;
//! it cannot be uploaded, replaced or generated. The management paths
//! that accept a PEM body are not mounted on this listener and the
//! matrix declares nothing for them, so they are reachable by no token,
//! and the two request bodies this module owns are `deny_unknown_fields`
//! with no field that could carry one. `tests/openapi_contract.rs`
//! asserts both halves against the document and against these
//! handlers' request structs rather than promising it here.

use std::collections::BTreeSet;

use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use lorica_config::models::{Backend, ManagedBy, Route};
use lorica_config::ConfigStore;
use serde::Deserialize;
use serde_json::Value;

use super::auth::AutomationPrincipal;
use super::environments::{audit_context, caller_may_access, ensure_backend_address_granted};
use crate::audit::ClientConnectInfo;
use crate::backends::{CreateBackendRequest, UpdateBackendRequest};
use crate::error::ApiError;
use crate::preview::{DryRunQuery, WriteMode};
use crate::routes::{CreateRouteRequest, UpdateRouteRequest};
use crate::server::AppState;
use crate::target::{BackendGuard, CertificateGuard, RouteGuard, RouteTarget};

/// JSON body for `PUT /automation/v1/routes/{id}/certificate`.
///
/// `deny_unknown_fields`, so a body carrying anything else, a PEM field
/// included, is a 422 rather than a field silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindCertificateRequest {
    /// The stored certificate to bind, by id. The empty string unbinds
    /// the route's certificate and clears `force_https` with it, which
    /// is how `PUT /api/v1/routes/{id}` reads the same value.
    pub certificate_id: String,
}

/// The hostname grant, applied to every name a route write claims: the
/// route's own hostname and each alias.
///
/// A wildcard alias is refused outright rather than matched against a
/// wildcard grant. The grant is checked one exact host at a time,
/// which is what an operator reads it as; a name that stands for every
/// host under a parent is a claim the grant cannot weigh.
fn ensure_hostnames_granted(
    principal: &AutomationPrincipal,
    hostname: Option<&str>,
    aliases: Option<&[String]>,
) -> Result<(), ApiError> {
    let claimed = hostname.into_iter().map(|name| ("hostname", name)).chain(
        aliases
            .unwrap_or_default()
            .iter()
            .map(|alias| ("hostname_aliases", alias.as_str())),
    );
    for (field, name) in claimed {
        let name = name.trim();
        if name.contains('*') {
            return Err(ApiError::Forbidden(format!(
                "{field}: a wildcard names more than one host and this token's grant is \
                 checked one exact host at a time; name each host"
            )));
        }
        if !principal.allows_hostname(name) {
            return Err(ApiError::Forbidden(format!(
                "{field} `{name}` is outside this token's allowed_hostnames"
            )));
        }
    }
    Ok(())
}

/// The two route fields a token may not send at all, whatever the
/// value, a clearing one included.
///
/// `forward_auth.address` is any absolute URL: the CIDR grant cannot
/// weigh it, and the proxy forwards every downstream `Cookie` and
/// `Authorization` header to it, so a model-authored body could send
/// every visitor's session off-site or make the proxy call a metadata
/// address per request. `mirror` ships a copy of every request,
/// credentials included, to a second set of backends. Neither is the
/// tier's in either direction; both are set in the dashboard, by a
/// human, and the tools do not offer them.
fn refuse_unbounded_reach(forward_auth: bool, mirror: bool) -> Result<(), ApiError> {
    if forward_auth {
        return Err(ApiError::Forbidden(
            "forward_auth is not accepted from an automation token: its address is a URL \
             allowed_backend_cidrs cannot weigh, and the proxy forwards every downstream Cookie \
             and Authorization header to it; set it in the dashboard"
                .to_string(),
        ));
    }
    if mirror {
        return Err(ApiError::Forbidden(
            "mirror is not accepted from an automation token: it ships a copy of every request \
             to a second set of backends; set it in the dashboard"
                .to_string(),
        ));
    }
    Ok(())
}

/// A row an environment owns is reachable exactly when the environment
/// is, by the environment resource's own rule: a route delete that
/// would cascade an environment is refused where the environment's
/// delete would be. A mark whose environment row is gone owns nothing
/// and refuses nothing; the hostname or address rule still applies.
fn ensure_environment_granted(
    store: &ConfigStore,
    principal: &AutomationPrincipal,
    environment: &str,
    kind: &str,
    id: &str,
) -> Result<(), ApiError> {
    let Some(owned) = store.get_automation_environment(environment)? else {
        return Ok(());
    };
    if caller_may_access(&owned, &principal.as_owner()) {
        return Ok(());
    }
    Err(ApiError::Forbidden(format!(
        "{kind} `{id}` belongs to an environment this token does not own"
    )))
}

/// The rule a stored route is held to before a token may act on it:
/// its hostname and every alias inside the hostname grant, one exact
/// host at a time, and, when an environment owns it, an environment
/// the token may reach.
///
/// The refusal names the row by id and nothing else: a token probing
/// ids outside its grant must not read a production hostname off the
/// answer.
fn ensure_route_row_granted(
    store: &ConfigStore,
    principal: &AutomationPrincipal,
    route: &Route,
) -> Result<(), ApiError> {
    let outside = std::iter::once(route.hostname.as_str())
        .chain(route.hostname_aliases.iter().map(String::as_str))
        .map(str::trim)
        .any(|name| name.contains('*') || !principal.allows_hostname(name));
    if outside {
        return Err(ApiError::Forbidden(format!(
            "route `{}` names a host outside this token's allowed_hostnames",
            route.id
        )));
    }
    if let Some(ManagedBy::Automation { environment }) = &route.managed_by {
        ensure_environment_granted(store, principal, environment, "route", &route.id)?;
    }
    Ok(())
}

/// The rule a stored backend is held to before a token may act on it
/// or link it: its address inside the CIDR grant, by the same function
/// a claimed address goes through, and, when an environment owns it,
/// an environment the token may reach.
///
/// A stored name, which no CIDR can weigh, is outside the grant as a
/// claimed one would be. The refusal names the id and never the
/// address.
fn ensure_backend_row_granted(
    store: &ConfigStore,
    principal: &AutomationPrincipal,
    backend: &Backend,
) -> Result<(), ApiError> {
    if ensure_backend_address_granted(principal, "address", &backend.address).is_err() {
        return Err(ApiError::Forbidden(format!(
            "backend `{}` points outside this token's allowed_backend_cidrs",
            backend.id
        )));
    }
    if let Some(ManagedBy::Automation { environment }) = &backend.managed_by {
        ensure_environment_granted(store, principal, environment, "backend", &backend.id)?;
    }
    Ok(())
}

/// Every backend id a route row names below the top level: path
/// rules, header rules, traffic splits and the mirror.
fn backend_ids_named(route: &Route) -> BTreeSet<String> {
    route
        .path_rules
        .iter()
        .flat_map(|rule| rule.backend_ids.iter().flatten())
        .chain(
            route
                .header_rules
                .iter()
                .flat_map(|rule| rule.backend_ids.iter()),
        )
        .chain(
            route
                .traffic_splits
                .iter()
                .flat_map(|split| split.backend_ids.iter()),
        )
        .chain(
            route
                .mirror
                .iter()
                .flat_map(|mirror| mirror.backend_ids.iter()),
        )
        .map(|id| id.trim().to_string())
        .collect()
}

/// The backends a route write links that the route did not carry, each
/// resolved to its row and held to [`ensure_backend_row_granted`].
///
/// A backend the route already carries is not re-weighed: the grant
/// bounds what a write reaches anew, and a patch that leaves the links
/// alone reaches nothing. An id naming no row reaches nothing either;
/// the store refuses it on apply, as it always has.
fn ensure_new_links_granted(
    store: &ConfigStore,
    principal: &AutomationPrincipal,
    target: RouteTarget<'_>,
) -> Result<(), ApiError> {
    let mut named = target.after.map(backend_ids_named).unwrap_or_default();
    if let Some(ids) = target.backend_ids {
        named.extend(ids.iter().map(|id| id.trim().to_string()));
    }
    let mut carried = target.before.map(backend_ids_named).unwrap_or_default();
    if let (Some(before), Some(_)) = (target.before, target.backend_ids) {
        carried.extend(store.list_backends_for_route(&before.id)?);
    }
    for id in named.difference(&carried) {
        if let Some(backend) = store.get_backend(id)? {
            ensure_backend_row_granted(store, principal, &backend)?;
        }
    }
    Ok(())
}

/// The token's grant as the guard a route write runs inside its store
/// closure: the row as stored, the row as it would be, and the
/// backends linked anew.
fn route_guard(principal: &AutomationPrincipal) -> RouteGuard {
    let principal = principal.clone();
    RouteGuard::bounded(move |store, target| {
        if let Some(before) = target.before {
            ensure_route_row_granted(store, &principal, before)?;
        }
        if let Some(after) = target.after {
            ensure_hostnames_granted(
                &principal,
                Some(&after.hostname),
                Some(&after.hostname_aliases),
            )?;
        }
        ensure_new_links_granted(store, &principal, target)
    })
}

/// The token's grant as the guard a backend write runs inside its
/// store closure, on the row as stored and on the row as it would be.
fn backend_guard(principal: &AutomationPrincipal) -> BackendGuard {
    let principal = principal.clone();
    BackendGuard::bounded(move |store, backend| {
        ensure_backend_row_granted(store, &principal, backend)
    })
}

/// The token's grant as the guard a renewal runs on the certificate
/// it names: every name the certificate carries, `domain` and each
/// SAN, inside the hostname grant. A wildcard name is weighed as the
/// grant spells it, so a wildcard certificate covering exactly the
/// grant's own namespace is renewable and one covering a wider or a
/// different one is not.
fn certificate_guard(principal: &AutomationPrincipal) -> CertificateGuard {
    let principal = principal.clone();
    CertificateGuard::bounded(move |certificate| {
        let outside = std::iter::once(certificate.domain.as_str())
            .chain(certificate.san_domains.iter().map(String::as_str))
            .map(str::trim)
            .any(|name| !principal.allows_hostname(name));
        if outside {
            return Err(ApiError::Forbidden(format!(
                "certificate `{}` covers a name outside this token's allowed_hostnames",
                certificate.id
            )));
        }
        Ok(())
    })
}

/// `POST /automation/v1/routes` (scope `routes:write`).
///
/// The management route create, as the token: same body, same
/// validators, same defaults, same 201 and the same `route.create`
/// audit row, naming the token. The hostname and every alias must be
/// inside the token's `allowed_hostnames` (403), every backend the body
/// links must sit inside its `allowed_backend_cidrs` and belong to no
/// other principal's environment (403), and `forward_auth` and `mirror`
/// are refused (403). With `?dry_run=true`, the route it would have
/// created, and nothing created.
///
/// # Errors
///
/// `Forbidden` for a name, a link or a field outside the grant, then
/// whatever [`crate::routes::crud::create_route_as`] answers.
pub async fn create_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    refuse_unbounded_reach(body.forward_auth.is_some(), body.mirror.is_some())?;
    ensure_hostnames_granted(
        &principal,
        Some(&body.hostname),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::create_route_as(
        &state,
        &actor,
        body,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await
}

/// `PUT /automation/v1/routes/{id}` (scope `routes:write`).
///
/// The management route update, as the token: a patch of the fields
/// sent and nothing else, the managed-row refusal (409) included. The
/// route named must be inside the token's `allowed_hostnames` on its
/// current hostname and every current alias, and reachable through the
/// environment resource's rule when an environment owns it (403); a
/// hostname or an alias the patch names must be inside the grant too,
/// every backend the patch links anew must sit inside
/// `allowed_backend_cidrs` and belong to no other principal's
/// environment, and `forward_auth` and `mirror` are refused (403 each).
/// With `?dry_run=true`, the route before and after the patch, and
/// nothing changed.
///
/// # Errors
///
/// `Forbidden` for a target, a name, a link or a field outside the
/// grant, then whatever [`crate::routes::crud::update_route_as`]
/// answers.
pub async fn update_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<UpdateRouteRequest>,
) -> Result<Json<Value>, ApiError> {
    refuse_unbounded_reach(body.forward_auth.is_some(), body.mirror.is_some())?;
    ensure_hostnames_granted(
        &principal,
        body.hostname.as_deref(),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::update_route_as(
        &state,
        &actor,
        id,
        body,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await
}

/// `DELETE /automation/v1/routes/{id}` (scope `routes:write`).
///
/// The management route delete, as the token. The route named must be
/// inside the token's `allowed_hostnames` on its current hostname and
/// every current alias (403). A managed route is deletable there and
/// therefore here, and takes its environment with it, so it is
/// reachable exactly when the environment resource would let this token
/// reach that environment (403 otherwise); the audit row names the
/// environment. With `?dry_run=true`, the route that would go, and
/// nothing deleted.
///
/// # Errors
///
/// `Forbidden` for a target outside the grant, then whatever
/// [`crate::routes::crud::delete_route_as`] answers.
pub async fn delete_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::delete_route_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await
}

/// `PUT /automation/v1/routes/{id}/certificate` (scope
/// `certificates:write`).
///
/// Binds a stored certificate to a route, as the one-field patch
/// `PUT /api/v1/routes/{id}` would make, through the same function:
/// the managed-row refusal (409) holds, and the empty string unbinds.
/// The route named must be inside the token's `allowed_hostnames` on
/// its current hostname and every current alias (403). Selecting a
/// certificate is naming its id here; what the id names entered the
/// node through the management API. With `?dry_run=true`, the route
/// before and after the binding, and nothing bound.
///
/// # Errors
///
/// `Forbidden` for a target outside the grant, then whatever
/// [`crate::routes::crud::update_route_as`] answers.
pub async fn bind_certificate(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<BindCertificateRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    let patch = UpdateRouteRequest {
        certificate_id: Some(body.certificate_id),
        ..UpdateRouteRequest::default()
    };
    crate::routes::crud::update_route_as(
        &state,
        &actor,
        id,
        patch,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await
}

/// `POST /automation/v1/backends` (scope `backends:write`).
///
/// The management backend create, as the token. The address must be an
/// `ip:port` (422, since a name cannot be checked against a CIDR
/// grant) inside the token's `allowed_backend_cidrs` (403), the same
/// rule the environment resource applies to its backends. With
/// `?dry_run=true`, the backend it would have created, and nothing
/// created.
///
/// # Errors
///
/// The grant's refusal, then whatever
/// [`crate::backends::create_backend_as`] answers.
pub async fn create_backend(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<CreateBackendRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    ensure_backend_address_granted(&principal, "address", &body.address)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::backends::create_backend_as(&state, &actor, body, WriteMode::from(dry_run)).await
}

/// `PUT /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend update, as the token, the managed-row
/// refusal (409) included. The backend named must sit inside the
/// token's `allowed_backend_cidrs` on its stored address and belong to
/// no other principal's environment (403); an address the patch names
/// is checked against the grant exactly as on create. With
/// `?dry_run=true`, the backend before and after the patch, and
/// nothing changed.
///
/// # Errors
///
/// The grant's refusal, on the target or on the patch, then whatever
/// [`crate::backends::update_backend_as`] answers.
pub async fn update_backend(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<UpdateBackendRequest>,
) -> Result<Json<Value>, ApiError> {
    if let Some(address) = body.address.as_deref() {
        ensure_backend_address_granted(&principal, "address", address)?;
    }
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::backends::update_backend_as(
        &state,
        &actor,
        id,
        body,
        WriteMode::from(dry_run),
        backend_guard(&principal),
    )
    .await
}

/// `DELETE /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend delete, as the token: the graceful drain,
/// and the refusal of a backend an environment owns (409). The backend
/// named must sit inside the token's `allowed_backend_cidrs` on its
/// stored address and belong to no other principal's environment
/// (403). With `?dry_run=true`, the backend marked closing as the
/// drain would leave it, or the row that would go at once when it is
/// already closing, and no drain started.
///
/// # Errors
///
/// The grant's refusal on the target, then whatever
/// [`crate::backends::delete_backend_as`] answers.
pub async fn delete_backend(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::backends::delete_backend_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        backend_guard(&principal),
    )
    .await
}

/// `POST /automation/v1/certificates/{id}/renew` (scope
/// `certificates:write`).
///
/// The management renewal, as the token: an ACME order for a row the
/// node already holds, in place under the same id. Every name the
/// certificate carries, `domain` and each SAN, must be inside the
/// token's `allowed_hostnames` (403), checked before anything about
/// the row is said. A certificate that was uploaded rather than issued
/// is refused (400) exactly as on the management plane, since there is
/// nothing to renew it against, and no path here takes the replacement.
/// With `?dry_run=true`, the certificate that would be renewed, and no
/// order made.
///
/// # Errors
///
/// The grant's refusal on the target, then whatever
/// [`crate::acme::renew_certificate_as`] answers.
pub async fn renew_certificate(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::acme::renew_certificate_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        certificate_guard(&principal),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{AutomationScope, OwnerKind};

    /// A principal granted `*.review.example.com` and `10.0.0.0/8`.
    fn principal() -> AutomationPrincipal {
        AutomationPrincipal {
            kind: OwnerKind::StaticToken,
            principal: "config-tier".to_string(),
            grant_id: "0123456789abcdef01234567".to_string(),
            scopes: vec![AutomationScope::RoutesWrite],
            allowed_hostnames: vec!["*.review.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            pipeline: None,
            required_environment_slug: None,
        }
    }

    #[test]
    fn every_name_a_route_write_claims_is_checked_against_the_grant() {
        let granted = principal();
        ensure_hostnames_granted(&granted, Some("pr-42.review.example.com"), None)
            .expect("inside the grant");
        ensure_hostnames_granted(
            &granted,
            Some("pr-42.review.example.com"),
            Some(&["pr-42-api.review.example.com".to_string()]),
        )
        .expect("every alias inside the grant");
        // A patch that names no host claims nothing here; the route it
        // names is held to the grant by the guard, inside the store
        // closure, which the whole-stack tests in `crate::tests` drive.
        ensure_hostnames_granted(&granted, None, None).expect("nothing claimed");

        for (hostname, aliases) in [
            ("www.example.com", Vec::new()),
            ("review.example.com", Vec::new()),
            ("a.b.review.example.com", Vec::new()),
            (
                "pr-42.review.example.com",
                vec!["www.example.com".to_string()],
            ),
        ] {
            let refused = ensure_hostnames_granted(&granted, Some(hostname), Some(&aliases))
                .expect_err("outside the grant");
            assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
        }
    }

    #[test]
    fn a_wildcard_is_refused_even_under_a_wildcard_grant() {
        // `*.review.example.com` against the grant `*.review.example.com`
        // would match label for label and hand the token every host
        // under the parent in one row.
        let granted = principal();
        let refused = ensure_hostnames_granted(&granted, Some("*.review.example.com"), None)
            .expect_err("a wildcard is not one host");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
        let refused = ensure_hostnames_granted(
            &granted,
            Some("pr-42.review.example.com"),
            Some(&["*.review.example.com".to_string()]),
        )
        .expect_err("a wildcard alias is not one host either");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
    }

    #[test]
    fn a_certificate_is_renewable_when_every_name_it_carries_is_inside_the_grant() {
        // A wildcard certificate covering exactly the grant's namespace
        // is the review-app case and is renewable; any name outside,
        // the domain or one SAN, refuses the whole renewal, and the
        // refusal names the id and not the name.
        let guard = certificate_guard(&principal());
        let certificate = |domain: &str, sans: &[&str]| lorica_config::models::Certificate {
            id: "c-1".to_string(),
            domain: domain.to_string(),
            san_domains: sans.iter().map(|s| (*s).to_string()).collect(),
            fingerprint: String::new(),
            cert_pem: String::new(),
            key_pem: String::new(),
            issuer: String::new(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now(),
            is_acme: true,
            acme_auto_renew: true,
            created_at: chrono::Utc::now(),
            acme_method: None,
            acme_dns_provider_id: None,
        };
        guard
            .check(&certificate("*.review.example.com", &[]))
            .expect("the grant's own namespace");
        guard
            .check(&certificate(
                "pr-42.review.example.com",
                &["pr-42-api.review.example.com"],
            ))
            .expect("every name inside");
        for (domain, sans) in [
            ("www.example.com", &[][..]),
            ("*.example.com", &[]),
            ("pr-42.review.example.com", &["www.example.com"]),
        ] {
            let refused = guard
                .check(&certificate(domain, sans))
                .expect_err("a name outside the grant");
            match refused {
                ApiError::Forbidden(message) => {
                    assert!(message.contains("c-1"), "{message}");
                    assert!(!message.contains("example.com"), "{message}");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn forward_auth_and_mirror_are_refused_from_a_token_whatever_the_value() {
        refuse_unbounded_reach(false, false).expect("neither field");
        for (forward_auth, mirror, field) in [
            (true, false, "forward_auth"),
            (false, true, "mirror"),
            (true, true, "forward_auth"),
        ] {
            match refuse_unbounded_reach(forward_auth, mirror).expect_err(field) {
                ApiError::Forbidden(message) => assert!(message.starts_with(field), "{message}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_bind_body_carries_the_id_and_nothing_else() {
        let bound: BindCertificateRequest =
            serde_json::from_str(r#"{"certificate_id": "c-1"}"#).expect("the one field");
        assert_eq!(bound.certificate_id, "c-1");
        for body in [
            r#"{"certificate_id": "c-1", "key_pem": "-----BEGIN PRIVATE KEY-----"}"#,
            r#"{"certificate_id": "c-1", "cert_pem": "-----BEGIN CERTIFICATE-----"}"#,
            r#"{"certificate": "c-1"}"#,
            r#"{}"#,
        ] {
            assert!(
                serde_json::from_str::<BindCertificateRequest>(body).is_err(),
                "{body} was accepted"
            );
        }
    }
}
