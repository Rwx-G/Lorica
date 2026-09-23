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
//! What this module adds is the token's own grant, which is
//! authorization and not validation. Every hostname a route write
//! claims must be inside the token's `allowed_hostnames`, and every
//! address a backend write points at must be an `ip:port` inside its
//! `allowed_backend_cidrs`; both are refused with 403 before the
//! handler runs and before anything is written. They are the same two
//! grants the environment resource applies, through the same
//! functions, so a token minted for one shape of write is bounded the
//! same way on the other.
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
//! and that body runs its validators, builds the row it would store and
//! stops before the store, the reload signal and the audit row. The
//! grant checks run first either way, since an apply the grant refuses
//! is a change the preview must not show as possible. A preview sits
//! behind the write's own scope by construction, because the matrix
//! reads the path and not the query, and its request row records
//! `?dry_run` beside the verb.
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

use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::Value;

use super::auth::AutomationPrincipal;
use super::environments::{audit_context, ensure_backend_address_granted};
use crate::audit::ClientConnectInfo;
use crate::backends::{CreateBackendRequest, UpdateBackendRequest};
use crate::error::ApiError;
use crate::preview::{DryRunQuery, WriteMode};
use crate::routes::{CreateRouteRequest, UpdateRouteRequest};
use crate::server::AppState;

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

/// `POST /automation/v1/routes` (scope `routes:write`).
///
/// The management route create, as the token: same body, same
/// validators, same defaults, same 201 and the same `route.create`
/// audit row, naming the token. The hostname and every alias must be
/// inside the token's `allowed_hostnames` (403). With `?dry_run=true`,
/// the route it would have created, and nothing created.
///
/// # Errors
///
/// `Forbidden` for a name outside the grant, then whatever
/// [`crate::routes::crud::create_route_as`] answers.
pub async fn create_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    ensure_hostnames_granted(
        &principal,
        Some(&body.hostname),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::create_route_as(&state, &actor, body, WriteMode::from(dry_run)).await
}

/// `PUT /automation/v1/routes/{id}` (scope `routes:write`).
///
/// The management route update, as the token: a patch of the fields
/// sent and nothing else, the managed-row refusal (409) included. A
/// hostname or an alias the patch names must be inside the token's
/// `allowed_hostnames` (403). With `?dry_run=true`, the route before
/// and after the patch, and nothing changed.
///
/// # Errors
///
/// `Forbidden` for a name outside the grant, then whatever
/// [`crate::routes::crud::update_route_as`] answers.
pub async fn update_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<UpdateRouteRequest>,
) -> Result<Json<Value>, ApiError> {
    ensure_hostnames_granted(
        &principal,
        body.hostname.as_deref(),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::update_route_as(&state, &actor, id, body, WriteMode::from(dry_run)).await
}

/// `DELETE /automation/v1/routes/{id}` (scope `routes:write`).
///
/// The management route delete, as the token. A managed route is
/// deletable there and therefore here, and takes its environment with
/// it; the audit row names the environment. With `?dry_run=true`, the
/// route that would go, and nothing deleted.
///
/// # Errors
///
/// Whatever [`crate::routes::crud::delete_route_as`] answers.
pub async fn delete_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::routes::crud::delete_route_as(&state, &actor, id, WriteMode::from(dry_run)).await
}

/// `PUT /automation/v1/routes/{id}/certificate` (scope
/// `certificates:write`).
///
/// Binds a stored certificate to a route, as the one-field patch
/// `PUT /api/v1/routes/{id}` would make, through the same function:
/// the managed-row refusal (409) holds, and the empty string unbinds.
/// Selecting a certificate is naming its id here; what the id names
/// entered the node through the management API. With `?dry_run=true`,
/// the route before and after the binding, and nothing bound.
///
/// # Errors
///
/// Whatever [`crate::routes::crud::update_route_as`] answers.
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
    crate::routes::crud::update_route_as(&state, &actor, id, patch, WriteMode::from(dry_run)).await
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
/// refusal (409) included. An address the patch names is checked
/// against the grant exactly as on create. With `?dry_run=true`, the
/// backend before and after the patch, and nothing changed.
///
/// # Errors
///
/// The grant's refusal, then whatever
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
    crate::backends::update_backend_as(&state, &actor, id, body, WriteMode::from(dry_run)).await
}

/// `DELETE /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend delete, as the token: the graceful drain,
/// and the refusal of a backend an environment owns (409). With
/// `?dry_run=true`, the backend that would drain, and no drain
/// started.
///
/// # Errors
///
/// Whatever [`crate::backends::delete_backend_as`] answers.
pub async fn delete_backend(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::backends::delete_backend_as(&state, &actor, id, WriteMode::from(dry_run)).await
}

/// `POST /automation/v1/certificates/{id}/renew` (scope
/// `certificates:write`).
///
/// The management renewal, as the token: an ACME order for a row the
/// node already holds, in place under the same id. A certificate that
/// was uploaded rather than issued is refused (400) exactly as on the
/// management plane, since there is nothing to renew it against, and
/// no path here takes the replacement. With `?dry_run=true`, the
/// certificate that would be renewed, and no order made.
///
/// # Errors
///
/// Whatever [`crate::acme::renew_certificate_as`] answers.
pub async fn renew_certificate(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::acme::renew_certificate_as(&state, &actor, id, WriteMode::from(dry_run)).await
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
        // A patch that names no host claims nothing.
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
