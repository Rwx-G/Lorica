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

//! The environment resource (Story 10.4): one idempotent call that
//! makes `https://<slug>.review.example.com` reach a container.
//!
//! # One transaction
//!
//! A `PUT` touches four tables: the route, its backends, the joins and
//! the `automation_environments` row. Every write happens inside
//! [`lorica_config::ConfigStore::in_transaction`], on the one store
//! lock `db_blocking` holds, so a failure anywhere in the middle
//! leaves nothing. The validation and the certificate resolution run
//! BEFORE the first write on purpose: the transaction is the safety
//! net for a database error, not the mechanism by which a refusal is
//! expressed.
//!
//! # Concurrency
//!
//! Two pipelines racing on one `name` serialise on the store mutex:
//! `db_blocking` takes it for the whole closure, and the closure is
//! the whole transaction, so the later `PUT` sees the earlier one's
//! rows and wins in full. That mutex is the row-level serialisation
//! AC #9 asks for; there is no finer lock and none is needed while
//! the store is a single connection. `If-Match` is the opt-in for a
//! pipeline that would rather get a 412 than silently win.
//!
//! # The listener-host rule
//!
//! AC #3 refuses a hostname that names the management or the
//! automation listener. The management listener is loopback by
//! construction and the automation listener binds an IP address, so
//! the names a route hostname could collide with are `localhost` and
//! an address literal; both are refused outright rather than compared
//! against a bind that is not part of `AppState`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, TimeDelta, Utc};
use lorica_config::models::{
    matches_one_label, may_access, resolve_certificate_for_hostname, validate_environment_name,
    wildcard_patterns_an_operator_could_provision, AutomationEnvironment, AutomationScope, Backend,
    Certificate, CertificateMode, EnvironmentOwner, HealthStatus, LifecycleState, LoadBalancing,
    ManagedBy, PipelineIdentity, Route, WafMode, AUTOMATION_MAX_BACKENDS_PER_ENVIRONMENT,
    AUTOMATION_MAX_ENVIRONMENTS_PER_PRINCIPAL,
};
use lorica_config::{ConfigError, ConfigStore, ConnectionFilterPolicy};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::auth::AutomationPrincipal;
use crate::audit::{AuditContext, ClientConnectInfo};
use crate::cluster::ClusterRuntime;
use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::log_store::LogStore;
use crate::server::AppState;

/// `target_type` of every environment audit row.
pub const ENVIRONMENT_TARGET_TYPE: &str = "automation_environment";

/// Audit action the reaper records for each environment it collects.
pub const ENVIRONMENT_EXPIRED_ACTION: &str = "automation.environment.expired";

/// The machine-readable token at the head of the 422 message when no
/// certificate covers the hostname. The error envelope carries one
/// `code` per status, so the specific reason rides the message where a
/// pipeline can still match it.
pub const NO_CERTIFICATE_COVERS_HOSTNAME: &str = "no_certificate_covers_hostname";

/// Where an operator provisions the missing wildcard.
const DNS01_PROVISIONING_ENDPOINT: &str = "POST /api/v1/acme/provision-dns";

/// Default backend weight when the request leaves it out.
const DEFAULT_BACKEND_WEIGHT: i32 = 1;

/// Highest backend weight an environment may ask for.
///
/// The route model stores a bare `i32` and caps nothing, so a caller
/// could write `2_147_483_647` beside a weight of 1 and turn a
/// round-robin pool into a single upstream while the response still
/// reports two backends. A thousand to one is more spread than any
/// real pool needs and keeps every weight sum inside an `i32`.
const AUTOMATION_MAX_BACKEND_WEIGHT: i32 = 1_000;

/// Health-check cadence for automation backends, the same default the
/// backend API applies.
const DEFAULT_HEALTH_CHECK_INTERVAL_S: i32 = 10;

/// The `error.code` of a 412, which [`ApiError`] has no variant for.
const PRECONDITION_FAILED_CODE: &str = "precondition_failed";

/// JSON body for `PUT /automation/v1/environments/{name}`.
///
/// `deny_unknown_fields`: anything this slice does not know is 422, so
/// a pipeline that sends a field from a later version learns so on the
/// first call rather than watching it be ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRequest {
    /// The exact hostname the environment answers on. No wildcard.
    pub hostname: String,
    /// The upstreams, at least one, every address an `ip:port` inside
    /// the token's `allowed_backend_cidrs`.
    pub backends: Vec<EnvironmentBackendRequest>,
    /// `"auto"` to bind the certificate covering the hostname, or an
    /// explicit certificate id (needs `certificates:read`).
    pub certificate: String,
    /// Whether the WAF inspects this route. Default off.
    #[serde(default)]
    pub waf_enabled: bool,
    /// Whether plain HTTP redirects to HTTPS. Default off.
    #[serde(default)]
    pub force_https: bool,
    /// The route's path prefix. Default `/`.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// How long the environment lives, at or under the token's
    /// `max_ttl_seconds`. Recomputed from now on every `PUT`.
    pub ttl_seconds: u32,
    /// Free-form labels; `shared: "true"` opens the environment to
    /// every principal.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// One upstream of an environment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentBackendRequest {
    /// `ip:port`. A name is refused: it cannot be checked against the
    /// token's CIDR grant.
    pub address: String,
    /// Whether the upstream speaks TLS.
    #[serde(default)]
    pub tls_upstream: bool,
    /// SNI to present to a TLS upstream; the route hostname otherwise.
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// Load-balancing weight, at least 1. Default 1.
    #[serde(default)]
    pub weight: Option<i32>,
}

/// Payload of a successful `PUT`.
#[derive(Debug, Serialize)]
pub struct EnvironmentWriteResponse {
    /// The environment name.
    pub name: String,
    /// `https://<hostname><path_prefix>`.
    pub url: String,
    /// The route the environment owns; stable across updates.
    pub route_id: String,
    /// The backend rows this `PUT` wrote, in request order.
    pub backend_ids: Vec<String>,
    /// The certificate bound to the route by this `PUT`.
    pub certificate_id: String,
    /// RFC 3339 expiry of that certificate.
    pub certificate_not_after: String,
    /// RFC 3339 instant the reaper may collect the environment.
    pub expires_at: String,
    /// The fleet configuration generation the control plane had
    /// PUBLISHED when this response was built; 0 on a standalone node,
    /// which has no fleet to wait for.
    ///
    /// The write starts a replication round that publishes the next
    /// generation once every node has prepared it, so a strict
    /// pipeline polls `GET /api/v1/cluster/status` until
    /// `applied_config_generation` EXCEEDS this value. It is the
    /// generation and never the hash: since Story 10.0 two converged
    /// nodes legitimately report two different hashes, and a poll on
    /// hash agreement would wait forever.
    pub applied_generation: u64,
}

/// One environment as `GET` reports it.
#[derive(Debug, Serialize)]
pub struct EnvironmentView {
    /// The environment name.
    pub name: String,
    /// The route's hostname.
    pub hostname: String,
    /// The route's path prefix.
    pub path_prefix: String,
    /// `https://<hostname><path_prefix>`.
    pub url: String,
    /// The route the environment owns.
    pub route_id: String,
    /// The backends linked to that route.
    pub backend_ids: Vec<String>,
    /// The certificate currently bound to the route.
    pub certificate_id: Option<String>,
    /// How that certificate is chosen.
    pub certificate_mode: CertificateMode,
    /// The labels the last `PUT` set.
    pub labels: BTreeMap<String, String>,
    /// Who created the environment.
    pub owner: EnvironmentOwner,
    /// RFC 3339 instant the reaper may collect the environment.
    pub expires_at: String,
    /// RFC 3339 creation instant.
    pub created_at: String,
    /// RFC 3339 instant of the last `PUT`; the source of the `ETag`.
    pub updated_at: String,
    /// The pipeline identifier of the last `PUT`, when one was given.
    pub last_pipeline: Option<String>,
    /// The CI job behind the last `PUT`, when it authenticated with a
    /// GitLab ID token (Story 10.5 AC #3); absent for a static token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<PipelineIdentity>,
}

/// Query string of `GET /automation/v1/environments`.
#[derive(Debug, Default, Deserialize)]
pub struct ListEnvironmentsQuery {
    /// `key:value`; only environments carrying exactly that label.
    #[serde(default)]
    pub label: Option<String>,
    /// Only the environment on this hostname.
    #[serde(default)]
    pub hostname: Option<String>,
    /// RFC 3339; only environments expiring strictly before it.
    #[serde(default)]
    pub expiring_before: Option<String>,
}

/// One backend after validation: the parsed address beside the raw one.
#[derive(Debug, Clone)]
struct ValidatedBackend {
    address: String,
    tls_upstream: bool,
    tls_sni: Option<String>,
    weight: i32,
}

/// Everything the transaction needs, resolved from the request and the
/// credential before the store lock is taken.
#[derive(Debug)]
struct WriteInput {
    name: String,
    hostname: String,
    path_prefix: String,
    backends: Vec<ValidatedBackend>,
    certificate_mode: CertificateMode,
    waf_enabled: bool,
    force_https: bool,
    labels: BTreeMap<String, String>,
    owner: EnvironmentOwner,
    pipeline: Option<PipelineIdentity>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    if_match: Option<String>,
}

/// What the transaction wrote.
#[derive(Debug)]
struct Written {
    created: bool,
    route: Route,
    backend_ids: Vec<String>,
    certificate_id: String,
    certificate_not_after: DateTime<Utc>,
    environment: AutomationEnvironment,
}

/// How a `PUT` transaction ended, short of an error.
#[derive(Debug)]
enum PutOutcome {
    Written(Box<Written>),
    /// `If-Match` named a version the row is not at. `current` is the
    /// live `ETag`, or `None` when the environment does not exist.
    StaleIfMatch {
        current: Option<String>,
    },
    /// The name is taken by another principal's environment.
    Foreign,
}

/// A lookup that produced nothing the caller may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    /// No row carries that name.
    Unknown,
    /// A row carries it and another principal owns it.
    ///
    /// The wire answer is the one [`Missing::Unknown`] gets, so a
    /// caller cannot walk the name space to learn which environments
    /// its neighbours run; the distinction reaches the audit row and
    /// nothing else.
    Foreign,
}

/// The one 404 an environment lookup answers, whether the name is
/// unknown or owned by another principal.
fn not_found(name: &str) -> ApiError {
    ApiError::NotFound(format!("environment {name}"))
}

/// The rows a delete removed, for the audit payload.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedEnvironment {
    /// The environment name.
    pub name: String,
    /// The route that was removed.
    pub route_id: String,
    /// The backends that were removed with it.
    pub backend_ids: Vec<String>,
}

// ---- Validation, pure ----

/// The RFC 1123 rule every name field on this resource reads, with
/// the field named so the caller knows which one it is about.
///
/// Same shape as the route API's own hostname check: a bare name, no
/// scheme, path, port, wildcard or address literal, 253 characters at
/// most, every label 1 to 63 ASCII alphanumerics and inner hyphens.
/// Returns the name lowercased with a trailing dot folded away, which
/// is the form the rows store and compare.
fn validate_dns_name(raw: &str, field: &str) -> Result<String, ApiError> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let refuse = |why: &str| ApiError::Unprocessable(format!("{field} {why}"));
    if name.is_empty() {
        return Err(refuse("must not be empty"));
    }
    if name.contains('*') {
        return Err(refuse("cannot be a wildcard: it names one exact host"));
    }
    if name.contains("://") || name.contains('/') {
        return Err(refuse(
            "must be a bare hostname, without a scheme or a path",
        ));
    }
    if name.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#' | ':' | '@' | '[')) {
        return Err(refuse(
            "contains a character that is not valid in a hostname (whitespace, `?`, `#`, `:`, \
             `@`, `[`)",
        ));
    }
    if name.parse::<IpAddr>().is_ok() {
        return Err(refuse("must be a DNS name, not an address literal"));
    }
    if name.len() > 253 {
        return Err(refuse("is longer than 253 characters (DNS limit)"));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(refuse("contains an empty DNS label (consecutive dots)"));
        }
        if label.len() > 63 {
            return Err(refuse("contains a DNS label longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(refuse("contains a DNS label that starts or ends with `-`"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(refuse(
                "may only contain ASCII letters, digits, `-` and `.`",
            ));
        }
    }
    Ok(name)
}

/// Check the hostname the way AC #3 reads it: an exact DNS name,
/// lowercase, that names neither listener.
fn validate_environment_hostname(raw: &str) -> Result<String, ApiError> {
    let name = validate_dns_name(raw, "hostname")?;
    // The listener rule, which applies to the name a route answers on
    // and to nothing else: an address literal names a listener rather
    // than a site, and `localhost` is the management listener's host.
    if name == "localhost" || name.ends_with(".localhost") {
        return Err(ApiError::Unprocessable(
            "hostname cannot be `localhost`: that is the management listener's host".to_string(),
        ));
    }
    Ok(name)
}

/// `/` when absent; otherwise an absolute path with nothing a URL
/// would read as a query, a fragment or a parent step.
fn validate_path_prefix(raw: Option<&str>) -> Result<String, ApiError> {
    let value = raw.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Ok("/".to_string());
    }
    if !value.starts_with('/') {
        return Err(ApiError::Unprocessable(
            "path_prefix must start with `/`".to_string(),
        ));
    }
    if value.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#')) || value.contains("..")
    {
        return Err(ApiError::Unprocessable(
            "path_prefix may not contain whitespace, `?`, `#` or `..`".to_string(),
        ));
    }
    Ok(value.to_string())
}

/// Parse and grant-check every backend against the credential.
///
/// The address has to be an `ip:port`: the grant is a CIDR list, and a
/// name cannot be checked against one without a resolution the token
/// holder would control. Outside the grant is 403, the same answer the
/// scope gate gives: the token is real and the grant is not there.
///
/// # An empty grant is deny-all here
///
/// [`ConnectionFilterPolicy`] reads an empty allow list as
/// default-allow, which is right for a filter an operator opts into
/// and wrong for a grant a credential carries: it would make a
/// credential minted without the field the widest one on the node,
/// able to aim a public hostname at `127.0.0.1` or at a cloud
/// metadata address. The models refuse an empty list at write time;
/// this refuses it again at use time, for the rows written before
/// that rule landed.
fn validate_backends(
    principal: &AutomationPrincipal,
    backends: &[EnvironmentBackendRequest],
) -> Result<Vec<ValidatedBackend>, ApiError> {
    if backends.is_empty() {
        return Err(ApiError::Unprocessable(
            "backends must name at least one upstream".to_string(),
        ));
    }
    if backends.len() > AUTOMATION_MAX_BACKENDS_PER_ENVIRONMENT {
        return Err(ApiError::Unprocessable(format!(
            "backends names {} upstreams; an environment carries at most \
             {AUTOMATION_MAX_BACKENDS_PER_ENVIRONMENT}, because every one of them is a row \
             written inside the single transaction this call holds the store for",
            backends.len()
        )));
    }
    if principal.allowed_backend_cidrs.is_empty() {
        return Err(ApiError::Forbidden(
            "this credential names no allowed_backend_cidrs, so its backend grant covers no \
             address; ask an operator to name the ranges it may reach"
                .to_string(),
        ));
    }
    let policy = ConnectionFilterPolicy::from_cidrs(&principal.allowed_backend_cidrs, &[]);
    let mut out = Vec::with_capacity(backends.len());
    for (index, backend) in backends.iter().enumerate() {
        let field = format!("backends[{index}].address");
        let raw = backend.address.trim();
        let addr: SocketAddr = raw.parse().map_err(|_| {
            ApiError::Unprocessable(format!(
                "{field} `{raw}` must be `ip:port`; a name cannot be checked against \
                 allowed_backend_cidrs"
            ))
        })?;
        if addr.port() == 0 {
            return Err(ApiError::Unprocessable(format!(
                "{field} `{raw}` must carry a non-zero port"
            )));
        }
        if !policy.accepts(addr.ip()) {
            return Err(ApiError::Forbidden(format!(
                "{field} `{raw}` is outside this token's allowed_backend_cidrs"
            )));
        }
        let weight = backend.weight.unwrap_or(DEFAULT_BACKEND_WEIGHT);
        if weight < 1 {
            return Err(ApiError::Unprocessable(format!(
                "backends[{index}].weight must be at least 1"
            )));
        }
        if weight > AUTOMATION_MAX_BACKEND_WEIGHT {
            return Err(ApiError::Unprocessable(format!(
                "backends[{index}].weight `{weight}` exceeds \
                 {AUTOMATION_MAX_BACKEND_WEIGHT}"
            )));
        }
        let tls_sni = match backend
            .tls_sni
            .as_deref()
            .map(str::trim)
            .filter(|sni| !sni.is_empty())
        {
            // The SNI lands on a backend row and is presented on the
            // wire to the upstream, so it goes through the same DNS
            // name rule the route path applies to every other name
            // this API stores.
            Some(sni) => Some(validate_dns_name(
                sni,
                &format!("backends[{index}].tls_sni"),
            )?),
            None => None,
        };
        out.push(ValidatedBackend {
            address: addr.to_string(),
            tls_upstream: backend.tls_upstream,
            tls_sni,
            weight,
        });
    }
    Ok(out)
}

/// `now + ttl`, refused when the lifetime is zero or over the
/// credential's ceiling.
fn resolve_expiry(
    now: DateTime<Utc>,
    ttl_seconds: u32,
    principal: &AutomationPrincipal,
) -> Result<DateTime<Utc>, ApiError> {
    if ttl_seconds == 0 {
        return Err(ApiError::Unprocessable(
            "ttl_seconds must be greater than zero".to_string(),
        ));
    }
    if ttl_seconds > principal.max_ttl_seconds {
        return Err(ApiError::Unprocessable(format!(
            "ttl_seconds `{ttl_seconds}` exceeds this token's max_ttl_seconds `{}`",
            principal.max_ttl_seconds
        )));
    }
    now.checked_add_signed(TimeDelta::seconds(i64::from(ttl_seconds)))
        .ok_or_else(|| {
            ApiError::Unprocessable("ttl_seconds does not land on a representable instant".into())
        })
}

/// `"auto"`, or an explicit id the credential may name.
fn parse_certificate_mode(
    raw: &str,
    principal: &AutomationPrincipal,
) -> Result<CertificateMode, ApiError> {
    let value = raw.trim();
    if value.eq_ignore_ascii_case("auto") {
        return Ok(CertificateMode::Auto);
    }
    if value.is_empty() {
        return Err(ApiError::Unprocessable(
            "certificate must be `auto` or a certificate id".to_string(),
        ));
    }
    if !principal.has_scope(AutomationScope::CertificatesRead) {
        return Err(ApiError::Forbidden(
            "certificate: naming an explicit certificate id needs the certificates:read scope; \
             use `auto` to let Lorica pick one"
                .to_string(),
        ));
    }
    Ok(CertificateMode::Explicit(value.to_string()))
}

/// The AC #6 ownership rule.
///
/// `caller` is the principal as an owner: a static token's name, or
/// an ID token's `project_path` (Story 10.5 AC #3), each in its own
/// kind, so the two never match each other. An environment is reached
/// by its exact owner, or by anybody when its owner labelled it
/// `shared = "true"`.
fn caller_may_access(environment: &AutomationEnvironment, caller: &EnvironmentOwner) -> bool {
    may_access(
        &environment.owner,
        &caller.principal,
        caller.kind,
        &environment.labels,
    )
}

/// AC #3: a credential bound to `environment_protected = true` may only
/// write the environment its job runs for, named by the GitLab slug of
/// the job's `environment` claim.
fn ensure_environment_binding(name: &str, principal: &AutomationPrincipal) -> Result<(), ApiError> {
    let Some(slug) = principal.required_environment_slug.as_deref() else {
        return Ok(());
    };
    if slug.is_empty() {
        return Err(ApiError::Forbidden(
            "name: this credential is bound to environment_protected=true but the token \
             carries no environment claim"
                .to_string(),
        ));
    }
    if name != slug {
        return Err(ApiError::Forbidden(format!(
            "name `{name}` must equal the job's environment slug `{slug}`: this credential is \
             bound to environment_protected=true"
        )));
    }
    Ok(())
}

/// The `ETag` of an environment: its `updated_at`, quoted. Every `PUT`
/// moves `updated_at`, so the tag changes exactly when the row does.
fn etag_for(environment: &AutomationEnvironment) -> String {
    format!("\"{}\"", environment.updated_at.to_rfc3339())
}

/// Whether an `If-Match` header accepts the current tag (RFC 7232
/// section 3.1). A weak tag compares by value; `*` matches any
/// existing row and no missing one.
fn if_match_holds(if_match: Option<&str>, current: Option<&str>) -> bool {
    let Some(header) = if_match else {
        return true;
    };
    let Some(current) = current else {
        return false;
    };
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == current
    })
}

/// A 412 in the same envelope every other refusal uses.
fn precondition_failed(current: Option<&str>) -> Response {
    let message = match current {
        Some(tag) => format!("If-Match does not match the current ETag {tag}"),
        None => "If-Match was sent but the environment does not exist".to_string(),
    };
    let body = serde_json::json!({
        "error": { "code": PRECONDITION_FAILED_CODE, "message": message }
    });
    (StatusCode::PRECONDITION_FAILED, Json(body)).into_response()
}

fn url_for(hostname: &str, path_prefix: &str) -> String {
    format!("https://{hostname}{path_prefix}")
}

fn group_name_for(environment: &str) -> String {
    format!("automation:{environment}")
}

fn managed_by(environment: &str) -> Option<ManagedBy> {
    Some(ManagedBy::Automation {
        environment: environment.to_string(),
    })
}

// ---- The rows ----

/// The route row an environment owns. Every field the request does
/// not name is the route API's own default, so an environment's route
/// behaves like one an operator created with the same four settings.
fn environment_route(
    input: &WriteInput,
    route_id: String,
    certificate_id: &str,
    created_at: DateTime<Utc>,
) -> Route {
    Route {
        id: route_id,
        hostname: input.hostname.clone(),
        path_prefix: input.path_prefix.clone(),
        certificate_id: Some(certificate_id.to_string()),
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: input.waf_enabled,
        waf_mode: WafMode::Detection,
        enabled: true,
        force_https: input.force_https,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52_428_800,
        max_connections: None,
        slowloris_threshold_ms: 5_000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3_600,
        path_rules: Vec::new(),
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: Vec::new(),
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: Vec::new(),
        header_rules: Vec::new(),
        traffic_splits: Vec::new(),
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: group_name_for(&input.name),
        node_selector: Vec::new(),
        ai_bot_policy: None,
        ai_bot_spoofed_fallback: None,
        serve_robots_txt: false,
        managed_by: managed_by(&input.name),
        created_at,
        updated_at: input.now,
    }
}

/// One backend row, exclusively owned by the environment.
fn environment_backend(input: &WriteInput, index: usize, backend: &ValidatedBackend) -> Backend {
    Backend {
        id: uuid::Uuid::new_v4().to_string(),
        address: backend.address.clone(),
        name: format!("{}-{index}", input.name),
        group_name: group_name_for(&input.name),
        weight: backend.weight,
        health_status: HealthStatus::Unknown,
        health_check_enabled: true,
        health_check_interval_s: DEFAULT_HEALTH_CHECK_INTERVAL_S,
        health_check_path: None,
        lifecycle_state: LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: backend.tls_upstream,
        tls_skip_verify: false,
        tls_sni: backend.tls_sni.clone(),
        h2_upstream: false,
        managed_by: managed_by(&input.name),
        created_at: input.now,
        updated_at: input.now,
    }
}

/// Whether a backend row belongs to `environment`.
fn is_owned_by(backend: &Backend, environment: &str) -> bool {
    matches!(
        &backend.managed_by,
        Some(ManagedBy::Automation { environment: owner }) if owner == environment
    )
}

/// The body of a `PUT`, run inside the caller's transaction.
///
/// In order: ownership and `If-Match`, the hostname collision, the
/// certificate, the route, the backend set, the environment row. The
/// first four write nothing, so every refusal a caller can provoke
/// rolls back an empty transaction; the last three are where a
/// database error would strand a partial environment, and that is
/// what the transaction is for.
fn write_environment(store: &ConfigStore, input: &WriteInput) -> Result<PutOutcome, ApiError> {
    let existing = store.get_automation_environment(&input.name)?;
    let current_etag = existing.as_ref().map(etag_for);
    if let Some(existing) = &existing {
        if !caller_may_access(existing, &input.owner) {
            return Ok(PutOutcome::Foreign);
        }
    }
    if !if_match_holds(input.if_match.as_deref(), current_etag.as_deref()) {
        return Ok(PutOutcome::StaleIfMatch {
            current: current_etag,
        });
    }
    if existing.is_none() {
        // The quota is counted on create alone: an update rewrites
        // rows the principal already owns and adds nothing to the
        // fleet's row set.
        let owned = store
            .list_automation_environments()?
            .into_iter()
            .filter(|environment| environment.owner == input.owner)
            .count();
        if owned >= AUTOMATION_MAX_ENVIRONMENTS_PER_PRINCIPAL {
            return Err(ApiError::Unprocessable(format!(
                "this principal already owns {owned} environments and the cap is \
                 {AUTOMATION_MAX_ENVIRONMENTS_PER_PRINCIPAL}; delete one before creating \
                 another"
            )));
        }
    }

    // The conflict names the hostname and nothing about the route
    // holding it: the caller is a credential from another project, and
    // which manual route sits on a name is an operator's business.
    let own_route_id = existing.as_ref().map(|e| e.route_id.as_str());
    for route in store.list_routes()? {
        if Some(route.id.as_str()) == own_route_id {
            continue;
        }
        let taken = route.hostname.eq_ignore_ascii_case(&input.hostname)
            || route
                .hostname_aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(&input.hostname));
        if taken {
            return Err(ApiError::Conflict(format!(
                "hostname `{}` is already used by another route",
                input.hostname
            )));
        }
    }

    let certificates = store.list_certificates()?;
    let certificate = match &input.certificate_mode {
        CertificateMode::Auto => resolve_certificate_for_hostname(&certificates, &input.hostname)
            .ok_or_else(|| {
            let patterns = wildcard_patterns_an_operator_could_provision(&input.hostname);
            let suggestion = if patterns.is_empty() {
                format!("a certificate for `{}`", input.hostname)
            } else {
                patterns.join(", ")
            };
            ApiError::Unprocessable(format!(
                "{NO_CERTIFICATE_COVERS_HOSTNAME}: no certificate covers `{}`; provision \
                     {suggestion} through {DNS01_PROVISIONING_ENDPOINT} (DNS-01), or name an \
                     explicit certificate id",
                input.hostname
            ))
        })?,
        CertificateMode::Explicit(id) => {
            let named = certificates
                .iter()
                .find(|cert| &cert.id == id)
                .ok_or_else(|| {
                    ApiError::Unprocessable(format!("certificate `{id}` does not exist"))
                })?;
            // Naming an id does not widen what the certificate covers.
            // Without this the route would serve a name the leaf does
            // not carry, and every browser would refuse the site the
            // pipeline just reported as up.
            let covers = std::iter::once(named.domain.as_str())
                .chain(named.san_domains.iter().map(String::as_str))
                .any(|name| matches_one_label(name, &input.hostname));
            if !covers {
                return Err(ApiError::Unprocessable(format!(
                    "{NO_CERTIFICATE_COVERS_HOSTNAME}: certificate `{id}` covers `{}` and not \
                     `{}`; name a certificate that carries the hostname, or use `auto`",
                    named.domain, input.hostname
                )));
            }
            named
        }
    };

    let (route_id, route_created_at) = match &existing {
        Some(existing) => {
            let created_at = store
                .get_route(&existing.route_id)?
                .map(|route| route.created_at)
                .unwrap_or(input.now);
            (existing.route_id.clone(), created_at)
        }
        None => (uuid::Uuid::new_v4().to_string(), input.now),
    };
    let route = environment_route(input, route_id.clone(), &certificate.id, route_created_at);
    if existing.is_some() {
        store.update_route(&route)?;
    } else {
        store.create_route(&route)?;
    }

    // Replace the backend set. Rows this environment owns go; a row it
    // does not own but that somehow got linked is unlinked, never
    // deleted, because it is somebody else's.
    for backend_id in store.list_backends_for_route(&route_id)? {
        match store.get_backend(&backend_id)? {
            Some(backend) if is_owned_by(&backend, &input.name) => {
                store.delete_backend(&backend_id)?;
            }
            _ => store.unlink_route_backend(&route_id, &backend_id)?,
        }
    }
    let mut backend_ids = Vec::with_capacity(input.backends.len());
    for (index, backend) in input.backends.iter().enumerate() {
        let row = environment_backend(input, index, backend);
        store.create_backend(&row)?;
        store.link_route_backend(&route_id, &row.id)?;
        backend_ids.push(row.id);
    }

    // The owner of an existing row is never replaced, and its labels
    // are rewritten by the exact owner alone. `shared = "true"` is a
    // door its owner opened: a caller who walks through it must not be
    // able to close it behind them by PUTting an empty label set and
    // stamping themselves as the owner.
    let (owner, labels) = match &existing {
        Some(existing) if existing.owner == input.owner => {
            (existing.owner.clone(), input.labels.clone())
        }
        Some(existing) => (existing.owner.clone(), existing.labels.clone()),
        None => (input.owner.clone(), input.labels.clone()),
    };

    let environment = AutomationEnvironment {
        name: input.name.clone(),
        route_id,
        owner,
        certificate_mode: input.certificate_mode.clone(),
        labels,
        expires_at: input.expires_at,
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(input.now),
        updated_at: input.now,
        last_pipeline: input
            .pipeline
            .as_ref()
            .and_then(|pipeline| pipeline.pipeline_id.clone()),
        pipeline: input.pipeline.clone(),
    };
    environment.validate().map_err(ApiError::Unprocessable)?;
    store.upsert_automation_environment(&environment)?;

    Ok(PutOutcome::Written(Box::new(Written {
        created: existing.is_none(),
        route,
        backend_ids,
        certificate_id: certificate.id.clone(),
        certificate_not_after: certificate.not_after,
        environment,
    })))
}

/// Remove an environment's rows: the route (which cascades the joins
/// and the environment row), then the backends it owned.
///
/// Shared by `DELETE` and the reaper so both remove exactly the same
/// thing. The caller wraps it in
/// [`lorica_config::ConfigStore::in_transaction`].
///
/// # Errors
///
/// Any store error; the caller's transaction rolls back.
pub fn delete_environment_rows(
    store: &ConfigStore,
    environment: &AutomationEnvironment,
) -> Result<DeletedEnvironment, ConfigError> {
    let linked = store.list_backends_for_route(&environment.route_id)?;
    store.delete_route(&environment.route_id)?;
    let mut backend_ids = Vec::with_capacity(linked.len());
    for backend_id in linked {
        if let Some(backend) = store.get_backend(&backend_id)? {
            if is_owned_by(&backend, &environment.name) {
                store.delete_backend(&backend_id)?;
                backend_ids.push(backend_id);
            }
        }
    }
    Ok(DeletedEnvironment {
        name: environment.name.clone(),
        route_id: environment.route_id.clone(),
        backend_ids,
    })
}

// ---- Re-resolution at snapshot build (AC #4) ----

/// One route the snapshot build rebound to a different certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReresolvedCertificate {
    /// The environment whose route moved.
    pub environment: String,
    /// The route that was rewritten.
    pub route_id: String,
    /// The hostname the certificate was resolved for.
    pub hostname: String,
    /// The certificate the route carried before, when it carried one.
    pub previous: Option<String>,
    /// The certificate it carries now.
    pub current: String,
}

/// Re-resolve every `certificate_mode = auto` environment against the
/// current certificates and land the result on the route row (AC #4).
///
/// Runs at configuration snapshot build, under the store lock that
/// read `routes` and `certificates`, so the resolution sees exactly
/// the rows the snapshot is built from. `routes` is updated in place:
/// the snapshot being assembled uses the new id without a second read.
/// The row write is the part that matters beyond this process: the
/// route row is what replicates, a follower never resolves the mode
/// itself, and it must serve the certificate the control plane chose,
/// so the choice has to be in the row and not only in this snapshot.
///
/// Same resolver and same tie-break as the `PUT` handler
/// ([`resolve_certificate_for_hostname`]), so a row never flips
/// between what the write picked and what the build picks.
///
/// A follower is a no-op, on the same stored-identity check the reaper
/// uses: its `certificate_id` arrives by replication and a local
/// rewrite would be undone on the next round.
///
/// When no certificate covers the hostname any more, the route keeps
/// the id it has and a WARN names the environment and the hostname,
/// once per build.
///
/// # Errors
///
/// A store read or write failure. The caller decides whether that
/// fails the snapshot; it should not, since a snapshot carrying
/// yesterday's certificate ids is better than no snapshot.
pub fn reresolve_auto_certificates(
    store: &ConfigStore,
    routes: &mut [Route],
    certificates: &[Certificate],
    now: DateTime<Utc>,
) -> Result<Vec<ReresolvedCertificate>, ConfigError> {
    if store.is_follower() {
        return Ok(Vec::new());
    }
    let mut rewritten = Vec::new();
    for environment in store.list_automation_environments()? {
        if environment.certificate_mode != CertificateMode::Auto {
            continue;
        }
        let Some(route) = routes
            .iter_mut()
            .find(|route| route.id == environment.route_id)
        else {
            continue;
        };
        let Some(resolved) = resolve_certificate_for_hostname(certificates, &route.hostname) else {
            // An environment that served yesterday must not silently
            // stop serving because a certificate row was deleted and
            // not replaced: the last id that worked stays on the row,
            // the TLS resolver treats a missing certificate the way it
            // always has, and the operator hears about it here.
            tracing::warn!(
                environment = %environment.name,
                hostname = %route.hostname,
                certificate_id = ?route.certificate_id,
                "no certificate covers this environment's hostname any more; keeping the last \
                 certificate it served with"
            );
            continue;
        };
        if route.certificate_id.as_deref() == Some(resolved.id.as_str()) {
            continue;
        }
        store.set_route_certificate(&route.id, &resolved.id, now)?;
        let previous = route.certificate_id.replace(resolved.id.clone());
        route.updated_at = now;
        rewritten.push(ReresolvedCertificate {
            environment: environment.name,
            route_id: route.id.clone(),
            hostname: route.hostname.clone(),
            previous,
            current: resolved.id.clone(),
        });
    }
    Ok(rewritten)
}

// ---- Metrics (AC #10) ----

/// The two figures `lorica_automation_environments` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentCounts {
    /// Environments whose `expires_at` is still ahead.
    pub active: usize,
    /// Environments at or past `expires_at` that the reaper has not
    /// collected yet.
    pub expired: usize,
}

/// Count the environments and publish
/// `lorica_automation_environments{state}`.
///
/// The one place the gauge is set. Called under the store lock right
/// after each write that changes the set (a `PUT`, a `DELETE`, a
/// reaper sweep), so the gauge never describes a row set other than
/// the one just committed. `expired` is the window between an expiry
/// and the sweep that collects it, at most one reaper interval on a
/// healthy node.
///
/// # Errors
///
/// A store read failure.
pub fn publish_environment_gauges(
    store: &ConfigStore,
    now: DateTime<Utc>,
) -> Result<EnvironmentCounts, ConfigError> {
    let environments = store.list_automation_environments()?;
    let expired = environments
        .iter()
        .filter(|environment| environment.expires_at <= now)
        .count();
    let counts = EnvironmentCounts {
        active: environments.len() - expired,
        expired,
    };
    crate::metrics::set_automation_environments(
        i64::try_from(counts.active).unwrap_or(i64::MAX),
        i64::try_from(counts.expired).unwrap_or(i64::MAX),
    );
    Ok(counts)
}

/// [`publish_environment_gauges`] on a write path: a failed count must
/// not fail the write it follows.
fn refresh_environment_gauges(store: &ConfigStore, now: DateTime<Utc>) {
    if let Err(e) = publish_environment_gauges(store, now) {
        tracing::warn!(error = %e, "environment gauges not refreshed");
    }
}

/// The `outcome` label of an operation that ended in `err`: a failure
/// on the node's side is `error`, anything the caller provoked is
/// `refused`.
fn op_outcome(err: &ApiError) -> &'static str {
    match err {
        ApiError::Internal(_) | ApiError::ServiceUnavailable(_) => "error",
        _ => "refused",
    }
}

/// Whether an environment row exists, read before a `PUT` so its
/// counter can say `create` or `update` even when the call is refused
/// before the transaction. The transaction re-reads under its own
/// lock; a race between the two can mislabel one metric sample, which
/// is the most a metric label may cost.
async fn environment_exists(state: &AppState, name: &str) -> bool {
    let lookup = name.to_string();
    db_blocking(&state.store, move |store| {
        store.get_automation_environment(&lookup)
    })
    .await
    .is_ok_and(|found| found.is_some())
}

/// One environment plus the route facts the view needs.
fn view_for(
    store: &ConfigStore,
    environment: &AutomationEnvironment,
) -> Result<Option<EnvironmentView>, ConfigError> {
    let Some(route) = store.get_route(&environment.route_id)? else {
        // The row cascades away with its route, so this is a read that
        // raced a delete: report nothing rather than a half view.
        return Ok(None);
    };
    let backend_ids = store.list_backends_for_route(&route.id)?;
    Ok(Some(EnvironmentView {
        name: environment.name.clone(),
        hostname: route.hostname.clone(),
        path_prefix: route.path_prefix.clone(),
        url: url_for(&route.hostname, &route.path_prefix),
        route_id: route.id,
        backend_ids,
        certificate_id: route.certificate_id,
        certificate_mode: environment.certificate_mode.clone(),
        labels: environment.labels.clone(),
        owner: environment.owner.clone(),
        expires_at: environment.expires_at.to_rfc3339(),
        created_at: environment.created_at.to_rfc3339(),
        updated_at: environment.updated_at.to_rfc3339(),
        last_pipeline: environment.last_pipeline.clone(),
        pipeline: environment.pipeline.clone(),
    }))
}

// ---- Audit ----

/// The audit identity of an automation principal, the same shape the
/// request-level audit layer stamps so the two rows join on it.
fn audit_context(
    principal: &AutomationPrincipal,
    connect_info: &ClientConnectInfo,
    headers: &HeaderMap,
) -> AuditContext {
    AuditContext {
        username: principal.audit_identity(),
        role: super::audit::AUTOMATION_ROLE.to_string(),
        ip: connect_info
            .as_ref()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_default(),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    }
}

/// Record one environment-level row beside the request-level one.
async fn audit_environment(
    state: &AppState,
    ctx: &AuditContext,
    action: &str,
    name: &str,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) {
    crate::audit::record(
        state,
        ctx,
        action,
        (ENVIRONMENT_TARGET_TYPE, name),
        before,
        after,
    )
    .await;
}

/// The fleet generation to report; see
/// [`EnvironmentWriteResponse::applied_generation`].
fn applied_generation(state: &AppState) -> u64 {
    match &state.cluster {
        ClusterRuntime::ControlPlane(runtime) => runtime.control.config_version().generation,
        _ => 0,
    }
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn if_match_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

// ---- Handlers ----

/// `PUT /automation/v1/environments/{name}` (scope `environments:write`).
///
/// 201 on create, 200 on update, one transaction either way.
pub async fn put_environment(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(name): Path<String>,
    Json(body): Json<EnvironmentRequest>,
) -> Result<Response, ApiError> {
    let op: &'static str = if environment_exists(&state, &name).await {
        "update"
    } else {
        "create"
    };
    let result = put_environment_inner(principal, connect_info, headers, &state, &name, body).await;
    let outcome: &'static str = match &result {
        Ok(response) if response.status() == StatusCode::PRECONDITION_FAILED => "refused",
        Ok(_) => "ok",
        Err(err) => op_outcome(err),
    };
    crate::metrics::inc_automation_environment_op(op, outcome);
    result
}

/// The body of [`put_environment`], separated so every exit is
/// counted once by the wrapper.
async fn put_environment_inner(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    state: &AppState,
    name: &str,
    body: EnvironmentRequest,
) -> Result<Response, ApiError> {
    validate_environment_name(name)
        .map_err(|why| ApiError::Unprocessable(format!("name {why}")))?;
    ensure_environment_binding(name, &principal)?;
    let hostname = validate_environment_hostname(&body.hostname)?;
    if !principal.allows_hostname(&hostname) {
        return Err(ApiError::Forbidden(format!(
            "hostname `{hostname}` is outside this token's allowed_hostnames"
        )));
    }
    let path_prefix = validate_path_prefix(body.path_prefix.as_deref())?;
    let backends = validate_backends(&principal, &body.backends)?;
    let certificate_mode = parse_certificate_mode(&body.certificate, &principal)?;
    let now = Utc::now();
    let expires_at = resolve_expiry(now, body.ttl_seconds, &principal)?;

    let input = WriteInput {
        name: name.to_string(),
        hostname: hostname.clone(),
        path_prefix: path_prefix.clone(),
        backends,
        certificate_mode,
        waf_enabled: body.waf_enabled,
        force_https: body.force_https,
        labels: body.labels,
        owner: principal.as_owner(),
        pipeline: principal.pipeline.clone(),
        expires_at,
        now,
        if_match: if_match_header(&headers),
    };
    let ctx = audit_context(&principal, &connect_info, &headers);

    let outcome = db_blocking(&state.store, move |store| {
        let outcome = store.in_transaction(|store| write_environment(store, &input))?;
        if matches!(outcome, PutOutcome::Written(_)) {
            refresh_environment_gauges(store, now);
        }
        Ok::<_, ApiError>(outcome)
    })
    .await;
    let written = match outcome {
        Ok(PutOutcome::Written(written)) => written,
        Ok(PutOutcome::StaleIfMatch { current }) => {
            return Ok(precondition_failed(current.as_deref()));
        }
        Ok(PutOutcome::Foreign) => {
            audit_environment(
                state,
                &ctx,
                "automation.environment.forbidden",
                name,
                None,
                None,
            )
            .await;
            return Err(not_found(name));
        }
        Err(err @ ApiError::Forbidden(_)) => {
            audit_environment(
                state,
                &ctx,
                "automation.environment.forbidden",
                name,
                None,
                None,
            )
            .await;
            return Err(err);
        }
        Err(err) => return Err(err),
    };

    state.notify_config_changed();

    let response = EnvironmentWriteResponse {
        name: name.to_string(),
        url: url_for(&hostname, &path_prefix),
        route_id: written.route.id.clone(),
        backend_ids: written.backend_ids.clone(),
        certificate_id: written.certificate_id.clone(),
        certificate_not_after: written.certificate_not_after.to_rfc3339(),
        expires_at: written.environment.expires_at.to_rfc3339(),
        applied_generation: applied_generation(state),
    };
    let action = if written.created {
        "automation.environment.create"
    } else {
        "automation.environment.update"
    };
    let after = serde_json::to_value(&response).ok();
    audit_environment(state, &ctx, action, name, None, after.as_ref()).await;

    let status = if written.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok(with_etag(
        json_data_with_status(status, response).into_response(),
        &etag_for(&written.environment),
    ))
}

/// `GET /automation/v1/environments` (scope `environments:read`).
///
/// Only the environments the caller may access, filtered by `label`,
/// `hostname` and `expiring_before`.
pub async fn list_environments(
    principal: AutomationPrincipal,
    Extension(state): Extension<AppState>,
    Query(query): Query<ListEnvironmentsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let label: Option<(String, String)> = match query.label.as_deref() {
        Some(raw) => Some(
            raw.split_once(':')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .filter(|(k, _)| !k.is_empty())
                .ok_or_else(|| {
                    ApiError::Unprocessable("label filter must be `key:value`".to_string())
                })?,
        ),
        None => None,
    };
    let hostname: Option<String> = query
        .hostname
        .as_deref()
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase());
    let expiring_before: Option<DateTime<Utc>> = match query.expiring_before.as_deref() {
        Some(raw) => Some(
            DateTime::parse_from_rfc3339(raw.trim())
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| {
                    ApiError::Unprocessable(
                        "expiring_before must be an RFC 3339 timestamp".to_string(),
                    )
                })?,
        ),
        None => None,
    };
    let caller = principal.as_owner();

    let views = db_blocking(&state.store, move |store| {
        let environments = match expiring_before {
            Some(instant) => store.list_automation_environments_expiring_before(instant)?,
            None => store.list_automation_environments()?,
        };
        let mut views = Vec::new();
        for environment in environments {
            if !may_access(
                &environment.owner,
                &caller.principal,
                caller.kind,
                &environment.labels,
            ) {
                continue;
            }
            if let Some((key, value)) = &label {
                if environment.labels.get(key) != Some(value) {
                    continue;
                }
            }
            let Some(view) = view_for(store, &environment)? else {
                continue;
            };
            if let Some(wanted) = &hostname {
                if !view.hostname.eq_ignore_ascii_case(wanted) {
                    continue;
                }
            }
            views.push(view);
        }
        Ok::<_, ConfigError>(views)
    })
    .await?;

    Ok(json_data(serde_json::json!({ "environments": views })))
}

/// `GET /automation/v1/environments/{name}` (scope `environments:read`).
///
/// Answers with the `ETag` a pipeline sends back as `If-Match`.
pub async fn get_environment(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    ensure_environment_binding(&name, &principal)?;
    let caller = principal.as_owner();
    let lookup = name.clone();
    let outcome = db_blocking(&state.store, move |store| {
        let Some(environment) = store.get_automation_environment(&lookup)? else {
            return Ok::<_, ConfigError>(Err(Missing::Unknown));
        };
        if !caller_may_access(&environment, &caller) {
            return Ok(Err(Missing::Foreign));
        }
        let Some(view) = view_for(store, &environment)? else {
            return Ok(Err(Missing::Unknown));
        };
        Ok(Ok((etag_for(&environment), view)))
    })
    .await?;
    let (etag, view) = match outcome {
        Ok(found) => found,
        Err(missing) => {
            if missing == Missing::Foreign {
                let ctx = audit_context(&principal, &connect_info, &headers);
                audit_environment(
                    &state,
                    &ctx,
                    "automation.environment.forbidden",
                    &name,
                    None,
                    None,
                )
                .await;
            }
            return Err(not_found(&name));
        }
    };
    Ok(with_etag(json_data(view).into_response(), &etag))
}

/// `DELETE /automation/v1/environments/{name}` (scope `environments:write`).
///
/// 204 whether or not the environment exists. "Never existed" and
/// "already deleted" both answer 204: telling them apart would mean
/// consulting the audit trail, which is a forensics log that may be
/// absent (worker mode, tests) or truncated by retention, and an API
/// answer must not depend on log retention. A pipeline's cleanup job
/// wants "gone" to be success; a typo in the name is a diagnostic the
/// audit row of this very call gives the operator.
///
/// An environment another principal owns answers the 404 a `GET` on
/// it answers, not a 403: a 403 would confirm that the name is taken
/// and by somebody else, which is the one fact a neighbour on a shared
/// node must not be able to enumerate. The refusal reason is in the
/// audit row.
pub async fn delete_environment(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let result = delete_environment_inner(principal, connect_info, headers, &state, &name).await;
    let outcome: &'static str = match &result {
        Ok(_) => "ok",
        Err(err) => op_outcome(err),
    };
    crate::metrics::inc_automation_environment_op("delete", outcome);
    result
}

/// The body of [`delete_environment`], separated so every exit is
/// counted once by the wrapper.
async fn delete_environment_inner(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    state: &AppState,
    name: &str,
) -> Result<StatusCode, ApiError> {
    ensure_environment_binding(name, &principal)?;
    let caller = principal.as_owner();
    let lookup = name.to_string();
    let ctx = audit_context(&principal, &connect_info, &headers);
    let outcome = db_blocking(&state.store, move |store| {
        let Some(environment) = store.get_automation_environment(&lookup)? else {
            return Ok::<_, ApiError>(Ok(None));
        };
        if !caller_may_access(&environment, &caller) {
            return Ok(Err(Missing::Foreign));
        }
        let deleted = store.in_transaction(|store| delete_environment_rows(store, &environment))?;
        refresh_environment_gauges(store, Utc::now());
        Ok(Ok(Some(deleted)))
    })
    .await?;
    let deleted = match outcome {
        Ok(deleted) => deleted,
        Err(_) => {
            audit_environment(
                state,
                &ctx,
                "automation.environment.forbidden",
                name,
                None,
                None,
            )
            .await;
            return Err(not_found(name));
        }
    };
    if let Some(deleted) = deleted {
        state.notify_config_changed();
        let before = serde_json::to_value(&deleted).ok();
        audit_environment(
            state,
            &ctx,
            "automation.environment.delete",
            name,
            before.as_ref(),
            None,
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- The reaper (AC #7) ----

/// Delete every environment whose `expires_at` is at or before `now`,
/// each in its own transaction, and audit each as
/// [`ENVIRONMENT_EXPIRED_ACTION`].
///
/// Returns the names collected, so the caller knows whether to signal
/// a configuration reload. One transaction per environment rather than
/// one for the sweep: an environment whose rows cannot be removed must
/// not keep every other expired one standing.
pub async fn reap_expired_environments(
    store: &Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<LogStore>>,
    now: DateTime<Utc>,
) -> Vec<String> {
    crate::metrics::inc_automation_reaper_run();
    let swept = db_blocking(store, move |store| {
        let expired = store.list_expired_automation_environments(now)?;
        let mut reaped: Vec<DeletedEnvironment> = Vec::with_capacity(expired.len());
        for environment in expired {
            match store.in_transaction(|store| delete_environment_rows(store, &environment)) {
                Ok(deleted) => {
                    crate::metrics::inc_automation_environment_op("expire", "ok");
                    reaped.push(deleted);
                }
                Err(e) => {
                    crate::metrics::inc_automation_environment_op("expire", "error");
                    tracing::warn!(
                        environment = %environment.name,
                        error = %e,
                        "expired environment could not be removed; it will be retried next sweep"
                    );
                }
            }
        }
        // After the sweep, not only after a removal: a row that could
        // not be removed is exactly what `expired` must keep showing.
        refresh_environment_gauges(store, now);
        Ok::<_, ConfigError>(reaped)
    })
    .await;
    let reaped = match swept {
        Ok(reaped) => reaped,
        Err(e) => {
            tracing::warn!(error = %e, "environment reaper sweep did not run");
            return Vec::new();
        }
    };

    // The actor is the node, not a principal: no token is behind an
    // expiry, which is the shape `AuditContext::node` carries.
    let ctx = AuditContext::node("reaper");
    let mut names = Vec::with_capacity(reaped.len());
    for deleted in reaped {
        tracing::info!(
            environment = %deleted.name,
            route_id = %deleted.route_id,
            backends = deleted.backend_ids.len(),
            "expired environment removed"
        );
        let before = serde_json::to_value(&deleted).ok();
        crate::audit::record_with_store(
            log_store.clone(),
            &ctx,
            ENVIRONMENT_EXPIRED_ACTION,
            (ENVIRONMENT_TARGET_TYPE, &deleted.name),
            before.as_ref(),
            None,
        )
        .await;
        names.push(deleted.name);
    }
    names
}

#[cfg(test)]
mod tests;
