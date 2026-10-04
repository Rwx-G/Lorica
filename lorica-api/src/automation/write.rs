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

//! The automation plane's write surface: routes, backends and
//! certificate bindings, each behind its own write scope (Story 11.2),
//! and the admin tier's one write, the operational settings named in
//! [`SETTINGS_ALLOWLIST`] behind `settings:write` (Story 11.3).
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
//! certificate's `domain` and every SAN inside the hostname grant, for
//! a renewal and for a certificate a route write binds anew; and a
//! route or a backend an environment owns is reachable only when the
//! environment resource's own rules, its ownership rule and the
//! `environment_protected` binding, would let this token reach that
//! environment. Every backend a route write links anew, at
//! the top level or inside `path_rules`, `header_rules` or
//! `traffic_splits`, must point inside the CIDR grant and belong to no
//! other principal's environment. A refusal names the row by its id
//! and echoes none of its values, so a token probing ids outside its
//! grant reads no production hostname off the answer, and a preview is
//! refused exactly where the apply would be.
//!
//! The fields of [`WITHHELD_ROUTE_FIELDS`] are refused from a token
//! outright, whatever their value, each for the reason beside it there;
//! the config tier's tools offer none of them.
//!
//! # Protections move one way
//!
//! Inside the grant, the access-control and trust controls of
//! [`ROUTE_PROTECTIONS`] and [`BACKEND_PROTECTIONS`] may only be
//! strengthened by a token (the maintainer's decision of 2026-09-30,
//! "safe direction only"). The guards weigh each on the row as stored
//! against the row about to be written, inside the same store closure,
//! so the direction is the store's and never a caller's account of it,
//! and the preview is refused where the apply would be. A route create
//! is not weighed, since every one of those controls is at its weakest
//! on the row the management create stores when the body names none of
//! them; a backend create is weighed against the create's own default,
//! which verifies the upstream whenever TLS is on. The dashboard is not
//! bound by any of it.
//!
//! # The scopes bound each other
//!
//! A route write naming `certificate_id` binds a certificate, which is
//! `certificates:write`'s verb, so it needs that scope beside
//! `routes:write`: without this the binding path's scope bounded
//! nothing a route body could not do. The apply needs its write scope
//! and no more.
//!
//! A preview needs the read scope of what it answers, unless what it
//! answers is exactly its own write vocabulary. A route, backend or
//! certificate preview answers the full row it would change, which
//! carries fields the write scope cannot set, so it needs the read
//! scope of that row (`routes:read`, `backends:read`,
//! `certificates:read`): without this a write scope alone read any row
//! inside its grant through `?dry_run=true`. The settings preview
//! answers the allowlisted keys and nothing else, the keys
//! `settings:write` itself sets, so it discloses nothing a no-op apply
//! would not, and it needs no scope beside the write. The property, not
//! the scope, is what exempts it, and the whole-stack test asserts the
//! property on the answer.
//!
//! # A renewal is budgeted per certificate
//!
//! Every renewal is an ACME order the CA counts per identifier set and
//! a rotation of the node's bot-protection HMAC, and the MCP call
//! budget counts calls, not orders. So the renewal handler hands the
//! management body [`crate::acme::RenewalBudget::PerCertificate`]: one
//! order per certificate at a time, none within
//! [`crate::acme::MIN_TOKEN_RENEWAL_INTERVAL_HOURS`] of the last
//! issuance, none during a CA cooldown the background loop recorded.
//! The dashboard's own renew is bounded by none of it.
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
//!
//! # The admin tier is defined by what it refuses
//!
//! `PUT /automation/v1/settings` is the management settings write, as
//! the token, bounded by [`SETTINGS_ALLOWLIST`]: the body is read as a
//! JSON object and a key outside the allowlist is refused with a 403
//! naming it before any value is looked at, before any validator runs.
//! Each key the allowlist names carries a bound and a direction, the
//! safe way to move it, and a value outside either is refused with a
//! 422 on the document the write is about to store, under the store
//! lock. The plane is the control and the MCP tool's schema, built
//! from the same constant in `lorica-automation-policy`, is the
//! affordance: a token
//! holding `settings:write` reaches the same keys whether it calls the
//! tool or the path. A preview and an apply answer the allowlisted part
//! of the document and nothing else, so the scope that writes those
//! keys reads back exactly those keys and needs no read scope beside
//! it.

use std::collections::BTreeSet;

use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use lorica_automation_policy::admin_setting;
use lorica_automation_policy::protections::{
    backend as backend_rule, route as route_rule, ProtectionRule,
};
use lorica_config::models::{AutomationScope, Backend, ManagedBy, Route};
use lorica_config::ConfigStore;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::auth::AutomationPrincipal;
use super::environments::{
    audit_context, caller_may_access, ensure_backend_address_granted, ensure_environment_binding,
};
use super::redact;
use super::scope::scope_str;
use crate::audit::ClientConnectInfo;
use crate::backends::{CreateBackendRequest, UpdateBackendRequest};
use crate::error::{json_data, ApiError};
use crate::preview::{previewed, DryRunQuery, WriteMode};
use crate::routes::{CreateRouteRequest, UpdateRouteRequest};
use crate::server::AppState;
use crate::settings::{SettingsAuditTarget, UpdateSettingsRequest};
use crate::target::{BackendGuard, CertificateGuard, RouteGuard, RouteTarget};

// The admin tier's surface is the automation policy's, declared in
// `lorica-automation-policy` so `lorica-mcp` builds its tool from the
// same statement; re-exported so this module's path to it, which the
// CLI and the tests read, is unchanged.
pub use lorica_automation_policy::settings::{
    AdminSetting, Direction, Reach, TakesEffect, RETENTION_TIER_CEILING_ROWS, SETTINGS_ALLOWLIST,
};

/// Whether `key` is one of [`SETTINGS_ALLOWLIST`]'s names.
fn is_allowlisted_setting(key: &str) -> bool {
    admin_setting(key).is_some()
}

/// The JSON body `PUT /automation/v1/settings` reads: an object whose
/// keys are weighed against [`SETTINGS_ALLOWLIST`] before any value is.
///
/// Not `UpdateSettingsRequest`, on purpose: that struct ignores an
/// unknown key and types every known one, so deserialising into it
/// first would run a type check on a key the tier must refuse, and drop
/// a key it must name.
pub type SettingsPatch = Map<String, Value>;

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

// The route fields no token may send, with the reason each refusal
// gives, are declared in `lorica-automation-policy`.
pub use lorica_automation_policy::protections::WITHHELD_ROUTE_FIELDS;

/// A route write body, asked which of [`WITHHELD_ROUTE_FIELDS`] it
/// carries.
///
/// `None` for a name the body has no field for: a name added to the
/// table and not here is a refusal of the whole write rather than a
/// field that silently passes, and the test that walks the table
/// against both bodies turns it red first.
trait WithheldFields {
    /// Whether the body sends the field named `field`.
    fn sends(&self, field: &str) -> Option<bool>;
}

impl WithheldFields for CreateRouteRequest {
    fn sends(&self, field: &str) -> Option<bool> {
        match field {
            "basic_auth_password" => Some(self.basic_auth_password.is_some()),
            "forward_auth" => Some(self.forward_auth.is_some()),
            "mirror" => Some(self.mirror.is_some()),
            "mtls" => Some(self.mtls.is_some()),
            "proxy_headers" => Some(self.proxy_headers.is_some()),
            _ => None,
        }
    }
}

impl WithheldFields for UpdateRouteRequest {
    fn sends(&self, field: &str) -> Option<bool> {
        match field {
            "basic_auth_password" => Some(self.basic_auth_password.is_some()),
            "forward_auth" => Some(self.forward_auth.is_some()),
            "mirror" => Some(self.mirror.is_some()),
            "mtls" => Some(self.mtls.is_some()),
            "proxy_headers" => Some(self.proxy_headers.is_some()),
            _ => None,
        }
    }
}

/// The first of [`WITHHELD_ROUTE_FIELDS`] the body sends, refused with
/// a 403 naming it and its reason.
fn refuse_withheld(body: &impl WithheldFields) -> Result<(), ApiError> {
    for (field, why) in WITHHELD_ROUTE_FIELDS {
        match body.sends(field) {
            Some(false) => {}
            Some(true) => {
                return Err(ApiError::Forbidden(format!(
                    "{field} is not accepted from an automation token: {why}; set it in the \
                     dashboard"
                )))
            }
            None => {
                return Err(ApiError::Internal(format!(
                    "{field} is withheld from automation tokens and the route body has no such \
                     field"
                )))
            }
        }
    }
    Ok(())
}

/// One access-control or trust field of a stored row that an
/// automation token may move only toward stronger (the maintainer's
/// decision of 2026-09-30, "safe direction only"): a
/// [`ProtectionRule`] of `lorica-automation-policy`, paired with the
/// predicate that weighs it on this crate's row types.
///
/// The rule runs in the guard, inside the store closure, on the row as
/// stored and the row as it would be written, so the direction is
/// weighed against what the store holds under the lock that writes it
/// and never against what a caller says the row was. A preview is
/// refused exactly where the apply would be.
#[derive(Clone, Copy)]
pub struct Protection<T: 'static> {
    /// The fields the rule weighs, as the request bodies spell them.
    pub fields: &'static [&'static str],
    /// The safe direction, in the words a refusal and the docs use.
    pub rule: &'static str,
    /// Why the other direction is the dashboard's and not a token's.
    pub why: &'static str,
    /// Whether `after` is weaker than `before` on this control.
    pub weakened: fn(&T, &T) -> bool,
}

impl<T> Protection<T> {
    /// `policy`, weighed by `weakened`.
    const fn weighing(policy: ProtectionRule, weakened: fn(&T, &T) -> bool) -> Protection<T> {
        Protection {
            fields: policy.fields,
            rule: policy.rule,
            why: policy.why,
            weakened,
        }
    }
}

impl<T> std::fmt::Debug for Protection<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protection")
            .field("fields", &self.fields)
            .field("rule", &self.rule)
            .finish()
    }
}

/// Every route control an automation token may only strengthen:
/// `ROUTE_PROTECTION_RULES`, in its order, each with its predicate. A
/// test holds this list to that one, so a rule declared there without a
/// predicate here is a red gate rather than a control nobody weighs.
pub const ROUTE_PROTECTIONS: &[Protection<Route>] = &[
    Protection::weighing(route_rule::BASIC_AUTH, basic_auth_weakened),
    Protection::weighing(route_rule::IP_ALLOWLIST, allowlist_weakened),
    Protection::weighing(route_rule::IP_DENYLIST, denylist_weakened),
    Protection::weighing(route_rule::GEOIP, geoip_weakened),
    Protection::weighing(route_rule::BOT_PROTECTION, bot_protection_weakened),
    Protection::weighing(route_rule::WAF_ENABLED, waf_switched_off),
    Protection::weighing(route_rule::WAF_MODE, waf_mode_weakened),
    Protection::weighing(route_rule::RATE_LIMIT, rate_limit_weakened),
    Protection::weighing(route_rule::LEGACY_RATE_LIMIT, legacy_rate_weakened),
    Protection::weighing(route_rule::AUTO_BAN_THRESHOLD, auto_ban_weakened),
];

/// Every backend control an automation token may only strengthen:
/// `BACKEND_PROTECTION_RULES`, each with its predicate, held to that
/// list by the same test.
pub const BACKEND_PROTECTIONS: &[Protection<Backend>] = &[
    Protection::weighing(backend_rule::TLS_SKIP_VERIFY, verification_switched_off),
    Protection::weighing(backend_rule::TLS_UPSTREAM, upstream_tls_switched_off),
    Protection::weighing(backend_rule::TLS_SNI, verified_name_changed),
];

/// The first rule of `protections` that `after` breaks against
/// `before`, refused with a 403 naming the field and the rule and
/// echoing neither value.
fn ensure_not_weakened<T>(
    protections: &[Protection<T>],
    kind: &str,
    id: &str,
    before: &T,
    after: &T,
) -> Result<(), ApiError> {
    for protection in protections {
        if (protection.weakened)(before, after) {
            return Err(ApiError::Forbidden(format!(
                "{} on {kind} `{id}` may only be strengthened by an automation token: {}, \
                 because {}; weaken it in the dashboard",
                protection.fields.join(" / "),
                protection.rule,
                protection.why
            )));
        }
    }
    Ok(())
}

fn basic_auth_weakened(before: &Route, after: &Route) -> bool {
    let in_force =
        before.basic_auth_username.is_some() && before.basic_auth_password_hash.is_some();
    in_force
        && (before.basic_auth_username != after.basic_auth_username
            || before.basic_auth_password_hash != after.basic_auth_password_hash)
}

/// An allowlist or denylist entry as the proxy compiles it: a CIDR, or
/// a bare address as its host network. `None` for what the proxy skips.
fn listed_network(entry: &str) -> Option<ipnet::IpNet> {
    let entry = entry.trim();
    entry.parse::<ipnet::IpNet>().ok().or_else(|| {
        entry
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from)
    })
}

/// Whether some network of `within` contains `net`.
fn covered(net: &ipnet::IpNet, within: &[String]) -> bool {
    within
        .iter()
        .filter_map(|entry| listed_network(entry))
        .any(|outer| outer.contains(net))
}

/// An allowlist admits every address when empty and otherwise only
/// what its parsed entries cover; an entry the proxy cannot parse
/// admits nothing. Narrowed means every parsed entry after sits inside
/// a parsed entry before.
fn allowlist_weakened(before: &Route, after: &Route) -> bool {
    if before.ip_allowlist.is_empty() {
        return false;
    }
    after.ip_allowlist.is_empty()
        || after
            .ip_allowlist
            .iter()
            .filter_map(|entry| listed_network(entry))
            .any(|net| !covered(&net, &before.ip_allowlist))
}

/// A denylist refuses what its parsed entries cover. Extended means
/// every parsed entry before is covered by a parsed entry after.
fn denylist_weakened(before: &Route, after: &Route) -> bool {
    before
        .ip_denylist
        .iter()
        .filter_map(|entry| listed_network(entry))
        .any(|net| !covered(&net, &after.ip_denylist))
}

fn geoip_weakened(before: &Route, after: &Route) -> bool {
    use lorica_config::models::GeoIpMode;
    let Some(stored) = &before.geoip else {
        return false;
    };
    let Some(patched) = &after.geoip else {
        return true;
    };
    let listed = |countries: &[String], country: &str| {
        countries.iter().any(|c| c.eq_ignore_ascii_case(country))
    };
    if stored.mode != patched.mode {
        return true;
    }
    match stored.mode {
        GeoIpMode::Allowlist => patched
            .countries
            .iter()
            .any(|country| !listed(&stored.countries, country)),
        GeoIpMode::Denylist => stored
            .countries
            .iter()
            .any(|country| !listed(&patched.countries, country)),
    }
}

fn bot_protection_weakened(before: &Route, after: &Route) -> bool {
    before.bot_protection.is_some() && before.bot_protection != after.bot_protection
}

fn waf_switched_off(before: &Route, after: &Route) -> bool {
    before.waf_enabled && !after.waf_enabled
}

fn waf_mode_weakened(before: &Route, after: &Route) -> bool {
    use lorica_config::models::WafMode;
    before.waf_mode == WafMode::Blocking && after.waf_mode != WafMode::Blocking
}

fn rate_limit_weakened(before: &Route, after: &Route) -> bool {
    let Some(stored) = &before.rate_limit else {
        return false;
    };
    let Some(patched) = &after.rate_limit else {
        return true;
    };
    patched.capacity > stored.capacity
        || patched.refill_per_sec > stored.refill_per_sec
        || patched.scope != stored.scope
}

/// The legacy pair as the bucket the proxy builds from it, so a burst
/// raised alone reads as the capacity it raises.
fn legacy_rate_weakened(before: &Route, after: &Route) -> bool {
    use lorica_config::models::RateLimit;
    let Some(stored_rps) = before.rate_limit_rps else {
        return false;
    };
    let Some(patched_rps) = after.rate_limit_rps else {
        return true;
    };
    let stored = RateLimit::from_legacy(stored_rps, before.rate_limit_burst);
    let patched = RateLimit::from_legacy(patched_rps, after.rate_limit_burst);
    patched.capacity > stored.capacity || patched.refill_per_sec > stored.refill_per_sec
}

fn auto_ban_weakened(before: &Route, after: &Route) -> bool {
    match (before.auto_ban_threshold, after.auto_ban_threshold) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(stored), Some(patched)) => patched > stored,
    }
}

fn verification_switched_off(before: &Backend, after: &Backend) -> bool {
    !before.tls_skip_verify && after.tls_skip_verify
}

fn upstream_tls_switched_off(before: &Backend, after: &Backend) -> bool {
    before.tls_upstream && !after.tls_upstream
}

fn verified_name_changed(before: &Backend, after: &Backend) -> bool {
    before.tls_upstream && !before.tls_skip_verify && before.tls_sni != after.tls_sni
}

/// The backend the management create would store with none of
/// [`BACKEND_PROTECTIONS`]'s fields named: what a create is weighed
/// against.
fn as_created_by_default(requested: &Backend) -> Backend {
    Backend {
        tls_upstream: false,
        tls_skip_verify: false,
        tls_sni: None,
        ..requested.clone()
    }
}

/// A route write naming `certificate_id`, the empty string included,
/// binds or unbinds a certificate, which is `certificates:write`'s
/// verb: the binding path sits behind that scope, and a route body
/// that could bind under `routes:write` alone made withholding it mean
/// nothing. The environment resource applies the same rule to an
/// explicit certificate id.
fn ensure_certificate_binding_granted(
    principal: &AutomationPrincipal,
    certificate_id: Option<&str>,
) -> Result<(), ApiError> {
    if certificate_id.is_some() && !principal.has_scope(AutomationScope::CertificatesWrite) {
        return Err(ApiError::Forbidden(
            "certificate_id: binding or unbinding a certificate needs the certificates:write \
             scope beside routes:write"
                .to_string(),
        ));
    }
    Ok(())
}

/// A preview answers the full row it would change, so a write scope
/// alone would read any row inside the grant through it. It needs the
/// read scope of that row, which a config-tier token carries anyway
/// since the tier finds its ids through it; the apply needs nothing
/// beyond its write scope.
fn ensure_preview_readable(
    principal: &AutomationPrincipal,
    mode: WriteMode,
    read: AutomationScope,
) -> Result<(), ApiError> {
    if mode.previews() && !principal.has_scope(read) {
        return Err(ApiError::Forbidden(format!(
            "dry_run: a preview answers the row it would change, which needs the {} scope",
            scope_str(read)
        )));
    }
    Ok(())
}

/// A row an environment owns is reachable exactly when the environment
/// is, by the environment resource's own rules, the ownership rule and
/// the `environment_protected` binding: a route delete that would
/// cascade an environment is refused where the environment's delete
/// would be. A mark whose environment row is gone owns nothing and
/// refuses nothing; the hostname or address rule still applies.
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
    if !caller_may_access(&owned, &principal.as_owner()) {
        return Err(ApiError::Forbidden(format!(
            "{kind} `{id}` belongs to an environment this token does not own"
        )));
    }
    // An ID token bound to `environment_protected = true` writes the one
    // environment its job deploys, on the environment resource and here
    // alike: a route delete cascades its environment, so without this a
    // job reached every other environment of its own project through
    // the route path.
    if principal.required_environment_slug.is_some()
        && ensure_environment_binding(environment, principal).is_err()
    {
        return Err(ApiError::Forbidden(format!(
            "{kind} `{id}` belongs to an environment other than the one this job deploys, and \
             this credential is bound to environment_protected=true"
        )));
    }
    Ok(())
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
    if !route_names_granted(
        principal,
        &route.hostname,
        route.hostname_aliases.iter().map(String::as_str),
    ) {
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

/// Whether a route answering to `hostname` and `aliases` is inside the
/// principal's hostname grant: every name, one exact host at a time, a
/// wildcard name never.
///
/// The one predicate the write guard and the grant-filtered route
/// listing ([`super::read::list_routes`]) both apply, so a route a
/// config-tier token may act on and a route it may see are the same set.
pub(super) fn route_names_granted<'a>(
    principal: &AutomationPrincipal,
    hostname: &'a str,
    aliases: impl IntoIterator<Item = &'a str>,
) -> bool {
    std::iter::once(hostname)
        .chain(aliases)
        .map(str::trim)
        .all(|name| !name.contains('*') && principal.allows_hostname(name))
}

/// Whether a certificate naming `domain` and `sans` is inside the
/// principal's hostname grant: every name, weighed as the grant spells
/// it, so a wildcard certificate covering exactly the grant's own
/// namespace is inside it and one covering a wider or a different one
/// is not.
///
/// Shared by the renewal guard and the grant-filtered certificate
/// listing ([`super::read::list_certificates`]).
pub(super) fn certificate_names_granted<'a>(
    principal: &AutomationPrincipal,
    domain: &'a str,
    sans: impl IntoIterator<Item = &'a str>,
) -> bool {
    std::iter::once(domain)
        .chain(sans)
        .map(str::trim)
        .all(|name| principal.allows_hostname(name))
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
/// backends linked anew. A header-rule value sent back as the mask this
/// plane answered it with keeps the stored value
/// ([`redact::restore_header_rule_values`]) before any of that is
/// weighed.
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
            ensure_new_certificate_granted(store, &principal, target.before, after)?;
        }
        if let (Some(before), Some(after)) = (target.before, target.after) {
            ensure_not_weakened(ROUTE_PROTECTIONS, "route", &before.id, before, after)?;
        }
        ensure_new_links_granted(store, &principal, target)
    })
    .restoring_withheld(redact::restore_header_rule_values)
}

/// A certificate a route write binds anew, weighed as a renewal would
/// weigh it: every name it covers, `domain` and each SAN, inside the
/// hostname grant. Without this the grant said which routes a token
/// may reach and nothing of which certificates it may deploy on them.
///
/// A binding the route already carries is not re-weighed, and an id
/// naming no row reaches nothing: the store refuses it on apply. The
/// refusal names the certificate by id and none of its names.
fn ensure_new_certificate_granted(
    store: &ConfigStore,
    principal: &AutomationPrincipal,
    before: Option<&Route>,
    after: &Route,
) -> Result<(), ApiError> {
    let Some(id) = after.certificate_id.as_deref().filter(|id| !id.is_empty()) else {
        return Ok(());
    };
    if before.and_then(|route| route.certificate_id.as_deref()) == Some(id) {
        return Ok(());
    }
    let Some(certificate) = store.get_certificate(id)? else {
        return Ok(());
    };
    if !certificate_names_granted(
        principal,
        &certificate.domain,
        certificate.san_domains.iter().map(String::as_str),
    ) {
        return Err(ApiError::Forbidden(format!(
            "certificate `{id}` covers a name outside this token's allowed_hostnames"
        )));
    }
    Ok(())
}

/// The token's grant as the guard a backend write runs inside its
/// store closure, on the row as stored and on the row as it would be,
/// and the direction each of [`BACKEND_PROTECTIONS`] may move between
/// them, a create weighed against the backend the management create
/// stores by default.
fn backend_guard(principal: &AutomationPrincipal) -> BackendGuard {
    let principal = principal.clone();
    BackendGuard::bounded(move |store, target| {
        if let Some(before) = target.before {
            ensure_backend_row_granted(store, &principal, before)?;
        }
        if let Some(after) = target.after {
            ensure_backend_row_granted(store, &principal, after)?;
            let created;
            let before = match target.before {
                Some(before) => before,
                None => {
                    created = as_created_by_default(after);
                    &created
                }
            };
            ensure_not_weakened(BACKEND_PROTECTIONS, "backend", &after.id, before, after)?;
        }
        Ok(())
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
        if !certificate_names_granted(
            &principal,
            &certificate.domain,
            certificate.san_domains.iter().map(String::as_str),
        ) {
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
/// other principal's environment (403), the fields of
/// [`WITHHELD_ROUTE_FIELDS`] are refused (403), and `certificate_id`
/// needs `certificates:write` and a certificate whose every name is
/// inside the hostname grant (403). With `?dry_run=true`, which needs
/// `routes:read` (403), the route it would have created, and nothing
/// created.
///
/// # Errors
///
/// `Forbidden` for a name, a link, a field or a scope outside the
/// grant, then whatever [`crate::routes::crud::create_route_as`]
/// answers.
pub async fn create_route(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::RoutesRead)?;
    refuse_withheld(&body)?;
    ensure_certificate_binding_granted(&principal, body.certificate_id.as_deref())?;
    ensure_hostnames_granted(
        &principal,
        Some(&body.hostname),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let (status, answer) = crate::routes::crud::create_route_as(
        &state,
        &actor,
        body,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await?;
    Ok((status, redact::write_answer(answer, redact::route_row)))
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
/// environment, the fields of [`WITHHELD_ROUTE_FIELDS`] are refused, a
/// control of [`ROUTE_PROTECTIONS`] may only be strengthened, and
/// `certificate_id` needs `certificates:write` and a certificate whose
/// every name is inside the hostname grant (403 each). With
/// `?dry_run=true`, which needs `routes:read` (403), the route before
/// and after the patch, and nothing changed.
///
/// # Errors
///
/// `Forbidden` for a target, a name, a link, a field or a scope
/// outside the grant, then whatever
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::RoutesRead)?;
    refuse_withheld(&body)?;
    ensure_certificate_binding_granted(&principal, body.certificate_id.as_deref())?;
    ensure_hostnames_granted(
        &principal,
        body.hostname.as_deref(),
        body.hostname_aliases.as_deref(),
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let answer = crate::routes::crud::update_route_as(
        &state,
        &actor,
        id,
        body,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await?;
    Ok(redact::write_answer(answer, redact::route_row))
}

/// `DELETE /automation/v1/routes/{id}` (scope `routes:write`).
///
/// The management route delete, as the token. The route named must be
/// inside the token's `allowed_hostnames` on its current hostname and
/// every current alias (403). A managed route is deletable there and
/// therefore here, and takes its environment with it, so it is
/// reachable exactly when the environment resource would let this token
/// reach that environment (403 otherwise); the audit row names the
/// environment. With `?dry_run=true`, which needs `routes:read` (403),
/// the route that would go, and nothing deleted.
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::RoutesRead)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let answer = crate::routes::crud::delete_route_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await?;
    Ok(redact::write_answer(answer, redact::route_row))
}

/// `PUT /automation/v1/routes/{id}/certificate` (scope
/// `certificates:write`).
///
/// Binds a stored certificate to a route, as the one-field patch
/// `PUT /api/v1/routes/{id}` would make, through the same function:
/// the managed-row refusal (409) holds, and the empty string unbinds.
/// The route named must be inside the token's `allowed_hostnames` on
/// its current hostname and every current alias (403), and so must
/// every name the certificate covers, its `domain` and each SAN (403).
/// Selecting a certificate is naming its id here; what the id names
/// entered the node through the management API. With `?dry_run=true`,
/// which needs
/// `routes:read` since it answers the route (403), the route before
/// and after the binding, and nothing bound.
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::RoutesRead)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let patch = UpdateRouteRequest {
        certificate_id: Some(body.certificate_id),
        ..UpdateRouteRequest::default()
    };
    let answer = crate::routes::crud::update_route_as(
        &state,
        &actor,
        id,
        patch,
        WriteMode::from(dry_run),
        route_guard(&principal),
    )
    .await?;
    Ok(redact::write_answer(answer, redact::route_row))
}

/// `POST /automation/v1/backends` (scope `backends:write`).
///
/// The management backend create, as the token. The address must be an
/// `ip:port` (422, since a name cannot be checked against a CIDR
/// grant) inside the token's `allowed_backend_cidrs` (403), the same
/// rule the environment resource applies to its backends, and an
/// unverified upstream (`tls_skip_verify`) is refused (403), the create
/// weighed against [`BACKEND_PROTECTIONS`] from the management create's
/// default. With `?dry_run=true`, which needs `backends:read` (403), the
/// backend it would have created, and nothing created.
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::BackendsRead)?;
    ensure_backend_address_granted(&principal, "address", &body.address)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let (status, answer) = crate::backends::create_backend_as(
        &state,
        &actor,
        body,
        WriteMode::from(dry_run),
        backend_guard(&principal),
    )
    .await?;
    Ok((status, redact::write_answer(answer, redact::backend_row)))
}

/// `PUT /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend update, as the token, the managed-row
/// refusal (409) included. The backend named must sit inside the
/// token's `allowed_backend_cidrs` on its stored address and belong to
/// no other principal's environment (403); an address the patch names
/// is checked against the grant exactly as on create, and a control of
/// [`BACKEND_PROTECTIONS`] may only be strengthened (403). With
/// `?dry_run=true`, which needs `backends:read` (403), the backend
/// before and after the patch, and nothing changed.
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::BackendsRead)?;
    if let Some(address) = body.address.as_deref() {
        ensure_backend_address_granted(&principal, "address", address)?;
    }
    let actor = audit_context(&principal, &connect_info, &headers);
    let answer = crate::backends::update_backend_as(
        &state,
        &actor,
        id,
        body,
        WriteMode::from(dry_run),
        backend_guard(&principal),
    )
    .await?;
    Ok(redact::write_answer(answer, redact::backend_row))
}

/// `DELETE /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend delete, as the token: the graceful drain,
/// and the refusal of a backend an environment owns (409). The backend
/// named must sit inside the token's `allowed_backend_cidrs` on its
/// stored address and belong to no other principal's environment
/// (403). With `?dry_run=true`, which needs `backends:read` (403), the
/// backend marked closing as the drain would leave it, or the row that
/// would go at once when it is already closing, and no drain started.
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
    ensure_preview_readable(&principal, dry_run.mode(), AutomationScope::BackendsRead)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let answer = crate::backends::delete_backend_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        backend_guard(&principal),
    )
    .await?;
    Ok(redact::write_answer(answer, redact::backend_row))
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
/// A token renews one certificate at a time (409) and not within
/// [`crate::acme::MIN_TOKEN_RENEWAL_INTERVAL_HOURS`] of its last
/// issuance or during a CA cooldown (429). With `?dry_run=true`, which
/// needs `certificates:read` (403), the certificate that would be
/// renewed, and no order made.
///
/// # Errors
///
/// The grant's refusal on the target, then whatever
/// [`crate::acme::renew_certificate_as`] answers, the budget's 409 and
/// 429 included.
pub async fn renew_certificate(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(dry_run): Query<DryRunQuery>,
) -> Result<Json<Value>, ApiError> {
    ensure_preview_readable(
        &principal,
        dry_run.mode(),
        AutomationScope::CertificatesRead,
    )?;
    let actor = audit_context(&principal, &connect_info, &headers);
    crate::acme::renew_certificate_as(
        &state,
        &actor,
        id,
        WriteMode::from(dry_run),
        certificate_guard(&principal),
        crate::acme::RenewalBudget::PerCertificate,
    )
    .await
}

/// The longest key a settings refusal repeats back.
const SETTINGS_KEY_ECHO_MAX_BYTES: usize = 64;

/// Every key of `body` inside [`SETTINGS_ALLOWLIST`], or a 403 naming
/// the first key that is not.
///
/// The key is named when it is shaped like a settings field name, which
/// every real field is; anything else is the caller's own text in a
/// sentence this node writes, and is described rather than repeated.
fn ensure_settings_allowlisted(body: &SettingsPatch) -> Result<(), ApiError> {
    let Some(outside) = body.keys().find(|key| !is_allowlisted_setting(key)) else {
        return Ok(());
    };
    let field_shaped = (1..=SETTINGS_KEY_ECHO_MAX_BYTES).contains(&outside.len())
        && outside
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    let named = if field_shaped {
        format!("`{outside}` is")
    } else {
        "a key that is not a settings field name is".to_string()
    };
    let allowed: Vec<&str> = SETTINGS_ALLOWLIST.iter().map(|s| s.name).collect();
    Err(ApiError::Forbidden(format!(
        "settings key {named} outside the admin tier's allowlist and is not accepted from an \
         automation token; set it in the dashboard. The keys this path accepts: {}",
        allowed.join(", ")
    )))
}

/// The allowlisted body as the management request, with a type error
/// naming the key it is on.
///
/// Each key is read alone first, because a whole-body error from serde
/// names the value it choked on and not the field, and the field is
/// what the caller needs.
fn settings_request(body: SettingsPatch) -> Result<UpdateSettingsRequest, ApiError> {
    for (key, value) in &body {
        let alone = Map::from_iter([(key.clone(), value.clone())]);
        serde_json::from_value::<UpdateSettingsRequest>(Value::Object(alone))
            .map_err(|refused| ApiError::Unprocessable(format!("{key}: {refused}")))?;
    }
    serde_json::from_value(Value::Object(body))
        .map_err(|refused| ApiError::Unprocessable(refused.to_string()))
}

/// The allowlisted keys of a settings document, and nothing else.
///
/// What a settings write answers on this plane, for the apply and the
/// preview alike: the scope that writes these keys reads back these
/// keys, and the rest of the document (listener addresses, sink
/// destinations, secrets) stays where no automation scope reaches it.
///
/// The document is masked before it is projected, so an allowlist that
/// ever named a secret by mistake would answer the sentinel and not the
/// secret.
fn allowlisted_view(settings: &lorica_config::models::GlobalSettings) -> Value {
    let mut masked = settings.clone();
    crate::settings::mask_settings_secrets(&mut masked);
    let mut view = serde_json::to_value(&masked).unwrap_or_default();
    if let Some(object) = view.as_object_mut() {
        object.retain(|key, _| is_allowlisted_setting(key));
    }
    view
}

/// The admin tier's bound on each key `body` sets, as the check
/// [`crate::settings::update_settings_as`] runs on the stored document
/// and the patched one under the store lock.
///
/// A key sent as `null` sets nothing and is not weighed. The first key
/// outside its entry's bound, or moved against its entry's direction,
/// is refused with a 422 naming the key, the value and the bound.
fn tier_bounds(
    body: &SettingsPatch,
) -> impl FnOnce(
    &lorica_config::models::GlobalSettings,
    &lorica_config::models::GlobalSettings,
) -> Result<(), ApiError>
       + Send
       + 'static {
    let named: Vec<&'static AdminSetting> = body
        .iter()
        .filter(|(_, value)| !value.is_null())
        .filter_map(|(key, _)| admin_setting(key))
        .collect();
    move |before, after| {
        let before = serde_json::to_value(before).unwrap_or_default();
        let after = serde_json::to_value(after).unwrap_or_default();
        for setting in named {
            let (Some(stored), Some(patched)) =
                (before[setting.name].as_i64(), after[setting.name].as_i64())
            else {
                return Err(ApiError::Internal(format!(
                    "{} is not an integer in the settings document",
                    setting.name
                )));
            };
            if let Some(refused) = setting.refusal(stored, patched) {
                return Err(ApiError::Unprocessable(refused));
            }
        }
        Ok(())
    }
}

/// `PUT /automation/v1/settings` (scope `settings:write`).
///
/// The management settings write, as the token, bounded by
/// [`SETTINGS_ALLOWLIST`]: a key outside it is refused with a 403
/// naming it before any value is read, a value outside its entry's
/// bound or against its direction with a 422 naming the key and the
/// bound, then the body goes through the dashboard's own validators,
/// reload signal and `settings.update` audit row, whose target names
/// each key the write changed with its value before and after. The
/// answer is the allowlisted part of the document after the write.
/// With `?dry_run=true`, the same part before and after, and nothing
/// written; the preview needs no scope beyond this one, because it
/// shows only what this scope may write.
///
/// # Errors
///
/// `Forbidden` for a key outside the allowlist, `Unprocessable` for a
/// value of the wrong type or outside the tier's bound, then whatever
/// [`crate::settings::update_settings_as`] answers.
pub async fn update_settings(
    principal: AutomationPrincipal,
    connect_info: ClientConnectInfo,
    headers: HeaderMap,
    Extension(state): Extension<AppState>,
    Query(dry_run): Query<DryRunQuery>,
    Json(body): Json<SettingsPatch>,
) -> Result<Json<Value>, ApiError> {
    ensure_settings_allowlisted(&body)?;
    let bounds = tier_bounds(&body);
    let request = settings_request(body)?;
    let actor = audit_context(&principal, &connect_info, &headers);
    let mode = WriteMode::from(dry_run);
    let change = crate::settings::update_settings_as(
        &state,
        &actor,
        request,
        mode,
        SettingsAuditTarget::ChangedValues,
        bounds,
    )
    .await?;
    let after = allowlisted_view(&change.after);
    if mode.previews() {
        return Ok(previewed(
            "update",
            Some(allowlisted_view(&change.before)),
            Some(after),
        ));
    }
    Ok(json_data(after))
}

#[cfg(test)]
mod admin_tier_tests;
#[cfg(test)]
mod plane_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_automation_policy::{BACKEND_PROTECTION_RULES, ROUTE_PROTECTION_RULES};
    use lorica_config::models::{AutomationScope, OwnerKind};

    #[test]
    fn every_protection_rule_is_weighed_here_once_in_its_order() {
        // The rules are the policy crate's and the predicates are this
        // module's; the pairing is the one thing written twice, so it is
        // held to the rule lists entry by entry. A rule added there and
        // not paired here, or paired twice, turns this red.
        fn stated<T>(protections: &[Protection<T>]) -> Vec<ProtectionRule> {
            protections
                .iter()
                .map(|protection| ProtectionRule {
                    fields: protection.fields,
                    rule: protection.rule,
                    why: protection.why,
                })
                .collect()
        }
        assert_eq!(stated(ROUTE_PROTECTIONS), ROUTE_PROTECTION_RULES);
        assert_eq!(stated(BACKEND_PROTECTIONS), BACKEND_PROTECTION_RULES);
    }

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
        // closure, which the whole-stack tests in `plane_tests` drive.
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
    fn every_withheld_field_is_refused_from_a_token_whatever_the_value() {
        // Each entry of the table is sent alone, in a body read the way
        // the handler reads it, on the create and on the update: the
        // table is the one statement of what is withheld, and a name it
        // gains with no field behind it turns this red rather than
        // passing silently.
        let empty: CreateRouteRequest =
            serde_json::from_value(serde_json::json!({ "hostname": "a.review.example.com" }))
                .expect("a minimal create");
        refuse_withheld(&empty).expect("nothing withheld is sent");
        refuse_withheld(&UpdateRouteRequest::default()).expect("nothing withheld is sent");
        for (field, _) in WITHHELD_ROUTE_FIELDS {
            assert!(empty.sends(field).is_some(), "{field}: no create field");
            assert!(
                UpdateRouteRequest::default().sends(field).is_some(),
                "{field}: no update field"
            );
            let value = match *field {
                "basic_auth_password" => serde_json::json!(""),
                "proxy_headers" => serde_json::json!({}),
                "forward_auth" => serde_json::json!({ "address": "" }),
                "mirror" => serde_json::json!({ "backend_ids": [] }),
                "mtls" => serde_json::json!({ "ca_cert_pem": "" }),
                other => panic!("{other}: give this test a clearing value for it"),
            };
            let create: CreateRouteRequest = serde_json::from_value(serde_json::json!({
                "hostname": "a.review.example.com",
                *field: value.clone(),
            }))
            .unwrap_or_else(|e| panic!("{field}: {e}"));
            let update: UpdateRouteRequest =
                serde_json::from_value(serde_json::json!({ *field: value }))
                    .unwrap_or_else(|e| panic!("{field}: {e}"));
            for refused in [refuse_withheld(&create), refuse_withheld(&update)] {
                match refused.expect_err(field) {
                    ApiError::Forbidden(message) => {
                        assert!(message.starts_with(field), "{message}")
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// A stored route with every protection at its create default.
    fn stored_route() -> Route {
        serde_json::from_value(serde_json::json!({
            "id": "r-1",
            "hostname": "pr-42.review.example.com",
            "path_prefix": "/",
            "load_balancing": "round_robin",
            "waf_enabled": false,
            "waf_mode": "detection",
            "enabled": true,
            "created_at": "2026-09-30T00:00:00Z",
            "updated_at": "2026-09-30T00:00:00Z",
        }))
        .expect("a minimal route")
    }

    /// Whether the guard's direction rules accept `after` over `before`.
    fn route_move(before: &Route, after: &Route) -> Result<(), ApiError> {
        ensure_not_weakened(ROUTE_PROTECTIONS, "route", &before.id, before, after)
    }

    /// The route `edit` makes of the stored row `base`.
    fn edited(base: &Route, edit: impl FnOnce(&mut Route)) -> Route {
        let mut route = base.clone();
        edit(&mut route);
        route
    }

    /// `strong` over `weak` is accepted, `weak` over `strong` refused
    /// naming `field` and echoing no value of either.
    fn only_strengthens(weak: &Route, strong: &Route, field: &str) {
        route_move(weak, strong).unwrap_or_else(|e| panic!("{field} strengthened: {e:?}"));
        route_move(strong, strong).unwrap_or_else(|e| panic!("{field} unchanged: {e:?}"));
        match route_move(strong, weak).expect_err(field) {
            ApiError::Forbidden(message) => {
                assert!(message.starts_with(field), "{message}");
                assert!(message.contains("dashboard"), "{message}");
                assert!(!message.contains("192.0.2"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_route_protection_moves_toward_stronger_and_never_back() {
        let base = stored_route();
        let with = |edit: fn(&mut Route)| edited(&base, edit);

        only_strengthens(
            &base,
            &with(|r| {
                r.basic_auth_username = Some("ops".into());
                r.basic_auth_password_hash = Some("$argon2id$stored".into());
            }),
            "basic_auth_username",
        );
        let protected = with(|r| {
            r.basic_auth_username = Some("ops".into());
            r.basic_auth_password_hash = Some("$argon2id$stored".into());
        });
        route_move(
            &protected,
            &edited(&protected, |r| r.basic_auth_username = Some("guest".into())),
        )
        .expect_err("a renamed credential");
        // A username with no password stored is not a credential in
        // force: setting or clearing it weakens nothing.
        let inert = with(|r| r.basic_auth_username = Some("ops".into()));
        route_move(&inert, &base).expect("no Basic auth was in force");

        only_strengthens(
            &with(|r| r.ip_allowlist = vec!["10.0.0.0/8".into()]),
            &with(|r| r.ip_allowlist = vec!["10.1.0.0/16".into(), "10.2.0.7".into()]),
            "ip_allowlist",
        );
        only_strengthens(
            &base,
            &with(|r| r.ip_allowlist = vec!["192.0.2.0/24".into()]),
            "ip_allowlist",
        );
        route_move(
            &with(|r| r.ip_allowlist = vec!["10.0.0.0/8".into()]),
            &with(|r| r.ip_allowlist = vec!["10.0.0.0/8".into(), "192.0.2.0/24".into()]),
        )
        .expect_err("an allowlist widened");

        only_strengthens(
            &with(|r| r.ip_denylist = vec!["192.0.2.10".into()]),
            &with(|r| r.ip_denylist = vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()]),
            "ip_denylist",
        );

        only_strengthens(
            &with(|r| {
                r.geoip = Some(lorica_config::models::GeoIpConfig {
                    mode: lorica_config::models::GeoIpMode::Allowlist,
                    countries: vec!["FR".into(), "DE".into()],
                })
            }),
            &with(|r| {
                r.geoip = Some(lorica_config::models::GeoIpConfig {
                    mode: lorica_config::models::GeoIpMode::Allowlist,
                    countries: vec!["FR".into()],
                })
            }),
            "geoip",
        );
        only_strengthens(
            &base,
            &with(|r| {
                r.geoip = Some(lorica_config::models::GeoIpConfig {
                    mode: lorica_config::models::GeoIpMode::Denylist,
                    countries: vec!["XX".into()],
                })
            }),
            "geoip",
        );
        route_move(
            &with(|r| {
                r.geoip = Some(lorica_config::models::GeoIpConfig {
                    mode: lorica_config::models::GeoIpMode::Denylist,
                    countries: vec!["XX".into()],
                })
            }),
            &with(|r| {
                r.geoip = Some(lorica_config::models::GeoIpConfig {
                    mode: lorica_config::models::GeoIpMode::Allowlist,
                    countries: vec!["FR".into()],
                })
            }),
        )
        .expect_err("a mode switched");

        let challenged = with(|r| {
            r.bot_protection = serde_json::from_value(serde_json::json!({ "mode": "cookie" }))
                .expect("a bot-protection config");
        });
        only_strengthens(&base, &challenged, "bot_protection");
        let bypassed = edited(&challenged, |r| {
            if let Some(config) = r.bot_protection.as_mut() {
                config.bypass.ip_cidrs.push("0.0.0.0/0".into());
            }
        });
        route_move(&challenged, &bypassed).expect_err("a bypass added");

        only_strengthens(&base, &with(|r| r.waf_enabled = true), "waf_enabled");
        only_strengthens(
            &base,
            &with(|r| r.waf_mode = lorica_config::models::WafMode::Blocking),
            "waf_mode",
        );

        let bucket = |capacity: u32, refill_per_sec: u32| lorica_config::models::RateLimit {
            capacity,
            refill_per_sec,
            scope: lorica_config::models::RateLimitScope::PerIp,
        };
        only_strengthens(
            &edited(&base, |r| r.rate_limit = Some(bucket(100, 10))),
            &edited(&base, |r| r.rate_limit = Some(bucket(50, 5))),
            "rate_limit",
        );
        only_strengthens(
            &base,
            &edited(&base, |r| r.rate_limit = Some(bucket(100, 10))),
            "rate_limit",
        );

        only_strengthens(
            &with(|r| r.rate_limit_rps = Some(100)),
            &with(|r| r.rate_limit_rps = Some(10)),
            "rate_limit_rps",
        );
        route_move(
            &with(|r| r.rate_limit_rps = Some(10)),
            &with(|r| {
                r.rate_limit_rps = Some(10);
                r.rate_limit_burst = Some(1_000);
            }),
        )
        .expect_err("a burst raised alone raises the capacity");
        only_strengthens(
            &base,
            &with(|r| r.rate_limit_rps = Some(10)),
            "rate_limit_rps",
        );

        only_strengthens(
            &with(|r| r.auto_ban_threshold = Some(50)),
            &with(|r| r.auto_ban_threshold = Some(5)),
            "auto_ban_threshold",
        );
        only_strengthens(
            &base,
            &with(|r| r.auto_ban_threshold = Some(5)),
            "auto_ban_threshold",
        );
    }

    #[test]
    fn a_route_field_outside_the_protections_moves_either_way() {
        // The rules bound the controls they name and nothing else: a
        // model still turns maintenance on and off, moves a timeout
        // both ways and edits the routing.
        let base = stored_route();
        let moved = edited(&base, |r| {
            r.maintenance_mode = true;
            r.read_timeout_s = 5;
            r.enabled = false;
            r.redirect_to = Some("https://pr-43.review.example.com".into());
        });
        route_move(&base, &moved).expect("either way");
        route_move(&moved, &base).expect("either way");
    }

    /// A stored backend inside the grant, plain HTTP.
    fn stored_backend() -> Backend {
        Backend {
            id: "b-1".to_string(),
            address: "10.0.0.10:8443".to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 1,
            health_status: lorica_config::models::HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_backend_trust_setting_moves_toward_stronger_and_never_back() {
        let store = ConfigStore::open_in_memory().expect("store");
        let guard = backend_guard(&principal());
        let check = |before: Option<&Backend>, after: &Backend| {
            guard.check(
                &store,
                crate::target::BackendTarget {
                    before,
                    after: Some(after),
                },
            )
        };
        let refused_naming = |result: Result<(), ApiError>, field: &str| match result {
            Err(ApiError::Forbidden(message)) => assert!(message.starts_with(field), "{message}"),
            other => panic!("{field}: {other:?}"),
        };
        let plain = stored_backend();
        let verified = Backend {
            tls_upstream: true,
            tls_sni: Some("api.review.example.com".into()),
            ..stored_backend()
        };
        let unverified = Backend {
            tls_skip_verify: true,
            ..verified.clone()
        };

        check(Some(&plain), &verified).expect("TLS turned on, verified");
        check(Some(&unverified), &verified).expect("verification turned on");
        refused_naming(check(Some(&verified), &unverified), "tls_skip_verify");
        refused_naming(check(Some(&verified), &plain), "tls_upstream");
        refused_naming(
            check(
                Some(&verified),
                &Backend {
                    tls_sni: Some("elsewhere.example.net".into()),
                    ..verified.clone()
                },
            ),
            "tls_sni",
        );
        check(
            Some(&unverified),
            &Backend {
                tls_sni: Some("elsewhere.example.net".into()),
                ..unverified.clone()
            },
        )
        .expect("an unverified leg verifies no name, so its SNI moves freely");

        // A create is weighed against the management create's default,
        // which verifies whenever TLS is on.
        check(None, &verified).expect("a verified create");
        check(None, &plain).expect("a plain create");
        refused_naming(check(None, &unverified), "tls_skip_verify");

        // The management plane is not bounded by any of it.
        crate::target::BackendGuard::unbounded()
            .check(
                &store,
                crate::target::BackendTarget {
                    before: Some(&verified),
                    after: Some(&unverified),
                },
            )
            .expect("an operator moves it either way");
    }

    #[test]
    fn a_bound_job_reaches_only_its_own_environment_through_the_route_path() {
        // `environment_protected = true` binds a job to the environment
        // it deploys. A route delete cascades its environment, so the
        // route path is held to the same binding as the environment
        // path: the job's own environment is reachable, a sibling of
        // the same project is not.
        use lorica_config::models::{
            AutomationEnvironment, CertificateMode, EnvironmentOwner, OwnerKind,
        };
        let store = ConfigStore::open_in_memory().expect("store");
        let now = chrono::Utc::now();
        for (name, route_id) in [("review-mr-42", "r-42"), ("review-mr-43", "r-43")] {
            let mut route = stored_route();
            route.id = route_id.to_string();
            route.hostname = format!("{name}.review.example.com");
            store.create_route(&route).expect("the route lands");
            store
                .upsert_automation_environment(&AutomationEnvironment {
                    name: name.to_string(),
                    route_id: route_id.to_string(),
                    owner: EnvironmentOwner {
                        kind: OwnerKind::OidcProject,
                        principal: "acme/web".to_string(),
                    },
                    certificate_mode: CertificateMode::Auto,
                    labels: std::collections::BTreeMap::new(),
                    expires_at: now + chrono::Duration::hours(1),
                    created_at: now,
                    updated_at: now,
                    last_pipeline: None,
                    pipeline: None,
                })
                .expect("the environment lands");
        }
        let job = AutomationPrincipal {
            kind: OwnerKind::OidcProject,
            principal: "acme/web".to_string(),
            required_environment_slug: Some("review-mr-42".to_string()),
            ..principal()
        };
        ensure_environment_granted(&store, &job, "review-mr-42", "route", "r-42")
            .expect("the job's own environment");
        match ensure_environment_granted(&store, &job, "review-mr-43", "route", "r-43")
            .expect_err("a sibling environment of the same project")
        {
            ApiError::Forbidden(message) => {
                assert!(message.contains("r-43"), "{message}");
                assert!(message.contains("environment_protected"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        let unbound = AutomationPrincipal {
            required_environment_slug: None,
            ..job
        };
        ensure_environment_granted(&store, &unbound, "review-mr-43", "route", "r-43")
            .expect("an unbound credential of the owner reaches every environment it owns");
    }

    #[test]
    fn a_certificate_id_on_a_route_write_needs_the_certificate_scope_and_a_preview_its_read_scope()
    {
        let routes_only = principal();
        ensure_certificate_binding_granted(&routes_only, None).expect("no binding named");
        for certificate_id in ["c-1", ""] {
            match ensure_certificate_binding_granted(&routes_only, Some(certificate_id))
                .expect_err("a binding under routes:write alone")
            {
                ApiError::Forbidden(message) => {
                    assert!(message.contains("certificates:write"), "{message}")
                }
                other => panic!("{other:?}"),
            }
        }
        let both = AutomationPrincipal {
            scopes: vec![
                AutomationScope::RoutesWrite,
                AutomationScope::CertificatesWrite,
            ],
            ..principal()
        };
        ensure_certificate_binding_granted(&both, Some("c-1")).expect("the scope is held");

        ensure_preview_readable(&routes_only, WriteMode::Apply, AutomationScope::RoutesRead)
            .expect("an apply needs no read scope");
        match ensure_preview_readable(
            &routes_only,
            WriteMode::Preview,
            AutomationScope::RoutesRead,
        )
        .expect_err("a preview answers the row")
        {
            ApiError::Forbidden(message) => assert!(message.contains("routes:read"), "{message}"),
            other => panic!("{other:?}"),
        }
        let reading = AutomationPrincipal {
            scopes: vec![AutomationScope::RoutesWrite, AutomationScope::RoutesRead],
            ..principal()
        };
        ensure_preview_readable(&reading, WriteMode::Preview, AutomationScope::RoutesRead)
            .expect("the read scope is held");
    }

    #[test]
    fn an_ipv4_mapped_address_is_weighed_as_the_ipv4_it_maps_to() {
        // `[::ffff:127.0.0.1]:80` parses as an IPv6 socket address and
        // connects to IPv4 loopback. A grant over a v6 range covering the
        // mapped space (`::/0`, `::ffff:0:0/96`) accepted it as v6 and
        // handed the token every IPv4 address there is; the same form
        // under a v4 grant was refused by the family mismatch. The
        // address is weighed as the IPv4 it maps to, on a claim and on
        // a stored row alike.
        let granted = |cidrs: &[&str]| AutomationPrincipal {
            allowed_backend_cidrs: cidrs.iter().map(|c| (*c).to_string()).collect(),
            ..principal()
        };
        let any_v6 = granted(&["::/0"]);
        let refused = ensure_backend_address_granted(&any_v6, "address", "[::ffff:127.0.0.1]:80")
            .expect_err("the report's input");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
        ensure_backend_address_granted(&any_v6, "address", "[2001:db8::10]:80")
            .expect("a real v6 address inside the grant");

        let mapped_space = granted(&["::ffff:0:0/96"]);
        let refused =
            ensure_backend_address_granted(&mapped_space, "address", "[::ffff:127.0.0.1]:80")
                .expect_err("a v6 grant over the mapped space grants no v4 address");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");

        let v4 = principal();
        ensure_backend_address_granted(&v4, "address", "[::ffff:10.0.0.10]:8080")
            .expect("weighed as 10.0.0.10, inside the grant");
        let refused = ensure_backend_address_granted(&v4, "address", "[::ffff:192.0.2.10]:8080")
            .expect_err("weighed as 192.0.2.10, outside the grant");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");

        // The guard over a stored row goes through the same function.
        let store = ConfigStore::open_in_memory().expect("store");
        let stored = Backend {
            id: "b-1".to_string(),
            address: "[::ffff:127.0.0.1]:80".to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 1,
            health_status: lorica_config::models::HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let refused = backend_guard(&any_v6)
            .check(
                &store,
                crate::target::BackendTarget {
                    before: Some(&stored),
                    after: None,
                },
            )
            .expect_err("the stored row is weighed the same way");
        assert!(matches!(refused, ApiError::Forbidden(_)), "{refused:?}");
    }

    #[test]
    fn a_stored_grant_whose_entries_do_not_parse_admits_no_address() {
        // The connection filter skips what it cannot parse, and an allow
        // list left empty by the skipping reads as every address. The
        // mint refuses such entries; a row stored before that rule, or
        // repaired by hand, reaches this guard without passing it again.
        for stored in [
            vec![String::new()],
            vec!["not-a-cidr".to_string()],
            vec!["10.0.0.0/33".to_string()],
            // One good entry does not rescue a list holding a bad one.
            vec!["10.0.0.0/8".to_string(), "   ".to_string()],
        ] {
            let unparsable = AutomationPrincipal {
                allowed_backend_cidrs: stored.clone(),
                ..principal()
            };
            for address in ["127.0.0.1:80", "169.254.169.254:80", "10.0.0.10:8080"] {
                let refused = ensure_backend_address_granted(&unparsable, "address", address)
                    .expect_err("an unparsable grant admits nothing");
                assert!(
                    matches!(refused, ApiError::Forbidden(_)),
                    "{stored:?} {address}: {refused:?}"
                );
            }
        }
    }

    #[test]
    fn an_empty_grant_admits_no_address_and_no_host_on_every_path_that_reads_one() {
        // Typed absence (2026-09-30): a credential with no grant-bounded
        // scope carries empty grants, and a row stored before the rule
        // can too. Empty must mean nothing on every consumer, never the
        // connection filter's own reading of an empty allow list as
        // every address. Walked over the claim checks and the guards a
        // write runs on the stored row.
        let empty = AutomationPrincipal {
            allowed_hostnames: Vec::new(),
            allowed_backend_cidrs: Vec::new(),
            ..principal()
        };
        for address in [
            "10.0.0.10:8080",
            "127.0.0.1:80",
            "169.254.169.254:80",
            "[::1]:80",
            "[::ffff:127.0.0.1]:80",
            "0.0.0.0:80",
        ] {
            let refused = ensure_backend_address_granted(&empty, "address", address)
                .expect_err("an empty CIDR grant admits no address");
            assert!(
                matches!(refused, ApiError::Forbidden(_)),
                "{address}: {refused:?}"
            );
        }
        for host in ["pr-42.review.example.com", "localhost", "example.com"] {
            assert!(!empty.allows_hostname(host), "{host}");
            let refused = ensure_hostnames_granted(&empty, Some(host), None)
                .expect_err("an empty hostname grant admits no host");
            assert!(
                matches!(refused, ApiError::Forbidden(_)),
                "{host}: {refused:?}"
            );
        }

        let store = ConfigStore::open_in_memory().expect("store");
        let stored = Backend {
            id: "b-1".to_string(),
            address: "10.0.0.10:8080".to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 1,
            health_status: lorica_config::models::HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let refused = backend_guard(&empty)
            .check(
                &store,
                crate::target::BackendTarget {
                    before: Some(&stored),
                    after: None,
                },
            )
            .expect_err("a stored backend is outside an empty grant");
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

    /// Every `settingsForm` field the dashboard's settings tabs bind to
    /// an editable input, read off the components themselves.
    ///
    /// A binding on an element carrying a bare `disabled` attribute is
    /// shown and not editable, so it is left out: the management port
    /// is displayed there and changed nowhere in the form.
    fn dashboard_form_vocabulary() -> BTreeSet<String> {
        let tabs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../lorica-dashboard/frontend/src/components/settings-tabs");
        let mut fields = BTreeSet::new();
        let mut components = 0usize;
        for entry in std::fs::read_dir(&tabs).expect("the settings tabs directory") {
            let path = entry.expect("a directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("svelte") {
                continue;
            }
            components += 1;
            let source = std::fs::read_to_string(&path).expect("a readable component");
            for line in source.lines() {
                let disabled = line
                    .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
                    .any(|token| token == "disabled");
                if disabled {
                    continue;
                }
                let mut remaining = line;
                while let Some(at) = remaining.find("={settingsForm.") {
                    let before = &remaining[..at];
                    let after = &remaining[at + "={settingsForm.".len()..];
                    let is_binding = ["bind:value", "bind:checked", "bind:group"]
                        .iter()
                        .any(|directive| before.ends_with(directive));
                    let name: String = after
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if is_binding && !name.is_empty() {
                        fields.insert(name);
                    }
                    remaining = after;
                }
            }
        }
        assert!(
            components > 0,
            "no settings tab read under {}",
            tabs.display()
        );
        assert!(
            !fields.is_empty(),
            "no `bind:...={{settingsForm.<field>}}` read in {components} settings tabs; the \
             parse went blind"
        );
        fields
    }

    #[test]
    fn every_allowlisted_setting_is_a_field_the_dashboard_form_edits_and_the_document_carries() {
        // AC #3: reversible from the dashboard means a human who lost the
        // MCP client finds the key on the dashboard's settings form. A
        // field the management request merely accepts is not enough:
        // only a hand-built request or a configuration import writes it.
        let document = serde_json::to_value(lorica_config::models::GlobalSettings::default())
            .expect("the settings document serialises");
        let document = document.as_object().expect("an object");
        let form = dashboard_form_vocabulary();
        let mut seen = BTreeSet::new();
        for setting in SETTINGS_ALLOWLIST {
            assert!(seen.insert(setting.name), "{} twice", setting.name);
            assert!(
                document.contains_key(setting.name),
                "{} is not a key of GlobalSettings",
                setting.name
            );
            assert!(
                !setting.why.trim().is_empty(),
                "{} has no reason",
                setting.name
            );
            assert!(
                form.contains(setting.name),
                "{} is bound to no editable field of the dashboard's settings form, so a human \
                 could not undo it there",
                setting.name
            );
        }
        assert!(
            SETTINGS_ALLOWLIST.len() < document.len(),
            "the allowlist is the whole document"
        );
    }

    #[test]
    fn every_allowlisted_bound_lies_inside_the_dashboards_own_and_never_reaches_zero() {
        // The tier is narrower than the dashboard or equal to it, never
        // wider: a bound the shared validator would refuse is a bound
        // this tier does not have. And no entry lets it write 0, which
        // on every one of them means off or unlimited.
        let schema = crate::settings::settings_schema();
        for setting in SETTINGS_ALLOWLIST {
            assert!(setting.min <= setting.max, "{}", setting.name);
            assert!(setting.min > 0, "{} lets the tier write 0", setting.name);
            let shared = &schema[setting.name];
            assert!(
                shared.is_object(),
                "{} publishes no bound in the settings schema",
                setting.name
            );
            if let Some(min) = shared["min"].as_i64() {
                assert!(
                    setting.min >= min,
                    "{} below the shared minimum",
                    setting.name
                );
            }
            if let Some(max) = shared["max"].as_i64() {
                assert!(
                    setting.max <= max,
                    "{} above the shared maximum",
                    setting.name
                );
            }
        }
    }

    #[test]
    fn the_retention_ceiling_is_ten_times_the_shipped_default() {
        let defaults = lorica_config::models::GlobalSettings::default();
        for shipped in [defaults.access_log_retention, defaults.waf_event_retention] {
            assert_eq!(RETENTION_TIER_CEILING_ROWS, shipped * 10);
        }
        for name in ["access_log_retention", "waf_event_retention"] {
            let setting = admin_setting(name).expect("allowlisted");
            assert_eq!(setting.max, RETENTION_TIER_CEILING_ROWS, "{name}");
            assert!(
                setting
                    .refusal(1_000, RETENTION_TIER_CEILING_ROWS + 1)
                    .is_some(),
                "{name} above the ceiling"
            );
        }
    }

    #[test]
    fn a_setting_reaches_the_fleet_exactly_when_the_fleet_replicates_it() {
        let canonical =
            serde_json::to_value(lorica_config::canonical::CanonicalGlobalSettings::from(
                &lorica_config::models::GlobalSettings::default(),
            ))
            .expect("the canonical settings serialise");
        let replicated = canonical.as_object().expect("an object");
        for setting in SETTINGS_ALLOWLIST {
            assert_eq!(
                setting.reach == Reach::Fleet,
                replicated.contains_key(setting.name),
                "{} says {:?}",
                setting.name,
                setting.reach
            );
        }
    }

    #[test]
    fn a_value_is_refused_outside_its_bound_and_against_its_direction() {
        let retention = admin_setting("access_log_retention").expect("allowlisted");
        assert_eq!(retention.refusal(100, 100), None);
        assert_eq!(retention.refusal(100, 500), None);
        let lowered = retention.refusal(500, 100).expect("a retention lowered");
        assert!(lowered.starts_with("access_log_retention: 100 is below the stored 500"));
        assert!(lowered.contains(&retention.bound_text()), "{lowered}");
        let unlimited = retention.refusal(100, 0).expect("unlimited");
        assert!(unlimited.contains("outside"), "{unlimited}");

        let warning = admin_setting("cert_warning_days").expect("allowlisted");
        assert_eq!(warning.bound_text(), "14..=365");
        assert_eq!(
            warning.refusal(30, 14),
            None,
            "either direction inside the bound"
        );
        assert_eq!(warning.refusal(30, 365), None);
        let hidden = warning.refusal(30, 2).expect("an expiry hidden");
        assert!(
            hidden.starts_with("cert_warning_days: 2 is outside"),
            "{hidden}"
        );
        assert!(warning.refusal(30, 366).is_some());
    }

    #[test]
    fn the_tier_bounds_weigh_the_keys_the_body_sets_and_no_other() {
        let stored = lorica_config::models::GlobalSettings {
            waf_ban_threshold: 1,
            ..Default::default()
        };
        // A key the body does not set is not weighed, even when the
        // dashboard left it outside the tier's bound.
        let body: SettingsPatch = Map::from_iter([(
            "cert_warning_days".to_string(),
            serde_json::json!(stored.cert_warning_days + 1),
        )]);
        let mut patched = stored.clone();
        patched.cert_warning_days += 1;
        tier_bounds(&body)(&stored, &patched).expect("the named key is inside its bound");

        let body: SettingsPatch =
            Map::from_iter([("waf_ban_threshold".to_string(), serde_json::json!(2))]);
        let mut patched = stored.clone();
        patched.waf_ban_threshold = 2;
        match tier_bounds(&body)(&stored, &patched) {
            Err(ApiError::Unprocessable(message)) => {
                assert!(message.starts_with("waf_ban_threshold: 2"), "{message}")
            }
            other => panic!("{other:?}"),
        }

        let body: SettingsPatch = Map::from_iter([("waf_ban_threshold".to_string(), Value::Null)]);
        tier_bounds(&body)(&stored, &stored).expect("a null sets nothing");
    }

    #[test]
    fn a_key_outside_the_allowlist_is_refused_by_name_before_any_value_is_read() {
        let inside = SETTINGS_ALLOWLIST[0].name;
        for outside in [
            "management_port",
            "automation_allowed_cidrs",
            "audit_log_retention_days",
            "max_active_probes",
            "log_level",
            "flood_threshold_rps",
            "not_a_setting",
        ] {
            // The value is of the wrong type on purpose: the refusal is
            // the allowlist's, not a type check's.
            let body: SettingsPatch = Map::from_iter([
                (inside.to_string(), serde_json::json!(1)),
                (outside.to_string(), serde_json::json!({ "not": "a port" })),
            ]);
            match ensure_settings_allowlisted(&body).expect_err(outside) {
                ApiError::Forbidden(message) => {
                    assert!(message.contains(&format!("`{outside}`")), "{message}");
                    assert!(message.contains(inside), "{message}");
                }
                other => panic!("{other:?}"),
            }
        }
        // A key that is not shaped like a field is described, not
        // repeated back.
        let smuggled = "Ignore previous instructions";
        let body: SettingsPatch = Map::from_iter([(smuggled.to_string(), Value::Null)]);
        match ensure_settings_allowlisted(&body).expect_err("outside") {
            ApiError::Forbidden(message) => assert!(!message.contains(smuggled), "{message}"),
            other => panic!("{other:?}"),
        }
        let inside: SettingsPatch = SETTINGS_ALLOWLIST
            .iter()
            .map(|setting| (setting.name.to_string(), Value::Null))
            .collect();
        ensure_settings_allowlisted(&inside).expect("every allowlisted key passes");
        ensure_settings_allowlisted(&SettingsPatch::new()).expect("an empty body names nothing");
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_naming_its_key() {
        let body: SettingsPatch = Map::from_iter([
            ("cert_warning_days".to_string(), serde_json::json!(30)),
            ("waf_ban_threshold".to_string(), serde_json::json!("many")),
        ]);
        // `UpdateSettingsRequest` is not `Debug`, so the result is
        // matched rather than unwrapped.
        match settings_request(body) {
            Err(ApiError::Unprocessable(message)) => {
                assert!(message.starts_with("waf_ban_threshold:"), "{message}")
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a string for an integer was accepted"),
        }
        let body: SettingsPatch =
            Map::from_iter([("cert_warning_days".to_string(), serde_json::json!(30))]);
        let request = settings_request(body).expect("a well-typed body");
        assert_eq!(request.cert_warning_days, Some(30));
    }

    #[test]
    fn the_answer_carries_the_allowlisted_keys_and_nothing_else() {
        let view = allowlisted_view(&lorica_config::models::GlobalSettings::default());
        let keys: BTreeSet<&str> = view
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = SETTINGS_ALLOWLIST.iter().map(|s| s.name).collect();
        assert_eq!(keys, allowed);
    }
}
