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
//! Four route fields are refused from a token outright, whatever their
//! value: `forward_auth`, whose address is a URL the CIDR grant cannot
//! weigh and to which the proxy forwards every downstream `Cookie` and
//! `Authorization` header; `mirror`, which ships a copy of every
//! request to a second set of backends; `mtls`, the route's
//! client-authentication trust anchor; and `proxy_headers`, a static
//! header map to the upstream, where a credential would go. The config
//! tier's tools offer none of them.
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
//! lock. The plane is the control and the MCP tool's schema, which
//! restates the same keys and bounds and is pinned against this
//! constant by `tests/openapi_contract.rs`, is the affordance: a token
//! holding `settings:write` reaches the same keys whether it calls the
//! tool or the path. A preview and an apply answer the allowlisted part
//! of the document and nothing else, so the scope that writes those
//! keys reads back exactly those keys and needs no read scope beside
//! it.

use std::collections::BTreeSet;

use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use lorica_config::models::{AutomationScope, Backend, ManagedBy, Route};
use lorica_config::ConfigStore;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::auth::AutomationPrincipal;
use super::environments::{audit_context, caller_may_access, ensure_backend_address_granted};
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

/// Which way the admin tier may move a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Anywhere inside the bound.
    Either,
    /// Up from the stored value, never below it, and inside the bound:
    /// a retention lowered destroys rows that setting it back does not
    /// bring back.
    RaiseOnly,
}

/// How far a setting's effect reaches when it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Fleet policy (`CanonicalGlobalSettings`): on a control plane it
    /// replicates to every follower.
    Fleet,
    /// This node only.
    Node,
}

impl Reach {
    /// How an operator reads it, in `docs/mcp.md`'s settings table and
    /// in the blast radius `lorica mcp token create --tier admin` prints.
    pub fn describe(self) -> &'static str {
        match self {
            Reach::Fleet => "fleet",
            Reach::Node => "this node",
        }
    }
}

/// When a stored value starts to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakesEffect {
    /// On the next reload or the next run of the loop that reads it,
    /// without a restart.
    Live,
    /// At the next restart of the process that reads it.
    Restart,
}

impl TakesEffect {
    /// How an operator reads it, in the same two places as
    /// [`Reach::describe`].
    pub fn describe(self) -> &'static str {
        match self {
            TakesEffect::Live => "live",
            TakesEffect::Restart => "at restart",
        }
    }
}

/// One global setting the admin tier may change, why it may, and how
/// far it may move it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSetting {
    /// The key, as `GlobalSettings` and `UpdateSettingsRequest` spell it.
    pub name: &'static str,
    /// Why a model driving the admin tier may change it: what makes it
    /// operational, and why a value inside its bound is undone from the
    /// dashboard without having taken anything down.
    pub why: &'static str,
    /// The lowest value this tier may set, inclusive. The dashboard's
    /// own validator still runs after this one and may be narrower.
    pub min: i64,
    /// The highest value this tier may set, inclusive.
    pub max: i64,
    /// Which way inside `min..=max` this tier may move it.
    pub direction: Direction,
    /// Where a write lands.
    pub reach: Reach,
    /// When a write acts.
    pub takes_effect: TakesEffect,
}

impl AdminSetting {
    /// The bound as the docs, the tool description and a refusal spell
    /// it: `14..=365`, or `raise-only, 1..=100000000`.
    pub fn bound_text(&self) -> String {
        match self.direction {
            Direction::Either => format!("{}..={}", self.min, self.max),
            Direction::RaiseOnly => format!("raise-only, {}..={}", self.min, self.max),
        }
    }

    /// Why `after` is not a value this tier may store when `before` is
    /// stored, or `None` when it may.
    pub fn refusal(&self, before: i64, after: i64) -> Option<String> {
        if !(self.min..=self.max).contains(&after) {
            return Some(format!(
                "{}: {after} is outside what an automation token may set ({}); set it in the \
                 dashboard",
                self.name,
                self.bound_text()
            ));
        }
        if self.direction == Direction::RaiseOnly && after < before {
            return Some(format!(
                "{}: {after} is below the stored {before}, and an automation token may only \
                 raise it ({}); lower it in the dashboard",
                self.name,
                self.bound_text()
            ));
        }
        None
    }
}

/// Every setting `PUT /automation/v1/settings` accepts: the admin tier's
/// whole surface (Story 11.3 AC #1), decided by exclusion, each with
/// the bound and the direction this tier may move it in.
///
/// The one statement of it. The plane refuses any other key with a 403
/// before a validator runs, and a value outside its entry's bound with
/// a 422 naming the key and the bound, on the document it is about to
/// write. The MCP tool restates the names and the bounds, the
/// `SettingsPatch` schema the names and the bounds, `docs/mcp.md` the
/// whole row; tests pin each against this constant.
///
/// A key is here only when a model reading attacker-authored text can
/// move it in a direction that harms nothing: every entry has a safe
/// direction, a bound, and a dashboard field that undoes it (AC #3).
///
/// What is NOT here is the decision, and its reasons are in the story
/// (`docs/stories/story-11.3-admin-tier.md`) and in `docs/mcp.md`, by
/// family: anything that can lock the operator out of the management
/// plane (its port, its TLS pair, the connection and automation
/// allowlists, the trusted proxies); credentials and trust anchors
/// (the bot HMAC secret, the scrape token and its switch, the upgrade
/// signing key, the certificate export family); identity policy;
/// data-plane capacity and mirroring concurrency, which are reversible
/// and not harmless; the telemetry and log-sink destinations, since a
/// redirect is not visibly wrong; `audit_log_retention_days`, because
/// retention protecting the audit of this tier is not this tier's to
/// shorten; and the probe and load-test budgets the dashboard has no
/// write path for, so a value set here could not be undone there
/// (AC #3), which `docs/backlog.md` records.
///
/// Taken out on 2026-09-28, each for a reason the first list missed:
/// `flood_threshold_rps`, because either direction harms (lowered it
/// makes every per-IP bucket answer 429, at 0 it switches the flood
/// defence off); `flood_strict_rps` and `header_timeout_s`, because the
/// dashboard has no field for them, so a value set here could not be
/// undone there (`docs/backlog.md` #89); `sla_purge_enabled`, because
/// off means unbounded growth; `sla_purge_schedule`, because the only
/// direction it moves is purges more often; and `log_level`, because it
/// has no safe direction: raised it floods the disk and writes request
/// detail into the logs, lowered it blinds the investigation.
///
/// Every later request to add an entry will be reasonable on its own
/// terms. An entry arrives with its reason and its bound or not at all.
pub const SETTINGS_ALLOWLIST: &[AdminSetting] = &[
    AdminSetting {
        name: "access_log_retention",
        why: "retention of the persistent access-log buffer; raised, it keeps more history, \
              and 0 (unlimited) is refused because the table then grows until the disk fills",
        min: 1,
        max: 100_000_000,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "waf_event_retention",
        why: "retention of the persistent WAF-event buffer, the data plane's security trail; \
              raised, it keeps more of it, and 0 (unlimited) is refused",
        min: 1,
        max: 100_000_000,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "sla_purge_retention_days",
        why: "how long SLA buckets are kept; raised, it keeps more history and purges nothing \
              sooner",
        min: 1,
        max: 3650,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "cert_warning_days",
        why: "when a certificate expiry raises a warning; an alert threshold, no traffic \
              effect, and no lower than two weeks so an expiry cannot be hidden",
        min: 14,
        max: 365,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "cert_critical_days",
        why: "when a certificate expiry raises a critical alert; an alert threshold, no \
              traffic effect, and no lower than three days",
        min: 3,
        max: 365,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "waf_ban_threshold",
        why: "how many WAF blocks earn an automatic ban; a protection threshold, never so \
              low that one false positive bans a shared address and never so high that \
              auto-ban is off in practice",
        min: 3,
        max: 100,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "waf_ban_duration_s",
        why: "how long an automatic WAF ban lasts; a ban keeps the duration it was issued \
              with, so a day at most, and never so short that a ban does nothing",
        min: 60,
        max: 86_400,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "default_health_check_interval_s",
        why: "the fallback health-check interval; a probe budget read on every cycle, bounded \
              far below the dashboard's own ceiling because a dead backend keeps its traffic \
              for three probes of whatever interval is set",
        min: 5,
        max: 60,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
    AdminSetting {
        name: "health_max_concurrent_probes",
        why: "the cap on concurrent health probes; a probe budget, never so low that a few \
              unreachable backends starve the probes of every other",
        min: 16,
        max: 512,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
    },
];

/// The entry of [`SETTINGS_ALLOWLIST`] named `key`.
fn admin_setting(key: &str) -> Option<&'static AdminSetting> {
    SETTINGS_ALLOWLIST
        .iter()
        .find(|setting| setting.name == key)
}

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

/// The four route fields a token may not send at all, whatever the
/// value, a clearing one included.
///
/// `forward_auth.address` is any absolute URL: the CIDR grant cannot
/// weigh it, and the proxy forwards every downstream `Cookie` and
/// `Authorization` header to it, so a model-authored body could send
/// every visitor's session off-site or make the proxy call a metadata
/// address per request. `mirror` ships a copy of every request,
/// credentials included, to a second set of backends. `mtls` is the
/// route's client-authentication trust anchor: the CA bundle whose
/// client certificates the route accepts, so a model reading attacker
/// text that could replace it would let every client certificate the
/// attacker mints through. `proxy_headers` is a static header map sent
/// to the upstream on every request, which is where a credential would
/// go, so a model must neither choose one nor clear one (the
/// maintainer's decision, 2026-09-23). None is the tier's in either
/// direction; all four are set in the dashboard, by a human, and the
/// tools do not offer them.
fn refuse_unbounded_reach(
    forward_auth: bool,
    mirror: bool,
    mtls: bool,
    proxy_headers: bool,
) -> Result<(), ApiError> {
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
    if mtls {
        return Err(ApiError::Forbidden(
            "mtls is not accepted from an automation token: it is the route's \
             client-authentication trust anchor, the CA whose client certificates the route \
             accepts; set it in the dashboard"
                .to_string(),
        ));
    }
    if proxy_headers {
        return Err(ApiError::Forbidden(
            "proxy_headers is not accepted from an automation token: a static header map to \
             the upstream is where a credential would go; set it in the dashboard"
                .to_string(),
        ));
    }
    Ok(())
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
/// other principal's environment (403), `forward_auth`, `mirror`, `mtls`
/// and `proxy_headers` are refused (403), and `certificate_id` needs
/// `certificates:write` (403). With `?dry_run=true`, which needs
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
    refuse_unbounded_reach(
        body.forward_auth.is_some(),
        body.mirror.is_some(),
        body.mtls.is_some(),
        body.proxy_headers.is_some(),
    )?;
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
/// environment, `forward_auth`, `mirror`, `mtls` and `proxy_headers` are
/// refused, and `certificate_id` needs `certificates:write` (403 each). With
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
    refuse_unbounded_reach(
        body.forward_auth.is_some(),
        body.mirror.is_some(),
        body.mtls.is_some(),
        body.proxy_headers.is_some(),
    )?;
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
/// its current hostname and every current alias (403). Selecting a
/// certificate is naming its id here; what the id names entered the
/// node through the management API. With `?dry_run=true`, which needs
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
/// rule the environment resource applies to its backends. With
/// `?dry_run=true`, which needs `backends:read` (403), the backend it
/// would have created, and nothing created.
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
    let (status, answer) =
        crate::backends::create_backend_as(&state, &actor, body, WriteMode::from(dry_run)).await?;
    Ok((status, redact::write_answer(answer, redact::backend_row)))
}

/// `PUT /automation/v1/backends/{id}` (scope `backends:write`).
///
/// The management backend update, as the token, the managed-row
/// refusal (409) included. The backend named must sit inside the
/// token's `allowed_backend_cidrs` on its stored address and belong to
/// no other principal's environment (403); an address the patch names
/// is checked against the grant exactly as on create. With
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
    fn forward_auth_mirror_mtls_and_proxy_headers_are_refused_from_a_token_whatever_the_value() {
        refuse_unbounded_reach(false, false, false, false).expect("no such field");
        for (forward_auth, mirror, mtls, proxy_headers, field) in [
            (true, false, false, false, "forward_auth"),
            (false, true, false, false, "mirror"),
            (false, false, true, false, "mtls"),
            (false, false, false, true, "proxy_headers"),
            (true, true, true, true, "forward_auth"),
        ] {
            match refuse_unbounded_reach(forward_auth, mirror, mtls, proxy_headers)
                .expect_err(field)
            {
                ApiError::Forbidden(message) => assert!(message.starts_with(field), "{message}"),
                other => panic!("{other:?}"),
            }
        }
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
            .check(&store, &stored)
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
            .check(&store, &stored)
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
