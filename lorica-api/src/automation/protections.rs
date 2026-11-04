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

//! The controls an automation token may only strengthen, and how a row
//! is weighed against them (the maintainer's decision of 2026-09-30,
//! "safe direction only").
//!
//! The rules are `lorica-automation-policy`'s, so `lorica-mcp` reads
//! the same statement; this module pairs each with the predicate that
//! weighs it on this crate's row types, and answers which of them are in
//! force on a route. It reads no store and knows no token: the guards in
//! `super::write` and the records in `super::records` are what apply it.

use lorica_automation_policy::protections::{
    backend as backend_rule, route as route_rule, ProtectionRule,
};
use lorica_config::models::{Backend, Route};

use crate::error::ApiError;

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
    /// Raises the second row to the first on this control, for a row
    /// that takes the control over instead of being refused: an
    /// environment's route (`super::displacement::inherit_displaced_protections`). Called
    /// only where `weakened` holds, after which it no longer does; a
    /// test holds every rule to that.
    pub strengthened: fn(&T, &mut T),
}

impl<T> Protection<T> {
    /// `policy`, weighed by `weakened` and raised by `strengthened`.
    const fn weighing(
        policy: ProtectionRule,
        weakened: fn(&T, &T) -> bool,
        strengthened: fn(&T, &mut T),
    ) -> Protection<T> {
        Protection {
            fields: policy.fields,
            rule: policy.rule,
            why: policy.why,
            weakened,
            strengthened,
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
    Protection::weighing(
        route_rule::BASIC_AUTH,
        basic_auth_weakened,
        adopt_basic_auth,
    ),
    Protection::weighing(
        route_rule::FORWARD_AUTH,
        forward_auth_weakened,
        adopt_forward_auth,
    ),
    Protection::weighing(route_rule::MTLS, mtls_weakened, adopt_mtls),
    Protection::weighing(
        route_rule::IP_ALLOWLIST,
        allowlist_weakened,
        adopt_allowlist,
    ),
    Protection::weighing(route_rule::IP_DENYLIST, denylist_weakened, extend_denylist),
    Protection::weighing(route_rule::GEOIP, geoip_weakened, adopt_geoip),
    Protection::weighing(
        route_rule::BOT_PROTECTION,
        bot_protection_weakened,
        adopt_bot_protection,
    ),
    Protection::weighing(route_rule::WAF_ENABLED, waf_switched_off, switch_waf_on),
    Protection::weighing(route_rule::WAF_MODE, waf_mode_weakened, adopt_waf_mode),
    Protection::weighing(
        route_rule::RATE_LIMIT,
        rate_limit_weakened,
        adopt_rate_limit,
    ),
    Protection::weighing(
        route_rule::AUTO_BAN_THRESHOLD,
        auto_ban_weakened,
        adopt_auto_ban,
    ),
    Protection::weighing(
        route_rule::CASE_INSENSITIVE_PATHS,
        case_folding_switched_off,
        switch_case_folding_on,
    ),
];

/// Every backend control an automation token may only strengthen:
/// `BACKEND_PROTECTION_RULES`, each with its predicate, held to that
/// list by the same test.
pub const BACKEND_PROTECTIONS: &[Protection<Backend>] = &[
    Protection::weighing(
        backend_rule::TLS_SKIP_VERIFY,
        verification_switched_off,
        adopt_verification,
    ),
    Protection::weighing(
        backend_rule::TLS_UPSTREAM,
        upstream_tls_switched_off,
        switch_upstream_tls_on,
    ),
    Protection::weighing(
        backend_rule::TLS_SNI,
        verified_name_changed,
        adopt_verified_name,
    ),
];

/// The first rule of `protections` that `after` breaks against
/// `before`.
pub(super) fn first_weakened<'p, T>(
    protections: &'p [Protection<T>],
    before: &T,
    after: &T,
) -> Option<&'p Protection<T>> {
    protections
        .iter()
        .find(|protection| (protection.weakened)(before, after))
}

/// The first rule of `protections` that `after` breaks against
/// `before`, refused with a 403 naming the field and the rule and
/// echoing neither value.
pub(super) fn ensure_not_weakened<T>(
    protections: &[Protection<T>],
    kind: &str,
    id: &str,
    before: &T,
    after: &T,
) -> Result<(), ApiError> {
    match first_weakened(protections, before, after) {
        Some(protection) => Err(ApiError::Forbidden(format!(
            "{} on {kind} `{id}` may only be strengthened by an automation token: {}, because \
             {}; weaken it in the dashboard",
            protection.fields.join(" / "),
            protection.rule,
            protection.why
        ))),
        None => Ok(()),
    }
}

/// The route the management create stores when the body names nothing
/// but its hostname: every control of [`ROUTE_PROTECTIONS`] at its
/// weakest. The fields spelled here are the ones the model requires;
/// every other field is the model's own default. A test holds this row
/// to the one the management create actually stores, control by
/// control, through the predicates.
pub(crate) fn as_created_bare() -> Result<Route, ApiError> {
    serde_json::from_value(serde_json::json!({
        "id": "",
        "hostname": "",
        "path_prefix": "/",
        "load_balancing": "round_robin",
        "waf_enabled": false,
        "waf_mode": "detection",
        "enabled": true,
        "created_at": "1970-01-01T00:00:00Z",
        "updated_at": "1970-01-01T00:00:00Z",
    }))
    .map_err(|e| ApiError::Internal(format!("the bare route does not build: {e}")))
}

/// Every control of [`ROUTE_PROTECTIONS`] in force on `route`: those a
/// route created with none of them named would be weaker on.
///
/// # Errors
///
/// [`ApiError::Internal`] if the bare route does not build.
pub fn controls_in_force(route: &Route) -> Result<Vec<&'static Protection<Route>>, ApiError> {
    let bare = as_created_bare()?;
    Ok(ROUTE_PROTECTIONS
        .iter()
        .filter(|protection| (protection.weakened)(route, &bare))
        .collect())
}

/// A route on `hostname` and `path_prefix` with every control at its
/// weakest: what the management create stores for that body.
#[cfg(test)]
pub(crate) fn bare_route(id: &str, hostname: &str, path_prefix: &str) -> Route {
    let mut route = as_created_bare().expect("test setup: the bare route");
    route.id = id.to_string();
    route.hostname = hostname.to_string();
    route.path_prefix = path_prefix.to_string();
    route
}

/// A route with every control of [`ROUTE_PROTECTIONS`] in force, held
/// to that by `in_force_is_the_predicates_answer_for_every_control_and_each_alone`,
/// so a control added to the table without a value here turns it red.
#[cfg(test)]
pub(crate) fn fortified(id: &str, hostname: &str) -> Route {
    let mut route = bare_route(id, hostname, "/");
    route.basic_auth_username = Some("user01".into());
    route.basic_auth_password_hash = Some("$argon2id$stored".into());
    route.forward_auth = Some(lorica_config::models::ForwardAuthConfig {
        address: "http://auth.internal.example.org:9091/verify".into(),
        timeout_ms: 5_000,
        response_headers: Vec::new(),
        verdict_cache_ttl_ms: 0,
    });
    route.mtls = Some(lorica_config::models::MtlsConfig {
        ca_cert_pem: "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n".into(),
        required: true,
        allowed_organizations: Vec::new(),
    });
    route.ip_allowlist = vec!["192.0.2.0/24".into()];
    route.ip_denylist = vec!["198.51.100.0/24".into()];
    route.geoip = Some(lorica_config::models::GeoIpConfig {
        mode: lorica_config::models::GeoIpMode::Allowlist,
        countries: vec!["FR".into()],
    });
    route.bot_protection = serde_json::from_value(serde_json::json!({ "mode": "cookie" }))
        .expect("test setup: a bot-protection config");
    route.waf_enabled = true;
    route.waf_mode = lorica_config::models::WafMode::Blocking;
    route.rate_limit = Some(lorica_config::models::RateLimit {
        capacity: 10,
        refill_per_sec: 5,
        scope: lorica_config::models::RateLimitScope::PerIp,
    });
    route.auto_ban_threshold = Some(5);
    route.case_insensitive_paths = true;
    route
}

fn basic_auth_weakened(before: &Route, after: &Route) -> bool {
    let in_force =
        before.basic_auth_username.is_some() && before.basic_auth_password_hash.is_some();
    in_force
        && (before.basic_auth_username != after.basic_auth_username
            || before.basic_auth_password_hash != after.basic_auth_password_hash)
}

/// A gate a token cannot send: weakened by any route that does not
/// carry it exactly as set, which every token's route is.
fn forward_auth_weakened(before: &Route, after: &Route) -> bool {
    before.forward_auth.is_some() && before.forward_auth != after.forward_auth
}

fn mtls_weakened(before: &Route, after: &Route) -> bool {
    before.mtls.is_some() && before.mtls != after.mtls
}

/// An allowlist or denylist entry as the proxy compiles it, through
/// the workspace's one address parser: a CIDR, or a bare address as its
/// host network. `None` for what the proxy skips.
fn listed_network(entry: &str) -> Option<ipnet::IpNet> {
    lorica_config::connection_filter::parse_cidr(entry).ok()
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

/// The bucket the proxy builds for the route, the structured
/// `rate_limit` when set and the legacy pair otherwise
/// ([`Route::effective_rate_limit`]), so adding a generous structured
/// bucket over a strict legacy rate reads as the raise it is.
fn rate_limit_weakened(before: &Route, after: &Route) -> bool {
    let Some(stored) = before.effective_rate_limit() else {
        return false;
    };
    let Some(patched) = after.effective_rate_limit() else {
        return true;
    };
    patched.capacity > stored.capacity
        || patched.refill_per_sec > stored.refill_per_sec
        || patched.scope != stored.scope
}

fn auto_ban_weakened(before: &Route, after: &Route) -> bool {
    match (before.auto_ban_threshold, after.auto_ban_threshold) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(stored), Some(patched)) => patched > stored,
    }
}

/// The stored credential, hash and all, never a password: the row is
/// copied server side and the hash stays in the store.
fn adopt_basic_auth(from: &Route, to: &mut Route) {
    to.basic_auth_username.clone_from(&from.basic_auth_username);
    to.basic_auth_password_hash
        .clone_from(&from.basic_auth_password_hash);
}

/// The gate as the dashboard set it, copied server side: the
/// environment resource's route takes it over, and no answer, audit row
/// or log carries its address.
fn adopt_forward_auth(from: &Route, to: &mut Route) {
    to.forward_auth.clone_from(&from.forward_auth);
}

/// The trust anchor and its requirement as the dashboard set them,
/// copied server side.
fn adopt_mtls(from: &Route, to: &mut Route) {
    to.mtls.clone_from(&from.mtls);
}

fn adopt_allowlist(from: &Route, to: &mut Route) {
    to.ip_allowlist.clone_from(&from.ip_allowlist);
}

/// The union: every parsed entry `to` does not already cover is added,
/// so neither list loses an address it refused.
fn extend_denylist(from: &Route, to: &mut Route) {
    let missing: Vec<String> = from
        .ip_denylist
        .iter()
        .filter(|entry| listed_network(entry).is_some_and(|net| !covered(&net, &to.ip_denylist)))
        .cloned()
        .collect();
    to.ip_denylist.extend(missing);
}

fn adopt_geoip(from: &Route, to: &mut Route) {
    to.geoip.clone_from(&from.geoip);
}

fn adopt_bot_protection(from: &Route, to: &mut Route) {
    to.bot_protection.clone_from(&from.bot_protection);
}

fn switch_waf_on(_from: &Route, to: &mut Route) {
    to.waf_enabled = true;
}

fn adopt_waf_mode(from: &Route, to: &mut Route) {
    to.waf_mode = from.waf_mode.clone();
}

/// Both spellings, so the bucket the proxy builds is the displaced
/// route's whichever of them it was set with.
fn adopt_rate_limit(from: &Route, to: &mut Route) {
    to.rate_limit.clone_from(&from.rate_limit);
    to.rate_limit_rps = from.rate_limit_rps;
    to.rate_limit_burst = from.rate_limit_burst;
}

fn adopt_auto_ban(from: &Route, to: &mut Route) {
    to.auto_ban_threshold = from.auto_ban_threshold;
}

fn case_folding_switched_off(before: &Route, after: &Route) -> bool {
    before.case_insensitive_paths && !after.case_insensitive_paths
}

fn switch_case_folding_on(_from: &Route, to: &mut Route) {
    to.case_insensitive_paths = true;
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

fn adopt_verification(from: &Backend, to: &mut Backend) {
    to.tls_skip_verify = from.tls_skip_verify;
}

fn switch_upstream_tls_on(_from: &Backend, to: &mut Backend) {
    to.tls_upstream = true;
}

fn adopt_verified_name(from: &Backend, to: &mut Backend) {
    to.tls_sni.clone_from(&from.tls_sni);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_automation_policy::{BACKEND_PROTECTION_RULES, ROUTE_PROTECTION_RULES};

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

    #[test]
    fn in_force_is_the_predicates_answer_for_every_control_and_each_alone() {
        // Walked over the table: a control added to ROUTE_PROTECTIONS is
        // in force on the fortified route (or this fixture turns red),
        // and a route carrying it alone has it, and only it, in force.
        let bare = as_created_bare().expect("the bare route");
        assert!(controls_in_force(&bare).expect("weighs").is_empty());
        let strong = fortified("r-1", "app.example.com");
        let in_force: Vec<&[&str]> = controls_in_force(&strong)
            .expect("weighs")
            .iter()
            .map(|protection| protection.fields)
            .collect();
        let every: Vec<&[&str]> = ROUTE_PROTECTIONS.iter().map(|p| p.fields).collect();
        assert_eq!(
            in_force, every,
            "the fixture leaves a control at its weakest"
        );
        for protection in ROUTE_PROTECTIONS {
            let mut alone = bare_route("r-2", "app.example.com", "/");
            (protection.strengthened)(&strong, &mut alone);
            let in_force: Vec<&[&str]> = controls_in_force(&alone)
                .expect("weighs")
                .iter()
                .map(|protection| protection.fields)
                .collect();
            assert_eq!(in_force, vec![protection.fields], "{:?}", protection.fields);
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

        // The legacy pair is weighed as the bucket the proxy builds from
        // it, under the same rule, whose refusal names `rate_limit` first.
        only_strengthens(
            &with(|r| r.rate_limit_rps = Some(100)),
            &with(|r| r.rate_limit_rps = Some(10)),
            "rate_limit",
        );
        route_move(
            &with(|r| r.rate_limit_rps = Some(10)),
            &with(|r| {
                r.rate_limit_rps = Some(10);
                r.rate_limit_burst = Some(1_000);
            }),
        )
        .expect_err("a burst raised alone raises the capacity");
        only_strengthens(&base, &with(|r| r.rate_limit_rps = Some(10)), "rate_limit");

        // Security audit L1: the structured bucket replaces the legacy one
        // outright, so one added over a strict legacy rate is weighed
        // against that rate, never against "no structured bucket yet".
        let strict_legacy = with(|r| r.rate_limit_rps = Some(10));
        route_move(
            &strict_legacy,
            &edited(&strict_legacy, |r| {
                r.rate_limit = Some(bucket(1_000_000, 1_000_000))
            }),
        )
        .expect_err("a generous structured bucket lifts the legacy rate");
        route_move(
            &strict_legacy,
            &edited(&strict_legacy, |r| r.rate_limit = Some(bucket(10, 5))),
        )
        .expect("a structured bucket at most as wide as the legacy one");
        // And a structured bucket in force hides the legacy pair, so the
        // pair alone moves nothing the proxy enforces.
        let structured = edited(&strict_legacy, |r| r.rate_limit = Some(bucket(10, 5)));
        route_move(
            &structured,
            &edited(&structured, |r| r.rate_limit_rps = Some(1_000)),
        )
        .expect("the legacy pair under a structured bucket is not enforced");
        route_move(&structured, &edited(&structured, |r| r.rate_limit = None))
            .expect_err("removing the structured bucket falls back to a wider legacy one");

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

        only_strengthens(
            &base,
            &with(|r| r.case_insensitive_paths = true),
            "case_insensitive_paths",
        );
    }

    #[test]
    fn every_protection_raises_a_weaker_row_to_the_stronger_one() {
        // The environment resource inherits a displaced route's controls
        // through each rule's `strengthened`: walked over the tables, so
        // a rule whose raise leaves the row weaker turns this red.
        let weak = stored_route();
        let strong = fortified(&weak.id, &weak.hostname);
        for protection in ROUTE_PROTECTIONS {
            assert!(
                (protection.weakened)(&strong, &weak),
                "{:?}: the fixture does not set this control",
                protection.fields
            );
            let mut raised = weak.clone();
            (protection.strengthened)(&strong, &mut raised);
            assert!(
                !(protection.weakened)(&strong, &raised),
                "{:?}: raising leaves the row weaker",
                protection.fields
            );
        }

        let mut verified = stored_backend();
        verified.tls_upstream = true;
        verified.tls_sni = Some("upstream.internal.example.org".into());
        let mut unverified = stored_backend();
        unverified.tls_skip_verify = true;
        for protection in BACKEND_PROTECTIONS {
            assert!(
                (protection.weakened)(&verified, &unverified),
                "{:?}: the fixture does not set this control",
                protection.fields
            );
            let mut raised = unverified.clone();
            (protection.strengthened)(&verified, &mut raised);
            assert!(
                !(protection.weakened)(&verified, &raised),
                "{:?}: raising leaves the row weaker",
                protection.fields
            );
        }
    }

    #[test]
    fn a_denylist_is_raised_to_the_union_and_keeps_its_own_entries() {
        let base = stored_route();
        let displaced = edited(&base, |r| {
            r.ip_denylist = vec!["198.51.100.0/24".into(), "203.0.113.7".into()]
        });
        let mut own = edited(&base, |r| {
            r.ip_denylist = vec!["192.0.2.0/24".into(), "203.0.113.0/24".into()]
        });
        extend_denylist(&displaced, &mut own);
        assert_eq!(
            own.ip_denylist,
            vec![
                "192.0.2.0/24".to_string(),
                "203.0.113.0/24".to_string(),
                "198.51.100.0/24".to_string(),
            ],
            "an entry already covered is not repeated, and none is dropped"
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

    #[tokio::test]
    async fn the_bare_route_is_the_one_the_management_create_stores() {
        // `as_created_bare` spells the model's required fields; the
        // management create is what decides each default. Weighed both
        // ways through every predicate, the two rows are the same.
        let (state, session_store, rate_limiter) = crate::tests::test_state().await;
        let admin =
            crate::tests::setup_admin_and_login(&state, &session_store, &rate_limiter).await;
        let created = crate::tests::send(
            &state,
            &session_store,
            &rate_limiter,
            "POST",
            "/api/v1/routes",
            &admin,
            Some(serde_json::json!({ "hostname": "bare.example.com" })),
        )
        .await;
        assert_eq!(created.status(), axum::http::StatusCode::CREATED);
        let id = crate::tests::parse_data(created).await["id"]
            .as_str()
            .expect("route id")
            .to_string();
        let stored = state
            .store
            .lock()
            .await
            .get_route(&id)
            .expect("store")
            .expect("the route");
        let bare = as_created_bare().expect("the bare route");
        for protection in ROUTE_PROTECTIONS {
            assert!(
                !(protection.weakened)(&stored, &bare) && !(protection.weakened)(&bare, &stored),
                "{:?}: the bare route and the management create disagree",
                protection.fields
            );
        }
    }
}
