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

//! The protections of a route a token deleted, held against what the
//! plane writes next (backlog #93, maintainer decision of 2026-11-04).
//!
//! # The gap
//!
//! A token's route write is held to [`ROUTE_PROTECTIONS`] against the
//! row it replaces and against every stored route it would take a
//! request from. A token whose grant lets it delete a route could still
//! delete a protected one and create it again without its protections:
//! once deleted, the route was no longer there to be weighed against.
//!
//! # The record
//!
//! A route deleted through this plane that carries at least one control
//! of [`ROUTE_PROTECTIONS`] in force leaves a
//! [`RouteProtectionRecord`]: the deleted row itself, as the store held
//! it. "In force" is the predicates' own answer: a control is in force
//! when the route the management create stores for a body naming none
//! of the controls ([`as_created_bare`]) is weaker on it. Nothing here
//! lists a control.
//!
//! The record stands for the route it was made of, switched on, and is
//! weighed the way that route would be: every later write of this plane
//! that would make a route serve a name and path the deleted route
//! would serve today, through the proxy's own selection
//! ([`records_displaced_by`]), is held to the same predicates against
//! it. A token's write is refused naming the control and the record; the
//! environment resource, which cannot be refused there, takes the
//! recorded controls over instead, as it takes a displaced route's.
//!
//! # A record is kept, not consumed
//!
//! A write that matches or strengthens a record lands and leaves it in
//! place. Consuming it would trust the write to cover everything the
//! deleted route served, and a record of a wildcard or of a route with
//! aliases is matched by a write serving one name of it: consumed, it
//! would let the next write take the other names weaker. Kept, it costs
//! a matching route nothing, since that route is itself held in place by
//! the same rules. A later token delete of a route of the same names and
//! path replaces a record it is at least as strong as, so a loop of
//! deletes and creates leaves one row. An operator clears a record in
//! the dashboard, or by writing a route that serves one of its names
//! (`crate::route_protection_records`).
//!
//! # What makes no record
//!
//! A delete through the dashboard, whose session the rule never bound.
//! And a route an environment owns: the environment resource rewrites
//! that route's controls from its profile on every `PUT`, so the plane
//! never held them in place, and a record would bind the pipeline to a
//! choice it may undo without deleting anything. What such a route took
//! over from a protected route is still held by that route, which is
//! still stored, or by its record.

use std::collections::BTreeSet;

use lorica_config::models::{Route, RouteProtectionRecord};
use lorica_config::route_selection::HostIndex;
use lorica_config::ConfigStore;

use super::write::{first_weakened, Protection, ROUTE_PROTECTIONS};
use crate::error::ApiError;
use crate::route_protection_records::{
    record_view, RECORD_CREATE_ACTION, RECORD_SUPERSEDE_ACTION, RECORD_TARGET_TYPE,
};
use crate::target::{RouteTarget, SettledRow};

/// The route the management create stores when the body names nothing
/// but its hostname: every control of [`ROUTE_PROTECTIONS`] at its
/// weakest. The fields spelled here are the ones the model requires;
/// every other field is the model's own default. A test holds this row
/// to the one the management create actually stores, control by
/// control, through the predicates.
fn as_created_bare() -> Result<Route, ApiError> {
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

/// A record and the route it stands for, switched on: a disabled route
/// serves nothing, and its controls were held in place all the same, so
/// a write that would switch a route on for those names is weighed.
pub(super) struct Recorded {
    pub(super) record: RouteProtectionRecord,
    pub(super) route: Route,
}

/// Every record in the store, read back.
///
/// A record whose snapshot does not read fails closed: the write is
/// refused naming the record, so an operator reads and clears it in the
/// dashboard, rather than the record weighing nothing.
pub(super) fn recorded(store: &ConfigStore) -> Result<Vec<Recorded>, ApiError> {
    store
        .list_route_protection_records()?
        .into_iter()
        .map(|record| match record.route() {
            Ok(mut route) => {
                route.enabled = true;
                Ok(Recorded { record, route })
            }
            Err(_) => Err(ApiError::Forbidden(format!(
                "route protection record `{}` cannot be read, so this node cannot tell \
                 whether this write takes over the protections it holds; an operator clears \
                 it in the dashboard",
                record.id
            ))),
        })
        .collect()
}

/// Every record `after` would take a request from, each once, in the
/// order found: for each name `after` answers to and each path it would
/// serve, the pick once `after` replaces its own row in `stored` is
/// `after`, and the pick from `stored` with every record's route beside
/// it is that record's. A stored route wins a tie against a record, so a
/// record shadowed by a route serving the same name and path today is
/// not weighed: that route is, in place.
///
/// The paths weighed are `after`'s prefix and every stored or recorded
/// prefix below it, the only places where the pick can change. A
/// disabled `after` serves nothing and takes nothing.
pub(super) fn records_displaced_by<'r>(
    stored: &[Route],
    recorded: &'r [Recorded],
    after: &Route,
) -> Vec<&'r Recorded> {
    let mut displaced: Vec<&'r Recorded> = Vec::new();
    if !after.enabled || recorded.is_empty() {
        return displaced;
    }
    let with_records = HostIndex::new(
        stored.iter().map(|route| (None, route)).chain(
            recorded
                .iter()
                .enumerate()
                .map(|(index, entry)| (Some(index), &entry.route)),
        ),
        route_of,
    );
    let tomorrow = HostIndex::new(
        stored
            .iter()
            .filter(|route| route.id != after.id)
            .chain(std::iter::once(after)),
        |route| *route,
    );
    let paths: BTreeSet<&str> = std::iter::once(after.path_prefix.as_str())
        .chain(
            stored
                .iter()
                .map(|route| route.path_prefix.as_str())
                .chain(
                    recorded
                        .iter()
                        .map(|entry| entry.route.path_prefix.as_str()),
                )
                .filter(|prefix| prefix.starts_with(after.path_prefix.as_str())),
        )
        .collect();
    let names = std::iter::once(&after.hostname).chain(&after.hostname_aliases);
    for name in names {
        for path in &paths {
            let taken = tomorrow.select(name, path, |route| *route);
            if taken.map(|route| route.id.as_str()) != Some(after.id.as_str()) {
                continue;
            }
            let Some((Some(index), _)) = with_records.select(name, path, route_of) else {
                continue;
            };
            let Some(record) = recorded.get(*index) else {
                continue;
            };
            if !displaced
                .iter()
                .any(|known| known.record.id == record.record.id)
            {
                displaced.push(record);
            }
        }
    }
    displaced
}

/// The route of an index entry: a stored route (`None`) or the route of
/// the record at that index.
fn route_of<'e>(entry: &'e (Option<usize>, &Route)) -> &'e Route {
    entry.1
}

/// A token's route about to be written, weighed against every record it
/// would take a request from ([`records_displaced_by`]), exactly as it
/// is weighed against a stored route it displaces.
///
/// The refusal names the control and the record's id, and nothing of
/// what the record holds.
pub(super) fn ensure_no_record_displaced_weaker(
    store: &ConfigStore,
    after: &Route,
) -> Result<(), ApiError> {
    if !after.enabled {
        return Ok(());
    }
    let recorded = recorded(store)?;
    if recorded.is_empty() {
        return Ok(());
    }
    let stored = store.list_routes()?;
    for displaced in records_displaced_by(&stored, &recorded, after) {
        if let Some(protection) = first_weakened(ROUTE_PROTECTIONS, &displaced.route, after) {
            return Err(ApiError::Forbidden(format!(
                "{}: route protection record `{}` holds the protections of a route an \
                 automation token deleted, which served this route's host, and this route \
                 would serve it weaker on that control. A token's route may only match or \
                 strengthen it ({}), because {}; set it in the dashboard, or clear the record \
                 there",
                protection.fields.join(" / "),
                displaced.record.id,
                protection.rule,
                protection.why
            )));
        }
    }
    Ok(())
}

/// Whether two records stand for the same names and path.
fn same_identity(a: &RouteProtectionRecord, b: &RouteProtectionRecord) -> bool {
    let aliases = |record: &RouteProtectionRecord| -> BTreeSet<String> {
        record
            .hostname_aliases
            .iter()
            .map(|alias| alias.to_ascii_lowercase())
            .collect()
    };
    a.hostname.eq_ignore_ascii_case(&b.hostname)
        && a.path_prefix == b.path_prefix
        && aliases(a) == aliases(b)
}

/// The automation guard's settle: a route a token deleted, carrying a
/// control in force and owned by no environment, leaves its record.
///
/// A record of the same names and path that the deleted route is at
/// least as strong as, on every control, is replaced by the new one and
/// audited as superseded; one it is weaker than on some control stays
/// beside it, so no recorded control is lost. Runs in the transaction
/// that deletes the route, so the record commits with the delete.
///
/// # Errors
///
/// A store failure, which rolls the delete back with it.
pub(super) fn record_deleted_protections(
    store: &ConfigStore,
    actor: &str,
    target: RouteTarget<'_>,
) -> Result<Vec<SettledRow>, ApiError> {
    let (Some(deleted), None) = (target.before, target.after) else {
        return Ok(Vec::new());
    };
    if deleted.managed_by.is_some() || controls_in_force(deleted)?.is_empty() {
        return Ok(Vec::new());
    }
    let record = RouteProtectionRecord::of_deleted(deleted, actor, chrono::Utc::now())?;
    let mut rows = Vec::new();
    for existing in store.list_route_protection_records()? {
        if !same_identity(&existing, &record) {
            continue;
        }
        let Ok(existing_route) = existing.route() else {
            continue;
        };
        if first_weakened(ROUTE_PROTECTIONS, &existing_route, deleted).is_some() {
            continue;
        }
        store.delete_route_protection_record(&existing.id)?;
        rows.push(SettledRow {
            action: RECORD_SUPERSEDE_ACTION,
            target_type: RECORD_TARGET_TYPE,
            target_id: existing.id.clone(),
            before: Some(record_view(&existing)),
            after: Some(serde_json::json!({ "superseded_by": record.id })),
        });
    }
    store.create_route_protection_record(&record)?;
    rows.push(SettledRow {
        action: RECORD_CREATE_ACTION,
        target_type: RECORD_TARGET_TYPE,
        target_id: record.id.clone(),
        before: None,
        after: Some(record_view(&record)),
    });
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(id: &str, hostname: &str, path_prefix: &str) -> Route {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": hostname,
            "path_prefix": path_prefix,
            "load_balancing": "round_robin",
            "waf_enabled": false,
            "waf_mode": "detection",
            "enabled": true,
            "created_at": "2026-11-04T00:00:00Z",
            "updated_at": "2026-11-04T00:00:00Z",
        }))
        .expect("test setup: a route")
    }

    /// A route with every control of [`ROUTE_PROTECTIONS`] in force,
    /// held to that by the first assertion of the test that uses it.
    fn fortified(id: &str, hostname: &str) -> Route {
        let mut route = route(id, hostname, "/");
        route.basic_auth_username = Some("user01".into());
        route.basic_auth_password_hash = Some("$argon2id$stored".into());
        route.ip_allowlist = vec!["192.0.2.0/24".into()];
        route.ip_denylist = vec!["198.51.100.0/24".into()];
        route.geoip = Some(lorica_config::models::GeoIpConfig {
            mode: lorica_config::models::GeoIpMode::Allowlist,
            countries: vec!["FR".into()],
        });
        route.bot_protection = serde_json::from_value(serde_json::json!({ "mode": "cookie" }))
            .expect("a bot-protection config");
        route.waf_enabled = true;
        route.waf_mode = lorica_config::models::WafMode::Blocking;
        route.rate_limit = Some(lorica_config::models::RateLimit {
            capacity: 10,
            refill_per_sec: 5,
            scope: lorica_config::models::RateLimitScope::PerIp,
        });
        route.auto_ban_threshold = Some(5);
        route
    }

    fn recorded_of(deleted: &Route) -> Recorded {
        let record = RouteProtectionRecord::of_deleted(deleted, "ci (0123)", chrono::Utc::now())
            .expect("a record");
        let mut route = record.route().expect("reads");
        route.enabled = true;
        Recorded { record, route }
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
            let mut alone = route("r-2", "app.example.com", "/");
            (protection.strengthened)(&strong, &mut alone);
            let in_force: Vec<&[&str]> = controls_in_force(&alone)
                .expect("weighs")
                .iter()
                .map(|protection| protection.fields)
                .collect();
            assert_eq!(in_force, vec![protection.fields], "{:?}", protection.fields);
        }
    }

    #[test]
    fn a_record_is_weighed_by_every_protection_exactly_as_a_displaced_route_would_be() {
        // For each control alone: the bare recreate takes the record
        // over weaker on that control and is refused by its predicate,
        // and the recreate carrying the control as recorded is not.
        let strong = fortified("r-1", "app.example.com");
        for protection in ROUTE_PROTECTIONS {
            let mut deleted = route("r-1", "app.example.com", "/");
            (protection.strengthened)(&strong, &mut deleted);
            let recorded = vec![recorded_of(&deleted)];
            let bare = route("r-2", "app.example.com", "/");
            let displaced = records_displaced_by(&[], &recorded, &bare);
            assert_eq!(displaced.len(), 1, "{:?}", protection.fields);
            let refused = first_weakened(ROUTE_PROTECTIONS, &displaced[0].route, &bare)
                .expect("the bare recreate is weaker");
            assert_eq!(refused.fields, protection.fields);
            let mut matching = bare.clone();
            (protection.strengthened)(&displaced[0].route, &mut matching);
            assert!(
                first_weakened(ROUTE_PROTECTIONS, &displaced[0].route, &matching).is_none(),
                "{:?}: a matching recreate is refused",
                protection.fields
            );
        }
    }

    #[test]
    fn a_record_is_taken_over_through_the_proxys_own_selection() {
        let mut aliased = fortified("gone", "app.example.com");
        aliased.hostname_aliases = vec!["www.example.com".into()];
        aliased.path_prefix = "/api".into();
        let recorded = vec![recorded_of(&aliased)];
        let ids = |after: &Route, stored: &[Route]| -> usize {
            records_displaced_by(stored, &recorded, after).len()
        };

        // An alias is a name the record serves; a path below its prefix
        // is served by it; a path beside it is not.
        assert_eq!(ids(&route("n", "www.example.com", "/"), &[]), 1);
        assert_eq!(ids(&route("n", "app.example.com", "/api/v2"), &[]), 1);
        assert_eq!(ids(&route("n", "app.example.com", "/public"), &[]), 0);
        // `/` on that host takes `/api` from the record too.
        assert_eq!(ids(&route("n", "app.example.com", "/"), &[]), 1);
        // Another host takes nothing; a disabled route takes nothing.
        assert_eq!(ids(&route("n", "other.example.com", "/"), &[]), 0);
        let mut off = route("n", "app.example.com", "/api");
        off.enabled = false;
        assert_eq!(ids(&off, &[]), 0);

        // A stored route on the same name and path shadows the record:
        // an update of that route is weighed against itself in place.
        let shadow = route("s", "app.example.com", "/api");
        let mut updated = shadow.clone();
        updated.read_timeout_s = 5;
        assert_eq!(ids(&updated, std::slice::from_ref(&shadow)), 0);

        // A recorded wildcard is taken by any exact name under it.
        let wildcard = vec![recorded_of(&fortified("w", "*.example.com"))];
        assert_eq!(
            records_displaced_by(&[], &wildcard, &route("n", "a.example.com", "/")).len(),
            1
        );
        assert_eq!(
            records_displaced_by(&[], &wildcard, &route("n", "example.org", "/")).len(),
            0
        );

        // A disabled deleted route is recorded switched on.
        let mut disabled = fortified("d", "off.example.com");
        disabled.enabled = false;
        let recorded = vec![recorded_of(&disabled)];
        assert_eq!(
            records_displaced_by(&[], &recorded, &route("n", "off.example.com", "/")).len(),
            1
        );
    }

    #[test]
    fn a_token_delete_records_a_protected_route_once_and_nothing_else() {
        let store = ConfigStore::open_in_memory().expect("store");
        let delete = |route: &Route| {
            record_deleted_protections(
                &store,
                "ci (0123)",
                RouteTarget {
                    before: Some(route),
                    after: None,
                    backend_ids: None,
                },
            )
            .expect("settles")
        };

        // Nothing in force, nothing recorded.
        assert!(delete(&route("r-0", "plain.example.com", "/")).is_empty());
        // An environment's route, nothing recorded.
        let mut managed = fortified("r-e", "env.example.com");
        managed.managed_by = Some(lorica_config::models::ManagedBy::Automation {
            environment: "review-1".into(),
        });
        assert!(delete(&managed).is_empty());
        assert!(store
            .list_route_protection_records()
            .expect("list")
            .is_empty());

        // A protected route, one record, audited without a value.
        let strong = fortified("r-1", "app.example.com");
        let rows = delete(&strong);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, RECORD_CREATE_ACTION);
        let audited = serde_json::to_string(&rows[0].after).expect("serialises");
        for value in ["$argon2id$stored", "192.0.2.0", "198.51.100.0", "user01"] {
            assert!(!audited.contains(value), "{audited}");
        }
        let first = store.list_route_protection_records().expect("list");
        assert_eq!(first.len(), 1);

        // Deleted again as strong: the new record replaces the old one.
        let rows = delete(&fortified("r-2", "app.example.com"));
        assert_eq!(
            rows.iter().map(|row| row.action).collect::<Vec<_>>(),
            vec![RECORD_SUPERSEDE_ACTION, RECORD_CREATE_ACTION]
        );
        assert_eq!(rows[0].target_id, first[0].id);
        let second = store.list_route_protection_records().expect("list");
        assert_eq!(second.len(), 1);
        assert_ne!(second[0].id, first[0].id);

        // Deleted weaker on a control (imported weaker, say): both stay.
        let mut weaker = fortified("r-3", "app.example.com");
        weaker.waf_enabled = false;
        let rows = delete(&weaker);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            store.list_route_protection_records().expect("list").len(),
            2
        );
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
