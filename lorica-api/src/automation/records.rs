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
//! of the controls is weaker on it ([`controls_in_force`]). Nothing here
//! lists a control.
//!
//! The record stands for the route it was made of, switched on, and is
//! weighed the way that route would be: every later write of this plane
//! that would make a route serve a name and path the deleted route
//! would serve today is held to the same predicates against it, through
//! the one weighing of what a write takes requests from
//! (`super::displacement`), where a record sits beside the stored
//! routes. A token's write is refused naming the control and the record;
//! the environment resource, which cannot be refused there, takes the
//! recorded controls over instead, as it takes a displaced route's.
//!
//! # A record that does not read binds its own names, and only them
//!
//! A record whose snapshot does not read is weighed as a route carrying
//! nothing on its names and path, which the store keeps apart from the
//! snapshot, and a write that would take a request from it is refused
//! naming it, so an operator reads and clears it in the dashboard rather
//! than the record weighing nothing. A write elsewhere never reads it.
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
use lorica_config::route_selection::same_name;
use lorica_config::ConfigStore;

use super::protections::{as_created_bare, controls_in_force, first_weakened, ROUTE_PROTECTIONS};
use crate::error::ApiError;
use crate::route_protection_records::{
    record_view, RECORD_CREATE_ACTION, RECORD_SUPERSEDE_ACTION, RECORD_TARGET_TYPE,
};
use crate::target::{RouteTarget, SettledRow};

/// A record and the route it stands for, switched on: a disabled route
/// serves nothing, and its controls were held in place all the same, so
/// a write that would switch a route on for those names is weighed.
pub(super) struct Recorded {
    pub(super) record: RouteProtectionRecord,
    /// The recorded route, or, when the snapshot does not read, a route
    /// on the record's names and path carrying nothing.
    pub(super) route: Route,
    /// Whether the snapshot read. A record that did not is never
    /// weighed: a write that would take a request from it is refused.
    pub(super) readable: bool,
}

impl Recorded {
    /// `record` read back, or stood in for when its snapshot does not
    /// read.
    fn of(record: RouteProtectionRecord) -> Result<Recorded, ApiError> {
        let (mut route, readable) = match record.route() {
            Ok(route) => (route, true),
            Err(_) => {
                let mut stand_in = as_created_bare()?;
                stand_in.id.clone_from(&record.route_id);
                stand_in.hostname.clone_from(&record.hostname);
                stand_in
                    .hostname_aliases
                    .clone_from(&record.hostname_aliases);
                stand_in.path_prefix.clone_from(&record.path_prefix);
                (stand_in, false)
            }
        };
        route.enabled = true;
        Ok(Recorded {
            record,
            route,
            readable,
        })
    }

    /// The refusal of a write that would take a request from a record
    /// that does not read: the node cannot tell what it would weaken.
    pub(super) fn unreadable(&self) -> ApiError {
        ApiError::Forbidden(format!(
            "route protection record `{}` cannot be read, so this node cannot tell whether this \
             write takes over the protections it holds; an operator clears it in the dashboard",
            self.record.id
        ))
    }
}

/// Every record holding one of `names`, read back, found through the
/// store's index on the names and decoding no other record.
pub(super) fn recorded_naming(
    store: &ConfigStore,
    names: &[&str],
) -> Result<Vec<Recorded>, ApiError> {
    store
        .route_protection_records_naming(names)?
        .into_iter()
        .map(Recorded::of)
        .collect()
}

/// Whether two records stand for the same names and path.
fn same_identity(a: &RouteProtectionRecord, b: &RouteProtectionRecord) -> bool {
    let holds_every_name_of = |one: &RouteProtectionRecord, other: &RouteProtectionRecord| {
        other
            .names()
            .all(|name| one.names().any(|held| same_name(held, name)))
    };
    a.path_prefix == b.path_prefix && holds_every_name_of(a, b) && holds_every_name_of(b, a)
}

/// The automation guard's settle: a route a token deleted, carrying a
/// control in force and owned by no environment, leaves its record.
///
/// A record of the same names and path that the deleted route is at
/// least as strong as, on every control, is replaced by the new one and
/// audited as superseded; one it is weaker than on some control stays
/// beside it, so no recorded control is lost, and so does one that does
/// not read, which an operator clears. Runs in the transaction that
/// deletes the route, so the record commits with the delete.
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
    let names: BTreeSet<&str> = record.names().collect();
    let names: Vec<&str> = names.into_iter().collect();
    let mut rows = Vec::new();
    for existing in store.route_protection_records_naming(&names)? {
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
pub(super) mod tests {
    use super::*;
    use crate::automation::protections::{bare_route as route, fortified};

    /// `deleted`'s record, read back as the plane weighs it.
    pub(in crate::automation) fn recorded_of(deleted: &Route) -> Recorded {
        let record = RouteProtectionRecord::of_deleted(deleted, "ci (0123)", chrono::Utc::now())
            .expect("a record");
        Recorded::of(record).expect("reads")
    }

    #[test]
    fn a_record_whose_snapshot_does_not_read_stands_in_on_its_names_alone() {
        let mut record = RouteProtectionRecord::of_deleted(
            &fortified("gone", "app.example.com"),
            "ci (0123)",
            chrono::Utc::now(),
        )
        .expect("a record");
        record.route = serde_json::json!("not a route");
        let recorded = Recorded::of(record).expect("stands in");
        assert!(!recorded.readable);
        assert_eq!(recorded.route.hostname, "app.example.com");
        assert!(recorded.route.enabled);
        assert!(controls_in_force(&recorded.route)
            .expect("weighs")
            .is_empty());
        assert!(matches!(
            recorded.unreadable(),
            ApiError::Forbidden(message) if message.contains("cannot be read")
        ));
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
}
