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

//! What a route write would take requests from, and how the row is
//! held to it.
//!
//! A route of this plane is weighed against every holder of the traffic
//! it would take: a stored route a wildcard or the catch-all serves
//! today, and the record of a protected route a token deleted
//! (`super::records`), which stands for that route as if it were still
//! stored. Both sit in one index, built once per write through the
//! proxy's own selection (`lorica_config::route_selection`), so a rule
//! on how a route takes a host over is written once. A stored route wins
//! a tie against a record, so a record shadowed by a route serving the
//! same name and path today is not weighed there: that route is, in
//! place.
//!
//! A token's row is refused on the first control it would serve weaker
//! ([`ensure_not_displaced_weaker`]); the environment resource's row,
//! written from a fixed profile the pipeline cannot shape, takes the
//! controls over instead ([`inherit_displaced_protections`]).

use std::collections::BTreeSet;

use lorica_config::models::Route;
use lorica_config::route_selection::{keys_reaching, HostIndex};
use lorica_config::ConfigStore;

use super::protections::{first_weakened, Protection, ROUTE_PROTECTIONS};
use super::records::{recorded_naming, Recorded};
use crate::error::ApiError;

/// Something that serves a host today, as the index holds it.
#[derive(Clone, Copy)]
pub(super) enum Holder<'a> {
    /// A stored route.
    Route(&'a Route),
    /// The record of a protected route a token deleted.
    Record(&'a Recorded),
}

impl<'a> Holder<'a> {
    /// The route this holder serves the host as.
    fn route(&self) -> &'a Route {
        match *self {
            Holder::Route(route) => route,
            Holder::Record(recorded) => &recorded.route,
        }
    }

    /// Whether `self` and `other` are the same row.
    fn same_as(&self, other: &Holder<'_>) -> bool {
        match (self, other) {
            (Holder::Route(a), Holder::Route(b)) => a.id == b.id,
            (Holder::Record(a), Holder::Record(b)) => a.record.id == b.record.id,
            _ => false,
        }
    }

    /// The refusal of a token's route that would serve this holder's
    /// host weaker on `protection`, naming the holder by id and nothing
    /// of its values.
    fn refusal(&self, protection: &Protection<Route>) -> ApiError {
        let (named, recourse) = match self {
            Holder::Route(route) => (
                format!(
                    "route `{}` serves this route's host today, and this route would take it \
                     over weaker on that control",
                    route.id
                ),
                "set it in the dashboard",
            ),
            Holder::Record(recorded) => (
                format!(
                    "route protection record `{}` holds the protections of a route an \
                     automation token deleted, which served this route's host, and this route \
                     would serve it weaker on that control",
                    recorded.record.id
                ),
                "set it in the dashboard, or clear the record there",
            ),
        };
        ApiError::Forbidden(format!(
            "{}: {named}. A token's route may only match or strengthen it ({}), because {}; \
             {recourse}",
            protection.fields.join(" / "),
            protection.rule,
            protection.why
        ))
    }
}

/// The rows a route write is weighed against, read once per write: every
/// stored route, and the records holding a name the write's route could
/// be selected for.
pub(super) struct Serving {
    stored: Vec<Route>,
    recorded: Vec<Recorded>,
}

impl Serving {
    /// What serves the hosts `after` answers to: every stored route, and
    /// every record holding a key the selection of one of those hosts
    /// can reach ([`keys_reaching`]), so no other record is read.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub(super) fn read(store: &ConfigStore, after: &Route) -> Result<Serving, ApiError> {
        let keys: BTreeSet<String> = std::iter::once(&after.hostname)
            .chain(&after.hostname_aliases)
            .flat_map(|name| keys_reaching(name))
            .collect();
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        Ok(Serving {
            stored: store.list_routes()?,
            recorded: recorded_naming(store, &keys)?,
        })
    }

    /// This, without the stored route `id`: what serves its hosts with
    /// that route's own row taken away.
    fn without(mut self, id: &str) -> Serving {
        self.stored.retain(|route| route.id != id);
        self
    }

    /// Every stored route and record.
    fn holders(&self) -> impl Iterator<Item = Holder<'_>> {
        self.stored
            .iter()
            .map(Holder::Route)
            .chain(self.recorded.iter().map(Holder::Record))
    }

    /// Every holder `after` would take a request from, each once, in the
    /// order found: for each name `after` answers to and each path it
    /// would serve, the pick once `after` replaces its own row is
    /// `after`, and the pick today is that holder. `after`'s own stored
    /// row is no holder: an update is weighed against it in place. A
    /// disabled `after` serves nothing and takes nothing.
    ///
    /// The paths weighed are `after`'s prefix and every held prefix
    /// below it, the only places where the pick can change.
    pub(super) fn displaced_by(&self, after: &Route) -> Vec<Holder<'_>> {
        let mut displaced: Vec<Holder<'_>> = Vec::new();
        if !after.enabled {
            return displaced;
        }
        let today = HostIndex::new(self.holders(), |holder| holder.route());
        let tomorrow = HostIndex::new(
            self.stored
                .iter()
                .filter(|route| route.id != after.id)
                .chain(std::iter::once(after)),
            |route| *route,
        );
        let paths: BTreeSet<&str> = std::iter::once(after.path_prefix.as_str())
            .chain(
                self.holders()
                    .map(|holder| holder.route().path_prefix.as_str())
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
                let Some(holder) = today.select(name, path, |holder| holder.route()) else {
                    continue;
                };
                if matches!(holder, Holder::Route(route) if route.id == after.id) {
                    continue;
                }
                if !displaced.iter().any(|known| known.same_as(holder)) {
                    displaced.push(*holder);
                }
            }
        }
        displaced
    }
}

/// A token's route about to be written, weighed against every holder of
/// the traffic it would take ([`Serving::displaced_by`]): `after` is held
/// to [`ROUTE_PROTECTIONS`] against each, exactly as an update is held
/// against the row it replaces, and a record that does not read refuses
/// it outright.
///
/// Without this, an exact name created under an operator's
/// `*.review.example.com` or catch-all route took that host's traffic
/// to a row carrying none of the protections the operator set there,
/// and the token never had to reach the protected route itself; and a
/// token could delete a protected route and create it again bare.
///
/// # Errors
///
/// A store read failure, or a 403 naming the control and the holder's
/// id and nothing of its values.
pub(super) fn ensure_not_displaced_weaker(
    store: &ConfigStore,
    after: &Route,
) -> Result<(), ApiError> {
    if !after.enabled {
        return Ok(());
    }
    let serving = Serving::read(store, after)?;
    for holder in serving.displaced_by(after) {
        if let Holder::Record(recorded) = holder {
            if !recorded.readable {
                return Err(recorded.unreadable());
            }
        }
        if let Some(protection) = first_weakened(ROUTE_PROTECTIONS, holder.route(), after) {
            return Err(holder.refusal(protection));
        }
    }
    Ok(())
}

/// An environment's route raised, control by control, to every holder
/// of the traffic it takes (the maintainer's decision of 2026-10-04), so
/// the environment resource cannot do what the token-route guard
/// refuses: put a host a protected wildcard, catch-all or deleted route
/// serves behind a row with none of its protections.
///
/// The environment's route is written from a fixed profile the pipeline
/// cannot shape, so it inherits rather than being refused. Each of
/// [`ROUTE_PROTECTIONS`] the route is weaker on is raised to the
/// holder's value by the rule's own `strengthened`, and a control the
/// profile already holds more strongly (the WAF a pipeline switched on)
/// is kept. Basic auth is copied as the stored username and password
/// hash, server side; neither reaches the answer, the audit row or a
/// log, which carry the ids this returns and nothing more.
///
/// The route weighs against the rows as they would be without its own:
/// a `PUT` rewrites the whole route from the profile, so an update
/// inherits from what serves the host underneath it today, a protection
/// the operator added there since included.
///
/// Returns the ids of the routes, and of the records, at least one
/// control was raised from.
///
/// # Errors
///
/// A store read failure, a 403 naming a record that does not read, or a
/// 403 naming the field and the holder's id when two holders ask for
/// what no one value meets (two Basic auth credentials, two allowlists
/// neither of which covers the other), which the environment's route
/// cannot satisfy.
pub(super) fn inherit_displaced_protections(
    store: &ConfigStore,
    route: &mut Route,
) -> Result<Inherited, ApiError> {
    let serving = Serving::read(store, route)?.without(&route.id);
    let displaced = serving.displaced_by(route);
    for holder in &displaced {
        if let Holder::Record(recorded) = holder {
            if !recorded.readable {
                return Err(recorded.unreadable());
            }
        }
    }
    let mut inherited = Inherited::default();
    for holder in &displaced {
        for protection in ROUTE_PROTECTIONS {
            if (protection.weakened)(holder.route(), route) {
                (protection.strengthened)(holder.route(), route);
                inherited.note(holder);
            }
        }
    }
    for holder in &displaced {
        if let Some(protection) = first_weakened(ROUTE_PROTECTIONS, holder.route(), route) {
            let named = match holder {
                Holder::Route(from) => {
                    format!(
                        "route `{}` serves this environment's hostname today",
                        from.id
                    )
                }
                Holder::Record(from) => format!(
                    "route protection record `{}` holds the protections of a deleted route \
                     that served this environment's hostname",
                    from.record.id
                ),
            };
            return Err(ApiError::Forbidden(format!(
                "{}: {named}, and the environment's route cannot take over its protections \
                 without being weaker on that control ({}); another route serving the same \
                 hostname asks for a different value, and an operator reconciles them in the \
                 dashboard",
                protection.fields.join(" / "),
                protection.rule
            )));
        }
    }
    Ok(inherited)
}

/// What an environment's route was raised from, as
/// [`inherit_displaced_protections`] reports it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Inherited {
    /// The stored routes at least one control was raised from.
    pub(super) routes: Vec<String>,
    /// The route protection records at least one control was raised
    /// from.
    pub(super) records: Vec<String>,
}

impl Inherited {
    /// Notes `holder` once.
    fn note(&mut self, holder: &Holder<'_>) {
        let (ids, id) = match holder {
            Holder::Route(route) => (&mut self.routes, &route.id),
            Holder::Record(recorded) => (&mut self.records, &recorded.record.id),
        };
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::protections::{bare_route as route, fortified};
    use crate::automation::records::tests::recorded_of;

    /// The ids `after` displaces from `stored` and `recorded`, records
    /// prefixed `record:`.
    fn displaced(stored: Vec<Route>, recorded: Vec<Recorded>, after: &Route) -> Vec<String> {
        Serving { stored, recorded }
            .displaced_by(after)
            .iter()
            .map(|holder| match holder {
                Holder::Route(route) => route.id.clone(),
                Holder::Record(recorded) => format!("record:{}", recorded.route.id),
            })
            .collect()
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
            let serving = Serving {
                stored: Vec::new(),
                recorded: vec![recorded_of(&deleted)],
            };
            let bare = route("r-2", "app.example.com", "/");
            let holders = serving.displaced_by(&bare);
            assert_eq!(holders.len(), 1, "{:?}", protection.fields);
            let refused = first_weakened(ROUTE_PROTECTIONS, holders[0].route(), &bare)
                .expect("the bare recreate is weaker");
            assert_eq!(refused.fields, protection.fields);
            let mut matching = bare.clone();
            (protection.strengthened)(holders[0].route(), &mut matching);
            assert!(
                first_weakened(ROUTE_PROTECTIONS, holders[0].route(), &matching).is_none(),
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
        let count = |after: &Route, stored: Vec<Route>| -> usize {
            displaced(stored, vec![recorded_of(&aliased)], after).len()
        };

        // An alias is a name the record serves; a path below its prefix
        // is served by it; a path beside it is not.
        assert_eq!(count(&route("n", "www.example.com", "/"), Vec::new()), 1);
        assert_eq!(
            count(&route("n", "app.example.com", "/api/v2"), Vec::new()),
            1
        );
        assert_eq!(
            count(&route("n", "app.example.com", "/public"), Vec::new()),
            0
        );
        // `/` on that host takes `/api` from the record too.
        assert_eq!(count(&route("n", "app.example.com", "/"), Vec::new()), 1);
        // Another host takes nothing; a disabled route takes nothing.
        assert_eq!(count(&route("n", "other.example.com", "/"), Vec::new()), 0);
        let mut off = route("n", "app.example.com", "/api");
        off.enabled = false;
        assert_eq!(count(&off, Vec::new()), 0);

        // A stored route on the same name and path shadows the record:
        // an update of that route is weighed against itself in place.
        let shadow = route("s", "app.example.com", "/api");
        let mut updated = shadow.clone();
        updated.read_timeout_s = 5;
        assert_eq!(count(&updated, vec![shadow]), 0);

        // A recorded wildcard is taken by any exact name under it.
        let wildcard = || vec![recorded_of(&fortified("w", "*.example.com"))];
        assert_eq!(
            displaced(Vec::new(), wildcard(), &route("n", "a.example.com", "/")).len(),
            1
        );
        assert_eq!(
            displaced(Vec::new(), wildcard(), &route("n", "example.org", "/")).len(),
            0
        );

        // A disabled deleted route is recorded switched on.
        let mut disabled = fortified("d", "off.example.com");
        disabled.enabled = false;
        assert_eq!(
            displaced(
                Vec::new(),
                vec![recorded_of(&disabled)],
                &route("n", "off.example.com", "/")
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_stored_wildcard_and_a_record_are_each_weighed_where_each_serves() {
        // The record stands for the exact route it was made of, which
        // the wildcard served under; the wildcard still serves the
        // names beside it.
        let stored = vec![fortified("wild", "*.example.com")];
        let recorded = || vec![recorded_of(&fortified("gone", "app.example.com"))];
        assert_eq!(
            displaced(
                stored.clone(),
                recorded(),
                &route("n", "app.example.com", "/")
            ),
            vec!["record:gone".to_string()]
        );
        let mut both = route("n", "app.example.com", "/");
        both.hostname_aliases = vec!["b.example.com".into()];
        assert_eq!(
            displaced(stored, recorded(), &both),
            vec!["record:gone".to_string(), "wild".to_string()]
        );
    }

    #[test]
    fn a_route_takes_a_host_from_a_wildcard_or_the_catch_all_and_not_from_itself() {
        let stored = vec![
            route("catch", "_", "/"),
            route("wild", "*.example.com", "/"),
            route("mine", "mine.example.com", "/"),
        ];
        assert_eq!(
            displaced(
                stored.clone(),
                Vec::new(),
                &route("n", "a.example.com", "/")
            ),
            vec!["wild".to_string()]
        );
        assert_eq!(
            displaced(
                stored.clone(),
                Vec::new(),
                &route("n", "a.example.org", "/")
            ),
            vec!["catch".to_string()]
        );
        let mut mine = route("mine", "mine.example.com", "/");
        mine.read_timeout_s = 5;
        assert!(displaced(stored, Vec::new(), &mine).is_empty());
    }
}
