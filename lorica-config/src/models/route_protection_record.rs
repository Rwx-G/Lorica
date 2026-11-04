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

//! What a route deleted through the automation plane served, kept after
//! the route is gone (backlog #93).
//!
//! The automation plane holds a token's route write to the protections
//! of every stored route it would take a request from. A route a token
//! deleted is no longer stored, so without this row a token that may
//! delete a protected route could create it again without its
//! protections. The row keeps the deleted route itself, as the store
//! held it, so the plane weighs a later write against it with the same
//! predicates and the same route selection it uses for a stored route.
//! Which controls count, and in which direction, is the plane's
//! (`ROUTE_PROTECTIONS` in `lorica-api`); nothing here names one.

use chrono::{DateTime, Utc};

use super::route::Route;
use crate::error::{ConfigError, Result};

/// How many unknown fields [`RouteProtectionRecord::route`] strips from
/// a snapshot before it gives up on it.
const UNKNOWN_FIELDS_STRIPPED_MAX: usize = 32;

/// One deleted route's protections, as the store keeps them.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteProtectionRecord {
    /// Stable UUID of the record.
    pub id: String,
    /// The id the deleted route had.
    pub route_id: String,
    /// The deleted route's hostname.
    pub hostname: String,
    /// The deleted route's aliases.
    pub hostname_aliases: Vec<String>,
    /// The deleted route's path prefix.
    pub path_prefix: String,
    /// The deleted route as the store held it, serialised.
    ///
    /// Kept as JSON rather than as a [`Route`] so a field added to the
    /// model later reads with its serde default and a snapshot written
    /// by a newer binary reads on an older one ([`Self::route`]). A
    /// field of the model that is renamed must migrate these snapshots
    /// with it, or the control it carried is read at its default.
    ///
    /// It carries the Basic-auth password hash, as `routes` does: the
    /// environment resource copies a recorded credential server side
    /// exactly as it copies a displaced route's. No answer, audit row or
    /// log renders it.
    pub route: serde_json::Value,
    /// Who deleted the route, as its audit row names the actor.
    pub deleted_by: String,
    /// When the route was deleted.
    pub deleted_at: DateTime<Utc>,
}

impl RouteProtectionRecord {
    /// The record of `route`, deleted by `deleted_by` at `deleted_at`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Serialization`] when the route does not serialise.
    pub fn of_deleted(
        route: &Route,
        deleted_by: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<RouteProtectionRecord> {
        let snapshot = serde_json::to_value(route)
            .map_err(|e| ConfigError::Serialization(format!("route snapshot: {e}")))?;
        Ok(RouteProtectionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            route_id: route.id.clone(),
            hostname: route.hostname.clone(),
            hostname_aliases: route.hostname_aliases.clone(),
            path_prefix: route.path_prefix.clone(),
            route: snapshot,
            deleted_by: deleted_by.to_string(),
            deleted_at,
        })
    }

    /// Every name the deleted route answered to: its hostname, then each
    /// alias.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.hostname.as_str())
            .chain(self.hostname_aliases.iter().map(String::as_str))
    }

    /// The deleted route, read back from the snapshot.
    ///
    /// A field this binary does not know, which a newer binary wrote, is
    /// dropped and the rest read: [`Route`] refuses unknown fields, and
    /// a record that did not read would weigh nothing. A field this
    /// binary knows is never dropped.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Corrupt`] when the snapshot is not an object, or
    /// does not read once the unknown fields are gone.
    pub fn route(&self) -> Result<Route> {
        let mut snapshot = self.route.clone();
        for _ in 0..=UNKNOWN_FIELDS_STRIPPED_MAX {
            let refused = match serde_json::from_value::<Route>(snapshot.clone()) {
                Ok(route) => return Ok(route),
                Err(refused) => refused,
            };
            let unknown = unknown_field(&refused.to_string());
            let removed = match (unknown, snapshot.as_object_mut()) {
                (Some(field), Some(object)) => object.remove(&field).is_some(),
                _ => false,
            };
            if !removed {
                return Err(ConfigError::Corrupt(format!(
                    "route protection record {} does not read: {refused}",
                    self.id
                )));
            }
        }
        Err(ConfigError::Corrupt(format!(
            "route protection record {} carries more fields this binary does not know than it \
             strips",
            self.id
        )))
    }
}

/// The field serde names in an `unknown field` refusal, the one shape
/// `deny_unknown_fields` gives it.
fn unknown_field(refusal: &str) -> Option<String> {
    let rest = refusal.strip_prefix("unknown field `")?;
    rest.split_once('`').map(|(field, _)| field.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> Route {
        serde_json::from_value(serde_json::json!({
            "id": "r-1",
            "hostname": "app.example.com",
            "hostname_aliases": ["www.example.com"],
            "path_prefix": "/api",
            "load_balancing": "round_robin",
            "waf_enabled": true,
            "waf_mode": "blocking",
            "enabled": true,
            "ip_allowlist": ["192.0.2.0/24"],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a route")
    }

    #[test]
    fn a_record_reads_back_the_route_it_was_made_of() {
        let record =
            RouteProtectionRecord::of_deleted(&route(), "ci (0123)", Utc::now()).expect("record");
        assert_eq!(record.route_id, "r-1");
        assert_eq!(
            record.names().collect::<Vec<_>>(),
            vec!["app.example.com", "www.example.com"]
        );
        assert_eq!(record.path_prefix, "/api");
        let read = record.route().expect("reads");
        assert_eq!(
            serde_json::to_value(&read).expect("serialises"),
            serde_json::to_value(route()).expect("serialises")
        );
    }

    #[test]
    fn a_field_a_newer_binary_wrote_is_dropped_and_a_known_one_kept() {
        let mut record =
            RouteProtectionRecord::of_deleted(&route(), "ci (0123)", Utc::now()).expect("record");
        let object = record.route.as_object_mut().expect("an object");
        object.insert("a_later_field".into(), serde_json::json!(true));
        object.insert("another_later_field".into(), serde_json::json!({ "x": 1 }));
        let read = record.route().expect("reads without the unknown fields");
        assert!(read.waf_enabled);
        assert_eq!(read.ip_allowlist, vec!["192.0.2.0/24".to_string()]);
    }

    #[test]
    fn a_field_added_to_the_model_later_reads_at_its_default() {
        let mut record =
            RouteProtectionRecord::of_deleted(&route(), "ci (0123)", Utc::now()).expect("record");
        record
            .route
            .as_object_mut()
            .expect("an object")
            .remove("ip_denylist");
        assert!(record.route().expect("reads").ip_denylist.is_empty());
    }

    #[test]
    fn a_snapshot_that_cannot_read_is_corrupt_rather_than_empty() {
        let mut record =
            RouteProtectionRecord::of_deleted(&route(), "ci (0123)", Utc::now()).expect("record");
        record
            .route
            .as_object_mut()
            .expect("an object")
            .insert("waf_enabled".into(), serde_json::json!("not a boolean"));
        assert!(matches!(record.route(), Err(ConfigError::Corrupt(_))));
        record.route = serde_json::json!([]);
        assert!(matches!(record.route(), Err(ConfigError::Corrupt(_))));
    }
}
