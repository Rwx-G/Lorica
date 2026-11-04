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

//! Which route serves a request, from its host and its path.
//!
//! The one statement of the proxy's route selection. The data plane
//! builds its snapshot's index with [`HostIndex::new`] and answers each
//! request through [`select`]; the automation plane builds the same
//! index from the stored rows to learn which route a host is served by
//! today, before it lets a token's route take that host over. Two
//! copies of this precedence would let the plane weigh a route the
//! proxy never picks, so there is one.
//!
//! The precedence, per request: an exact name (a hostname or an alias)
//! first, then the wildcard patterns, the most specific first, then the
//! catch-all [`CATCH_ALL_HOSTNAME`]. At each level the longest
//! `path_prefix` the path starts with wins, and a level where no prefix
//! matches falls through to the next.

use std::collections::HashMap;

use crate::models::Route;

/// The hostname of a route that serves every host no other route
/// claims.
pub const CATCH_ALL_HOSTNAME: &str = "_";

/// Routes keyed by the names they answer to, as the proxy looks them
/// up.
#[derive(Debug, Clone)]
pub struct HostIndex<E> {
    /// Exact names, the catch-all included, each with its routes,
    /// longest `path_prefix` first.
    pub exact: HashMap<String, Vec<E>>,
    /// Wildcard patterns (`*.example.com`), the most specific first,
    /// each with its routes, longest `path_prefix` first.
    pub wildcards: Vec<(String, Vec<E>)>,
}

impl<E: Clone> HostIndex<E> {
    /// Index `entries` under every name their route answers to: its
    /// hostname and each alias. A disabled route serves nothing and is
    /// left out.
    ///
    /// Overlapping wildcards (`*.example.com` and `*.b.example.com`) are
    /// ordered longest pattern first, then by spelling, so the pattern
    /// a host matches most narrowly wins and the choice is the same on
    /// every node and every reload.
    pub fn new<F>(entries: impl IntoIterator<Item = E>, route_of: F) -> HostIndex<E>
    where
        F: Fn(&E) -> &Route,
    {
        let mut by_name: HashMap<String, Vec<E>> = HashMap::new();
        for entry in entries {
            let route = route_of(&entry);
            if !route.enabled {
                continue;
            }
            let names: Vec<String> = std::iter::once(&route.hostname)
                .chain(route.hostname_aliases.iter())
                .cloned()
                .collect();
            for name in names {
                by_name.entry(name).or_default().push(entry.clone());
            }
        }
        let wildcard_names: Vec<String> = by_name
            .keys()
            .filter(|name| name.starts_with("*."))
            .cloned()
            .collect();
        let mut wildcards: Vec<(String, Vec<E>)> = wildcard_names
            .into_iter()
            .filter_map(|name| by_name.remove(&name).map(|entries| (name, entries)))
            .collect();
        wildcards.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let longest_prefix_first = |entries: &mut Vec<E>| {
            entries.sort_by_key(|entry| std::cmp::Reverse(route_of(entry).path_prefix.len()));
        };
        for entries in by_name.values_mut() {
            longest_prefix_first(entries);
        }
        for (_, entries) in &mut wildcards {
            longest_prefix_first(entries);
        }
        HostIndex {
            exact: by_name,
            wildcards,
        }
    }

    /// The route that serves `host` and `path`; see [`select`].
    pub fn select<F>(&self, host: &str, path: &str, route_of: F) -> Option<&E>
    where
        F: Fn(&E) -> &Route,
    {
        select(&self.exact, &self.wildcards, host, path, route_of)
    }
}

/// The route that serves `host` and `path` from an index built by
/// [`HostIndex::new`], held as its two parts so the proxy's snapshot
/// can keep them as fields of its own.
pub fn select<'a, E, F>(
    exact: &'a HashMap<String, Vec<E>>,
    wildcards: &'a [(String, Vec<E>)],
    host: &str,
    path: &str,
    route_of: F,
) -> Option<&'a E>
where
    F: Fn(&E) -> &Route,
{
    let serving = |entries: &'a [E]| {
        entries
            .iter()
            .find(|entry| path.starts_with(&route_of(entry).path_prefix))
    };
    if let Some(entry) = exact.get(host).and_then(|entries| serving(entries)) {
        return Some(entry);
    }
    for (pattern, entries) in wildcards {
        if wildcard_covers(pattern, host) {
            if let Some(entry) = serving(entries) {
                return Some(entry);
            }
        }
    }
    exact
        .get(CATCH_ALL_HOSTNAME)
        .and_then(|entries| serving(entries))
}

/// Whether the wildcard `pattern` (`*.example.com`) covers `host`: any
/// name ending in `.example.com` with at least one character before it,
/// deeper labels included, and never `example.com` itself.
pub fn wildcard_covers(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix('*') else {
        return false;
    };
    host.len() > suffix.len() && host.ends_with(suffix)
}

/// Whether two names are the same name to the selection.
///
/// The one comparison of two route names outside the index, which keys
/// its maps by the same equality: a caller asking whether a route still
/// answers to a name, or holds one another row holds, asks here, so the
/// day names are compared in another form every such caller moves with
/// the index.
pub fn same_name(a: &str, b: &str) -> bool {
    a == b
}

/// Whether `route` answers to `name` for every path `path_prefix`
/// covers: it answers to `name` and its own prefix is `path_prefix` or
/// one above it.
///
/// No other route can take one of those requests from it: a name is
/// held by one route at most (`ConfigStore::hostname_claimed_elsewhere`),
/// so at that name's level of the selection `route` is the only entry,
/// and a longer prefix it does not cover would be its own.
pub fn serves_all_of(route: &Route, name: &str, path_prefix: &str) -> bool {
    std::iter::once(route.hostname.as_str())
        .chain(route.hostname_aliases.iter().map(String::as_str))
        .any(|own| same_name(own, name))
        && path_prefix.starts_with(route.path_prefix.as_str())
}

/// Every index key whose routes [`select`] can reach for `host`: the
/// name itself, each wildcard pattern that covers it, and the
/// catch-all, so a caller holding rows outside an index reads only the
/// ones that could serve `host` before it builds one.
pub fn keys_reaching(host: &str) -> Vec<String> {
    let mut keys = vec![host.to_string()];
    keys.extend(
        host.match_indices('.')
            .filter(|(at, _)| *at > 0)
            .map(|(at, _)| format!("*{}", &host[at..])),
    );
    keys.push(CATCH_ALL_HOSTNAME.to_string());
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(id: &str, hostname: &str, path_prefix: &str) -> Route {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": hostname,
            "path_prefix": path_prefix,
            "certificate_id": null,
            "load_balancing": "round_robin",
            "waf_enabled": false,
            "waf_mode": "detection",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }))
        .expect("test setup: a route with every defaulted field left out")
    }

    fn served<'a>(index: &'a HostIndex<&Route>, host: &str, path: &str) -> Option<&'a str> {
        index
            .select(host, path, |r| *r)
            .map(|route| route.id.as_str())
    }

    #[test]
    fn an_exact_name_wins_over_a_wildcard_and_a_wildcard_over_the_catch_all() {
        let routes = [
            route("catch", CATCH_ALL_HOSTNAME, "/"),
            route("wild", "*.example.com", "/"),
            route("exact", "app.example.com", "/"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        assert_eq!(served(&index, "app.example.com", "/"), Some("exact"));
        assert_eq!(served(&index, "other.example.com", "/"), Some("wild"));
        assert_eq!(served(&index, "a.b.example.com", "/"), Some("wild"));
        assert_eq!(served(&index, "example.com", "/"), Some("catch"));
        assert_eq!(served(&index, "unrelated.org", "/x"), Some("catch"));
    }

    #[test]
    fn a_level_whose_prefixes_miss_the_path_falls_through_to_the_next() {
        let routes = [
            route("catch", CATCH_ALL_HOSTNAME, "/"),
            route("exact-api", "app.example.com", "/api"),
            route("wild-admin", "*.example.com", "/admin"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        assert_eq!(
            served(&index, "app.example.com", "/api/v1"),
            Some("exact-api")
        );
        assert_eq!(
            served(&index, "app.example.com", "/admin"),
            Some("wild-admin")
        );
        assert_eq!(served(&index, "app.example.com", "/"), Some("catch"));
    }

    #[test]
    fn the_longest_prefix_wins_within_a_level() {
        let routes = [
            route("root", "*.example.com", "/"),
            route("api", "*.example.com", "/api"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        assert_eq!(served(&index, "a.example.com", "/api/x"), Some("api"));
        assert_eq!(served(&index, "a.example.com", "/other"), Some("root"));
    }

    #[test]
    fn the_narrowest_wildcard_wins_whatever_the_insertion_order() {
        let wide = route("wide", "*.example.com", "/");
        let narrow = route("narrow", "*.b.example.com", "/");
        for routes in [[wide.clone(), narrow.clone()], [narrow, wide]] {
            let index = HostIndex::new(routes.iter(), |r| *r);
            assert_eq!(served(&index, "a.b.example.com", "/"), Some("narrow"));
            assert_eq!(served(&index, "a.c.example.com", "/"), Some("wide"));
        }
    }

    #[test]
    fn an_alias_is_a_name_and_a_disabled_route_serves_nothing() {
        let mut aliased = route("aliased", "app.example.com", "/");
        aliased.hostname_aliases = vec!["www.example.com".to_string()];
        let mut off = route("off", "off.example.com", "/");
        off.enabled = false;
        let routes = [aliased, off];
        let index = HostIndex::new(routes.iter(), |r| *r);
        assert_eq!(served(&index, "www.example.com", "/"), Some("aliased"));
        assert_eq!(served(&index, "off.example.com", "/"), None);
    }

    #[test]
    fn a_wildcard_covers_a_subdomain_and_never_its_own_parent() {
        assert!(wildcard_covers("*.example.com", "a.example.com"));
        assert!(wildcard_covers("*.example.com", "a.b.example.com"));
        assert!(!wildcard_covers("*.example.com", "example.com"));
        assert!(!wildcard_covers("*.example.com", ".example.com"));
        assert!(!wildcard_covers("example.com", "a.example.com"));
    }

    #[test]
    fn the_keys_reaching_a_host_are_exactly_those_the_selection_can_pick() {
        // Held to `select` itself: a lone route under each key is picked
        // for the host exactly when the key is among those listed.
        let keys = [
            "a.b.example.com",
            "b.example.com",
            "*.b.example.com",
            "*.example.com",
            "*.com",
            "*.a.b.example.com",
            "*.other.com",
            "example.com",
            CATCH_ALL_HOSTNAME,
        ];
        for host in [
            "a.b.example.com",
            "b.example.com",
            "example.com",
            "x.other.com",
        ] {
            let reaching = keys_reaching(host);
            for key in keys {
                let lone = [route("lone", key, "/")];
                let index = HostIndex::new(lone.iter(), |r| *r);
                assert_eq!(
                    served(&index, host, "/").is_some(),
                    reaching.iter().any(|reached| reached == key),
                    "{host} under {key}: {reaching:?}"
                );
            }
        }
    }

    #[test]
    fn a_route_serves_all_of_a_name_from_its_own_prefix_down() {
        let mut aliased = route("r", "app.example.com", "/api");
        aliased.hostname_aliases = vec!["www.example.com".to_string()];
        assert!(serves_all_of(&aliased, "www.example.com", "/api"));
        assert!(serves_all_of(&aliased, "app.example.com", "/api/v1"));
        assert!(!serves_all_of(&aliased, "app.example.com", "/"));
        assert!(!serves_all_of(&aliased, "other.example.com", "/api"));
    }
}
