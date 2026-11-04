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
//!
//! # One spelling of a name
//!
//! A host name is case-insensitive (RFC 9110 section 4.2.3), and an
//! absolute name carrying its root dot is the same host. Every name is
//! therefore compared, keyed and stored in the form
//! [`canonical_hostname`] gives it: ASCII lowercase, one trailing dot
//! dropped. A name compared in any other form is a second name to that
//! comparison and the same host to every client, which is how a route
//! could take a host from a protected one without any guard seeing a
//! conflict.
//!
//! A configuration written before this rule can hold two routes whose
//! names are spellings of one name. The selection serves such a name
//! from one of them ([`served_spelling`]) and reports the other as a
//! [`NameCollision`]; nothing is deleted or switched off.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::models::Route;

/// The hostname of a route that serves every host no other route
/// claims.
pub const CATCH_ALL_HOSTNAME: &str = "_";

/// `name` in the one form names are compared, keyed and stored in:
/// ASCII letters lowercased and at most one trailing dot removed.
///
/// It applies to exact names and to wildcard patterns alike. No IDNA
/// mapping is applied: a request carries A-labels, and a byte outside
/// ASCII is left as it is. Borrowed, without an allocation, when `name`
/// is already canonical, which is every request a browser sends.
///
/// ```
/// use lorica_config::route_selection::canonical_hostname;
/// assert_eq!(canonical_hostname("App.Example.COM."), "app.example.com");
/// assert_eq!(canonical_hostname("*.Example.com"), "*.example.com");
/// assert!(matches!(
///     canonical_hostname("app.example.com"),
///     std::borrow::Cow::Borrowed(_)
/// ));
/// ```
pub fn canonical_hostname(name: &str) -> Cow<'_, str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

/// Whether two names are the same name to the selection.
///
/// The one comparison of two route names outside the index, which keys
/// its maps by the same [`canonical_hostname`] form: a caller asking
/// whether a route still answers to a name, or holds one another row
/// holds, asks here.
pub fn same_name(a: &str, b: &str) -> bool {
    canonical_hostname(a) == canonical_hostname(b)
}

/// Of the routes answering to one name under different spellings, the
/// spelling the name is served under and the route that spells it so:
/// a route spelling it canonically first, then the smallest route id.
///
/// `claims` pairs each route's spelling of `name` with its id, one pair
/// per route; `name` is canonical. `None` when there is no claim.
///
/// The canonical spelling wins because it is the one every browser
/// sends, so its route is the one serving the name before this rule;
/// the id breaks a tie the same way on every node and every reload.
pub fn served_spelling<'a>(
    name: &str,
    claims: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Option<(&'a str, &'a str)> {
    claims
        .into_iter()
        .min_by_key(|(spelling, route_id)| (*spelling != name, *route_id))
}

/// The names one route answers to, each canonical name once with the
/// spelling the route claims it under: the canonical spelling when the
/// route has it among its names, else the first it has.
fn claims_of<'a>(names: impl Iterator<Item = &'a String>) -> Vec<(String, &'a str)> {
    let mut claims: Vec<(String, &str)> = Vec::new();
    for name in names {
        let key = canonical_hostname(name);
        match claims.iter_mut().find(|(held, _)| *held == key) {
            Some((held, spelling)) => {
                if name == held {
                    *spelling = name;
                }
            }
            None => claims.push((key.into_owned(), name)),
        }
    }
    claims
}

/// A name two routes answer to under two spellings, of which the
/// selection serves one ([`served_spelling`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCollision {
    /// The name, canonical.
    pub name: String,
    /// The route the name is served by.
    pub served_route_id: String,
    /// A route that spells the name otherwise and is not served on it.
    pub shadowed_route_id: String,
    /// How the shadowed route spells it.
    pub shadowed_spelling: String,
}

/// Routes keyed by the names they answer to, as the proxy looks them
/// up.
#[derive(Debug, Clone)]
pub struct HostIndex<E> {
    /// Exact names, the catch-all included, each canonical and with its
    /// routes, longest `path_prefix` first.
    pub exact: HashMap<String, Vec<E>>,
    /// Wildcard patterns (`*.example.com`), canonical, the most specific
    /// first, each with its routes, longest `path_prefix` first.
    pub wildcards: Vec<(String, Vec<E>)>,
    /// The names two routes answer to under two spellings, each indexed
    /// under the route [`served_spelling`] picks; sorted by name, then
    /// by the shadowed route's id.
    pub collisions: Vec<NameCollision>,
}

impl<E: Clone> HostIndex<E> {
    /// Index `entries` under every name their route answers to: its
    /// hostname and each alias, in [`canonical_hostname`] form. A
    /// disabled route serves nothing and is left out.
    ///
    /// A name several routes answer to under different spellings is
    /// indexed under the routes [`served_spelling`] picks alone, the
    /// others reported in [`HostIndex::collisions`]: indexed beside it, a
    /// twin with a longer `path_prefix` would take those paths from it.
    ///
    /// Overlapping wildcards (`*.example.com` and `*.b.example.com`) are
    /// ordered longest pattern first, then by spelling, so the pattern
    /// a host matches most narrowly wins and the choice is the same on
    /// every node and every reload.
    pub fn new<F>(entries: impl IntoIterator<Item = E>, route_of: F) -> HostIndex<E>
    where
        F: Fn(&E) -> &Route,
    {
        let mut claimed: HashMap<String, Vec<(String, E)>> = HashMap::new();
        for entry in entries {
            let route = route_of(&entry);
            if !route.enabled {
                continue;
            }
            let claims: Vec<(String, String)> =
                claims_of(std::iter::once(&route.hostname).chain(route.hostname_aliases.iter()))
                    .into_iter()
                    .map(|(name, spelling)| (name, spelling.to_string()))
                    .collect();
            for (name, spelling) in claims {
                claimed
                    .entry(name)
                    .or_default()
                    .push((spelling, entry.clone()));
            }
        }
        let mut collisions = Vec::new();
        let mut by_name: HashMap<String, Vec<E>> = HashMap::with_capacity(claimed.len());
        for (name, claims) in claimed {
            let Some((served, served_route_id)) = served_spelling(
                &name,
                claims
                    .iter()
                    .map(|(spelling, entry)| (spelling.as_str(), route_of(entry).id.as_str())),
            )
            .map(|(spelling, id)| (spelling.to_string(), id.to_string())) else {
                continue;
            };
            let mut serving = Vec::with_capacity(claims.len());
            for (spelling, entry) in claims {
                if spelling == served {
                    serving.push(entry);
                } else {
                    collisions.push(NameCollision {
                        name: name.clone(),
                        served_route_id: served_route_id.clone(),
                        shadowed_route_id: route_of(&entry).id.clone(),
                        shadowed_spelling: spelling,
                    });
                }
            }
            by_name.insert(name, serving);
        }
        collisions.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.shadowed_route_id.cmp(&b.shadowed_route_id))
        });
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
            collisions,
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
/// can keep them as fields of its own. `host` is looked up in
/// [`canonical_hostname`] form, without an allocation when it is in it
/// already.
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
    let host = canonical_hostname(host);
    let serving = |entries: &'a [E]| {
        entries
            .iter()
            .find(|entry| path.starts_with(&route_of(entry).path_prefix))
    };
    if let Some(entry) = exact
        .get(host.as_ref())
        .and_then(|entries| serving(entries))
    {
        return Some(entry);
    }
    for (pattern, entries) in wildcards {
        if suffix_covers(pattern, &host) {
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
/// deeper labels included, and never `example.com` itself. Both are
/// compared in [`canonical_hostname`] form.
pub fn wildcard_covers(pattern: &str, host: &str) -> bool {
    suffix_covers(&canonical_hostname(pattern), &canonical_hostname(host))
}

/// [`wildcard_covers`] on two names already canonical.
fn suffix_covers(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix('*') else {
        return false;
    };
    host.len() > suffix.len() && host.ends_with(suffix)
}

/// One route's names, for a caller that holds them outside a [`Route`]
/// (a migration reading raw rows) or rewrites them for a whole set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteNames {
    /// The route's id.
    pub route_id: String,
    /// Its hostname.
    pub hostname: String,
    /// Its aliases, in order.
    pub aliases: Vec<String>,
}

impl RouteNames {
    /// The names `route` answers to.
    pub fn of(route: &Route) -> RouteNames {
        RouteNames {
            route_id: route.id.clone(),
            hostname: route.hostname.clone(),
            aliases: route.hostname_aliases.clone(),
        }
    }
}

/// `names` in [`canonical_hostname`] form, each once, in order.
///
/// ```
/// use lorica_config::route_selection::canonical_names;
/// assert_eq!(
///     canonical_names(["A.example.com.", "a.example.com", "B.example.com"]),
///     vec!["a.example.com".to_string(), "b.example.com".to_string()]
/// );
/// ```
pub fn canonical_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = canonical_hostname(name);
        if !out.iter().any(|held| *held == name) {
            out.push(name.into_owned());
        }
    }
    out
}

/// Rewrite the names of a whole route set to [`canonical_hostname`]
/// form, as the selection serves them, and report what two routes
/// collide on.
///
/// A name one route alone answers to is rewritten, and an alias that is
/// then the same name as the route's hostname or an earlier alias is
/// dropped. A name several routes answer to under different spellings
/// is rewritten on the routes [`served_spelling`] picks, and kept as
/// stored on every other one, which is reported in the returned list:
/// rewritten, it would be a byte-identical second holder of a name the
/// store holds once, and the selection would split the name's paths
/// between the two.
///
/// ```
/// use lorica_config::route_selection::{canonicalise_route_names, RouteNames};
/// let mut routes = [
///     RouteNames {
///         route_id: "a".into(),
///         hostname: "App.Example.com".into(),
///         aliases: vec!["WWW.Example.com.".into()],
///     },
///     RouteNames {
///         route_id: "b".into(),
///         hostname: "app.example.com".into(),
///         aliases: vec![],
///     },
/// ];
/// let collisions = canonicalise_route_names(&mut routes);
/// assert_eq!(routes[0].hostname, "App.Example.com");
/// assert_eq!(routes[0].aliases, vec!["www.example.com".to_string()]);
/// assert_eq!(collisions[0].served_route_id, "b");
/// ```
pub fn canonicalise_route_names(routes: &mut [RouteNames]) -> Vec<NameCollision> {
    let claims: Vec<Vec<(String, String)>> = routes
        .iter()
        .map(|route| {
            claims_of(std::iter::once(&route.hostname).chain(route.aliases.iter()))
                .into_iter()
                .map(|(name, spelling)| (name, spelling.to_string()))
                .collect()
        })
        .collect();
    let mut claimed: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for (route, own) in routes.iter().zip(&claims) {
        for (name, spelling) in own {
            claimed
                .entry(name.as_str())
                .or_default()
                .push((spelling.as_str(), route.route_id.as_str()));
        }
    }
    let mut collisions = Vec::new();
    let mut served: HashMap<String, String> = HashMap::with_capacity(claimed.len());
    for (name, holders) in &claimed {
        let Some((spelling, served_route_id)) = served_spelling(name, holders.iter().copied())
        else {
            continue;
        };
        for (other, route_id) in holders {
            if *other != spelling {
                collisions.push(NameCollision {
                    name: name.to_string(),
                    served_route_id: served_route_id.to_string(),
                    shadowed_route_id: route_id.to_string(),
                    shadowed_spelling: other.to_string(),
                });
            }
        }
        served.insert(name.to_string(), spelling.to_string());
    }
    for (route, own) in routes.iter_mut().zip(&claims) {
        let rewrite = |name: &str| -> String {
            let key = canonical_hostname(name);
            let route_spelling = own.iter().find(|(held, _)| *held == key).map(|(_, s)| s);
            if served.get(key.as_ref()) == route_spelling {
                key.into_owned()
            } else {
                name.to_string()
            }
        };
        let hostname = rewrite(&route.hostname);
        let mut aliases: Vec<String> = Vec::with_capacity(route.aliases.len());
        for alias in &route.aliases {
            let alias = rewrite(alias);
            if alias != hostname && !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
        route.hostname = hostname;
        route.aliases = aliases;
    }
    collisions.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.shadowed_route_id.cmp(&b.shadowed_route_id))
    });
    collisions
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
/// ones that could serve `host` before it builds one. Every key is in
/// [`canonical_hostname`] form.
pub fn keys_reaching(host: &str) -> Vec<String> {
    let host = canonical_hostname(host);
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
    fn a_name_is_selected_whatever_its_case_and_root_dot() {
        let routes = [
            route("catch", CATCH_ALL_HOSTNAME, "/"),
            route("wild", "*.Example.com", "/"),
            route("exact", "app.example.com", "/"),
            route("stored-mixed", "Shop.Example.COM.", "/"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        for host in ["app.example.com", "App.Example.COM", "app.example.com."] {
            assert_eq!(served(&index, host, "/"), Some("exact"), "{host}");
        }
        for host in ["other.example.com", "Other.EXAMPLE.com."] {
            assert_eq!(served(&index, host, "/"), Some("wild"), "{host}");
        }
        assert_eq!(
            served(&index, "shop.example.com", "/"),
            Some("stored-mixed")
        );
        assert_eq!(served(&index, "Example.COM.", "/"), Some("catch"));
    }

    #[test]
    fn a_twin_spelling_never_takes_a_path_from_the_route_spelled_canonically() {
        let routes = [
            route("canonical", "app.example.com", "/"),
            route("twin", "App.Example.com", "/api"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        for host in ["app.example.com", "APP.example.com", "App.Example.com"] {
            for path in ["/", "/api", "/api/v1"] {
                assert_eq!(
                    served(&index, host, path),
                    Some("canonical"),
                    "{host}{path}"
                );
            }
        }
    }

    #[test]
    fn the_canonical_form_folds_ascii_case_and_one_root_dot_only() {
        for (name, canonical) in [
            ("app.example.com", "app.example.com"),
            ("App.Example.COM", "app.example.com"),
            ("app.example.com.", "app.example.com"),
            ("*.Example.com.", "*.example.com"),
            ("app.example.com..", "app.example.com."),
            ("_", "_"),
            (".", ""),
            ("[2001:DB8::1]", "[2001:db8::1]"),
            ("Bücher.example", "bücher.example"),
        ] {
            assert_eq!(canonical_hostname(name), canonical, "{name}");
        }
        assert!(matches!(
            canonical_hostname("app.example.com"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            canonical_hostname("app.example.com."),
            Cow::Borrowed(_)
        ));
        assert!(same_name("App.Example.com.", "app.example.COM"));
        assert!(!same_name("app.example.com", "app.example.org"));
        assert!(wildcard_covers("*.Example.com", "A.EXAMPLE.com."));
        assert_eq!(keys_reaching("A.Example.com.")[0], "a.example.com");
    }

    #[test]
    fn a_twin_spelling_is_reported_and_the_canonical_route_keeps_the_name() {
        let mut canonical = route("canonical", "app.example.com", "/");
        canonical.hostname_aliases = vec!["App.Example.com".to_string()];
        let routes = [
            route("twin-b", "APP.example.com", "/"),
            canonical,
            route("twin-a", "App.Example.com.", "/api"),
            route("both-1", "B.example.com", "/"),
            route("both-0", "b.EXAMPLE.com", "/"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        let reported: Vec<(&str, &str, &str, &str)> = index
            .collisions
            .iter()
            .map(|c| {
                (
                    c.name.as_str(),
                    c.served_route_id.as_str(),
                    c.shadowed_route_id.as_str(),
                    c.shadowed_spelling.as_str(),
                )
            })
            .collect();
        assert_eq!(
            reported,
            vec![
                ("app.example.com", "canonical", "twin-a", "App.Example.com."),
                ("app.example.com", "canonical", "twin-b", "APP.example.com"),
                ("b.example.com", "both-0", "both-1", "B.example.com"),
            ]
        );
        assert_eq!(served(&index, "b.example.com", "/"), Some("both-0"));
    }

    #[test]
    fn a_route_set_is_rewritten_canonical_but_for_the_twin_it_would_duplicate() {
        let names = |id: &str, hostname: &str, aliases: &[&str]| RouteNames {
            route_id: id.to_string(),
            hostname: hostname.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
        };
        let mut routes = [
            names("r-twin", "App.Example.com", &["Free.Example.com."]),
            names("r-canonical", "app.example.com", &[]),
            names(
                "r-mixed",
                "Shop.Example.com.",
                &["shop.example.com", "WWW.Shop.example.com"],
            ),
        ];
        let collisions = canonicalise_route_names(&mut routes);
        assert_eq!(
            routes,
            [
                names("r-twin", "App.Example.com", &["free.example.com"]),
                names("r-canonical", "app.example.com", &[]),
                names("r-mixed", "shop.example.com", &["www.shop.example.com"]),
            ]
        );
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].shadowed_route_id, "r-twin");
        assert_eq!(collisions[0].served_route_id, "r-canonical");

        // Rewritten, the set indexes with no collision left but the twin.
        let mut again = routes.clone();
        assert_eq!(canonicalise_route_names(&mut again), collisions);
        assert_eq!(again, routes);
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
