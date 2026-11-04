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

/// What a hostname field accepts besides an exact DNS name, for
/// [`validate_hostname_syntax`]. Every field that takes a bare hostname
/// names its shape here, so the differences between them are these
/// flags and nothing else (audit M-23 folded the hand-rolled copies).
#[derive(Debug, Clone, Copy)]
pub struct HostnameShape<'a> {
    /// A leading `*.` wildcard (`*.example.com`): a route's hostname or
    /// alias, which the selection serves as a wildcard. Not a redirect
    /// target.
    pub allow_wildcard: bool,
    /// Empty input is `Ok("")`, which the caller reads as "clear the
    /// field". Otherwise it is refused as missing.
    pub allow_empty: bool,
    /// The catch-all [`CATCH_ALL_HOSTNAME`]: a route's primary hostname
    /// only, since the selection reads it there and nowhere else.
    pub allow_catch_all: bool,
    /// A bracketed IPv6 literal (`[2001:db8::1]`), the form a `Host`
    /// header carries one in: a route's primary hostname only. An IPv4
    /// literal needs no flag, it is labels of digits.
    pub allow_ipv6_literal: bool,
    /// The field's name, which every refusal starts with so a client can
    /// point at the input.
    pub field_label: &'a str,
}

/// The shape of a route's primary `hostname` as a write sets it: what
/// an alias takes, plus the two forms only a primary takes, the
/// catch-all [`CATCH_ALL_HOSTNAME`] and a bracketed IPv6 literal.
/// Every write path that sets one (the route API on both planes, the
/// TOML import) checks it against this.
pub const ROUTE_HOSTNAME_SHAPE: HostnameShape<'static> = HostnameShape {
    allow_wildcard: true,
    allow_empty: false,
    allow_catch_all: true,
    allow_ipv6_literal: true,
    field_label: "hostname",
};

/// RFC 1123-shaped hostname validation for every field that takes a
/// bare hostname: no scheme, path, port, query, fragment, userinfo or
/// whitespace, at most 253 characters, every label 1 to 63 ASCII
/// alphanumerics and inner hyphens, plus what `shape` allows. Returns
/// the input trimmed, or the refusal as a sentence naming the field.
///
/// The check order is "cheap discriminator first": URL-shape refusals
/// fire before the length and label checks, so a pasted URL gets the
/// actionable "drop the http:// prefix" rather than a label error. A
/// caller storing the name canonicalises it first
/// ([`canonical_hostname`]); a root dot left after that is refused.
///
/// ```
/// use lorica_config::route_selection::{validate_hostname_syntax, HostnameShape};
/// let primary = HostnameShape {
///     allow_wildcard: true,
///     allow_empty: false,
///     allow_catch_all: true,
///     allow_ipv6_literal: true,
///     field_label: "hostname",
/// };
/// assert!(validate_hostname_syntax("*.example.com", primary).is_ok());
/// assert!(validate_hostname_syntax("_", primary).is_ok());
/// assert!(validate_hostname_syntax("[2001:db8::1]", primary).is_ok());
/// assert!(validate_hostname_syntax("https://example.com", primary).is_err());
/// ```
pub fn validate_hostname_syntax(raw: &str, shape: HostnameShape<'_>) -> Result<String, String> {
    let label = shape.field_label;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        if shape.allow_empty {
            return Ok(String::new());
        }
        return Err(format!("{label} must not be empty"));
    }
    if shape.allow_catch_all && trimmed == CATCH_ALL_HOSTNAME {
        return Ok(trimmed.to_string());
    }
    if shape.allow_ipv6_literal {
        if let Some(inner) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            return match inner.parse::<std::net::Ipv6Addr>() {
                Ok(_) => Ok(trimmed.to_string()),
                Err(_) => Err(format!(
                    "{label} holds a bracketed literal that is not an IPv6 address"
                )),
            };
        }
    }
    if trimmed.contains("://") {
        return Err(format!(
            "{label} must be a bare hostname (e.g. `example.com`) without a scheme \
             - drop the `http://` / `https://` prefix"
        ));
    }
    if trimmed.contains('/') {
        return Err(format!(
            "{label} must be a bare hostname without a path or trailing slash \
             - drop everything after the hostname"
        ));
    }
    // No port in this field. A redirect that needs a non-standard port
    // goes through `redirect_to` (a full URL) instead.
    if trimmed.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#' | ':' | '@')) {
        return Err(format!(
            "{label} contains a character that is not valid in a hostname \
             (whitespace, `?`, `#`, `:`, `@`)"
        ));
    }
    if trimmed.len() > 253 {
        return Err(format!("{label} is longer than 253 characters (DNS limit)"));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err(format!("{label} must not start or end with a dot"));
    }
    let check_body = if shape.allow_wildcard {
        trimmed.strip_prefix("*.").unwrap_or(trimmed)
    } else {
        trimmed
    };
    for dns_label in check_body.split('.') {
        if dns_label.is_empty() {
            return Err(format!(
                "{label} contains an empty DNS label (consecutive dots)"
            ));
        }
        if dns_label.len() > 63 {
            return Err(format!(
                "{label} contains a DNS label longer than 63 characters"
            ));
        }
        if dns_label.starts_with('-') || dns_label.ends_with('-') {
            return Err(format!(
                "{label} contains a DNS label that starts or ends with `-`"
            ));
        }
        if !dns_label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!(
                "{label} may only contain ASCII letters, digits, `-` and `.`"
            ));
        }
    }
    Ok(trimmed.to_string())
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
    select_where(exact, wildcards, host, |entry| {
        path.starts_with(&route_of(entry).path_prefix)
    })
}

/// [`select`] with the path test left to `serves`: the first entry it
/// accepts at the first level of the precedence that has one.
fn select_where<'a, E>(
    exact: &'a HashMap<String, Vec<E>>,
    wildcards: &'a [(String, Vec<E>)],
    host: &str,
    serves: impl Fn(&E) -> bool,
) -> Option<&'a E> {
    let host = canonical_hostname(host);
    let serving = |entries: &'a [E]| entries.iter().find(|entry| serves(*entry));
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

/// `path` as a backend that normalises request paths reads it: `\` read
/// as `/` and each segment's `;` parameters dropped, every
/// percent-encoded octet decoded once, `\` and `;` read again in what
/// the decoding produced, each run of `/` merged into one, and the `.`
/// and `..` segments resolved (RFC 3986 section 5.2.4). Borrowed when
/// that changes nothing, which is every path a browser sends.
///
/// Selection itself runs on the path as the client sent it, which is
/// also the path the backend receives. This reading exists for
/// [`selects_alike_once_normalised`]. It is deliberately broader than
/// RFC 3986 normalisation (which decodes unreserved characters only and
/// keeps `//`), because what matters is what some backend may make of
/// the path: nginx decodes every octet and merges slashes before it
/// matches a location, a servlet container reads `/a;x=1/b` as `/a/b`,
/// and a Windows backend reads `\` as a separator.
///
/// The parameters and separators are read before the decoding, as
/// Tomcat and Spring strip parameters from the undecoded path: read
/// after it only, `/%61dmin;%2F..%2Fpublic` would decode its parameter
/// into a `..` segment that climbs out of `/admin`, a segment the
/// container never sees, which strips `;%2F..%2Fpublic` and serves
/// `/admin`. They are read once more after the decoding, so `%3B` and
/// `%5C` count as the `;` and the `\` a backend that decodes first
/// reads them as. Case is left as it is.
///
/// ```
/// use lorica_config::route_selection::normalised_path;
/// assert_eq!(normalised_path("/%61dmin/x"), "/admin/x");
/// assert_eq!(normalised_path("//admin"), "/admin");
/// assert_eq!(normalised_path("/public/../admin/"), "/admin/");
/// assert_eq!(normalised_path("/%2e%2e/admin"), "/admin");
/// assert_eq!(normalised_path("/..;/admin"), "/admin");
/// assert_eq!(normalised_path("/x\\..\\admin"), "/admin");
/// assert!(matches!(
///     normalised_path("/admin/x"),
///     std::borrow::Cow::Borrowed(_)
/// ));
/// ```
pub fn normalised_path(path: &str) -> Cow<'_, str> {
    if !path.contains(['%', ';', '\\']) && !path.contains("//") && !path.contains("/.") {
        return Cow::Borrowed(path);
    }
    let decoded = percent_decoded_once(&separators_and_parameters_read(path));
    let read = separators_and_parameters_read(&decoded);
    let leading_slash = read.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    let mut ends_in_a_directory = false;
    for segment in read.split('/') {
        ends_in_a_directory = matches!(segment, "" | "." | "..");
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            name => segments.push(name),
        }
    }
    let mut normalised = String::with_capacity(read.len());
    if leading_slash {
        normalised.push('/');
    }
    normalised.push_str(&segments.join("/"));
    if ends_in_a_directory && !segments.is_empty() {
        normalised.push('/');
    }
    if normalised == path {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(normalised)
    }
}

/// `text` with each `\` read as `/`, and each `;` dropped with the rest
/// of its segment, up to the next separator: the segment parameters a
/// servlet container strips (`/a;jsessionid=1/b` is `/a/b`). Borrowed
/// when `text` holds neither.
fn separators_and_parameters_read(text: &str) -> Cow<'_, str> {
    if !text.contains([';', '\\']) {
        return Cow::Borrowed(text);
    }
    let mut read = String::with_capacity(text.len());
    let mut in_parameters = false;
    for c in text.chars() {
        match c {
            '/' | '\\' => {
                in_parameters = false;
                read.push('/');
            }
            ';' => in_parameters = true,
            c if !in_parameters => read.push(c),
            _ => {}
        }
    }
    Cow::Owned(read)
}

/// `text` with every `%XX` (two hex digits) replaced by its octet, once,
/// and an octet sequence that is not UTF-8 read lossily. A `%` that does
/// not start such a triplet is kept.
fn percent_decoded_once(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let octet = (bytes[at] == b'%')
            .then(|| bytes.get(at + 1..at + 3))
            .flatten()
            .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match octet {
            Some(octet) => {
                decoded.push(octet);
                at += 3;
            }
            None => {
                decoded.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Whether `path` and its [`normalised_path`] are served by the same
/// entry and, within its route, by the same path rule, or both by none.
/// The normalised path is matched against each route's prefix and each
/// rule's path read the same way, so a prefix stored with an encoded
/// octet still matches the decoded request.
///
/// When they differ, a backend that normalises paths would serve, under
/// the route or the rule the raw path selects, a resource the normalised
/// path's route or rule covers: `/%61dmin` reaching a catch-all route
/// that does not require what the `/admin` route requires, or a rule on
/// `/admin` that denies it, then `/admin` at the backend. The proxy
/// refuses such a request rather than guess which reading the backend
/// applies.
pub fn selects_alike_once_normalised<E, F>(
    exact: &HashMap<String, Vec<E>>,
    wildcards: &[(String, Vec<E>)],
    host: &str,
    path: &str,
    route_of: F,
) -> bool
where
    F: Fn(&E) -> &Route,
{
    let Cow::Owned(normalised) = normalised_path(path) else {
        return true;
    };
    let as_sent = select(exact, wildcards, host, path, &route_of);
    let as_normalised = select_where(exact, wildcards, host, |entry| {
        normalised.starts_with(normalised_path(&route_of(entry).path_prefix).as_ref())
    });
    match (as_sent, as_normalised) {
        (None, None) => true,
        (Some(sent), Some(normalised_entry)) => {
            std::ptr::eq(sent, normalised_entry)
                && selects_the_same_path_rule(route_of(sent), path, &normalised)
        }
        _ => false,
    }
}

/// Whether `path`, and `normalised` matched against each rule's path
/// read the same way, select the same rule of `route`, or both none.
/// First match wins on both readings, as everywhere rules are
/// evaluated ([`Route::matching_path_rule`]).
fn selects_the_same_path_rule(route: &Route, path: &str, normalised: &str) -> bool {
    let as_sent = route.matching_path_rule(path).map(|(index, _)| index);
    let as_normalised = route
        .path_rules
        .iter()
        .position(|rule| rule.matches_as(&normalised_path(&rule.path), normalised));
    as_sent == as_normalised
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
    fn a_normalised_path_decodes_merges_and_resolves_dot_segments() {
        for (sent, read) in [
            ("/%61dmin", "/admin"),
            ("/%41dmin", "/Admin"),
            ("//admin", "/admin"),
            ("/./admin", "/admin"),
            ("/x/../admin", "/admin"),
            ("/%2e%2e/admin", "/admin"),
            ("/x%2f..%2fadmin", "/admin"),
            ("/admin/./", "/admin/"),
            ("/admin/x/..", "/admin/"),
            ("/../../admin", "/admin"),
            ("/a%2", "/a%2"),
            ("/a%+1", "/a%+1"),
            ("/caf%C3%A9", "/café"),
        ] {
            assert_eq!(normalised_path(sent), read, "{sent}");
        }
        for unchanged in ["/", "/admin", "/admin/", "/.well-known/acme-challenge/x"] {
            assert!(
                matches!(normalised_path(unchanged), Cow::Borrowed(_)),
                "{unchanged}"
            );
        }
    }

    #[test]
    fn a_path_that_selects_another_route_once_normalised_is_told_apart() {
        let routes = [
            route("public", "app.example.com", "/"),
            route("admin", "app.example.com", "/admin"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        let alike = |path: &str| {
            selects_alike_once_normalised(
                &index.exact,
                &index.wildcards,
                "app.example.com",
                path,
                |r| *r,
            )
        };
        for steered in [
            "/%61dmin/x",
            "//admin",
            "/./admin",
            "/x/../admin",
            "/%2e%2e/admin",
        ] {
            assert_eq!(served(&index, "app.example.com", steered), Some("public"));
            assert!(!alike(steered), "{steered}");
        }
        // Normalisation that leaves the route alone is no ambiguity.
        for harmless in [
            "/admin",
            "/admin//x",
            "/admin/./x",
            "/files/My%20Doc",
            "/x/../y",
        ] {
            assert!(alike(harmless), "{harmless}");
        }
        // A path that leaves the protected route once normalised is one
        // too: a backend that does not normalise could serve it as
        // `/admin/...`.
        assert!(!alike("/admin/../public"));
    }

    #[test]
    fn a_normalised_path_reads_segment_parameters_and_backslashes() {
        for (sent, read) in [
            ("/a;x=1/b", "/a/b"),
            ("/admin;jsessionid=0", "/admin"),
            ("/;x/admin", "/admin"),
            ("/..;/admin", "/admin"),
            ("/x/..;x=1/admin", "/admin"),
            ("/a%3Bx=1/b", "/a/b"),
            ("/..%3b/admin", "/admin"),
            ("/x\\..\\admin", "/admin"),
            ("\\admin", "/admin"),
            ("/x%5C..%5Cadmin", "/admin"),
            ("/x%5c..%5cadmin", "/admin"),
            ("/admin\\", "/admin/"),
            // A parameter is dropped before the decoding, so an encoded
            // separator inside it cannot mint the segment it spells, as
            // a container that strips parameters first never sees it.
            ("/%61dmin;%2F..%2Fpublic", "/admin"),
            ("/admin;%2F..%2F..%2Fpublic/x", "/admin/x"),
        ] {
            assert_eq!(normalised_path(sent), read, "{sent}");
        }
    }

    #[test]
    fn a_path_steered_by_parameters_or_backslashes_is_told_apart() {
        let routes = [
            route("public", "app.example.com", "/"),
            route("admin", "app.example.com", "/admin"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        let alike = |path: &str| {
            selects_alike_once_normalised(
                &index.exact,
                &index.wildcards,
                "app.example.com",
                path,
                |r| *r,
            )
        };
        for steered in [
            "/;x=1/admin/x",
            "/..;/admin/x",
            "/..%3B/admin/x",
            "/x\\..\\admin/x",
            "/x%5C..%5Cadmin/x",
            "/%61dmin;%2F..%2Fpublic",
        ] {
            assert_eq!(served(&index, "app.example.com", steered), Some("public"));
            assert!(!alike(steered), "{steered}");
        }
        for harmless in ["/admin;x=1/y", "/public;jsessionid=0", "/files\\x"] {
            assert!(alike(harmless), "{harmless}");
        }
    }

    #[test]
    fn a_path_that_selects_another_path_rule_once_normalised_is_told_apart() {
        use crate::models::{PathMatchType, PathRule};
        let mut public = route("public", "app.example.com", "/");
        public.path_rules = vec![
            PathRule {
                path: "/admin".into(),
                return_status: Some(403),
                ..Default::default()
            },
            PathRule {
                path: "/health".into(),
                match_type: PathMatchType::Exact,
                return_status: Some(200),
                ..Default::default()
            },
            PathRule {
                path: "/caf%C3%A9".into(),
                rate_limit_rps: Some(1),
                ..Default::default()
            },
        ];
        let routes = [public];
        let index = HostIndex::new(routes.iter(), |r| *r);
        let alike = |path: &str| {
            selects_alike_once_normalised(
                &index.exact,
                &index.wildcards,
                "app.example.com",
                path,
                |r| *r,
            )
        };
        // One route either way, but a rule on one reading and none, or
        // another, on the other.
        for steered in [
            "/%61dmin",
            "//admin/x",
            "/x/../admin",
            "/..;/admin",
            "/x%5C..%5Cadmin",
            "/admin/../x",
            "/%68ealth",
            "/health;x",
            "/caf%c3%a9",
        ] {
            assert!(!alike(steered), "{steered}");
        }
        for harmless in [
            "/admin",
            "/admin//x",
            "/admin;x=1",
            "/x//y",
            "/health",
            "/caf%C3%A9/menu",
        ] {
            assert!(alike(harmless), "{harmless}");
        }
    }

    #[test]
    fn a_prefix_stored_encoded_matches_the_decoded_request() {
        let routes = [
            route("public", "app.example.com", "/"),
            route("cafe", "app.example.com", "/caf%C3%A9"),
        ];
        let index = HostIndex::new(routes.iter(), |r| *r);
        assert!(selects_alike_once_normalised(
            &index.exact,
            &index.wildcards,
            "app.example.com",
            "/caf%C3%A9/menu",
            |r| *r,
        ));
    }

    #[test]
    fn a_host_no_route_serves_is_alike_both_ways() {
        let routes = [route("admin", "app.example.com", "/admin")];
        let index = HostIndex::new(routes.iter(), |r| *r);
        let alike = |path: &str| {
            selects_alike_once_normalised(
                &index.exact,
                &index.wildcards,
                "app.example.com",
                path,
                |r| *r,
            )
        };
        assert!(alike("/x/%2e%2e/other"));
        // No route as sent, the protected one once normalised.
        assert!(!alike("/x/../admin"));
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
    fn a_primary_hostname_takes_every_shape_the_selection_serves_and_nothing_else() {
        for accepted in [
            "app.example.com",
            "localhost",
            "a",
            "*.example.com",
            CATCH_ALL_HOSTNAME,
            "192.0.2.10",
            "[2001:db8::1]",
            "xn--bcher-kva.example",
        ] {
            assert_eq!(
                validate_hostname_syntax(accepted, ROUTE_HOSTNAME_SHAPE).as_deref(),
                Ok(accepted),
                "{accepted}"
            );
        }
        for refused in [
            "",
            "https://app.example.com",
            "app.example.com/path",
            "app.example.com:8443",
            "user@app.example.com",
            "app example.com",
            "app.example.com.",
            ".example.com",
            "a..example.com",
            "-app.example.com",
            "app_1.example.com",
            "*",
            "a.*.example.com",
            "[not-an-address]",
            "2001:db8::1",
            "Bücher.example",
        ] {
            let refusal =
                validate_hostname_syntax(refused, ROUTE_HOSTNAME_SHAPE).expect_err(refused);
            assert!(refusal.starts_with("hostname "), "{refused}: {refusal}");
        }
        // The two forms only a primary takes are explicit flags.
        let alias = HostnameShape {
            allow_catch_all: false,
            allow_ipv6_literal: false,
            ..ROUTE_HOSTNAME_SHAPE
        };
        assert!(validate_hostname_syntax(CATCH_ALL_HOSTNAME, alias).is_err());
        assert!(validate_hostname_syntax("[2001:db8::1]", alias).is_err());
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
