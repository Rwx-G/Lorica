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

//! Compiled capture predicates: the read side of a
//! [`lorica_config::models::CaptureRule`].
//!
//! Everything an operator can write that needs parsing (a path regex, a
//! header regex, a list of source CIDRs) is turned into its runtime form
//! once, when a configuration snapshot is built, and only read from
//! there on. A request never compiles a regex (Story 10.1 AC #7).
//!
//! Two gates, in order:
//!
//! 1. [`CompiledCaptureRules::candidates_for_request`], on the request,
//!    answers "which rules on this route consider this request at all".
//! 2. [`CompiledCaptureRule::should_emit`], on the response, answers
//!    "is this exchange worth writing out".

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use lorica_config::models::{CaptureRule, HeaderMatch, HeaderMatchType, CAPTURE_PATTERN_MAX_LEN};
use regex::{Regex, RegexBuilder};
use tracing::warn;

/// Upper bound on the compiled size, in bytes, of any regex built from a
/// capture rule.
///
/// The number is `WafEngine::MAX_CUSTOM_REGEX_SIZE`, and the two budgets
/// are meant to agree: both gate `RegexBuilder::build` on a pattern an
/// authenticated operator supplied, and there is no reason a capture
/// pattern should be allowed to cost more at compile time than a custom
/// WAF pattern. It is the second half of the pair whose first half,
/// [`CAPTURE_PATTERN_MAX_LEN`], `lorica-config` already applies to the
/// source text; that crate has no `regex` dependency, so it cannot
/// measure the compiled automaton and this one does.
pub const CAPTURE_REGEX_SIZE_LIMIT: usize = 512 * 1024;

/// One header predicate with its value matcher already built.
///
/// The regex lives inside the `Regex` variant rather than beside an
/// untyped match kind, so "declared as a regex but holding no compiled
/// pattern" is not a state the hot path has to consider.
#[derive(Debug)]
enum ValueMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

#[derive(Debug)]
struct CompiledHeaderMatch {
    name: String,
    matcher: ValueMatcher,
}

impl CompiledHeaderMatch {
    fn compile(header: &HeaderMatch) -> Result<Self, String> {
        let matcher = match header.match_type {
            HeaderMatchType::Exact => ValueMatcher::Exact(header.value.clone()),
            HeaderMatchType::Prefix => ValueMatcher::Prefix(header.value.clone()),
            HeaderMatchType::Regex => ValueMatcher::Regex(compile_pattern(&header.value)?),
        };
        Ok(Self {
            name: header.name.clone(),
            matcher,
        })
    }

    /// Whether `headers` carries this header with a satisfying value.
    ///
    /// A header whose value is not UTF-8 cannot satisfy any of the three
    /// string predicates, so it reads as absent rather than as an error:
    /// a capture rule is a diagnostic, and one odd byte upstream must
    /// not turn into a per-request failure path.
    fn matches(&self, headers: &http::HeaderMap) -> bool {
        let Some(value) = headers
            .get(self.name.as_str())
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        match &self.matcher {
            ValueMatcher::Exact(expected) => value == expected,
            ValueMatcher::Prefix(prefix) => value.starts_with(prefix.as_str()),
            ValueMatcher::Regex(re) => re.is_match(value),
        }
    }
}

/// One capture rule with every operator pattern already parsed.
///
/// Holds the stored rule verbatim alongside the compiled forms, because
/// the later slices that act on a match (body buffering, redaction,
/// output paths) read `capture`, `limits`, `output` and `redact` from it
/// and would otherwise need a second lookup.
#[derive(Debug)]
pub struct CompiledCaptureRule {
    /// The stored rule this was built from.
    pub rule: CaptureRule,
    /// Compiled `match.path_regex`, when the rule sets one.
    path_regex: Option<Regex>,
    /// Compiled `match.headers`, in declaration order.
    headers: Vec<CompiledHeaderMatch>,
    /// Parsed `match.source_cidrs`. Empty means the rule does not
    /// constrain the client address.
    source_nets: Vec<IpNet>,
}

impl CompiledCaptureRule {
    /// Build the runtime form of `rule`.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when a pattern exceeds
    /// [`CAPTURE_PATTERN_MAX_LEN`] or [`CAPTURE_REGEX_SIZE_LIMIT`], when
    /// a pattern is not a valid regex, or when a source CIDR does not
    /// parse. The caller logs it and drops the single rule; see
    /// [`CompiledCaptureRules::compile`].
    fn compile(rule: &CaptureRule) -> Result<Self, String> {
        let path_regex = rule
            .match_
            .path_regex
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(compile_pattern)
            .transpose()?;

        let headers = rule
            .match_
            .headers
            .iter()
            .map(CompiledHeaderMatch::compile)
            .collect::<Result<Vec<_>, _>>()?;

        // A rule that names source addresses and ends up with none
        // parsed would read as "any client", widening the rule instead
        // of narrowing it. Refusing the whole rule on any bad entry is
        // the only outcome that cannot silently record more traffic
        // than the operator asked for.
        let source_nets = rule
            .match_
            .source_cidrs
            .iter()
            .map(|entry| parse_net(entry))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            rule: rule.clone(),
            path_regex,
            headers,
            source_nets,
        })
    }

    /// Whether every `match` predicate holds for this request.
    ///
    /// Predicates are ANDed and an unset one imposes nothing, so an
    /// empty `match` block considers every request on the route.
    fn matches_request(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        client_ip: IpAddr,
    ) -> bool {
        self.method_matches(method)
            && self.path_matches(path)
            && self.source_matches(client_ip)
            && self.headers.iter().all(|h| h.matches(headers))
    }

    /// Methods are stored uppercase (the config model refuses anything
    /// else), and the comparison tolerates a lowercase request token so
    /// an odd client does not slip past a rule aimed at it.
    fn method_matches(&self, method: &str) -> bool {
        let methods = &self.rule.match_.methods;
        methods.is_empty()
            || methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
    }

    fn path_matches(&self, path: &str) -> bool {
        let prefix_ok = self
            .rule
            .match_
            .path_prefix
            .as_deref()
            .is_none_or(|prefix| path.starts_with(prefix));
        let regex_ok = self.path_regex.as_ref().is_none_or(|re| re.is_match(path));
        prefix_ok && regex_ok
    }

    fn source_matches(&self, client_ip: IpAddr) -> bool {
        self.source_nets.is_empty() || self.source_nets.iter().any(|net| net.contains(&client_ip))
    }

    /// Whether the finished exchange is worth writing out.
    ///
    /// `emit.always` records everything the `match` block considered.
    /// Otherwise the predicates are ORed: any satisfied status, or the
    /// latency floor reached, or an upstream failure when the rule asks
    /// for one. The config model refuses `always` combined with any of
    /// the three, so the two arms never overlap.
    pub fn should_emit(&self, status: u16, latency_ms: u64, upstream_error: bool) -> bool {
        let emit = &self.rule.emit;
        if emit.always {
            return true;
        }
        emit.status.iter().any(|m| m.matches(status))
            || emit.min_latency_ms.is_some_and(|floor| latency_ms >= floor)
            || (emit.upstream_error && upstream_error)
    }
}

/// Every compiled capture rule on a node, indexed by route.
///
/// Built once per configuration snapshot and read from every request
/// thereafter.
#[derive(Debug, Default)]
pub struct CompiledCaptureRules {
    /// Rules grouped by `route_id`. The request-side gate always knows
    /// which route matched before it asks anything about captures, so
    /// grouping here turns "any rule on this route" into one hash lookup
    /// instead of a scan over every rule in the fleet's configuration.
    by_route: HashMap<String, Vec<CompiledCaptureRule>>,
}

impl CompiledCaptureRules {
    /// Compile `rules` into the runtime set, dropping the ones that
    /// cannot be built.
    ///
    /// A rule whose regex does not compile, or whose source CIDR does
    /// not parse, is skipped with a warning naming its id, and the rest
    /// of the set is built. A configuration snapshot must never fail to
    /// build because one operator rule is bad: the snapshot also carries
    /// routes, backends and certificates, so refusing it would take the
    /// whole node down over a diagnostic feature.
    ///
    /// Disabled rules are dropped here rather than filtered per request.
    /// `enabled` only changes when the configuration changes, which is
    /// exactly when this runs.
    ///
    /// ```
    /// use lorica::capture::CompiledCaptureRules;
    ///
    /// let rules = CompiledCaptureRules::compile(&[]);
    /// assert!(rules.is_empty());
    /// assert!(!rules.has_rules_for_route("route-1"));
    /// ```
    pub fn compile(rules: &[CaptureRule]) -> Self {
        let mut by_route: HashMap<String, Vec<CompiledCaptureRule>> = HashMap::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            match CompiledCaptureRule::compile(rule) {
                Ok(compiled) => by_route
                    .entry(rule.route_id.clone())
                    .or_default()
                    .push(compiled),
                Err(e) => warn!(
                    capture_rule_id = %rule.id,
                    route_id = %rule.route_id,
                    error = %e,
                    "invalid capture rule, skipping it for this configuration snapshot"
                ),
            }
        }
        Self { by_route }
    }

    /// Whether the set holds no rule at all.
    pub fn is_empty(&self) -> bool {
        self.by_route.is_empty()
    }

    /// Whether any rule targets `route_id`, without evaluating a single
    /// predicate. The cheapest question the request path can ask.
    pub fn has_rules_for_route(&self, route_id: &str) -> bool {
        self.by_route.contains_key(route_id)
    }

    /// Every rule on `route_id`, or an empty slice.
    ///
    /// The response side uses this with the rule ids a request recorded
    /// at `request_filter`, so `emit` is evaluated without running the
    /// `match` predicates a second time on a request already admitted.
    pub fn rules_for_route(&self, route_id: &str) -> &[CompiledCaptureRule] {
        self.by_route.get(route_id).map_or(&[][..], Vec::as_slice)
    }

    /// The rules on `route_id` that consider this request.
    ///
    /// `now` is a parameter rather than a `Utc::now()` call inside, so
    /// the whole request is evaluated against one instant and the tests
    /// are not clock-dependent.
    pub fn candidates_for_request(
        &self,
        route_id: &str,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        client_ip: IpAddr,
        now: DateTime<Utc>,
    ) -> Vec<&CompiledCaptureRule> {
        let Some(on_route) = self.by_route.get(route_id) else {
            return Vec::new();
        };
        on_route
            .iter()
            .filter(|c| c.rule.expires_at > now)
            .filter(|c| c.matches_request(method, path, headers, client_ip))
            .collect()
    }
}

/// Build one operator pattern under both budgets.
fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    if pattern.len() > CAPTURE_PATTERN_MAX_LEN {
        return Err(format!("pattern exceeds {CAPTURE_PATTERN_MAX_LEN} bytes"));
    }
    RegexBuilder::new(pattern)
        .size_limit(CAPTURE_REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("invalid regex: {e}"))
}

/// Parse one `source_cidrs` entry, promoting a bare address to its
/// single-host network the way `connection_filter::parse_cidrs` does.
fn parse_net(entry: &str) -> Result<IpNet, String> {
    let trimmed = entry.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(net);
    }
    trimmed
        .parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| format!("`{entry}` is not a valid IP or CIDR"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use http::{HeaderMap, HeaderValue};
    use lorica_config::models::{
        CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureScope,
        StatusMatch,
    };

    fn now() -> DateTime<Utc> {
        // A fixed instant so expiry assertions read as arithmetic and
        // not as a race with the wall clock.
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: a literal RFC 3339 instant parses")
            .with_timezone(&Utc)
    }

    /// A rule that matches everything on `route-1` and emits on 5xx, so
    /// each test changes exactly one thing.
    fn rule(id: &str) -> CaptureRule {
        CaptureRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            route_id: "route-1".to_string(),
            enabled: true,
            match_: CaptureMatch::default(),
            emit: CaptureEmit {
                always: false,
                status: vec![StatusMatch::ServerError],
                min_latency_ms: None,
                upstream_error: false,
            },
            capture: CaptureScope::default(),
            limits: CaptureLimits::default(),
            output: CaptureOutput::default(),
            redact: CaptureRedaction::default(),
            created_by: "admin".to_string(),
            created_at: now(),
            expires_at: now() + Duration::hours(1),
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name: http::header::HeaderName = name
                .parse()
                .expect("test setup: a literal header name is valid");
            let value =
                HeaderValue::from_str(value).expect("test setup: a literal header value is valid");
            map.insert(name, value);
        }
        map
    }

    /// Evaluate `rules` against one GET on `route-1` and report which
    /// rule ids consider it.
    fn candidate_ids(
        set: &CompiledCaptureRules,
        route_id: &str,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        client_ip: &str,
    ) -> Vec<String> {
        let ip: IpAddr = client_ip
            .parse()
            .expect("test setup: a literal address parses");
        set.candidates_for_request(route_id, method, path, headers, ip, now())
            .into_iter()
            .map(|c| c.rule.id.clone())
            .collect()
    }

    fn plain_get(set: &CompiledCaptureRules, route_id: &str) -> Vec<String> {
        candidate_ids(
            set,
            route_id,
            "GET",
            "/checkout",
            &HeaderMap::new(),
            "10.0.0.7",
        )
    }

    #[test]
    fn an_empty_predicate_set_matches_every_request_on_its_route() {
        let set = CompiledCaptureRules::compile(&[rule("cap-1")]);
        assert_eq!(plain_get(&set, "route-1"), vec!["cap-1".to_string()]);
        assert_eq!(
            candidate_ids(
                &set,
                "route-1",
                "DELETE",
                "/anything/else",
                &headers(&[("x-trace", "abc")]),
                "2001:db8::5",
            ),
            vec!["cap-1".to_string()]
        );
    }

    #[test]
    fn an_empty_predicate_set_matches_no_request_on_another_route() {
        let set = CompiledCaptureRules::compile(&[rule("cap-1")]);
        assert!(plain_get(&set, "route-2").is_empty());
        assert!(set.has_rules_for_route("route-1"));
        assert!(!set.has_rules_for_route("route-2"));
    }

    #[test]
    fn a_method_predicate_admits_only_the_listed_methods() {
        let mut r = rule("cap-1");
        r.match_.methods = vec!["POST".to_string(), "PATCH".to_string()];
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert!(candidate_ids(&set, "route-1", "GET", "/c", &empty, "10.0.0.7").is_empty());
        assert_eq!(
            candidate_ids(&set, "route-1", "POST", "/c", &empty, "10.0.0.7"),
            vec!["cap-1".to_string()]
        );
    }

    #[test]
    fn a_path_prefix_predicate_admits_only_paths_under_it() {
        let mut r = rule("cap-1");
        r.match_.path_prefix = Some("/api/".to_string());
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert!(candidate_ids(&set, "route-1", "GET", "/ui/home", &empty, "10.0.0.7").is_empty());
        assert_eq!(
            candidate_ids(&set, "route-1", "GET", "/api/orders", &empty, "10.0.0.7"),
            vec!["cap-1".to_string()]
        );
    }

    #[test]
    fn a_path_regex_predicate_admits_only_matching_paths() {
        let mut r = rule("cap-1");
        r.match_.path_regex = Some(r"^/orders/\d+$".to_string());
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert!(
            candidate_ids(&set, "route-1", "GET", "/orders/abc", &empty, "10.0.0.7").is_empty()
        );
        assert_eq!(
            candidate_ids(&set, "route-1", "GET", "/orders/42", &empty, "10.0.0.7"),
            vec!["cap-1".to_string()]
        );
    }

    #[test]
    fn an_exact_header_predicate_admits_only_the_exact_value() {
        let mut r = rule("cap-1");
        r.match_.headers = vec![HeaderMatch {
            name: "X-Tenant".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "acme".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[r]);
        assert!(candidate_ids(
            &set,
            "route-1",
            "GET",
            "/c",
            &headers(&[("x-tenant", "acme-corp")]),
            "10.0.0.7",
        )
        .is_empty());
        assert_eq!(
            candidate_ids(
                &set,
                "route-1",
                "GET",
                "/c",
                &headers(&[("x-tenant", "acme")]),
                "10.0.0.7",
            ),
            vec!["cap-1".to_string()]
        );
    }

    #[test]
    fn a_missing_header_never_satisfies_a_header_predicate() {
        let mut r = rule("cap-1");
        r.match_.headers = vec![HeaderMatch {
            name: "X-Tenant".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "acme".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[r]);
        assert!(plain_get(&set, "route-1").is_empty());
    }

    #[test]
    fn a_prefix_header_predicate_admits_any_value_starting_with_it() {
        let mut r = rule("cap-1");
        r.match_.headers = vec![HeaderMatch {
            name: "X-Tenant".to_string(),
            match_type: HeaderMatchType::Prefix,
            value: "acme".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[r]);
        assert_eq!(
            candidate_ids(
                &set,
                "route-1",
                "GET",
                "/c",
                &headers(&[("x-tenant", "acme-corp")]),
                "10.0.0.7",
            ),
            vec!["cap-1".to_string()]
        );
        assert!(candidate_ids(
            &set,
            "route-1",
            "GET",
            "/c",
            &headers(&[("x-tenant", "globex")]),
            "10.0.0.7",
        )
        .is_empty());
    }

    #[test]
    fn a_regex_header_predicate_admits_matching_values_only() {
        let mut r = rule("cap-1");
        r.match_.headers = vec![HeaderMatch {
            name: "X-Trace".to_string(),
            match_type: HeaderMatchType::Regex,
            value: r"^[0-9a-f]{8}$".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[r]);
        assert_eq!(
            candidate_ids(
                &set,
                "route-1",
                "GET",
                "/c",
                &headers(&[("x-trace", "deadbeef")]),
                "10.0.0.7",
            ),
            vec!["cap-1".to_string()]
        );
        assert!(candidate_ids(
            &set,
            "route-1",
            "GET",
            "/c",
            &headers(&[("x-trace", "not-hex")]),
            "10.0.0.7",
        )
        .is_empty());
    }

    #[test]
    fn a_v4_source_cidr_admits_only_addresses_inside_it() {
        let mut r = rule("cap-1");
        r.match_.source_cidrs = vec!["10.0.0.0/8".to_string()];
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert_eq!(
            candidate_ids(&set, "route-1", "GET", "/c", &empty, "10.9.9.9"),
            vec!["cap-1".to_string()]
        );
        assert!(candidate_ids(&set, "route-1", "GET", "/c", &empty, "192.0.2.10").is_empty());
    }

    #[test]
    fn a_v6_source_cidr_admits_only_addresses_inside_it() {
        let mut r = rule("cap-1");
        r.match_.source_cidrs = vec!["2001:db8::/32".to_string()];
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert_eq!(
            candidate_ids(&set, "route-1", "GET", "/c", &empty, "2001:db8::1"),
            vec!["cap-1".to_string()]
        );
        assert!(candidate_ids(&set, "route-1", "GET", "/c", &empty, "2001:db9::1").is_empty());
    }

    #[test]
    fn a_bare_ip_entry_admits_that_single_host() {
        let mut r = rule("cap-1");
        r.match_.source_cidrs = vec!["192.0.2.10".to_string()];
        let set = CompiledCaptureRules::compile(&[r]);
        let empty = HeaderMap::new();
        assert_eq!(
            candidate_ids(&set, "route-1", "GET", "/c", &empty, "192.0.2.10"),
            vec!["cap-1".to_string()]
        );
        assert!(candidate_ids(&set, "route-1", "GET", "/c", &empty, "192.0.2.11").is_empty());
    }

    #[test]
    fn a_rule_whose_source_cidr_does_not_parse_is_skipped_rather_than_widened() {
        let mut r = rule("cap-1");
        r.match_.source_cidrs = vec!["10.0.0.0/33".to_string()];
        let set = CompiledCaptureRules::compile(&[r]);
        assert!(set.is_empty());
    }

    #[test]
    fn predicates_are_anded_so_three_of_four_is_not_a_candidate() {
        let mut r = rule("cap-1");
        r.match_.methods = vec!["POST".to_string()];
        r.match_.path_prefix = Some("/api/".to_string());
        r.match_.source_cidrs = vec!["10.0.0.0/8".to_string()];
        r.match_.headers = vec![HeaderMatch {
            name: "X-Tenant".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "acme".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[r]);
        let good = headers(&[("x-tenant", "acme")]);
        assert_eq!(
            candidate_ids(&set, "route-1", "POST", "/api/orders", &good, "10.0.0.7"),
            vec!["cap-1".to_string()]
        );
        // Method, path and source hold; the header does not.
        let wrong_header = headers(&[("x-tenant", "globex")]);
        assert!(candidate_ids(
            &set,
            "route-1",
            "POST",
            "/api/orders",
            &wrong_header,
            "10.0.0.7",
        )
        .is_empty());
        // Method, path and header hold; the source does not.
        assert!(
            candidate_ids(&set, "route-1", "POST", "/api/orders", &good, "192.0.2.10").is_empty()
        );
    }

    #[test]
    fn a_disabled_rule_is_never_a_candidate() {
        let mut r = rule("cap-1");
        r.enabled = false;
        let set = CompiledCaptureRules::compile(&[r]);
        assert!(set.is_empty());
        assert!(plain_get(&set, "route-1").is_empty());
    }

    #[test]
    fn an_expired_rule_is_never_a_candidate() {
        let mut r = rule("cap-1");
        r.expires_at = now() - Duration::seconds(1);
        let set = CompiledCaptureRules::compile(&[r]);
        assert!(set.has_rules_for_route("route-1"));
        assert!(plain_get(&set, "route-1").is_empty());
    }

    #[test]
    fn a_rule_whose_path_regex_does_not_compile_is_skipped_and_the_others_still_compile() {
        let mut broken = rule("cap-broken");
        broken.match_.path_regex = Some("(unclosed".to_string());
        let set = CompiledCaptureRules::compile(&[broken, rule("cap-good")]);
        assert_eq!(plain_get(&set, "route-1"), vec!["cap-good".to_string()]);
    }

    #[test]
    fn a_rule_whose_header_regex_does_not_compile_is_skipped_and_the_others_still_compile() {
        let mut broken = rule("cap-broken");
        broken.match_.headers = vec![HeaderMatch {
            name: "X-Trace".to_string(),
            match_type: HeaderMatchType::Regex,
            value: "(unclosed".to_string(),
        }];
        let set = CompiledCaptureRules::compile(&[broken, rule("cap-good")]);
        assert_eq!(plain_get(&set, "route-1"), vec!["cap-good".to_string()]);
    }

    #[test]
    fn a_pattern_longer_than_the_source_cap_is_refused_at_compile_time() {
        let pattern = "a".repeat(CAPTURE_PATTERN_MAX_LEN + 1);
        let err = compile_pattern(&pattern).expect_err("an over-length pattern must be refused");
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn a_pattern_whose_compiled_size_exceeds_the_budget_is_refused_at_compile_time() {
        // Short source, enormous automaton: a large Unicode class
        // repeated is exactly the shape the size limit exists for.
        let pattern = r"[\p{L}\p{N}\p{P}]{500}";
        assert!(pattern.len() < CAPTURE_PATTERN_MAX_LEN);
        let err = compile_pattern(pattern).expect_err("an oversized automaton must be refused");
        assert!(err.contains("invalid regex"), "got: {err}");
    }

    #[test]
    fn emit_always_records_regardless_of_status_and_latency() {
        let mut r = rule("cap-1");
        r.emit = CaptureEmit {
            always: true,
            ..CaptureEmit::default()
        };
        let compiled = CompiledCaptureRule::compile(&r).expect("test setup: the rule compiles");
        assert!(compiled.should_emit(200, 0, false));
        assert!(compiled.should_emit(503, 9_000, true));
    }

    #[test]
    fn emit_predicates_are_ored_so_a_slow_two_hundred_still_emits() {
        let mut r = rule("cap-1");
        r.emit = CaptureEmit {
            always: false,
            status: vec![StatusMatch::ServerError],
            min_latency_ms: Some(2_000),
            upstream_error: false,
        };
        let compiled = CompiledCaptureRule::compile(&r).expect("test setup: the rule compiles");
        assert!(compiled.should_emit(200, 3_000, false));
        assert!(compiled.should_emit(503, 5, false));
        assert!(!compiled.should_emit(200, 5, false));
    }

    #[test]
    fn emit_on_upstream_error_only_fires_when_the_rule_asks_for_it() {
        let mut r = rule("cap-1");
        r.emit = CaptureEmit {
            always: false,
            status: vec![],
            min_latency_ms: None,
            upstream_error: true,
        };
        let compiled = CompiledCaptureRule::compile(&r).expect("test setup: the rule compiles");
        assert!(compiled.should_emit(502, 10, true));
        assert!(!compiled.should_emit(502, 10, false));
    }

    #[test]
    fn client_aborted_catches_four_ninety_nine_and_client_error_does_not() {
        let mut aborted = rule("cap-aborted");
        aborted.emit.status = vec![StatusMatch::ClientAborted];
        let aborted =
            CompiledCaptureRule::compile(&aborted).expect("test setup: the rule compiles");
        assert!(aborted.should_emit(499, 0, false));
        assert!(!aborted.should_emit(404, 0, false));

        let mut client_error = rule("cap-4xx");
        client_error.emit.status = vec![StatusMatch::ClientError];
        let client_error =
            CompiledCaptureRule::compile(&client_error).expect("test setup: the rule compiles");
        assert!(!client_error.should_emit(499, 0, false));
        assert!(client_error.should_emit(404, 0, false));
    }

    #[test]
    fn rules_on_different_routes_do_not_see_each_others_requests() {
        let mut other = rule("cap-2");
        other.route_id = "route-2".to_string();
        let set = CompiledCaptureRules::compile(&[rule("cap-1"), other]);
        assert_eq!(plain_get(&set, "route-1"), vec!["cap-1".to_string()]);
        assert_eq!(plain_get(&set, "route-2"), vec!["cap-2".to_string()]);
    }
}
