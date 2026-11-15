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

//! Which rule of a TLS stream a ClientHello matches (Story 12.4 D-d).
//!
//! The rules are tried by level, never by their order in the stream:
//!
//! 1. a server name present: the rules naming it exactly, then the
//!    wildcard rules covering it (at any depth, as a route's wildcard
//!    does), the most specific pattern first ([`wildcard_precedence`]),
//!    one pattern at a time;
//! 2. no server name: the `no_sni` rules, and nothing else.
//!
//! Within a level the client's ALPN offer decides: the rule holding the
//! client's most preferred offered protocol wins; when no rule of the
//! level holds an offered protocol, a rule with an empty `alpn` holds;
//! when none does either, the next level is tried. A client offering no
//! ALPN matches only empty-`alpn` rules. Validation refuses two rules
//! of a stream sharing a name (or both `no_sni`) whose ALPN sets meet,
//! so at most one rule of a level can win.

use lorica_config::models::{StreamMatchRule, StreamMatcher};
use lorica_config::route_selection::{wildcard_covers, wildcard_precedence};

/// The rule of `rules` a ClientHello naming `server_name` (canonical,
/// as [`super::client_hello::Parsed::server_name`] gives it) and
/// offering `offered_alpn` (in the client's order) matches; `None` when
/// no rule does, which refuses the connection `no_match`.
pub fn select<'a>(
    rules: &'a [StreamMatchRule],
    server_name: Option<&str>,
    offered_alpn: &[Vec<u8>],
) -> Option<&'a StreamMatchRule> {
    let Some(name) = server_name else {
        let level = rules
            .iter()
            .filter(|rule| matches!(rule.matcher, StreamMatcher::NoSni { .. }));
        return by_alpn(level, offered_alpn);
    };
    let tls_rules = || {
        rules
            .iter()
            .filter(|rule| matches!(rule.matcher, StreamMatcher::Tls { .. }))
    };
    let exact = tls_rules().filter(|rule| rule.matcher.server_names().iter().any(|n| n == name));
    if let Some(rule) = by_alpn(exact, offered_alpn) {
        return Some(rule);
    }
    let mut patterns: Vec<&str> = tls_rules()
        .flat_map(|rule| rule.matcher.server_names())
        .filter(|pattern| pattern.starts_with('*') && wildcard_covers(pattern, name))
        .map(String::as_str)
        .collect();
    patterns.sort_by(|a, b| wildcard_precedence(a, b));
    patterns.dedup();
    patterns.into_iter().find_map(|pattern| {
        let level =
            tls_rules().filter(|rule| rule.matcher.server_names().iter().any(|n| n == pattern));
        by_alpn(level, offered_alpn)
    })
}

/// The ALPN step within one level.
fn by_alpn<'a>(
    level: impl Iterator<Item = &'a StreamMatchRule>,
    offered_alpn: &[Vec<u8>],
) -> Option<&'a StreamMatchRule> {
    let level: Vec<&StreamMatchRule> = level.collect();
    offered_alpn
        .iter()
        .find_map(|offer| {
            level.iter().copied().find(|rule| {
                rule.matcher
                    .alpn()
                    .iter()
                    .any(|protocol| protocol.as_bytes() == offer.as_slice())
            })
        })
        .or_else(|| {
            level
                .iter()
                .copied()
                .find(|rule| rule.matcher.alpn().is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(name: &str, names: &[&str], alpn: &[&str]) -> StreamMatchRule {
        StreamMatchRule {
            name: name.into(),
            matcher: StreamMatcher::Tls {
                server_names: names.iter().map(|n| n.to_string()).collect(),
                alpn: alpn.iter().map(|a| a.to_string()).collect(),
            },
        }
    }

    fn no_sni(name: &str, alpn: &[&str]) -> StreamMatchRule {
        StreamMatchRule {
            name: name.into(),
            matcher: StreamMatcher::NoSni {
                alpn: alpn.iter().map(|a| a.to_string()).collect(),
            },
        }
    }

    fn offer(protocols: &[&str]) -> Vec<Vec<u8>> {
        protocols.iter().map(|p| p.as_bytes().to_vec()).collect()
    }

    fn picked(rules: &[StreamMatchRule], name: Option<&str>, alpn: &[&str]) -> Option<String> {
        select(rules, name, &offer(alpn)).map(|rule| rule.name.clone())
    }

    #[test]
    fn an_exact_name_beats_every_wildcard() {
        let rules = [
            tls("wild", &["*.example.com"], &[]),
            tls("exact", &["app.example.com"], &[]),
        ];
        assert_eq!(
            picked(&rules, Some("app.example.com"), &[]).as_deref(),
            Some("exact")
        );
        assert_eq!(
            picked(&rules, Some("other.example.com"), &[]).as_deref(),
            Some("wild")
        );
    }

    #[test]
    fn wildcards_cover_any_depth_the_most_specific_first() {
        let rules = [
            tls("broad", &["*.example.com"], &[]),
            tls("narrow", &["*.eu.example.com"], &[]),
        ];
        assert_eq!(
            picked(&rules, Some("a.b.eu.example.com"), &[]).as_deref(),
            Some("narrow")
        );
        assert_eq!(
            picked(&rules, Some("a.b.us.example.com"), &[]).as_deref(),
            Some("broad")
        );
        assert_eq!(picked(&rules, Some("example.com"), &[]), None);
        assert_eq!(picked(&rules, Some("example.org"), &[]), None);
    }

    #[test]
    fn the_client_preference_decides_between_alpn_rules() {
        let rules = [
            tls("grpc", &["api.example.com"], &["h2"]),
            tls("web", &["api.example.com"], &["http/1.1"]),
        ];
        assert_eq!(
            picked(&rules, Some("api.example.com"), &["h2", "http/1.1"]).as_deref(),
            Some("grpc")
        );
        assert_eq!(
            picked(&rules, Some("api.example.com"), &["http/1.1", "h2"]).as_deref(),
            Some("web")
        );
        // GREASE and unknown values are skipped, not matched.
        assert_eq!(
            picked(&rules, Some("api.example.com"), &["\u{a}\u{a}", "h2"]).as_deref(),
            Some("grpc")
        );
        assert_eq!(picked(&rules, Some("api.example.com"), &[]), None);
    }

    #[test]
    fn an_empty_alpn_rule_holds_any_offer_and_none_after_the_alpn_rules() {
        let rules = [
            tls("pg", &["db.example.com"], &["postgresql"]),
            tls("any", &["db.example.com"], &[]),
        ];
        assert_eq!(
            picked(&rules, Some("db.example.com"), &["postgresql"]).as_deref(),
            Some("pg")
        );
        assert_eq!(
            picked(&rules, Some("db.example.com"), &["h2"]).as_deref(),
            Some("any")
        );
        assert_eq!(
            picked(&rules, Some("db.example.com"), &[]).as_deref(),
            Some("any")
        );
    }

    #[test]
    fn a_level_whose_alpn_does_not_hold_falls_through_to_the_next() {
        let rules = [
            tls("exact-h2", &["app.example.com"], &["h2"]),
            tls("wild", &["*.example.com"], &[]),
        ];
        assert_eq!(
            picked(&rules, Some("app.example.com"), &["http/1.1"]).as_deref(),
            Some("wild")
        );
        assert_eq!(
            picked(&rules, Some("app.example.com"), &["h2"]).as_deref(),
            Some("exact-h2")
        );
    }

    #[test]
    fn a_client_without_sni_reaches_only_no_sni_rules() {
        let with = [tls("named", &["*.example.com"], &[]), no_sni("bare", &[])];
        let without = [tls("named", &["*.example.com"], &[])];
        assert_eq!(picked(&with, None, &[]).as_deref(), Some("bare"));
        assert_eq!(picked(&without, None, &[]), None);
        assert_eq!(
            picked(&with, Some("a.example.com"), &[]).as_deref(),
            Some("named"),
            "a client with SNI never reaches a no_sni rule"
        );
        let alpn_only = [no_sni("bare-h2", &["h2"])];
        assert_eq!(
            picked(&alpn_only, None, &["h2"]).as_deref(),
            Some("bare-h2")
        );
        assert_eq!(picked(&alpn_only, None, &[]), None);
    }
}
