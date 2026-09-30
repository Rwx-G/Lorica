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

//! What the config tier may not touch, and what it may only
//! strengthen, as data (Story 11.2, maintainer decision of 2026-09-30,
//! "safe direction only").
//!
//! The rules are declared here; the weighing is not. Whether a patched
//! route is weaker than the stored one is a function of the stored row's
//! types, which live in `lorica-config`, so `lorica-api` pairs each rule
//! below with its predicate (`ROUTE_PROTECTIONS` and
//! `BACKEND_PROTECTIONS` in `automation/write.rs`) and a test there
//! holds the pairing to these lists, in order, one predicate per rule.

/// One access-control or trust control of a stored row that an
/// automation token may move only toward stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionRule {
    /// The fields the rule weighs, as the request bodies spell them.
    pub fields: &'static [&'static str],
    /// The safe direction, in the words a refusal and the docs use.
    pub rule: &'static str,
    /// Why the other direction is the dashboard's and not a token's.
    pub why: &'static str,
}

/// The route controls, one constant each so the plane can pair each
/// with its predicate by name rather than by position.
pub mod route {
    use super::ProtectionRule;

    /// The Basic-auth credential in force.
    pub const BASIC_AUTH: ProtectionRule = ProtectionRule {
        fields: &["basic_auth_username"],
        rule: "the Basic-auth credential in force is neither cleared nor changed",
        why: "clearing the username switches the route's Basic auth off, and renaming it \
              changes a credential whose password a token never sees",
    };

    /// The source-address allowlist.
    pub const IP_ALLOWLIST: ProtectionRule = ProtectionRule {
        fields: &["ip_allowlist"],
        rule: "added, or narrowed so every entry sits inside one already there; never removed \
               or widened",
        why: "an empty allowlist admits every address",
    };

    /// The source-address denylist.
    pub const IP_DENYLIST: ProtectionRule = ProtectionRule {
        fields: &["ip_denylist"],
        rule: "extended, every entry already there staying covered; never shortened",
        why: "an entry removed admits the addresses it refused",
    };

    /// The country filter.
    pub const GEOIP: ProtectionRule = ProtectionRule {
        fields: &["geoip"],
        rule: "added, or tightened in the same mode (fewer countries allowed, more denied); \
               never removed or switched to the other mode",
        why: "the country filter decides who reaches the route at all",
    };

    /// The bot challenge.
    pub const BOT_PROTECTION: ProtectionRule = ProtectionRule {
        fields: &["bot_protection", "bot_protection_disable"],
        rule: "added where none is set; never changed or removed once set",
        why: "its bypass lists and its mode decide which clients skip the challenge, and no \
              ordering of them is safe to move automatically",
    };

    /// The WAF switch.
    pub const WAF_ENABLED: ProtectionRule = ProtectionRule {
        fields: &["waf_enabled"],
        rule: "switched on, never off",
        why: "the WAF is the route's request filter",
    };

    /// The WAF mode.
    pub const WAF_MODE: ProtectionRule = ProtectionRule {
        fields: &["waf_mode"],
        rule: "moved to blocking, never back to detection",
        why: "detection lets every request the WAF flags through",
    };

    /// The token bucket.
    pub const RATE_LIMIT: ProtectionRule = ProtectionRule {
        fields: &["rate_limit"],
        rule: "added, or tightened with its capacity and refill never raised and its scope \
               unchanged; never removed",
        why: "the token bucket is the route's defence against a flood",
    };

    /// The legacy per-client rate pair.
    pub const LEGACY_RATE_LIMIT: ProtectionRule = ProtectionRule {
        fields: &["rate_limit_rps", "rate_limit_burst"],
        rule: "added, or lowered; never raised or cleared",
        why: "the per-client rate is the route's defence against a flood",
    };

    /// The automatic-ban threshold.
    pub const AUTO_BAN_THRESHOLD: ProtectionRule = ProtectionRule {
        fields: &["auto_ban_threshold"],
        rule: "added, or lowered; never raised or cleared",
        why: "the threshold is how many blocks earn an automatic ban, and cleared it bans no one",
    };
}

/// The backend controls, one constant each for the same reason as
/// [`route`]'s.
pub mod backend {
    use super::ProtectionRule;

    /// Upstream certificate verification.
    pub const TLS_SKIP_VERIFY: ProtectionRule = ProtectionRule {
        fields: &["tls_skip_verify"],
        rule: "switched off, never on",
        why: "on, the upstream leg accepts any certificate, so anyone on the path reads and \
              rewrites it",
    };

    /// Upstream TLS.
    pub const TLS_UPSTREAM: ProtectionRule = ProtectionRule {
        fields: &["tls_upstream"],
        rule: "switched on, never off",
        why: "off, the upstream leg is plain text",
    };

    /// The name the upstream certificate is verified against.
    pub const TLS_SNI: ProtectionRule = ProtectionRule {
        fields: &["tls_sni"],
        rule: "left unchanged while the upstream certificate is verified",
        why: "it is the name the upstream certificate is verified against, so changing it with \
              the address inside the grant hands the leg to whoever holds a certificate for the \
              new name",
    };
}

/// Every route control an automation token may only strengthen, in the
/// order a refusal weighs them.
///
/// A route create is not weighed: each of these is at its weakest on
/// the row the management create stores when the body names none of
/// them, so nothing a create sets weakens anything. What is NOT here,
/// and why, is recorded next to the rule in `docs/mcp.md`: the capacity
/// limits (they price a request, they do not decide whether it is
/// admitted), the browser-facing hardening (`force_https`,
/// `security_headers`, the CORS lists and `response_headers`, which
/// shape how a browser treats an answer the route already admits), the
/// AI-crawler policy (a content policy toward clients that declare
/// themselves, which a hostile client does not), and the routing fields
/// (where a request goes, bounded by the hostname and CIDR grants).
pub const ROUTE_PROTECTION_RULES: &[ProtectionRule] = &[
    route::BASIC_AUTH,
    route::IP_ALLOWLIST,
    route::IP_DENYLIST,
    route::GEOIP,
    route::BOT_PROTECTION,
    route::WAF_ENABLED,
    route::WAF_MODE,
    route::RATE_LIMIT,
    route::LEGACY_RATE_LIMIT,
    route::AUTO_BAN_THRESHOLD,
];

/// Every backend control an automation token may only strengthen.
///
/// A create is weighed against the backend the management create
/// stores when the body names none of these, which is plain HTTP,
/// verified whenever TLS is turned on: so a create may not ask for an
/// unverified upstream either.
pub const BACKEND_PROTECTION_RULES: &[ProtectionRule] = &[
    backend::TLS_SKIP_VERIFY,
    backend::TLS_UPSTREAM,
    backend::TLS_SNI,
];

/// The route fields a token may not send at all, whatever the value, a
/// clearing one included, each with the reason the refusal gives.
///
/// None is the tier's in either direction: each is set in the
/// dashboard, by a human, and the config tier's tools offer none of
/// them. The plane refuses them from any automation token, whether it
/// calls a tool or the path.
pub const WITHHELD_ROUTE_FIELDS: &[(&str, &str)] = &[
    (
        "basic_auth_password",
        "it is the route's Basic-auth credential, which a model would be choosing or relaying \
         in the clear, and clearing it switches the route's Basic auth off",
    ),
    (
        "forward_auth",
        "its address is a URL allowed_backend_cidrs cannot weigh, and the proxy forwards every \
         downstream Cookie and Authorization header to it",
    ),
    (
        "mirror",
        "it ships a copy of every request to a second set of backends",
    ),
    (
        "mtls",
        "it is the route's client-authentication trust anchor, the CA whose client certificates \
         the route accepts",
    ),
    (
        "proxy_headers",
        "a static header map to the upstream is where a credential would go",
    ),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn no_field_is_weighed_twice_withheld_and_weighed_or_left_without_words() {
        // A field under two rules would be refused for whichever runs
        // first, and a withheld field under a rule is a rule nothing can
        // reach, so each field has one home.
        let withheld: BTreeSet<&str> = WITHHELD_ROUTE_FIELDS.iter().map(|(f, _)| *f).collect();
        assert_eq!(withheld.len(), WITHHELD_ROUTE_FIELDS.len());
        for rules in [ROUTE_PROTECTION_RULES, BACKEND_PROTECTION_RULES] {
            assert!(!rules.is_empty());
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for rule in rules {
                assert!(!rule.fields.is_empty());
                assert!(!rule.rule.trim().is_empty() && !rule.why.trim().is_empty());
                for field in rule.fields {
                    assert!(seen.insert(field), "{field} is weighed twice");
                    assert!(!withheld.contains(field), "{field} is withheld and weighed");
                }
            }
        }
        for (field, why) in WITHHELD_ROUTE_FIELDS {
            assert!(!why.trim().is_empty(), "{field}");
        }
    }
}
