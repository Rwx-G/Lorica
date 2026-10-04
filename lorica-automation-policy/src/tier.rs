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

//! Story 11.4 AC #1: the MCP tier partition, as data.
//!
//! # One table, every reader
//!
//! [`TIERS`] names, for each [`Tier`], the scopes it REQUIRES and the
//! scopes it TOLERATES. Every automation scope sits in exactly one
//! tier's required set, which a test derives from
//! [`AutomationScope::ALL`]. A tier tolerates a scope of another tier
//! only when its own tools cannot work without it: the config tier's
//! previews answer the row they would change and need that row's read
//! scope, and its tools find the ids they act on through the read
//! tier's listings. The read tier tolerates no write scope and the
//! admin tier tolerates nothing.
//!
//! Everything that has to know what a tier is reads this table and
//! nothing else: the startup refusal ([`resolve`]), the registry rule
//! `lorica-mcp` builds its tool list with, its startup notice, the
//! `lorica mcp token create --tier` minting command, the lifetime it
//! mints with when none is named, the blast radius it prints, the OIDC
//! issuer entry's refusal of the admin tier in `lorica-config`, and the
//! dashboard's mint form, through the generated fixture
//! `lorica-api/tests/automation_scope_fixture.rs` renders from this
//! module. A scope moved between tiers moves all of them.
//!
//! # Why the refusal is here
//!
//! One process serves one tier. A token carrying `logs:read` and
//! `routes:write` would start a server that reads attacker-authored
//! text and holds a mutating tool, which is the session the tiering
//! exists to prevent. [`resolve`] is what refuses it, and `lorica-mcp`
//! calls it from the one constructor both its bindings share. The
//! dashboard replays the same answers from a vector set rendered by
//! [`resolve`], so its warning and this refusal cannot disagree.
//!
//! # The environment scopes are partitioned and never minted
//!
//! `environments:read` and `environments:write` have no MCP tool: the
//! environment resource is a CI pipeline's surface. They still sit in a
//! tier, so a token carrying one is judged like any other, and the
//! minting command leaves them out, because a scope no tool uses is
//! reach the minted credential would carry for nothing.

use core::fmt;
use core::str::FromStr;

use crate::scope::AutomationScope;

/// One of the three MCP tiers.
///
/// Declared in increasing order of what a session holding it can
/// change, which is the order [`resolve`] reads when it names the tier
/// a token's scopes would make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Reads the node: logs, WAF events, SLA windows, the cluster
    /// status, routes, backends and certificate metadata.
    Read,
    /// Changes routes, backends and certificate bindings, bounded by
    /// the token's hostname and backend grants.
    Config,
    /// Changes the operational global settings the plane's allowlist
    /// names.
    Admin,
}

/// What one tier requires and what it tolerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierDefinition {
    /// The tier this row defines.
    pub tier: Tier,
    /// The scopes that make a token this tier. Every automation scope
    /// is in exactly one tier's list.
    pub requires: &'static [AutomationScope],
    /// Scopes of another tier this tier's tools need, and so allows
    /// beside its own.
    pub tolerates: &'static [AutomationScope],
    /// The lifetime, in days, `lorica mcp token create --tier` mints
    /// with when `--lifetime-days` is not given (maintainer decision,
    /// 2026-09-30): the further a tier reaches, the shorter it lives
    /// unattended. The node refuses a `settings:write` token past
    /// [`crate::AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS`] whatever
    /// this says, and a test holds every tier allowing that scope
    /// beneath it.
    pub default_lifetime_days: i64,
}

/// The read tier.
const READ: TierDefinition = TierDefinition {
    tier: Tier::Read,
    requires: &[
        AutomationScope::LogsRead,
        AutomationScope::WafRead,
        AutomationScope::SlaRead,
        AutomationScope::ClusterRead,
        AutomationScope::BackendsRead,
        AutomationScope::RoutesRead,
        AutomationScope::CertificatesRead,
        AutomationScope::EnvironmentsRead,
    ],
    tolerates: &[],
    default_lifetime_days: 90,
};

/// The config tier.
const CONFIG: TierDefinition = TierDefinition {
    tier: Tier::Config,
    requires: &[
        AutomationScope::RoutesWrite,
        AutomationScope::BackendsWrite,
        AutomationScope::CertificatesWrite,
        AutomationScope::EnvironmentsWrite,
    ],
    tolerates: &[
        AutomationScope::BackendsRead,
        AutomationScope::RoutesRead,
        AutomationScope::CertificatesRead,
    ],
    default_lifetime_days: 7,
};

/// The admin tier.
const ADMIN: TierDefinition = TierDefinition {
    tier: Tier::Admin,
    requires: &[AutomationScope::SettingsWrite],
    tolerates: &[],
    default_lifetime_days: 1,
};

/// The tier partition, in [`Tier::ALL`] order.
pub const TIERS: &[TierDefinition] = &[READ, CONFIG, ADMIN];

impl Tier {
    /// Every tier, in increasing order of reach.
    pub const ALL: [Tier; 3] = [Tier::Read, Tier::Config, Tier::Admin];

    /// The tier's name as `--tier` spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Read => "read",
            Tier::Config => "config",
            Tier::Admin => "admin",
        }
    }

    /// This tier's row of [`TIERS`].
    pub fn definition(self) -> &'static TierDefinition {
        match self {
            Tier::Read => &READ,
            Tier::Config => &CONFIG,
            Tier::Admin => &ADMIN,
        }
    }

    /// The scopes that make a token this tier.
    pub fn requires(self) -> &'static [AutomationScope] {
        self.definition().requires
    }

    /// The scopes of another tier this tier allows because its tools
    /// need them.
    pub fn tolerates(self) -> &'static [AutomationScope] {
        self.definition().tolerates
    }

    /// The lifetime, in days, a token of this tier is minted with when
    /// the operator names none.
    pub fn default_lifetime_days(self) -> i64 {
        self.definition().default_lifetime_days
    }

    /// Whether a token of this tier may carry `scope`.
    pub fn allows(self, scope: AutomationScope) -> bool {
        self.requires().contains(&scope) || self.tolerates().contains(&scope)
    }

    /// The tier whose required set names `scope`.
    ///
    /// `None` only if the partition left a scope out, which the test
    /// walking [`AutomationScope::ALL`] refuses.
    pub fn requiring(scope: AutomationScope) -> Option<Tier> {
        Tier::ALL
            .into_iter()
            .find(|tier| tier.requires().contains(&scope))
    }

    /// The tier whose required set names the scope spelled `scope`, or
    /// `None` for a spelling no tier knows.
    pub fn of_scope(scope: &str) -> Option<Tier> {
        AutomationScope::from_wire(scope).and_then(Tier::requiring)
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} tier", self.as_str())
    }
}

/// A `--tier` value that names no tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTier;

impl fmt::Display for UnknownTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a tier is one of {}",
            Tier::ALL.map(Tier::as_str).join(", ")
        )
    }
}

impl std::error::Error for UnknownTier {}

impl FromStr for Tier {
    type Err = UnknownTier;

    fn from_str(value: &str) -> Result<Tier, UnknownTier> {
        Tier::ALL
            .into_iter()
            .find(|tier| tier.as_str() == value)
            .ok_or(UnknownTier)
    }
}

/// Why a token cannot be served by one process.
///
/// Carries scope spellings and tier names only. Naming the scopes
/// discloses nothing: the holder of the token reads the same list from
/// `whoami`. Spellings rather than [`AutomationScope`] values, because
/// a token minted on a newer node carries scopes this build cannot
/// type, and those are exactly the ones the refusal has to name.
///
/// The `Display` is written by hand below: which sentence it is depends
/// on the scopes it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierError {
    /// The tier the token's highest-reaching scopes would make it, or
    /// `None` when it carries no scope any tier requires.
    pub tier: Option<Tier>,
    /// The scopes that name that tier, in the order the token carries
    /// them.
    pub anchoring: Vec<String>,
    /// The scopes that tier does not allow, in the order the token
    /// carries them.
    pub offending: Vec<String>,
}

impl TierError {
    /// Whether every scope refused is one no tier of this build knows,
    /// which is a token minted against a newer node and not two tiers.
    fn only_unknown_scopes(&self) -> bool {
        !self.offending.is_empty()
            && self
                .offending
                .iter()
                .all(|scope| Tier::of_scope(scope).is_none())
    }

    /// What an operator holding a static automation token does about
    /// it, to append after the refusal.
    ///
    /// Kept out of [`fmt::Display`] because the fix depends on the
    /// credential: a static token is minted again per tier, while an
    /// OIDC issuer entry grants its scopes to every matching job and is
    /// split into one entry per tier instead. Each binding appends the
    /// remedy for the credential it saw.
    pub fn remedy_for_static_token(&self) -> String {
        if self.only_unknown_scopes() {
            "Run the lorica-mcp that ships with the node the token was minted on.".to_string()
        } else {
            format!(
                "Mint one token per tier with `lorica mcp token create --tier {}`.",
                tier_names()
            )
        }
    }
}

impl fmt::Display for TierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let placed = |scope: &String| match Tier::of_scope(scope) {
            Some(tier) => format!("{scope} ({tier})"),
            None => format!("{scope} (no tier: not a scope this build of lorica-mcp knows)"),
        };
        let offending: Vec<String> = self.offending.iter().map(placed).collect();
        match self.tier {
            Some(_) if self.only_unknown_scopes() => write!(
                f,
                "this token carries a scope this build of lorica-mcp does not know, most likely \
                 because the node is newer: {}.",
                offending.join(", "),
            ),
            Some(tier) => write!(
                f,
                "this token's scopes span more than one MCP tier, and one process serves one \
                 tier. {} {} it the {tier}, which does not allow {}.",
                self.anchoring.join(", "),
                if self.anchoring.len() == 1 {
                    "makes"
                } else {
                    "make"
                },
                offending.join(", "),
            ),
            None => write!(
                f,
                "this token carries no scope any MCP tier requires: {}.",
                if offending.is_empty() {
                    "it carries none".to_string()
                } else {
                    offending.join(", ")
                },
            ),
        }
    }
}

impl std::error::Error for TierError {}

/// The `--tier` alternatives, as a usage line spells them.
fn tier_names() -> String {
    let names: Vec<&str> = Tier::ALL.into_iter().map(Tier::as_str).collect();
    names.join("|")
}

/// The one tier a token carrying `scopes` is, or why it is none.
///
/// The tier is the highest-reaching one whose required set the token
/// touches; every other scope it carries must be one that tier allows.
/// A config-tier token carrying the reads its tools need is therefore
/// one tier, and a token carrying `logs:read` beside `routes:write` is
/// two and refused, both scopes named.
///
/// ```
/// use lorica_automation_policy::{resolve, Tier};
/// let owned = |scopes: &[&str]| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>();
/// assert_eq!(resolve(&owned(&["routes:write", "routes:read"])), Ok(Tier::Config));
/// let refused = resolve(&owned(&["logs:read", "routes:write"])).unwrap_err();
/// assert_eq!(refused.offending, owned(&["logs:read"]));
/// ```
///
/// # Errors
///
/// [`TierError`] naming the scopes that put the token in two tiers, a
/// scope no tier knows, or the absence of any scope at all.
pub fn resolve(scopes: &[String]) -> Result<Tier, TierError> {
    let tier: Option<Tier> = scopes
        .iter()
        .filter_map(|scope| Tier::of_scope(scope))
        .max();
    let allowed = |tier: Tier, scope: &str| {
        AutomationScope::from_wire(scope).is_some_and(|scope| tier.allows(scope))
    };
    let offending: Vec<String> = scopes
        .iter()
        .filter(|scope| tier.is_none_or(|tier| !allowed(tier, scope)))
        .cloned()
        .collect();
    match tier {
        Some(tier) if offending.is_empty() => Ok(tier),
        _ => Err(TierError {
            tier,
            anchoring: scopes
                .iter()
                .filter(|scope| tier.is_some_and(|tier| Tier::of_scope(scope) == Some(tier)))
                .cloned()
                .collect(),
            offending,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS;

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_string()).collect()
    }

    fn spelled(scopes: &[AutomationScope]) -> Vec<String> {
        scopes.iter().map(|scope| scope.to_string()).collect()
    }

    #[test]
    fn every_automation_scope_is_required_by_exactly_one_tier() {
        // The partition's own invariant, walked from the enum rather
        // than from a list typed here: a scope added to
        // `AutomationScope` is in no tier until someone decides which,
        // and this is what makes that decision unavoidable.
        assert!(!AutomationScope::ALL.is_empty());
        for scope in AutomationScope::ALL {
            let requiring: Vec<Tier> = Tier::ALL
                .into_iter()
                .filter(|tier| tier.requires().contains(scope))
                .collect();
            assert_eq!(
                requiring.len(),
                1,
                "{scope} is required by {requiring:?}; it must be required by exactly one tier"
            );
            assert_eq!(Tier::requiring(*scope), Some(requiring[0]));
            assert_eq!(Tier::of_scope(scope.as_str()), Some(requiring[0]));
        }
        for definition in TIERS {
            let unique: BTreeSet<&str> = definition
                .requires
                .iter()
                .chain(definition.tolerates)
                .map(|scope| scope.as_str())
                .collect();
            assert_eq!(
                unique.len(),
                definition.requires.len() + definition.tolerates.len(),
                "{} names a scope twice",
                definition.tier
            );
        }
    }

    #[test]
    fn the_table_is_in_tier_order_and_each_row_defines_its_own_tier() {
        assert_eq!(TIERS.len(), Tier::ALL.len());
        for (definition, tier) in TIERS.iter().zip(Tier::ALL) {
            assert_eq!(definition.tier, tier);
            assert_eq!(tier.definition(), definition);
        }
    }

    #[test]
    fn a_tier_tolerates_only_what_it_does_not_require_and_never_a_write_of_another_tier() {
        // The read tier holds no write scope by any route, which is the
        // property the whole tiering rests on: a session reading
        // attacker-authored text holds nothing that changes the node.
        for tier in Tier::ALL {
            for scope in tier.tolerates() {
                assert!(!tier.requires().contains(scope), "{tier}: {scope} twice");
                assert!(
                    scope.as_str().ends_with(":read"),
                    "{tier} tolerates the write {scope}"
                );
            }
        }
        for scope in Tier::Read.requires() {
            assert!(
                scope.as_str().ends_with(":read"),
                "the read tier requires {scope}"
            );
        }
        assert!(Tier::Read.tolerates().is_empty());
        assert!(Tier::Admin.tolerates().is_empty());
    }

    #[test]
    fn a_tier_tolerates_only_the_read_of_a_resource_it_writes() {
        // A tier may tolerate `X:read` only when it requires `X:write`,
        // so no tier that writes ever tolerates a read with no write of
        // its own (the access log, WAF events, SLA, the cluster
        // status), which is where attacker-written traffic comes from.
        // `lorica-mcp` derives the tolerated set from what its tools'
        // prose names; this is the structural bound that derivation
        // cannot widen.
        for tier in Tier::ALL {
            for scope in tier.tolerates() {
                let resource = scope
                    .as_str()
                    .strip_suffix(":read")
                    .expect("a tolerated scope is a read (asserted above)");
                let write = format!("{resource}:write");
                assert!(
                    tier.requires()
                        .iter()
                        .any(|required| required.as_str() == write),
                    "{tier} tolerates {scope} without requiring {write}"
                );
            }
        }
    }

    #[test]
    fn a_tier_allowing_settings_write_defaults_within_the_nodes_lifetime_ceiling() {
        // The node refuses a settings:write token past its ceiling, and
        // `--tier` mints with this table's default when no lifetime is
        // named. A default past the ceiling would be a command whose
        // default invocation the node refuses. Weighed on everything a
        // tier allows, which is more than it mints.
        let mut bounded = 0;
        for tier in Tier::ALL {
            assert!(tier.default_lifetime_days() > 0, "{tier}");
            if tier.allows(AutomationScope::SettingsWrite) {
                bounded += 1;
                assert!(
                    tier.default_lifetime_days() <= AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS,
                    "{tier} mints for {} days, past the node's ceiling of {}",
                    tier.default_lifetime_days(),
                    AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS
                );
            }
        }
        assert!(bounded > 0, "no tier allows settings:write");
        // Reach orders the defaults: a tier that changes more lives
        // shorter unattended.
        for pair in Tier::ALL.windows(2) {
            assert!(
                pair[0].default_lifetime_days() >= pair[1].default_lifetime_days(),
                "{} outlives {}",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn the_config_tier_is_the_grant_bounded_one_and_no_other_tier_allows_a_bounded_scope() {
        // `lorica mcp token create` asks for hostname and backend grants
        // by tier, and the token model requires them by scope. The two
        // rules agree because the grant-bounded scopes are exactly the
        // config tier's required set, which is what this pins.
        let bounded: BTreeSet<&str> = AutomationScope::ALL
            .iter()
            .filter(|scope| scope.is_grant_bounded())
            .map(|scope| scope.as_str())
            .collect();
        let config: BTreeSet<&str> = Tier::Config
            .requires()
            .iter()
            .map(|scope| scope.as_str())
            .collect();
        assert_eq!(bounded, config);
        for tier in [Tier::Read, Tier::Admin] {
            for scope in tier.requires().iter().chain(tier.tolerates()) {
                assert!(
                    !bounded.contains(scope.as_str()),
                    "{tier} allows the bounded {scope}"
                );
            }
        }
    }

    #[test]
    fn every_tier_resolves_to_itself_on_everything_it_allows() {
        for tier in Tier::ALL {
            let allowed: Vec<AutomationScope> = tier
                .requires()
                .iter()
                .chain(tier.tolerates())
                .copied()
                .collect();
            assert_eq!(resolve(&spelled(&allowed)), Ok(tier));
            for scope in &allowed {
                assert!(tier.allows(*scope), "{tier} refuses {scope}");
            }
        }
    }

    #[test]
    fn iv1_a_token_carrying_logs_read_and_routes_write_is_refused_with_both_named() {
        let refused = resolve(&owned(&["logs:read", "routes:write"]))
            .expect_err("a token spanning two tiers is refused");
        assert_eq!(refused.tier, Some(Tier::Config));
        assert_eq!(refused.anchoring, owned(&["routes:write"]));
        assert_eq!(refused.offending, owned(&["logs:read"]));
        let message = refused.to_string();
        assert!(message.contains("logs:read"), "{message}");
        assert!(message.contains("routes:write"), "{message}");
        assert!(message.contains("read tier"), "{message}");
        assert!(message.contains("config tier"), "{message}");
        assert!(message.contains("routes:write makes it"), "{message}");
        assert!(refused.remedy_for_static_token().contains("--tier"));
    }

    #[test]
    fn the_refusal_example_in_the_operator_reference_is_the_message_itself() {
        // docs/mcp.md quotes what `lorica-mcp` prints for IV1. Compared
        // with whitespace normalised, since the document wraps it.
        let refused = resolve(&owned(&["logs:read", "routes:write"])).expect_err("IV1");
        let printed = format!(
            "lorica-mcp: {refused} {}",
            refused.remedy_for_static_token()
        );
        let words = |text: &str| text.split_whitespace().collect::<Vec<&str>>().join(" ");
        let reference = words(include_str!("../../docs/mcp.md"));
        assert!(
            reference.contains(&words(&printed)),
            "docs/mcp.md no longer quotes the IV1 refusal as printed:\n{printed}"
        );
    }

    #[test]
    fn a_token_from_a_newer_node_is_told_to_match_versions_not_to_split_tiers() {
        let refused = resolve(&owned(&["logs:read", "dns:write"])).expect_err("unknown scope");
        let message = refused.to_string();
        assert!(!message.contains("span more than one"), "{message}");
        assert!(message.contains("dns:write"), "{message}");
        assert!(!refused.remedy_for_static_token().contains("--tier"));
    }

    #[test]
    fn every_pair_of_scopes_from_two_tiers_is_refused_unless_one_tolerates_the_other() {
        // Walked over the whole table, both orders, so the rule is the
        // table's and not the handful of pairs somebody thought of.
        for first in Tier::ALL {
            for second in Tier::ALL.into_iter().filter(|tier| *tier != first) {
                for a in first.requires() {
                    for b in second.requires() {
                        let pair = spelled(&[*a, *b]);
                        let higher = first.max(second);
                        let tolerated =
                            higher.tolerates().contains(a) || higher.tolerates().contains(b);
                        match resolve(&pair) {
                            Ok(tier) => {
                                assert!(tolerated, "{a} + {b} resolved to {tier}");
                                assert_eq!(tier, higher, "{a} + {b}");
                            }
                            Err(refused) => {
                                assert!(!tolerated, "{a} + {b} refused: {refused}");
                                let named = refused.to_string();
                                assert!(
                                    named.contains(a.as_str()) && named.contains(b.as_str()),
                                    "{named}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_scope_no_tier_knows_and_an_empty_set_are_refused() {
        let refused = resolve(&owned(&["logs:read", "dns:write"])).expect_err("unknown scope");
        assert_eq!(refused.tier, Some(Tier::Read));
        assert_eq!(refused.offending, owned(&["dns:write"]));
        assert!(refused.to_string().contains("dns:write"), "{refused}");

        let refused = resolve(&owned(&["dns:write"])).expect_err("only an unknown scope");
        assert_eq!(refused.tier, None);
        assert!(refused.to_string().contains("dns:write"), "{refused}");

        let refused = resolve(&[]).expect_err("no scope at all");
        assert_eq!(refused.tier, None);
        assert!(refused.offending.is_empty());
    }

    #[test]
    fn a_tier_is_spelled_the_way_the_flag_takes_it() {
        for tier in Tier::ALL {
            assert_eq!(tier.as_str().parse::<Tier>(), Ok(tier));
            assert_eq!(tier.to_string(), format!("{} tier", tier.as_str()));
        }
        assert_eq!("everything".parse::<Tier>(), Err(UnknownTier));
        assert!(UnknownTier.to_string().contains("config"));
    }
}
