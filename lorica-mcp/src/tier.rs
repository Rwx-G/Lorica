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

//! Story 11.4 AC #1: the tier partition, as data.
//!
//! # One table, every reader
//!
//! [`TIERS`] names, for each [`Tier`], the scopes it REQUIRES and the
//! scopes it TOLERATES. Every automation scope sits in exactly one
//! tier's required set, which a test derives from the token model's
//! own enum. A tier tolerates a scope of another tier only when its own
//! tools cannot work without it: the config tier's previews answer the
//! row they would change and need that row's read scope, and its tools
//! find the ids they act on through the read tier's listings. The read
//! tier tolerates no write scope and the admin tier tolerates nothing.
//!
//! Everything that has to know what a tier is reads this table and
//! nothing else: the startup refusal ([`resolve`]), the registry rule
//! ([`Tier::registers`]) that [`crate::server::McpServer`] builds its
//! tool list with, its startup notice, the
//! `lorica mcp token create --tier` minting command, the lifetime it
//! mints with when none is named, and the blast radius it prints. A
//! scope moved between tiers moves all of them.
//!
//! # Why the refusal is here and not in an adapter
//!
//! One process serves one tier. A token carrying `logs:read` and
//! `routes:write` would start a server that reads attacker-authored
//! text and holds a mutating tool, which is the session the tiering
//! exists to prevent. [`resolve`] is what refuses it, and
//! [`crate::server::McpServer::sharing`] calls it, so the stdio binding,
//! which builds one server at startup, and the Streamable HTTP binding,
//! which builds one per request, both inherit the refusal from the one
//! constructor they share rather than from a check each had to
//! remember.
//!
//! # The environment scopes are partitioned and never minted
//!
//! `environments:read` and `environments:write` have no MCP tool: the
//! environment resource is a CI pipeline's surface. They still sit in a
//! tier, so a token carrying one is judged like any other, and
//! [`Tier::minted_scopes`] leaves them out, because a scope no tool
//! uses is reach the minted credential would carry for nothing.

use core::fmt;
use core::str::FromStr;

use crate::tools::{catalogue, ToolSpec};

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
    pub requires: &'static [&'static str],
    /// Scopes of another tier this tier's tools need, and so allows
    /// beside its own.
    pub tolerates: &'static [&'static str],
    /// The lifetime, in days, `lorica mcp token create --tier` mints
    /// with when `--lifetime-days` is not given (maintainer decision,
    /// 2026-09-30): the further a tier reaches, the shorter it lives
    /// unattended. The node refuses a `settings:write` token past
    /// `AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS` whatever this
    /// says, and a test holds every tier minting that scope beneath it.
    pub default_lifetime_days: i64,
}

/// The read tier.
const READ: TierDefinition = TierDefinition {
    tier: Tier::Read,
    requires: &[
        "logs:read",
        "waf:read",
        "sla:read",
        "cluster:read",
        "backends:read",
        "routes:read",
        "certificates:read",
        "environments:read",
    ],
    tolerates: &[],
    default_lifetime_days: 90,
};

/// The config tier.
const CONFIG: TierDefinition = TierDefinition {
    tier: Tier::Config,
    requires: &[
        "routes:write",
        "backends:write",
        "certificates:write",
        "environments:write",
    ],
    tolerates: &["backends:read", "routes:read", "certificates:read"],
    default_lifetime_days: 7,
};

/// The admin tier.
const ADMIN: TierDefinition = TierDefinition {
    tier: Tier::Admin,
    requires: &["settings:write"],
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
    pub fn requires(self) -> &'static [&'static str] {
        self.definition().requires
    }

    /// The scopes of another tier this tier allows because its tools
    /// need them.
    pub fn tolerates(self) -> &'static [&'static str] {
        self.definition().tolerates
    }

    /// The lifetime, in days, a token of this tier is minted with when
    /// the operator names none.
    pub fn default_lifetime_days(self) -> i64 {
        self.definition().default_lifetime_days
    }

    /// Whether a token of this tier may carry `scope`.
    pub fn allows(self, scope: &str) -> bool {
        self.requires().contains(&scope) || self.tolerates().contains(&scope)
    }

    /// The tools this tier owns, in catalogue order.
    pub fn tools(self) -> impl Iterator<Item = &'static ToolSpec> {
        catalogue().iter().filter(move |spec| spec.tier == self)
    }

    /// Whether a server of this tier registers `spec` for a token that
    /// holds its scope: a tool of the tier's own, or a tool whose scope
    /// the tier tolerates.
    pub fn serves(self, spec: &ToolSpec) -> bool {
        spec.tier == self || self.tolerates().contains(&spec.scope)
    }

    /// Whether a server of this tier registers `spec` for a token
    /// holding `held`: a tool it serves, behind a scope the token holds.
    ///
    /// The one registry rule. [`crate::server::McpServer::sharing`]
    /// builds its tool list with it, and the blast radius
    /// `lorica mcp token create` prints is computed with it, so the two
    /// cannot describe different registries.
    ///
    /// For a token [`resolve`] accepted, holding the scope already
    /// implies [`Self::serves`]: every scope it holds is one this tier
    /// requires or tolerates, and a required scope's tools are this
    /// tier's own. The `serves` half is a tripwire behind those tested
    /// invariants, not a filter that removes anything today; it is kept
    /// because the types do not express them.
    pub fn registers<S: AsRef<str>>(self, spec: &ToolSpec, held: &[S]) -> bool {
        self.serves(spec) && held.iter().any(|scope| scope.as_ref() == spec.scope)
    }

    /// The scopes this tier's own tools sit behind, once each, in
    /// catalogue order.
    pub fn tool_scopes(self) -> Vec<&'static str> {
        deduplicated(self.tools().map(|spec| spec.scope))
    }

    /// The scopes `lorica mcp token create --tier` mints: the tier's
    /// tool scopes and what it tolerates.
    ///
    /// A required scope no tool of the tier uses is left out (see the
    /// module documentation on the environment scopes), and a tolerated
    /// one is put in, since the tier's tools do not work without it.
    pub fn minted_scopes(self) -> Vec<&'static str> {
        deduplicated(
            self.tool_scopes()
                .into_iter()
                .chain(self.tolerates().iter().copied()),
        )
    }

    /// The tier whose required set names `scope`, or `None` for a
    /// spelling no tier knows.
    pub fn of_scope(scope: &str) -> Option<Tier> {
        Tier::ALL
            .into_iter()
            .find(|tier| tier.requires().contains(&scope))
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
        let names: Vec<&str> = Tier::ALL.into_iter().map(Tier::as_str).collect();
        write!(f, "a tier is one of {}", names.join(", "))
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
/// `whoami`.
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
/// # Errors
///
/// [`TierError`] naming the scopes that put the token in two tiers, a
/// scope no tier knows, or the absence of any scope at all.
pub fn resolve(scopes: &[String]) -> Result<Tier, TierError> {
    let tier: Option<Tier> = scopes
        .iter()
        .filter_map(|scope| Tier::of_scope(scope))
        .max();
    let offending: Vec<String> = scopes
        .iter()
        .filter(|scope| tier.is_none_or(|tier| !tier.allows(scope)))
        .cloned()
        .collect();
    match tier {
        Some(tier) if offending.is_empty() => Ok(tier),
        _ => Err(TierError {
            tier,
            anchoring: scopes
                .iter()
                .filter(|scope| tier.is_some_and(|tier| tier.requires().contains(&scope.as_str())))
                .cloned()
                .collect(),
            offending,
        }),
    }
}

/// `names` with later repeats dropped, order kept.
pub(crate) fn deduplicated(names: impl IntoIterator<Item = &'static str>) -> Vec<&'static str> {
    let mut kept: Vec<&'static str> = Vec::new();
    for name in names {
        if !kept.contains(&name) {
            kept.push(name);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lorica_config::models::AutomationScope;

    use super::*;
    use crate::tools::{Kind, ADMIN_MUTATIONS, MUTATIONS, READS};
    use lorica_config::models::{OidcIssuer, AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS};

    /// How the token model spells `scope`.
    fn wire(scope: AutomationScope) -> String {
        serde_json::to_value(scope)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .expect("a scope serialises to a string")
    }

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_string()).collect()
    }

    #[test]
    fn every_automation_scope_is_required_by_exactly_one_tier() {
        // The partition's own invariant, walked from the token model's
        // enum rather than from a list typed here: a scope added to
        // `AutomationScope` is in no tier until someone decides which,
        // and this is what makes that decision unavoidable.
        assert!(!AutomationScope::ALL.is_empty());
        for scope in AutomationScope::ALL {
            let spelled = wire(*scope);
            let requiring: Vec<Tier> = Tier::ALL
                .into_iter()
                .filter(|tier| tier.requires().contains(&spelled.as_str()))
                .collect();
            assert_eq!(
                requiring.len(),
                1,
                "{spelled} is required by {requiring:?}; it must be required by exactly one tier"
            );
        }
        // And the table names nothing the enum does not declare, in
        // either of its columns.
        let declared: BTreeSet<String> = AutomationScope::ALL.iter().copied().map(wire).collect();
        for definition in TIERS {
            for scope in definition.requires.iter().chain(definition.tolerates) {
                assert!(
                    declared.contains(*scope),
                    "{}: {scope} is not an AutomationScope spelling",
                    definition.tier
                );
            }
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
                    scope.ends_with(":read"),
                    "{tier} tolerates the write {scope}"
                );
            }
        }
        for scope in Tier::Read.requires() {
            assert!(scope.ends_with(":read"), "the read tier requires {scope}");
        }
        assert!(Tier::Read.tolerates().is_empty());
        assert!(Tier::Admin.tolerates().is_empty());
    }

    #[test]
    fn what_a_tier_tolerates_is_what_its_own_tools_send_you_to_read() {
        // Derived rather than asserted: a tier's tools name the read
        // tools an operator or a model finds their ids through, in
        // their summaries and in the doc of the id they take. The reads
        // those name, outside the tier's own required set, are exactly
        // what the tier tolerates. A config tool that starts pointing at
        // another listing without the table moving, or a tolerated read
        // no tool of the tier needs any more, turns this red.
        for tier in Tier::ALL {
            let mut named: BTreeSet<&str> = BTreeSet::new();
            for spec in tier.tools() {
                let mut text = spec.summary.to_string();
                if let Some(param) = spec.resource {
                    text.push_str(param.doc);
                }
                if let Some(body) = spec.body() {
                    text.push_str(body.doc);
                }
                for read in READS {
                    if text.contains(&format!("`{}`", read.name)) {
                        named.insert(read.scope);
                    }
                }
            }
            let expected: BTreeSet<&str> = named
                .into_iter()
                .filter(|scope| !tier.requires().contains(scope))
                .collect();
            let tolerated: BTreeSet<&str> = tier.tolerates().iter().copied().collect();
            assert_eq!(tolerated, expected, "{tier}");
        }
    }

    #[test]
    fn a_tier_tolerates_only_the_read_of_a_resource_it_writes() {
        // The security invariant `what_a_tier_tolerates...` cannot hold:
        // that test derives the tolerated set from what the tools' prose
        // names, so a config tool whose summary started naming
        // `lorica_logs` would turn it red asking for `logs:read` to be
        // tolerated, which every test above would then accept. This one
        // refuses it by structure: a tier may tolerate `X:read` only when
        // it requires `X:write`, so no tier that writes ever tolerates a
        // read with no write of its own (the access log, WAF events,
        // SLA, the cluster status), which is where attacker-written
        // traffic comes from.
        for tier in Tier::ALL {
            for scope in tier.tolerates() {
                let resource = scope
                    .strip_suffix(":read")
                    .expect("a tolerated scope is a read (asserted above)");
                let write = format!("{resource}:write");
                assert!(
                    tier.requires().contains(&write.as_str()),
                    "{tier} tolerates {scope} without requiring {write}"
                );
            }
        }
    }

    #[test]
    fn a_tier_minting_settings_write_defaults_within_the_nodes_lifetime_ceiling() {
        // Two crates, one rule: the node refuses a settings:write token
        // past its ceiling, and `--tier` mints with this table's default
        // when no lifetime is named. A default past the ceiling would be
        // a command whose default invocation the node refuses.
        let settings_write = AutomationScope::SettingsWrite.as_str();
        let mut bounded = 0;
        for tier in Tier::ALL {
            assert!(tier.default_lifetime_days() > 0, "{tier}");
            if tier.minted_scopes().contains(&settings_write) {
                bounded += 1;
                assert!(
                    tier.default_lifetime_days() <= AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS,
                    "{tier} mints for {} days, past the node's ceiling of {}",
                    tier.default_lifetime_days(),
                    AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS
                );
            }
        }
        assert!(bounded > 0, "no tier mints settings:write");
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
    fn an_oidc_issuer_entry_may_carry_no_scope_the_admin_tier_requires() {
        // `lorica-config` refuses the admin tier on an issuer entry by
        // naming one variant, since it cannot see this table. This is
        // what ties the two: a scope joining the admin tier without the
        // issuer refusal following it turns this red.
        let entry_carrying = |scope: &str| -> OidcIssuer {
            serde_json::from_value(serde_json::json!({
                "id": "issuer-1",
                "issuer": "https://gitlab.example.com",
                "audience": "lorica-prod",
                "jwks_url": "https://gitlab.example.com/oauth/discovery/keys",
                "bound_claims": { "project_path": "acme/*" },
                "allowed_hostnames": [],
                "allowed_backend_cidrs": [],
                "max_ttl_seconds": 3600,
                "scopes": [scope],
                "created_by": "admin",
                "created_at": "2026-01-01T00:00:00Z",
            }))
            .expect("test setup: an issuer entry")
        };
        assert!(!Tier::Admin.requires().is_empty());
        for scope in Tier::Admin.requires() {
            let refused = entry_carrying(scope).validate();
            assert!(refused.is_err(), "an issuer entry carries {scope}");
        }
        // And the refusal is about the scope, not the fixture: a read
        // scope on the same entry validates.
        entry_carrying("logs:read")
            .validate()
            .expect("the fixture is otherwise valid");
    }

    #[test]
    fn every_tool_carries_the_tier_of_the_array_it_comes_from_and_a_scope_that_tier_requires() {
        // For a mutation, `catalogue()` sets the tier FROM the array it
        // walks, so the array check below cannot fail for the config and
        // admin tools; it pins the nine `READS` literals, which carry
        // their tier by hand. The scope and kind checks are real for
        // every tool.
        let reads: BTreeSet<&str> = READS.iter().map(|spec| spec.name).collect();
        let config: BTreeSet<&str> = MUTATIONS
            .iter()
            .flat_map(|mutation| [mutation.apply, mutation.preview])
            .collect();
        let admin: BTreeSet<&str> = ADMIN_MUTATIONS
            .iter()
            .flat_map(|mutation| [mutation.apply, mutation.preview])
            .collect();
        for spec in catalogue() {
            let expected = if reads.contains(spec.name) {
                Tier::Read
            } else if config.contains(spec.name) {
                Tier::Config
            } else {
                assert!(
                    admin.contains(spec.name),
                    "{} comes from no array",
                    spec.name
                );
                Tier::Admin
            };
            assert_eq!(spec.tier, expected, "{}", spec.name);
            assert!(
                spec.tier.requires().contains(&spec.scope),
                "{} sits behind {}, which the {} does not require",
                spec.name,
                spec.scope,
                spec.tier
            );
            assert_eq!(matches!(spec.kind, Kind::Read), spec.tier == Tier::Read);
        }
        // Every tier owns a tool, or `--tier` would mint a token that
        // registers nothing.
        for tier in Tier::ALL {
            assert!(tier.tools().next().is_some(), "{tier} owns no tool");
        }
    }

    #[test]
    fn the_config_tier_is_the_grant_bounded_one_and_no_other_tier_carries_a_bounded_scope() {
        // `lorica mcp token create` asks for hostname and backend grants
        // by tier, and the token model requires them by scope. The two
        // rules agree because the grant-bounded scopes are exactly the
        // config tier's required set, which is what this pins.
        let bounded: BTreeSet<String> = AutomationScope::ALL
            .iter()
            .copied()
            .filter(|scope| scope.is_grant_bounded())
            .map(wire)
            .collect();
        let config: BTreeSet<String> = owned(Tier::Config.requires()).into_iter().collect();
        assert_eq!(bounded, config);
        for tier in [Tier::Read, Tier::Admin] {
            for scope in tier.minted_scopes() {
                assert!(!bounded.contains(scope), "{tier} mints the bounded {scope}");
            }
        }
    }

    #[test]
    fn a_minted_tier_carries_its_tools_scopes_and_what_it_tolerates_and_resolves_to_itself() {
        for tier in Tier::ALL {
            let minted = tier.minted_scopes();
            for scope in tier.tool_scopes() {
                assert!(minted.contains(&scope), "{tier} does not mint {scope}");
            }
            for scope in tier.tolerates() {
                assert!(minted.contains(scope), "{tier} does not mint {scope}");
            }
            for scope in &minted {
                assert!(tier.allows(scope), "{tier} mints {scope}, which it refuses");
            }
            assert_eq!(resolve(&owned(&minted)), Ok(tier));
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
    fn a_tier_registers_what_it_serves_behind_a_held_scope_and_nothing_else() {
        for tier in Tier::ALL {
            let held = tier.minted_scopes();
            for spec in catalogue() {
                assert_eq!(
                    tier.registers(spec, &held),
                    tier.serves(spec) && held.contains(&spec.scope),
                    "{tier}: {}",
                    spec.name
                );
                // No scope held, nothing registered.
                assert!(!tier.registers(spec, &[] as &[&str]));
            }
        }
    }

    #[test]
    fn every_pair_of_scopes_from_two_tiers_is_refused_unless_one_tolerates_the_other() {
        // Walked over the whole table, both orders, so the rule is the
        // table's and not the handful of pairs somebody thought of.
        for first in Tier::ALL {
            for second in Tier::ALL.into_iter().filter(|tier| *tier != first) {
                for a in first.requires() {
                    for b in second.requires() {
                        let pair = owned(&[a, b]);
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
                                assert!(named.contains(a) && named.contains(b), "{named}");
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
