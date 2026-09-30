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

//! Story 11.4 AC #1: the tier partition, and what it means for this
//! server's tools.
//!
//! # The table is the policy crate's
//!
//! [`TIERS`], [`Tier`] and [`resolve`] are `lorica-automation-policy`'s,
//! re-exported here so this crate's paths to them are unchanged. That
//! crate is where every reader of the partition reads it: this server,
//! the `lorica mcp token create --tier` minting command, the OIDC
//! issuer entry's validator and the dashboard's mint form.
//!
//! # What this module adds is the catalogue
//!
//! A tier's tools, the registry rule and the scopes a tier mints depend
//! on [`crate::tools::catalogue`], which is this crate's. [`TierTools`]
//! carries them. [`TierTools::registers`] is the one registry rule:
//! [`crate::server::McpServer::sharing`] builds its tool list with it,
//! and the blast radius `lorica mcp token create` prints is computed
//! with it, so the two cannot describe different registries.
//!
//! # Why the refusal runs in the constructor and not in an adapter
//!
//! One process serves one tier. [`crate::server::McpServer::sharing`]
//! calls [`resolve`], so the stdio binding, which builds one server at
//! startup, and the Streamable HTTP binding, which builds one per
//! request, both inherit the refusal from the one constructor they
//! share rather than from a check each had to remember.
//!
//! # The environment scopes are partitioned and never minted
//!
//! `environments:read` and `environments:write` have no MCP tool: the
//! environment resource is a CI pipeline's surface. They still sit in a
//! tier, so a token carrying one is judged like any other, and
//! [`TierTools::minted_scopes`] leaves them out, because a scope no tool
//! uses is reach the minted credential would carry for nothing.

use lorica_automation_policy::AutomationScope;

pub use lorica_automation_policy::tier::{
    resolve, Tier, TierDefinition, TierError, UnknownTier, TIERS,
};

use crate::tools::{catalogue, ToolSpec};

/// What a tier means for this server's catalogue.
///
/// A trait because [`Tier`] is the policy crate's type and the
/// catalogue is this crate's; implemented for [`Tier`] alone.
pub trait TierTools: Copy {
    /// The tools this tier owns, in catalogue order.
    fn tools(self) -> impl Iterator<Item = &'static ToolSpec>;

    /// Whether a server of this tier registers `spec` for a token that
    /// holds its scope: a tool of the tier's own, or a tool whose scope
    /// the tier tolerates.
    fn serves(self, spec: &ToolSpec) -> bool;

    /// Whether a server of this tier registers `spec` for a token
    /// holding `held`: a tool it serves, behind a scope the token holds.
    ///
    /// For a token [`resolve`] accepted, holding the scope already
    /// implies [`Self::serves`]: every scope it holds is one this tier
    /// requires or tolerates, and a required scope's tools are this
    /// tier's own. The `serves` half is a tripwire behind those tested
    /// invariants, not a filter that removes anything today; it is kept
    /// because the types do not express them.
    fn registers<S: AsRef<str>>(self, spec: &ToolSpec, held: &[S]) -> bool;

    /// The scopes this tier's own tools sit behind, once each, in
    /// catalogue order.
    fn tool_scopes(self) -> Vec<AutomationScope>;

    /// The scopes `lorica mcp token create --tier` mints: the tier's
    /// tool scopes and what it tolerates.
    ///
    /// A required scope no tool of the tier uses is left out (see the
    /// module documentation on the environment scopes), and a tolerated
    /// one is put in, since the tier's tools do not work without it.
    fn minted_scopes(self) -> Vec<AutomationScope>;
}

impl TierTools for Tier {
    fn tools(self) -> impl Iterator<Item = &'static ToolSpec> {
        catalogue().iter().filter(move |spec| spec.tier == self)
    }

    fn serves(self, spec: &ToolSpec) -> bool {
        spec.tier == self || self.tolerates().contains(&spec.scope)
    }

    fn registers<S: AsRef<str>>(self, spec: &ToolSpec, held: &[S]) -> bool {
        self.serves(spec)
            && held
                .iter()
                .any(|scope| scope.as_ref() == spec.scope.as_str())
    }

    fn tool_scopes(self) -> Vec<AutomationScope> {
        deduplicated(self.tools().map(|spec| spec.scope))
    }

    fn minted_scopes(self) -> Vec<AutomationScope> {
        deduplicated(
            self.tool_scopes()
                .into_iter()
                .chain(self.tolerates().iter().copied()),
        )
    }
}

/// The wire spellings of `scopes`, joined for a sentence.
pub fn joined(scopes: &[AutomationScope]) -> String {
    let spelled: Vec<&str> = scopes.iter().map(|scope| scope.as_str()).collect();
    spelled.join(", ")
}

/// `scopes` with later repeats dropped, order kept.
fn deduplicated(scopes: impl IntoIterator<Item = AutomationScope>) -> Vec<AutomationScope> {
    let mut kept: Vec<AutomationScope> = Vec::new();
    for scope in scopes {
        if !kept.contains(&scope) {
            kept.push(scope);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::tools::{admin_mutations, Kind, MUTATIONS, READS};

    fn spelled(scopes: &[AutomationScope]) -> Vec<String> {
        scopes.iter().map(|scope| scope.to_string()).collect()
    }

    #[test]
    fn what_a_tier_tolerates_is_what_its_own_tools_send_you_to_read() {
        // Derived rather than asserted: a tier's tools name the read
        // tools an operator or a model finds their ids through, in
        // their summaries and in the doc of the id they take. The reads
        // those name, outside the tier's own required set, are exactly
        // what the tier tolerates. A config tool that starts pointing at
        // another listing without the table moving, or a tolerated read
        // no tool of the tier needs any more, turns this red. The policy
        // crate's structural test is what stops this derivation from
        // ever widening the table to a read with no write of its own.
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
                        named.insert(read.scope.as_str());
                    }
                }
            }
            let expected: BTreeSet<&str> = named
                .into_iter()
                .filter(|scope| {
                    !tier
                        .requires()
                        .iter()
                        .any(|required| required.as_str() == *scope)
                })
                .collect();
            let tolerated: BTreeSet<&str> = tier
                .tolerates()
                .iter()
                .map(|scope| scope.as_str())
                .collect();
            assert_eq!(tolerated, expected, "{tier}");
        }
    }

    #[test]
    fn every_tool_carries_the_tier_of_the_array_it_comes_from_and_a_scope_that_tier_requires() {
        // For a mutation, `catalogue()` sets the tier FROM the array it
        // walks, so the array check below cannot fail for the config and
        // admin tools; it pins the `READS` literals, which carry their
        // tier by hand. The scope and kind checks are real for
        // every tool.
        let reads: BTreeSet<&str> = READS.iter().map(|spec| spec.name).collect();
        let config: BTreeSet<&str> = MUTATIONS
            .iter()
            .flat_map(|mutation| [mutation.apply, mutation.preview])
            .collect();
        let admin: BTreeSet<&str> = admin_mutations()
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
    fn no_tier_but_the_config_tier_mints_a_grant_bounded_scope() {
        // `lorica mcp token create` asks for hostname and backend grants
        // by tier, and the token model requires them by scope; the
        // policy crate pins the bounded set to the config tier's
        // required set, and this pins what the other tiers mint.
        for tier in [Tier::Read, Tier::Admin] {
            for scope in tier.minted_scopes() {
                assert!(
                    !scope.is_grant_bounded(),
                    "{tier} mints the bounded {scope}"
                );
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
                assert!(
                    tier.allows(*scope),
                    "{tier} mints {scope}, which it refuses"
                );
            }
            assert_eq!(resolve(&spelled(&minted)), Ok(tier));
        }
    }

    #[test]
    fn a_tier_registers_what_it_serves_behind_a_held_scope_and_nothing_else() {
        for tier in Tier::ALL {
            let held = spelled(&tier.minted_scopes());
            for spec in catalogue() {
                assert_eq!(
                    tier.registers(spec, &held),
                    tier.serves(spec) && held.contains(&spec.scope.to_string()),
                    "{tier}: {}",
                    spec.name
                );
                // No scope held, nothing registered.
                assert!(!tier.registers(spec, &[] as &[&str]));
            }
        }
    }

    #[test]
    fn a_tier_never_registers_a_tool_it_does_not_serve_even_behind_a_held_scope() {
        // The `serves` half of the registry rule, observed: every held
        // set above comes from the tier itself, and for those holding
        // the scope already implies serving the tool. Here the token
        // holds exactly the tool's own scope and the tier still says
        // no, which is what deleting the `serves` check would change.
        for tier in Tier::ALL {
            let foreign: Vec<&ToolSpec> = catalogue()
                .iter()
                .filter(|spec| !tier.serves(spec))
                .collect();
            assert!(!foreign.is_empty(), "the {tier} serves every tool");
            for spec in foreign {
                assert!(
                    !tier.registers(spec, &[spec.scope.as_str()]),
                    "the {tier} registers {} behind {}",
                    spec.name,
                    spec.scope
                );
            }
        }
    }

    #[test]
    fn joined_spells_the_scopes_in_order() {
        assert_eq!(
            joined(&[AutomationScope::LogsRead, AutomationScope::RoutesWrite]),
            "logs:read, routes:write"
        );
        assert_eq!(joined(&[]), "");
    }
}
