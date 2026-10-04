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

//! The automation scope vocabulary (Story 10.3, widened by Epic 11) and
//! the one lifetime rule a scope carries.

use core::fmt;

use serde::{Deserialize, Serialize};

/// The longest lifetime, in days, of an automation token carrying
/// `settings:write` (maintainer decision, 2026-09-30).
///
/// That scope is the MCP admin tier's: it changes fleet-wide
/// operational settings and is minted for the one task that needs it.
/// A short lifetime was advice until this constant; `lorica-config`'s
/// `AutomationToken::validate` now refuses a longer one, so the
/// dashboard, the management API and both CLI commands are held to it
/// by the one validator they share. Every tier that may carry the
/// scope mints with a default at or beneath it, which a test in
/// [`crate::tier`] holds.
pub const AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS: i64 = 7;

/// What an automation token is allowed to do.
///
/// The enum is closed and [`AutomationScope::ALL`] is the whole surface.
/// What is absent from it is absent deliberately: there is no
/// `certificates:upload`, no `users:*` and no `cluster:write`, because
/// key material, identity and fleet membership enter through the
/// management API, by a human, and never through a token.
///
/// The read grants beyond `routes:read` and `certificates:read` arrived
/// with the management MCP server (Epic 11). Its read tier is what
/// consumes them: a session that can only read has nothing an injected
/// instruction can usefully reach.
///
/// The three write grants, `routes:write`, `backends:write` and
/// `certificates:write`, arrived with that server's config tier (Story
/// 11.2) and reverse the Story 10.3 decision that the automation
/// surface is the environment resource and never the management API
/// behind a different door. The reversal is recorded beside that
/// decision in the Epic 10 PRD. A token carrying one of them reaches
/// the management plane's own handler and validators for that
/// resource, bounded by the token's hostname and backend grants; it is
/// a different credential from the one a CI pipeline uses for
/// ephemeral environments, and an operator mints it as such.
///
/// `settings:write` arrived with that server's admin tier (Story 11.3)
/// and reverses the rest of the same Story 10.3 decision for node-wide
/// settings, bounded: it reaches one path, and that path accepts only
/// the keys [`crate::settings::SETTINGS_ALLOWLIST`] names, each with
/// the reason it is there. Every other setting, and every identity and
/// cluster operation, stays out of reach of any token.
///
/// An unknown scope string fails to deserialise rather than being
/// dropped, so a token minted against a newer Lorica is refused here
/// instead of silently losing the grant an operator wrote down.
///
/// ```
/// use lorica_automation_policy::AutomationScope;
/// let scope: AutomationScope =
///     serde_json::from_str("\"environments:write\"").expect("known scope");
/// assert_eq!(scope, AutomationScope::EnvironmentsWrite);
/// assert!(serde_json::from_str::<AutomationScope>("\"users:write\"").is_err());
/// ```
// The serde renames below are this vocabulary's source of truth. The
// surfaces named here carry the same strings and none of them is
// maintained from memory: `AutomationScope::as_str` below (the string
// an operator reads in a 403 and in an audit row) is asserted against
// these renames by a test that walks `ALL`; `lorica-api`'s
// `is_published_reason` publishes them as refusal reasons from `ALL`,
// beside the `AUTOMATION_AUDIT_REASONS` list that carries none of them;
// the two OpenAPI documents restate the enum and
// `lorica-api/tests/openapi_contract.rs` holds each to `ALL`; and
// `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`,
// what the mint form offers, is diffed against `ALL` by
// `lorica-api/tests/automation_scope_fixture.rs`. Add a variant here
// alone and each of those turns red, and so does the tier partition in
// `tier.rs`, which must place it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutomationScope {
    /// Create, update and tear down environments.
    #[serde(rename = "environments:write")]
    EnvironmentsWrite,
    /// Read environments and their state.
    #[serde(rename = "environments:read")]
    EnvironmentsRead,
    /// Read the routes an environment resolves to.
    #[serde(rename = "routes:read")]
    RoutesRead,
    /// Read certificate metadata (never private key material).
    #[serde(rename = "certificates:read")]
    CertificatesRead,
    /// Read access-log rows.
    #[serde(rename = "logs:read")]
    LogsRead,
    /// Read WAF events and their aggregate counts.
    #[serde(rename = "waf:read")]
    WafRead,
    /// Read SLA windows per route.
    #[serde(rename = "sla:read")]
    SlaRead,
    /// Read cluster and node status.
    #[serde(rename = "cluster:read")]
    ClusterRead,
    /// Read the backends a route resolves to.
    #[serde(rename = "backends:read")]
    BackendsRead,
    /// Create, update and delete routes, one by id, and bind a
    /// certificate to one.
    #[serde(rename = "routes:write")]
    RoutesWrite,
    /// Create, update and delete backends, one by id.
    #[serde(rename = "backends:write")]
    BackendsWrite,
    /// Bind a stored certificate to a route and renew an ACME one.
    /// Never an upload: key material is not an argument anywhere on
    /// the automation plane.
    #[serde(rename = "certificates:write")]
    CertificatesWrite,
    /// Change the operational global settings the admin tier's
    /// allowlist names, and nothing else: never an identity, a
    /// credential, a listener or the fleet.
    #[serde(rename = "settings:write")]
    SettingsWrite,
}

impl AutomationScope {
    /// Every variant, in declaration order.
    ///
    /// The one place anything that has to walk the vocabulary reads it
    /// from, so that the surfaces restating the spellings (the
    /// [`AutomationScope::as_str`] match, the published audit
    /// reasons, the dashboard's generated fixture) are each checked
    /// against the enum instead of against somebody's memory of it. A
    /// variant added above and not here fails
    /// `all_carries_every_variant_the_enum_declares`.
    pub const ALL: &'static [AutomationScope] = &[
        AutomationScope::EnvironmentsWrite,
        AutomationScope::EnvironmentsRead,
        AutomationScope::RoutesRead,
        AutomationScope::CertificatesRead,
        AutomationScope::LogsRead,
        AutomationScope::WafRead,
        AutomationScope::SlaRead,
        AutomationScope::ClusterRead,
        AutomationScope::BackendsRead,
        AutomationScope::RoutesWrite,
        AutomationScope::BackendsWrite,
        AutomationScope::CertificatesWrite,
        AutomationScope::SettingsWrite,
    ];

    /// Whether a path this scope reaches consults the credential's
    /// hostname and backend grants.
    ///
    /// The one place the set is decided, and it is decided by what the
    /// automation plane's handlers read, verified on the code: the
    /// environment write checks every hostname and backend address it
    /// claims; the route, backend and certificate writes run the grant
    /// guards on the body and on the stored row they name. No read and
    /// not the settings write consults either grant, so on a credential
    /// carrying none of these the grants bound nothing, and
    /// `lorica-config`'s `validate_automation_grants` refuses them there.
    ///
    /// An exhaustive `match` and not a list, so a scope added to the
    /// enum is a compile error here until somebody decides.
    ///
    /// ```
    /// use lorica_automation_policy::AutomationScope;
    /// assert!(AutomationScope::RoutesWrite.is_grant_bounded());
    /// assert!(!AutomationScope::SettingsWrite.is_grant_bounded());
    /// assert!(!AutomationScope::LogsRead.is_grant_bounded());
    /// ```
    pub fn is_grant_bounded(self) -> bool {
        match self {
            AutomationScope::EnvironmentsWrite
            | AutomationScope::RoutesWrite
            | AutomationScope::BackendsWrite
            | AutomationScope::CertificatesWrite => true,
            AutomationScope::EnvironmentsRead
            | AutomationScope::RoutesRead
            | AutomationScope::CertificatesRead
            | AutomationScope::LogsRead
            | AutomationScope::WafRead
            | AutomationScope::SlaRead
            | AutomationScope::ClusterRead
            | AutomationScope::BackendsRead
            | AutomationScope::SettingsWrite => false,
        }
    }

    /// The scope as the wire spells it: the serde rename, which a test
    /// walking [`Self::ALL`] holds this match to.
    ///
    /// ```
    /// use lorica_automation_policy::AutomationScope;
    /// assert_eq!(AutomationScope::SettingsWrite.as_str(), "settings:write");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            AutomationScope::EnvironmentsWrite => "environments:write",
            AutomationScope::EnvironmentsRead => "environments:read",
            AutomationScope::RoutesRead => "routes:read",
            AutomationScope::CertificatesRead => "certificates:read",
            AutomationScope::LogsRead => "logs:read",
            AutomationScope::WafRead => "waf:read",
            AutomationScope::SlaRead => "sla:read",
            AutomationScope::ClusterRead => "cluster:read",
            AutomationScope::BackendsRead => "backends:read",
            AutomationScope::RoutesWrite => "routes:write",
            AutomationScope::BackendsWrite => "backends:write",
            AutomationScope::CertificatesWrite => "certificates:write",
            AutomationScope::SettingsWrite => "settings:write",
        }
    }

    /// The scope a wire spelling names, or `None` for one this build
    /// does not know.
    ///
    /// ```
    /// use lorica_automation_policy::AutomationScope;
    /// assert_eq!(
    ///     AutomationScope::from_wire("routes:write"),
    ///     Some(AutomationScope::RoutesWrite)
    /// );
    /// assert_eq!(AutomationScope::from_wire("dns:write"), None);
    /// ```
    pub fn from_wire(spelling: &str) -> Option<AutomationScope> {
        AutomationScope::ALL
            .iter()
            .copied()
            .find(|scope| scope.as_str() == spelling)
    }
}

/// The wire spelling, so a message names a scope the way a 403 and the
/// token listing do.
impl fmt::Display for AutomationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The wire spelling, so a rule that weighs the scopes a token holds
/// takes them typed or as the plane spelled them, without a copy.
impl AsRef<str> for AutomationScope {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire spellings this file's enum declares, read back out of
    /// its own source.
    ///
    /// Nothing else in the process can see a serde rename, so the only
    /// way to assert that [`AutomationScope::ALL`] is complete is to
    /// look at what the enum wrote. A hand-written expectation would
    /// need remembering on exactly the day it matters.
    fn renames_declared_by_the_enum() -> Vec<&'static str> {
        const MARKER: &str = "#[serde(rename = \"";
        let body: &'static str = include_str!("scope.rs")
            .split_once("pub enum AutomationScope {")
            .expect("the enum is declared in this file")
            .1
            .split_once("\n}")
            .expect("the enum body ends at a closing brace in column zero")
            .0;
        body.match_indices(MARKER)
            .filter_map(|(at, marker)| body[at + marker.len()..].split_once('"'))
            .map(|(spelling, _)| spelling)
            .collect()
    }

    /// How serde spells `scope`.
    fn serde_spelling(scope: AutomationScope) -> String {
        serde_json::to_value(scope)
            .expect("test setup: a scope serialises")
            .as_str()
            .expect("test setup: a scope serialises to a string")
            .to_string()
    }

    #[test]
    fn all_carries_every_variant_the_enum_declares() {
        let declared: Vec<&str> = renames_declared_by_the_enum();
        assert!(
            !declared.is_empty(),
            "the rename scan found nothing: the enum was reshaped and this guard went blind"
        );
        let spelled: Vec<String> = AutomationScope::ALL
            .iter()
            .copied()
            .map(serde_spelling)
            .collect();
        assert_eq!(
            spelled, declared,
            "AutomationScope::ALL and the enum's serde renames disagree. \
             ALL is what every other surface walks, so a variant missing \
             from it is a grant the 403 cannot name and the mint form \
             cannot offer."
        );
    }

    #[test]
    fn every_scope_round_trips_through_its_exact_wire_string() {
        for scope in AutomationScope::ALL {
            let json = serde_json::to_string(scope).expect("test setup: scope serialises");
            let back: AutomationScope =
                serde_json::from_str(&json).expect("test setup: scope deserialises");
            assert_eq!(back, *scope);
        }
    }

    #[test]
    fn an_unknown_scope_string_fails_to_deserialise_rather_than_being_ignored() {
        // [`AutomationScope::ALL`] is the whole grant surface. Dropping
        // an unknown entry would mint a token narrower than the
        // operator wrote, and they would find out at the first call.
        for unknown in [
            "\"users:write\"",
            "\"certificates:upload\"",
            "\"waf:write\"",
            "\"environments\"",
            "\"\"",
        ] {
            assert!(
                serde_json::from_str::<AutomationScope>(unknown).is_err(),
                "{unknown} must be refused"
            );
        }
    }

    #[test]
    fn a_scope_spells_itself_the_way_serde_does_and_reads_back() {
        assert!(!AutomationScope::ALL.is_empty());
        for scope in AutomationScope::ALL {
            assert_eq!(scope.as_str(), serde_spelling(*scope));
            assert_eq!(scope.to_string(), scope.as_str());
            assert_eq!(AutomationScope::from_wire(scope.as_str()), Some(*scope));
        }
        assert_eq!(AutomationScope::from_wire("users:write"), None);
        assert_eq!(AutomationScope::from_wire(""), None);
    }

    #[test]
    fn the_grant_bounded_scopes_are_writes_and_the_settings_write_is_not_one() {
        // The admin tier's scope reaches the settings path, which no
        // grant bounds; every other write is bounded.
        let mut bounded = 0usize;
        for scope in AutomationScope::ALL {
            if scope.is_grant_bounded() {
                bounded += 1;
                assert!(scope.as_str().ends_with(":write"), "{scope}");
            }
        }
        assert!(bounded > 0);
        assert!(!AutomationScope::SettingsWrite.is_grant_bounded());
    }
}
