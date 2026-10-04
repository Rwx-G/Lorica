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

//! Story 11.3: the admin tier's whole surface, the global settings an
//! automation token holding `settings:write` may change, each with its
//! reason, its bound, the direction it may move in, where a write lands
//! and when it acts.
//!
//! `lorica-api` enforces it on `PUT /automation/v1/settings`,
//! `lorica-mcp` builds the settings tool's body and bounds from it,
//! `lorica mcp token create --tier admin` prints it as the blast
//! radius, and `docs/mcp.md` tabulates it under a test that renders
//! each row from the entry.

/// Which way the admin tier may move a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Anywhere inside the bound.
    Either,
    /// Up from the stored value, never below it, and inside the bound:
    /// a retention lowered destroys rows that setting it back does not
    /// bring back.
    RaiseOnly,
}

/// How far a setting's effect reaches when it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Fleet policy (`CanonicalGlobalSettings`): on a control plane it
    /// replicates to every follower.
    Fleet,
    /// This node only.
    Node,
}

impl Reach {
    /// How an operator reads it, in `docs/mcp.md`'s settings table and
    /// in the blast radius `lorica mcp token create --tier admin` prints.
    pub fn describe(self) -> &'static str {
        match self {
            Reach::Fleet => "fleet",
            Reach::Node => "this node",
        }
    }
}

/// When a stored value starts to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakesEffect {
    /// On the next reload or the next run of the loop that reads it,
    /// without a restart.
    Live,
    /// At the next restart of the process that reads it.
    Restart,
}

impl TakesEffect {
    /// How an operator reads it, in the same two places as
    /// [`Reach::describe`].
    pub fn describe(self) -> &'static str {
        match self {
            TakesEffect::Live => "live",
            TakesEffect::Restart => "at restart",
        }
    }
}

/// One global setting the admin tier may change, why it may, and how
/// far it may move it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminSetting {
    /// The key, as `GlobalSettings` and `UpdateSettingsRequest` spell it.
    pub name: &'static str,
    /// Why a model driving the admin tier may change it: what makes it
    /// operational, and why a value inside its bound is undone from the
    /// dashboard without having taken anything down. Read by no surface
    /// a model or an operator sees: it is the reason an entry arrives
    /// with, required non-empty by a test so the allowlist grows only by
    /// a stated decision.
    pub why: &'static str,
    /// The lowest value this tier may set, inclusive. The dashboard's
    /// own validator still runs after this one and may be narrower.
    pub min: i64,
    /// The highest value this tier may set, inclusive.
    pub max: i64,
    /// Which way inside `min..=max` this tier may move it.
    pub direction: Direction,
    /// Where a write lands.
    pub reach: Reach,
    /// When a write acts.
    pub takes_effect: TakesEffect,
    /// A rule the management validator adds to this key beyond the
    /// tier's bound, in the words the MCP tool states it in beside the
    /// bound: a model told only the bound would be refused by a rule
    /// it was never shown. Not part of the bound, and not enforced
    /// here; the management validator is what enforces it.
    pub validator_also: Option<&'static str>,
}

impl AdminSetting {
    /// The bound as the docs, the tool description and a refusal spell
    /// it: `14..=365`, or `raise-only, 1..=1000000`.
    ///
    /// ```
    /// use lorica_automation_policy::admin_setting;
    /// let setting = admin_setting("cert_warning_days").expect("allowlisted");
    /// assert_eq!(setting.bound_text(), "14..=365");
    /// ```
    pub fn bound_text(&self) -> String {
        match self.direction {
            Direction::Either => format!("{}..={}", self.min, self.max),
            Direction::RaiseOnly => format!("raise-only, {}..={}", self.min, self.max),
        }
    }

    /// Why `after` is not a value this tier may store when `before` is
    /// stored, or `None` when it may.
    pub fn refusal(&self, before: i64, after: i64) -> Option<String> {
        if !(self.min..=self.max).contains(&after) {
            return Some(format!(
                "{}: {after} is outside what an automation token may set ({}); set it in the \
                 dashboard",
                self.name,
                self.bound_text()
            ));
        }
        if self.direction == Direction::RaiseOnly && after < before {
            return Some(format!(
                "{}: {after} is below the stored {before}, and an automation token may only \
                 raise it ({}); lower it in the dashboard",
                self.name,
                self.bound_text()
            ));
        }
        None
    }
}

/// The highest row retention the admin tier may raise either persistent
/// buffer to: ten times the shipped default of 100000 rows.
///
/// A raise-only retention is safe only up to a size a human chose the
/// disk for. An access-log row weighs about 500 bytes once its four
/// indexes are counted, so the ceiling is about half a gigabyte per
/// table: ten times the history the node ships with, and not the size
/// that fills a disk. The previous ceiling of one hundred million rows
/// was about fifty gigabytes per table, a disk-exhaustion value one
/// write away. A retention beyond it is a disk decision, made in the
/// dashboard. A test in `lorica-api` pins the ceiling to the default it
/// derives from.
pub const RETENTION_TIER_CEILING_ROWS: i64 = 1_000_000;

/// Every setting `PUT /automation/v1/settings` accepts: the admin tier's
/// whole surface (Story 11.3 AC #1), decided by exclusion, each with
/// the bound and the direction this tier may move it in.
///
/// The one statement of it. The plane refuses any other key with a 403
/// before a validator runs, and a value outside its entry's bound with
/// a 422 naming the key and the bound, on the document it is about to
/// write. The MCP tool's body vocabulary and the bounds its description
/// states are built from it; the `SettingsPatch` schema in
/// `openapi-automation.yaml` and the table in `docs/mcp.md` restate it
/// and tests in `lorica-api` pin each against this constant.
///
/// A key is here only when a model reading attacker-authored text can
/// move it in a direction that harms nothing: every entry has a safe
/// direction, a bound, and a dashboard field that undoes it (AC #3).
///
/// What is NOT here is the decision, and its reasons are in the story
/// (`docs/stories/story-11.3-admin-tier.md`) and in `docs/mcp.md`, by
/// family: anything that can lock the operator out of the management
/// plane (its port, its TLS pair, the connection and automation
/// allowlists, the trusted proxies); credentials and trust anchors
/// (the bot HMAC secret, the scrape token and its switch, the upgrade
/// signing key, the certificate export family); identity policy;
/// data-plane capacity and mirroring concurrency, which are reversible
/// and not harmless; the telemetry and log-sink destinations, since a
/// redirect is not visibly wrong; `audit_log_retention_days`, because
/// retention protecting the audit of this tier is not this tier's to
/// shorten; and the probe and load-test budgets (`max_active_probes`
/// and the three load-test ceilings).
///
/// Taken out on 2026-09-28, each for a reason the first list missed:
/// `flood_threshold_rps`, because either direction harms (lowered it
/// makes every per-IP bucket answer 429, at 0 it switches the flood
/// defence off); `flood_strict_rps` and `header_timeout_s`, for the
/// reason the next paragraph gives;
/// `sla_purge_enabled`, because off means unbounded growth;
/// `sla_purge_schedule`, because the only direction it moves is purges
/// more often; and `log_level`, because it has no safe direction:
/// raised it floods the disk and writes request detail into the logs,
/// lowered it blinds the investigation.
///
/// The probe and load-test budgets, `flood_strict_rps` and
/// `header_timeout_s` first stayed out because the dashboard had no
/// write path for them, so a value set here could not have been undone
/// there (AC #3). Since `docs/backlog.md` #89 (2026-10-04) the dashboard
/// writes all six, and they stay out all the same: a dashboard field is
/// what an entry requires, not a reason to add one, and none of the six
/// has been admitted by a decision with its reason, its bound and its
/// safe direction.
///
/// Every later request to add an entry will be reasonable on its own
/// terms. An entry arrives with its reason and its bound or not at all.
pub const SETTINGS_ALLOWLIST: &[AdminSetting] = &[
    AdminSetting {
        name: "access_log_retention",
        why: "retention of the persistent access-log buffer; raised, it keeps more history, \
              and 0 (unlimited) is refused because the table then grows until the disk fills; \
              no higher than RETENTION_TIER_CEILING_ROWS, about half a gigabyte of rows, for \
              the same reason",
        min: 1,
        max: RETENTION_TIER_CEILING_ROWS,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "waf_event_retention",
        why: "retention of the persistent WAF-event buffer, the data plane's security trail; \
              raised, it keeps more of it, and 0 (unlimited) is refused; no higher than \
              RETENTION_TIER_CEILING_ROWS, for the disk's sake",
        min: 1,
        max: RETENTION_TIER_CEILING_ROWS,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "sla_purge_retention_days",
        why: "how long SLA buckets are kept; raised, it keeps more history and purges nothing \
              sooner",
        min: 1,
        max: 3650,
        direction: Direction::RaiseOnly,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "cert_warning_days",
        why: "when a certificate expiry raises a warning; an alert threshold, no traffic \
              effect, and no lower than two weeks so an expiry cannot be hidden",
        min: 14,
        max: 365,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "cert_critical_days",
        why: "when a certificate expiry raises a critical alert; an alert threshold, no \
              traffic effect, and no lower than three days",
        min: 3,
        max: 365,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: Some("below `cert_warning_days`"),
    },
    AdminSetting {
        name: "waf_ban_threshold",
        why: "how many WAF blocks earn an automatic ban; a protection threshold, never so \
              low that one false positive bans a shared address and never so high that \
              auto-ban is off in practice",
        min: 3,
        max: 100,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "waf_ban_duration_s",
        why: "how long an automatic WAF ban lasts; a ban keeps the duration it was issued \
              with, so a day at most, and never so short that a ban does nothing",
        min: 60,
        max: 86_400,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "default_health_check_interval_s",
        why: "the fallback health-check interval; a probe budget read on every cycle, bounded \
              far below the dashboard's own ceiling because a dead backend keeps its traffic \
              for three probes of whatever interval is set",
        min: 5,
        max: 60,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
    AdminSetting {
        name: "health_max_concurrent_probes",
        why: "the cap on concurrent health probes; a probe budget, never so low that a few \
              unreachable backends starve the probes of every other",
        min: 16,
        max: 512,
        direction: Direction::Either,
        reach: Reach::Fleet,
        takes_effect: TakesEffect::Live,
        validator_also: None,
    },
];

/// [`SETTINGS_ALLOWLIST`]'s names in ascending byte order, for a
/// surface that lists field names canonically, as the MCP tool's body
/// vocabulary does. Computed from the allowlist at compile time, so it
/// holds no name of its own.
pub const SETTINGS_ALLOWLIST_NAMES: [&str; SETTINGS_ALLOWLIST.len()] = sorted_setting_names();

const fn sorted_setting_names() -> [&'static str; SETTINGS_ALLOWLIST.len()] {
    let mut names: [&'static str; SETTINGS_ALLOWLIST.len()] = [""; SETTINGS_ALLOWLIST.len()];
    let mut at = 0;
    while at < names.len() {
        names[at] = SETTINGS_ALLOWLIST[at].name;
        at += 1;
    }
    let mut sorted = 1;
    while sorted < names.len() {
        let mut at = sorted;
        while at > 0 && precedes(names[at], names[at - 1]) {
            let moved = names[at];
            names[at] = names[at - 1];
            names[at - 1] = moved;
            at -= 1;
        }
        sorted += 1;
    }
    names
}

/// `a < b` in byte order, which is what `str`'s `Ord` compares, for a
/// const context where that impl cannot be called.
const fn precedes(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut at = 0;
    while at < a.len() && at < b.len() {
        if a[at] != b[at] {
            return a[at] < b[at];
        }
        at += 1;
    }
    a.len() < b.len()
}

/// The entry of [`SETTINGS_ALLOWLIST`] named `key`.
pub fn admin_setting(key: &str) -> Option<&'static AdminSetting> {
    SETTINGS_ALLOWLIST
        .iter()
        .find(|setting| setting.name == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sorted_names_are_the_allowlist_sorted_and_unique() {
        let mut expected: Vec<&str> = SETTINGS_ALLOWLIST.iter().map(|s| s.name).collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(SETTINGS_ALLOWLIST_NAMES.as_slice(), expected.as_slice());
        assert!(!expected.is_empty());
    }

    #[test]
    fn every_entry_has_a_reason_a_bound_and_a_lookup() {
        for setting in SETTINGS_ALLOWLIST {
            assert!(!setting.why.trim().is_empty(), "{}", setting.name);
            assert!(setting.min <= setting.max, "{}", setting.name);
            assert_eq!(admin_setting(setting.name), Some(setting));
        }
        assert_eq!(admin_setting("log_level"), None);
    }

    #[test]
    fn a_refusal_names_the_key_and_the_bound_and_a_raise_only_key_refuses_a_lowering() {
        for setting in SETTINGS_ALLOWLIST {
            assert_eq!(setting.refusal(setting.min, setting.max), None);
            let outside = setting
                .refusal(setting.min, setting.max + 1)
                .expect("above the bound");
            assert!(outside.contains(setting.name), "{outside}");
            assert!(outside.contains(&setting.bound_text()), "{outside}");
            let lowered = setting.refusal(setting.max, setting.min);
            assert_eq!(
                lowered.is_some(),
                setting.direction == Direction::RaiseOnly,
                "{}",
                setting.name
            );
        }
    }
}
