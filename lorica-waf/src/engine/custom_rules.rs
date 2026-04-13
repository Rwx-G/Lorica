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

//! Custom (admin-defined) WAF rule CRUD.
//!
//! Split out from the main engine module to keep the surface that
//! mutates user-provided rules isolated from the hot evaluation path.
//! Pattern and compiled-regex size caps live here because they gate
//! the admin-facing API.

use super::{CustomRule, WafEngine};
use crate::rules::RuleCategory;

impl WafEngine {
    /// Maximum raw pattern length accepted for a custom WAF rule.
    /// Caps the admin-only attack surface on `RegexBuilder::build`:
    /// the `regex` crate has linear-time matching but pathological
    /// alternations or nested repetitions can still burn seconds and
    /// megabytes at *compile* time. 4 KiB is enough for any realistic
    /// operator-written pattern and short-circuits adversarial input.
    pub const MAX_CUSTOM_PATTERN_LEN: usize = 4 * 1024;

    /// Upper bound on the compiled NFA / DFA size (in bytes) for a
    /// custom rule. Matches what `RegexBuilder::size_limit` gates.
    pub const MAX_CUSTOM_REGEX_SIZE: usize = 512 * 1024;

    /// Add a custom user-defined WAF rule.
    ///
    /// Returns `Err` with a human-readable message if the pattern
    /// exceeds [`Self::MAX_CUSTOM_PATTERN_LEN`], if the compiled regex
    /// would exceed [`Self::MAX_CUSTOM_REGEX_SIZE`], or if the pattern
    /// is not a valid regex. On success the rule starts enabled.
    pub fn add_custom_rule(
        &self,
        id: u32,
        description: String,
        category: RuleCategory,
        pattern: &str,
        severity: u8,
    ) -> Result<(), String> {
        if pattern.len() > Self::MAX_CUSTOM_PATTERN_LEN {
            return Err(format!(
                "pattern exceeds {} bytes",
                Self::MAX_CUSTOM_PATTERN_LEN
            ));
        }
        let regex = regex::RegexBuilder::new(pattern)
            .size_limit(Self::MAX_CUSTOM_REGEX_SIZE)
            .build()
            .map_err(|e| format!("invalid regex: {e}"))?;
        let rule = CustomRule {
            id,
            description,
            category,
            pattern: pattern.to_string(),
            severity,
            enabled: true,
        };
        self.custom_rules.write().push((rule, regex));
        Ok(())
    }

    /// Remove a custom rule by ID. Returns `true` if a rule was removed.
    pub fn remove_custom_rule(&self, id: u32) -> bool {
        let mut rules = self.custom_rules.write();
        let before = rules.len();
        rules.retain(|(r, _)| r.id != id);
        rules.len() < before
    }

    /// Remove all custom rules.
    pub fn clear_custom_rules(&self) {
        self.custom_rules.write().clear();
    }

    /// List all custom rules.
    pub fn list_custom_rules(&self) -> Vec<CustomRule> {
        self.custom_rules
            .read()
            .iter()
            .map(|(r, _)| r.clone())
            .collect()
    }
}
