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

//! WAF engine for Lorica with OWASP CRS-inspired rules.
//!
//! Provides SQL injection, XSS, and path traversal detection using
//! precompiled regex patterns. Supports detection-only and blocking modes.

pub mod engine;
pub mod rules;

pub use engine::{RuleSummary, WafEngine, WafEvent, WafVerdict};
pub use rules::{RuleCategory, RuleSet, WafRule};
