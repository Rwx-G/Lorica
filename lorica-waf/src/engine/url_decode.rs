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

//! Recursive URL decoding helpers used by the WAF to defeat
//! double- or triple-encoded bypass attempts.
//!
//! Exposed as associated functions on [`super::WafEngine`] so the
//! public calling convention (`WafEngine::url_decode(...)`) is
//! preserved - tests and downstream crates rely on that path.

use super::WafEngine;

impl WafEngine {
    /// Recursive URL decoding for encoded attack payloads.
    ///
    /// Decodes until stable or max 3 iterations to prevent double-encoding bypass.
    pub(super) fn url_decode(input: &str) -> String {
        // Fast path: no percent-encoding or plus signs -> skip decode entirely
        if !input.contains('%') && !input.contains('+') {
            return input.to_string();
        }
        let mut current = input.to_string();
        for _ in 0..3 {
            let decoded = Self::url_decode_once(&current);
            if decoded == current {
                break;
            }
            current = decoded;
        }
        current
    }

    /// Single-pass URL decoding helper.
    fn url_decode_once(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }
        result
    }
}
