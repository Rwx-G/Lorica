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

//! The named TCP health-check templates (Story 12.7, D-4).
//!
//! # Why protocol bytes live in a policy crate
//!
//! A custom send/expect check makes Lorica send operator-chosen bytes
//! to an address, so it is written from the management plane only
//! (PRD D9). An automation token and the MCP config tier may instead
//! name a template, and the set of templates is therefore the
//! allowlist of bytes a token can cause Lorica to send: policy, in the
//! sense [`crate::settings::SETTINGS_ALLOWLIST`] is policy for the
//! admin tier. `lorica-mcp`, which cannot reach `lorica-config`, needs
//! the names to render its tool schema, and this crate is what both
//! can read.
//!
//! The catalogue is `&'static` data, so the crate stays `serde`-only.
//! A template is a release decision, not a stored row: a backend stores
//! the template's name, and a template corrected in a later release
//! reaches every backend that names it.

use serde::{Deserialize, Serialize};

/// Where an expected answer must appear in the bytes a probe reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchAnchor {
    /// The bytes read start with the expected bytes.
    Prefix,
    /// The expected bytes occur anywhere in the bytes read.
    Contains,
}

/// One answer a template accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateExpectation {
    /// Where the bytes must appear.
    pub anchor: MatchAnchor,
    /// The bytes, matched literally.
    pub bytes: &'static [u8],
}

/// A named send/expect exchange shipped with the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckTemplate {
    /// The name a backend's `tcp_template` check stores.
    pub name: &'static str,
    /// One line for an operator choosing a template.
    pub summary: &'static str,
    /// What the probe sends once connected, if anything.
    pub send: Option<&'static [u8]>,
    /// The answers that make the probe healthy, any one of them.
    pub expect: &'static [TemplateExpectation],
}

/// Every template a `tcp_template` check may name.
pub const TCP_CHECK_TEMPLATES: &[CheckTemplate] = &[
    CheckTemplate {
        name: "redis_ping",
        summary: "Redis: PING answered by +PONG, or by -NOAUTH from a server that requires \
                  authentication (it is up and speaking its protocol)",
        send: Some(b"PING\r\n"),
        expect: &[
            TemplateExpectation {
                anchor: MatchAnchor::Prefix,
                bytes: b"+PONG",
            },
            TemplateExpectation {
                anchor: MatchAnchor::Prefix,
                bytes: b"-NOAUTH",
            },
        ],
    },
    CheckTemplate {
        name: "smtp_banner",
        summary: "SMTP: the server's greeting starts with 220",
        send: None,
        expect: &[TemplateExpectation {
            anchor: MatchAnchor::Prefix,
            bytes: b"220",
        }],
    },
    CheckTemplate {
        name: "postgresql_ssl_request",
        summary: "PostgreSQL: an SSLRequest answered by S (TLS offered) or N (TLS declined)",
        send: Some(&[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]),
        expect: &[
            TemplateExpectation {
                anchor: MatchAnchor::Prefix,
                bytes: b"S",
            },
            TemplateExpectation {
                anchor: MatchAnchor::Prefix,
                bytes: b"N",
            },
        ],
    },
];

/// The template named `name`, if the release ships one.
pub fn tcp_check_template(name: &str) -> Option<&'static CheckTemplate> {
    TCP_CHECK_TEMPLATES
        .iter()
        .find(|template| template.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_names_are_unique_snake_case_words() {
        let mut seen = std::collections::HashSet::new();
        for template in TCP_CHECK_TEMPLATES {
            assert!(
                seen.insert(template.name),
                "{} is listed twice",
                template.name
            );
            let mut chars = template.name.chars();
            assert!(
                chars.next().is_some_and(|c| c.is_ascii_lowercase()),
                "{} starts with a lowercase letter",
                template.name
            );
            assert!(
                chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{} is in the snake_case alphabet",
                template.name
            );
        }
    }

    #[test]
    fn every_template_expects_something_and_sends_bytes_when_it_sends() {
        for template in TCP_CHECK_TEMPLATES {
            assert!(!template.expect.is_empty(), "{}", template.name);
            assert!(
                template.expect.iter().all(|e| !e.bytes.is_empty()),
                "{}: an empty alternative matches anything",
                template.name
            );
            assert_ne!(template.send, Some(&[][..]), "{}", template.name);
            assert!(!template.summary.is_empty(), "{}", template.name);
        }
    }

    #[test]
    fn a_template_is_found_by_its_name_and_only_by_it() {
        for template in TCP_CHECK_TEMPLATES {
            assert_eq!(tcp_check_template(template.name), Some(template));
        }
        assert_eq!(tcp_check_template("no_such_template"), None);
    }

    #[test]
    fn the_anchor_spells_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_value(MatchAnchor::Contains).expect("serialize"),
            serde_json::json!("contains")
        );
        assert_eq!(
            serde_json::from_value::<MatchAnchor>(serde_json::json!("prefix")).expect("parse"),
            MatchAnchor::Prefix
        );
    }
}
