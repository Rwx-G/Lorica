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

//! The guard on the two places the TCP health-check templates and the
//! limits of a custom check are read outside Rust (Story 12.7, D-12):
//! the dashboard's `health-check-templates.generated.ts` and the marked
//! section of `docs/health-checks.md`.
//!
//! Both are rendered here from `TCP_CHECK_TEMPLATES`
//! (`lorica-automation-policy`) and the limit constants of
//! `lorica-config`, and compared with the committed text byte for byte,
//! the way `adcs_vocabulary_fixture.rs` holds its file: a template added
//! or corrected in Rust, or a limit moved, turns this red until the
//! file, or the section, is replaced with what the failure prints.
//! Nothing is auto-written.

use lorica_automation_policy::{CheckTemplate, MatchAnchor, TCP_CHECK_TEMPLATES};
use lorica_config::models::{
    EXPECT_MAX_ALTERNATIVES, EXPECT_MAX_BYTES, PROBE_READ_MAX_BYTES, PROBE_TIMEOUT_MS_DEFAULT,
    PROBE_TIMEOUT_MS_MAX, PROBE_TIMEOUT_MS_MIN, SEND_MAX_BYTES,
};

/// The generated module, read through `include_str!` so a rename or a
/// move is a compile error naming the path.
const GENERATED_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lorica-dashboard/frontend/src/lib/health-check-templates.generated.ts"
));

/// Where the module lives, for the failure message.
const FIXTURE_PATH: &str = "lorica-dashboard/frontend/src/lib/health-check-templates.generated.ts";

/// The operator documentation carrying the rendered section.
const OPERATOR_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/health-checks.md"
));

/// Where the documentation lives, for the failure message.
const OPERATOR_DOC_PATH: &str = "docs/health-checks.md";

/// The line opening the rendered section of the documentation.
const SECTION_BEGIN: &str = "<!-- BEGIN health-check-templates: rendered by \
                             lorica-api/tests/health_check_template_fixture.rs, never edit by \
                             hand -->";

/// The line closing it.
const SECTION_END: &str = "<!-- END health-check-templates -->";

/// Every limit a custom check is held to, by its Rust name, with what
/// it bounds and its value.
fn limits() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "SEND_MAX_BYTES",
            "most bytes a custom `send` carries, decoded",
            SEND_MAX_BYTES.to_string(),
        ),
        (
            "EXPECT_MAX_ALTERNATIVES",
            "most alternatives a custom `expect` lists",
            EXPECT_MAX_ALTERNATIVES.to_string(),
        ),
        (
            "EXPECT_MAX_BYTES",
            "most bytes one expected alternative carries, decoded",
            EXPECT_MAX_BYTES.to_string(),
        ),
        (
            "PROBE_READ_MAX_BYTES",
            "most bytes one probe reads, whatever the check says",
            PROBE_READ_MAX_BYTES.to_string(),
        ),
        (
            "PROBE_TIMEOUT_MS_MIN",
            "shortest `timeout_ms` a check may set",
            PROBE_TIMEOUT_MS_MIN.to_string(),
        ),
        (
            "PROBE_TIMEOUT_MS_MAX",
            "longest `timeout_ms` a check may set",
            PROBE_TIMEOUT_MS_MAX.to_string(),
        ),
        (
            "PROBE_TIMEOUT_MS_DEFAULT",
            "`timeout_ms` of a check that sets none",
            PROBE_TIMEOUT_MS_DEFAULT.to_string(),
        ),
    ]
}

/// The spellings of `MatchAnchor`, read from serde's refusal of one it
/// does not know, so a variant added in Rust reaches the union here.
fn anchor_words() -> Vec<String> {
    let refusal = serde_json::from_value::<MatchAnchor>(serde_json::json!("no_such_anchor"))
        .expect_err("an unknown anchor is refused")
        .to_string();
    let words: Vec<String> = refusal
        .split_once("expected")
        .unwrap_or_else(|| panic!("serde names the anchors it expects: {refusal}"))
        .1
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    assert!(words.len() >= 2, "{refusal}");
    words
}

/// The wire word of `anchor`.
fn anchor_word(anchor: MatchAnchor) -> String {
    serde_json::to_value(anchor)
        .expect("an anchor serialises")
        .as_str()
        .expect("an anchor serialises to a string")
        .to_string()
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `bytes` as an operator reads them: printable ASCII kept, `\r`, `\n`,
/// `\t` and `\\` escaped, every other byte as `\xNN`.
fn shown(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            b'\r' => "\\r".to_string(),
            b'\n' => "\\n".to_string(),
            b'\t' => "\\t".to_string(),
            b'\\' => "\\\\".to_string(),
            0x20..=0x7e => char::from(*byte).to_string(),
            other => format!("\\x{other:02x}"),
        })
        .collect()
}

/// `text` as a single-quoted TypeScript string literal.
fn ts(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

/// `bytes` as a `TemplateBytes` object literal.
fn ts_bytes(bytes: &[u8]) -> String {
    format!(
        "{{ hex: {}, shown: {} }}",
        ts(&hex(bytes)),
        ts(&shown(bytes))
    )
}

/// The whole TypeScript module as it must read.
fn rendered_module() -> String {
    let mut out = String::new();
    out.push_str(
        "// Rendered from Rust by lorica-api/tests/health_check_template_fixture.rs, which\n\
         // prints the whole file as it must read when the committed one differs. Replace\n\
         // the file with that output; never edit it by hand.\n\n",
    );
    out.push_str(
        "/** Where an expected answer must appear in the bytes a probe reads (`MatchAnchor`). */\n",
    );
    out.push_str(&format!(
        "export type MatchAnchor = {};\n\n",
        anchor_words()
            .iter()
            .map(|word| ts(word))
            .collect::<Vec<String>>()
            .join(" | ")
    ));
    out.push_str(
        "/**\n * Bytes as a template carries them: lowercase `hex`, and the same bytes\n \
         * `shown` with printable ASCII kept, `\\r`, `\\n`, `\\t` and `\\\\` escaped, and\n \
         * every other byte as `\\xNN`.\n */\n\
         export interface TemplateBytes {\n  readonly hex: string;\n  readonly shown: string;\n}\n\n",
    );
    out.push_str(
        "/** One answer a template accepts. */\n\
         export interface TemplateExpectation {\n  readonly match: MatchAnchor;\n  \
         readonly bytes: TemplateBytes;\n}\n\n",
    );
    out.push_str(&format!(
        "/** The name a `tcp_template` check stores. */\nexport type TcpCheckTemplateName = {};\n\n",
        TCP_CHECK_TEMPLATES
            .iter()
            .map(|template| ts(template.name))
            .collect::<Vec<String>>()
            .join(" | ")
    ));
    out.push_str(
        "/** A TCP check the release ships, referenced by name (`CheckTemplate`). */\n\
         export interface CheckTemplate {\n  readonly name: TcpCheckTemplateName;\n  \
         readonly summary: string;\n  readonly send: TemplateBytes | null;\n  \
         readonly expect: readonly TemplateExpectation[];\n}\n\n",
    );
    out.push_str("/** Every template, in `TCP_CHECK_TEMPLATES` order. */\n");
    out.push_str("export const TCP_CHECK_TEMPLATES: readonly CheckTemplate[] = [\n");
    for template in TCP_CHECK_TEMPLATES {
        out.push_str("  {\n");
        out.push_str(&format!("    name: {},\n", ts(template.name)));
        out.push_str(&format!("    summary: {},\n", ts(template.summary)));
        out.push_str(&format!(
            "    send: {},\n",
            template.send.map_or_else(|| "null".to_string(), ts_bytes)
        ));
        out.push_str("    expect: [\n");
        for expectation in template.expect {
            out.push_str(&format!(
                "      {{ match: {}, bytes: {} }},\n",
                ts(&anchor_word(expectation.anchor)),
                ts_bytes(expectation.bytes)
            ));
        }
        out.push_str("    ],\n  },\n");
    }
    out.push_str("];\n\n");
    out.push_str(
        "// The limits a custom send/expect check is held to when written, by their Rust names.\n",
    );
    for (name, bounds, value) in limits() {
        out.push_str(&format!(
            "/** The {bounds}. */\n\
             export const {name} = {value};\n"
        ));
    }
    out
}

/// What a template expects, as the documentation reads it.
fn expected_answers(template: &CheckTemplate) -> String {
    template
        .expect
        .iter()
        .map(|expectation| {
            format!(
                "{} `{}`",
                anchor_word(expectation.anchor),
                shown(expectation.bytes)
            )
        })
        .collect::<Vec<String>>()
        .join(", ")
}

/// The documentation's rendered section, between its marker lines,
/// both excluded.
fn rendered_section() -> String {
    let mut out = String::new();
    out.push_str("\n| Template | Sends | Expects, any of | What it proves |\n|---|---|---|---|\n");
    for template in TCP_CHECK_TEMPLATES {
        let sends = template.send.map_or_else(
            || "nothing".to_string(),
            |bytes| format!("`{}` (hex `{}`)", shown(bytes), hex(bytes)),
        );
        out.push_str(&format!(
            "| `{}` | {sends} | {} | {} |\n",
            template.name,
            expected_answers(template),
            template.summary
        ));
    }
    out.push_str("\n| Limit | Meaning | Value |\n|---|---|---|\n");
    for (name, bounds, value) in limits() {
        out.push_str(&format!("| `{name}` | {bounds} | {value} |\n"));
    }
    out.push('\n');
    out
}

/// The committed section of the documentation, between the markers,
/// with LF line endings.
fn committed_section() -> String {
    let start = OPERATOR_DOC
        .find(SECTION_BEGIN)
        .unwrap_or_else(|| panic!("{OPERATOR_DOC_PATH} has no line `{SECTION_BEGIN}`"))
        + SECTION_BEGIN.len();
    let end = OPERATOR_DOC[start..]
        .find(SECTION_END)
        .unwrap_or_else(|| panic!("{OPERATOR_DOC_PATH} has no line `{SECTION_END}`"))
        + start;
    // A Markdown file is checked out with CRLF on a Windows clone; the
    // section is compared by content, its line endings aside.
    OPERATOR_DOC[start..end].replace("\r\n", "\n")
}

/// The first line where `committed` and `expected` differ, for a
/// failure message.
fn first_difference(committed: &str, expected: &str) -> String {
    committed
        .lines()
        .zip(expected.lines())
        .enumerate()
        .find(|(_, (committed, wanted))| committed != wanted)
        .map_or_else(
            || {
                format!(
                    "the texts agree line by line but differ in length or line endings \
                     (committed {} bytes, rendered {} bytes; LF line endings only)",
                    committed.len(),
                    expected.len()
                )
            },
            |(index, (committed, wanted))| {
                format!(
                    "line {}:\n  committed: {committed}\n  rendered:  {wanted}",
                    index + 1
                )
            },
        )
}

#[test]
fn the_dashboard_template_module_is_what_rust_renders() {
    let expected: String = rendered_module();
    if GENERATED_FIXTURE == expected {
        return;
    }
    panic!(
        "\n{FIXTURE_PATH} is not what the Rust catalogue renders.\n\nFirst difference, {}\n\n\
         Replace the whole file with this, byte for byte (everything between the two marker \
         lines, excluded), and never edit it by hand:\n\
         ----- BEGIN {FIXTURE_PATH} -----\n{expected}----- END {FIXTURE_PATH} -----\n",
        first_difference(GENERATED_FIXTURE, &expected)
    );
}

#[test]
fn the_documented_template_section_is_what_rust_renders() {
    let expected: String = rendered_section();
    let committed = committed_section();
    if committed == expected {
        return;
    }
    panic!(
        "\nThe template section of {OPERATOR_DOC_PATH} is not what the Rust catalogue \
         renders.\n\nFirst difference, {}\n\nReplace everything between `{SECTION_BEGIN}` and \
         `{SECTION_END}` with this, byte for byte (the two marker lines below excluded):\n\
         ----- BEGIN section -----{expected}----- END section -----\n",
        first_difference(&committed, &expected)
    );
}

#[test]
fn both_renderings_name_every_template_every_answer_and_every_limit() {
    // The renderings iterate the constants, so this holds by
    // construction; it keeps an edit of a renderer from dropping an
    // entry while still comparing equal to its own output.
    let module = rendered_module();
    let section = rendered_section();
    for template in TCP_CHECK_TEMPLATES {
        assert!(module.contains(&format!("name: '{}'", template.name)));
        assert!(section.contains(&format!("| `{}` |", template.name)));
        for expectation in template.expect {
            assert!(module.contains(&format!("hex: '{}'", hex(expectation.bytes))));
            assert!(section.contains(&format!("`{}`", shown(expectation.bytes))));
        }
    }
    for (name, _, value) in limits() {
        assert!(module.contains(&format!("export const {name} = {value};")));
        assert!(section.contains(&format!("| `{name}` |")));
    }
}

#[test]
fn bytes_are_shown_printable_and_escaped_otherwise() {
    assert_eq!(shown(b"PING\r\n"), "PING\\r\\n");
    assert_eq!(shown(&[0x00, 0xd2, b'S', b'\\']), "\\x00\\xd2S\\\\");
    assert_eq!(hex(&[0x00, 0x08, 0xd2]), "0008d2");
    assert_eq!(ts("it's a\\b"), "'it\\'s a\\\\b'");
}
