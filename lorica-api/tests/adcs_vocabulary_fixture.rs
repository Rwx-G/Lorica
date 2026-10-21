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

//! The one guard on the Rust-to-TypeScript edge of the vocabularies the
//! dashboard shows for alerts and AD CS: the alert types, the
//! certificate sources, the AD CS key types and subject fields, the
//! failure steps, the KDC codes that open the failed state, the AD CS
//! error codes and the reasons an adoption listing is empty.
//!
//! Each is owned by a Rust constant or an exhaustive match, and the
//! dashboard reads them from `adcs.generated.ts` instead of typing them
//! again. This test renders that whole file from the Rust side and
//! compares it with the committed one byte for byte, the way
//! `automation_scope_fixture.rs` holds the MCP tier section: a variant
//! added in Rust, or a word changed, turns this red until the file is
//! replaced with what the failure prints. Nothing is auto-written: a
//! generator someone has to remember to rerun is a delayed
//! transcription, not a guard.

use lorica_adcs::{kdc_error_meaning, kdc_rejection_codes, FailureStep};
use lorica_api::adcs::{AdoptionUnavailable, IssuanceStep, ADCS_CODES};
use lorica_api::vocabulary::{alert_type_label, alert_type_recovers, alert_type_tone, AlertTone};
use lorica_config::models::{AdcsKeyType, AdcsSubjectDefaults, CertificateSource};
use lorica_notify::events::AlertType;

/// The generated file, relative to this crate's manifest. Read through
/// `include_str!` so a rename or a move is a compile error naming the
/// path.
const GENERATED_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lorica-dashboard/frontend/src/lib/adcs.generated.ts"
));

/// Where the fixture lives, for the failure message.
const FIXTURE_PATH: &str = "lorica-dashboard/frontend/src/lib/adcs.generated.ts";

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

/// `values` as a TypeScript union of string literal types.
fn union<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    values
        .into_iter()
        .map(ts)
        .collect::<Vec<String>>()
        .join(" | ")
}

/// `pairs` as the body of an object literal, one `key: 'value',` per
/// line.
fn record_body<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .into_iter()
        .map(|(key, value)| format!("  {key}: {},\n", ts(value)))
        .collect()
}

fn adoption_reason(reason: AdoptionUnavailable) -> String {
    serde_json::to_value(reason)
        .expect("a reason serialises")
        .as_str()
        .expect("a reason serialises to a string")
        .to_string()
}

/// The whole file as it must read.
fn rendered() -> String {
    let mut out = String::new();
    out.push_str(
        "// Rendered from Rust by lorica-api/tests/adcs_vocabulary_fixture.rs, which prints\n\
         // the whole file as it must read when the committed one differs. Replace the file\n\
         // with that output; never edit it by hand.\n\n",
    );

    out.push_str("/** An alert type, as a notification channel subscribes to it. */\n");
    out.push_str(&format!(
        "export type AlertType = {};\n\n",
        union(AlertType::ALL.iter().map(AlertType::as_str))
    ));
    out.push_str("/** How an alert reads at a glance. */\n");
    out.push_str(&format!(
        "export type AlertTone = {};\n\n",
        union(AlertTone::ALL.iter().map(|tone| tone.as_str()))
    ));
    out.push_str(
        "/**\n * One alert type: its label, its tone, and the alert it closes when it is a\n \
         * recovery (a channel subscribed to one is meant to receive the other).\n */\n\
         export interface AlertTypeDefinition {\n  readonly value: AlertType;\n  \
         readonly label: string;\n  readonly tone: AlertTone;\n  \
         readonly recovers: AlertType | null;\n}\n\n",
    );
    out.push_str("/** Every alert type, in `AlertType::ALL` order. */\n");
    out.push_str("export const ALERT_TYPES: readonly AlertTypeDefinition[] = [\n");
    for alert_type in AlertType::ALL {
        out.push_str(&format!(
            "  {{ value: {}, label: {}, tone: {}, recovers: {} }},\n",
            ts(alert_type.as_str()),
            ts(alert_type_label(&alert_type)),
            ts(alert_type_tone(&alert_type).as_str()),
            alert_type_recovers(&alert_type)
                .map_or_else(|| "null".to_string(), |closed| ts(closed.as_str())),
        ));
    }
    out.push_str("];\n\n");

    out.push_str("/** Where a certificate comes from (`CertificateSource`). */\n");
    out.push_str(&format!(
        "export type CertificateSource = {};\n\n",
        union(CertificateSource::ALL.iter().map(|source| source.as_str()))
    ));
    out.push_str(
        "export const CERTIFICATE_SOURCE_LABELS: Readonly<Record<CertificateSource, string>> = {\n",
    );
    out.push_str(&record_body(
        CertificateSource::ALL
            .iter()
            .map(|source| (source.as_str(), source.label())),
    ));
    out.push_str("};\n\n");

    out.push_str("/** The key an AD CS certificate is generated with (`AdcsKeyType`). */\n");
    out.push_str(&format!(
        "export type AdcsKeyType = {};\n\n",
        union(AdcsKeyType::ALL.iter().map(|kind| kind.as_str()))
    ));
    out.push_str("export const ADCS_KEY_TYPE_LABELS: Readonly<Record<AdcsKeyType, string>> = {\n");
    out.push_str(&record_body(
        AdcsKeyType::ALL
            .iter()
            .map(|kind| (kind.as_str(), kind.label())),
    ));
    out.push_str("};\n\n");

    out.push_str(
        "/** A field of the subject an AD CS request carries (`AdcsSubjectDefaults`). */\n",
    );
    out.push_str(&format!(
        "export type AdcsSubjectField = {};\n\n",
        union(AdcsSubjectDefaults::FIELDS.iter().map(|(name, _)| *name))
    ));
    out.push_str(
        "export const ADCS_SUBJECT_FIELD_LABELS: Readonly<Record<AdcsSubjectField, string>> = {\n",
    );
    out.push_str(&record_body(AdcsSubjectDefaults::FIELDS.iter().copied()));
    out.push_str("};\n\n");

    out.push_str(
        "/**\n * The step an AD CS operation failed at: the client's (`FailureStep`), then\n \
         * the issuance's (`IssuanceStep`). `error.step`, audit rows and alerts carry it.\n */\n",
    );
    let steps: Vec<(&str, &str)> = FailureStep::ALL
        .iter()
        .map(|step| (step.as_str(), step.label()))
        .chain(
            IssuanceStep::ALL
                .iter()
                .map(|step| (step.as_str(), step.label())),
        )
        .collect();
    out.push_str(&format!(
        "export type AdcsFailureStep = {};\n\n",
        union(steps.iter().map(|(word, _)| *word))
    ));
    out.push_str(
        "export const ADCS_FAILURE_STEP_LABELS: Readonly<Record<AdcsFailureStep, string>> = {\n",
    );
    out.push_str(&record_body(steps.iter().copied()));
    out.push_str("};\n\n");

    out.push_str("/** The KDC error codes that open the failed state, and what each means. */\n");
    out.push_str("export const ADCS_KDC_CODE_MEANINGS: Readonly<Record<number, string>> = {\n");
    for code in kdc_rejection_codes() {
        let meaning: &str = kdc_error_meaning(code).expect("a rejection code has a meaning");
        out.push_str(&format!("  {code}: {},\n", ts(meaning)));
    }
    out.push_str("};\n\n");

    out.push_str("/** A code an AD CS endpoint answers with in `error.code`. */\n");
    out.push_str(&format!(
        "export type AdcsErrorCode = {};\n\n",
        union(ADCS_CODES.iter().map(|code| code.code))
    ));
    out.push_str(
        "export interface AdcsErrorCodeDefinition {\n  readonly code: AdcsErrorCode;\n  \
         readonly status: number;\n  readonly meaning: string;\n}\n\n",
    );
    out.push_str(
        "/** Every AD CS error code, with the status every endpoint answers it with. */\n",
    );
    out.push_str("export const ADCS_ERROR_CODES: readonly AdcsErrorCodeDefinition[] = [\n");
    for code in ADCS_CODES {
        out.push_str(&format!(
            "  {{ code: {}, status: {}, meaning: {} }},\n",
            ts(code.code),
            code.status.as_u16(),
            ts(code.meaning),
        ));
    }
    out.push_str("];\n\n");

    out.push_str("/** Why an adoption candidate listing is empty without looking. */\n");
    out.push_str(&format!(
        "export type AdoptionUnavailableReason = {};\n",
        AdoptionUnavailable::ALL
            .iter()
            .map(|reason| ts(&adoption_reason(*reason)))
            .collect::<Vec<String>>()
            .join(" | ")
    ));
    out
}

#[test]
fn the_dashboard_vocabulary_file_is_what_rust_renders() {
    let expected: String = rendered();
    if GENERATED_FIXTURE == expected {
        return;
    }
    let first_difference: String = GENERATED_FIXTURE
        .lines()
        .zip(expected.lines())
        .enumerate()
        .find(|(_, (committed, wanted))| committed != wanted)
        .map_or_else(
            || {
                format!(
                    "the files agree line by line but differ in length or line endings \
                     (committed {} bytes, rendered {} bytes; the file must end with one LF \
                     and use LF line endings)",
                    GENERATED_FIXTURE.len(),
                    expected.len()
                )
            },
            |(index, (committed, wanted))| {
                format!(
                    "line {}:\n  committed: {committed}\n  rendered:  {wanted}",
                    index + 1
                )
            },
        );
    panic!(
        "\n{FIXTURE_PATH} is not what the Rust vocabularies render.\n\nFirst difference, \
         {first_difference}\n\nReplace the whole file with this, byte for byte (everything \
         between the two marker lines, excluded), and never edit it by hand:\n\
         ----- BEGIN {FIXTURE_PATH} -----\n{expected}----- END {FIXTURE_PATH} -----\n"
    );
}

#[test]
fn the_rendering_names_every_entry_of_every_vocabulary() {
    // The rendering iterates the constants, so this holds by
    // construction; it is what keeps an edit of the renderer from
    // silently dropping a vocabulary while still comparing equal to its
    // own output.
    let file: String = rendered();
    for alert_type in AlertType::ALL {
        assert!(file.contains(&format!("value: '{}'", alert_type.as_str())));
    }
    for source in CertificateSource::ALL {
        assert!(file.contains(&format!("  {}: ", source.as_str())));
    }
    for kind in AdcsKeyType::ALL {
        assert!(file.contains(&format!("  {}: ", kind.as_str())));
    }
    for (name, _) in AdcsSubjectDefaults::FIELDS {
        assert!(file.contains(&format!("  {name}: ")));
    }
    for step in FailureStep::ALL {
        assert!(file.contains(&format!("  {}: ", step.as_str())));
    }
    for step in IssuanceStep::ALL {
        assert!(file.contains(&format!("  {}: ", step.as_str())));
    }
    for code in kdc_rejection_codes() {
        assert!(file.contains(&format!("  {code}: ")));
    }
    for code in ADCS_CODES {
        assert!(file.contains(&format!("code: '{}'", code.code)));
    }
    for reason in AdoptionUnavailable::ALL {
        assert!(file.contains(&format!("'{}'", adoption_reason(reason))));
    }
}

#[test]
fn a_quote_in_a_label_is_escaped() {
    assert_eq!(ts("account's"), "'account\\'s'");
    assert_eq!(ts("a\\b"), "'a\\\\b'");
}
