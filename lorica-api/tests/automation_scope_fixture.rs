//! The one guard on the Rust-to-TypeScript edge of the automation
//! scope vocabulary.
//!
//! Every other restatement of that vocabulary is pinned inside one
//! language: `scope_str`, `scope_wire_name` and the published audit
//! reasons are each walked against `AutomationScope::ALL` by a Rust
//! test, and `AutomationTokensTab` derives its create form from the
//! generated file this test reads. The edge between the two languages
//! is the only one nothing could check, and its failure mode is quiet
//! in both directions: add a variant on the Rust side and forget the
//! file, and the Rust suite passes, the frontend suite passes, and the
//! mint form simply cannot offer the scope.
//!
//! Same idiom as `openapi_contract.rs`, for the same reasons: the
//! committed file is read with `include_str!`, the extraction asserts
//! it found something before any comparison (two empty sets compare
//! equal, so a broken parser must not read as a clean contract), the
//! two sets are diffed in both directions, and the failure names what
//! to do. Nothing is auto-written: a generator someone has to remember
//! to rerun is a delayed transcription, not a guard.

use std::collections::BTreeSet;

use lorica_config::models::AutomationScope;

/// The generated file, relative to this crate's manifest.
///
/// Read through `include_str!` rather than at runtime so a rename or a
/// move is a compile error naming the path, which is a shorter walk
/// than a test that cannot find its fixture.
const GENERATED_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts"
));

/// Where the fixture lives, for the failure message.
const FIXTURE_PATH: &str =
    "lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts";

/// The exported array's name, which is also where the parse starts.
const EXPORT: &str = "AUTOMATION_SCOPE_WIRE_STRINGS";

#[test]
fn the_dashboard_fixture_carries_exactly_the_scopes_the_enum_declares() {
    let in_typescript: BTreeSet<String> = scopes_in_fixture(GENERATED_FIXTURE);
    assert!(
        !in_typescript.is_empty(),
        "no scope string found in {FIXTURE_PATH}: the array was reshaped and this \
         gate went blind. The parse expects `export const {EXPORT}` followed by \
         `= [` and a list of single-quoted strings."
    );

    let in_rust: BTreeSet<String> = AutomationScope::ALL
        .iter()
        .map(|scope| {
            serde_json::to_value(scope)
                .expect("a scope serialises")
                .as_str()
                .expect("a scope serialises to a string")
                .to_string()
        })
        .collect();

    let missing_from_typescript: Vec<&String> = in_rust.difference(&in_typescript).collect();
    let typescript_without_rust: Vec<&String> = in_typescript.difference(&in_rust).collect();

    if !missing_from_typescript.is_empty() || !typescript_without_rust.is_empty() {
        let mut msg = String::from("\nAutomation scope vocabulary drift, Rust vs TypeScript.\n");
        msg.push_str(&format!(
            "\nIn AutomationScope::ALL and missing from the fixture ({}):\n",
            missing_from_typescript.len()
        ));
        for scope in &missing_from_typescript {
            msg.push_str(&format!("  {scope}\n"));
        }
        msg.push_str(&format!(
            "\nIn the fixture and not in AutomationScope::ALL ({}):\n",
            typescript_without_rust.len()
        ));
        for scope in &typescript_without_rust {
            msg.push_str(&format!("  {scope}\n"));
        }
        msg.push_str(&format!(
            "\nEdit {FIXTURE_PATH} by hand so its list is exactly the serde renames on \
             `AutomationScope` in lorica-config, sorted. Nothing generates it. A scope \
             the fixture does not carry is a scope the dashboard's mint form cannot \
             offer, and an operator finds that out with no error anywhere.\n"
        ));
        panic!("{msg}");
    }
}

#[test]
fn the_fixture_is_sorted_so_its_shape_is_one_canonical_thing() {
    // The comparison above is set-based and would accept any order.
    // Pinning the order keeps the file a byte-comparable artefact:
    // whoever adds a scope inserts it in one predictable place, and a
    // diff on this file shows the change and nothing else.
    let listed: Vec<String> = ordered_scopes_in_fixture(GENERATED_FIXTURE);
    let mut sorted: Vec<String> = listed.clone();
    sorted.sort();
    assert_eq!(
        listed, sorted,
        "{FIXTURE_PATH} is not sorted; keep the list in ascending order"
    );
}

/// Every single-quoted string inside the exported array literal.
fn ordered_scopes_in_fixture(source: &str) -> Vec<String> {
    let after_export: &str = match source.split_once(EXPORT) {
        Some((_, rest)) => rest,
        None => return Vec::new(),
    };
    // `= [` and not a bare `[`: the declaration is annotated
    // `readonly AutomationScope[]`, so the first bracket in the line is
    // the type's and not the array's.
    let body: &str = match after_export.split_once("= [") {
        Some((_, rest)) => match rest.split_once(']') {
            Some((body, _)) => body,
            None => return Vec::new(),
        },
        None => return Vec::new(),
    };
    body.split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// The same strings as a set, which is what the diff compares.
fn scopes_in_fixture(source: &str) -> BTreeSet<String> {
    ordered_scopes_in_fixture(source).into_iter().collect()
}
