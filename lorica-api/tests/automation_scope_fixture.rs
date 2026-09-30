//! The one guard on the Rust-to-TypeScript edge of the automation
//! scope vocabulary, and of the MCP tier table the mint form reads.
//!
//! Every other restatement of that vocabulary is pinned inside one
//! language: `AutomationScope::as_str` and the published audit
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
//!
//! The tier section is held tighter, because the dashboard does more
//! with it than list it: the mint form resolves a scope set to a tier
//! the way `lorica_automation_policy::resolve` does, in TypeScript. Two
//! implementations of one rule share a vector set, so this test renders
//! the whole section, the table and what `resolve` answers for every
//! scope set up to two scopes wide and for each tier's allowed set,
//! and compares it with the committed bytes. The frontend suite replays
//! the vectors through its own implementation, so a rule changed on
//! either side alone turns one of the two suites red.

use std::collections::BTreeSet;

use lorica_automation_policy::{resolve, Tier, TIERS};
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

/// The second export: the scopes whose paths consult a token's grants.
const GRANT_BOUNDED_EXPORT: &str = "GRANT_BOUNDED_SCOPES";

/// How the enum spells `scope`.
fn wire(scope: AutomationScope) -> String {
    serde_json::to_value(scope)
        .expect("a scope serialises")
        .as_str()
        .expect("a scope serialises to a string")
        .to_string()
}

#[test]
fn the_dashboard_fixture_carries_exactly_the_scopes_the_enum_declares() {
    let in_typescript: BTreeSet<String> = scopes_in_fixture(GENERATED_FIXTURE, EXPORT);
    assert!(
        !in_typescript.is_empty(),
        "no scope string found in {FIXTURE_PATH}: the array was reshaped and this \
         gate went blind. The parse expects `export const {EXPORT}` followed by \
         `= [` and a list of single-quoted strings."
    );

    let in_rust: BTreeSet<String> = AutomationScope::ALL.iter().copied().map(wire).collect();

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
fn the_dashboard_fixture_names_exactly_the_scopes_the_enum_says_its_grants_bound() {
    // Typed absence (2026-09-30) is enforced by the model and rendered
    // by the dashboard, which asks for grants only when a bounded scope
    // is selected and shows "not applicable" otherwise. The set is the
    // enum's `is_grant_bounded`; this is the edge that keeps the form
    // asking for exactly what the node will require and refuse.
    let in_typescript: BTreeSet<String> =
        scopes_in_fixture(GENERATED_FIXTURE, GRANT_BOUNDED_EXPORT);
    assert!(
        !in_typescript.is_empty(),
        "no scope string found under `export const {GRANT_BOUNDED_EXPORT}` in {FIXTURE_PATH}: \
         the array was reshaped and this gate went blind"
    );
    let in_rust: BTreeSet<String> = AutomationScope::ALL
        .iter()
        .copied()
        .filter(|scope| scope.is_grant_bounded())
        .map(wire)
        .collect();
    assert_eq!(
        in_typescript, in_rust,
        "\nEdit `{GRANT_BOUNDED_EXPORT}` in {FIXTURE_PATH} by hand so it is exactly the scopes \
         `AutomationScope::is_grant_bounded` answers true for, sorted. A scope missing there is \
         one the mint form mints without the grants the node then refuses it for.\n"
    );
}

#[test]
fn the_fixture_is_sorted_so_its_shape_is_one_canonical_thing() {
    // The comparison above is set-based and would accept any order.
    // Pinning the order keeps the file a byte-comparable artefact:
    // whoever adds a scope inserts it in one predictable place, and a
    // diff on this file shows the change and nothing else.
    for export in [EXPORT, GRANT_BOUNDED_EXPORT] {
        let listed: Vec<String> = ordered_scopes_in_fixture(GENERATED_FIXTURE, export);
        let mut sorted: Vec<String> = listed.clone();
        sorted.sort();
        assert_eq!(
            listed, sorted,
            "`{export}` in {FIXTURE_PATH} is not sorted; keep the list in ascending order"
        );
    }
}

/// Every single-quoted string inside the array literal `export` names.
fn ordered_scopes_in_fixture(source: &str, export: &str) -> Vec<String> {
    let declaration = format!("export const {export}");
    let after_export: &str = match source.split_once(declaration.as_str()) {
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
    without_comments(body)
        .split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// `body` with every comment removed.
///
/// The one way this guard could pass while the vocabularies disagree:
/// a commented-out entry (`// 'waf:read',`) still carries its quotes,
/// so the quote split counted it as present while the mint form had
/// lost the scope. That is exactly the silent failure the test exists
/// to prevent. A scope string never spans a line, so dropping whole
/// comment spans cannot swallow a live entry.
fn without_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        let line_comment = rest.find("//");
        let block_comment = rest.find("/*");
        let (at, close) = match (line_comment, block_comment) {
            (Some(line), Some(block)) if line < block => (line, "\n"),
            (Some(_), Some(block)) => (block, "*/"),
            (Some(line), None) => (line, "\n"),
            (None, Some(block)) => (block, "*/"),
            (None, None) => {
                out.push_str(rest);
                return out;
            }
        };
        out.push_str(&rest[..at]);
        rest = match rest[at..].find(close) {
            Some(end) => &rest[at + end + close.len()..],
            // An unterminated comment swallows the remainder, which
            // leaves the extraction empty and trips the sanity
            // assertion rather than reading as agreement.
            None => return out,
        };
    }
}

/// The same strings as a set, which is what the diff compares.
fn scopes_in_fixture(source: &str, export: &str) -> BTreeSet<String> {
    ordered_scopes_in_fixture(source, export)
        .into_iter()
        .collect()
}

#[test]
fn a_commented_out_entry_is_not_counted_as_present() {
    // The one way this guard could pass while the vocabularies
    // disagree. Asserted on a synthetic fixture rather than by editing
    // the committed one, so the check is about the parser and not
    // about today's list.
    let commented = format!(
        "export const {EXPORT}: readonly AutomationScope[] = [\n\
         \x20 'cluster:read',\n\
         \x20 // 'waf:read',\n\
         \x20 /* 'logs:read', */\n\
         ];\n"
    );
    assert_eq!(
        ordered_scopes_in_fixture(&commented, EXPORT),
        vec!["cluster:read".to_string()]
    );
}

/// Where the rendered tier section opens and closes in the fixture.
const TIER_SECTION_BEGIN: &str = "// BEGIN MCP TIERS";
const TIER_SECTION_END: &str = "// END MCP TIERS";

/// `scopes` as a TypeScript array literal of single-quoted strings.
fn typescript_list<S: AsRef<str>>(scopes: &[S]) -> String {
    let quoted: Vec<String> = scopes
        .iter()
        .map(|scope| format!("'{}'", scope.as_ref()))
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// Every scope set the vectors cover: none, each scope alone, each
/// pair in `AutomationScope::ALL` order, and each tier's allowed set.
fn vector_scope_sets() -> Vec<Vec<AutomationScope>> {
    let all = AutomationScope::ALL;
    let mut sets: Vec<Vec<AutomationScope>> = vec![Vec::new()];
    sets.extend(all.iter().map(|scope| vec![*scope]));
    for (at, first) in all.iter().enumerate() {
        for second in &all[at + 1..] {
            sets.push(vec![*first, *second]);
        }
    }
    sets.extend(TIERS.iter().map(|definition| {
        definition
            .requires
            .iter()
            .chain(definition.tolerates)
            .copied()
            .collect()
    }));
    sets
}

/// The fixture's tier section as it must read, rendered from the
/// policy crate.
fn rendered_tier_section() -> String {
    let mut out = String::new();
    out.push_str(TIER_SECTION_BEGIN);
    out.push_str(
        ": rendered from lorica-automation-policy by\n\
         // lorica-api/tests/automation_scope_fixture.rs, which prints the section as it\n\
         // must read when the committed one differs. Replace it with that; never edit\n\
         // it by hand.\n\n",
    );
    let names: Vec<String> = Tier::ALL
        .iter()
        .map(|tier| format!("'{}'", tier.as_str()))
        .collect();
    out.push_str("/** An MCP tier, in increasing order of reach (`Tier::ALL`). */\n");
    out.push_str(&format!("export type McpTier = {};\n\n", names.join(" | ")));
    out.push_str(
        "/**\n * One row of `TIERS`: the scopes that make a token this tier, and the\n \
         * scopes of another tier its tools need and so allow beside its own.\n */\n\
         export interface McpTierDefinition {\n  readonly tier: McpTier;\n  \
         readonly requires: readonly AutomationScope[];\n  \
         readonly tolerates: readonly AutomationScope[];\n}\n\n",
    );
    out.push_str("/** The tier partition, in increasing order of reach. */\n");
    out.push_str("export const MCP_TIERS: readonly McpTierDefinition[] = [\n");
    for definition in TIERS {
        out.push_str(&format!(
            "  {{\n    tier: '{}',\n    requires: {},\n    tolerates: {},\n  }},\n",
            definition.tier.as_str(),
            typescript_list(definition.requires),
            typescript_list(definition.tolerates),
        ));
    }
    out.push_str("];\n\n");
    out.push_str(
        "/**\n * What `resolve` answers for one scope set: the tier its highest-reaching\n \
         * scopes make it (`null` for none), the scopes that name that tier, and the\n \
         * scopes that tier does not allow. A set with no offending scope is one tier\n \
         * and starts lorica-mcp; any other is refused there.\n */\n\
         export interface McpTierVector {\n  readonly scopes: readonly AutomationScope[];\n  \
         readonly tier: McpTier | null;\n  readonly anchoring: readonly AutomationScope[];\n  \
         readonly offending: readonly AutomationScope[];\n}\n\n",
    );
    out.push_str("export const MCP_TIER_VECTORS: readonly McpTierVector[] = [\n");
    for set in vector_scope_sets() {
        let spelled: Vec<String> = set.iter().map(|scope| scope.as_str().to_string()).collect();
        let (tier, anchoring, offending) = match resolve(&spelled) {
            Ok(tier) => (
                Some(tier),
                spelled
                    .iter()
                    .filter(|scope| Tier::of_scope(scope) == Some(tier))
                    .cloned()
                    .collect(),
                Vec::new(),
            ),
            Err(refused) => (refused.tier, refused.anchoring, refused.offending),
        };
        out.push_str(&format!(
            "  {{ scopes: {}, tier: {}, anchoring: {}, offending: {} }},\n",
            typescript_list(&spelled),
            tier.map_or("null".to_string(), |tier| format!("'{}'", tier.as_str())),
            typescript_list(&anchoring),
            typescript_list(&offending),
        ));
    }
    out.push_str("];\n");
    out.push_str(TIER_SECTION_END);
    out
}

#[test]
fn the_dashboard_fixture_carries_the_tier_table_and_vectors_rendered_from_the_policy() {
    let rendered = rendered_tier_section();
    let committed: Option<&str> = GENERATED_FIXTURE
        .split_once(TIER_SECTION_BEGIN)
        .and_then(|(_, rest)| rest.split_once(TIER_SECTION_END))
        .map(|(inside, _)| inside);
    let expected_inside = rendered
        .strip_prefix(TIER_SECTION_BEGIN)
        .and_then(|rest| rest.strip_suffix(TIER_SECTION_END))
        .expect("the rendering opens and closes with the markers");
    assert!(
        committed == Some(expected_inside),
        "\nThe MCP tier section of {FIXTURE_PATH} is not what lorica-automation-policy \
         renders. Replace everything from `{TIER_SECTION_BEGIN}` to `{TIER_SECTION_END}` \
         (the markers included) with this, byte for byte:\n\n{rendered}\n"
    );
}

#[test]
fn the_tier_vectors_cover_every_scope_and_every_tier() {
    // A vector set that stopped exercising a scope or a tier would still
    // compare equal to its own rendering; this is what keeps it wide.
    let sets = vector_scope_sets();
    for scope in AutomationScope::ALL {
        assert!(sets.contains(&vec![*scope]), "{scope} alone");
    }
    let rendered = rendered_tier_section();
    for tier in Tier::ALL {
        assert!(
            rendered.contains(&format!("tier: '{}', anchoring", tier.as_str())),
            "no vector resolves to the {tier}"
        );
    }
    assert!(
        rendered.contains("tier: null"),
        "no vector resolves to no tier"
    );
    assert!(
        rendered.contains("offending: ['"),
        "no vector spans two tiers"
    );
}
