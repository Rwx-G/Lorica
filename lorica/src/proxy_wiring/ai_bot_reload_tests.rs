// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! White-box regression tests for the merged AI-crawler registry
//! (Story 8.2 AC #6 / #8). Covers the pure [`build_merged`] merge +
//! tolerance rules, the store-backed [`rebuild_from_store`] hot-reload
//! path, and the lenient loader skip behaviour.

use chrono::Utc;
use lorica_config::models::{CustomCrawler, CustomVerification};
use lorica_config::ConfigStore;

use super::ai_bot_merged::{self, MergedCrawler, MergedVerification};
use crate::ai_bot::BUILTIN_CRAWLERS;

fn custom(name: &str, pattern: &str, verification: CustomVerification, enabled: bool) -> CustomCrawler {
    let now = Utc::now();
    CustomCrawler {
        id: 0,
        name: name.to_string(),
        user_agent_pattern: pattern.to_string(),
        verification,
        enabled,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn build_merged_includes_enabled_custom() {
    let rows = vec![custom(
        "MyCustomBot",
        r"(?i)\bMyCustomBot\b",
        CustomVerification::UaOnly,
        true,
    )];
    let registry = ai_bot_merged::build_merged(&rows);

    assert_eq!(registry.len(), BUILTIN_CRAWLERS.len() + 1);
    let hit = MergedCrawler::match_first(&registry, "MyCustomBot/1.0")
        .expect("custom crawler should match its UA");
    assert_eq!(hit.name, "MyCustomBot");
    assert!(matches!(hit.verification, MergedVerification::UaOnly));
}

#[test]
fn disabled_custom_is_excluded() {
    let rows = vec![custom(
        "DisabledBot",
        r"(?i)\bDisabledBot\b",
        CustomVerification::UaOnly,
        false,
    )];
    let registry = ai_bot_merged::build_merged(&rows);

    assert_eq!(registry.len(), BUILTIN_CRAWLERS.len());
    assert!(MergedCrawler::match_first(&registry, "DisabledBot/1.0").is_none());
}

#[test]
fn custom_wins_on_name_conflict() {
    // A custom row named "GPTBot" must REPLACE the built-in GPTBot
    // entry (which uses IpRanges verification) with the custom's
    // UaOnly verification - in place, no duplicate.
    let rows = vec![custom(
        "GPTBot",
        r"(?i)\bGPTBot\b",
        CustomVerification::UaOnly,
        true,
    )];
    let registry = ai_bot_merged::build_merged(&rows);

    let gptbot_entries: Vec<&MergedCrawler> =
        registry.iter().filter(|c| c.name == "GPTBot").collect();
    assert_eq!(gptbot_entries.len(), 1, "custom must replace, not duplicate");
    assert!(
        matches!(gptbot_entries[0].verification, MergedVerification::UaOnly),
        "custom verification must win over the built-in IpRanges"
    );
    // Replacement is in place: total count stays builtin-sized.
    assert_eq!(registry.len(), BUILTIN_CRAWLERS.len());
}

#[test]
fn malformed_regex_row_skipped_registry_intact() {
    // One valid, one with an uncompilable pattern. The valid row
    // loads, the invalid is dropped, and the entire built-in registry
    // survives - the rebuild never aborts on bad operator input.
    let rows = vec![
        custom("GoodBot", r"(?i)\bGoodBot\b", CustomVerification::UaOnly, true),
        custom("BadBot", r"[invalid", CustomVerification::UaOnly, true),
    ];
    let registry = ai_bot_merged::build_merged(&rows);

    assert_eq!(registry.len(), BUILTIN_CRAWLERS.len() + 1);
    assert!(registry.iter().any(|c| c.name == "GoodBot"));
    assert!(!registry.iter().any(|c| c.name == "BadBot"));
    // Spot-check a built-in survived the bad row.
    assert!(registry.iter().any(|c| c.name == "GPTBot"));
}

#[test]
fn invalid_cidr_row_skipped_registry_intact() {
    let rows = vec![custom(
        "CidrBot",
        r"(?i)\bCidrBot\b",
        CustomVerification::IpRanges {
            cidrs: vec!["not-a-cidr".to_string()],
        },
        true,
    )];
    let registry = ai_bot_merged::build_merged(&rows);

    assert_eq!(registry.len(), BUILTIN_CRAWLERS.len());
    assert!(!registry.iter().any(|c| c.name == "CidrBot"));
}

#[test]
fn lenient_loader_returns_good_rows_no_skips() {
    let store = ConfigStore::open_in_memory().expect("in-memory store opens");
    store
        .create_custom_crawler(&custom(
            "LenientBot",
            r"(?i)\bLenientBot\b",
            CustomVerification::UaOnly,
            true,
        ))
        .expect("create custom crawler");

    let (good, skipped) = store.list_custom_crawlers_lenient();
    assert_eq!(good.len(), 1);
    assert_eq!(good[0].name, "LenientBot");
    assert!(skipped.is_empty(), "well-formed rows must not be skipped");
}

#[test]
fn rebuild_from_store_swaps_global_handle() {
    // This is the only test that writes the process-wide handle, so it
    // does not race other tests in the binary.
    let store = ConfigStore::open_in_memory().expect("in-memory store opens");
    store
        .create_custom_crawler(&custom(
            "HotReloadBot",
            r"(?i)\bHotReloadBot\b",
            CustomVerification::IpRanges {
                cidrs: vec!["203.0.113.0/24".to_string()],
            },
            true,
        ))
        .expect("create custom crawler");

    ai_bot_merged::rebuild_from_store(&store);

    let registry = ai_bot_merged::handle().load_full();
    let hit = MergedCrawler::match_first(&registry, "HotReloadBot/2.0")
        .expect("rebuilt registry should contain the custom crawler");
    assert_eq!(hit.name, "HotReloadBot");
    match &hit.verification {
        MergedVerification::IpRanges(ranges) => assert_eq!(ranges.len(), 1),
        other => panic!("expected IpRanges verification, got {other:?}"),
    }
    // Built-ins remain present after the swap.
    assert!(registry.iter().any(|c| c.name == "GPTBot"));
}
