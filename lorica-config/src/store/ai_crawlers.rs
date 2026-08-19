// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! `ai_crawlers_custom` table CRUD on `ConfigStore` (Story 8.2 AC #6).
//!
//! Schema lives at the bottom of `lorica-config/src/store/mod.rs::run_migrations()`
//! as the V40 inline block. JSON-blob storage convention mirrors the
//! existing `routes.aliases_json` / `routes.path_rules` pattern :
//! `verification_kind` carries the discriminant string and
//! `verification_data` carries the serde-rendered payload.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::{CustomCrawler, CustomVerification, CUSTOM_CRAWLER_MAX_COUNT};

impl ConfigStore {
    /// Insert a new custom crawler. Caller is responsible for
    /// validating regex compilation, baseline-UA non-match, CIDR
    /// list length cap, and `name` uniqueness against the built-in
    /// registry (those happen at the API boundary - see
    /// `lorica-api/src/ai_crawlers.rs`). The store layer enforces
    /// the count cap and the table-level UNIQUE on `name`.
    pub fn create_custom_crawler(&self, crawler: &CustomCrawler) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ai_crawlers_custom",
            [],
            |row| row.get(0),
        )?;
        if count as usize >= CUSTOM_CRAWLER_MAX_COUNT {
            return Err(ConfigError::Validation(format!(
                "Maximum {CUSTOM_CRAWLER_MAX_COUNT} custom crawlers reached ; \
                 delete an existing entry or contact maintainer if your \
                 use case requires more"
            )));
        }
        let (kind, data) = serialize_verification(&crawler.verification)?;
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO ai_crawlers_custom
             (name, user_agent_pattern, verification_kind, verification_data,
              enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                crawler.name,
                crawler.user_agent_pattern,
                kind,
                data,
                crawler.enabled as i32,
                now,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Fetch a single custom crawler by id.
    pub fn get_custom_crawler(&self, id: i64) -> Result<Option<CustomCrawler>> {
        self.conn
            .query_row(
                "SELECT id, name, user_agent_pattern, verification_kind, verification_data,
                 enabled, created_at, updated_at
                 FROM ai_crawlers_custom WHERE id = ?1",
                params![id],
                row_to_custom_crawler,
            )
            .optional()?
            .transpose()
    }

    /// List every custom crawler row, ordered by name.
    pub fn list_custom_crawlers(&self) -> Result<Vec<CustomCrawler>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, user_agent_pattern, verification_kind, verification_data,
             enabled, created_at, updated_at
             FROM ai_crawlers_custom ORDER BY name",
        )?;
        let rows = stmt.query_map([], row_to_custom_crawler)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// List every custom crawler row tolerantly (Story 8.2 AC #8).
    ///
    /// Unlike [`list_custom_crawlers`], a single malformed row (a
    /// `verification_data` blob that fails to parse, an unknown
    /// `verification_kind`, an invalid stored timestamp) does NOT
    /// abort the whole load : the bad row is dropped and recorded in
    /// the returned skip list while every well-formed row is still
    /// returned. The merged-registry rebuild uses this loader so a
    /// single corrupt row can never blank the live AI-crawler
    /// registry on hot-reload.
    ///
    /// Returns `(good_rows, skipped)` where `skipped` is a list of
    /// `(row_id, reason)` ; `row_id` is `-1` when the failure is at
    /// the statement / column-read level and no id could be read.
    pub fn list_custom_crawlers_lenient(&self) -> (Vec<CustomCrawler>, Vec<(i64, String)>) {
        let mut good: Vec<CustomCrawler> = Vec::new();
        let mut skipped: Vec<(i64, String)> = Vec::new();
        let mut stmt = match self.conn.prepare(
            "SELECT id, name, user_agent_pattern, verification_kind, verification_data,
             enabled, created_at, updated_at
             FROM ai_crawlers_custom ORDER BY name",
        ) {
            Ok(stmt) => stmt,
            Err(e) => {
                skipped.push((-1, format!("prepare failed: {e}")));
                return (good, skipped);
            }
        };
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            Ok((id, row_to_custom_crawler(row)?))
        });
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                skipped.push((-1, format!("query failed: {e}")));
                return (good, skipped);
            }
        };
        for row in rows {
            match row {
                Ok((_, Ok(crawler))) => good.push(crawler),
                Ok((id, Err(e))) => skipped.push((id, e.to_string())),
                Err(e) => skipped.push((-1, format!("row read failed: {e}"))),
            }
        }
        (good, skipped)
    }

    /// Update a custom crawler row. Returns `NotFound` if the id
    /// does not exist.
    pub fn update_custom_crawler(&self, crawler: &CustomCrawler) -> Result<()> {
        let (kind, data) = serialize_verification(&crawler.verification)?;
        let now = Utc::now().to_rfc3339();
        let changed = self.conn.execute(
            "UPDATE ai_crawlers_custom
             SET name=?2, user_agent_pattern=?3, verification_kind=?4,
                 verification_data=?5, enabled=?6, updated_at=?7
             WHERE id=?1",
            params![
                crawler.id,
                crawler.name,
                crawler.user_agent_pattern,
                kind,
                data,
                crawler.enabled as i32,
                now,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "ai_crawler_custom {}",
                crawler.id
            )));
        }
        Ok(())
    }

    /// Delete a custom crawler row by id.
    pub fn delete_custom_crawler(&self, id: i64) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM ai_crawlers_custom WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("ai_crawler_custom {id}")));
        }
        Ok(())
    }

    /// Total custom crawler row count. Used by the API layer to
    /// short-circuit POST when the count cap is reached.
    pub fn count_custom_crawlers(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ai_crawlers_custom",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

fn serialize_verification(v: &CustomVerification) -> Result<(&'static str, Option<String>)> {
    Ok(match v {
        CustomVerification::UaOnly => ("ua_only", None),
        CustomVerification::Rdns { suffixes } => {
            let blob = serde_json::to_string(&serde_json::json!({ "suffixes": suffixes }))
                .map_err(|e| {
                    ConfigError::Validation(format!("verification_data serialize: {e}"))
                })?;
            ("rdns", Some(blob))
        }
        CustomVerification::IpRanges { cidrs } => {
            let blob = serde_json::to_string(&serde_json::json!({ "cidrs": cidrs })).map_err(
                |e| ConfigError::Validation(format!("verification_data serialize: {e}")),
            )?;
            ("ip_ranges", Some(blob))
        }
    })
}

fn row_to_custom_crawler(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<CustomCrawler>> {
    let id: i64 = row.get(0)?;
    let name: String = row.get(1)?;
    let user_agent_pattern: String = row.get(2)?;
    let kind: String = row.get(3)?;
    let data: Option<String> = row.get(4)?;
    let enabled: i32 = row.get(5)?;
    let created_at_s: String = row.get(6)?;
    let updated_at_s: String = row.get(7)?;
    let built = decode_verification(id, &kind, data.as_deref()).and_then(|verification| {
        let created_at: DateTime<Utc> = parse_dt(&created_at_s)?;
        let updated_at: DateTime<Utc> = parse_dt(&updated_at_s)?;
        Ok(CustomCrawler {
            id,
            name,
            user_agent_pattern,
            verification,
            enabled: enabled != 0,
            created_at,
            updated_at,
        })
    });
    Ok(built)
}

fn decode_verification(id: i64, kind: &str, data: Option<&str>) -> Result<CustomVerification> {
    let verification = match (kind, data) {
        ("ua_only", _) => CustomVerification::UaOnly,
        ("rdns", Some(json)) => {
            #[derive(serde::Deserialize)]
            struct Shape {
                suffixes: Vec<String>,
            }
            let parsed: Shape = serde_json::from_str(json).map_err(|e| {
                ConfigError::Validation(format!("verification_data rdns parse: {e}"))
            })?;
            CustomVerification::Rdns {
                suffixes: parsed.suffixes,
            }
        }
        ("ip_ranges", Some(json)) => {
            #[derive(serde::Deserialize)]
            struct Shape {
                cidrs: Vec<String>,
            }
            let parsed: Shape = serde_json::from_str(json).map_err(|e| {
                ConfigError::Validation(format!("verification_data ip_ranges parse: {e}"))
            })?;
            CustomVerification::IpRanges {
                cidrs: parsed.cidrs,
            }
        }
        (k, _) => {
            return Err(ConfigError::Validation(format!(
                "unknown verification_kind {k:?} on ai_crawlers_custom row {id}"
            )));
        }
    };
    Ok(verification)
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| ConfigError::Validation(format!("invalid datetime {s:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;

    fn open_store() -> ConfigStore {
        ConfigStore::open_in_memory().expect("in-memory store opens")
    }

    #[test]
    fn create_and_get_custom_crawler_round_trip() {
        let store = open_store();
        let now = Utc::now();
        let entry = CustomCrawler {
            id: 0,
            name: "MyCustomBot".into(),
            user_agent_pattern: r"(?i)\bMyCustomBot\b".into(),
            verification: CustomVerification::IpRanges {
                cidrs: vec!["203.0.113.0/24".into(), "198.51.100.0/28".into()],
            },
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let id = store.create_custom_crawler(&entry).unwrap();
        let loaded = store.get_custom_crawler(id).unwrap().unwrap();
        assert_eq!(loaded.name, "MyCustomBot");
        match loaded.verification {
            CustomVerification::IpRanges { cidrs } => {
                assert_eq!(cidrs.len(), 2);
                assert!(cidrs.contains(&"203.0.113.0/24".to_string()));
            }
            _ => panic!("wrong verification kind"),
        }
    }

    #[test]
    fn ua_only_round_trip() {
        let store = open_store();
        let now = Utc::now();
        let entry = CustomCrawler {
            id: 0,
            name: "InternalScraper".into(),
            user_agent_pattern: r"(?i)\bInternalScraper\b".into(),
            verification: CustomVerification::UaOnly,
            enabled: false,
            created_at: now,
            updated_at: now,
        };
        let id = store.create_custom_crawler(&entry).unwrap();
        let loaded = store.get_custom_crawler(id).unwrap().unwrap();
        assert!(matches!(loaded.verification, CustomVerification::UaOnly));
        assert!(!loaded.enabled);
    }

    #[test]
    fn list_orders_by_name() {
        let store = open_store();
        let now = Utc::now();
        for n in ["Charlie", "Alice", "Bob"] {
            store
                .create_custom_crawler(&CustomCrawler {
                    id: 0,
                    name: n.into(),
                    user_agent_pattern: format!(r"(?i)\b{n}\b"),
                    verification: CustomVerification::UaOnly,
                    enabled: true,
                    created_at: now,
                    updated_at: now,
                })
                .unwrap();
        }
        let listed = store.list_custom_crawlers().unwrap();
        let names: Vec<&str> = listed.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["Alice", "Bob", "Charlie"]);
    }

    #[test]
    fn update_changes_pattern_and_kind() {
        let store = open_store();
        let now = Utc::now();
        let id = store
            .create_custom_crawler(&CustomCrawler {
                id: 0,
                name: "Switcher".into(),
                user_agent_pattern: r"(?i)\bSwitcher\b".into(),
                verification: CustomVerification::UaOnly,
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .unwrap();
        let mut row = store.get_custom_crawler(id).unwrap().unwrap();
        row.user_agent_pattern = r"(?i)\bSwitcherV2\b".into();
        row.verification = CustomVerification::Rdns {
            suffixes: vec![".switcher.example".into()],
        };
        store.update_custom_crawler(&row).unwrap();
        let reloaded = store.get_custom_crawler(id).unwrap().unwrap();
        assert!(reloaded.user_agent_pattern.contains("V2"));
        assert!(matches!(
            reloaded.verification,
            CustomVerification::Rdns { .. }
        ));
    }

    #[test]
    fn delete_returns_not_found_for_unknown_id() {
        let store = open_store();
        let err = store.delete_custom_crawler(9999).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }

    #[test]
    fn create_unique_name_violation() {
        let store = open_store();
        let now = Utc::now();
        let entry = CustomCrawler {
            id: 0,
            name: "Duplicate".into(),
            user_agent_pattern: r"(?i)\bDuplicate\b".into(),
            verification: CustomVerification::UaOnly,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        store.create_custom_crawler(&entry).unwrap();
        // Second insert with the same name should fail via the
        // table's UNIQUE constraint - mapped to a Sqlite error.
        let result = store.create_custom_crawler(&entry);
        assert!(result.is_err());
    }
}
