//! Row-to-struct conversion helpers shared across the `store`
//! submodules. These free functions translate a `rusqlite::Row` into a
//! typed domain model, performing enum parsing, JSON decoding of
//! column-typed fields, and datetime parsing. They are `pub(super)` so
//! every sibling file under `store/` can re-use them without leaking
//! implementation details to the rest of the crate.

use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::error::{ConfigError, Result};
use crate::models::*;

/// Parse a datetime string from SQLite into a UTC `DateTime`.
///
/// Accepts two formats:
///
/// 1. **RFC3339** (canonical, e.g. `2026-04-17T19:13:17Z` or
///    `2026-04-17T19:13:17+00:00`). This is what every Rust writer in
///    the codebase emits via `DateTime::to_rfc3339()`.
///
/// 2. **SQLite SQL-plain** (`2026-04-17 19:13:17`, space separator, no
///    timezone). SQLite's `datetime('now')` - used as the `DEFAULT`
///    on several schema columns and as a raw SQL fragment in older
///    paths - produces this format. Interpreted as UTC. A historical
///    ACME renewal path (`certs.rs::reassign_certificate`) wrote this
///    format and caused every worker to crash-loop on the next
///    config reload; the write side was fixed to emit RFC3339 but
///    legacy rows may still carry the old format, hence the fallback
///    here to keep future loads crash-safe.
pub(super) fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    // Canonical path: RFC3339 with explicit timezone.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Fallback: SQLite SQL-plain. Parse as naive, assume UTC - matches
    // SQLite's documented convention for `datetime('now')`.
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(naive.and_utc());
    }
    // Some SQLite builds emit fractional seconds. Try that shape too.
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Ok(naive.and_utc());
    }
    Err(ConfigError::Validation(format!(
        "invalid datetime '{s}': expected RFC3339 (2026-04-17T19:13:17Z) or SQLite format (2026-04-17 19:13:17)"
    )))
}

/// Parse an optional RFC3339 datetime string.
pub(super) fn parse_optional_datetime(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    match s {
        Some(s) => Ok(Some(parse_datetime(&s)?)),
        None => Ok(None),
    }
}

pub(super) fn row_to_route(row: &rusqlite::Row<'_>) -> Result<Route> {
    let hostname_aliases_json: String = row.get(11)?;
    let hostname_aliases: Vec<String> = serde_json::from_str(&hostname_aliases_json)
        .map_err(|e| ConfigError::Validation(format!("invalid hostname_aliases JSON: {e}")))?;

    let proxy_headers_json: String = row.get(12)?;
    let proxy_headers: std::collections::HashMap<String, String> =
        serde_json::from_str(&proxy_headers_json)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers JSON: {e}")))?;

    let response_headers_json: String = row.get(13)?;
    let response_headers: std::collections::HashMap<String, String> =
        serde_json::from_str(&response_headers_json)
            .map_err(|e| ConfigError::Validation(format!("invalid response_headers JSON: {e}")))?;

    let proxy_headers_remove_json: String = row.get(23)?;
    let proxy_headers_remove: Vec<String> = serde_json::from_str(&proxy_headers_remove_json)
        .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers_remove JSON: {e}")))?;

    let response_headers_remove_json: String = row.get(24)?;
    let response_headers_remove: Vec<String> = serde_json::from_str(&response_headers_remove_json)
        .map_err(|e| {
            ConfigError::Validation(format!("invalid response_headers_remove JSON: {e}"))
        })?;

    let ip_allowlist_json: String = row.get(29)?;
    let ip_allowlist: Vec<String> = serde_json::from_str(&ip_allowlist_json)
        .map_err(|e| ConfigError::Validation(format!("invalid ip_allowlist JSON: {e}")))?;

    let ip_denylist_json: String = row.get(30)?;
    let ip_denylist: Vec<String> = serde_json::from_str(&ip_denylist_json)
        .map_err(|e| ConfigError::Validation(format!("invalid ip_denylist JSON: {e}")))?;

    let cors_allowed_origins_json: String = row.get(31)?;
    let cors_allowed_origins: Vec<String> = serde_json::from_str(&cors_allowed_origins_json)
        .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_origins JSON: {e}")))?;

    let cors_allowed_methods_json: String = row.get(32)?;
    let cors_allowed_methods: Vec<String> = serde_json::from_str(&cors_allowed_methods_json)
        .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_methods JSON: {e}")))?;

    let path_rules_json: String = row.get(45)?;
    let path_rules: Vec<PathRule> = serde_json::from_str(&path_rules_json)
        .map_err(|e| ConfigError::Validation(format!("invalid path_rules JSON: {e}")))?;
    let return_status: Option<u16> = row.get::<_, Option<i32>>(46)?.map(|v| v as u16);

    Ok(Route {
        id: row.get(0)?,
        hostname: row.get(1)?,
        path_prefix: row.get(2)?,
        certificate_id: row.get(3)?,
        load_balancing: LoadBalancing::from_str(&row.get::<_, String>(4)?)
            .map_err(|e| ConfigError::Validation(format!("invalid load_balancing: {e}")))?,
        waf_enabled: row.get(5)?,
        waf_mode: WafMode::from_str(&row.get::<_, String>(6)?)
            .map_err(|e| ConfigError::Validation(format!("invalid waf_mode: {e}")))?,
        enabled: row.get(7)?,
        force_https: row.get(8)?,
        redirect_hostname: row.get(9)?,
        redirect_to: row.get(10)?,
        hostname_aliases,
        proxy_headers,
        response_headers,
        security_headers: row.get(14)?,
        connect_timeout_s: row.get(15)?,
        read_timeout_s: row.get(16)?,
        send_timeout_s: row.get(17)?,
        strip_path_prefix: row.get(18)?,
        add_path_prefix: row.get(19)?,
        path_rewrite_pattern: row.get(20)?,
        path_rewrite_replacement: row.get(21)?,
        access_log_enabled: row.get(22)?,
        proxy_headers_remove,
        response_headers_remove,
        max_request_body_bytes: row.get::<_, Option<i64>>(25)?.map(|v| v as u64),
        websocket_enabled: row.get(26)?,
        rate_limit_rps: row.get::<_, Option<i32>>(27)?.map(|v| v as u32),
        rate_limit_burst: row.get::<_, Option<i32>>(28)?.map(|v| v as u32),
        ip_allowlist,
        ip_denylist,
        cors_allowed_origins,
        cors_allowed_methods,
        cors_max_age_s: row.get(33)?,
        compression_enabled: row.get(34)?,
        retry_attempts: row.get::<_, Option<i32>>(35)?.map(|v| v as u32),
        cache_enabled: row.get(36)?,
        cache_ttl_s: row.get(37)?,
        cache_max_bytes: row.get(38)?,
        max_connections: row.get::<_, Option<i32>>(39)?.map(|v| v as u32),
        slowloris_threshold_ms: row.get(40)?,
        auto_ban_threshold: row.get::<_, Option<i32>>(41)?.map(|v| v as u32),
        auto_ban_duration_s: row.get(42)?,
        path_rules,
        return_status,
        sticky_session: row.get::<_, bool>(47).unwrap_or(false),
        basic_auth_username: row.get::<_, Option<String>>(48).unwrap_or(None),
        basic_auth_password_hash: row.get::<_, Option<String>>(49).unwrap_or(None),
        stale_while_revalidate_s: row.get::<_, i32>(50).unwrap_or(10),
        stale_if_error_s: row.get::<_, i32>(51).unwrap_or(60),
        retry_on_methods: {
            let json: String = row
                .get::<_, String>(52)
                .unwrap_or_else(|_| "[]".to_string());
            serde_json::from_str(&json).unwrap_or_default()
        },
        maintenance_mode: row.get::<_, bool>(53).unwrap_or(false),
        error_page_html: row.get::<_, Option<String>>(54).unwrap_or(None),
        cache_vary_headers: {
            let json: String = row
                .get::<_, String>(55)
                .unwrap_or_else(|_| "[]".to_string());
            serde_json::from_str(&json).unwrap_or_default()
        },
        header_rules: {
            let json: String = row
                .get::<_, String>(56)
                .unwrap_or_else(|_| "[]".to_string());
            serde_json::from_str(&json).unwrap_or_default()
        },
        traffic_splits: {
            let json: String = row
                .get::<_, String>(57)
                .unwrap_or_else(|_| "[]".to_string());
            serde_json::from_str(&json).unwrap_or_default()
        },
        forward_auth: {
            let raw: Option<String> = row.get::<_, Option<String>>(58).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        mirror: {
            let raw: Option<String> = row.get::<_, Option<String>>(59).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        response_rewrite: {
            let raw: Option<String> = row.get::<_, Option<String>>(60).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        mtls: {
            let raw: Option<String> = row.get::<_, Option<String>>(61).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        rate_limit: {
            let raw: Option<String> = row.get::<_, Option<String>>(62).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        geoip: {
            // Column index 63 (v1.4.0 story 2.2 migration V34). Stored
            // as JSON or NULL; a parse failure downgrades silently to
            // `None` so a hand-edited bad row cannot crash the proxy.
            let raw: Option<String> = row.get::<_, Option<String>>(63).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        bot_protection: {
            // Column index 64 (v1.4.0 story 3.3 migration V35). Same
            // forgiving parse policy as geoip above — a corrupt JSON
            // blob on one row degrades the feature to off for that
            // route but does not take the proxy down.
            let raw: Option<String> = row.get::<_, Option<String>>(64).unwrap_or(None);
            raw.and_then(|s| serde_json::from_str(&s).ok())
        },
        group_name: {
            // Column index 65 (v1.4.1 migration V37). Free-form
            // operator-supplied classification string, empty = ungrouped.
            // `unwrap_or_default` covers rows that pre-date the V37
            // migration on a bisect build.
            row.get::<_, String>(65).unwrap_or_default()
        },
        created_at: parse_datetime(&row.get::<_, String>(43)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(44)?)?,
    })
}

pub(super) fn row_to_backend(row: &rusqlite::Row<'_>) -> Result<Backend> {
    Ok(Backend {
        id: row.get(0)?,
        address: row.get(1)?,
        name: row.get(2)?,
        group_name: row.get(3)?,
        weight: row.get(4)?,
        health_status: HealthStatus::from_str(&row.get::<_, String>(5)?)
            .map_err(|e| ConfigError::Validation(format!("invalid health_status: {e}")))?,
        health_check_enabled: row.get(6)?,
        health_check_interval_s: row.get(7)?,
        health_check_path: row.get(8)?,
        lifecycle_state: LifecycleState::from_str(&row.get::<_, String>(9)?)
            .map_err(|e| ConfigError::Validation(format!("invalid lifecycle_state: {e}")))?,
        active_connections: row.get(10)?,
        tls_upstream: row.get(11)?,
        created_at: parse_datetime(&row.get::<_, String>(12)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(13)?)?,
        h2_upstream: row.get(14)?,
        tls_sni: {
            let s: String = row.get(15)?;
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        },
        tls_skip_verify: row.get::<_, bool>(16).unwrap_or(false),
    })
}

pub(super) fn row_to_notification_config(row: &rusqlite::Row<'_>) -> Result<NotificationConfig> {
    let alert_json: String = row.get(4)?;
    let alert_types: Vec<String> = serde_json::from_str(&alert_json)
        .map_err(|e| ConfigError::Validation(format!("invalid alert_types JSON: {e}")))?;
    Ok(NotificationConfig {
        id: row.get(0)?,
        channel: NotificationChannel::from_str(&row.get::<_, String>(1)?)
            .map_err(|e| ConfigError::Validation(format!("invalid notification channel: {e}")))?,
        enabled: row.get(2)?,
        config: row.get(3)?,
        alert_types,
    })
}

pub(super) fn row_to_user_preference(row: &rusqlite::Row<'_>) -> Result<UserPreference> {
    Ok(UserPreference {
        id: row.get(0)?,
        preference_key: row.get(1)?,
        value: PreferenceValue::from_str(&row.get::<_, String>(2)?)
            .map_err(|e| ConfigError::Validation(format!("invalid preference value: {e}")))?,
        created_at: parse_datetime(&row.get::<_, String>(3)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(4)?)?,
    })
}

pub(super) fn row_to_admin_user(row: &rusqlite::Row<'_>) -> Result<AdminUser> {
    Ok(AdminUser {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        must_change_password: row.get(3)?,
        created_at: parse_datetime(&row.get::<_, String>(4)?)?,
        last_login: parse_optional_datetime(row.get(5)?)?,
    })
}

pub(super) fn row_to_load_test_config(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<LoadTestConfig>> {
    let headers_json: String = row.get(4)?;
    let headers: std::collections::HashMap<String, String> =
        match serde_json::from_str(&headers_json) {
            Ok(h) => h,
            Err(e) => {
                return Ok(Err(ConfigError::Validation(format!(
                    "invalid headers JSON: {e}"
                ))))
            }
        };
    Ok(Ok(LoadTestConfig {
        id: row.get(0)?,
        name: row.get(1)?,
        target_url: row.get(2)?,
        method: row.get(3)?,
        headers,
        body: row.get(5)?,
        concurrency: row.get(6)?,
        requests_per_second: row.get(7)?,
        duration_s: row.get(8)?,
        error_threshold_pct: row.get(9)?,
        schedule_cron: row.get(10)?,
        enabled: row.get(11)?,
        created_at: match parse_datetime(&row.get::<_, String>(12)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        updated_at: match parse_datetime(&row.get::<_, String>(13)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
    }))
}

pub(super) fn row_to_load_test_result(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<LoadTestResult>> {
    Ok(Ok(LoadTestResult {
        id: row.get(0)?,
        config_id: row.get(1)?,
        started_at: match parse_datetime(&row.get::<_, String>(2)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        finished_at: match parse_datetime(&row.get::<_, String>(3)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        total_requests: row.get(4)?,
        successful_requests: row.get(5)?,
        failed_requests: row.get(6)?,
        avg_latency_ms: row.get(7)?,
        p50_latency_ms: row.get(8)?,
        p95_latency_ms: row.get(9)?,
        p99_latency_ms: row.get(10)?,
        min_latency_ms: row.get(11)?,
        max_latency_ms: row.get(12)?,
        throughput_rps: row.get(13)?,
        aborted: row.get(14)?,
        abort_reason: row.get(15)?,
    }))
}

pub(super) fn row_to_probe_config(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<ProbeConfig>> {
    Ok(Ok(ProbeConfig {
        id: row.get(0)?,
        route_id: row.get(1)?,
        method: row.get(2)?,
        path: row.get(3)?,
        expected_status: row.get(4)?,
        interval_s: row.get(5)?,
        timeout_ms: row.get(6)?,
        enabled: row.get(7)?,
        created_at: match parse_datetime(&row.get::<_, String>(8)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        updated_at: match parse_datetime(&row.get::<_, String>(9)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
    }))
}

pub(super) fn row_to_sla_bucket(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<SlaBucket>> {
    Ok(Ok(SlaBucket {
        id: row.get(0)?,
        route_id: row.get(1)?,
        bucket_start: match parse_datetime(&row.get::<_, String>(2)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        request_count: row.get(3)?,
        success_count: row.get(4)?,
        error_count: row.get(5)?,
        latency_sum_ms: row.get(6)?,
        latency_min_ms: row.get(7)?,
        latency_max_ms: row.get(8)?,
        latency_p50_ms: row.get(9)?,
        latency_p95_ms: row.get(10)?,
        latency_p99_ms: row.get(11)?,
        source: row.get(12)?,
        cfg_max_latency_ms: row.get(13)?,
        cfg_status_min: row.get(14)?,
        cfg_status_max: row.get(15)?,
        cfg_target_pct: row.get(16)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_datetime_rfc3339_z() {
        let dt = parse_datetime("2026-04-17T19:13:17Z").expect("rfc3339 with Z");
        assert_eq!(dt.to_rfc3339(), "2026-04-17T19:13:17+00:00");
    }

    #[test]
    fn parse_datetime_rfc3339_offset() {
        let dt = parse_datetime("2026-04-17T21:13:17+02:00").expect("rfc3339 with offset");
        assert_eq!(dt.to_rfc3339(), "2026-04-17T19:13:17+00:00");
    }

    #[test]
    fn parse_datetime_sqlite_plain() {
        // SQLite's datetime('now') emits this exact shape. A historical
        // ACME renewal path wrote it to routes.updated_at and every
        // worker crash-looped on the next reload. The fallback here
        // keeps the load crash-safe if any row still carries the
        // legacy format.
        let dt = parse_datetime("2026-04-17 19:13:17").expect("sqlite plain");
        assert_eq!(dt.to_rfc3339(), "2026-04-17T19:13:17+00:00");
    }

    #[test]
    fn parse_datetime_sqlite_plain_fractional() {
        let dt = parse_datetime("2026-04-17 19:13:17.123").expect("sqlite plain + ms");
        assert_eq!(dt.to_rfc3339(), "2026-04-17T19:13:17.123+00:00");
    }

    #[test]
    fn parse_datetime_garbage_rejected() {
        let err = parse_datetime("not a datetime").expect_err("garbage should reject");
        let msg = format!("{err:?}");
        assert!(msg.contains("invalid datetime"), "{msg}");
    }

    #[test]
    fn parse_datetime_empty_rejected() {
        assert!(parse_datetime("").is_err());
    }

    #[test]
    fn parse_optional_datetime_none() {
        let got = parse_optional_datetime(None).expect("None ok");
        assert!(got.is_none());
    }

    #[test]
    fn parse_optional_datetime_some_sqlite_plain() {
        let got = parse_optional_datetime(Some("2026-04-17 19:13:17".to_string()))
            .expect("Some sqlite plain ok");
        assert!(got.is_some());
    }
}
