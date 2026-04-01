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

use std::sync::Arc;

use chrono::{Datelike, Timelike, Utc};
use lorica_config::ConfigStore;
use tokio::sync::Mutex as TokioMutex;
use tracing::{error, info, warn};

use crate::load_test::LoadTestEngine;

/// Simple cron expression matcher.
/// Supports 5-field format: `min hour dom month dow`
/// Each field can be `*` (any) or a single number.
/// Examples: `0 3 * * *` (daily at 03:00), `30 * * * *` (every hour at :30)
pub fn cron_matches_now(expr: &str) -> bool {
    let now = Utc::now();
    cron_matches(
        expr,
        now.minute(),
        now.hour(),
        now.day(),
        now.month(),
        now.weekday().num_days_from_sunday(),
    )
}

fn cron_matches(expr: &str, minute: u32, hour: u32, dom: u32, month: u32, dow: u32) -> bool {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }

    field_matches(fields[0], minute)
        && field_matches(fields[1], hour)
        && field_matches(fields[2], dom)
        && field_matches(fields[3], month)
        && field_matches(fields[4], dow)
}

fn field_matches(field: &str, value: u32) -> bool {
    if field == "*" {
        return true;
    }
    // Support comma-separated values: "0,15,30,45"
    for part in field.split(',') {
        // Support range: "1-5"
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                if value >= s && value <= e {
                    return true;
                }
            }
        } else if let Ok(n) = part.parse::<u32>() {
            if n == value {
                return true;
            }
        }
    }
    false
}

/// Start the load test scheduler background task.
/// Checks every 60 seconds if any scheduled tests need to run.
pub fn start_scheduler(
    store: Arc<TokioMutex<ConfigStore>>,
    engine: Arc<LoadTestEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;

            let configs = {
                let s = store.lock().await;
                match s.list_load_test_configs() {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %e, "scheduler: failed to list load test configs");
                        continue;
                    }
                }
            };

            for config in configs {
                if !config.enabled {
                    continue;
                }
                let cron_expr = match &config.schedule_cron {
                    Some(c) if !c.is_empty() => c.clone(),
                    _ => continue,
                };

                if !cron_matches_now(&cron_expr) {
                    continue;
                }

                // Don't start if a test is already running
                if engine.is_running().await {
                    warn!(
                        config_id = %config.id,
                        "scheduler: skipping scheduled test, another test is running"
                    );
                    continue;
                }

                info!(
                    config_id = %config.id,
                    name = %config.name,
                    cron = %cron_expr,
                    "scheduler: starting scheduled load test"
                );

                let engine = Arc::clone(&engine);
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    engine.run(&config, &store).await;
                });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_matches_wildcard() {
        assert!(field_matches("*", 0));
        assert!(field_matches("*", 59));
    }

    #[test]
    fn test_field_matches_exact() {
        assert!(field_matches("30", 30));
        assert!(!field_matches("30", 15));
    }

    #[test]
    fn test_field_matches_comma_list() {
        assert!(field_matches("0,15,30,45", 15));
        assert!(field_matches("0,15,30,45", 45));
        assert!(!field_matches("0,15,30,45", 10));
    }

    #[test]
    fn test_field_matches_range() {
        assert!(field_matches("1-5", 1));
        assert!(field_matches("1-5", 3));
        assert!(field_matches("1-5", 5));
        assert!(!field_matches("1-5", 0));
        assert!(!field_matches("1-5", 6));
    }

    #[test]
    fn test_cron_matches_daily_3am() {
        // "0 3 * * *" = daily at 03:00
        assert!(cron_matches("0 3 * * *", 0, 3, 15, 6, 1));
        assert!(!cron_matches("0 3 * * *", 0, 4, 15, 6, 1));
        assert!(!cron_matches("0 3 * * *", 30, 3, 15, 6, 1));
    }

    #[test]
    fn test_cron_matches_every_hour_at_30() {
        // "30 * * * *" = every hour at :30
        assert!(cron_matches("30 * * * *", 30, 0, 1, 1, 0));
        assert!(cron_matches("30 * * * *", 30, 23, 28, 12, 6));
        assert!(!cron_matches("30 * * * *", 0, 0, 1, 1, 0));
    }

    #[test]
    fn test_cron_matches_weekday_only() {
        // "0 9 * * 1-5" = weekdays at 09:00
        assert!(cron_matches("0 9 * * 1-5", 0, 9, 15, 6, 1)); // Monday
        assert!(cron_matches("0 9 * * 1-5", 0, 9, 15, 6, 5)); // Friday
        assert!(!cron_matches("0 9 * * 1-5", 0, 9, 15, 6, 0)); // Sunday
        assert!(!cron_matches("0 9 * * 1-5", 0, 9, 15, 6, 6)); // Saturday
    }

    #[test]
    fn test_cron_invalid_format() {
        assert!(!cron_matches_now("invalid"));
        assert!(!cron_matches_now("* *"));
        assert!(!cron_matches_now(""));
    }

    #[test]
    fn test_cron_mixed_range_and_list() {
        // "0,30 9-17 * * 1-5" = on the hour and half-hour, 9am-5pm, weekdays
        assert!(cron_matches("0,30 9-17 * * 1-5", 0, 9, 1, 1, 1));
        assert!(cron_matches("0,30 9-17 * * 1-5", 30, 12, 15, 6, 3));
        assert!(cron_matches("0,30 9-17 * * 1-5", 0, 17, 1, 1, 5));
        assert!(!cron_matches("0,30 9-17 * * 1-5", 15, 12, 1, 1, 3)); // minute 15 not matched
        assert!(!cron_matches("0,30 9-17 * * 1-5", 0, 18, 1, 1, 3)); // hour 18 out of range
        assert!(!cron_matches("0,30 9-17 * * 1-5", 0, 12, 1, 1, 0)); // Sunday
    }

    #[test]
    fn test_field_matches_invalid_range() {
        // Non-numeric range bounds should not match
        assert!(!field_matches("a-z", 5));
        assert!(!field_matches("1-abc", 2));
    }

    #[test]
    fn test_field_matches_single_item_comma() {
        // A single value in comma format
        assert!(field_matches("5", 5));
        assert!(!field_matches("5", 6));
    }

    #[test]
    fn test_cron_specific_dom_and_month() {
        // "0 0 25 12 *" = midnight on Dec 25
        assert!(cron_matches("0 0 25 12 *", 0, 0, 25, 12, 3));
        assert!(!cron_matches("0 0 25 12 *", 0, 0, 24, 12, 2));
        assert!(!cron_matches("0 0 25 12 *", 0, 0, 25, 11, 3));
    }

    #[test]
    fn test_cron_too_many_fields_fails() {
        assert!(!cron_matches("* * * * * *", 0, 0, 1, 1, 0)); // 6 fields
    }

    #[test]
    fn test_cron_all_stars() {
        // "* * * * *" = every minute
        assert!(cron_matches("* * * * *", 0, 0, 1, 1, 0));
        assert!(cron_matches("* * * * *", 59, 23, 31, 12, 6));
    }
}
