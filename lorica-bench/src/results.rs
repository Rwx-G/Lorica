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

use chrono::{Duration, Utc};
use lorica_config::models::{SlaSummary, StreamSlaSummary};
use lorica_config::ConfigStore;

/// Standard SLA time windows.
pub enum SlaWindow {
    OneHour,
    TwentyFourHours,
    SevenDays,
    ThirtyDays,
}

impl SlaWindow {
    /// Every standard window, shortest first: the order the SLA reads
    /// answer their summaries in.
    pub const ALL: [SlaWindow; 4] = [
        SlaWindow::OneHour,
        SlaWindow::TwentyFourHours,
        SlaWindow::SevenDays,
        SlaWindow::ThirtyDays,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::TwentyFourHours => "24h",
            Self::SevenDays => "7d",
            Self::ThirtyDays => "30d",
        }
    }

    pub fn duration(&self) -> Duration {
        match self {
            Self::OneHour => Duration::hours(1),
            Self::TwentyFourHours => Duration::hours(24),
            Self::SevenDays => Duration::days(7),
            Self::ThirtyDays => Duration::days(30),
        }
    }
}

/// Compute SLA summaries for all standard windows for a given route.
pub fn compute_all_windows(
    store: &ConfigStore,
    route_id: &str,
    source: &str,
) -> lorica_config::Result<Vec<SlaSummary>> {
    let now = Utc::now();
    let mut summaries = Vec::with_capacity(SlaWindow::ALL.len());
    for window in &SlaWindow::ALL {
        let from = now - window.duration();
        let summary = store.compute_sla_summary(route_id, &from, &now, window.label(), source)?;
        summaries.push(summary);
    }
    Ok(summaries)
}

/// Compute SLA summaries for all standard windows for a given stream
/// (Story 12.9), in the order [`compute_all_windows`] answers a route's.
pub fn compute_all_stream_windows(
    store: &ConfigStore,
    stream_id: &str,
    source: &str,
) -> lorica_config::Result<Vec<StreamSlaSummary>> {
    let now = Utc::now();
    let mut summaries = Vec::with_capacity(SlaWindow::ALL.len());
    for window in &SlaWindow::ALL {
        let from = now - window.duration();
        let summary =
            store.compute_stream_sla_summary(stream_id, &from, &now, window.label(), source)?;
        summaries.push(summary);
    }
    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_window_labels() {
        assert_eq!(SlaWindow::OneHour.label(), "1h");
        assert_eq!(SlaWindow::TwentyFourHours.label(), "24h");
        assert_eq!(SlaWindow::SevenDays.label(), "7d");
        assert_eq!(SlaWindow::ThirtyDays.label(), "30d");
    }

    #[test]
    fn test_sla_window_durations() {
        assert_eq!(SlaWindow::OneHour.duration(), Duration::hours(1));
        assert_eq!(SlaWindow::ThirtyDays.duration(), Duration::days(30));
    }

    #[test]
    fn test_compute_all_windows_no_data() {
        let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");
        let summaries = compute_all_windows(&store, "nonexistent", "passive")
            .expect("test setup: compute all windows");
        assert_eq!(summaries.len(), 4);
        for s in &summaries {
            assert_eq!(s.total_requests, 0);
        }
    }

    #[test]
    fn a_stream_answers_every_standard_window_in_the_route_order() {
        let store = ConfigStore::open_in_memory().expect("test setup: open in-memory store");
        let summaries = compute_all_stream_windows(&store, "nonexistent", "passive")
            .expect("test setup: compute all stream windows");
        let labels: Vec<&str> = summaries.iter().map(|s| s.window.as_str()).collect();
        let expected: Vec<&str> = SlaWindow::ALL.iter().map(SlaWindow::label).collect();
        assert_eq!(labels, expected);
        for s in &summaries {
            assert_eq!(s.judged_count, 0);
            assert_eq!(s.avg_connect_latency_ms, None);
        }
    }
}
