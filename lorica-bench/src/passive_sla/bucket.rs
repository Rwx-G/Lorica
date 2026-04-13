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

//! Per-route in-memory time bucket aggregating metrics for a single minute.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use lorica_config::models::SlaBucket;

use super::helpers::compute_percentiles;

/// A single in-memory time bucket collecting metrics for one route.
pub(super) struct RouteBucket {
    pub(super) bucket_start: DateTime<Utc>,
    pub(super) request_count: AtomicI64,
    pub(super) success_count: AtomicI64,
    pub(super) error_count: AtomicI64,
    pub(super) latency_sum_ms: AtomicI64,
    pub(super) latency_min_ms: AtomicI64,
    pub(super) latency_max_ms: AtomicI64,
    pub(super) latency_samples: Mutex<Vec<u64>>,
}

impl RouteBucket {
    pub(super) fn new(bucket_start: DateTime<Utc>) -> Self {
        Self {
            bucket_start,
            request_count: AtomicI64::new(0),
            success_count: AtomicI64::new(0),
            error_count: AtomicI64::new(0),
            latency_sum_ms: AtomicI64::new(0),
            latency_min_ms: AtomicI64::new(i64::MAX),
            latency_max_ms: AtomicI64::new(0),
            latency_samples: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn record(&self, latency_ms: u64, is_success: bool) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if is_success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_ms
            .fetch_add(latency_ms as i64, Ordering::Relaxed);

        // Update min (atomic CAS loop)
        let mut current = self.latency_min_ms.load(Ordering::Relaxed);
        let new_val = latency_ms as i64;
        while new_val < current {
            match self.latency_min_ms.compare_exchange_weak(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // Update max
        let mut current = self.latency_max_ms.load(Ordering::Relaxed);
        while new_val > current {
            match self.latency_max_ms.compare_exchange_weak(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        if let Ok(mut samples) = self.latency_samples.lock() {
            samples.push(latency_ms);
        }
    }

    pub(super) fn to_sla_bucket(&self) -> SlaBucket {
        let request_count = self.request_count.load(Ordering::Relaxed);
        let min_ms = self.latency_min_ms.load(Ordering::Relaxed);
        let max_ms = self.latency_max_ms.load(Ordering::Relaxed);

        let (p50, p95, p99) = if let Ok(mut samples) = self.latency_samples.lock() {
            compute_percentiles(&mut samples)
        } else {
            (0, 0, 0)
        };

        SlaBucket {
            id: None,
            route_id: String::new(), // Set by caller
            bucket_start: self.bucket_start,
            request_count,
            success_count: self.success_count.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            latency_sum_ms: self.latency_sum_ms.load(Ordering::Relaxed),
            latency_min_ms: if request_count > 0 { min_ms } else { 0 },
            latency_max_ms: max_ms,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            source: "passive".to_string(),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        }
    }
}
