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

//! Small helpers shared across the passive SLA submodules.

use chrono::{DateTime, Timelike, Utc};

/// Compute p50, p95, p99 from a mutable sample vec (sorts in place).
pub fn compute_percentiles(samples: &mut [u64]) -> (i64, i64, i64) {
    if samples.is_empty() {
        return (0, 0, 0);
    }
    samples.sort_unstable();
    let len = samples.len();
    let p50 = samples[len * 50 / 100] as i64;
    let p95 = samples[len * 95 / 100] as i64;
    let p99 = samples[std::cmp::min(len * 99 / 100, len - 1)] as i64;
    (p50, p95, p99)
}

/// Current minute bucket start (truncated to minute boundary).
pub(crate) fn current_bucket_start() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_nanosecond(0)
        .expect("0 is a valid nanosecond value")
        .with_second(0)
        .expect("0 is a valid second value")
}
