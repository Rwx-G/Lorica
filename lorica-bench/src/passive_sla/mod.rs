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

//! Passive SLA collection: per-request metrics aggregated into minute
//! buckets, flushed to SQLite, and evaluated for threshold breaches.
//!
//! Submodules:
//! - [`helpers`]: percentile math and bucket-boundary utilities.
//! - [`bucket`]: the in-memory `RouteBucket` aggregator (internal).
//! - [`collector`]: the public `SlaCollector` struct and its hot-path API.
//! - [`persistence`]: DB flushing and threshold alert dispatch.

mod bucket;
mod collector;
mod helpers;
mod persistence;

#[cfg(test)]
mod tests;

pub use collector::SlaCollector;
pub use helpers::compute_percentiles;
