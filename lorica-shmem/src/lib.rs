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

//! Cross-worker shared-memory primitives for Lorica.
//!
//! This crate implements component (B) of the worker shared-state design
//! (see `docs/architecture/worker-shared-state.md` § 5): an anonymous
//! memfd region shared between the supervisor and all worker processes,
//! containing two fixed-layout atomic hashtables used by WPAR-1 for
//! per-IP WAF flood and auto-ban counters.
//!
//! The entry point is [`SharedRegion`]:
//!
//! - [`SharedRegion::create_supervisor`] on the supervisor at startup
//!   allocates the memfd, initialises the header (magic, version,
//!   random siphash key), and returns a mapped `&'static SharedRegion`
//!   plus the `OwnedFd` of the memfd. The supervisor passes the fd to
//!   each worker at fork via the existing SCM_RIGHTS machinery in
//!   `lorica/src/main.rs`.
//! - [`SharedRegion::open_worker`] on each worker adopts the passed fd,
//!   mmaps the region, verifies the magic/version header, and returns
//!   the same `&'static SharedRegion` reference. The hash key is read
//!   out of the region (written by the supervisor) so all processes
//!   probe the same chain for the same key.
//!
//! The tables use open addressing with linear probing; each slot is a
//! 64-byte cache line with three independent atomics (key, value,
//! last_update_ns). There is no seqlock: readers perform a single
//! `AtomicU64::load` on `value` and observe some past committed value,
//! never a torn read. Writers race on the commutative `fetch_add` for
//! existing keys and on a CAS for new-key claims. See design doc § 5.2,
//! § 5.3, § 8.
//!
//! Linux-only: the crate relies on `memfd_create`, `mmap(MAP_SHARED)`,
//! and SCM_RIGHTS. This matches the rest of the Lorica codebase.

#![warn(clippy::all)]
#![cfg(target_os = "linux")]

pub mod eviction;
pub mod hash;
pub mod region;
pub mod table;

pub use eviction::{evict_once, EvictionStats, DEFAULT_SCAN_INTERVAL, DEFAULT_STALE_AFTER};
pub use hash::{random_key, siphash13_u64};
pub use region::{SharedRegion, SharedRegionError, LAYOUT_VERSION, MAGIC, REGION_SIZE, WAF_SLOTS};
pub use table::{now_ns, tagged_hash, AtomicHashTable, Slot, MAX_PROBE, SATURATED};
