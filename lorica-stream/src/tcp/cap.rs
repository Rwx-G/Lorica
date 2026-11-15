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

//! The per-stream connection cap and what it declares to the fd budget
//! (Story 12.3 D-p).
//!
//! `max_connections` is enforced per worker process until Story 12.6
//! moves it onto the shared stream-caps tables, where the same field
//! becomes the per-node cap (Resolved 1). Until then a node with `W`
//! workers holds up to `W x max_connections` connections of one stream,
//! each process within its own fd budget.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lorica_config::models::{Stream, StreamProtocol};

use crate::budget::HeldFds;
use crate::table::StreamTable;

/// Fds one TCP stream connection holds: the client socket and one
/// backend socket (the connect phase holds at most one at a time).
pub const TCP_FDS_PER_CONNECTION: u64 = 2;

/// What a TCP stream may hold at its cap, for the fd budget: the one
/// definition, read through [`crate::StreamDemand::of`], which both the
/// driver's demand and the API's budget check build on, so they cannot
/// disagree. `None` for a UDP stream (Story 12.5 declares its own).
pub fn held_fds(stream: &Stream) -> Option<HeldFds> {
    match stream.protocol {
        StreamProtocol::Tcp => Some(HeldFds {
            ceiling: u64::from(stream.max_connections),
            fds_per_unit: TCP_FDS_PER_CONNECTION,
        }),
        StreamProtocol::Udp => None,
    }
}

/// The open connections of each stream in this process.
#[derive(Debug, Default)]
pub struct ConnectionCaps(Mutex<HashMap<String, Arc<AtomicU32>>>);

/// One connection's place under its stream's cap, released on drop.
#[derive(Debug)]
pub struct CapSlot(Arc<AtomicU32>);

impl Drop for CapSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ConnectionCaps {
    /// A slot for one more connection of `stream_id`, or `None` when it
    /// already holds `max` of them.
    pub fn try_acquire(&self, stream_id: &str, max: u32) -> Option<CapSlot> {
        let open = Arc::clone(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(stream_id.to_string())
                .or_default(),
        );
        // Take the slot, then give it back if it was over the cap: a
        // racing acquirer may be refused by the overshoot, never admitted
        // past the cap.
        if open.fetch_add(1, Ordering::AcqRel) < max {
            Some(CapSlot(open))
        } else {
            open.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }

    /// Forget the streams `table` no longer holds. Their live slots keep
    /// their own count and release it into nothing.
    pub fn retain(&self, table: &StreamTable) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn the_cap_refuses_the_next_and_frees_on_drop() {
        let caps = ConnectionCaps::default();
        let held: Vec<CapSlot> = (0..3).map(|_| caps.try_acquire("s", 3).unwrap()).collect();
        assert!(caps.try_acquire("s", 3).is_none());
        assert!(caps.try_acquire("other", 3).is_some());
        drop(held);
        assert!(caps.try_acquire("s", 3).is_some());
    }

    #[test]
    fn a_tcp_stream_holds_two_fds_per_connection() {
        let mut tcp = Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().unwrap(),
            5432,
            5432,
            Utc::now(),
        );
        tcp.max_connections = 100;
        assert_eq!(
            held_fds(&tcp),
            Some(HeldFds {
                ceiling: 100,
                fds_per_unit: 2
            })
        );
        let udp = Stream::new(
            "u".into(),
            "u".into(),
            StreamProtocol::Udp,
            "0.0.0.0".parse().unwrap(),
            53,
            53,
            Utc::now(),
        );
        assert_eq!(held_fds(&udp), None);
    }
}
