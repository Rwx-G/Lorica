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

//! The forwarding outbox: the numbered events a worker has yet to hand
//! to the supervisor.
//!
//! Kept apart from the recent-event ring for two reasons. The ring is
//! the dashboard's, sized for display, and a reader that must see every
//! event has to clone it under the ring's lock, which the request path
//! pushes through. The outbox is drained instead: a read moves the new
//! events out under its lock and clones nothing. And an event the outbox
//! has to drop is not forgotten whole: its source (client address and
//! category) is counted, so the supervisor still learns that the source
//! fired, which is what its alerts and its auto-ban decision need.

use std::collections::{HashMap, VecDeque};

use super::types::WafEvent;
use super::EventsAfter;
use crate::rules::RuleCategory;

/// Events the outbox holds between two reads before it drops the
/// oldest. Independent of the dashboard ring.
pub const FORWARD_OUTBOX_CAPACITY: usize = 4096;

/// Distinct sources whose dropped events are counted between two reads.
/// A drop from a source past this many is counted only in
/// [`EventsAfter::lost`].
pub const LOST_SOURCES_CAPACITY: usize = 1024;

/// Events of one source the outbox dropped before they were read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LostEvents {
    /// The client address the events came from.
    pub client_ip: String,
    /// Their category.
    pub category: RuleCategory,
    /// How many were dropped.
    pub count: u64,
}

/// What [`ForwardOutbox::take_after`] moved out, before conversion.
pub(super) struct Taken {
    events: VecDeque<WafEvent>,
    lost_sources: HashMap<(String, RuleCategory), u64>,
    next: u64,
    lost: u64,
}

impl From<Taken> for EventsAfter {
    fn from(taken: Taken) -> Self {
        EventsAfter {
            events: taken.events.into(),
            next: taken.next,
            lost: taken.lost,
            lost_by_source: taken
                .lost_sources
                .into_iter()
                .map(|((client_ip, category), count)| LostEvents {
                    client_ip,
                    category,
                    count,
                })
                .collect(),
        }
    }
}

#[derive(Debug)]
pub(super) struct ForwardOutbox {
    events: VecDeque<WafEvent>,
    capacity: usize,
    /// Events ever pushed, which makes it the sequence number of the
    /// newest one.
    recorded: u64,
    /// `recorded` at the last [`Self::clear`]: the events up to it were
    /// forgotten on purpose, not dropped.
    cleared_through: u64,
    lost_sources: HashMap<(String, RuleCategory), u64>,
    lost_sources_capacity: usize,
}

impl ForwardOutbox {
    pub(super) fn new(capacity: usize, lost_sources_capacity: usize) -> Self {
        Self {
            events: VecDeque::new(),
            capacity,
            recorded: 0,
            cleared_through: 0,
            lost_sources: HashMap::new(),
            lost_sources_capacity,
        }
    }

    /// Append `events`, already cloned by the caller, dropping the
    /// oldest past capacity and counting each drop against its source.
    pub(super) fn push(&mut self, events: Vec<WafEvent>) {
        self.recorded += events.len() as u64;
        for event in events {
            if self.events.len() >= self.capacity {
                if let Some(dropped) = self.events.pop_front() {
                    self.count_lost(dropped);
                }
            }
            self.events.push_back(event);
        }
    }

    fn count_lost(&mut self, dropped: WafEvent) {
        let key = (dropped.client_ip, dropped.category);
        if let Some(count) = self.lost_sources.get_mut(&key) {
            *count += 1;
        } else if self.lost_sources.len() < self.lost_sources_capacity {
            self.lost_sources.insert(key, 1);
        }
    }

    /// See [`super::WafEngine::events_after`]. Moves the events out, so
    /// the outbox has one reader; the caller turns the result into an
    /// [`EventsAfter`] once it has released the lock.
    pub(super) fn take_after(&mut self, cursor: u64) -> Taken {
        let oldest_held = self.recorded - self.events.len() as u64;
        let from = cursor.max(self.cleared_through).min(self.recorded);
        let first_new = from.max(oldest_held);
        // Events at or before the cursor were read already.
        self.events.drain(..(first_new - oldest_held) as usize);
        Taken {
            events: std::mem::take(&mut self.events),
            lost_sources: std::mem::take(&mut self.lost_sources),
            next: self.recorded,
            lost: oldest_held.saturating_sub(from),
        }
    }

    pub(super) fn clear(&mut self) {
        self.events.clear();
        self.lost_sources.clear();
        self.cleared_through = self.recorded;
    }
}
