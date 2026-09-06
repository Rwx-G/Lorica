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

//! Pre-authentication budgets (Story 9.2 AC #3) shared by both cluster
//! listeners, and the per-source gate that keeps one address from
//! monopolising them.
//!
//! # The permit rule
//!
//! A handshake permit is taken BEFORE a connection gets a task and is
//! held until the connection either dies or enters the NEXT bounded
//! pool: the enrollment-exchange permit on the enrollment listener,
//! the session slot on the operational one. It is never released into
//! an unbounded phase (a peer that completed TLS and then stalls still
//! holds a permit), and it is never held past the point where a
//! smaller pool takes over (which would turn the handshake cap into a
//! total-connection cap). Both listeners follow the same rule, so the
//! `rejected_concurrent_handshakes` counters mean the same thing on
//! both.
//!
//! # Why a per-source gate
//!
//! A global pool alone inverts into a remote lockout: a handful of
//! silent TCP connections re-opened every handshake timeout keep every
//! permit busy and every legitimate follower is dropped at accept, for
//! the price of a few sockets and no cryptography. The [`SourceGate`]
//! bounds what one address may hold at once - an IPv4 address, or an
//! IPv6 /64 (one customer's routing allocation, the smallest unit an
//! attacker rotates inside for free) - so exhausting the pool takes as
//! many distinct prefixes as `max_concurrent_handshakes /
//! max_per_source`. The gate's map only ever holds addresses with a
//! live connection, so it is bounded by the global pool and needs no
//! eviction.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Pre-authentication budgets (AC #3), enforced BEFORE any token or
/// message logic. The enrollment listener applies all of them; the
/// operational listener applies the handshake, concurrency and
/// per-source bounds to its pre-session phase (the other two are
/// enrollment-frame concerns).
#[derive(Debug, Clone)]
pub struct PreAuthBudgets {
    /// Max time for the TLS handshake to complete. TLS 1.3 is one
    /// round trip; a peer that needs longer is stalling.
    pub handshake_timeout: Duration,
    /// Max pre-session connections at once (see the permit rule in
    /// the module doc); excess connections are dropped immediately,
    /// before a task exists for them. Sized so that a handful of
    /// sockets cannot exhaust it.
    pub max_concurrent_handshakes: usize,
    /// Max pre-session connections ONE source (IPv4 address or IPv6
    /// /64) may hold at once; excess connections from that source are
    /// dropped before a task exists.
    pub max_per_source: usize,
    /// Max enrollment exchanges in flight at once (post-TLS), distinct
    /// from the handshake bound so slow token verifications (Story
    /// 9.3) cannot be used to starve the TLS accept path. This is also
    /// Story 9.3 AC #1's global cap on concurrent verifications.
    pub max_inflight_enrollments: usize,
    /// Max bytes a connection may send in its enrollment frame.
    pub per_conn_max_bytes: u64,
    /// Max total lifetime of one enrollment connection.
    pub per_conn_max_duration: Duration,
}

impl Default for PreAuthBudgets {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(3),
            max_concurrent_handshakes: 256,
            max_per_source: 8,
            max_inflight_enrollments: 8,
            per_conn_max_bytes: 16 * 1024,
            per_conn_max_duration: Duration::from_secs(15),
        }
    }
}

/// The unit the per-source gate counts: an IPv4 address, or the /64
/// prefix of an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// One IPv4 address (IPv4-mapped IPv6 addresses collapse here).
    V4(Ipv4Addr),
    /// The upper 64 bits of an IPv6 address.
    V6Prefix([u8; 8]),
}

/// Map a peer address to the key the gate counts it under.
pub fn source_key(ip: IpAddr) -> SourceKey {
    match ip {
        IpAddr::V4(v4) => SourceKey::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SourceKey::V4(v4),
            None => {
                let octets = v6.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&octets[..8]);
                SourceKey::V6Prefix(prefix)
            }
        },
    }
}

/// Per-source concurrency bound for pre-session connections.
pub struct SourceGate {
    max_per_source: usize,
    live: Mutex<HashMap<SourceKey, usize>>,
}

impl SourceGate {
    /// A gate allowing `max_per_source` concurrent connections per
    /// [`SourceKey`].
    pub fn new(max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_source,
            live: Mutex::new(HashMap::new()),
        })
    }

    /// Take a slot for `peer`, or `None` when that source already
    /// holds `max_per_source` connections. The slot is released when
    /// the returned guard drops.
    pub fn try_enter(self: &Arc<Self>, peer: IpAddr) -> Option<SourceSlot> {
        let key = source_key(peer);
        let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
        let count = live.get(&key).copied().unwrap_or(0);
        if count >= self.max_per_source {
            return None;
        }
        live.insert(key, count + 1);
        Some(SourceSlot {
            gate: Arc::clone(self),
            key,
        })
    }

    /// Sources currently holding at least one slot (the map's size;
    /// bounded by the global handshake pool).
    pub fn live_sources(&self) -> usize {
        self.live.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// RAII slot in a [`SourceGate`]; dropping it releases the source's
/// count and removes the entry at zero.
pub struct SourceSlot {
    gate: Arc<SourceGate>,
    key: SourceKey,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut live = self.gate.live.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = live.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.remove(&self.key);
            }
        }
    }
}

/// Pause after a failed `accept()` so a persistent condition (EMFILE,
/// ENFILE, ENOBUFS) is a logged, throttled retry rather than a hot
/// spin pinning a core with nothing in the journal.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// Log a failed `accept()` (loud on the first and every hundredth
/// occurrence, quiet in between) and pause before the next attempt.
pub(crate) async fn accept_error_pause(listener: &'static str, error: &std::io::Error, count: u64) {
    if count == 1 || count.is_multiple_of(100) {
        tracing::warn!(
            listener,
            error = %error,
            count,
            "cluster accept() failed; pausing before the next accept (descriptor exhaustion?)"
        );
    } else {
        tracing::debug!(listener, error = %error, "cluster accept() failed");
    }
    tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv6_sources_are_keyed_by_their_slash_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("v6");
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("v6");
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("v6");
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(c));
    }

    #[test]
    fn ipv4_mapped_addresses_collapse_onto_the_ipv4_key() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
        let plain: IpAddr = "192.0.2.10".parse().expect("v4");
        assert_eq!(source_key(mapped), source_key(plain));
        assert_eq!(source_key(plain), SourceKey::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn gate_bounds_one_source_and_releases_on_drop() {
        let gate = SourceGate::new(2);
        let peer: IpAddr = "192.0.2.10".parse().expect("v4");
        let other: IpAddr = "192.0.2.11".parse().expect("v4");
        let first = gate.try_enter(peer).expect("first slot");
        let second = gate.try_enter(peer).expect("second slot");
        assert!(gate.try_enter(peer).is_none(), "third must be refused");
        // Another source is unaffected.
        let elsewhere = gate.try_enter(other).expect("other source");
        assert_eq!(gate.live_sources(), 2);
        drop(first);
        assert!(gate.try_enter(peer).is_some(), "released slot is reusable");
        drop(second);
        drop(elsewhere);
    }

    #[test]
    fn entries_disappear_at_zero_so_the_map_stays_bounded() {
        let gate = SourceGate::new(1);
        let peer: IpAddr = "2001:db8::1".parse().expect("v6");
        let slot = gate.try_enter(peer).expect("slot");
        assert_eq!(gate.live_sources(), 1);
        drop(slot);
        assert_eq!(gate.live_sources(), 0);
        // A zero cap refuses everyone and inserts nothing.
        let closed = SourceGate::new(0);
        assert!(closed.try_enter(peer).is_none());
        assert_eq!(closed.live_sources(), 0);
    }
}
