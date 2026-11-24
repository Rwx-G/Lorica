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

//! The connect-time local check (Story 12.3 D-m), protocol-neutral so
//! the UDP engine runs the same one at session creation (Story 12.5
//! Interface edit E2).
//!
//! A destination is local when [`is_local_ip`] says so (loopback,
//! unspecified, link-local, in either family and the IPv4-mapped form)
//! or when it is an address of one of this node's interfaces. A local
//! destination is refused when its port is one of the node's reserved
//! ports or a listen port this process binds for any stream (rule B,
//! flag or not), and otherwise unless the stream sets
//! `allow_local_backend` (rule A). A cloud instance metadata address
//! ([`is_instance_metadata_ip`]) is not this node, so rule B leaves it
//! alone, but rule A refuses it as it refuses a local destination.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use lorica_config::listen_ports::ReservedPorts;
use lorica_config::local_address::{is_instance_metadata_ip, is_local_ip};

/// The listen ports of every binding attached in this process, TCP and
/// UDP alike. The runtime keeps it current on attach and detach; an
/// engine reads it at connect. Cloning shares it.
#[derive(Debug, Clone, Default)]
pub struct BoundPorts(Arc<RwLock<HashMap<u16, usize>>>);

impl BoundPorts {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a binding of this process listens on `port`.
    pub fn contains(&self, port: u16) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&port)
    }

    /// Count one more socket listening on `port`.
    pub fn add(&self, port: u16) {
        *self
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(port)
            .or_default() += 1;
    }

    /// Count one socket on `port` fewer.
    pub fn remove(&self, port: u16) {
        let mut ports = self.0.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                ports.remove(&port);
            }
        }
    }
}

/// Why a local destination is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRefusal {
    /// Rule A: a local or cloud instance metadata destination on a
    /// stream without `allow_local_backend`.
    NeedsFlag,
    /// Rule B: a local destination on a reserved port of the node or a
    /// listen port this process binds, refused whatever the flag. This
    /// is also the forwarding-loop guard.
    NodePort,
}

impl LocalRefusal {
    /// The snake_case word a log line uses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NeedsFlag => "local_needs_flag",
            Self::NodePort => "local_node_port",
        }
    }
}

/// What the check knows of the node it runs on.
#[derive(Debug, Clone, Copy)]
pub struct NodeLocality<'a> {
    /// The addresses of this node's interfaces, canonical.
    pub interfaces: &'a HashSet<IpAddr>,
    /// The node's reserved ports, when the process knows them.
    pub reserved: Option<&'a ReservedPorts>,
    /// The listen ports this process binds.
    pub bound: &'a BoundPorts,
}

impl NodeLocality<'_> {
    /// Whether `ip` reaches this node.
    pub fn is_local(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        is_local_ip(ip) || self.interfaces.contains(&ip)
    }

    /// Check `destination` for a stream whose `allow_local_backend` is
    /// `allow_local`: `Ok` when it may be connected.
    ///
    /// # Errors
    ///
    /// The rule that refuses it.
    pub fn check(&self, destination: SocketAddr, allow_local: bool) -> Result<(), LocalRefusal> {
        if self.is_local(destination.ip()) {
            let port = destination.port();
            if self.reserved.is_some_and(|r| r.clash(port).is_some()) || self.bound.contains(port) {
                return Err(LocalRefusal::NodePort);
            }
        } else if !is_instance_metadata_ip(destination.ip()) {
            return Ok(());
        }
        if allow_local {
            Ok(())
        } else {
            Err(LocalRefusal::NeedsFlag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserved() -> ReservedPorts {
        ReservedPorts {
            management: 9443,
            http: 8080,
            https: 8443,
            cluster: None,
            enrollment: None,
            automation: Some(9444),
        }
    }

    fn sa(text: &str) -> SocketAddr {
        text.parse().expect("test setup: address")
    }

    #[test]
    fn both_rules_with_and_without_the_flag() {
        let interfaces: HashSet<IpAddr> = ["10.0.0.5".parse().unwrap()].into();
        let bound = BoundPorts::new();
        bound.add(5432);
        let reserved = reserved();
        let node = NodeLocality {
            interfaces: &interfaces,
            reserved: Some(&reserved),
            bound: &bound,
        };
        for local in [
            "127.0.0.1",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "10.0.0.5",
            "0.0.0.0",
        ] {
            assert_eq!(
                node.check(sa(&format!("{local}:9443")), true),
                Err(LocalRefusal::NodePort),
                "{local} on the management port"
            );
            assert_eq!(
                node.check(sa(&format!("{local}:5432")), true),
                Err(LocalRefusal::NodePort),
                "{local} on a bound stream port"
            );
            assert_eq!(
                node.check(sa(&format!("{local}:6000")), false),
                Err(LocalRefusal::NeedsFlag),
                "{local} without the flag"
            );
            assert_eq!(node.check(sa(&format!("{local}:6000")), true), Ok(()));
        }
        assert_eq!(node.check(sa("192.0.2.10:9443"), false), Ok(()));
        bound.remove(5432);
        assert_eq!(node.check(sa("127.0.0.1:5432"), true), Ok(()));
    }

    #[test]
    fn an_instance_metadata_address_needs_the_flag_and_is_no_node_port() {
        let interfaces: HashSet<IpAddr> = HashSet::new();
        let bound = BoundPorts::new();
        bound.add(80);
        let reserved = reserved();
        let node = NodeLocality {
            interfaces: &interfaces,
            reserved: Some(&reserved),
            bound: &bound,
        };
        for &(ip, service) in lorica_config::local_address::INSTANCE_METADATA_ADDRESSES {
            for port in [80, 9443] {
                let destination = SocketAddr::new(ip, port);
                assert_eq!(
                    node.check(destination, false),
                    Err(LocalRefusal::NeedsFlag),
                    "{service} on {port} without the flag"
                );
                assert_eq!(
                    node.check(destination, true),
                    Ok(()),
                    "{service} on {port} with the flag: not this node's port"
                );
            }
        }
        assert_eq!(
            node.check(sa("[::ffff:100.100.100.200]:80"), false),
            Err(LocalRefusal::NeedsFlag)
        );
        assert_eq!(node.check(sa("100.100.100.201:80"), false), Ok(()));
    }

    #[test]
    fn bound_ports_count_sockets() {
        let bound = BoundPorts::new();
        bound.add(53);
        bound.add(53);
        bound.remove(53);
        assert!(bound.contains(53));
        bound.remove(53);
        assert!(!bound.contains(53));
        bound.remove(53);
        assert!(!bound.contains(53));
    }
}
