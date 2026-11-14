//! The one reserved-port and listen-address rule (Story 12.1, D-5),
//! shared by the CLI's listener validation, the control plane's stream
//! conflict check and, through it, the bind contract of Story 12.2.
//!
//! Against a node's reserved ports the rule is port-only and
//! protocol-agnostic: the HTTP and HTTPS listeners bind every address,
//! and UDP 443 is where HTTP/3 will listen. Between two streams it is
//! protocol, port interval and [`listen_addresses_conflict`].

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use strum::{IntoStaticStr, VariantArray};

use crate::models::{binds_here_when_enabled, NodeRole, Stream, StreamProtocol};

/// The ports a node's own listeners hold. The `Option`s are listeners
/// that may be off, in which case there is no port to collide with.
///
/// Persisted as JSON in `cluster_nodes.reserved_ports_json` for each
/// follower that reported it in its heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedPorts {
    /// The management API port.
    pub management: u16,
    /// The HTTP proxy listener port.
    pub http: u16,
    /// The HTTPS proxy listener port.
    pub https: u16,
    /// The cluster plane's operational port, when the plane is on.
    pub cluster: Option<u16>,
    /// The cluster plane's enrollment port, when the plane is on.
    pub enrollment: Option<u16>,
    /// The automation API's port, when it is on.
    pub automation: Option<u16>,
}

/// One of the listeners [`ReservedPorts`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IntoStaticStr, VariantArray)]
#[strum(serialize_all = "snake_case")]
pub enum ReservedListener {
    /// The management API.
    Management,
    /// The HTTP proxy listener.
    Http,
    /// The HTTPS proxy listener.
    Https,
    /// The cluster plane's operational listener.
    Cluster,
    /// The cluster plane's enrollment listener.
    Enrollment,
    /// The automation API.
    Automation,
}

impl ReservedListener {
    /// The snake_case name of the listener (`https`, `enrollment`, ...).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }

    /// How a refusal names the listener's port, the phrase the CLI has
    /// always printed ("port 9443 is the management API port").
    pub fn phrase(&self) -> &'static str {
        match self {
            Self::Management => "the management API port",
            Self::Http | Self::Https => "a proxy listener port",
            Self::Cluster => "the cluster plane port",
            Self::Enrollment => "the cluster enrollment port",
            Self::Automation => "the automation API port",
        }
    }
}

impl ReservedPorts {
    /// The port `listener` holds, `None` when it is off.
    pub fn port_of(&self, listener: ReservedListener) -> Option<u16> {
        match listener {
            ReservedListener::Management => Some(self.management),
            ReservedListener::Http => Some(self.http),
            ReservedListener::Https => Some(self.https),
            ReservedListener::Cluster => self.cluster,
            ReservedListener::Enrollment => self.enrollment,
            ReservedListener::Automation => self.automation,
        }
    }

    /// The listener holding `port`, if any. The first in
    /// [`ReservedListener::VARIANTS`] order when two share it.
    pub fn clash(&self, port: u16) -> Option<ReservedListener> {
        ReservedListener::VARIANTS
            .iter()
            .copied()
            .find(|&listener| self.port_of(listener) == Some(port))
    }

    /// The lowest port of `first..=last` a listener holds, with that
    /// listener. Defined through [`ReservedPorts::clash`] so a single port
    /// and a range cannot be judged differently.
    pub fn clash_in(&self, first: u16, last: u16) -> Option<(u16, ReservedListener)> {
        (first..=last).find_map(|port| self.clash(port).map(|listener| (port, listener)))
    }
}

/// Whether two streams on the same protocol and port, one listening on
/// `a` and one on `b`, conflict.
///
/// This is the bind contract Story 12.2 binds by:
///
/// - `[::]` binds with `IPV6_V6ONLY` off (dual-stack) and conflicts
///   with every address;
/// - any other IPv6 literal binds with `IPV6_V6ONLY` on and conflicts
///   only with itself and `[::]`;
/// - `0.0.0.0` conflicts with every IPv4 address and with `[::]`;
/// - any other IPv4 literal conflicts with itself, `0.0.0.0` and `[::]`.
///
/// IPv4-mapped IPv6 addresses never reach it: `Stream::validate` refuses
/// them.
pub fn listen_addresses_conflict(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V6(x), _) if x.is_unspecified() => true,
        (_, IpAddr::V6(y)) if y.is_unspecified() => true,
        (IpAddr::V4(x), IpAddr::V4(y)) => x == y || x.is_unspecified() || y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V6(y)) => x == y,
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

/// How a conflict names the node it happens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeLabel {
    /// The node running the check.
    ThisNode,
    /// An enrolled node, by its `cluster_nodes.name`.
    Named(String),
}

impl std::fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThisNode => f.write_str("this node"),
            Self::Named(name) => write!(f, "node `{name}`"),
        }
    }
}

/// A node a candidate stream is checked on: who it is, which streams
/// it binds (through its role, [`binds_here_when_enabled`]) and its
/// reserved ports, `None` for an enrolled node that never reported them.
#[derive(Debug, Clone)]
pub struct NodePorts<'a> {
    /// How a conflict names the node.
    pub label: NodeLabel,
    /// The node's role, which decides the other streams it binds.
    pub role: NodeRole<'a>,
    /// The node's reserved ports, if known.
    pub reserved: Option<ReservedPorts>,
}

/// What a candidate stream collides with on one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortConflictObject {
    /// One of the node's own listeners.
    Reserved {
        /// The first port of the candidate's range it holds.
        port: u16,
        /// The listener.
        listener: ReservedListener,
    },
    /// Another stream the node binds.
    Stream {
        /// Its name.
        name: String,
        /// Its protocol.
        protocol: StreamProtocol,
        /// Its listen address.
        listen_address: IpAddr,
        /// Its first port.
        port_first: u16,
        /// Its last port.
        port_last: u16,
    },
    /// The node has not reported its reserved ports, so the candidate
    /// cannot be checked there and is refused (fail closed).
    NotReported,
}

/// A refusal of a candidate stream's ports on one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConflict {
    /// The node.
    pub node: NodeLabel,
    /// What the candidate collides with.
    pub object: PortConflictObject,
}

impl std::fmt::Display for PortConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let node = &self.node;
        match &self.object {
            PortConflictObject::Reserved { port, listener } => write!(
                f,
                "port {port} is reserved on {node}: {} ({} listener)",
                listener.phrase(),
                listener.as_str()
            ),
            PortConflictObject::Stream {
                name,
                protocol,
                listen_address,
                port_first,
                port_last,
            } => {
                let ports = if port_first == port_last {
                    port_first.to_string()
                } else {
                    format!("{port_first}-{port_last}")
                };
                let address = match listen_address {
                    IpAddr::V6(_) => format!("[{listen_address}]"),
                    IpAddr::V4(_) => listen_address.to_string(),
                };
                write!(
                    f,
                    "on {node}, the ports overlap stream `{name}` ({address}:{ports}/{})",
                    protocol.as_str()
                )
            }
            PortConflictObject::NotReported => write!(
                f,
                "{node} has not reported its reserved ports yet, so a stream cannot be \
                 checked there; let it connect to the control plane once"
            ),
        }
    }
}

impl std::error::Error for PortConflict {}

/// Every port conflict of `candidate` on `nodes`, in node order, the
/// reserved ports of a node before its streams.
///
/// The caller chooses the nodes (D-5: those the candidate's selector
/// resolves to, plus this node when it would bind the candidate); this
/// function checks the candidate on each of them, against the node's
/// reserved ports and against every stream of `others` the node binds
/// by [`binds_here_when_enabled`], disabled ones included since a
/// disabled stream keeps its ports. `others` may hold the candidate's
/// own stored row; it is skipped by id.
pub fn stream_port_conflicts(
    candidate: &Stream,
    nodes: &[NodePorts<'_>],
    others: &[Stream],
) -> Vec<PortConflict> {
    let mut conflicts = Vec::new();
    for node in nodes {
        match node.reserved {
            None => conflicts.push(PortConflict {
                node: node.label.clone(),
                object: PortConflictObject::NotReported,
            }),
            Some(reserved) => {
                if let Some((port, listener)) =
                    reserved.clash_in(candidate.port_first, candidate.port_last)
                {
                    conflicts.push(PortConflict {
                        node: node.label.clone(),
                        object: PortConflictObject::Reserved { port, listener },
                    });
                }
            }
        }
        for other in others {
            let overlaps = other.id != candidate.id
                && other.protocol == candidate.protocol
                && other.port_first <= candidate.port_last
                && candidate.port_first <= other.port_last
                && listen_addresses_conflict(other.listen_address, candidate.listen_address)
                && binds_here_when_enabled(other, node.role);
            if overlaps {
                conflicts.push(PortConflict {
                    node: node.label.clone(),
                    object: PortConflictObject::Stream {
                        name: other.name.clone(),
                        protocol: other.protocol,
                        listen_address: other.listen_address,
                        port_first: other.port_first,
                        port_last: other.port_last,
                    },
                });
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::sample_stream;

    /// Every field holds a distinct port, so each listener is found by
    /// its own port and by no other.
    fn distinct() -> ReservedPorts {
        ReservedPorts {
            management: 9443,
            http: 8080,
            https: 8443,
            cluster: Some(9444),
            enrollment: Some(9445),
            automation: Some(9600),
        }
    }

    #[test]
    fn clash_finds_every_listener_by_its_own_port() {
        let reserved = distinct();
        for &listener in ReservedListener::VARIANTS {
            let port = reserved.port_of(listener).expect("every listener is on");
            assert_eq!(reserved.clash(port), Some(listener), "{listener:?}");
            assert_eq!(reserved.clash_in(port, port), Some((port, listener)));
            // A range ending on the port finds it, and only it, since
            // every lower port in the range is free.
            let free_below = (1..port)
                .rev()
                .take_while(|&p| reserved.clash(p).is_none())
                .last()
                .unwrap_or(port);
            assert_eq!(reserved.clash_in(free_below, port), Some((port, listener)));
        }
        assert_eq!(reserved.clash(1), None);
        assert_eq!(reserved.clash_in(1, 1000), None);
    }

    #[test]
    fn an_off_listener_reserves_nothing() {
        let on = distinct();
        let off = ReservedPorts {
            cluster: None,
            enrollment: None,
            automation: None,
            ..on
        };
        for &listener in ReservedListener::VARIANTS {
            let port = on.port_of(listener).expect("on");
            assert_eq!(
                off.clash(port).is_some(),
                off.port_of(listener).is_some(),
                "{listener:?}"
            );
        }
    }

    #[test]
    fn clash_in_reports_the_lowest_reserved_port_of_the_range() {
        let reserved = distinct();
        assert_eq!(
            reserved.clash_in(8000, 9000),
            Some((8080, ReservedListener::Http))
        );
        assert_eq!(
            reserved.clash_in(8444, 9443),
            Some((9443, ReservedListener::Management))
        );
        assert_eq!(reserved.clash_in(8081, 8442), None);
        // Agrees with clash on every port of a span.
        for port in 9440..=9450 {
            assert_eq!(
                reserved.clash_in(port, port).map(|(_, l)| l),
                reserved.clash(port)
            );
        }
    }

    #[test]
    fn reserved_ports_round_trip_as_json() {
        let reserved = distinct();
        let json = serde_json::to_string(&reserved).expect("serialize");
        assert_eq!(
            serde_json::from_str::<ReservedPorts>(&json).expect("deserialize"),
            reserved
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test setup: address")
    }

    /// (a, b, conflict): every row is asserted both ways round.
    const ADDRESS_VECTORS: &[(&str, &str, bool)] = &[
        // [::] against everything.
        ("::", "192.0.2.10", true),
        ("::", "0.0.0.0", true),
        ("::", "2001:db8::1", true),
        ("::", "::", true),
        // 0.0.0.0 against an IPv4 literal, an IPv6 literal and itself.
        ("0.0.0.0", "192.0.2.10", true),
        ("0.0.0.0", "2001:db8::1", false),
        ("0.0.0.0", "0.0.0.0", true),
        // Two literals of one family.
        ("192.0.2.10", "192.0.2.20", false),
        ("192.0.2.10", "192.0.2.10", true),
        ("2001:db8::1", "2001:db8::2", false),
        ("2001:db8::1", "2001:db8::1", true),
        // Across families.
        ("2001:db8::1", "192.0.2.10", false),
    ];

    #[test]
    fn the_dual_stack_rule_over_every_address_vector() {
        for &(a, b, expected) in ADDRESS_VECTORS {
            assert_eq!(
                listen_addresses_conflict(ip(a), ip(b)),
                expected,
                "{a} vs {b}"
            );
            assert_eq!(
                listen_addresses_conflict(ip(b), ip(a)),
                expected,
                "{b} vs {a}"
            );
        }
    }

    fn on(
        id: &str,
        name: &str,
        protocol: StreamProtocol,
        address: &str,
        ports: (u16, u16),
    ) -> Stream {
        let mut s = sample_stream(id, name, protocol, ports.0);
        s.port_last = ports.1;
        s.listen_address = ip(address);
        s
    }

    fn standalone(reserved: ReservedPorts) -> Vec<NodePorts<'static>> {
        vec![NodePorts {
            label: NodeLabel::ThisNode,
            role: NodeRole::Standalone,
            reserved: Some(reserved),
        }]
    }

    #[test]
    fn stream_conflicts_follow_the_address_vectors() {
        let nodes = standalone(distinct());
        for &(a, b, expected) in ADDRESS_VECTORS {
            for (x, y) in [(a, b), (b, a)] {
                let existing = on("e", "existing", StreamProtocol::Udp, x, (53, 53));
                let candidate = on("c", "candidate", StreamProtocol::Udp, y, (53, 53));
                let found = stream_port_conflicts(&candidate, &nodes, &[existing]);
                assert_eq!(!found.is_empty(), expected, "{x} existing, {y} candidate");
            }
        }
    }

    #[test]
    fn protocols_and_port_intervals_decide_a_stream_conflict() {
        let nodes = standalone(distinct());
        let existing = on("e", "game", StreamProtocol::Udp, "0.0.0.0", (6000, 6099));

        let intersecting = on("c", "c", StreamProtocol::Udp, "0.0.0.0", (6099, 6199));
        let found = stream_port_conflicts(&intersecting, &nodes, std::slice::from_ref(&existing));
        assert_eq!(found.len(), 1);
        let message = found[0].to_string();
        assert!(
            message.contains("`game`") && message.contains("this node"),
            "{message}"
        );
        assert!(message.contains("6000-6099/udp"), "{message}");

        let adjacent = on("c", "c", StreamProtocol::Udp, "0.0.0.0", (6100, 6199));
        assert!(
            stream_port_conflicts(&adjacent, &nodes, std::slice::from_ref(&existing)).is_empty()
        );

        let other_protocol = on("c", "c", StreamProtocol::Tcp, "0.0.0.0", (6000, 6099));
        assert!(
            stream_port_conflicts(&other_protocol, &nodes, std::slice::from_ref(&existing))
                .is_empty()
        );

        // The candidate's own stored row is not a conflict.
        let itself = on("e", "game", StreamProtocol::Udp, "0.0.0.0", (6000, 6099));
        assert!(stream_port_conflicts(&itself, &nodes, std::slice::from_ref(&existing)).is_empty());
    }

    #[test]
    fn a_disabled_stream_still_holds_its_ports() {
        let nodes = standalone(distinct());
        let mut existing = on("e", "dns", StreamProtocol::Udp, "0.0.0.0", (53, 53));
        existing.enabled = false;
        let candidate = on("c", "dns-2", StreamProtocol::Udp, "192.0.2.10", (53, 53));
        assert_eq!(
            stream_port_conflicts(&candidate, &nodes, &[existing]).len(),
            1
        );
    }

    #[test]
    fn a_reserved_port_is_refused_whatever_the_protocol_and_address() {
        let nodes = standalone(distinct());
        for protocol in [StreamProtocol::Tcp, StreamProtocol::Udp] {
            for address in ["192.0.2.10", "2001:db8::1", "0.0.0.0", "::"] {
                let candidate = on("c", "c", protocol, address, (8400, 8500));
                let found = stream_port_conflicts(&candidate, &nodes, &[]);
                assert_eq!(
                    found,
                    vec![PortConflict {
                        node: NodeLabel::ThisNode,
                        object: PortConflictObject::Reserved {
                            port: 8443,
                            listener: ReservedListener::Https,
                        },
                    }]
                );
            }
        }
    }

    #[test]
    fn a_node_is_checked_against_the_streams_it_binds_only() {
        let edge = vec![NodePorts {
            label: NodeLabel::Named("edge-1".to_string()),
            role: NodeRole::Follower {
                node_name: "edge-1",
            },
            reserved: Some(distinct()),
        }];
        let mut elsewhere = on(
            "e",
            "elsewhere",
            StreamProtocol::Tcp,
            "0.0.0.0",
            (5000, 5000),
        );
        elsewhere.node_selector = vec!["edge-2".to_string()];
        let candidate = on("c", "c", StreamProtocol::Tcp, "0.0.0.0", (5000, 5000));
        assert!(
            stream_port_conflicts(&candidate, &edge, std::slice::from_ref(&elsewhere)).is_empty()
        );

        elsewhere.node_selector = vec!["edge-1".to_string()];
        let found = stream_port_conflicts(&candidate, &edge, std::slice::from_ref(&elsewhere));
        assert_eq!(found.len(), 1);
        assert!(
            found[0].to_string().contains("node `edge-1`"),
            "{}",
            found[0]
        );

        // The control plane binds only fleet-wide streams.
        let plane = vec![NodePorts {
            label: NodeLabel::ThisNode,
            role: NodeRole::ControlPlane,
            reserved: Some(distinct()),
        }];
        assert!(
            stream_port_conflicts(&candidate, &plane, std::slice::from_ref(&elsewhere)).is_empty()
        );
        elsewhere.node_selector.clear();
        assert_eq!(
            stream_port_conflicts(&candidate, &plane, std::slice::from_ref(&elsewhere)).len(),
            1
        );
    }

    #[test]
    fn a_node_that_never_reported_refuses_the_stream_by_name() {
        let nodes = vec![NodePorts {
            label: NodeLabel::Named("edge-1".to_string()),
            role: NodeRole::Follower {
                node_name: "edge-1",
            },
            reserved: None,
        }];
        let candidate = on("c", "c", StreamProtocol::Tcp, "0.0.0.0", (5000, 5000));
        let found = stream_port_conflicts(&candidate, &nodes, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].object, PortConflictObject::NotReported);
        assert!(found[0].to_string().contains("node `edge-1`"));
    }

    #[test]
    fn a_reserved_conflict_names_the_node_and_the_listener() {
        let nodes = vec![NodePorts {
            label: NodeLabel::Named("edge-1".to_string()),
            role: NodeRole::Follower {
                node_name: "edge-1",
            },
            reserved: Some(distinct()),
        }];
        let candidate = on("c", "c", StreamProtocol::Tcp, "0.0.0.0", (8443, 8443));
        let message = stream_port_conflicts(&candidate, &nodes, &[])[0].to_string();
        assert!(message.contains("edge-1"), "{message}");
        assert!(message.contains("https"), "{message}");
    }
}
