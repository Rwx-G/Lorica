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

//! Stream sockets as the supervisor binds them, and the process fd limit.
//! Also the two `nix` calls the stream engine needs, kept here so
//! `lorica-stream` takes no `nix` edge of its own: the host's interface
//! addresses and `IP_BIND_ADDRESS_NO_PORT`.
//!
//! - **TCP:** one listening socket per port, `SO_REUSEADDR` on and
//!   `SO_REUSEPORT` off, so a port any other socket holds is refused with
//!   `EADDRINUSE` whoever holds it. Every worker receives a dup of it and
//!   they share one accept queue.
//! - **UDP:** per port, one socket per worker slot, each with
//!   `SO_REUSEPORT` set before `bind`, forming one group. The supervisor
//!   keeps every slot for the binding's life so the group size, and with
//!   it the kernel's 4-tuple hash, never changes when a worker dies. On
//!   the unspecified address each slot also reports every datagram's
//!   destination address, so a reply can leave from it.
//! - **IPv6:** `IPV6_V6ONLY` is set explicitly on every IPv6 socket, never
//!   left to `net.ipv6.bindv6only`: off for the unspecified address `[::]`,
//!   which then takes IPv4 too, on for every other IPv6 literal.
//!
//! Every socket is `SOCK_CLOEXEC`, so it only ever reaches a worker
//! through the stream control channel.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::os::fd::OwnedFd;

use nix::errno::Errno;
use nix::sys::resource::{getrlimit, Resource};
use socket2::{Domain, Protocol, Socket, Type};

use crate::fd_passing::StreamProto;

/// Listen backlog of a TCP stream listener, the HTTP listeners' figure;
/// the kernel clamps it to `net.core.somaxconn`.
pub const TCP_STREAM_BACKLOG: i32 = 65535;

/// Why a stream binding failed, as reported on the stream (API, audit,
/// alert). The errno-backed kinds come from [`Self::from_io_error`];
/// `ReservedPort`, `FdBudget` and `SourcePorts` are the node-side checks
/// run before any bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindFailureKind {
    /// `EADDRINUSE`: another socket holds the address and port.
    AddressInUse,
    /// `EACCES` or `EPERM`: typically a privileged port without
    /// `CAP_NET_BIND_SERVICE`.
    PermissionDenied,
    /// `EADDRNOTAVAIL`: the address is not (yet) on this host.
    AddressNotAvailable,
    /// The port is one of this node's own reserved ports.
    ReservedPort,
    /// The binding would break the node's fd budget.
    FdBudget,
    /// The binding's UDP sessions would commit more ephemeral source ports
    /// than a source address has usable ([`usable_udp_source_ports`]).
    SourcePorts,
    /// Any other error.
    Other,
}

impl BindFailureKind {
    /// Every kind, in declaration order.
    pub const ALL: [BindFailureKind; 7] = [
        BindFailureKind::AddressInUse,
        BindFailureKind::PermissionDenied,
        BindFailureKind::AddressNotAvailable,
        BindFailureKind::ReservedPort,
        BindFailureKind::FdBudget,
        BindFailureKind::SourcePorts,
        BindFailureKind::Other,
    ];

    /// The kind whose [`Self::as_str`] spelling is `name`, `None` for a
    /// spelling no kind has (a newer peer's, read by an older control
    /// plane).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == name)
    }

    /// Classify a bind error by its errno.
    pub fn from_io_error(err: &io::Error) -> Self {
        match err.raw_os_error().map(Errno::from_raw) {
            Some(Errno::EADDRINUSE) => BindFailureKind::AddressInUse,
            Some(Errno::EACCES) | Some(Errno::EPERM) => BindFailureKind::PermissionDenied,
            Some(Errno::EADDRNOTAVAIL) => BindFailureKind::AddressNotAvailable,
            _ => BindFailureKind::Other,
        }
    }

    /// The API, audit and alert spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            BindFailureKind::AddressInUse => "address_in_use",
            BindFailureKind::PermissionDenied => "permission_denied",
            BindFailureKind::AddressNotAvailable => "address_not_available",
            BindFailureKind::ReservedPort => "reserved_port",
            BindFailureKind::FdBudget => "fd_budget",
            BindFailureKind::SourcePorts => "source_ports",
            BindFailureKind::Other => "other",
        }
    }
}

impl std::fmt::Display for BindFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stream socket that could not be created or bound. `source`'s text
/// is the OS error reported on the stream
/// (`Address already in use (os error 98)`).
#[derive(Debug, thiserror::Error)]
#[error("cannot bind {proto} {addr}: {source}")]
pub struct BindError {
    /// Protocol of the failing socket.
    pub proto: StreamProto,
    /// Address and port of the failing socket.
    pub addr: SocketAddr,
    /// Classification of `source`.
    pub kind: BindFailureKind,
    /// The OS error.
    #[source]
    pub source: io::Error,
}

impl BindError {
    fn new(proto: StreamProto, addr: SocketAddr, source: io::Error) -> Self {
        BindError {
            proto,
            addr,
            kind: BindFailureKind::from_io_error(&source),
            source,
        }
    }
}

/// The sockets bound for one port of a binding: one for TCP, one per
/// worker slot for UDP.
#[derive(Debug)]
pub struct BoundPort {
    /// The bound address and port.
    pub addr: SocketAddr,
    /// The sockets, in slot order for UDP.
    pub sockets: Vec<OwnedFd>,
}

/// Apply the `IPV6_V6ONLY` rule to an IPv6 socket before `bind`: off for
/// `[::]` (dual stack), on for any other IPv6 literal.
fn apply_v6_rule(socket: &Socket, addr: &SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V6(v6) => socket.set_only_v6(!v6.ip().is_unspecified()),
        SocketAddr::V4(_) => Ok(()),
    }
}

/// Bind a TCP stream listener on `addr`: `SO_REUSEADDR` on, `SO_REUSEPORT`
/// off, the IPv6 rule, backlog [`TCP_STREAM_BACKLOG`].
pub fn bind_tcp_stream_listener(addr: SocketAddr) -> Result<OwnedFd, BindError> {
    let fail = |e: io::Error| BindError::new(StreamProto::Tcp, addr, e);
    let socket =
        Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP)).map_err(fail)?;
    socket.set_reuse_address(true).map_err(fail)?;
    socket.set_reuse_port(false).map_err(fail)?;
    apply_v6_rule(&socket, &addr).map_err(fail)?;
    socket.bind(&addr.into()).map_err(fail)?;
    socket.listen(TCP_STREAM_BACKLOG).map_err(fail)?;
    Ok(OwnedFd::from(socket))
}

/// Ask the kernel for each datagram's destination address on a UDP socket
/// bound to the unspecified address: `IP_PKTINFO` on IPv4,
/// `IPV6_RECVPKTINFO` on IPv6. A dual-stack `[::]` socket then reports an
/// IPv4 datagram's destination IPv4-mapped in `IPV6_PKTINFO`, so the
/// IPv6 option alone serves both families. A socket bound to a specific
/// address knows its destination already and gets neither.
///
/// The stream engine reads the destination to key the session and to
/// send the reply from the address the client targeted (Story 12.5 D-g).
fn apply_pktinfo_rule(socket: &Socket, addr: &SocketAddr) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    if !addr.ip().is_unspecified() {
        return Ok(());
    }
    match addr {
        SocketAddr::V4(_) => setsockopt(socket, sockopt::Ipv4PacketInfo, &true),
        SocketAddr::V6(_) => setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true),
    }
    .map_err(io::Error::from)
}

/// Bind a UDP `SO_REUSEPORT` group of `slots` sockets on `addr`, one per
/// worker slot, all or none: a failure closes the slots already bound.
/// On the unspecified address every slot also reports each datagram's
/// destination address ([`apply_pktinfo_rule`]).
pub fn bind_udp_group(addr: SocketAddr, slots: usize) -> Result<Vec<OwnedFd>, BindError> {
    let fail = |e: io::Error| BindError::new(StreamProto::Udp, addr, e);
    let mut group = Vec::with_capacity(slots);
    for _ in 0..slots {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
            .map_err(fail)?;
        socket.set_reuse_port(true).map_err(fail)?;
        apply_v6_rule(&socket, &addr).map_err(fail)?;
        apply_pktinfo_rule(&socket, &addr).map_err(fail)?;
        socket.bind(&addr.into()).map_err(fail)?;
        group.push(OwnedFd::from(socket));
    }
    Ok(group)
}

/// Bind every port of `ports` on `ip`, all or none. TCP binds one
/// listener per port; UDP binds a group of `udp_slots` per port
/// (`udp_slots` is ignored for TCP). On the first failure every port
/// already bound is closed and the error names the failing port.
pub fn bind_range(
    proto: StreamProto,
    ip: IpAddr,
    ports: RangeInclusive<u16>,
    udp_slots: usize,
) -> Result<Vec<BoundPort>, BindError> {
    let mut bound = Vec::with_capacity(ports.len());
    for port in ports {
        let addr = SocketAddr::new(ip, port);
        let sockets = match proto {
            StreamProto::Tcp => vec![bind_tcp_stream_listener(addr)?],
            StreamProto::Udp => bind_udp_group(addr, udp_slots)?,
        };
        bound.push(BoundPort { addr, sockets });
    }
    Ok(bound)
}

/// The process's soft `RLIMIT_NOFILE`, the `L` of the fd budget. Only
/// read: the packaged unit forbids `setrlimit`.
pub fn process_fd_limit() -> Result<u64, nix::Error> {
    let (soft, _hard) = getrlimit(Resource::RLIMIT_NOFILE)?;
    Ok(soft)
}

/// Ephemeral ports left to the host's own UDP clients (its resolver,
/// health probes, other processes) out of the usable range, so stream
/// sessions never take the last of them (Story 12.5 D-e).
pub const EPHEMERAL_PORT_MARGIN: u32 = 1024;

/// Where the kernel publishes the ephemeral port range. It governs IPv6
/// as well, despite the name.
pub const IP_LOCAL_PORT_RANGE_PATH: &str = "/proc/sys/net/ipv4/ip_local_port_range";

/// Where the kernel publishes the ports excluded from ephemeral choice.
pub const IP_LOCAL_RESERVED_PORTS_PATH: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";

/// The ephemeral port settings could not be read or understood. The
/// caller reports it; no figure is ever guessed in its place.
#[derive(Debug, thiserror::Error)]
pub enum PortRangeError {
    /// A `/proc` file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: &'static str,
        /// The read failure.
        #[source]
        source: io::Error,
    },
    /// A `/proc` file did not hold what the kernel writes there.
    #[error("cannot parse {path}: {reason}")]
    Parse {
        /// The file.
        path: &'static str,
        /// What was wrong.
        reason: &'static str,
    },
}

/// The UDP source ports one source address can use for stream sessions,
/// `U` of the node session ceiling (Story 12.5 D-e): the size of
/// `ip_local_port_range`, minus the ports of `ip_local_reserved_ports`
/// inside it, minus [`EPHEMERAL_PORT_MARGIN`], saturating at 0. Read on
/// every call, so a sysctl change is seen without a restart.
///
/// # Errors
///
/// A file that cannot be read or parsed.
pub fn usable_udp_source_ports() -> Result<u32, PortRangeError> {
    let read = |path: &'static str| {
        std::fs::read_to_string(path).map_err(|source| PortRangeError::Read { path, source })
    };
    usable_source_ports_from(
        &read(IP_LOCAL_PORT_RANGE_PATH)?,
        &read(IP_LOCAL_RESERVED_PORTS_PATH)?,
    )
}

/// [`usable_udp_source_ports`] over the two files' contents.
///
/// `range` is `<low> <high>` (the kernel separates them with a tab);
/// `reserved` is a comma-separated list of ports and `<a>-<b>` ranges,
/// possibly empty. Reserved entries outside the range, and overlapping
/// ones, count once or not at all.
///
/// # Errors
///
/// [`PortRangeError::Parse`] for content the kernel would not write.
pub fn usable_source_ports_from(range: &str, reserved: &str) -> Result<u32, PortRangeError> {
    let range_error = |reason| PortRangeError::Parse {
        path: IP_LOCAL_PORT_RANGE_PATH,
        reason,
    };
    let reserved_error = |reason| PortRangeError::Parse {
        path: IP_LOCAL_RESERVED_PORTS_PATH,
        reason,
    };
    let bounds: Vec<&str> = range.split_ascii_whitespace().collect();
    let [low, high] = bounds[..] else {
        return Err(range_error("expected two ports"));
    };
    let low: u16 = parse_port(low).ok_or_else(|| range_error("not a port"))?;
    let high: u16 = parse_port(high).ok_or_else(|| range_error("not a port"))?;
    if low > high {
        return Err(range_error("the low port is above the high port"));
    }

    let mut inside: Vec<(u16, u16)> = Vec::new();
    for entry in reserved.trim().split(',').filter(|e| !e.is_empty()) {
        let (first, last) = match entry.split_once('-') {
            Some((a, b)) => (parse_port(a), parse_port(b)),
            None => (parse_port(entry), parse_port(entry)),
        };
        let (Some(first), Some(last)) = (first, last) else {
            return Err(reserved_error("not a port or a port range"));
        };
        if first > last {
            return Err(reserved_error("a range runs backwards"));
        }
        let (first, last) = (first.max(low), last.min(high));
        if first <= last {
            inside.push((first, last));
        }
    }
    inside.sort_unstable();
    let mut reserved_count: u32 = 0;
    let mut covered_to: Option<u16> = None;
    for (first, last) in inside {
        let start = match covered_to {
            Some(end) if end >= last => continue,
            Some(end) if end >= first => end + 1,
            _ => first,
        };
        reserved_count += u32::from(last - start) + 1;
        covered_to = Some(last);
    }

    let size = u32::from(high - low) + 1;
    Ok(size
        .saturating_sub(reserved_count)
        .saturating_sub(EPHEMERAL_PORT_MARGIN))
}

/// A port in decimal digits only.
fn parse_port(text: &str) -> Option<u16> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Every address assigned to an interface of this host, canonical
/// (an IPv4-mapped address as the IPv4 address it carries). The stream
/// engine treats a backend on one of them as local (Story 12.3 D-m):
/// `10.0.0.5:<management port>` on the node itself is the management
/// API exactly as `127.0.0.1` is.
///
/// # Errors
///
/// The `getifaddrs` failure.
pub fn interface_addresses() -> Result<Vec<IpAddr>, nix::Error> {
    let mut addresses: Vec<IpAddr> = nix::ifaddrs::getifaddrs()?
        .filter_map(|ifaddr| {
            let address = ifaddr.address?;
            if let Some(v4) = address.as_sockaddr_in() {
                Some(IpAddr::V4(v4.ip()))
            } else {
                address
                    .as_sockaddr_in6()
                    .map(|v6| IpAddr::V6(v6.ip()).to_canonical())
            }
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

/// Set `IP_BIND_ADDRESS_NO_PORT` on an unbound socket, so a later `bind`
/// to `(address, 0)` reserves no ephemeral port and the kernel picks one
/// at `connect` per destination 4-tuple (Story 12.3 D-l). Must be set
/// before `bind`. Applies to IPv6 sockets too: Linux handles `SOL_IP`
/// options on them.
///
/// # Errors
///
/// The `setsockopt` failure.
pub fn set_bind_address_no_port(socket: &impl std::os::fd::AsFd) -> Result<(), nix::Error> {
    nix::sys::socket::setsockopt(
        socket,
        nix::sys::socket::sockopt::IpBindAddressNoPort,
        &true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_from_errno() {
        let cases = [
            (Errno::EADDRINUSE, BindFailureKind::AddressInUse),
            (Errno::EACCES, BindFailureKind::PermissionDenied),
            (Errno::EPERM, BindFailureKind::PermissionDenied),
            (Errno::EADDRNOTAVAIL, BindFailureKind::AddressNotAvailable),
            (Errno::EINVAL, BindFailureKind::Other),
            (Errno::EMFILE, BindFailureKind::Other),
        ];
        for (errno, kind) in cases {
            let err = io::Error::from_raw_os_error(errno as i32);
            assert_eq!(BindFailureKind::from_io_error(&err), kind, "{errno}");
        }
        let synthetic = io::Error::other("no errno");
        assert_eq!(
            BindFailureKind::from_io_error(&synthetic),
            BindFailureKind::Other
        );
    }

    #[test]
    fn kind_spellings_are_the_story_vocabulary() {
        // The API, audit and alert contract of Story 12.2 D-h.
        let contract = [
            (BindFailureKind::AddressInUse, "address_in_use"),
            (BindFailureKind::PermissionDenied, "permission_denied"),
            (
                BindFailureKind::AddressNotAvailable,
                "address_not_available",
            ),
            (BindFailureKind::ReservedPort, "reserved_port"),
            (BindFailureKind::FdBudget, "fd_budget"),
            (BindFailureKind::SourcePorts, "source_ports"),
            (BindFailureKind::Other, "other"),
        ];
        for (kind, spelling) in contract {
            assert_eq!(kind.as_str(), spelling);
            assert_eq!(kind.to_string(), spelling);
            assert_eq!(BindFailureKind::from_name(spelling), Some(kind));
        }
        assert_eq!(BindFailureKind::ALL.len(), contract.len());
        assert_eq!(BindFailureKind::from_name("no_such_kind"), None);
    }

    #[test]
    fn usable_ports_at_the_default_range_leave_the_margin() {
        // Linux's default range, as the kernel writes it, nothing reserved.
        let default_size: u32 = 60999 - 32768 + 1;
        assert_eq!(
            usable_source_ports_from("32768\t60999\n", "\n").unwrap(),
            default_size - EPHEMERAL_PORT_MARGIN
        );
    }

    #[test]
    fn reserved_ports_count_only_inside_the_range_and_once() {
        let range = "10000\t19999\n";
        let size: u32 = 10_000;
        let cases: [(&str, u32); 8] = [
            ("", 0),
            ("15000\n", 1),
            ("15000,16000", 2),
            ("15000-15009", 10),
            // Outside the range, below and above.
            ("80,443,8000-8080,20000-20100", 0),
            // Straddling either end.
            ("9900-10009,19990-21000", 10 + 10),
            // Overlapping and nested entries count each port once.
            ("11000-11099,11050-11149,11020-11030,11100", 150),
            // The whole range and beyond.
            ("0-65535", size),
        ];
        for (reserved, count) in cases {
            assert_eq!(
                usable_source_ports_from(range, reserved).unwrap(),
                (size - count).saturating_sub(EPHEMERAL_PORT_MARGIN),
                "{reserved:?}"
            );
        }
    }

    #[test]
    fn a_range_narrower_than_the_margin_saturates_at_zero() {
        assert_eq!(usable_source_ports_from("40000 40099", "").unwrap(), 0);
        assert_eq!(usable_source_ports_from("40000 40000", "").unwrap(), 0);
    }

    #[test]
    fn unparseable_port_settings_are_errors_never_guesses() {
        for range in [
            "",
            "32768",
            "32768 60999 1",
            "a b",
            "-1 5",
            "61000 32768",
            "1 70000",
        ] {
            assert!(
                matches!(
                    usable_source_ports_from(range, ""),
                    Err(PortRangeError::Parse {
                        path: IP_LOCAL_PORT_RANGE_PATH,
                        ..
                    })
                ),
                "{range:?}"
            );
        }
        for reserved in ["x", "100-", "-100", "200-100", "1,,2,a", "+5", "70000"] {
            assert!(
                matches!(
                    usable_source_ports_from("1 65535", reserved),
                    Err(PortRangeError::Parse {
                        path: IP_LOCAL_RESERVED_PORTS_PATH,
                        ..
                    })
                ),
                "{reserved:?}"
            );
        }
    }

    #[test]
    fn the_host_port_settings_are_readable() {
        // The test container's own sysctls; whatever they are, they parse.
        usable_udp_source_ports().expect("the /proc port settings parse");
    }

    #[test]
    fn fd_limit_is_readable() {
        assert!(process_fd_limit().expect("getrlimit") > 0);
    }

    #[test]
    fn the_loopback_is_an_interface_address() {
        let addresses = interface_addresses().expect("getifaddrs");
        assert!(addresses.contains(&IpAddr::from([127, 0, 0, 1])));
        assert!(addresses.iter().all(|ip| *ip == ip.to_canonical()));
    }

    #[test]
    fn bind_address_no_port_is_set_before_bind() {
        use nix::sys::socket::{getsockopt, sockopt::IpBindAddressNoPort};
        for domain in [Domain::IPV4, Domain::IPV6] {
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).expect("socket");
            set_bind_address_no_port(&socket).expect("setsockopt");
            assert!(getsockopt(&socket, IpBindAddressNoPort).expect("getsockopt"));
        }
    }
}
