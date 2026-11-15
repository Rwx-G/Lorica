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
//!   it the kernel's 4-tuple hash, never changes when a worker dies.
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
/// `ReservedPort` and `FdBudget` are the node-side checks run before any
/// bind.
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
    /// Any other error.
    Other,
}

impl BindFailureKind {
    /// Every kind, in declaration order.
    pub const ALL: [BindFailureKind; 6] = [
        BindFailureKind::AddressInUse,
        BindFailureKind::PermissionDenied,
        BindFailureKind::AddressNotAvailable,
        BindFailureKind::ReservedPort,
        BindFailureKind::FdBudget,
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

/// Bind a UDP `SO_REUSEPORT` group of `slots` sockets on `addr`, one per
/// worker slot, all or none: a failure closes the slots already bound.
pub fn bind_udp_group(addr: SocketAddr, slots: usize) -> Result<Vec<OwnedFd>, BindError> {
    let fail = |e: io::Error| BindError::new(StreamProto::Udp, addr, e);
    let mut group = Vec::with_capacity(slots);
    for _ in 0..slots {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
            .map_err(fail)?;
        socket.set_reuse_port(true).map_err(fail)?;
        apply_v6_rule(&socket, &addr).map_err(fail)?;
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
