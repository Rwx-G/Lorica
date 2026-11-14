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

//! The stream control channel and the stream sockets against a real
//! kernel (Story 12.2 Lot A). Linux only.

use std::io::{IoSlice, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{
    chunk_sockets, create_seqpacket_pair, recv_msg, send_msg, StreamCtlError, StreamCtlMsg,
    StreamSocket, ATTACH_MAX_SOCKETS,
};
use lorica_worker::stream_sockets::{
    bind_range, bind_tcp_stream_listener, bind_udp_group, BindFailureKind,
};
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{self, ControlMessage, MsgFlags, UnixAddr};
use nix::sys::stat::fstat;
use socket2::{Domain, SockRef, Socket, Type};

const STREAM_ID: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";

/// Inode of the open file description behind `fd`.
fn inode(fd: impl AsFd) -> u64 {
    fstat(fd).expect("fstat").st_ino
}

/// How many descriptors of this process refer to socket inode `ino`.
fn open_fds_on(ino: u64) -> usize {
    let target = format!("socket:[{ino}]");
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .filter_map(|e| e.ok())
        .filter(|e| {
            std::fs::read_link(e.path())
                .map(|l| l.to_string_lossy() == target)
                .unwrap_or(false)
        })
        .count()
}

fn plain_socket(domain: Domain, ty: Type) -> OwnedFd {
    OwnedFd::from(Socket::new(domain, ty, None).expect("socket"))
}

/// A base port where `count` consecutive ports are free for TCP and UDP
/// on every address, IPv4 and IPv6 alike.
fn free_ports(count: u16) -> u16 {
    'search: for _ in 0..64 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe");
        let base = probe.local_addr().unwrap().port();
        drop(probe);
        if base > u16::MAX - count {
            continue;
        }
        for port in base..base + count {
            for ty in [Type::STREAM, Type::DGRAM] {
                let s = Socket::new(Domain::IPV6, ty, None).unwrap();
                s.set_only_v6(false).unwrap();
                let addr: SocketAddr = (IpAddr::from([0u16; 8]), port).into();
                if s.bind(&addr.into()).is_err() {
                    continue 'search;
                }
            }
        }
        return base;
    }
    panic!("no run of {count} free ports found");
}

fn v6_unspecified(port: u16) -> SocketAddr {
    SocketAddr::new("::".parse().unwrap(), port)
}

fn sa(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}

#[test]
fn attach_round_trips_a_real_listener_that_still_accepts() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    let listener = bind_tcp_stream_listener(sa("127.0.0.1", 0)).unwrap();
    let local = SockRef::from(&listener)
        .local_addr()
        .unwrap()
        .as_socket()
        .unwrap();
    let ino = inode(&listener);

    let msg = StreamCtlMsg::Attach {
        seq: 41,
        stream_id: STREAM_ID.into(),
        bind_gen: 7,
        sockets: vec![StreamSocket {
            proto: StreamProto::Tcp,
            addr: local,
            fd: listener,
        }],
    };
    send_msg(&sup, &msg).unwrap();

    let StreamCtlMsg::Attach {
        seq,
        stream_id,
        bind_gen,
        mut sockets,
    } = recv_msg(&wrk).unwrap()
    else {
        panic!("expected attach");
    };
    assert_eq!((seq, stream_id.as_str(), bind_gen), (41, STREAM_ID, 7));
    assert_eq!(sockets.len(), 1);
    let received = sockets.pop().unwrap();
    assert_eq!(received.proto, StreamProto::Tcp);
    assert_eq!(received.addr, local);
    assert_eq!(inode(&received.fd), ino, "same socket, fresh descriptor");
    let flags = FdFlag::from_bits_truncate(fcntl(&received.fd, FcntlArg::F_GETFD).unwrap());
    assert!(flags.contains(FdFlag::FD_CLOEXEC), "MSG_CMSG_CLOEXEC");

    // Drop the sender's copy: the received descriptor alone serves.
    drop(msg);
    let worker_listener = TcpListener::from(received.fd);
    let mut client = TcpStream::connect(local).unwrap();
    let (mut served, _) = worker_listener.accept().unwrap();
    client.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    served.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    // The answer travels back on the same pair.
    send_msg(&wrk, &StreamCtlMsg::Ack { seq: 41, count: 1 }).unwrap();
    assert!(matches!(
        recv_msg(&sup).unwrap(),
        StreamCtlMsg::Ack { seq: 41, count: 1 }
    ));
}

#[test]
fn a_1024_socket_binding_round_trips_in_32_fd_chunks() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    let sockets: Vec<StreamSocket> = (0..1024u16)
        .map(|i| StreamSocket {
            proto: StreamProto::Udp,
            addr: SocketAddr::new("::".parse().unwrap(), 20_000 + i),
            fd: plain_socket(Domain::IPV6, Type::DGRAM),
        })
        .collect();
    let inodes: Vec<u64> = sockets.iter().map(|s| inode(&s.fd)).collect();

    let chunks = chunk_sockets(sockets);
    assert_eq!(chunks.len(), 1024 / ATTACH_MAX_SOCKETS);
    let mut seen = 0usize;
    for (seq, chunk) in chunks.into_iter().enumerate() {
        assert_eq!(chunk.len(), ATTACH_MAX_SOCKETS);
        let msg = StreamCtlMsg::Attach {
            seq: seq as u64,
            stream_id: STREAM_ID.into(),
            bind_gen: 3,
            sockets: chunk,
        };
        // Stop-and-wait: one message in flight, as the supervisor does.
        send_msg(&sup, &msg).unwrap();
        let StreamCtlMsg::Attach {
            seq: got_seq,
            sockets,
            ..
        } = recv_msg(&wrk).unwrap()
        else {
            panic!("expected attach");
        };
        assert_eq!(got_seq, seq as u64);
        for s in &sockets {
            assert_eq!(s.addr.port(), 20_000 + seen as u16, "order kept");
            assert_eq!(inode(&s.fd), inodes[seen]);
            seen += 1;
        }
    }
    assert_eq!(seen, 1024);
}

#[test]
fn chunking_keeps_order_and_a_short_tail() {
    let sockets: Vec<StreamSocket> = (0..70u16)
        .map(|i| StreamSocket {
            proto: StreamProto::Tcp,
            addr: sa("127.0.0.1", 1 + i),
            fd: plain_socket(Domain::IPV4, Type::STREAM),
        })
        .collect();
    let chunks = chunk_sockets(sockets);
    let sizes: Vec<usize> = chunks.iter().map(Vec::len).collect();
    assert_eq!(
        sizes,
        [
            ATTACH_MAX_SOCKETS,
            ATTACH_MAX_SOCKETS,
            70 - 2 * ATTACH_MAX_SOCKETS
        ]
    );
    let ports: Vec<u16> = chunks.iter().flatten().map(|s| s.addr.port()).collect();
    assert_eq!(ports, (1..=70).collect::<Vec<u16>>());
    assert!(chunk_sockets(Vec::new()).is_empty());
}

#[test]
fn send_refuses_an_attach_past_the_fd_ceiling_or_empty() {
    let (sup, _wrk) = create_seqpacket_pair().unwrap();
    for count in [0, ATTACH_MAX_SOCKETS + 1] {
        let msg = StreamCtlMsg::Attach {
            seq: 1,
            stream_id: STREAM_ID.into(),
            bind_gen: 1,
            sockets: (0..count)
                .map(|_| StreamSocket {
                    proto: StreamProto::Tcp,
                    addr: sa("127.0.0.1", 1),
                    fd: plain_socket(Domain::IPV4, Type::STREAM),
                })
                .collect(),
        };
        assert!(matches!(
            send_msg(&sup, &msg),
            Err(StreamCtlError::Invalid(_))
        ));
    }
}

/// Send a hand-built payload with `fds` attached, bypassing the encoder.
fn send_raw(sock: &OwnedFd, payload: &[u8], fds: &[RawFd]) {
    let iov = [IoSlice::new(payload)];
    let rights = [ControlMessage::ScmRights(fds)];
    let cmsgs: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
    socket::sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)
        .expect("raw sendmsg");
}

#[test]
fn a_truncated_payload_closes_every_received_fd() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    let passed = plain_socket(Domain::IPV4, Type::STREAM);
    let ino = inode(&passed);
    assert_eq!(open_fds_on(ino), 1);

    let oversized = vec![b'a'; 9000];
    send_raw(&sup, &oversized, &[passed.as_raw_fd()]);
    assert!(matches!(recv_msg(&wrk), Err(StreamCtlError::Truncated)));
    assert_eq!(open_fds_on(ino), 1, "the received copy was closed");
}

#[test]
fn too_many_fds_truncate_the_control_data_and_close_what_arrived() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    let passed: Vec<OwnedFd> = (0..ATTACH_MAX_SOCKETS + 1)
        .map(|_| plain_socket(Domain::IPV4, Type::STREAM))
        .collect();
    let inodes: Vec<u64> = passed.iter().map(inode).collect();
    let raw: Vec<RawFd> = passed.iter().map(AsRawFd::as_raw_fd).collect();

    send_raw(&sup, b"attach 1 s1 1", &raw);
    let got = recv_msg(&wrk);
    assert!(matches!(got, Err(StreamCtlError::Truncated)), "{got:?}");
    for ino in inodes {
        assert_eq!(open_fds_on(ino), 1);
    }
}

#[test]
fn a_count_mismatch_closes_every_received_fd() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    let passed = plain_socket(Domain::IPV4, Type::STREAM);
    let ino = inode(&passed);

    // Two socket tokens, one fd.
    send_raw(
        &sup,
        b"attach 1 s1 2 stream:tcp:2:127.0.0.1:1 stream:tcp:2:127.0.0.1:2",
        &[passed.as_raw_fd()],
    );
    assert!(matches!(
        recv_msg(&wrk),
        Err(StreamCtlError::FdCountMismatch { fds: 1, tokens: 2 })
    ));
    assert_eq!(open_fds_on(ino), 1);

    // An fd on a message that carries none.
    send_raw(&sup, b"refresh 2 drain_ms=10", &[passed.as_raw_fd()]);
    assert!(matches!(
        recv_msg(&wrk),
        Err(StreamCtlError::FdCountMismatch { fds: 1, tokens: 0 })
    ));
    assert_eq!(open_fds_on(ino), 1);

    // A socket token whose bind_gen is not the header's.
    send_raw(
        &sup,
        b"attach 3 s1 2 stream:tcp:9:127.0.0.1:1",
        &[passed.as_raw_fd()],
    );
    assert!(matches!(recv_msg(&wrk), Err(StreamCtlError::Malformed(_))));
    assert_eq!(open_fds_on(ino), 1);

    // The channel survives bad messages.
    send_msg(
        &sup,
        &StreamCtlMsg::Refresh {
            seq: 4,
            drain_ms: 5,
        },
    )
    .unwrap();
    assert!(matches!(
        recv_msg(&wrk).unwrap(),
        StreamCtlMsg::Refresh {
            seq: 4,
            drain_ms: 5
        }
    ));
}

#[test]
fn a_closed_peer_reads_as_closed() {
    let (sup, wrk) = create_seqpacket_pair().unwrap();
    drop(sup);
    assert!(matches!(recv_msg(&wrk), Err(StreamCtlError::Closed)));
    assert!(matches!(
        send_msg(&wrk, &StreamCtlMsg::Ack { seq: 1, count: 0 }),
        Err(StreamCtlError::Send(_))
    ));
}

#[test]
fn tcp_a_second_bind_on_the_same_port_is_address_in_use() {
    let port = free_ports(1);
    let _first = bind_tcp_stream_listener(sa("127.0.0.1", port)).unwrap();
    let err = bind_tcp_stream_listener(sa("127.0.0.1", port)).unwrap_err();
    assert_eq!(err.kind, BindFailureKind::AddressInUse);
    assert_eq!(err.proto, StreamProto::Tcp);
    assert_eq!(err.addr.port(), port);
    assert!(
        err.source.to_string().contains("os error 98"),
        "{}",
        err.source
    );

    // A foreign holder is refused the same way: SO_REUSEPORT is off.
    let port = free_ports(1);
    let _squatter = TcpListener::bind(sa("127.0.0.1", port)).unwrap();
    let err = bind_tcp_stream_listener(sa("127.0.0.1", port)).unwrap_err();
    assert_eq!(err.kind, BindFailureKind::AddressInUse);
}

#[test]
fn udp_a_group_of_four_binds_and_a_plain_fifth_socket_is_refused() {
    let port = free_ports(1);
    let addr = sa("127.0.0.1", port);
    let group = bind_udp_group(addr, 4).unwrap();
    assert_eq!(group.len(), 4);
    for fd in &group {
        let local = SockRef::from(fd).local_addr().unwrap().as_socket().unwrap();
        assert_eq!(local, addr);
        assert!(SockRef::from(fd).reuse_port().unwrap());
    }
    let err = UdpSocket::bind(addr).unwrap_err();
    assert_eq!(
        BindFailureKind::from_io_error(&err),
        BindFailureKind::AddressInUse
    );
}

#[test]
fn ipv6_unspecified_is_dual_stack_and_refuses_ipv4_on_its_port_tcp() {
    let port = free_ports(1);
    let dual = bind_tcp_stream_listener(v6_unspecified(port)).unwrap();
    assert!(
        !SockRef::from(&dual).only_v6().unwrap(),
        "[::] is dual stack"
    );
    for ip in ["0.0.0.0", "127.0.0.1"] {
        let err = bind_tcp_stream_listener(sa(ip, port)).unwrap_err();
        assert_eq!(err.kind, BindFailureKind::AddressInUse, "{ip}");
    }
    // And an IPv4 client reaches the dual-stack listener.
    let listener = TcpListener::from(dual);
    let _client = TcpStream::connect(sa("127.0.0.1", port)).unwrap();
    let (_, peer) = listener.accept().unwrap();
    assert!(peer.is_ipv6(), "IPv4 peers arrive IPv4-mapped: {peer}");
}

#[test]
fn ipv6_unspecified_udp_group_refuses_a_plain_ipv4_socket() {
    let port = free_ports(1);
    let group = bind_udp_group(v6_unspecified(port), 2).unwrap();
    for fd in &group {
        assert!(!SockRef::from(fd).only_v6().unwrap());
    }
    for ip in ["0.0.0.0", "127.0.0.1"] {
        let err = UdpSocket::bind(sa(ip, port)).unwrap_err();
        assert_eq!(
            BindFailureKind::from_io_error(&err),
            BindFailureKind::AddressInUse,
            "{ip}"
        );
    }
}

/// The kernel is no backstop between two same-user `SO_REUSEPORT` UDP
/// sockets: a second group on the port is admitted, on `0.0.0.0`,
/// `127.0.0.1` or the very same address, and joins or shadows the first.
/// Only the supervisor's own registry can refuse a second UDP binding on a
/// port this node already serves. Pinned so that fact cannot be forgotten.
#[test]
fn udp_reuseport_groups_of_one_user_are_not_refused_by_the_kernel() {
    let port = free_ports(1);
    let _dual = bind_udp_group(v6_unspecified(port), 2).unwrap();
    for addr in [
        sa("0.0.0.0", port),
        sa("127.0.0.1", port),
        v6_unspecified(port),
    ] {
        assert!(bind_udp_group(addr, 2).is_ok(), "{addr} was refused");
    }
}

#[test]
fn ipv6_literal_is_v6_only_and_coexists_with_ipv4_loopback() {
    for proto in [StreamProto::Tcp, StreamProto::Udp] {
        let port = free_ports(1);
        let v6_fds = match proto {
            StreamProto::Tcp => vec![bind_tcp_stream_listener(sa("::1", port)).unwrap()],
            StreamProto::Udp => bind_udp_group(sa("::1", port), 2).unwrap(),
        };
        for fd in &v6_fds {
            assert!(SockRef::from(fd).only_v6().unwrap(), "{proto} [::1]");
        }
        let v4_fds = match proto {
            StreamProto::Tcp => vec![bind_tcp_stream_listener(sa("127.0.0.1", port)).unwrap()],
            StreamProto::Udp => bind_udp_group(sa("127.0.0.1", port), 2).unwrap(),
        };
        assert!(!v4_fds.is_empty());
    }
}

#[test]
fn ipv6_only_is_set_explicitly_whatever_the_default() {
    // Every IPv6 socket the module creates carries an explicit value, so
    // the outcome is the rule's and never `net.ipv6.bindv6only`'s.
    let port = free_ports(1);
    let dual = bind_tcp_stream_listener(v6_unspecified(port)).unwrap();
    let literal = bind_tcp_stream_listener(sa("::1", free_ports(1))).unwrap();
    assert!(!SockRef::from(&dual).only_v6().unwrap());
    assert!(SockRef::from(&literal).only_v6().unwrap());
    let udp_dual = bind_udp_group(v6_unspecified(port), 1).unwrap();
    assert!(!SockRef::from(&udp_dual[0]).only_v6().unwrap());
}

#[test]
fn bind_range_is_all_or_nothing_and_names_the_failing_port() {
    for proto in [StreamProto::Tcp, StreamProto::Udp] {
        let base = free_ports(3);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let blocker: Box<dyn std::any::Any> = match proto {
            StreamProto::Tcp => Box::new(TcpListener::bind((ip, base + 1)).unwrap()),
            StreamProto::Udp => Box::new(UdpSocket::bind((ip, base + 1)).unwrap()),
        };
        let err = bind_range(proto, ip, base..=base + 2, 2).unwrap_err();
        assert_eq!(err.addr.port(), base + 1, "{proto}");
        assert_eq!(err.kind, BindFailureKind::AddressInUse);
        drop(blocker);

        // The port bound before the failure was released.
        let range = bind_range(proto, ip, base..=base + 2, 2).unwrap();
        let expected = match proto {
            StreamProto::Tcp => 1,
            StreamProto::Udp => 2,
        };
        assert_eq!(range.len(), 3);
        for (i, port) in range.iter().enumerate() {
            assert_eq!(port.addr, SocketAddr::new(ip, base + i as u16));
            assert_eq!(port.sockets.len(), expected);
        }
    }
}

#[test]
fn an_address_not_on_the_host_is_address_not_available() {
    // 192.0.2.10 is TEST-NET-1 (RFC 5737), never configured on a host.
    let err = bind_tcp_stream_listener(sa("192.0.2.10", 5432)).unwrap_err();
    assert_eq!(err.kind, BindFailureKind::AddressNotAvailable);
    let err = bind_udp_group(sa("192.0.2.10", 5432), 2).unwrap_err();
    assert_eq!(err.kind, BindFailureKind::AddressNotAvailable);
}
