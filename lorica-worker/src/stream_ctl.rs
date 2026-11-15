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

//! The runtime stream control channel between the supervisor and a worker.
//!
//! One `SOCK_SEQPACKET` socketpair per worker, created beside the legacy
//! command and RPC pairs. The worker's end travels in the fork bundle as
//! [`FdKind::StreamCtl`]. Unlike the two byte-stream channels, a
//! sequenced-packet socket keeps one message, its tokens and its
//! `SCM_RIGHTS` fds atomic, so stream sockets can be attached to a running
//! worker with the same token discipline as the fork bundle.
//!
//! A message is a text payload of space-separated tokens. Supervisor to
//! worker:
//!
//! - `attach <seq> <stream_id> <bind_gen> <token>...`, one `SCM_RIGHTS` fd
//!   per socket token, in order, at most [`ATTACH_MAX_SOCKETS`];
//! - `detach <seq> <stream_id> <bind_gen> drain_ms=<n>`;
//! - `refresh <seq> drain_ms=<n>`;
//! - `quiesce <seq> reason=<reason> drain_ms=<n>`;
//! - `caps <seq> <stream_id> <caps_gen> slot=<i> stream-caps:<caps_gen>`,
//!   exactly one `SCM_RIGHTS` fd: the memfd of the stream's caps region,
//!   and `i` the worker's shard index in it, which the worker does not
//!   otherwise know.
//!
//! Worker to supervisor: `ack <seq> <count>` or `nack <seq> <reason>`,
//! where `reason` is a [`NackReason`] token, never free text.
//!
//! Flow control is stop-and-wait per worker, owned by the sender: the
//! next message goes out only after the previous one's answer or its
//! timeout. That bounds the fds in flight per worker to one `attach`,
//! which matters because the kernel charges in-flight `SCM_RIGHTS` fds to
//! the sending user's `RLIMIT_NOFILE` and refuses past it with
//! `ETOOMANYREFS`. A binding with more sockets than one message carries
//! is split with [`chunk_sockets`].

use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr,
};

use crate::fd_passing::{
    recv_with_rights, FdKind, StreamProto, MAX_FDS, PAYLOAD_BUF_SIZE, U64_MAX_DIGITS,
};

/// Most sockets one `attach` message carries.
pub const ATTACH_MAX_SOCKETS: usize = MAX_FDS;

/// Longest stream id the channel carries. Stream ids are UUIDs (36
/// bytes); the bound leaves headroom while keeping the `attach` header
/// inside the payload buffer (see the assertion in `fd_passing`).
pub const MAX_STREAM_ID_LEN: usize = 64;

/// Longest `attach <seq> <stream_id> <bind_gen>` header.
pub(crate) const ATTACH_HEADER_MAX_LEN: usize =
    "attach".len() + 1 + U64_MAX_DIGITS + 1 + MAX_STREAM_ID_LEN + 1 + U64_MAX_DIGITS;

/// Longest decimal rendering of a `u32`.
const U32_MAX_DIGITS: usize = 10;

/// Longest `caps` message, its one fd token included.
const CAPS_MAX_LEN: usize = "caps".len()
    + 1
    + U64_MAX_DIGITS
    + 1
    + MAX_STREAM_ID_LEN
    + 1
    + U64_MAX_DIGITS
    + " slot=".len()
    + U32_MAX_DIGITS
    + " stream-caps:".len()
    + U64_MAX_DIGITS;

const _: () = assert!(
    CAPS_MAX_LEN <= PAYLOAD_BUF_SIZE,
    "a caps message must fit the payload buffer"
);

/// Errors of the stream control channel.
#[derive(Debug, thiserror::Error)]
pub enum StreamCtlError {
    #[error("failed to create the stream control socketpair: {0}")]
    SocketPair(nix::Error),

    #[error("failed to send a stream control message: {0}")]
    Send(nix::Error),

    #[error("failed to receive a stream control message: {0}")]
    Recv(nix::Error),

    #[error("stream control channel closed by the peer")]
    Closed,

    #[error("stream control message truncated: payload or fds were lost")]
    Truncated,

    #[error("malformed stream control message: {0}")]
    Malformed(&'static str),

    #[error("stream control message carries {fds} fds for {tokens} socket tokens")]
    FdCountMismatch { fds: usize, tokens: usize },

    #[error("refusing to send an invalid stream control message: {0}")]
    Invalid(&'static str),
}

/// Why a stream is quiesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceReason {
    /// The process is stopping.
    Shutdown,
}

impl QuiesceReason {
    /// The wire token, the value of `reason=`.
    pub fn as_str(self) -> &'static str {
        match self {
            QuiesceReason::Shutdown => "shutdown",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "shutdown" => Some(QuiesceReason::Shutdown),
            _ => None,
        }
    }
}

/// Why a worker refused a message. A closed set, so a `nack` never
/// carries free text across the process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackReason {
    /// The message was understood but its content was unusable.
    Malformed,
    /// A `detach` named a binding the worker does not hold.
    UnknownBinding,
    /// The worker could not adopt a socket of an `attach`.
    AdoptFailed,
    /// The worker is quiesced and takes no new binding.
    ShuttingDown,
    /// A `refresh` could not load the stream table; the worker keeps
    /// serving the previous one and drained nothing.
    TableUnavailable,
}

impl NackReason {
    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            NackReason::Malformed => "malformed",
            NackReason::UnknownBinding => "unknown_binding",
            NackReason::AdoptFailed => "adopt_failed",
            NackReason::ShuttingDown => "shutting_down",
            NackReason::TableUnavailable => "table_unavailable",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "malformed" => Some(NackReason::Malformed),
            "unknown_binding" => Some(NackReason::UnknownBinding),
            "adopt_failed" => Some(NackReason::AdoptFailed),
            "shutting_down" => Some(NackReason::ShuttingDown),
            "table_unavailable" => Some(NackReason::TableUnavailable),
            _ => None,
        }
    }
}

/// One socket of a stream binding, owned.
#[derive(Debug)]
pub struct StreamSocket {
    /// Transport protocol of the socket.
    pub proto: StreamProto,
    /// Bind address of the socket.
    pub addr: SocketAddr,
    /// The socket itself.
    pub fd: OwnedFd,
}

/// A stream control message. Fds are owned, so the same type serves the
/// `SCM_RIGHTS` transport between processes and an in-process channel in
/// single-process mode.
#[derive(Debug)]
pub enum StreamCtlMsg {
    /// Hand sockets of binding `bind_gen` of `stream_id` to the worker.
    Attach {
        seq: u64,
        stream_id: String,
        bind_gen: u64,
        sockets: Vec<StreamSocket>,
    },
    /// Stop serving binding `bind_gen` and drain its connections.
    Detach {
        seq: u64,
        stream_id: String,
        bind_gen: u64,
        drain_ms: u64,
    },
    /// Reload the stream table and drain what the new table removed.
    Refresh { seq: u64, drain_ms: u64 },
    /// Stop every accept loop and drain everything.
    Quiesce {
        seq: u64,
        reason: QuiesceReason,
        drain_ms: u64,
    },
    /// Hand the worker the caps region `caps_gen` of UDP stream
    /// `stream_id`, as the memfd `region`; `slot` is the worker's shard
    /// index in it. Sent before the stream's first `attach`, in a respawn
    /// replay before the `attach` replay, and when the region is replaced.
    Caps {
        seq: u64,
        stream_id: String,
        caps_gen: u64,
        slot: u32,
        region: OwnedFd,
    },
    /// The worker applied message `seq`; `count` is what it applied (the
    /// number of sockets adopted for an `attach`).
    Ack { seq: u64, count: u32 },
    /// The worker refused message `seq`.
    Nack { seq: u64, reason: NackReason },
}

impl StreamCtlMsg {
    /// The sequence number every message carries.
    pub fn seq(&self) -> u64 {
        match self {
            StreamCtlMsg::Attach { seq, .. }
            | StreamCtlMsg::Detach { seq, .. }
            | StreamCtlMsg::Refresh { seq, .. }
            | StreamCtlMsg::Quiesce { seq, .. }
            | StreamCtlMsg::Caps { seq, .. }
            | StreamCtlMsg::Ack { seq, .. }
            | StreamCtlMsg::Nack { seq, .. } => *seq,
        }
    }

    /// Render the payload and the fds to pass, refusing what the
    /// receiver would refuse.
    fn encode(&self) -> Result<(String, Vec<RawFd>), StreamCtlError> {
        match self {
            StreamCtlMsg::Attach {
                seq,
                stream_id,
                bind_gen,
                sockets,
            } => {
                check_stream_id(stream_id).map_err(StreamCtlError::Invalid)?;
                if sockets.is_empty() || sockets.len() > ATTACH_MAX_SOCKETS {
                    return Err(StreamCtlError::Invalid(
                        "an attach carries between one and ATTACH_MAX_SOCKETS sockets",
                    ));
                }
                let mut payload = format!("attach {seq} {stream_id} {bind_gen}");
                for s in sockets {
                    let kind = FdKind::StreamSocket {
                        proto: s.proto,
                        bind_gen: *bind_gen,
                        addr: s.addr,
                    };
                    payload.push(' ');
                    payload.push_str(&kind.to_token());
                }
                let fds = sockets.iter().map(|s| s.fd.as_raw_fd()).collect();
                Ok((payload, fds))
            }
            StreamCtlMsg::Detach {
                seq,
                stream_id,
                bind_gen,
                drain_ms,
            } => {
                check_stream_id(stream_id).map_err(StreamCtlError::Invalid)?;
                Ok((
                    format!("detach {seq} {stream_id} {bind_gen} drain_ms={drain_ms}"),
                    Vec::new(),
                ))
            }
            StreamCtlMsg::Refresh { seq, drain_ms } => {
                Ok((format!("refresh {seq} drain_ms={drain_ms}"), Vec::new()))
            }
            StreamCtlMsg::Quiesce {
                seq,
                reason,
                drain_ms,
            } => Ok((
                format!(
                    "quiesce {seq} reason={} drain_ms={drain_ms}",
                    reason.as_str()
                ),
                Vec::new(),
            )),
            StreamCtlMsg::Caps {
                seq,
                stream_id,
                caps_gen,
                slot,
                region,
            } => {
                check_stream_id(stream_id).map_err(StreamCtlError::Invalid)?;
                let token = FdKind::StreamCaps {
                    caps_gen: *caps_gen,
                }
                .to_token();
                Ok((
                    format!("caps {seq} {stream_id} {caps_gen} slot={slot} {token}"),
                    vec![region.as_raw_fd()],
                ))
            }
            StreamCtlMsg::Ack { seq, count } => Ok((format!("ack {seq} {count}"), Vec::new())),
            StreamCtlMsg::Nack { seq, reason } => {
                Ok((format!("nack {seq} {}", reason.as_str()), Vec::new()))
            }
        }
    }

    /// Parse a payload and adopt its fds. Every fd is owned from the
    /// start, so any refusal closes them all.
    fn decode(payload: &str, fds: Vec<OwnedFd>) -> Result<Self, StreamCtlError> {
        let tokens: Vec<&str> = payload.split_ascii_whitespace().collect();
        let (&verb, args) = tokens
            .split_first()
            .ok_or(StreamCtlError::Malformed("empty payload"))?;
        if verb != "attach" && verb != "caps" && !fds.is_empty() {
            return Err(StreamCtlError::FdCountMismatch {
                fds: fds.len(),
                tokens: 0,
            });
        }
        match (verb, args) {
            ("attach", [seq, stream_id, bind_gen, socket_tokens @ ..]) => {
                let bind_gen = parse_u64(bind_gen)?;
                if socket_tokens.is_empty() || socket_tokens.len() > ATTACH_MAX_SOCKETS {
                    return Err(StreamCtlError::Malformed(
                        "attach socket count out of range",
                    ));
                }
                if fds.len() != socket_tokens.len() {
                    return Err(StreamCtlError::FdCountMismatch {
                        fds: fds.len(),
                        tokens: socket_tokens.len(),
                    });
                }
                let mut sockets = Vec::with_capacity(fds.len());
                for (tok, fd) in socket_tokens.iter().zip(fds) {
                    match FdKind::from_token(tok) {
                        Ok(FdKind::StreamSocket {
                            proto,
                            bind_gen: token_gen,
                            addr,
                        }) if token_gen == bind_gen => {
                            sockets.push(StreamSocket { proto, addr, fd })
                        }
                        Ok(FdKind::StreamSocket { .. }) => {
                            return Err(StreamCtlError::Malformed(
                                "socket token bind_gen differs from the header",
                            ))
                        }
                        _ => return Err(StreamCtlError::Malformed("bad socket token")),
                    }
                }
                Ok(StreamCtlMsg::Attach {
                    seq: parse_u64(seq)?,
                    stream_id: parse_stream_id(stream_id)?,
                    bind_gen,
                    sockets,
                })
            }
            ("detach", [seq, stream_id, bind_gen, drain]) => Ok(StreamCtlMsg::Detach {
                seq: parse_u64(seq)?,
                stream_id: parse_stream_id(stream_id)?,
                bind_gen: parse_u64(bind_gen)?,
                drain_ms: parse_u64(keyed(drain, "drain_ms")?)?,
            }),
            ("refresh", [seq, drain]) => Ok(StreamCtlMsg::Refresh {
                seq: parse_u64(seq)?,
                drain_ms: parse_u64(keyed(drain, "drain_ms")?)?,
            }),
            ("quiesce", [seq, reason, drain]) => Ok(StreamCtlMsg::Quiesce {
                seq: parse_u64(seq)?,
                reason: QuiesceReason::from_wire(keyed(reason, "reason")?)
                    .ok_or(StreamCtlError::Malformed("unknown quiesce reason"))?,
                drain_ms: parse_u64(keyed(drain, "drain_ms")?)?,
            }),
            ("caps", [seq, stream_id, caps_gen, slot, token]) => {
                let [region] = <[OwnedFd; 1]>::try_from(fds).map_err(|fds| {
                    StreamCtlError::FdCountMismatch {
                        fds: fds.len(),
                        tokens: 1,
                    }
                })?;
                let caps_gen = parse_u64(caps_gen)?;
                match FdKind::from_token(token) {
                    Ok(FdKind::StreamCaps {
                        caps_gen: token_gen,
                    }) if token_gen == caps_gen => {}
                    Ok(FdKind::StreamCaps { .. }) => {
                        return Err(StreamCtlError::Malformed(
                            "caps token caps_gen differs from the header",
                        ))
                    }
                    _ => return Err(StreamCtlError::Malformed("bad caps token")),
                }
                Ok(StreamCtlMsg::Caps {
                    seq: parse_u64(seq)?,
                    stream_id: parse_stream_id(stream_id)?,
                    caps_gen,
                    slot: u32::try_from(parse_u64(keyed(slot, "slot")?)?)
                        .map_err(|_| StreamCtlError::Malformed("caps slot out of range"))?,
                    region,
                })
            }
            ("ack", [seq, count]) => Ok(StreamCtlMsg::Ack {
                seq: parse_u64(seq)?,
                count: u32::try_from(parse_u64(count)?)
                    .map_err(|_| StreamCtlError::Malformed("ack count out of range"))?,
            }),
            ("nack", [seq, reason]) => Ok(StreamCtlMsg::Nack {
                seq: parse_u64(seq)?,
                reason: NackReason::from_wire(reason)
                    .ok_or(StreamCtlError::Malformed("unknown nack reason"))?,
            }),
            _ => Err(StreamCtlError::Malformed("unknown verb or token count")),
        }
    }
}

/// Whether the channel can carry `id`: non-empty, at most
/// [`MAX_STREAM_ID_LEN`] bytes, printable ASCII without spaces.
///
/// The one rule both ends apply, public so the supervisor can refuse a
/// binding it could never attach before binding a socket for it.
///
/// # Errors
///
/// The reason the id cannot be carried.
pub fn check_stream_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() || id.len() > MAX_STREAM_ID_LEN {
        return Err("stream id length out of range");
    }
    if !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("stream id must be printable ASCII without spaces");
    }
    Ok(())
}

fn parse_stream_id(tok: &str) -> Result<String, StreamCtlError> {
    check_stream_id(tok).map_err(StreamCtlError::Malformed)?;
    Ok(tok.to_string())
}

fn parse_u64(tok: &str) -> Result<u64, StreamCtlError> {
    if tok.is_empty() || !tok.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StreamCtlError::Malformed("expected a decimal u64"));
    }
    tok.parse()
        .map_err(|_| StreamCtlError::Malformed("u64 out of range"))
}

fn keyed<'a>(tok: &'a str, key: &str) -> Result<&'a str, StreamCtlError> {
    tok.strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or(StreamCtlError::Malformed("missing key=value token"))
}

/// Create the stream control socketpair: `AF_UNIX`, `SOCK_SEQPACKET`,
/// both ends `SOCK_CLOEXEC`.
///
/// Returns `(supervisor_end, worker_end)`.
pub fn create_seqpacket_pair() -> Result<(OwnedFd, OwnedFd), StreamCtlError> {
    socket::socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(StreamCtlError::SocketPair)
}

/// Split a binding's sockets into groups of at most
/// [`ATTACH_MAX_SOCKETS`], in order, one group per `attach` message.
pub fn chunk_sockets(sockets: Vec<StreamSocket>) -> Vec<Vec<StreamSocket>> {
    let mut chunks: Vec<Vec<StreamSocket>> = Vec::new();
    let mut current: Vec<StreamSocket> = Vec::with_capacity(ATTACH_MAX_SOCKETS);
    for s in sockets {
        current.push(s);
        if current.len() == ATTACH_MAX_SOCKETS {
            chunks.push(std::mem::replace(
                &mut current,
                Vec::with_capacity(ATTACH_MAX_SOCKETS),
            ));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Send one message on the stream control channel. An `attach` passes its
/// sockets with `SCM_RIGHTS`; the caller keeps its own copies, the
/// receiver gets fresh descriptors of the same sockets.
///
/// Blocking or not follows the socket's mode; `EINTR` is retried and
/// `SIGPIPE` is never raised (`MSG_NOSIGNAL`).
pub fn send_msg(sock: impl AsFd, msg: &StreamCtlMsg) -> Result<(), StreamCtlError> {
    let (payload, fds) = msg.encode()?;
    let iov = [IoSlice::new(payload.as_bytes())];
    let rights = [ControlMessage::ScmRights(&fds)];
    let cmsgs: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
    let raw = sock.as_fd().as_raw_fd();
    loop {
        match socket::sendmsg::<UnixAddr>(raw, &iov, cmsgs, MsgFlags::MSG_NOSIGNAL, None) {
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(StreamCtlError::Send(e)),
        }
    }
}

/// Receive one message from the stream control channel.
///
/// Received fds are `CLOEXEC` (`MSG_CMSG_CLOEXEC`) and owned from the
/// moment `recvmsg` returns: a truncated message (`MSG_TRUNC` or
/// `MSG_CTRUNC`), a count mismatch or any parse failure closes every fd
/// that arrived. The peer closing its end yields
/// [`StreamCtlError::Closed`]. `EINTR` is retried; on a non-blocking
/// socket `EAGAIN` comes back as [`StreamCtlError::Recv`].
pub fn recv_msg(sock: impl AsFd) -> Result<StreamCtlMsg, StreamCtlError> {
    let mut buf = [0u8; PAYLOAD_BUF_SIZE];
    let raw = sock.as_fd().as_raw_fd();

    let received = loop {
        match recv_with_rights(raw, &mut buf, MsgFlags::MSG_CMSG_CLOEXEC) {
            Ok(received) => break received,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(StreamCtlError::Recv(e)),
        }
    };

    if received.truncated {
        return Err(StreamCtlError::Truncated);
    }
    if received.bytes == 0 && received.fds.is_empty() {
        return Err(StreamCtlError::Closed);
    }
    let payload = std::str::from_utf8(&buf[..received.bytes])
        .map_err(|_| StreamCtlError::Malformed("payload is not UTF-8"))?;
    StreamCtlMsg::decode(payload, received.fds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: StreamCtlMsg) -> StreamCtlMsg {
        let (payload, fds) = msg.encode().expect("encode");
        assert!(fds.is_empty(), "fd-less round trip only");
        StreamCtlMsg::decode(&payload, Vec::new()).expect("decode")
    }

    #[test]
    fn fd_less_messages_round_trip() {
        match roundtrip(StreamCtlMsg::Detach {
            seq: 1,
            stream_id: "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d".into(),
            bind_gen: u64::MAX,
            drain_ms: 30_000,
        }) {
            StreamCtlMsg::Detach {
                seq,
                stream_id,
                bind_gen,
                drain_ms,
            } => {
                assert_eq!(seq, 1);
                assert_eq!(stream_id, "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d");
                assert_eq!(bind_gen, u64::MAX);
                assert_eq!(drain_ms, 30_000);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            roundtrip(StreamCtlMsg::Refresh {
                seq: 2,
                drain_ms: 0
            }),
            StreamCtlMsg::Refresh {
                seq: 2,
                drain_ms: 0
            }
        ));
        assert!(matches!(
            roundtrip(StreamCtlMsg::Quiesce {
                seq: 3,
                reason: QuiesceReason::Shutdown,
                drain_ms: 3_600_000
            }),
            StreamCtlMsg::Quiesce {
                seq: 3,
                reason: QuiesceReason::Shutdown,
                drain_ms: 3_600_000
            }
        ));
        assert!(matches!(
            roundtrip(StreamCtlMsg::Ack { seq: 4, count: 32 }),
            StreamCtlMsg::Ack { seq: 4, count: 32 }
        ));
        for reason in [
            NackReason::Malformed,
            NackReason::UnknownBinding,
            NackReason::AdoptFailed,
            NackReason::ShuttingDown,
            NackReason::TableUnavailable,
        ] {
            match roundtrip(StreamCtlMsg::Nack { seq: 5, reason }) {
                StreamCtlMsg::Nack { seq: 5, reason: r } => assert_eq!(r, reason),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn wire_forms_are_the_documented_ones() {
        let cases = [
            (
                StreamCtlMsg::Detach {
                    seq: 9,
                    stream_id: "s1".into(),
                    bind_gen: 4,
                    drain_ms: 250,
                },
                "detach 9 s1 4 drain_ms=250",
            ),
            (
                StreamCtlMsg::Refresh {
                    seq: 9,
                    drain_ms: 250,
                },
                "refresh 9 drain_ms=250",
            ),
            (
                StreamCtlMsg::Quiesce {
                    seq: 9,
                    reason: QuiesceReason::Shutdown,
                    drain_ms: 250,
                },
                "quiesce 9 reason=shutdown drain_ms=250",
            ),
            (StreamCtlMsg::Ack { seq: 9, count: 3 }, "ack 9 3"),
            (
                StreamCtlMsg::Nack {
                    seq: 9,
                    reason: NackReason::UnknownBinding,
                },
                "nack 9 unknown_binding",
            ),
        ];
        for (msg, wire) in cases {
            assert_eq!(msg.encode().unwrap().0, wire);
        }
    }

    #[test]
    fn decode_refuses_malformed_payloads() {
        for bad in [
            "",
            "hello 1",
            "refresh 1",
            "refresh 1 drain=5",
            "refresh 1 drain_ms=",
            "refresh 1 drain_ms=-5",
            "refresh +1 drain_ms=5",
            "refresh 1 drain_ms=5 extra",
            "detach 1 s1 2",
            "quiesce 1 reason=upgrade drain_ms=5",
            "quiesce 1 shutdown drain_ms=5",
            "ack 1",
            "ack 1 -1",
            "nack 1 because",
            "attach 1 s1 2",
        ] {
            assert!(
                StreamCtlMsg::decode(bad, Vec::new()).is_err(),
                "{bad:?} was accepted"
            );
        }
        let long_id = "a".repeat(MAX_STREAM_ID_LEN + 1);
        assert!(
            StreamCtlMsg::decode(&format!("detach 1 {long_id} 2 drain_ms=5"), Vec::new()).is_err()
        );
    }

    #[test]
    fn encode_refuses_invalid_stream_ids() {
        for id in [
            String::new(),
            "a".repeat(MAX_STREAM_ID_LEN + 1),
            "has space".into(),
            "caf\u{e9}".into(),
        ] {
            let msg = StreamCtlMsg::Detach {
                seq: 1,
                stream_id: id.clone(),
                bind_gen: 1,
                drain_ms: 0,
            };
            assert!(
                matches!(msg.encode(), Err(StreamCtlError::Invalid(_))),
                "{id:?} was accepted"
            );
        }
        let at_bound = StreamCtlMsg::Detach {
            seq: 1,
            stream_id: "a".repeat(MAX_STREAM_ID_LEN),
            bind_gen: 1,
            drain_ms: 0,
        };
        assert!(at_bound.encode().is_ok());
    }

    fn memfd() -> OwnedFd {
        nix::sys::memfd::memfd_create(c"lorica-caps-unit", nix::sys::memfd::MFdFlags::MFD_CLOEXEC)
            .expect("memfd_create")
    }

    #[test]
    fn caps_wire_form_is_the_documented_one_and_round_trips() {
        let msg = StreamCtlMsg::Caps {
            seq: 9,
            stream_id: "s1".into(),
            caps_gen: 4,
            slot: 2,
            region: memfd(),
        };
        let (payload, fds) = msg.encode().unwrap();
        assert_eq!(payload, "caps 9 s1 4 slot=2 stream-caps:4");
        assert_eq!(fds.len(), 1);
        let StreamCtlMsg::Caps {
            seq,
            stream_id,
            caps_gen,
            slot,
            ..
        } = StreamCtlMsg::decode(&payload, vec![memfd()]).unwrap()
        else {
            panic!("expected caps");
        };
        assert_eq!((seq, stream_id.as_str(), caps_gen, slot), (9, "s1", 4, 2));
    }

    #[test]
    fn longest_caps_message_matches_its_bound() {
        let msg = StreamCtlMsg::Caps {
            seq: u64::MAX,
            stream_id: "a".repeat(MAX_STREAM_ID_LEN),
            caps_gen: u64::MAX,
            slot: u32::MAX,
            region: memfd(),
        };
        assert_eq!(msg.encode().unwrap().0.len(), CAPS_MAX_LEN);
    }

    #[test]
    fn caps_decode_refuses_a_wrong_fd_count_or_malformed_fields() {
        for count in [0, 2] {
            let fds = (0..count).map(|_| memfd()).collect();
            assert!(matches!(
                StreamCtlMsg::decode("caps 1 s1 2 slot=0 stream-caps:2", fds),
                Err(StreamCtlError::FdCountMismatch { fds, tokens: 1 }) if fds == count
            ));
        }
        for bad in [
            "caps 1 s1 2 slot=0 stream-caps:3",
            "caps 1 s1 2 slot=0 stream:udp:2:127.0.0.1:53",
            "caps 1 s1 2 0 stream-caps:2",
            "caps 1 s1 2 slot=x stream-caps:2",
            "caps 1 s1 2 slot=4294967296 stream-caps:2",
            "caps 1 s1 2 slot=0",
            "caps 1 s1 2 slot=0 stream-caps:2 extra",
        ] {
            assert!(
                StreamCtlMsg::decode(bad, vec![memfd()]).is_err(),
                "{bad:?} was accepted"
            );
        }
    }

    #[test]
    fn longest_attach_header_matches_its_bound() {
        let header = format!(
            "attach {} {} {}",
            u64::MAX,
            "a".repeat(MAX_STREAM_ID_LEN),
            u64::MAX
        );
        assert_eq!(header.len(), ATTACH_HEADER_MAX_LEN);
    }
}
