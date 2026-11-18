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
//! where `reason` is a [`NackReason`] token, never free text. At the end
//! of an upgrade drain (Story 12.11 D-g), the worker's drain report,
//! under the seq of the `quiesce reason=upgrade` it answers:
//!
//! - `drained <seq> <closed>:<finished>:<stream_id>...`, as many as the
//!   entries need, each packed to the payload buffer ([`pack_drained`]);
//!   the stream id goes last because it is the one unvalidated string;
//! - then `drained_end <seq> <end> http_cut=<n> entries=<n>
//!   report=<complete|truncated>`, `end` a [`DrainEnd`] token and
//!   `entries` the number of entries the `drained` messages before it
//!   carried.
//!
//! The report is sent without waiting ([`send_drain_report`]): a send
//! that would block stops the entries and the end marker says
//! `truncated`. A worker never blocks its exit on its report.
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

/// Longest `drained <seq>` header.
const DRAINED_HEADER_MAX_LEN: usize = "drained".len() + 1 + U64_MAX_DIGITS;

/// Longest `<closed>:<finished>:<stream_id>` entry.
const DRAINED_ENTRY_MAX_LEN: usize = U64_MAX_DIGITS + 1 + U64_MAX_DIGITS + 1 + MAX_STREAM_ID_LEN;

/// Longest `drained_end` message.
const DRAINED_END_MAX_LEN: usize = "drained_end".len()
    + 1
    + U64_MAX_DIGITS
    + 1
    + DRAIN_END_MAX_LEN
    + " http_cut=".len()
    + U64_MAX_DIGITS
    + " entries=".len()
    + U64_MAX_DIGITS
    + " report=truncated".len();

/// Longest [`DrainEnd`] token.
const DRAIN_END_MAX_LEN: usize = "deadline".len();

const _: () = assert!(
    DRAINED_HEADER_MAX_LEN + 1 + DRAINED_ENTRY_MAX_LEN <= PAYLOAD_BUF_SIZE,
    "a drained message must carry at least one entry"
);

const _: () = assert!(
    DRAINED_END_MAX_LEN <= PAYLOAD_BUF_SIZE,
    "a drained_end message must fit the payload buffer"
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

/// Why a stream is quiesced. The worker closes what the drain leaves
/// with the end reason this maps to: `node_shutdown` for a stop,
/// `drained_by_upgrade` for a hot upgrade (Story 12.11 D-a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceReason {
    /// The process is stopping.
    Shutdown,
    /// A new generation took over the node's listening sockets; this one
    /// drains and exits.
    Upgrade,
}

impl QuiesceReason {
    /// Every reason, in wire order.
    pub const ALL: [QuiesceReason; 2] = [QuiesceReason::Shutdown, QuiesceReason::Upgrade];

    /// The wire token, the value of `reason=`.
    pub fn as_str(self) -> &'static str {
        match self {
            QuiesceReason::Shutdown => "shutdown",
            QuiesceReason::Upgrade => "upgrade",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// How a worker's drain ended, the `end` of a `drained_end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainEnd {
    /// No traffic was left before the deadline.
    Idle,
    /// The deadline passed with traffic still in flight.
    Deadline,
}

impl DrainEnd {
    /// Every end, in wire order.
    pub const ALL: [DrainEnd; 2] = [DrainEnd::Idle, DrainEnd::Deadline];

    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            DrainEnd::Idle => "idle",
            DrainEnd::Deadline => "deadline",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == s)
    }
}

/// One stream's line of a worker's drain report (Story 12.11 D-g).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedEntry {
    /// The stream.
    pub stream_id: String,
    /// Its connections and sessions that ended with `drained_by_upgrade`.
    pub closed: u64,
    /// Those marked draining for the upgrade that ended on their own.
    pub finished: u64,
}

impl DrainedEntry {
    fn to_token(&self) -> String {
        format!("{}:{}:{}", self.closed, self.finished, self.stream_id)
    }

    fn from_token(tok: &str) -> Result<Self, StreamCtlError> {
        let mut parts = tok.splitn(3, ':');
        let (Some(closed), Some(finished), Some(stream_id)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(StreamCtlError::Malformed(
                "a drained entry is closed:finished:stream_id",
            ));
        };
        Ok(DrainedEntry {
            closed: parse_u64(closed)?,
            finished: parse_u64(finished)?,
            stream_id: parse_stream_id(stream_id)?,
        })
    }
}

/// What a worker reports at the end of its upgrade drain, before the
/// wire splits it into messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReport {
    /// How the drain ended.
    pub end: DrainEnd,
    /// HTTP requests still in flight at the deadline, which the exit
    /// cuts; 0 when the drain ended idle.
    pub http_cut: u64,
    /// One entry per stream the upgrade drained something of.
    pub entries: Vec<DrainedEntry>,
}

/// What [`send_drain_report`] delivered: the end marker always, and the
/// entries before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportSent {
    /// Entries sent before the end marker.
    pub entries: u64,
    /// Whether a send would have blocked and the rest was left out.
    pub truncated: bool,
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
    /// Part of the drain report answering upgrade quiesce `seq`: one or
    /// more entries.
    Drained {
        seq: u64,
        entries: Vec<DrainedEntry>,
    },
    /// The end of the drain report answering upgrade quiesce `seq`.
    DrainedEnd {
        seq: u64,
        end: DrainEnd,
        http_cut: u64,
        /// Entries the `drained` messages before it carried.
        entries: u64,
        truncated: bool,
    },
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
            | StreamCtlMsg::Nack { seq, .. }
            | StreamCtlMsg::Drained { seq, .. }
            | StreamCtlMsg::DrainedEnd { seq, .. } => *seq,
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
            StreamCtlMsg::Drained { seq, entries } => {
                if entries.is_empty() {
                    return Err(StreamCtlError::Invalid(
                        "a drained message carries at least one entry",
                    ));
                }
                let mut payload = format!("drained {seq}");
                for entry in entries {
                    check_stream_id(&entry.stream_id).map_err(StreamCtlError::Invalid)?;
                    payload.push(' ');
                    payload.push_str(&entry.to_token());
                }
                if payload.len() > PAYLOAD_BUF_SIZE {
                    return Err(StreamCtlError::Invalid(
                        "a drained message must fit the payload buffer",
                    ));
                }
                Ok((payload, Vec::new()))
            }
            StreamCtlMsg::DrainedEnd {
                seq,
                end,
                http_cut,
                entries,
                truncated,
            } => Ok((
                format!(
                    "drained_end {seq} {} http_cut={http_cut} entries={entries} report={}",
                    end.as_str(),
                    if *truncated { "truncated" } else { "complete" }
                ),
                Vec::new(),
            )),
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
            ("drained", [seq, entries @ ..]) if !entries.is_empty() => Ok(StreamCtlMsg::Drained {
                seq: parse_u64(seq)?,
                entries: entries
                    .iter()
                    .map(|tok| DrainedEntry::from_token(tok))
                    .collect::<Result<_, _>>()?,
            }),
            ("drained_end", [seq, end, http_cut, entries, report]) => {
                Ok(StreamCtlMsg::DrainedEnd {
                    seq: parse_u64(seq)?,
                    end: DrainEnd::from_wire(end)
                        .ok_or(StreamCtlError::Malformed("unknown drain end"))?,
                    http_cut: parse_u64(keyed(http_cut, "http_cut")?)?,
                    entries: parse_u64(keyed(entries, "entries")?)?,
                    truncated: match keyed(report, "report")? {
                        "complete" => false,
                        "truncated" => true,
                        _ => return Err(StreamCtlError::Malformed("unknown report state")),
                    },
                })
            }
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

/// Split drain report `entries` into `drained` messages under `seq`, in
/// order, each as full as the payload buffer allows.
pub fn pack_drained(seq: u64, entries: Vec<DrainedEntry>) -> Vec<StreamCtlMsg> {
    let header = format!("drained {seq}").len();
    let mut messages = Vec::new();
    let mut current: Vec<DrainedEntry> = Vec::new();
    let mut len = header;
    for entry in entries {
        let entry_len = 1 + entry.to_token().len();
        if !current.is_empty() && len + entry_len > PAYLOAD_BUF_SIZE {
            messages.push(StreamCtlMsg::Drained {
                seq,
                entries: std::mem::take(&mut current),
            });
            len = header;
        }
        len += entry_len;
        current.push(entry);
    }
    if !current.is_empty() {
        messages.push(StreamCtlMsg::Drained {
            seq,
            entries: current,
        });
    }
    messages
}

/// Whether a send failed only because it would have blocked.
pub fn would_block(e: &StreamCtlError) -> bool {
    matches!(e, StreamCtlError::Send(Errno::EAGAIN))
}

/// Hand drain report `report` under `seq` to `try_send`, which never
/// waits and answers a send that would block with
/// [`StreamCtlError::Send`] of `EAGAIN`: the `drained` messages in order
/// until one would block, then the `drained_end` marker saying how many
/// entries went and whether the rest was left out.
///
/// # Errors
///
/// The error of the end marker's send, or of an entry's send that was
/// not a would-block: the supervisor then holds no complete report and
/// counts the worker as unreported.
pub fn deliver_drain_report(
    seq: u64,
    report: DrainReport,
    mut try_send: impl FnMut(StreamCtlMsg) -> Result<(), StreamCtlError>,
) -> Result<ReportSent, StreamCtlError> {
    let mut sent = ReportSent {
        entries: 0,
        truncated: false,
    };
    for msg in pack_drained(seq, report.entries) {
        let carried = match &msg {
            StreamCtlMsg::Drained { entries, .. } => entries.len() as u64,
            _ => 0,
        };
        match try_send(msg) {
            Ok(()) => sent.entries += carried,
            Err(e) if would_block(&e) => {
                sent.truncated = true;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    try_send(StreamCtlMsg::DrainedEnd {
        seq,
        end: report.end,
        http_cut: report.http_cut,
        entries: sent.entries,
        truncated: sent.truncated,
    })?;
    Ok(sent)
}

/// Send drain report `report` under `seq` on `sock` with
/// [`try_send_msg`]: never waits, whatever the socket's mode
/// ([`deliver_drain_report`]).
///
/// # Errors
///
/// As [`deliver_drain_report`].
pub fn send_drain_report(
    sock: impl AsFd,
    seq: u64,
    report: DrainReport,
) -> Result<ReportSent, StreamCtlError> {
    deliver_drain_report(seq, report, |msg| try_send_msg(&sock, &msg))
}

/// Send one message on the stream control channel. An `attach` passes its
/// sockets with `SCM_RIGHTS`; the caller keeps its own copies, the
/// receiver gets fresh descriptors of the same sockets.
///
/// Blocking or not follows the socket's mode; `EINTR` is retried and
/// `SIGPIPE` is never raised (`MSG_NOSIGNAL`).
pub fn send_msg(sock: impl AsFd, msg: &StreamCtlMsg) -> Result<(), StreamCtlError> {
    send_with(sock, msg, MsgFlags::MSG_NOSIGNAL)
}

/// [`send_msg`] that never waits, whatever the socket's mode
/// (`MSG_DONTWAIT`): a full socket buffer is [`StreamCtlError::Send`] of
/// `EAGAIN` ([`would_block`]).
pub fn try_send_msg(sock: impl AsFd, msg: &StreamCtlMsg) -> Result<(), StreamCtlError> {
    send_with(sock, msg, MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT)
}

fn send_with(sock: impl AsFd, msg: &StreamCtlMsg, flags: MsgFlags) -> Result<(), StreamCtlError> {
    let (payload, fds) = msg.encode()?;
    let iov = [IoSlice::new(payload.as_bytes())];
    let rights = [ControlMessage::ScmRights(&fds)];
    let cmsgs: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
    let raw = sock.as_fd().as_raw_fd();
    loop {
        match socket::sendmsg::<UnixAddr>(raw, &iov, cmsgs, flags, None) {
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
        for reason in QuiesceReason::ALL {
            match roundtrip(StreamCtlMsg::Quiesce {
                seq: 3,
                reason,
                drain_ms: 3_600_000,
            }) {
                StreamCtlMsg::Quiesce {
                    seq: 3,
                    reason: r,
                    drain_ms: 3_600_000,
                } => assert_eq!(r, reason),
                other => panic!("unexpected {other:?}"),
            }
        }
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
            (
                StreamCtlMsg::Quiesce {
                    seq: 9,
                    reason: QuiesceReason::Upgrade,
                    drain_ms: 250,
                },
                "quiesce 9 reason=upgrade drain_ms=250",
            ),
            (
                StreamCtlMsg::Drained {
                    seq: 9,
                    entries: vec![entry("s1", 3, 1), entry("s:2", 0, 7)],
                },
                "drained 9 3:1:s1 0:7:s:2",
            ),
            (
                StreamCtlMsg::DrainedEnd {
                    seq: 9,
                    end: DrainEnd::Deadline,
                    http_cut: 4,
                    entries: 2,
                    truncated: false,
                },
                "drained_end 9 deadline http_cut=4 entries=2 report=complete",
            ),
            (
                StreamCtlMsg::DrainedEnd {
                    seq: 9,
                    end: DrainEnd::Idle,
                    http_cut: 0,
                    entries: 0,
                    truncated: true,
                },
                "drained_end 9 idle http_cut=0 entries=0 report=truncated",
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
            "quiesce 1 reason=reload drain_ms=5",
            "quiesce 1 shutdown drain_ms=5",
            "drained 1",
            "drained 1 5:0",
            "drained 1 x:0:s1",
            "drained 1 1:2:",
            "drained_end 1 idle http_cut=0 entries=0",
            "drained_end 1 stopped http_cut=0 entries=0 report=complete",
            "drained_end 1 idle http_cut=0 entries=0 report=partial",
            "drained_end 1 idle cut=0 entries=0 report=complete",
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

    fn entry(stream_id: &str, closed: u64, finished: u64) -> DrainedEntry {
        DrainedEntry {
            stream_id: stream_id.into(),
            closed,
            finished,
        }
    }

    /// A canonical stream id numbered `n`, as the tracker holds them.
    fn uuid(n: usize) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }

    #[test]
    fn every_wire_list_holds_every_variant() {
        // Adding a variant breaks these matches until it is in `ALL`.
        for (i, reason) in QuiesceReason::ALL.into_iter().enumerate() {
            let position = match reason {
                QuiesceReason::Shutdown => 0,
                QuiesceReason::Upgrade => 1,
            };
            assert_eq!(i, position);
            assert_eq!(QuiesceReason::from_wire(reason.as_str()), Some(reason));
        }
        for (i, end) in DrainEnd::ALL.into_iter().enumerate() {
            let position = match end {
                DrainEnd::Idle => 0,
                DrainEnd::Deadline => 1,
            };
            assert_eq!(i, position);
            assert_eq!(DrainEnd::from_wire(end.as_str()), Some(end));
        }
    }

    #[test]
    fn drain_report_messages_round_trip() {
        let drained = StreamCtlMsg::Drained {
            seq: 4,
            entries: vec![entry(&uuid(1), u64::MAX, 0), entry("a:b:c", 0, 2)],
        };
        let StreamCtlMsg::Drained { seq, entries } = roundtrip(drained) else {
            panic!("expected drained");
        };
        assert_eq!(seq, 4);
        assert_eq!(
            entries,
            vec![entry(&uuid(1), u64::MAX, 0), entry("a:b:c", 0, 2)],
            "the stream id is last, so it may hold colons"
        );
        for end in DrainEnd::ALL {
            for truncated in [false, true] {
                let StreamCtlMsg::DrainedEnd {
                    seq,
                    end: e,
                    http_cut,
                    entries,
                    truncated: t,
                } = roundtrip(StreamCtlMsg::DrainedEnd {
                    seq: 4,
                    end,
                    http_cut: 12,
                    entries: 99,
                    truncated,
                })
                else {
                    panic!("expected drained_end");
                };
                assert_eq!((seq, e, http_cut, entries, t), (4, end, 12, 99, truncated));
            }
        }
    }

    #[test]
    fn longest_drained_end_matches_its_bound() {
        let msg = StreamCtlMsg::DrainedEnd {
            seq: u64::MAX,
            end: DrainEnd::Deadline,
            http_cut: u64::MAX,
            entries: u64::MAX,
            truncated: true,
        };
        assert_eq!(msg.encode().unwrap().0.len(), DRAINED_END_MAX_LEN);
        let longest_entry = entry(&"a".repeat(MAX_STREAM_ID_LEN), u64::MAX, u64::MAX);
        assert_eq!(longest_entry.to_token().len(), DRAINED_ENTRY_MAX_LEN);
        assert!(
            DrainEnd::ALL
                .iter()
                .all(|e| e.as_str().len() <= DRAIN_END_MAX_LEN),
            "DRAIN_END_MAX_LEN bounds every end token"
        );
    }

    #[test]
    fn an_empty_or_oversized_drained_message_is_refused() {
        assert!(matches!(
            StreamCtlMsg::Drained {
                seq: 1,
                entries: Vec::new()
            }
            .encode(),
            Err(StreamCtlError::Invalid(_))
        ));
        let too_many = (0..200)
            .map(|n| entry(&uuid(n), u64::MAX, u64::MAX))
            .collect();
        assert!(matches!(
            StreamCtlMsg::Drained {
                seq: 1,
                entries: too_many
            }
            .encode(),
            Err(StreamCtlError::Invalid(_))
        ));
    }

    #[test]
    fn packed_drained_messages_fill_the_buffer_and_keep_every_entry_in_order() {
        let entries: Vec<DrainedEntry> = (0..1_000)
            .map(|n| entry(&uuid(n), u64::MAX, n as u64))
            .collect();
        let messages = pack_drained(u64::MAX, entries.clone());
        assert!(messages.len() > 1, "a thousand entries need several");
        let mut unpacked = Vec::new();
        for (i, msg) in messages.iter().enumerate() {
            let (payload, _) = msg.encode().expect("every packed message encodes");
            assert!(payload.len() <= PAYLOAD_BUF_SIZE);
            if i + 1 < messages.len() {
                assert!(
                    payload.len() + 1 + DRAINED_ENTRY_MAX_LEN > PAYLOAD_BUF_SIZE,
                    "message {i} had room for another entry"
                );
            }
            let StreamCtlMsg::Drained { seq, entries } = msg else {
                panic!("expected drained");
            };
            assert_eq!(*seq, u64::MAX);
            unpacked.extend(entries.iter().cloned());
        }
        assert_eq!(unpacked, entries);
        assert!(pack_drained(1, Vec::new()).is_empty());
    }

    fn report(entries: usize) -> DrainReport {
        DrainReport {
            end: DrainEnd::Deadline,
            http_cut: 3,
            entries: (0..entries).map(|n| entry(&uuid(n), 1, 2)).collect(),
        }
    }

    #[test]
    fn a_drain_report_arrives_whole_over_a_seqpacket_pair() {
        let (supervisor, worker) = create_seqpacket_pair().unwrap();
        let sent = send_drain_report(&worker, 7, report(300)).expect("sent");
        assert_eq!(
            sent,
            ReportSent {
                entries: 300,
                truncated: false
            }
        );
        // The worker exits; what it queued is still read.
        drop(worker);
        let mut entries = Vec::new();
        loop {
            match recv_msg(&supervisor).expect("a queued message") {
                StreamCtlMsg::Drained { seq: 7, entries: e } => entries.extend(e),
                StreamCtlMsg::DrainedEnd {
                    seq: 7,
                    end,
                    http_cut,
                    entries: count,
                    truncated,
                } => {
                    assert_eq!((end, http_cut, truncated), (DrainEnd::Deadline, 3, false));
                    assert_eq!(count, entries.len() as u64);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(entries, report(300).entries);
        assert!(matches!(recv_msg(&supervisor), Err(StreamCtlError::Closed)));
    }

    #[test]
    fn a_send_that_would_block_truncates_the_report_and_never_waits() {
        let mut queue: Vec<StreamCtlMsg> = Vec::new();
        let sent = deliver_drain_report(7, report(300), |msg| {
            if matches!(msg, StreamCtlMsg::Drained { .. }) && !queue.is_empty() {
                return Err(StreamCtlError::Send(Errno::EAGAIN));
            }
            queue.push(msg);
            Ok(())
        })
        .expect("the end marker went");
        let first = match &queue[0] {
            StreamCtlMsg::Drained { entries, .. } => entries.len() as u64,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            sent,
            ReportSent {
                entries: first,
                truncated: true
            }
        );
        assert!(matches!(
            queue.last(),
            Some(StreamCtlMsg::DrainedEnd { entries, truncated: true, .. }) if *entries == first
        ));
    }

    #[test]
    fn a_full_socket_buffer_fails_the_report_at_once() {
        let (_supervisor, worker) = create_seqpacket_pair().unwrap();
        // Nobody reads the supervisor's end: fill the worker's send
        // buffer, in blocking mode, until a send would block.
        let filler = StreamCtlMsg::Refresh {
            seq: 1,
            drain_ms: 0,
        };
        while try_send_msg(&worker, &filler).is_ok() {}
        let started = std::time::Instant::now();
        let result = send_drain_report(&worker, 7, report(3));
        assert!(matches!(&result, Err(e) if would_block(e)), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
