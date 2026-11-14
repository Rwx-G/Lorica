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

//! Lorica: a sans-IO parser for the PROXY protocol, versions 1 and 2.
//!
//! This module does not exist upstream: it is an additive Lorica-only file
//! of the fork (`FORK.md`, "Lorica divergences in forked crates"), which an
//! upstream sync leaves alone. It is std only and not behind any feature,
//! so the HTTP listeners of this crate and the stream plane of
//! `lorica-stream` both build on it.
//!
//! The parser reads bytes and returns a verdict. It does no I/O, owns no
//! timer and knows nothing of trust: the caller reads from the socket,
//! applies [`HEADER_READ_TIMEOUT`], decides whether the peer may send a
//! header at all, and hands back to the client every byte after
//! the `consumed` length of [`Parsed::Complete`].
//!
//! Parsing is strict. A v1 line follows the specification's grammar to the
//! byte (single spaces, decimal ports without a sign or a leading zero, the
//! family matching both addresses) and is at most [`V1_MAX_LEN`] bytes. A
//! v2 header has version 2, a `LOCAL` or `PROXY` command, a defined
//! address family and transport, an address block as long as its family
//! needs, and a TLV area whose every entry fits in the declared length.
//! TLV contents are not interpreted, and `PP2_TYPE_CRC32C` is not checked:
//! the TLVs stay reachable through [`Header::tlvs`] for a consumer that
//! needs them.
//!
//! Specification: <https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt>

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// The largest header either version may occupy, in bytes. A v2 header
/// whose declared length takes it past this bound is
/// [`ParseError::Oversized`] as soon as its fixed part is read, before
/// the rest arrives.
pub const MAX_HEADER_LEN: usize = 4096;

/// How long after accept a caller waits for a complete header before it
/// gives up on the connection. A load balancer writes the header with the
/// connection, so this only ever bounds a peer that stalls.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest v1 line the specification allows, CRLF included. A line
/// with no CRLF within this many bytes is [`ParseError::Malformed`].
pub const V1_MAX_LEN: usize = 107;

/// The bytes every v1 header starts with.
pub const V1_SIGNATURE: &[u8; 6] = b"PROXY ";

/// The bytes every v2 header starts with.
pub const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Length of the fixed part of a v2 header: the signature, the version
/// and command byte, the family byte and the 16-bit length.
const V2_FIXED_LEN: usize = 16;

/// Address block lengths of the v2 families, per the specification.
const V2_INET_LEN: usize = 12;
const V2_INET6_LEN: usize = 36;
const V2_UNIX_LEN: usize = 216;

const NO_TLVS: Tlvs<'static> = Tlvs { remaining: &[] };

/// What the first bytes of a stream say about a PROXY header, as told by
/// [`classify_prefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    /// The stream opens with the v1 signature, `PROXY `.
    V1,
    /// The stream opens with the 12-byte v2 signature.
    V2,
    /// The bytes diverge from both signatures: whatever follows is not a
    /// PROXY header.
    NotProxy,
    /// Every byte so far matches one of the signatures, which is not yet
    /// complete. Empty input is `NeedMore`.
    NeedMore,
}

/// The protocol version a header was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// The human-readable line format.
    V1,
    /// The binary format.
    V2,
}

/// The command of a header. A v1 header is always [`Command::Proxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// The connection was made by the sender itself (a health check, for
    /// instance): the socket's own addresses are the real ones.
    Local,
    /// The connection is relayed on behalf of the client the header names.
    Proxy,
}

/// The addresses a header carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    /// No usable address: a v2 `LOCAL` header, a v2 `AF_UNSPEC` family, or
    /// a v1 `UNKNOWN` line. The socket's own addresses apply.
    Unspecified,
    /// A TCP connection (v1 `TCP4` / `TCP6`, v2 `STREAM` over
    /// `AF_INET` / `AF_INET6`).
    Tcp {
        /// The client the connection was relayed for.
        source: SocketAddr,
        /// The address the client connected to.
        destination: SocketAddr,
    },
    /// A UDP flow (v2 `DGRAM` over `AF_INET` / `AF_INET6`). An HTTP
    /// listener has no use for it and refuses it.
    Udp {
        /// The client the flow was relayed for.
        source: SocketAddr,
        /// The address the client sent to.
        destination: SocketAddr,
    },
    /// v2 `AF_UNIX`. The paths are not client addresses any control can
    /// use, so they are validated for length and not kept.
    Unix,
}

/// A parsed PROXY header. It borrows the TLV area from the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'a> {
    /// The version the header was written in.
    pub version: Version,
    /// `LOCAL` or `PROXY`.
    pub command: Command,
    /// The carried addresses, IPv4-mapped IPv6 addresses canonicalised to
    /// IPv4.
    pub addresses: Addresses,
    /// The v2 TLVs as `(type, value)`, already validated: iterating never
    /// fails. Always empty for v1 and for a v2 `LOCAL` header.
    pub tlvs: Tlvs<'a>,
}

/// An iterator over the TLVs of a v2 header, yielding `(type, value)`.
///
/// Built only by [`parse`] over an area whose structure it has validated,
/// so every entry is complete. Clone it to iterate more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlvs<'a> {
    remaining: &'a [u8],
}

impl Tlvs<'_> {
    /// Whether the header carried no TLV.
    pub fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (kind, value, rest) = split_tlv(self.remaining).ok()??;
        self.remaining = rest;
        Some((kind, value))
    }
}

/// The result of a successful call to [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// Every byte so far is consistent with a header that is not complete
    /// yet: read more and call again with the whole buffer.
    Incomplete,
    /// A complete header.
    Complete {
        /// The header.
        header: Header<'a>,
        /// The header's length in bytes. Bytes after it belong to the
        /// client and must be handed on.
        consumed: usize,
    },
}

/// Why a buffer is not a PROXY header. Each variant carries a short static
/// detail for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The bytes break the grammar of the version they claim.
    Malformed(&'static str),
    /// The header is longer than [`MAX_HEADER_LEN`].
    Oversized(&'static str),
    /// A well-formed v2 header uses a version, command, family or
    /// transport this parser does not accept.
    Unsupported(&'static str),
}

impl ParseError {
    /// The static detail of the refusal.
    pub fn detail(&self) -> &'static str {
        match self {
            ParseError::Malformed(detail)
            | ParseError::Oversized(detail)
            | ParseError::Unsupported(detail) => detail,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            ParseError::Malformed(_) => "malformed",
            ParseError::Oversized(_) => "oversized",
            ParseError::Unsupported(_) => "unsupported",
        };
        write!(f, "{kind} PROXY header: {}", self.detail())
    }
}

impl std::error::Error for ParseError {}

/// Tells from the first bytes of a stream whether it opens with a PROXY
/// signature, without parsing further.
///
/// The answer is final as soon as the bytes diverge from both signatures,
/// so a direct client is told apart on its first byte or within a few:
/// a TLS record starts with `0x16`, and an HTTP method shares at most
/// `P` with `PROXY ` before diverging. It reads at most 12 bytes.
pub fn classify_prefix(buf: &[u8]) -> Prefix {
    if buf.is_empty() {
        return Prefix::NeedMore;
    }
    for (signature, complete) in [
        (V1_SIGNATURE.as_slice(), Prefix::V1),
        (V2_SIGNATURE.as_slice(), Prefix::V2),
    ] {
        let compared = buf.len().min(signature.len());
        if buf[..compared] == signature[..compared] {
            return if compared == signature.len() {
                complete
            } else {
                Prefix::NeedMore
            };
        }
    }
    Prefix::NotProxy
}

/// Parses a PROXY header, v1 or v2, at the start of `buf`.
///
/// Call it with everything read from the connection so far. It answers
/// [`Parsed::Incomplete`] while the bytes are consistent with a header
/// that has not fully arrived, and the same [`Parsed::Complete`] however
/// the header was split across reads. Bytes after the header are never
/// counted in `consumed`. A buffer that does not open with a PROXY
/// signature is [`ParseError::Malformed`]; use [`classify_prefix`] first
/// where a header is optional.
///
/// A refusal is final: no longer buffer starting with the same bytes is
/// accepted.
///
/// # Example
///
/// ```
/// use lorica_core::protocols::proxy_protocol::{parse, Addresses, Parsed};
///
/// let wire = b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\nGET / HTTP/1.1\r\n";
/// let Parsed::Complete { header, consumed } = parse(wire).unwrap() else {
///     panic!("the header is complete");
/// };
/// let Addresses::Tcp { source, destination } = header.addresses else {
///     panic!("a TCP4 line carries TCP addresses");
/// };
/// assert_eq!(source, "192.0.2.10:51000".parse().unwrap());
/// assert_eq!(destination, "198.51.100.1:443".parse().unwrap());
/// assert_eq!(&wire[consumed..], b"GET / HTTP/1.1\r\n");
///
/// // A header cut short is not an error yet.
/// assert_eq!(parse(&wire[..20]), Ok(Parsed::Incomplete));
/// ```
pub fn parse(buf: &[u8]) -> Result<Parsed<'_>, ParseError> {
    match classify_prefix(buf) {
        Prefix::NeedMore => Ok(Parsed::Incomplete),
        Prefix::NotProxy => Err(ParseError::Malformed("no PROXY protocol signature")),
        Prefix::V1 => parse_v1(buf),
        Prefix::V2 => parse_v2(buf),
    }
}

fn parse_v1(buf: &[u8]) -> Result<Parsed<'_>, ParseError> {
    let window = &buf[..buf.len().min(V1_MAX_LEN)];
    let mut line_end = None;
    for (index, &byte) in window.iter().enumerate() {
        match byte {
            b'\r' => match window.get(index + 1) {
                Some(b'\n') => {
                    line_end = Some(index);
                    break;
                }
                Some(_) => return Err(ParseError::Malformed("v1 CR not followed by LF")),
                None => {}
            },
            b' '..=b'~' => {}
            _ => return Err(ParseError::Malformed("v1 line holds a non-printable byte")),
        }
    }
    let Some(line_end) = line_end else {
        return if buf.len() >= V1_MAX_LEN {
            Err(ParseError::Malformed(
                "v1 line has no CRLF within 107 bytes",
            ))
        } else {
            Ok(Parsed::Incomplete)
        };
    };

    // The window only holds printable ASCII before the CRLF.
    let line = std::str::from_utf8(&window[V1_SIGNATURE.len()..line_end])
        .map_err(|_| ParseError::Malformed("v1 line is not ASCII"))?;
    let addresses = parse_v1_fields(line)?;
    Ok(Parsed::Complete {
        header: Header {
            version: Version::V1,
            command: Command::Proxy,
            addresses,
            tlvs: NO_TLVS,
        },
        consumed: line_end + 2,
    })
}

/// Parses what follows `PROXY ` on a v1 line, CRLF excluded.
fn parse_v1_fields(line: &str) -> Result<Addresses, ParseError> {
    if line == "UNKNOWN" || line.starts_with("UNKNOWN ") {
        // The specification has the receiver ignore whatever follows
        // UNKNOWN up to the CRLF.
        return Ok(Addresses::Unspecified);
    }
    let mut fields = line.split(' ');
    let family = fields.next().unwrap_or_default();
    let (Some(source), Some(destination), Some(source_port), Some(destination_port), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(ParseError::Malformed(
            "v1 line does not have exactly four fields after the family",
        ));
    };
    let parse_ip: fn(&str) -> Result<IpAddr, ParseError> = match family {
        "TCP4" => parse_v1_ipv4,
        "TCP6" => parse_v1_ipv6,
        _ => {
            return Err(ParseError::Malformed(
                "v1 family is not TCP4, TCP6 or UNKNOWN",
            ))
        }
    };
    let source = SocketAddr::new(parse_ip(source)?, parse_v1_port(source_port)?);
    let destination = SocketAddr::new(parse_ip(destination)?, parse_v1_port(destination_port)?);
    Ok(Addresses::Tcp {
        source,
        destination,
    })
}

fn parse_v1_ipv4(text: &str) -> Result<IpAddr, ParseError> {
    text.parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .map_err(|_| ParseError::Malformed("v1 address is not an IPv4 address of family TCP4"))
}

fn parse_v1_ipv6(text: &str) -> Result<IpAddr, ParseError> {
    text.parse::<Ipv6Addr>()
        .map(|ip| IpAddr::V6(ip).to_canonical())
        .map_err(|_| ParseError::Malformed("v1 address is not an IPv6 address of family TCP6"))
}

/// A decimal port in 0..=65535, digits only, no leading zero.
fn parse_v1_port(text: &str) -> Result<u16, ParseError> {
    const BAD_PORT: ParseError =
        ParseError::Malformed("v1 port is not a decimal in 0..=65535 without a leading zero");
    let digits_only = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits_only || (text.len() > 1 && text.starts_with('0')) {
        return Err(BAD_PORT);
    }
    text.parse::<u16>().map_err(|_| BAD_PORT)
}

fn parse_v2(buf: &[u8]) -> Result<Parsed<'_>, ParseError> {
    let Some(fixed) = buf.get(..V2_FIXED_LEN) else {
        return Ok(Parsed::Incomplete);
    };
    let version = fixed[12] >> 4;
    let command = fixed[12] & 0x0F;
    let family = fixed[13];
    let declared = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));

    if version != 2 {
        return Err(ParseError::Unsupported("v2 version nibble is not 2"));
    }
    let command = match command {
        0x0 => Command::Local,
        0x1 => Command::Proxy,
        _ => {
            return Err(ParseError::Unsupported(
                "v2 command is neither LOCAL nor PROXY",
            ))
        }
    };
    let consumed = V2_FIXED_LEN + declared;
    if consumed > MAX_HEADER_LEN {
        return Err(ParseError::Oversized(
            "v2 declared length exceeds the 4096-byte header bound",
        ));
    }
    let Some(block) = buf.get(V2_FIXED_LEN..consumed) else {
        return Ok(Parsed::Incomplete);
    };

    if command == Command::Local {
        // The specification has the receiver discard the whole protocol
        // block of a LOCAL header, family included, and use the socket's
        // own addresses.
        return Ok(Parsed::Complete {
            header: Header {
                version: Version::V2,
                command,
                addresses: Addresses::Unspecified,
                tlvs: NO_TLVS,
            },
            consumed,
        });
    }

    let (address_len, transport_is_stream) = match family {
        0x00 => (0, true),
        0x11 => (V2_INET_LEN, true),
        0x12 => (V2_INET_LEN, false),
        0x21 => (V2_INET6_LEN, true),
        0x22 => (V2_INET6_LEN, false),
        0x31 | 0x32 => (V2_UNIX_LEN, true),
        _ => {
            return Err(ParseError::Unsupported(
                "v2 address family or transport is not defined",
            ))
        }
    };
    let Some(address_block) = block.get(..address_len) else {
        return Err(ParseError::Malformed(
            "v2 address block is shorter than its family requires",
        ));
    };
    let tlv_area = &block[address_len..];
    validate_tlvs(tlv_area)?;

    let addresses = match family {
        0x00 => Addresses::Unspecified,
        0x31 | 0x32 => Addresses::Unix,
        _ => {
            let (source, destination) = v2_socket_addresses(address_block);
            if transport_is_stream {
                Addresses::Tcp {
                    source,
                    destination,
                }
            } else {
                Addresses::Udp {
                    source,
                    destination,
                }
            }
        }
    };
    Ok(Parsed::Complete {
        header: Header {
            version: Version::V2,
            command,
            addresses,
            tlvs: Tlvs {
                remaining: tlv_area,
            },
        },
        consumed,
    })
}

/// Reads the source and destination of an `AF_INET` (12-byte) or
/// `AF_INET6` (36-byte) address block, whose length the caller checked.
fn v2_socket_addresses(block: &[u8]) -> (SocketAddr, SocketAddr) {
    let port = |at: usize| u16::from_be_bytes([block[at], block[at + 1]]);
    if block.len() == V2_INET_LEN {
        let ip = |at: usize| {
            IpAddr::V4(Ipv4Addr::new(
                block[at],
                block[at + 1],
                block[at + 2],
                block[at + 3],
            ))
        };
        (
            SocketAddr::new(ip(0), port(8)),
            SocketAddr::new(ip(4), port(10)),
        )
    } else {
        let ip = |at: usize| {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[at..at + 16]);
            IpAddr::V6(Ipv6Addr::from(octets)).to_canonical()
        };
        (
            SocketAddr::new(ip(0), port(32)),
            SocketAddr::new(ip(16), port(34)),
        )
    }
}

/// Splits the first TLV off `area` into its type, its value and the rest:
/// `Ok(None)` on an empty area.
fn split_tlv(area: &[u8]) -> Result<Option<(u8, &[u8], &[u8])>, ParseError> {
    let Some((&kind, rest)) = area.split_first() else {
        return Ok(None);
    };
    let Some(length) = rest.get(..2) else {
        return Err(ParseError::Malformed(
            "v2 TLV area ends inside a TLV's type and length",
        ));
    };
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let Some(value) = rest.get(2..2 + length) else {
        return Err(ParseError::Malformed(
            "v2 TLV value runs past the declared header length",
        ));
    };
    Ok(Some((kind, value, &rest[2 + length..])))
}

fn validate_tlvs(mut area: &[u8]) -> Result<(), ParseError> {
    while let Some((_, _, rest)) = split_tlv(area)? {
        area = rest;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    fn sock(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn complete(buf: &[u8]) -> (Header<'_>, usize) {
        match parse(buf) {
            Ok(Parsed::Complete { header, consumed }) => (header, consumed),
            other => panic!("expected a complete header, got {other:?}"),
        }
    }

    fn tcp(source: &str, destination: &str) -> Addresses {
        Addresses::Tcp {
            source: sock(source),
            destination: sock(destination),
        }
    }

    /// A v2 header: `ver_cmd`, `family`, then `body` as the protocol block,
    /// its length declared from `body`.
    fn v2(ver_cmd: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut wire = V2_SIGNATURE.to_vec();
        wire.push(ver_cmd);
        wire.push(family);
        wire.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(body);
        wire
    }

    fn inet_block() -> Vec<u8> {
        let mut block = vec![192, 0, 2, 10, 198, 51, 100, 1];
        block.extend_from_slice(&51000u16.to_be_bytes());
        block.extend_from_slice(&443u16.to_be_bytes());
        block
    }

    fn inet6_block(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
        let mut block = source.octets().to_vec();
        block.extend_from_slice(&destination.octets());
        block.extend_from_slice(&51000u16.to_be_bytes());
        block.extend_from_slice(&443u16.to_be_bytes());
        block
    }

    fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut entry = vec![kind];
        entry.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(value);
        entry
    }

    fn assert_malformed(buf: &[u8]) {
        assert!(
            matches!(parse(buf), Err(ParseError::Malformed(_))),
            "{:?} gave {:?}",
            String::from_utf8_lossy(buf),
            parse(buf)
        );
    }

    #[test]
    fn v1_tcp4() {
        let wire = b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n";
        let (header, consumed) = complete(wire);
        assert_eq!(header.version, Version::V1);
        assert_eq!(header.command, Command::Proxy);
        assert_eq!(
            header.addresses,
            tcp("192.0.2.10:51000", "198.51.100.1:443")
        );
        assert!(header.tlvs.is_empty());
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn v1_tcp6_and_port_extremes() {
        let wire = b"PROXY TCP6 2001:db8::10 2001:db8::1 0 65535\r\n";
        let (header, consumed) = complete(wire);
        assert_eq!(
            header.addresses,
            tcp("[2001:db8::10]:0", "[2001:db8::1]:65535")
        );
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn v1_tcp6_mapped_addresses_are_canonicalised_to_ipv4() {
        let (header, _) = complete(b"PROXY TCP6 ::ffff:192.0.2.10 ::ffff:c633:6401 1 2\r\n");
        assert_eq!(header.addresses, tcp("192.0.2.10:1", "198.51.100.1:2"));
    }

    #[test]
    fn v1_unknown_with_and_without_trailing_fields() {
        for wire in [
            b"PROXY UNKNOWN\r\n".as_slice(),
            b"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n",
        ] {
            let (header, consumed) = complete(wire);
            assert_eq!(header.addresses, Addresses::Unspecified);
            assert_eq!(header.command, Command::Proxy);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn v1_line_bound_is_107_bytes_crlf_included() {
        let mut at_bound = b"PROXY UNKNOWN ".to_vec();
        at_bound.resize(V1_MAX_LEN - 2, b'x');
        at_bound.extend_from_slice(b"\r\n");
        assert_eq!(at_bound.len(), V1_MAX_LEN);
        assert_eq!(complete(&at_bound).1, V1_MAX_LEN);

        let mut past_bound = b"PROXY UNKNOWN ".to_vec();
        past_bound.resize(V1_MAX_LEN - 1, b'x');
        past_bound.extend_from_slice(b"\r\n");
        assert_malformed(&past_bound);

        // The refusal comes at 107 bytes, not at the 4 KiB bound.
        let mut no_crlf = b"PROXY UNKNOWN ".to_vec();
        no_crlf.resize(V1_MAX_LEN - 1, b'x');
        assert_eq!(parse(&no_crlf), Ok(Parsed::Incomplete));
        no_crlf.push(b'x');
        assert_malformed(&no_crlf);
    }

    #[test]
    fn v1_refusals() {
        for wire in [
            // spacing
            "PROXY TCP4  192.0.2.10 198.51.100.1 51000 443\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000 443 \r\n",
            "PROXY  TCP4 192.0.2.10 198.51.100.1 51000 443\r\n",
            "PROXY TCP4\t192.0.2.10 198.51.100.1 51000 443\r\n",
            // field count
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000 443 80\r\n",
            "PROXY TCP4\r\n",
            "PROXY \r\n",
            // family
            "PROXY tcp4 192.0.2.10 198.51.100.1 51000 443\r\n",
            "PROXY UDP4 192.0.2.10 198.51.100.1 51000 443\r\n",
            "PROXY UNKNOWNX\r\n",
            // family mismatch
            "PROXY TCP4 2001:db8::10 2001:db8::1 51000 443\r\n",
            "PROXY TCP4 192.0.2.10 2001:db8::1 51000 443\r\n",
            "PROXY TCP6 192.0.2.10 198.51.100.1 51000 443\r\n",
            "PROXY TCP6 2001:db8::10 198.51.100.1 51000 443\r\n",
            // addresses
            "PROXY TCP4 192.0.2.010 198.51.100.1 51000 443\r\n",
            "PROXY TCP4 192.0.2 198.51.100.1 51000 443\r\n",
            "PROXY TCP4 192.0.2.256 198.51.100.1 51000 443\r\n",
            "PROXY TCP6 [2001:db8::10] 2001:db8::1 51000 443\r\n",
            // ports
            "PROXY TCP4 192.0.2.10 198.51.100.1 65536 443\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 051000 443\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 +51000 443\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 -1 443\r\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 0x50 443\r\n",
            // line ending
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\n",
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\rX",
            "PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\r\n",
        ] {
            assert_malformed(wire.as_bytes());
        }
        assert_malformed(b"PROXY TCP4 192.0.2.10\x00 198.51.100.1 1 2\r\n");
        assert_malformed(b"PROXY TCP4 192.0.2.\xc3\xa9 198.51.100.1 1 2\r\n");
        // Refused on the offending byte, not once 107 bytes have arrived.
        assert_malformed(b"PROXY \x16");
        assert_malformed(b"PROXY TCP4 \rX");
        assert_malformed(b"PROXY TCP4 192.0.2.10\n");
    }

    #[test]
    fn v2_tcp4_with_tlvs() {
        let mut body = inet_block();
        let alpn = tlv(0x01, b"h2");
        let noop = tlv(0x04, b"");
        let authority = tlv(0x02, b"example.com");
        body.extend_from_slice(&alpn);
        body.extend_from_slice(&noop);
        body.extend_from_slice(&authority);
        let wire = v2(0x21, 0x11, &body);
        let (header, consumed) = complete(&wire);
        assert_eq!(header.version, Version::V2);
        assert_eq!(header.command, Command::Proxy);
        assert_eq!(
            header.addresses,
            tcp("192.0.2.10:51000", "198.51.100.1:443")
        );
        let tlvs: Vec<(u8, &[u8])> = header.tlvs.clone().collect();
        assert_eq!(
            tlvs,
            vec![
                (0x01, b"h2".as_slice()),
                (0x04, b"".as_slice()),
                (0x02, b"example.com".as_slice())
            ]
        );
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn v2_tcp6_udp4_udp6() {
        let source: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let addresses = complete(&v2(0x21, 0x21, &inet6_block(source, destination)))
            .0
            .addresses;
        assert_eq!(addresses, tcp("[2001:db8::10]:51000", "[2001:db8::1]:443"));

        let addresses = complete(&v2(0x21, 0x12, &inet_block())).0.addresses;
        assert_eq!(
            addresses,
            Addresses::Udp {
                source: sock("192.0.2.10:51000"),
                destination: sock("198.51.100.1:443"),
            }
        );

        let addresses = complete(&v2(0x21, 0x22, &inet6_block(source, destination)))
            .0
            .addresses;
        assert_eq!(
            addresses,
            Addresses::Udp {
                source: sock("[2001:db8::10]:51000"),
                destination: sock("[2001:db8::1]:443"),
            }
        );
    }

    #[test]
    fn v2_mapped_addresses_are_canonicalised_to_ipv4() {
        let source = Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped();
        let destination = Ipv4Addr::new(198, 51, 100, 1).to_ipv6_mapped();
        let addresses = complete(&v2(0x21, 0x21, &inet6_block(source, destination)))
            .0
            .addresses;
        assert_eq!(addresses, tcp("192.0.2.10:51000", "198.51.100.1:443"));
    }

    #[test]
    fn v2_unspec_and_unix_carry_no_address() {
        let wire = v2(0x21, 0x00, &[]);
        let (header, consumed) = complete(&wire);
        assert_eq!(header.addresses, Addresses::Unspecified);
        assert_eq!(consumed, V2_FIXED_LEN);

        let wire = v2(0x21, 0x00, &tlv(0x04, b"pad"));
        let (header, _) = complete(&wire);
        assert_eq!(header.addresses, Addresses::Unspecified);
        assert_eq!(header.tlvs.count(), 1);

        for family in [0x31, 0x32] {
            let addresses = complete(&v2(0x21, family, &[0u8; V2_UNIX_LEN])).0.addresses;
            assert_eq!(addresses, Addresses::Unix);
        }
    }

    #[test]
    fn v2_local_discards_the_protocol_block() {
        for (family, body) in [
            (0x00, Vec::new()),
            (0x11, inet_block()),
            // The family of a LOCAL header is not interpreted at all.
            (0xFF, vec![0xAA; 5]),
        ] {
            let wire = v2(0x20, family, &body);
            let (header, consumed) = complete(&wire);
            assert_eq!(header.command, Command::Local);
            assert_eq!(header.addresses, Addresses::Unspecified);
            assert!(header.tlvs.is_empty());
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn v2_unsupported() {
        for (ver_cmd, family) in [
            (0x11, 0x11), // version 1 in the binary format
            (0x31, 0x11), // version 3
            (0x22, 0x11), // command 2
            (0x2F, 0x11), // command 15
            (0x21, 0x10), // AF_INET over AF_UNSPEC transport
            (0x21, 0x13), // transport 3
            (0x21, 0x01), // AF_UNSPEC with a transport
            (0x21, 0x41), // family 4
        ] {
            let wire = v2(ver_cmd, family, &inet_block());
            assert!(
                matches!(parse(&wire), Err(ParseError::Unsupported(_))),
                "{ver_cmd:#x} {family:#x} gave {:?}",
                parse(&wire)
            );
        }
    }

    #[test]
    fn v2_address_block_shorter_than_its_family() {
        for (family, needed) in [
            (0x11, V2_INET_LEN),
            (0x12, V2_INET_LEN),
            (0x21, V2_INET6_LEN),
            (0x22, V2_INET6_LEN),
            (0x31, V2_UNIX_LEN),
            (0x32, V2_UNIX_LEN),
        ] {
            assert_malformed(&v2(0x21, family, &vec![0u8; needed - 1]));
            assert!(complete(&v2(0x21, family, &vec![0u8; needed])).1 > 0);
        }
    }

    #[test]
    fn v2_tlv_structure_is_validated() {
        let mut one_byte_left = inet_block();
        one_byte_left.extend_from_slice(&tlv(0x01, b"h2"));
        one_byte_left.push(0x04);
        assert_malformed(&v2(0x21, 0x11, &one_byte_left));

        let mut two_bytes_left = inet_block();
        two_bytes_left.extend_from_slice(&[0x04, 0x00]);
        assert_malformed(&v2(0x21, 0x11, &two_bytes_left));

        let mut overrun = inet_block();
        overrun.extend_from_slice(&[0x02, 0x00, 0x05, b'a', b'b']);
        assert_malformed(&v2(0x21, 0x11, &overrun));
    }

    #[test]
    fn v2_oversized_is_refused_on_the_fixed_part_alone() {
        let largest = MAX_HEADER_LEN - V2_FIXED_LEN;
        let mut body = inet_block();
        let padding = largest - body.len() - 3;
        body.extend_from_slice(&tlv(0x04, &vec![0u8; padding]));
        let wire = v2(0x21, 0x11, &body);
        assert_eq!(wire.len(), MAX_HEADER_LEN);
        assert_eq!(complete(&wire).1, MAX_HEADER_LEN);

        let mut fixed = V2_SIGNATURE.to_vec();
        fixed.extend_from_slice(&[0x21, 0x11]);
        fixed.extend_from_slice(&u16::try_from(largest + 1).unwrap().to_be_bytes());
        assert!(matches!(parse(&fixed), Err(ParseError::Oversized(_))));
        fixed[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(parse(&fixed), Err(ParseError::Oversized(_))));
    }

    #[test]
    fn not_a_proxy_signature_is_malformed() {
        for wire in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"\x16\x03\x01\x02\x00",
            b"PROXX TCP4",
            b"\r\n\r\n\0\r\nQUIX\n",
        ] {
            assert_malformed(wire);
        }
        assert_eq!(parse(b""), Ok(Parsed::Incomplete));
    }

    #[test]
    fn classify_prefix_on_every_prefix_of_both_signatures() {
        assert_eq!(classify_prefix(b""), Prefix::NeedMore);
        for len in 1..V1_SIGNATURE.len() {
            assert_eq!(classify_prefix(&V1_SIGNATURE[..len]), Prefix::NeedMore);
        }
        for len in 1..V2_SIGNATURE.len() {
            assert_eq!(classify_prefix(&V2_SIGNATURE[..len]), Prefix::NeedMore);
        }
        assert_eq!(classify_prefix(V1_SIGNATURE), Prefix::V1);
        assert_eq!(classify_prefix(V2_SIGNATURE), Prefix::V2);
        assert_eq!(classify_prefix(b"PROXY TCP4 "), Prefix::V1);
        let mut v2_header = V2_SIGNATURE.to_vec();
        v2_header.push(0x21);
        assert_eq!(classify_prefix(&v2_header), Prefix::V2);
    }

    #[test]
    fn classify_prefix_on_direct_clients() {
        for request in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"POST / HTTP/1.1\r\n",
            b"PUT / HTTP/1.1\r\n",
            b"PATCH / HTTP/1.1\r\n",
            b"PROPFIND / HTTP/1.1\r\n",
            b"\x16\x03\x01\x02\x00\x01",
            b"\r\nGET / HTTP/1.1\r\n",
        ] {
            assert_eq!(classify_prefix(request), Prefix::NotProxy);
            // Decided as soon as the bytes diverge from both signatures.
            let decided_at = (1..=request.len())
                .find(|&len| classify_prefix(&request[..len]) != Prefix::NeedMore)
                .unwrap();
            assert!(decided_at <= 5, "{request:?} decided at {decided_at}");
            assert_eq!(classify_prefix(&request[..decided_at]), Prefix::NotProxy);
        }
        assert_eq!(classify_prefix(b"G"), Prefix::NotProxy);
        assert_eq!(classify_prefix(b"\x16"), Prefix::NotProxy);
        assert_eq!(classify_prefix(b"P"), Prefix::NeedMore);
        assert_eq!(classify_prefix(b"PO"), Prefix::NotProxy);
        assert_eq!(classify_prefix(b"\r\n"), Prefix::NeedMore);
        assert_eq!(classify_prefix(b"\r\nG"), Prefix::NotProxy);
    }

    fn valid_headers() -> Vec<Vec<u8>> {
        let mut with_tlvs = inet_block();
        with_tlvs.extend_from_slice(&tlv(0x01, b"http/1.1"));
        with_tlvs.extend_from_slice(&tlv(0xEA, &[7u8; 40]));
        vec![
            b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n".to_vec(),
            b"PROXY TCP6 2001:db8::10 2001:db8::1 51000 443\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            v2(0x21, 0x11, &with_tlvs),
            v2(
                0x21,
                0x21,
                &inet6_block(
                    "2001:db8::10".parse().unwrap(),
                    "2001:db8::1".parse().unwrap(),
                ),
            ),
            v2(0x20, 0x00, &[]),
        ]
    }

    #[test]
    fn split_at_every_byte_boundary() {
        for header in valid_headers() {
            let mut wire = header.clone();
            wire.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let expected = parse(&header).unwrap();
            let Parsed::Complete { consumed, .. } = expected else {
                panic!("{header:?} is a complete header");
            };
            assert_eq!(consumed, header.len());
            for cut in 0..header.len() {
                assert_eq!(
                    parse(&wire[..cut]),
                    Ok(Parsed::Incomplete),
                    "{header:?} cut at {cut}"
                );
            }
            for cut in header.len()..=wire.len() {
                assert_eq!(parse(&wire[..cut]).as_ref(), Ok(&expected), "cut at {cut}");
            }
        }
    }

    #[test]
    fn client_bytes_after_the_header_are_never_consumed() {
        for header in valid_headers() {
            // Client bytes that would themselves parse as a header, or
            // complete a v1 line if the parser read past its CRLF.
            for client in [
                b"\r\n".as_slice(),
                b"PROXY TCP4 192.0.2.99 198.51.100.1 1 2\r\n",
                [0u8; 64].as_slice(),
            ] {
                let mut wire = header.clone();
                wire.extend_from_slice(client);
                assert_eq!(complete(&wire).1, header.len());
            }
        }
    }

    /// Random bytes, and random mutations of valid headers, never panic,
    /// and a complete header never claims more than it was given or more
    /// than the bound.
    #[test]
    fn randomized_inputs_never_panic() {
        let mut rng = StdRng::seed_from_u64(0x5052_4f58_5920_7632);
        let seeds = valid_headers();
        for _ in 0..200_000 {
            let mut input = match rng.random_range(0..4) {
                0 => {
                    let len = rng.random_range(0..256);
                    (0..len).map(|_| rng.random::<u8>()).collect::<Vec<u8>>()
                }
                1 => {
                    let mut input = V2_SIGNATURE.to_vec();
                    let len = rng.random_range(0..300);
                    input.extend((0..len).map(|_| rng.random::<u8>()));
                    input
                }
                _ => seeds[rng.random_range(0..seeds.len())].clone(),
            };
            for _ in 0..rng.random_range(0..4) {
                if input.is_empty() {
                    break;
                }
                let at = rng.random_range(0..input.len());
                match rng.random_range(0..3) {
                    0 => input[at] = rng.random::<u8>(),
                    1 => input.truncate(at),
                    _ => input.insert(at, rng.random::<u8>()),
                }
            }
            let _ = classify_prefix(&input);
            if let Ok(Parsed::Complete { header, consumed }) = parse(&input) {
                assert!(consumed <= input.len());
                assert!(consumed <= MAX_HEADER_LEN);
                let tlv_bytes: usize = header.tlvs.map(|(_, value)| 3 + value.len()).sum();
                assert!(tlv_bytes <= consumed);
            }
        }
    }

    #[test]
    fn error_display_names_the_kind_and_the_detail() {
        let error = parse(b"PROXY TCP5 a b 1 2\r\n").unwrap_err();
        assert!(matches!(error, ParseError::Malformed(_)));
        assert_eq!(
            error.to_string(),
            format!("malformed PROXY header: {}", error.detail())
        );
    }
}
