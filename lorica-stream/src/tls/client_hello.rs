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

//! The bounded ClientHello reader of Story 12.4 (D-b).
//!
//! [`parse`] reads the TLS record layer and the ClientHello only far
//! enough to answer four things: the server name, the offered ALPN list in
//! the client's order, whether an `encrypted_client_hello` extension is
//! present, and how many bytes the hello took. It is not rustls'
//! `Acceptor`: a passthrough stream must not impose the acceptance policy
//! of a TLS stack Lorica does not run for that traffic, the bytes must be
//! replayed to the backend exactly as read, and no TLS state is held per
//! pending connection.
//!
//! The reader is incremental over one buffer: the engine appends what the
//! socket gives to a [`CLIENTHELLO_BUFFER`]-byte buffer and calls
//! [`parse`] on the whole of it again, until it answers or refuses. Every
//! call reparses from the first byte; the bounds make that cheap. Every
//! refusal happens as early as the bytes allow, so a client cannot hold a
//! connection open with a hello that will never be accepted.
//!
//! No I/O, no clock and no allocation beyond the answer itself (and, for
//! a hello spread over several records, one copy of the message): the
//! deadline and the socket are the engine's.

use std::fmt;
use std::net::IpAddr;

use lorica_config::route_selection::canonical_hostname;

/// The longest handshake message accepted, in bytes, the 24-bit length
/// of the ClientHello's handshake header: TLSPlaintext's record limit, and
/// nginx's `preread_buffer_size` default.
pub const CLIENTHELLO_MAX_LEN: usize = 16_384;

/// The most records a ClientHello may span, so a client fragmenting its
/// hello into one-byte records cannot make the reader walk thousands of
/// headers.
pub const CLIENTHELLO_MAX_RECORDS: usize = 64;

/// The size of the read buffer a TLS stream allocates once per connection
/// for its pending phase: 16 KiB plus headers. It is the TCP engine's
/// preamble buffer too, so bytes read past the ClientHello stay in it and
/// are replayed with it.
pub const CLIENTHELLO_BUFFER: usize = 17_408;

/// The length of a TLS record header: content type, version, length.
pub const RECORD_HEADER_LEN: usize = 5;

/// The largest record payload TLSPlaintext allows.
pub const MAX_RECORD_LEN: usize = 16_384;

/// The length of a handshake message header: type and 24-bit length.
const HANDSHAKE_HEADER_LEN: usize = 4;

/// The record content type of a handshake.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// The handshake type of a ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// The record versions a ClientHello record may carry: TLS 1.0 (sent by
/// clients of every version for compatibility) to TLS 1.3.
const RECORD_VERSIONS: std::ops::RangeInclusive<u16> = 0x0301..=0x0304;

/// The extension carrying the server name (RFC 6066).
pub const EXTENSION_SERVER_NAME: u16 = 0;

/// The extension carrying the offered ALPN protocols (RFC 7301).
pub const EXTENSION_ALPN: u16 = 16;

/// The extension of Encrypted Client Hello.
pub const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// The `host_name` type of a `server_name` entry.
const SERVER_NAME_HOST_NAME: u8 = 0;

/// The longest server name accepted, in bytes: the longest DNS name.
pub const SERVER_NAME_MAX_LEN: usize = 253;

/// The longest `session_id` a ClientHello carries.
const SESSION_ID_MAX_LEN: usize = 32;

/// The length of the ClientHello's `random`.
const RANDOM_LEN: usize = 32;

// The buffer holds a hello of the largest accepted message spread over
// the most accepted records, so a hello the parser would accept never
// needs more room than the engine allocates.
const _: () = assert!(
    HANDSHAKE_HEADER_LEN + CLIENTHELLO_MAX_LEN + CLIENTHELLO_MAX_RECORDS * RECORD_HEADER_LEN
        <= CLIENTHELLO_BUFFER
);

/// What a complete ClientHello tells a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The first `host_name` of the `server_name` extension, in
    /// `canonical_hostname` form (ASCII lowercase, one trailing dot
    /// dropped), the form a stream's rules are stored in. `None` without
    /// the extension, and for a name that is an IP address, which RFC 6066
    /// forbids and rustls reports as absent too.
    pub server_name: Option<String>,
    /// Every protocol of the ALPN extension, in the client's order, as
    /// sent (GREASE values included); empty without the extension.
    pub alpn: Vec<Vec<u8>>,
    /// Whether an `encrypted_client_hello` extension is present. With
    /// ECH, `server_name` is the outer hello's public name.
    pub ech_offered: bool,
    /// The bytes the records holding the hello took, from the first byte
    /// of the buffer. Bytes past it are the client's next flight.
    pub consumed: usize,
}

/// Why a ClientHello was refused. The connection ends
/// `refused(invalid_client_hello)` with nothing forwarded; the engine
/// counts [`InvalidClientHello::Oversized`] apart from the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidClientHello {
    /// A record other than a handshake before the hello is complete, an
    /// SSLv2-compatible hello included.
    NotHandshake,
    /// A record version outside TLS 1.0 to TLS 1.3.
    RecordVersion,
    /// A record of length 0 or over [`MAX_RECORD_LEN`].
    RecordLength,
    /// A handshake message other than a ClientHello.
    NotClientHello,
    /// A message over [`CLIENTHELLO_MAX_LEN`], or spread over more than
    /// [`CLIENTHELLO_MAX_RECORDS`] records.
    Oversized,
    /// A length that runs past what encloses it.
    Truncated,
    /// A field outside its own rule: a session id over 32 bytes, an odd
    /// or empty cipher suite list, no compression method, an empty name
    /// or protocol list, an empty protocol name, or bytes past the end of
    /// what they belong to.
    Malformed,
    /// Two extensions of one type (RFC 8446 section 4.2).
    DuplicateExtension,
    /// A server name with a byte outside ASCII letters, digits, `-`, `_`
    /// and `.`, empty, or over [`SERVER_NAME_MAX_LEN`] bytes.
    ServerName,
}

impl InvalidClientHello {
    /// Every refusal, the list a counter or a log reader derives its words
    /// from.
    pub const ALL: [InvalidClientHello; 9] = [
        Self::NotHandshake,
        Self::RecordVersion,
        Self::RecordLength,
        Self::NotClientHello,
        Self::Oversized,
        Self::Truncated,
        Self::Malformed,
        Self::DuplicateExtension,
        Self::ServerName,
    ];

    /// The snake_case word this refusal is logged as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotHandshake => "not_handshake",
            Self::RecordVersion => "record_version",
            Self::RecordLength => "record_length",
            Self::NotClientHello => "not_client_hello",
            Self::Oversized => "oversized",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::DuplicateExtension => "duplicate_extension",
            Self::ServerName => "server_name",
        }
    }
}

/// Why [`parse`] gave no answer yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloError {
    /// Every byte so far is valid and the hello is not complete: read
    /// more and call [`parse`] again on the whole buffer.
    NeedMore,
    /// The bytes cannot be the start of an accepted ClientHello.
    Invalid(InvalidClientHello),
}

impl fmt::Display for ClientHelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientHelloError::NeedMore => f.write_str("the ClientHello is not complete"),
            ClientHelloError::Invalid(kind) => {
                write!(f, "invalid ClientHello: {}", kind.as_str())
            }
        }
    }
}

impl std::error::Error for ClientHelloError {}

impl From<InvalidClientHello> for ClientHelloError {
    fn from(kind: InvalidClientHello) -> ClientHelloError {
        ClientHelloError::Invalid(kind)
    }
}

/// Read the ClientHello at the start of `buf`.
///
/// # Errors
///
/// [`ClientHelloError::NeedMore`] while every byte so far is valid and the
/// hello is incomplete; [`ClientHelloError::Invalid`] as soon as the bytes
/// cannot be an accepted hello, whatever would follow.
///
/// ```
/// use lorica_stream::tls::client_hello::{parse, ClientHelloError, InvalidClientHello};
/// assert_eq!(parse(&[]), Err(ClientHelloError::NeedMore));
/// assert_eq!(parse(&[22, 3]), Err(ClientHelloError::NeedMore));
/// assert_eq!(
///     parse(b"GET / HTTP/1.1\r\n"),
///     Err(ClientHelloError::Invalid(InvalidClientHello::NotHandshake))
/// );
/// ```
pub fn parse(buf: &[u8]) -> Result<Parsed, ClientHelloError> {
    let records: Records = walk_records(buf)?;
    let message: std::borrow::Cow<'_, [u8]> = if records.count == 1 {
        let (start, end) = records.fragments[0];
        std::borrow::Cow::Borrowed(&buf[start..end])
    } else {
        let mut message: Vec<u8> = Vec::with_capacity(records.message_len);
        for &(start, end) in &records.fragments[..records.count] {
            message.extend_from_slice(&buf[start..end]);
        }
        std::borrow::Cow::Owned(message)
    };
    let mut hello: Parsed = parse_body(&message[HANDSHAKE_HEADER_LEN..])?;
    hello.consumed = records.consumed;
    Ok(hello)
}

/// The records a complete hello spans.
struct Records {
    /// The payload range of each record, `count` of them.
    fragments: [(usize, usize); CLIENTHELLO_MAX_RECORDS],
    count: usize,
    /// The handshake message's length, its header included.
    message_len: usize,
    /// The end of the last record.
    consumed: usize,
}

/// Walk the record layer until the handshake message is complete,
/// refusing what the bytes so far already rule out.
fn walk_records(buf: &[u8]) -> Result<Records, ClientHelloError> {
    let mut fragments: [(usize, usize); CLIENTHELLO_MAX_RECORDS] =
        [(0, 0); CLIENTHELLO_MAX_RECORDS];
    let mut count: usize = 0;
    let mut pos: usize = 0;
    let mut payload_total: usize = 0;
    let mut header: [u8; HANDSHAKE_HEADER_LEN] = [0; HANDSHAKE_HEADER_LEN];
    let mut header_have: usize = 0;
    let mut message_len: Option<usize> = None;
    loop {
        let Some(&content_type) = buf.get(pos) else {
            return Err(ClientHelloError::NeedMore);
        };
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(InvalidClientHello::NotHandshake.into());
        }
        if count == CLIENTHELLO_MAX_RECORDS {
            return Err(InvalidClientHello::Oversized.into());
        }
        if let Some(&major) = buf.get(pos + 1) {
            if major != 3 {
                return Err(InvalidClientHello::RecordVersion.into());
            }
        }
        let Some(record_header) = buf.get(pos..pos + RECORD_HEADER_LEN) else {
            if let Some(&minor) = buf.get(pos + 2) {
                if !RECORD_VERSIONS.contains(&u16::from_be_bytes([3, minor])) {
                    return Err(InvalidClientHello::RecordVersion.into());
                }
            }
            return Err(ClientHelloError::NeedMore);
        };
        let version: u16 = u16::from_be_bytes([record_header[1], record_header[2]]);
        if !RECORD_VERSIONS.contains(&version) {
            return Err(InvalidClientHello::RecordVersion.into());
        }
        let length: usize = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
        if length == 0 || length > MAX_RECORD_LEN {
            return Err(InvalidClientHello::RecordLength.into());
        }
        let start: usize = pos + RECORD_HEADER_LEN;
        let end: usize = start + length;
        fragments[count] = (start, end);
        count += 1;
        payload_total += length;

        // The handshake header, as soon as its bytes are here, whichever
        // records they arrived in.
        let available: &[u8] = &buf[start.min(buf.len())..end.min(buf.len())];
        for &byte in available.iter().take(HANDSHAKE_HEADER_LEN - header_have) {
            header[header_have] = byte;
            header_have += 1;
        }
        if header_have >= 1 && header[0] != HANDSHAKE_CLIENT_HELLO {
            return Err(InvalidClientHello::NotClientHello.into());
        }
        if message_len.is_none() && header_have == HANDSHAKE_HEADER_LEN {
            let body_len: usize = (usize::from(header[1]) << 16)
                | (usize::from(header[2]) << 8)
                | usize::from(header[3]);
            if body_len > CLIENTHELLO_MAX_LEN {
                return Err(InvalidClientHello::Oversized.into());
            }
            message_len = Some(HANDSHAKE_HEADER_LEN + body_len);
        }
        if let Some(message_len) = message_len {
            // Nothing follows a ClientHello in the client's first
            // handshake flight, so a record running past the message is
            // refused rather than waited for.
            if payload_total > message_len {
                return Err(InvalidClientHello::Malformed.into());
            }
        }
        if buf.len() < end {
            return Err(ClientHelloError::NeedMore);
        }
        pos = end;
        if message_len == Some(payload_total) {
            return Ok(Records {
                fragments,
                count,
                message_len: payload_total,
                consumed: pos,
            });
        }
    }
}

/// A cursor over one length-delimited field.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], InvalidClientHello> {
        if n > self.data.len() {
            return Err(InvalidClientHello::Truncated);
        }
        let (taken, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, InvalidClientHello> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, InvalidClientHello> {
        let bytes: &[u8] = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// The field after a one-byte length.
    fn vec8(&mut self) -> Result<&'a [u8], InvalidClientHello> {
        let len: usize = usize::from(self.u8()?);
        self.take(len)
    }

    /// The field after a two-byte length.
    fn vec16(&mut self) -> Result<&'a [u8], InvalidClientHello> {
        let len: usize = usize::from(self.u16()?);
        self.take(len)
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The ClientHello body: version, random, session id, cipher suites,
/// compression methods, then extensions if any bytes remain.
fn parse_body(body: &[u8]) -> Result<Parsed, InvalidClientHello> {
    let mut reader = Reader { data: body };
    reader.take(2)?; // legacy_version
    reader.take(RANDOM_LEN)?;
    if reader.vec8()?.len() > SESSION_ID_MAX_LEN {
        return Err(InvalidClientHello::Malformed);
    }
    let suites: &[u8] = reader.vec16()?;
    if suites.is_empty() || !suites.len().is_multiple_of(2) {
        return Err(InvalidClientHello::Malformed);
    }
    if reader.vec8()?.is_empty() {
        return Err(InvalidClientHello::Malformed);
    }
    let mut hello = Parsed {
        server_name: None,
        alpn: Vec::new(),
        ech_offered: false,
        consumed: 0,
    };
    if reader.is_empty() {
        return Ok(hello);
    }
    let mut extensions = Reader {
        data: reader.vec16()?,
    };
    if !reader.is_empty() {
        return Err(InvalidClientHello::Malformed);
    }
    let mut seen: ExtensionSet = ExtensionSet::default();
    while !extensions.is_empty() {
        let kind: u16 = extensions.u16()?;
        let data: &[u8] = extensions.vec16()?;
        if !seen.insert(kind) {
            return Err(InvalidClientHello::DuplicateExtension);
        }
        match kind {
            EXTENSION_SERVER_NAME => hello.server_name = server_name(data)?,
            EXTENSION_ALPN => hello.alpn = alpn(data)?,
            EXTENSION_ENCRYPTED_CLIENT_HELLO => hello.ech_offered = true,
            _ => {}
        }
    }
    Ok(hello)
}

/// The extension types met so far: one bit per type, on the stack.
struct ExtensionSet([u64; 1024]);

impl Default for ExtensionSet {
    fn default() -> ExtensionSet {
        ExtensionSet([0; 1024])
    }
}

impl ExtensionSet {
    /// Record `kind`; `false` when it was already there.
    fn insert(&mut self, kind: u16) -> bool {
        let word: &mut u64 = &mut self.0[usize::from(kind >> 6)];
        let bit: u64 = 1 << (kind & 63);
        let fresh: bool = *word & bit == 0;
        *word |= bit;
        fresh
    }
}

/// The first `host_name` of a `server_name` extension (RFC 6066 section
/// 3), every entry's length checked.
fn server_name(data: &[u8]) -> Result<Option<String>, InvalidClientHello> {
    let mut outer = Reader { data };
    let mut entries = Reader {
        data: outer.vec16()?,
    };
    if !outer.is_empty() || entries.is_empty() {
        return Err(InvalidClientHello::Malformed);
    }
    let mut host_name: Option<&[u8]> = None;
    while !entries.is_empty() {
        let name_type: u8 = entries.u8()?;
        let name: &[u8] = entries.vec16()?;
        if name_type == SERVER_NAME_HOST_NAME && host_name.is_none() {
            host_name = Some(name);
        }
    }
    let Some(name) = host_name else {
        return Ok(None);
    };
    if name.is_empty()
        || name.len() > SERVER_NAME_MAX_LEN
        || !name
            .iter()
            .all(|&b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(InvalidClientHello::ServerName);
    }
    // Every byte is ASCII, checked above.
    let name: &str = std::str::from_utf8(name).map_err(|_| InvalidClientHello::ServerName)?;
    if name.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let canonical: String = canonical_hostname(name).into_owned();
    if canonical.is_empty() {
        return Err(InvalidClientHello::ServerName);
    }
    Ok(Some(canonical))
}

/// Every protocol of an ALPN extension (RFC 7301 section 3.1), in order.
fn alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, InvalidClientHello> {
    let mut outer = Reader { data };
    let mut names = Reader {
        data: outer.vec16()?,
    };
    if !outer.is_empty() || names.is_empty() {
        return Err(InvalidClientHello::Malformed);
    }
    let mut protocols: Vec<Vec<u8>> = Vec::new();
    while !names.is_empty() {
        let name: &[u8] = names.vec8()?;
        if name.is_empty() {
            return Err(InvalidClientHello::Malformed);
        }
        protocols.push(name.to_vec());
    }
    Ok(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ---- a hello builder ----

    /// A ClientHello body built field by field, so each test breaks the
    /// one field it is about.
    #[derive(Clone)]
    struct Hello {
        session_id: Vec<u8>,
        suites: Vec<u8>,
        compression: Vec<u8>,
        extensions: Option<Vec<(u16, Vec<u8>)>>,
    }

    impl Hello {
        fn new() -> Hello {
            Hello {
                session_id: vec![7; 32],
                suites: vec![0x13, 0x01, 0x13, 0x02],
                compression: vec![0],
                extensions: Some(Vec::new()),
            }
        }

        fn with(mut self, kind: u16, data: Vec<u8>) -> Hello {
            self.extensions
                .get_or_insert_with(Vec::new)
                .push((kind, data));
            self
        }

        fn body(&self) -> Vec<u8> {
            let mut body: Vec<u8> = vec![3, 3];
            body.extend_from_slice(&[0x42; RANDOM_LEN]);
            push8(&mut body, &self.session_id);
            push16(&mut body, &self.suites);
            push8(&mut body, &self.compression);
            if let Some(extensions) = &self.extensions {
                let mut all: Vec<u8> = Vec::new();
                for (kind, data) in extensions {
                    all.extend_from_slice(&kind.to_be_bytes());
                    push16(&mut all, data);
                }
                push16(&mut body, &all);
            }
            body
        }

        fn message(&self) -> Vec<u8> {
            message_of(&self.body())
        }

        /// The hello in one record.
        fn wire(&self) -> Vec<u8> {
            records(&self.message(), &[usize::MAX])
        }
    }

    fn push8(out: &mut Vec<u8>, data: &[u8]) {
        out.push(u8::try_from(data.len()).expect("test setup: length"));
        out.extend_from_slice(data);
    }

    fn push16(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(
            &u16::try_from(data.len())
                .expect("test setup: length")
                .to_be_bytes(),
        );
        out.extend_from_slice(data);
    }

    fn message_of(body: &[u8]) -> Vec<u8> {
        let len: [u8; 4] = u32::try_from(body.len())
            .expect("test setup: length")
            .to_be_bytes();
        let mut message: Vec<u8> = vec![HANDSHAKE_CLIENT_HELLO, len[1], len[2], len[3]];
        message.extend_from_slice(body);
        message
    }

    /// `message` cut into records of the payload sizes `sizes`, the last
    /// size repeating until the message is out.
    fn records(message: &[u8], sizes: &[usize]) -> Vec<u8> {
        let mut wire: Vec<u8> = Vec::new();
        let mut rest: &[u8] = message;
        let mut index: usize = 0;
        while !rest.is_empty() {
            let size: usize = sizes[index.min(sizes.len() - 1)]
                .min(rest.len())
                .min(MAX_RECORD_LEN);
            let (fragment, tail) = rest.split_at(size);
            wire.extend_from_slice(&[CONTENT_TYPE_HANDSHAKE, 3, 1]);
            wire.extend_from_slice(&u16::try_from(size).unwrap().to_be_bytes());
            wire.extend_from_slice(fragment);
            rest = tail;
            index += 1;
        }
        wire
    }

    fn sni(name: &[u8]) -> Vec<u8> {
        let mut entry: Vec<u8> = vec![SERVER_NAME_HOST_NAME];
        push16(&mut entry, name);
        let mut data: Vec<u8> = Vec::new();
        push16(&mut data, &entry);
        data
    }

    fn alpn_ext(protocols: &[&[u8]]) -> Vec<u8> {
        let mut names: Vec<u8> = Vec::new();
        for protocol in protocols {
            push8(&mut names, protocol);
        }
        let mut data: Vec<u8> = Vec::new();
        push16(&mut data, &names);
        data
    }

    fn invalid(buf: &[u8]) -> InvalidClientHello {
        match parse(buf) {
            Err(ClientHelloError::Invalid(kind)) => kind,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Every strict prefix of an accepted hello asks for more.
    fn assert_prefixes_need_more(wire: &[u8]) {
        for end in 0..wire.len() {
            assert_eq!(
                parse(&wire[..end]),
                Err(ClientHelloError::NeedMore),
                "prefix of {end} bytes"
            );
        }
    }

    // ---- hellos from rustls ----

    /// The first flight of a rustls client offering `versions`, naming
    /// `server_name` (an IP literal sends none), offering `alpn`.
    fn rustls_hello(
        versions: &[&'static rustls::SupportedProtocolVersion],
        server_name: &str,
        sni: bool,
        alpn: &[&[u8]],
    ) -> Vec<u8> {
        let mut config: rustls::ClientConfig = rustls::ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_protocol_versions(versions)
        .expect("test setup: versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.enable_sni = sni;
        config.alpn_protocols = alpn.iter().map(|p: &&[u8]| p.to_vec()).collect();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from(server_name.to_owned())
                .expect("test setup: name"),
        )
        .expect("test setup: client");
        let mut wire: Vec<u8> = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).expect("in memory");
        }
        wire
    }

    const TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

    #[test]
    fn rustls_hellos_parse_with_and_without_sni_and_alpn() {
        for versions in [TLS12, TLS13] {
            for (sni, alpn) in [
                (true, &[b"h2".as_slice(), b"http/1.1".as_slice()][..]),
                (true, &[][..]),
                (false, &[b"postgresql".as_slice()][..]),
                (false, &[][..]),
            ] {
                let wire: Vec<u8> = rustls_hello(versions, "App.Example.com", sni, alpn);
                let hello: Parsed = parse(&wire).expect("a rustls hello");
                assert_eq!(hello.consumed, wire.len());
                assert_eq!(
                    hello.server_name.as_deref(),
                    sni.then_some("app.example.com"),
                    "{versions:?} sni={sni}"
                );
                assert_eq!(
                    hello.alpn,
                    alpn.iter().map(|p: &&[u8]| p.to_vec()).collect::<Vec<_>>()
                );
                assert!(!hello.ech_offered);
                assert_prefixes_need_more(&wire);
            }
        }
    }

    #[test]
    fn a_rustls_hello_to_an_ip_literal_has_no_server_name() {
        let wire: Vec<u8> = rustls_hello(TLS13, "192.0.2.10", true, &[]);
        assert_eq!(parse(&wire).expect("a rustls hello").server_name, None);
    }

    #[test]
    fn bytes_past_the_hello_are_not_consumed() {
        let wire: Vec<u8> = rustls_hello(TLS13, "app.example.com", true, &[b"h2"]);
        let mut buf: Vec<u8> = wire.clone();
        buf.extend_from_slice(&[23, 3, 3, 0, 2, 0xAA, 0xBB]);
        assert_eq!(parse(&buf).expect("a hello").consumed, wire.len());
    }

    // ---- record layer and reassembly ----

    #[test]
    fn a_hello_split_over_two_and_over_sixty_four_records_reassembles() {
        let hello: Hello = Hello::new()
            .with(EXTENSION_SERVER_NAME, sni(b"app.example.com"))
            .with(EXTENSION_ALPN, alpn_ext(&[b"h2"]));
        let message: Vec<u8> = hello.message();
        let whole: Parsed = parse(&hello.wire()).expect("one record");

        let two: Vec<u8> = records(&message, &[3, usize::MAX]);
        let parsed: Parsed = parse(&two).expect("two records");
        assert_eq!(parsed.consumed, two.len());
        assert_eq!(parsed.server_name, whole.server_name);
        assert_eq!(parsed.alpn, whole.alpn);
        assert_prefixes_need_more(&two);

        let mut sizes: Vec<usize> = vec![1; CLIENTHELLO_MAX_RECORDS - 1];
        sizes.push(usize::MAX);
        let sixty_four: Vec<u8> = records(&message, &sizes);
        assert_eq!(
            sixty_four.len(),
            message.len() + CLIENTHELLO_MAX_RECORDS * RECORD_HEADER_LEN,
            "test setup: 64 records"
        );
        assert_eq!(
            parse(&sixty_four).expect("64 records").server_name,
            whole.server_name
        );
    }

    #[test]
    fn a_hello_whose_handshake_header_spans_records_reassembles() {
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(b"a.example.com"));
        let wire: Vec<u8> = records(&hello.message(), &[1, 1, 1, usize::MAX]);
        assert_eq!(
            parse(&wire).expect("header in three records").server_name,
            Some("a.example.com".to_string())
        );
    }

    #[test]
    fn sixty_five_records_are_refused_at_the_sixty_fifth_header() {
        let message: Vec<u8> = Hello::new().message();
        let wire: Vec<u8> = records(&message, &[1]);
        let mut cut: usize = 0;
        for _ in 0..CLIENTHELLO_MAX_RECORDS {
            cut += RECORD_HEADER_LEN + 1;
        }
        assert!(message.len() > CLIENTHELLO_MAX_RECORDS, "test setup");
        assert_eq!(
            parse(&wire[..cut]),
            Err(ClientHelloError::NeedMore),
            "64 records"
        );
        assert_eq!(
            invalid(&wire[..=cut]),
            InvalidClientHello::Oversized,
            "the first byte of the 65th"
        );
    }

    #[test]
    fn a_message_over_the_limit_is_refused_from_its_header() {
        let header: [u8; 9] = [
            CONTENT_TYPE_HANDSHAKE,
            3,
            1,
            0x40,
            0x00,
            1,
            0x00,
            0x40,
            0x01,
        ];
        assert_eq!(invalid(&header), InvalidClientHello::Oversized);
        let at_limit: [u8; 9] = [
            CONTENT_TYPE_HANDSHAKE,
            3,
            1,
            0x40,
            0x00,
            1,
            0x00,
            0x40,
            0x00,
        ];
        assert_eq!(parse(&at_limit), Err(ClientHelloError::NeedMore));
    }

    #[test]
    fn a_record_of_16385_or_of_zero_bytes_is_refused() {
        assert_eq!(
            invalid(&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0x40, 0x01]),
            InvalidClientHello::RecordLength
        );
        assert_eq!(
            invalid(&[CONTENT_TYPE_HANDSHAKE, 3, 1, 0, 0]),
            InvalidClientHello::RecordLength
        );
    }

    #[test]
    fn a_non_handshake_record_mid_hello_is_refused() {
        let wire: Vec<u8> = records(&Hello::new().message(), &[10, usize::MAX]);
        let mut spliced: Vec<u8> = wire[..RECORD_HEADER_LEN + 10].to_vec();
        spliced.extend_from_slice(&[21, 3, 3, 0, 2, 2, 40]);
        assert_eq!(invalid(&spliced), InvalidClientHello::NotHandshake);
        let mut change_cipher_spec: Vec<u8> = wire[..RECORD_HEADER_LEN + 10].to_vec();
        change_cipher_spec.push(20);
        assert_eq!(
            invalid(&change_cipher_spec),
            InvalidClientHello::NotHandshake
        );
    }

    #[test]
    fn an_sslv2_hello_and_other_protocols_are_refused_at_the_first_byte() {
        assert_eq!(invalid(&[0x80]), InvalidClientHello::NotHandshake);
        assert_eq!(
            invalid(&[0x80, 0x2e, 0x01]),
            InvalidClientHello::NotHandshake
        );
        // PostgreSQL's SSLRequest (sslmode=require) is no TLS record.
        assert_eq!(
            invalid(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]),
            InvalidClientHello::NotHandshake
        );
    }

    #[test]
    fn record_versions_outside_tls_1_0_to_1_3_are_refused_as_soon_as_read() {
        assert_eq!(
            invalid(&[CONTENT_TYPE_HANDSHAKE, 2]),
            InvalidClientHello::RecordVersion
        );
        assert_eq!(
            invalid(&[CONTENT_TYPE_HANDSHAKE, 3, 0]),
            InvalidClientHello::RecordVersion
        );
        assert_eq!(
            invalid(&[CONTENT_TYPE_HANDSHAKE, 3, 5]),
            InvalidClientHello::RecordVersion
        );
        for minor in 1..=4u8 {
            assert_eq!(
                parse(&[CONTENT_TYPE_HANDSHAKE, 3, minor]),
                Err(ClientHelloError::NeedMore)
            );
        }
    }

    #[test]
    fn a_handshake_other_than_a_client_hello_is_refused() {
        let mut message: Vec<u8> = Hello::new().message();
        message[0] = 2;
        assert_eq!(
            invalid(&records(&message, &[usize::MAX])[..RECORD_HEADER_LEN + 1]),
            InvalidClientHello::NotClientHello
        );
    }

    #[test]
    fn a_record_running_past_the_message_is_refused() {
        let message: Vec<u8> = Hello::new().message();
        let mut padded: Vec<u8> = message.clone();
        padded.push(0);
        let wire: Vec<u8> = records(&padded, &[usize::MAX]);
        assert_eq!(
            invalid(&wire[..RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN]),
            InvalidClientHello::Malformed,
            "known from the two headers"
        );
    }

    // ---- the body ----

    #[test]
    fn a_hello_without_extensions_is_valid_and_names_nothing() {
        let mut hello: Hello = Hello::new();
        hello.extensions = None;
        let parsed: Parsed = parse(&hello.wire()).expect("no extensions block");
        assert_eq!(parsed.server_name, None);
        assert!(parsed.alpn.is_empty());
        assert!(!parsed.ech_offered);
    }

    #[test]
    fn a_duplicate_extension_is_refused() {
        let hello: Hello = Hello::new()
            .with(EXTENSION_ALPN, alpn_ext(&[b"h2"]))
            .with(EXTENSION_ALPN, alpn_ext(&[b"h2"]));
        assert_eq!(
            invalid(&hello.wire()),
            InvalidClientHello::DuplicateExtension
        );
        let unknown: Hello = Hello::new().with(0xffff, vec![]).with(0xffff, vec![1]);
        assert_eq!(
            invalid(&unknown.wire()),
            InvalidClientHello::DuplicateExtension
        );
    }

    #[test]
    fn an_ip_literal_server_name_is_absent() {
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(b"192.0.2.10"));
        assert_eq!(parse(&hello.wire()).expect("valid").server_name, None);
    }

    #[test]
    fn a_server_name_with_an_invalid_byte_or_length_is_refused() {
        for name in [
            b"app.example.com:443".as_slice(),
            b"app example.com",
            b"app\0.example.com",
            b"[2001:db8::1]",
            "caf\u{e9}.example.com".as_bytes(),
            b"",
            b".",
        ] {
            let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(name));
            assert_eq!(
                invalid(&hello.wire()),
                InvalidClientHello::ServerName,
                "{name:?}"
            );
        }
        let long: Vec<u8> = vec![b'a'; SERVER_NAME_MAX_LEN + 1];
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(&long));
        assert_eq!(invalid(&hello.wire()), InvalidClientHello::ServerName);
        let longest: Vec<u8> = vec![b'a'; SERVER_NAME_MAX_LEN];
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(&longest));
        assert!(parse(&hello.wire()).is_ok());
    }

    #[test]
    fn an_uppercase_server_name_with_a_trailing_dot_is_canonicalised() {
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(b"App.Example.COM."));
        assert_eq!(
            parse(&hello.wire()).expect("valid").server_name.as_deref(),
            Some("app.example.com")
        );
    }

    #[test]
    fn the_first_host_name_entry_is_the_server_name() {
        let mut entries: Vec<u8> = vec![9];
        push16(&mut entries, b"opaque");
        entries.push(SERVER_NAME_HOST_NAME);
        push16(&mut entries, b"first.example.com");
        entries.push(SERVER_NAME_HOST_NAME);
        push16(&mut entries, b"second.example.com");
        let mut data: Vec<u8> = Vec::new();
        push16(&mut data, &entries);
        let hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, data);
        assert_eq!(
            parse(&hello.wire()).expect("valid").server_name.as_deref(),
            Some("first.example.com")
        );
    }

    #[test]
    fn ech_is_seen_and_alpn_keeps_the_client_order() {
        let hello: Hello = Hello::new()
            .with(EXTENSION_SERVER_NAME, sni(b"public.example.com"))
            .with(EXTENSION_ALPN, alpn_ext(&[b"\x0a\x0a", b"http/1.1", b"h2"]))
            .with(EXTENSION_ENCRYPTED_CLIENT_HELLO, vec![0, 1, 2, 3]);
        let parsed: Parsed = parse(&hello.wire()).expect("valid");
        assert!(parsed.ech_offered);
        assert_eq!(
            parsed.alpn,
            vec![b"\x0a\x0a".to_vec(), b"http/1.1".to_vec(), b"h2".to_vec()]
        );
        assert_eq!(
            parsed.server_name.as_deref(),
            Some("public.example.com"),
            "the outer name"
        );
    }

    #[test]
    fn an_empty_alpn_list_or_protocol_name_is_refused() {
        for data in [alpn_ext(&[]), alpn_ext(&[b"h2", b""])] {
            let hello: Hello = Hello::new().with(EXTENSION_ALPN, data);
            assert_eq!(invalid(&hello.wire()), InvalidClientHello::Malformed);
        }
    }

    #[test]
    fn body_field_rules_are_enforced() {
        let mut long_session: Hello = Hello::new();
        long_session.session_id = vec![0; SESSION_ID_MAX_LEN + 1];
        let mut odd_suites: Hello = Hello::new();
        odd_suites.suites = vec![0x13, 0x01, 0x13];
        let mut no_suites: Hello = Hello::new();
        no_suites.suites = Vec::new();
        let mut no_compression: Hello = Hello::new();
        no_compression.compression = Vec::new();
        for (hello, why) in [
            (long_session, "a session id of 33 bytes"),
            (odd_suites, "an odd suite list"),
            (no_suites, "no suite"),
            (no_compression, "no compression method"),
        ] {
            assert_eq!(
                invalid(&hello.wire()),
                InvalidClientHello::Malformed,
                "{why}"
            );
        }
        let mut trailing: Vec<u8> = Hello::new().body();
        trailing.push(0);
        assert_eq!(
            invalid(&records(&message_of(&trailing), &[usize::MAX])),
            InvalidClientHello::Malformed,
            "a byte after the extensions block"
        );
    }

    /// Every length field of a valid hello, raised by one so it runs one
    /// byte past what encloses it, is refused, never read past.
    #[test]
    fn every_length_field_one_past_its_enclosure_is_refused() {
        let hello: Hello = Hello::new()
            .with(EXTENSION_SERVER_NAME, sni(b"app.example.com"))
            .with(EXTENSION_ALPN, alpn_ext(&[b"h2", b"http/1.1"]))
            .with(EXTENSION_ENCRYPTED_CLIENT_HELLO, vec![1, 2]);
        let body: Vec<u8> = hello.body();
        // Offsets of each length field in the body, and its width.
        let mut fields: Vec<(usize, usize)> = Vec::new();
        let mut at: usize = 2 + RANDOM_LEN;
        fields.push((at, 1)); // session_id
        at += 1 + usize::from(body[at]);
        fields.push((at, 2)); // cipher_suites
        at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        fields.push((at, 1)); // compression_methods
        at += 1 + usize::from(body[at]);
        fields.push((at, 2)); // extensions block
        at += 2;
        while at < body.len() {
            let kind: u16 = u16::from_be_bytes([body[at], body[at + 1]]);
            let len: usize = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            fields.push((at + 2, 2)); // extension data
            match kind {
                EXTENSION_SERVER_NAME => {
                    fields.push((at + 4, 2)); // server_name_list
                    fields.push((at + 7, 2)); // host_name
                }
                EXTENSION_ALPN => {
                    fields.push((at + 4, 2)); // protocol_name_list
                    fields.push((at + 6, 1)); // first protocol name
                    fields.push((at + 6 + 1 + usize::from(body[at + 6]), 1)); // second
                }
                _ => {}
            }
            at += 4 + len;
        }
        assert_eq!(fields.len(), 12, "test setup: every length field");
        for (offset, width) in fields {
            let mut broken: Vec<u8> = body.clone();
            if width == 1 {
                broken[offset] += 1;
            } else {
                let value: u16 = u16::from_be_bytes([broken[offset], broken[offset + 1]]) + 1;
                broken[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            }
            let result = parse(&records(&message_of(&broken), &[usize::MAX]));
            assert!(
                matches!(
                    result,
                    Err(ClientHelloError::Invalid(
                        InvalidClientHello::Truncated | InvalidClientHello::Malformed
                    ))
                ),
                "length at {offset}: {result:?}"
            );
        }
        // The handshake length one past the record that carries it.
        let message: Vec<u8> = message_of(&body);
        let mut longer: Vec<u8> = message.clone();
        longer[3] += 1;
        let wire: Vec<u8> = records(&longer[..message.len()], &[usize::MAX]);
        assert_eq!(
            parse(&wire),
            Err(ClientHelloError::NeedMore),
            "the message continues in a record not sent yet"
        );
        // A record length one past the bytes sent.
        let mut wire: Vec<u8> = records(&message, &[usize::MAX]);
        let len: u16 = u16::from_be_bytes([wire[3], wire[4]]) + 1;
        wire[3..5].copy_from_slice(&len.to_be_bytes());
        assert_eq!(
            invalid(&wire),
            InvalidClientHello::Malformed,
            "a record longer than the message"
        );
    }

    #[test]
    fn the_buffer_holds_the_largest_accepted_hello() {
        let mut hello: Hello = Hello::new().with(EXTENSION_SERVER_NAME, sni(b"app.example.com"));
        let padding: usize = CLIENTHELLO_MAX_LEN - hello.body().len() - 4;
        hello = hello.with(0x0015, vec![0; padding]);
        let message: Vec<u8> = hello.message();
        assert_eq!(message.len(), HANDSHAKE_HEADER_LEN + CLIENTHELLO_MAX_LEN);
        let size: usize = message.len().div_ceil(CLIENTHELLO_MAX_RECORDS);
        let wire: Vec<u8> = records(&message, &[size]);
        assert!(wire.len() <= CLIENTHELLO_BUFFER, "{}", wire.len());
        assert_eq!(parse(&wire).expect("the largest").consumed, wire.len());
    }

    #[test]
    fn every_refusal_has_its_own_word() {
        let words: std::collections::BTreeSet<&str> = InvalidClientHello::ALL
            .iter()
            .map(InvalidClientHello::as_str)
            .collect();
        assert_eq!(words.len(), InvalidClientHello::ALL.len());
        // A new refusal stops this match compiling: the reminder to list
        // it in `ALL`, which the word check above then covers.
        for kind in InvalidClientHello::ALL {
            match kind {
                InvalidClientHello::NotHandshake
                | InvalidClientHello::RecordVersion
                | InvalidClientHello::RecordLength
                | InvalidClientHello::NotClientHello
                | InvalidClientHello::Oversized
                | InvalidClientHello::Truncated
                | InvalidClientHello::Malformed
                | InvalidClientHello::DuplicateExtension
                | InvalidClientHello::ServerName => {}
            }
        }
    }
}
