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

//! PROXY protocol on TCP streams (Story 12.3 D-j, D-k): the required
//! header of a trusted peer, read before a backend is chosen, and the
//! header the engine sends a backend.
//!
//! The untrusted-peer rule (the first bytes of a direct client on an
//! accepting stream must not open with a PROXY signature) is checked
//! in flight by the forwarding loop, not here: a server-first protocol
//! has a silent client, which a read before connect would stall.

use std::net::{IpAddr, SocketAddr};

use lorica_config::connection_filter::parse_cidr;
use lorica_config::models::StreamProxyProtocol;
use lorica_core::protocols::proxy_protocol::{
    encode_v1, encode_v2, parse, Addresses, Command, ParseError, Parsed, Version, MAX_HEADER_LEN,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::counters::ProxyHeaderOutcome;

/// Whether `peer` (canonical) is inside one of `cidrs`, a stream's
/// `proxy_protocol_trusted_cidrs`. An entry that does not parse trusts
/// nobody; validation refuses such a list before it is stored.
pub fn is_trusted(peer: IpAddr, cidrs: &[String]) -> bool {
    cidrs
        .iter()
        .filter_map(|entry| parse_cidr(entry).ok())
        .any(|net| net.contains(&peer))
}

/// What reading a trusted peer's header gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderRead {
    /// A header was accepted.
    Accepted {
        /// Which kind.
        outcome: ProxyHeaderOutcome,
        /// The (client, destination) it carried, canonical, when it
        /// carried TCP addresses.
        carried: Option<(SocketAddr, SocketAddr)>,
        /// The client bytes read past the header, replayed to the
        /// backend first.
        preamble: Vec<u8>,
    },
    /// The connection ends with `proxy_header_invalid`.
    Refused(ProxyHeaderOutcome),
}

fn refused(error: ParseError) -> HeaderRead {
    HeaderRead::Refused(match error {
        ParseError::Malformed(_) => ProxyHeaderOutcome::RefusedMalformed,
        ParseError::Oversized(_) => ProxyHeaderOutcome::RefusedOversized,
        ParseError::Unsupported(_) => ProxyHeaderOutcome::RefusedUnsupported,
    })
}

/// Read the header a trusted peer must send, at most
/// [`MAX_HEADER_LEN`] bytes, complete by `deadline`.
pub async fn read_trusted(client: &mut TcpStream, deadline: Instant) -> HeaderRead {
    let mut buf = vec![0u8; MAX_HEADER_LEN];
    let mut filled = 0;
    loop {
        match parse(&buf[..filled]) {
            Err(e) => return refused(e),
            Ok(Parsed::Complete { header, consumed }) => {
                let outcome_of_tcp = match header.version {
                    Version::V1 => ProxyHeaderOutcome::AcceptedV1,
                    Version::V2 => ProxyHeaderOutcome::AcceptedV2,
                };
                let (outcome, carried) = match (header.command, header.addresses) {
                    (Command::Local, _) => (ProxyHeaderOutcome::AcceptedLocal, None),
                    (
                        Command::Proxy,
                        Addresses::Tcp {
                            source,
                            destination,
                        },
                    ) => (
                        outcome_of_tcp,
                        Some((canonical(source), canonical(destination))),
                    ),
                    (Command::Proxy, Addresses::Udp { .. }) => {
                        return HeaderRead::Refused(ProxyHeaderOutcome::RefusedUnsupported)
                    }
                    (Command::Proxy, Addresses::Unspecified | Addresses::Unix) => {
                        (ProxyHeaderOutcome::AcceptedLocal, None)
                    }
                };
                return HeaderRead::Accepted {
                    outcome,
                    carried,
                    preamble: buf[consumed..filled].to_vec(),
                };
            }
            Ok(Parsed::Incomplete) if filled == buf.len() => {
                return HeaderRead::Refused(ProxyHeaderOutcome::RefusedOversized)
            }
            Ok(Parsed::Incomplete) => {}
        }
        match tokio::time::timeout_at(deadline, client.read(&mut buf[filled..])).await {
            Err(_) => return HeaderRead::Refused(ProxyHeaderOutcome::RefusedTimeout),
            Ok(Ok(0)) | Ok(Err(_)) => {
                return HeaderRead::Refused(ProxyHeaderOutcome::RefusedMalformed)
            }
            Ok(Ok(n)) => filled += n,
        }
    }
}

/// `addr` with an IPv4-mapped IP read as the IPv4 address it carries.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The header a stream sends its backend for a connection from `client`
/// to `destination`, `None` when it sends none. The encoder falls back
/// to `PROXY UNKNOWN` (v1) or `AF_UNSPEC` (v2) when the two families
/// differ.
pub fn send_header(
    mode: StreamProxyProtocol,
    client: SocketAddr,
    destination: SocketAddr,
) -> Option<Vec<u8>> {
    match mode {
        StreamProxyProtocol::Off => None,
        StreamProxyProtocol::V1 => Some(encode_v1(client, destination)),
        StreamProxyProtocol::V2 => Some(encode_v2(client, destination)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_reads_hosts_and_prefixes() {
        let list = vec!["10.0.0.0/8".to_string(), "192.0.2.10".to_string()];
        assert!(is_trusted("10.1.2.3".parse().unwrap(), &list));
        assert!(is_trusted("192.0.2.10".parse().unwrap(), &list));
        assert!(!is_trusted("192.0.2.11".parse().unwrap(), &list));
        assert!(!is_trusted("10.1.2.3".parse().unwrap(), &[]));
    }

    #[test]
    fn a_family_mismatch_sends_the_address_less_forms() {
        let v4: SocketAddr = "192.0.2.10:5000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(
            send_header(StreamProxyProtocol::V1, v4, v6),
            Some(b"PROXY UNKNOWN\r\n".to_vec())
        );
        let v2 = send_header(StreamProxyProtocol::V2, v4, v6).unwrap();
        let Ok(Parsed::Complete { header, .. }) = parse(&v2) else {
            panic!("a v2 header parses");
        };
        assert_eq!(header.addresses, Addresses::Unspecified);
        assert_eq!(send_header(StreamProxyProtocol::Off, v4, v4), None);
    }
}
