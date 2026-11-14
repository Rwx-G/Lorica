//! What "local" means for a stream backend (Story 12.3, D-m): one
//! definition every check reads, so validation, the per-node port rule
//! and the engine's connect-time check cannot disagree about which
//! addresses reach the node itself.
//!
//! Pure: no resolution and no interface enumeration happens here. The
//! addresses assigned to a node's interfaces are local too, but only the
//! node itself knows them, so the engine adds them at connect time.

use std::net::IpAddr;

/// Whether `ip` reaches the node it is dialled from whatever the node:
/// loopback, unspecified (Linux connects `0.0.0.0` and `::` to the
/// loopback) or link-local, of either family. An IPv4-mapped IPv6
/// address is judged as the IPv4 address it carries.
///
/// ```rust
/// use lorica_config::local_address::is_local_ip;
///
/// assert!(is_local_ip("127.0.0.1".parse().unwrap()));
/// assert!(is_local_ip("::ffff:127.0.0.1".parse().unwrap()));
/// assert!(is_local_ip("fe80::1".parse().unwrap()));
/// assert!(!is_local_ip("192.0.2.10".parse().unwrap()));
/// ```
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // `Ipv6Addr::is_unicast_link_local` is not stable: fe80::/10
            // by its first ten bits.
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Whether `name` is `localhost` or a name under it (RFC 6761 6.3: such
/// names resolve to the loopback), in any case and with or without the
/// trailing root dot.
///
/// ```rust
/// use lorica_config::local_address::is_local_host_name;
///
/// assert!(is_local_host_name("localhost"));
/// assert!(is_local_host_name("db.LOCALHOST."));
/// assert!(!is_local_host_name("localhost.example.com"));
/// ```
pub fn is_local_host_name(name: &str) -> bool {
    let name: String = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost")
}

/// Whether the host part of a backend address is local without
/// resolving it: an IP literal by [`is_local_ip`], a name by
/// [`is_local_host_name`]. Any other name may still resolve to a local
/// address, which only the connect-time check can see.
pub fn is_local_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(ip) => is_local_ip(ip),
        Err(_) => is_local_host_name(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (address, local): the literals Story 12.3 names, each family, and
    /// the neighbours that must stay remote.
    const IP_VECTORS: &[(&str, bool)] = &[
        ("127.0.0.1", true),
        ("127.255.255.254", true),
        ("::1", true),
        ("::ffff:127.0.0.1", true),
        ("169.254.1.1", true),
        ("::ffff:169.254.1.1", true),
        ("fe80::1", true),
        ("febf::1", true),
        ("0.0.0.0", true),
        ("::", true),
        ("::ffff:0.0.0.0", true),
        ("192.0.2.10", false),
        ("10.0.0.5", false),
        ("2001:db8::1", false),
        ("fec0::1", false),
        ("fe7f::1", false),
        ("::ffff:192.0.2.10", false),
        ("128.0.0.1", false),
    ];

    #[test]
    fn every_local_literal_and_its_remote_neighbours() {
        for &(address, local) in IP_VECTORS {
            let ip: IpAddr = address.parse().expect("test setup: address");
            assert_eq!(is_local_ip(ip), local, "{address}");
            assert_eq!(is_local_host(address), local, "{address} as a host");
        }
    }

    #[test]
    fn localhost_names_in_any_spelling() {
        for name in [
            "localhost",
            "LocalHost",
            "localhost.",
            "db.localhost",
            "a.b.localhost.",
        ] {
            assert!(is_local_host_name(name), "{name}");
            assert!(is_local_host(name), "{name}");
        }
        for name in [
            "localhost.example.com",
            "mylocalhost",
            "localhost-db",
            "example.com",
            "",
        ] {
            assert!(!is_local_host_name(name), "{name}");
            assert!(!is_local_host(name), "{name}");
        }
    }
}
