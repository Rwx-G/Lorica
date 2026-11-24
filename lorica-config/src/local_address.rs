//! What "local" means for a stream backend (Story 12.3, D-m): one
//! definition every check reads, so validation, the per-node port rule
//! and the engine's connect-time check cannot disagree about which
//! addresses reach the node itself.
//!
//! Pure: no resolution and no interface enumeration happens here. The
//! addresses assigned to a node's interfaces are local too, but only the
//! node itself knows them, so the engine adds them at connect time.
//!
//! Beside "local", the cloud instance metadata services that link-local
//! does not cover ([`INSTANCE_METADATA_ADDRESSES`]): rule A refuses them
//! as it refuses a local address, rule B does not, since they are not
//! this node and its ports are not theirs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The instance metadata services of the major clouds outside
/// link-local, which [`is_local_ip`] already covers (the IPv4 service
/// at `169.254.169.254` on AWS, Azure, Google Cloud and most others).
/// Each hands the instance's credentials to whoever reaches it from
/// the instance, so a stream forwarding raw TCP or UDP there needs the
/// stream's `allow_local_backend`, like a local address (audit finding
/// C5).
///
/// Exact addresses, never their surrounding ranges: `100.64.0.0/10`
/// around Alibaba's is carrier-grade NAT and Tailscale space, and the
/// ULA prefixes around the IPv6 ones hold legitimate backends.
pub const INSTANCE_METADATA_ADDRESSES: &[(IpAddr, &str)] = &[
    (
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)),
        "AWS IMDS over IPv6",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0xfd20, 0xce, 0, 0, 0, 0, 0, 0x254)),
        "Google Cloud metadata server over IPv6",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
        "Alibaba Cloud metadata service",
    ),
];

/// Whether `ip` is one of [`INSTANCE_METADATA_ADDRESSES`], an
/// IPv4-mapped IPv6 address judged as the IPv4 address it carries.
///
/// ```rust
/// use lorica_config::local_address::is_instance_metadata_ip;
///
/// assert!(is_instance_metadata_ip("fd00:ec2::254".parse().unwrap()));
/// assert!(is_instance_metadata_ip("::ffff:100.100.100.200".parse().unwrap()));
/// assert!(!is_instance_metadata_ip("100.100.100.201".parse().unwrap()));
/// ```
pub fn is_instance_metadata_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    INSTANCE_METADATA_ADDRESSES
        .iter()
        .any(|&(metadata, _)| metadata == ip)
}

/// Whether a stream needs `allow_local_backend` to forward to `host`,
/// judged without resolving it (rule A of Story 12.3 D-m): a local host
/// by [`is_local_host`], or an instance metadata literal by
/// [`is_instance_metadata_ip`]. Rule B, the node's own ports, reads
/// [`is_local_host`] alone.
///
/// ```rust
/// use lorica_config::local_address::needs_local_backend_flag;
///
/// assert!(needs_local_backend_flag("localhost"));
/// assert!(needs_local_backend_flag("100.100.100.200"));
/// assert!(!needs_local_backend_flag("192.0.2.10"));
/// ```
pub fn needs_local_backend_flag(host: &str) -> bool {
    is_local_host(host) || host.parse::<IpAddr>().is_ok_and(is_instance_metadata_ip)
}

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

    /// (address, instance metadata): each listed service in both
    /// spellings it can arrive in, and the neighbours that must stay
    /// ordinary backends.
    const METADATA_VECTORS: &[(&str, bool)] = &[
        ("fd00:ec2::254", true),
        ("fd20:ce::254", true),
        ("100.100.100.200", true),
        ("::ffff:100.100.100.200", true),
        ("fd00:ec2::253", false),
        ("fd00:ec2::1:254", false),
        ("fd20:ce::253", false),
        ("100.100.100.201", false),
        ("100.64.0.1", false),
        ("169.254.169.254", false),
    ];

    #[test]
    fn every_instance_metadata_literal_and_its_ordinary_neighbours() {
        for &(address, metadata) in METADATA_VECTORS {
            let ip: IpAddr = address.parse().expect("test setup: address");
            assert_eq!(is_instance_metadata_ip(ip), metadata, "{address}");
            assert!(!is_local_ip(ip) || !metadata, "{address} is local already");
            assert_eq!(
                needs_local_backend_flag(address),
                metadata || is_local_ip(ip),
                "{address} as a host"
            );
        }
        for &(ip, service) in INSTANCE_METADATA_ADDRESSES {
            assert!(is_instance_metadata_ip(ip), "{service}");
            assert!(!is_local_ip(ip), "{service}: rule B must not see it");
            assert!(!is_local_host(&ip.to_string()), "{service}");
            assert!(needs_local_backend_flag(&ip.to_string()), "{service}");
        }
    }

    #[test]
    fn every_local_host_needs_the_flag() {
        for &(address, local) in IP_VECTORS {
            assert_eq!(needs_local_backend_flag(address), local, "{address}");
        }
        assert!(needs_local_backend_flag("db.localhost"));
        assert!(!needs_local_backend_flag("pg.example.com"));
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
