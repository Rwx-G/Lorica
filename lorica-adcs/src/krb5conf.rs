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

//! The `krb5.conf` Lorica generates for its own Kerberos exchanges
//! (Epic 13 D3), rendered from typed values only.
//!
//! A realm or KDC value carrying a newline or a profile delimiter could
//! inject relations into the file: weaker encryption types, another KDC,
//! or a plugin module loaded into the process that holds the master key.
//! The types below are the only way to reach the renderer, and their
//! constructors refuse anything outside the grammar of Story 13.2 AC #1.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::AdcsError;

/// Encryption types the generated file permits, AES only (Epic 13 D3):
/// RC4 and DES are never negotiated, whatever the KDC offers.
const AES_ENCTYPES: &[&str] = &[
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha384-192",
    "aes128-cts-hmac-sha256-128",
];

/// The Kerberos port a KDC address without one implies (RFC 4120 7.2).
const DEFAULT_KDC_PORT: u16 = 88;

/// DNS limits of RFC 1035 2.3.4, which RFC 1123 2.1 keeps.
const MAX_LABEL_LEN: usize = 63;
const MAX_HOST_LEN: usize = 253;

/// Why `host` is not a host name of RFC 1123 labels, or `None` when it
/// is one. Shared with the CSR builder, whose SANs follow the same rule.
pub(crate) fn dns_name_problem(host: &str) -> Option<&'static str> {
    if host.is_empty() {
        return Some("the host is empty");
    }
    if host.len() > MAX_HOST_LEN {
        return Some("the host is longer than a DNS name can be");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Some("a label is empty or longer than DNS allows");
        }
        if !label
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Some("labels allow only letters, digits and '-'");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("a label cannot start or end with '-'");
        }
    }
    None
}

/// A Kerberos realm: `^[A-Z0-9][A-Z0-9.-]*$`, no longer than a DNS name.
/// Built only through [`Realm::new`], so a value of this type is always
/// safe to write into `krb5.conf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realm(String);

impl Realm {
    /// Validates `value` as a realm name. Upper case is required, not
    /// folded: AD realms are the upper-case DNS domain, and a lower-case
    /// value is more likely a mistake than an intent.
    pub fn new(value: &str) -> Result<Realm, AdcsError> {
        let refuse = |reason: &'static str| AdcsError::InvalidRealm {
            value: value.to_owned(),
            reason,
        };
        let mut chars = value.chars();
        let first: char = chars.next().ok_or_else(|| refuse("it is empty"))?;
        if !(first.is_ascii_uppercase() || first.is_ascii_digit()) {
            return Err(refuse("it must start with A-Z or 0-9"));
        }
        if !chars
            .all(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return Err(refuse("only A-Z, 0-9, '.' and '-' are allowed"));
        }
        if value.len() > MAX_HOST_LEN {
            return Err(refuse("it is longer than a DNS name can be"));
        }
        Ok(Realm(value.to_owned()))
    }

    /// The realm as validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A KDC address, `host[:port]`: a host name of RFC 1123 labels (which
/// also admits a dotted IPv4 address) and an optional port in
/// 1..=65535. Built only through [`KdcAddress::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcAddress {
    host: String,
    port: Option<u16>,
}

impl KdcAddress {
    /// Validates `value` as `host[:port]`. IPv6 literals are not
    /// accepted: their brackets and colons are outside the grammar.
    pub fn new(value: &str) -> Result<KdcAddress, AdcsError> {
        let refuse = |reason: &'static str| AdcsError::InvalidKdc {
            value: value.to_owned(),
            reason,
        };
        let (host, port): (&str, Option<u16>) = match value.split_once(':') {
            None => (value, None),
            Some((host, port)) => {
                if port.is_empty() || !port.bytes().all(|b: u8| b.is_ascii_digit()) {
                    return Err(refuse("the port must be digits only"));
                }
                let port: u16 = port
                    .parse()
                    .map_err(|_| refuse("the port must be within 1..=65535"))?;
                if port == 0 {
                    return Err(refuse("the port must be within 1..=65535"));
                }
                (host, Some(port))
            }
        };
        if let Some(problem) = dns_name_problem(host) {
            return Err(refuse(problem));
        }
        Ok(KdcAddress {
            host: host.to_owned(),
            port,
        })
    }

    /// The host part.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, or 88 when none was given.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_KDC_PORT)
    }
}

impl fmt::Display for KdcAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}:{port}", self.host),
            None => f.write_str(&self.host),
        }
    }
}

/// The total time MIT krb5 may spend on one KDC exchange, rendered as
/// `request_timeout` in `[libdefaults]`.
///
/// MIT honours that relation from release 1.22 only. Earlier releases
/// (1.20 on Debian 13, 1.21 on RHEL 9) ignore it, as they ignore any
/// unknown relation, and no profile relation bounds the exchange there:
/// the Heimdal names `kdc_timeout` and `max_retries` do nothing on MIT.
/// On those releases the operation timeout of Epic 13 D8 is the only
/// bound the caller sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdcTiming {
    request_timeout_secs: u32,
}

impl KdcTiming {
    /// Upper bound of the request timeout, in seconds.
    pub const MAX_REQUEST_TIMEOUT_SECS: u32 = 60;

    /// Validates a request timeout of `request_timeout_secs` (1 to
    /// [`Self::MAX_REQUEST_TIMEOUT_SECS`]).
    pub fn new(request_timeout_secs: u32) -> Result<KdcTiming, AdcsError> {
        if request_timeout_secs == 0 || request_timeout_secs > Self::MAX_REQUEST_TIMEOUT_SECS {
            return Err(AdcsError::InvalidKdcTiming {
                reason: format!(
                    "request_timeout must be within 1..={} seconds",
                    Self::MAX_REQUEST_TIMEOUT_SECS
                ),
            });
        }
        Ok(KdcTiming {
            request_timeout_secs,
        })
    }

    /// The request timeout, in seconds.
    pub fn request_timeout_secs(&self) -> u32 {
        self.request_timeout_secs
    }
}

/// Everything the generated `krb5.conf` is rendered from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Krb5Config {
    /// The default realm, the service account's.
    pub realm: Realm,
    /// Explicit KDCs of the realm; empty means DNS SRV discovery.
    pub kdcs: Vec<KdcAddress>,
    /// The bound of one KDC exchange, on MIT krb5 1.22 and later.
    pub timing: KdcTiming,
}

impl Krb5Config {
    /// The file's text. `rdns = false` and
    /// `dns_canonicalize_hostname = false` keep the service principal
    /// `HTTP/<host>` exactly as configured, so a spoofed PTR record cannot
    /// redirect the ticket; `udp_preference_limit = 1` prefers TCP, which
    /// AD tickets with a PAC usually outgrow UDP for anyway.
    pub fn render(&self) -> String {
        let enctypes: String = AES_ENCTYPES.join(" ");
        let mut out: String = String::new();
        out.push_str("[libdefaults]\n");
        out.push_str(&format!("    default_realm = {}\n", self.realm));
        out.push_str("    rdns = false\n");
        out.push_str("    dns_canonicalize_hostname = false\n");
        out.push_str("    udp_preference_limit = 1\n");
        out.push_str(&format!("    permitted_enctypes = {enctypes}\n"));
        out.push_str(&format!("    default_tkt_enctypes = {enctypes}\n"));
        out.push_str(&format!("    default_tgs_enctypes = {enctypes}\n"));
        out.push_str("    allow_weak_crypto = false\n");
        out.push_str(&format!(
            "    request_timeout = {}s\n",
            self.timing.request_timeout_secs
        ));
        if self.kdcs.is_empty() {
            out.push_str("    dns_lookup_kdc = true\n");
        } else {
            out.push_str("    dns_lookup_kdc = false\n");
            out.push_str("\n[realms]\n");
            out.push_str(&format!("    {} = {{\n", self.realm));
            for kdc in &self.kdcs {
                out.push_str(&format!("        kdc = {kdc}\n"));
            }
            out.push_str("    }\n");
        }
        out
    }

    /// Renders the file and writes it to `path` with
    /// [`write_atomically`].
    pub fn write_to(&self, path: &Path) -> Result<(), AdcsError> {
        write_atomically(path, self.render().as_bytes())
    }
}

/// Where the generated `krb5.conf` lives under the data directory
/// (Epic 13 D3): `<data-dir>/adcs/krb5.conf`. The `lorica` binary points
/// `KRB5_CONFIG` here at startup, before any thread exists, and MIT
/// krb5 reads it at every context creation, so the file can be written
/// later and rewritten when the authority changes.
pub fn krb5_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("adcs").join("krb5.conf")
}

/// Replaces `path` with `contents` so that a reader sees either the old
/// file or the new one, never a partial write: the bytes go to a sibling
/// temporary file in the same directory, which is flushed to disk and
/// then renamed over `path`. The parent directory is created when
/// absent, with mode 0700 on Unix, and the file gets mode 0600.
pub fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), AdcsError> {
    let write_error = |at: &Path| {
        let at: PathBuf = at.to_path_buf();
        move |source: std::io::Error| AdcsError::Krb5ConfWrite { path: at, source }
    };
    let parent: &Path = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let file_name: &std::ffi::OsStr = path.file_name().ok_or_else(|| AdcsError::Krb5ConfWrite {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"),
    })?;
    create_private_dir(parent).map_err(write_error(parent))?;

    let mut temp_name: std::ffi::OsString = std::ffi::OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let temp_path: PathBuf = parent.join(temp_name);

    let written: Result<(), std::io::Error> = (|| {
        let mut file: fs::File = open_new_private(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)
    })();
    if let Err(source) = written {
        // Best effort: the temporary file is useless once the write
        // failed, and the original error is the one worth reporting.
        let _ = fs::remove_file(&temp_path);
        return Err(AdcsError::Krb5ConfWrite {
            path: path.to_path_buf(),
            source,
        });
    }
    sync_dir(parent).map_err(write_error(parent))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn open_new_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_new_private(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

// The rename is only durable once the directory entry is, which on
// Linux takes an fsync of the directory itself.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every character that could end a relation, open or close a
    /// section or subsection, or assign a value, in each position.
    const INJECTIONS: &[&str] = &["\n", "\r", "[", "]", "{", "}", "=", " ", "\t", "#", ";"];

    fn timing() -> KdcTiming {
        KdcTiming::new(3).expect("timing")
    }

    #[test]
    fn the_file_lives_under_the_data_directory() {
        assert_eq!(
            krb5_config_path(Path::new("/var/lib/lorica")),
            Path::new("/var/lib/lorica/adcs/krb5.conf")
        );
    }

    #[test]
    fn realm_grammar() {
        assert!(Realm::new("CORP.EXAMPLE.ORG").is_ok());
        assert!(Realm::new("0CORP-1.EXAMPLE.ORG").is_ok());
        for bad in ["", "corp.example.org", ".CORP", "-CORP", "CORP_X", "CÖRP"] {
            assert!(
                matches!(Realm::new(bad), Err(AdcsError::InvalidRealm { .. })),
                "{bad:?}"
            );
        }
        assert!(Realm::new(&"A".repeat(254)).is_err());
    }

    #[test]
    fn kdc_grammar() {
        let kdc: KdcAddress = KdcAddress::new("dc01.corp.example.org").expect("host");
        assert_eq!((kdc.host(), kdc.port()), ("dc01.corp.example.org", 88));
        let kdc: KdcAddress = KdcAddress::new("dc01.corp.example.org:750").expect("host:port");
        assert_eq!(kdc.port(), 750);
        assert_eq!(kdc.to_string(), "dc01.corp.example.org:750");
        assert!(KdcAddress::new("192.0.2.10:88").is_ok());
        for bad in [
            "",
            ":88",
            "dc01:",
            "dc01:0",
            "dc01:65536",
            "dc01:+88",
            "dc01:8 8",
            "dc01:88:88",
            "-dc01.corp.example.org",
            "dc01-.corp.example.org",
            "dc01..corp.example.org",
            "[2001:db8::1]:88",
            "dc_01.corp.example.org",
        ] {
            assert!(
                matches!(KdcAddress::new(bad), Err(AdcsError::InvalidKdc { .. })),
                "{bad:?}"
            );
        }
        assert!(KdcAddress::new(&format!("{}.org", "a".repeat(64))).is_err());
    }

    #[test]
    fn injection_vectors_are_refused_at_construction() {
        for vector in INJECTIONS {
            for realm in [
                format!("CORP{vector}"),
                format!("CORP{vector}X"),
                format!("{vector}CORP"),
            ] {
                assert!(Realm::new(&realm).is_err(), "realm {realm:?}");
            }
            for kdc in [
                format!("dc01{vector}"),
                format!("dc01{vector}x.corp.example.org"),
                format!("{vector}dc01"),
                format!("dc01:88{vector}"),
            ] {
                assert!(KdcAddress::new(&kdc).is_err(), "kdc {kdc:?}");
            }
        }
        // A realm that tries to open a subsection carrying a plugin
        // relation, the attack D3 names.
        assert!(Realm::new("CORP.EXAMPLE.ORG = {\n module = /tmp/evil.so\n}").is_err());
    }

    #[test]
    fn timing_bounds() {
        assert!(KdcTiming::new(1).is_ok());
        assert!(KdcTiming::new(KdcTiming::MAX_REQUEST_TIMEOUT_SECS).is_ok());
        for out_of_bounds in [0, KdcTiming::MAX_REQUEST_TIMEOUT_SECS + 1] {
            assert!(
                matches!(
                    KdcTiming::new(out_of_bounds),
                    Err(AdcsError::InvalidKdcTiming { .. })
                ),
                "{out_of_bounds}"
            );
        }
    }

    #[test]
    fn golden_with_dns_discovery() {
        let config: Krb5Config = Krb5Config {
            realm: Realm::new("CORP.EXAMPLE.ORG").expect("realm"),
            kdcs: Vec::new(),
            timing: timing(),
        };
        let expected: &str = "[libdefaults]
    default_realm = CORP.EXAMPLE.ORG
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128
    allow_weak_crypto = false
    request_timeout = 3s
    dns_lookup_kdc = true
";
        assert_eq!(config.render(), expected);
    }

    #[test]
    fn golden_with_explicit_kdcs() {
        let config: Krb5Config = Krb5Config {
            realm: Realm::new("CORP.EXAMPLE.ORG").expect("realm"),
            kdcs: vec![
                KdcAddress::new("dc01.corp.example.org").expect("kdc"),
                KdcAddress::new("dc02.corp.example.org:88").expect("kdc"),
            ],
            timing: timing(),
        };
        let rendered: String = config.render();
        assert!(rendered.contains("    dns_lookup_kdc = false\n"));
        assert!(!rendered.contains("dns_lookup_kdc = true"));
        assert!(rendered.ends_with(
            "
[realms]
    CORP.EXAMPLE.ORG = {
        kdc = dc01.corp.example.org
        kdc = dc02.corp.example.org:88
    }
"
        ));
    }

    #[test]
    fn rendered_enctypes_are_the_aes_list_only() {
        let config: Krb5Config = Krb5Config {
            realm: Realm::new("CORP.EXAMPLE.ORG").expect("realm"),
            kdcs: Vec::new(),
            timing: timing(),
        };
        let rendered: String = config.render();
        for key in [
            "permitted_enctypes",
            "default_tkt_enctypes",
            "default_tgs_enctypes",
        ] {
            let line: &str = rendered
                .lines()
                .find(|line: &&str| line.trim_start().starts_with(key))
                .expect("enctype line");
            let listed: Vec<&str> = line
                .split_once('=')
                .expect("relation")
                .1
                .split_whitespace()
                .collect();
            assert_eq!(listed, AES_ENCTYPES);
        }
    }

    fn scratch_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "lorica-adcs-test-{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn atomic_write_creates_the_directory_and_replaces_the_file() {
        let root: PathBuf = scratch_dir();
        let path: PathBuf = root.join("adcs").join("krb5.conf");
        write_atomically(&path, b"first\n").expect("first write");
        write_atomically(&path, b"second\n").expect("second write");
        assert_eq!(fs::read(&path).expect("read back"), b"second\n");
        let leftovers: Vec<std::ffi::OsString> = fs::read_dir(path.parent().expect("parent"))
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("krb5.conf")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir_mode: u32 = fs::metadata(path.parent().expect("parent"))
                .expect("dir metadata")
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
            let file_mode: u32 = fs::metadata(&path).expect("metadata").permissions().mode();
            assert_eq!(file_mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn atomic_write_failure_names_the_path_and_leaves_no_temp_file() {
        let root: PathBuf = scratch_dir();
        // The target is an existing directory, so the rename fails.
        let path: PathBuf = root.join("krb5.conf");
        fs::create_dir_all(path.join("occupied")).expect("setup");
        let err: AdcsError = write_atomically(&path, b"x").expect_err("rename over a directory");
        assert!(
            matches!(&err, AdcsError::Krb5ConfWrite { path: p, .. } if *p == path),
            "{err}"
        );
        let entries: Vec<std::ffi::OsString> = fs::read_dir(&root)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("krb5.conf")]);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn write_to_writes_the_rendering() {
        let root: PathBuf = scratch_dir();
        let path: PathBuf = root.join("krb5.conf");
        let config: Krb5Config = Krb5Config {
            realm: Realm::new("CORP.EXAMPLE.ORG").expect("realm"),
            kdcs: Vec::new(),
            timing: timing(),
        };
        config.write_to(&path).expect("write");
        assert_eq!(fs::read_to_string(&path).expect("read"), config.render());
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
