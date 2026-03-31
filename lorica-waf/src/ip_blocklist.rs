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

//! IP address blocklist for WAF.
//!
//! Supports loading blocklists from plain-text files (one IP per line)
//! such as the [Data-Shield IPv4 Blocklist](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist).
//! Lookup is O(1) via HashSet. Thread-safe with RwLock for hot-reload.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;

use tracing::{info, warn};

/// Default blocklist URL (Data-Shield IPv4 Blocklist - updated every 6 hours).
pub const DEFAULT_BLOCKLIST_URL: &str =
    "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt";

/// Thread-safe IP blocklist with O(1) lookup.
pub struct IpBlocklist {
    ips: RwLock<HashSet<IpAddr>>,
    enabled: RwLock<bool>,
}

impl IpBlocklist {
    /// Create an empty blocklist.
    pub fn new() -> Self {
        Self {
            ips: RwLock::new(HashSet::new()),
            enabled: RwLock::new(false),
        }
    }

    /// Check if an IP address is blocked.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !*self.enabled.read().unwrap() {
            return false;
        }
        self.ips.read().unwrap().contains(ip)
    }

    /// Check if an IP string is blocked (parses the string first).
    pub fn is_blocked_str(&self, ip_str: &str) -> bool {
        if !*self.enabled.read().unwrap() {
            return false;
        }
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => self.ips.read().unwrap().contains(&ip),
            Err(_) => false,
        }
    }

    /// Load IPs from plain text (one IP per line, comments/blanks ignored).
    pub fn load_from_text(&self, text: &str) -> usize {
        let mut set = HashSet::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match trimmed.parse::<IpAddr>() {
                Ok(ip) => {
                    set.insert(ip);
                }
                Err(_) => {
                    // Skip invalid lines silently
                }
            }
        }
        let count = set.len();
        *self.ips.write().unwrap() = set;
        *self.enabled.write().unwrap() = true;
        info!(count = count, "IP blocklist loaded");
        count
    }

    /// Enable or disable the blocklist.
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().unwrap() = enabled;
    }

    /// Return whether the blocklist is enabled.
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read().unwrap()
    }

    /// Return the number of IPs in the blocklist.
    pub fn len(&self) -> usize {
        self.ips.read().unwrap().len()
    }

    /// Return true if the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.ips.read().unwrap().is_empty()
    }

    /// Clear the blocklist.
    pub fn clear(&self) {
        self.ips.write().unwrap().clear();
        *self.enabled.write().unwrap() = false;
    }
}

impl Default for IpBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LIST: &str = "\
1.0.164.165
1.1.179.83
1.2.164.188
# comment line
192.168.1.1

invalid-line
10.0.0.1
";

    #[test]
    fn test_load_from_text() {
        let bl = IpBlocklist::new();
        let count = bl.load_from_text(SAMPLE_LIST);
        assert_eq!(count, 5);
        assert!(bl.is_enabled());
    }

    #[test]
    fn test_is_blocked() {
        let bl = IpBlocklist::new();
        bl.load_from_text(SAMPLE_LIST);
        assert!(bl.is_blocked_str("1.0.164.165"));
        assert!(bl.is_blocked_str("10.0.0.1"));
        assert!(!bl.is_blocked_str("8.8.8.8"));
    }

    #[test]
    fn test_disabled_blocklist_passes_all() {
        let bl = IpBlocklist::new();
        bl.load_from_text(SAMPLE_LIST);
        bl.set_enabled(false);
        assert!(!bl.is_blocked_str("1.0.164.165"));
    }

    #[test]
    fn test_empty_blocklist() {
        let bl = IpBlocklist::new();
        assert!(!bl.is_enabled());
        assert!(!bl.is_blocked_str("1.0.164.165"));
        assert_eq!(bl.len(), 0);
        assert!(bl.is_empty());
    }

    #[test]
    fn test_clear() {
        let bl = IpBlocklist::new();
        bl.load_from_text(SAMPLE_LIST);
        assert_eq!(bl.len(), 5);
        bl.clear();
        assert_eq!(bl.len(), 0);
        assert!(!bl.is_enabled());
    }

    #[test]
    fn test_skips_comments_and_blanks() {
        let bl = IpBlocklist::new();
        let text = "# header\n\n1.2.3.4\n# another comment\n5.6.7.8\n\n";
        let count = bl.load_from_text(text);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_skips_invalid_lines() {
        let bl = IpBlocklist::new();
        let text = "1.2.3.4\nnot-an-ip\n999.999.999.999\n5.6.7.8";
        let count = bl.load_from_text(text);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_ipv6_supported() {
        let bl = IpBlocklist::new();
        let text = "1.2.3.4\n::1\nfe80::1";
        let count = bl.load_from_text(text);
        assert_eq!(count, 3);
        assert!(bl.is_blocked_str("::1"));
    }

    #[test]
    fn test_is_blocked_with_parsed_ip() {
        let bl = IpBlocklist::new();
        bl.load_from_text("192.168.1.1");
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(bl.is_blocked(&ip));
    }

    #[test]
    fn test_reload_replaces_list() {
        let bl = IpBlocklist::new();
        bl.load_from_text("1.2.3.4");
        assert!(bl.is_blocked_str("1.2.3.4"));

        bl.load_from_text("5.6.7.8");
        assert!(!bl.is_blocked_str("1.2.3.4"));
        assert!(bl.is_blocked_str("5.6.7.8"));
    }

    #[test]
    fn test_large_list_performance() {
        let bl = IpBlocklist::new();
        // Generate 100k IPs
        let mut text = String::new();
        for i in 0..100u32 {
            for j in 0..255u32 {
                for k in 0..4u32 {
                    text.push_str(&format!("{i}.{j}.{k}.1\n"));
                }
            }
        }
        let count = bl.load_from_text(&text);
        assert!(count > 90_000);

        // Lookup should be fast (O(1))
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            bl.is_blocked_str("50.128.2.1");
        }
        let elapsed = start.elapsed();
        let per_lookup_ns = elapsed.as_nanos() / 10_000;
        assert!(
            per_lookup_ns < 1000,
            "Lookup too slow: {per_lookup_ns}ns per lookup"
        );
    }
}
