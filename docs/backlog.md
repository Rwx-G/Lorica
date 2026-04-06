# Technical Backlog

Items identified during QA traceability audit (2026-04-01) and acceptance testing (2026-04-05/06).

## High Priority

| Source | Description | References |
|--------|-------------|------------|
| Security audit | **XFF Trust without validation**: proxy trusts X-Forwarded-For from any client, bypassing IP blocklist, bans, and rate limiting. Add `trusted_proxies` CIDR list to global settings. Only trust XFF when direct client IP is in the list. | `proxy_wiring.rs:548` |
| Security audit | **Encryption key rotation**: no mechanism to rotate the AES-256-GCM key. If key is lost, all encrypted data (cert private keys, notification configs) is unrecoverable. Implement `rotate_key(old, new)` and document key backup. | `crypto.rs` |

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Security audit | **Mutex poisoning (remaining)**: EwmaTracker and notification_history still use `std::sync::Mutex/RwLock`. LogStore and WafEngine migrated to `parking_lot`. Consider migrating the remaining ones. | `proxy_wiring.rs`, `settings.rs` |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| Code audit | **Stale `#[allow(dead_code)]`** on `RouteEntry` - may no longer be needed after recent refactors. | `proxy_wiring.rs:44` |
| Code audit | **`request_counts` and `waf_counts` DashMaps** grow with each unique (route_id, status) pair. Bounded by config but never cleared. Consider periodic reset if metrics are forwarded to Prometheus. | `proxy_wiring.rs:419-421` |
| Acceptance test | **HTTP request smuggling rule (920100)** untestable via curl - rejected at protocol level before WAF evaluation. Consider if the rule adds value or should be removed. | `rules.rs:236` |
