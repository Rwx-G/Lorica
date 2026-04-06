# Technical Backlog

Items identified during QA traceability audit (2026-04-01) and acceptance testing (2026-04-05/06).

## High Priority

| Source | Description | References |
|--------|-------------|------------|
| Security audit | **XFF Trust without validation**: proxy trusts X-Forwarded-For from any client, bypassing IP blocklist, bans, and rate limiting. Add `trusted_proxies` CIDR list to global settings. Only trust XFF when direct client IP is in the list. | `proxy_wiring.rs:548` |
| Security audit | **WAF config propagation to workers**: custom rules, disabled rules toggles added via dashboard require restart to take effect in workers. Add `CommandType::ReloadWafRules` to the command channel for dynamic propagation. | `main.rs` worker cmd handler |
| Security audit | **Encryption key rotation**: no mechanism to rotate the AES-256-GCM key. If key is lost, all encrypted data (cert private keys, notification configs) is unrecoverable. Implement `rotate_key(old, new)` and document key backup. | `crypto.rs` |

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| Security audit | **Mutex poisoning**: `std::sync::Mutex::lock().unwrap()` in LogStore, EwmaTracker, and notification history will panic if a previous holder panicked. Consider `parking_lot::Mutex` (no poisoning) or `.unwrap_or_else(\|e\| e.into_inner())`. | `log_store.rs`, `proxy_wiring.rs` |
| Acceptance test | **WAF auto-ban per-worker**: ban threshold counter is per-worker (not shared). With 6 workers and threshold=3, up to 18 requests may pass before ban. Consider shared counter via DashMap on supervisor or forwarding violation counts. | `proxy_wiring.rs:926` |
| Acceptance test | **IP blocklist toggle not propagated to workers in real-time**: disabling the blocklist in dashboard doesn't take effect until restart. The command channel propagation exists but may not cover all toggle paths. | `main.rs` worker cmd handler |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| Code audit | **Stale `#[allow(dead_code)]`** on `RouteEntry` - may no longer be needed after recent refactors. | `proxy_wiring.rs:44` |
| Code audit | **`request_counts` and `waf_counts` DashMaps** grow with each unique (route_id, status) pair. Bounded by config but never cleared. Consider periodic reset if metrics are forwarded to Prometheus. | `proxy_wiring.rs:419-421` |
| Acceptance test | **HTTP request smuggling rule (920100)** untestable via curl - rejected at protocol level before WAF evaluation. Consider if the rule adds value or should be removed. | `rules.rs:236` |
| UX | **WAF events in detection mode**: events are forwarded via waf.sock but persistence depends on worker having a LogStore. Verify detection-mode events are always persisted. | `proxy_wiring.rs`, `main.rs` |
