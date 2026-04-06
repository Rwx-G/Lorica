# Technical Backlog

Items identified during QA traceability audit (2026-04-01) and acceptance testing (2026-04-05/06).

## High Priority

| Source | Description | References |
|--------|-------------|------------|
| Security audit | **XFF Trust without validation**: proxy trusts X-Forwarded-For from any client, bypassing IP blocklist, bans, and rate limiting. Add `trusted_proxies` CIDR list to global settings. Only trust XFF when direct client IP is in the list. | `proxy_wiring.rs:548` |

## Medium Priority

| Source | Description | References |
|--------|-------------|------------|
| *(empty - all medium items resolved)* | | |

## Low Priority

| Source | Description | References |
|--------|-------------|------------|
| *(empty - all low items resolved)* | | |

## Resolved

| Item | Resolution |
|------|------------|
| `#[allow(dead_code)]` on RouteEntry | Already removed by prior refactor |
| `request_counts`/`waf_counts` DashMaps | Accepted: bounded by config (routes * status codes), low risk |
| Rule 920100 unreachable | Fixed: added `content-length` and `transfer-encoding` to WAF header inspection list |
| Mutex poisoning | Migrated to `parking_lot::Mutex/RwLock` across all crates |
| WAF config propagation | Already functional via ConfigReload command channel |
| WAF auto-ban per-worker | Fixed: global counter via supervisor + BanIp command broadcast |
| WAF events in detection mode | Working via waf.sock forwarding + supervisor persistence |
| Encryption key rotation | Implemented: `lorica rotate-key --new-key-file` CLI |
| Export secret leak | Fixed: SMTP passwords and private keys redacted in exports |
| Memory leak waf_violations | Fixed: entries removed on ban |
| SQLite busy_timeout | Fixed: PRAGMA busy_timeout=5000 on access-log.db |
