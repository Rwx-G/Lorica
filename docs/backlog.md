# Technical Backlog

Bug fixes, improvements, and maintenance tasks. For new features, see [ROADMAP.md](/ROADMAP.md).

## Open

| # | Item | Type | Notes |
|---|------|------|-------|
| 5 | Worker drain timeout too short for long-poll clients | Improvement | Observed in prod during v1.1.0 -> v1.2.0 upgrade: all 6 workers got SIGKILL after the 30 s drain timeout because GitLab runner long-polls (`POST /api/v4/jobs/request`) held connections open past the deadline. Not a bug but hurts graceful upgrades. Options: (a) make drain timeout configurable, (b) close idle keepalives aggressively on SIGTERM, (c) force-close long-polls after a grace period. Impacts zero-downtime deploys. |

## Resolved

| # | Item | Type | Resolution |
|---|------|------|------------|
| 1 | Global IP whitelist for WAF bypass | Fix | Resolved in v1.1.0 - Global WAF whitelist IPs in Settings |
| 2 | WAF pattern tuning (body scan false positives) | Fix | Resolved in v1.1.0 - Path traversal and protocol violation rules excluded from body scanning |
| 3 | SLA accuracy in worker mode | Fix | Resolved in v1.1.0 - Supervisor checks thresholds on every flush cycle |
| 4 | CLI unban command | Fix | Resolved in v1.1.0 - `lorica unban <IP> --password <PASSWORD>` |
