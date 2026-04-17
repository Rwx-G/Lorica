# Technical Backlog

Bug fixes, improvements, and maintenance tasks. For new features, see the Roadmap section in [README.md](/README.md).

## Open

| # | Item | Type | Notes |
|---|------|------|-------|
| 6 | `return_status` path renders an empty body | Bug | `lorica/src/proxy_wiring.rs:2889-2915` writes `ResponseHeader::build(status, None)` with no body when a route has `return_status` set (and no `redirect_to`). Neither the built-in branded error page nor the custom `error_page_html` is rendered. Inconsistent with every other terminal path (403 from IP blocklist/WAF/GeoIP, 429 from rate limit, 502/504 from upstream failures) which all go through `render_error_body()`. Fix: route the `return_status` branch through `render_error_body(status, route.error_page_html.as_deref())`. Estimated ~30 lines. Tracked in UXUI.md as finding #26. |


## Resolved

| # | Item | Type | Resolution |
|---|------|------|------------|
| 1 | Global IP whitelist for WAF bypass | Fix | Resolved in v1.1.0 - Global WAF whitelist IPs in Settings |
| 2 | WAF pattern tuning (body scan false positives) | Fix | Resolved in v1.1.0 - Path traversal and protocol violation rules excluded from body scanning |
| 3 | SLA accuracy in worker mode | Fix | Resolved in v1.1.0 - Supervisor checks thresholds on every flush cycle |
| 4 | CLI unban command | Fix | Resolved in v1.1.0 - `lorica unban <IP> --password <PASSWORD>` |
| 5 | Worker drain timeout too short for long-poll clients | Improvement | Observed in prod during v1.1.0 -> v1.2.0 upgrade: all 6 workers got SIGKILL after the 30 s drain timeout because GitLab runner long-polls (`POST /api/v4/jobs/request`) held connections open past the deadline. Not a bug but hurts graceful upgrades. Options: (a) make drain timeout configurable, (b) close idle keepalives aggressively on SIGTERM, (c) force-close long-polls after a grace period. Impacts zero-downtime deploys. Fixed in 1.4.0 |
