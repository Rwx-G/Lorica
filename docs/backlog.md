# Technical Backlog

Bug fixes, improvements, and maintenance tasks. For new features, see the Roadmap section in [README.md](/README.md).

## Open

| # | Item | Type | Notes |
|---|------|------|-------|


## Resolved

| # | Item | Type | Resolution |
|---|------|------|------------|
| 6 | `return_status` path renders an empty body | Bug | Fixed in v1.4.0. The `proxy_wiring::request_filter` branch for `return_status` (without `redirect_to`) used to write `ResponseHeader::build(status, None)` and no body, so clients received the status code with a blank page - inconsistent with every other terminal path that funnels through `render_error_body()`. The operator's optional `error_page_html` template was also ignored. Now routed through `render_error_body(status, error_page_html)` with `Content-Type: text/html; charset=utf-8` and explicit `Content-Length`. The per-path rule's `error_page_html` overrides the route-level default when set (picked up from `ctx.route_snapshot`). |
| 1 | Global IP whitelist for WAF bypass | Fix | Resolved in v1.1.0 - Global WAF whitelist IPs in Settings |
| 2 | WAF pattern tuning (body scan false positives) | Fix | Resolved in v1.1.0 - Path traversal and protocol violation rules excluded from body scanning |
| 3 | SLA accuracy in worker mode | Fix | Resolved in v1.1.0 - Supervisor checks thresholds on every flush cycle |
| 4 | CLI unban command | Fix | Resolved in v1.1.0 - `lorica unban <IP> --password <PASSWORD>` |
| 5 | Worker drain timeout too short for long-poll clients | Improvement | Observed in prod during v1.1.0 -> v1.2.0 upgrade: all 6 workers got SIGKILL after the 30 s drain timeout because GitLab runner long-polls (`POST /api/v4/jobs/request`) held connections open past the deadline. Not a bug but hurts graceful upgrades. Options: (a) make drain timeout configurable, (b) close idle keepalives aggressively on SIGTERM, (c) force-close long-polls after a grace period. Impacts zero-downtime deploys. Fixed in 1.4.0 |
