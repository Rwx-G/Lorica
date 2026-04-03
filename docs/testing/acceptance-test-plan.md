# Lorica - Acceptance Test Plan

Full scope validation organized by dashboard user flow. Each test maps to an EPIC/Story AC.
Test with `--workers 6` to validate worker mode simultaneously.

**Method**: Dashboard = browser UI, API = curl/API, Proxy = send traffic, CLI = command line
**Status**: ` ` = not tested, `OK` = passed, `KO` = failed (add note)

| # | Test | Method | Expected | Story | Status |
|---|------|--------|----------|-------|--------|
| | **0. INSTALLATION AND STARTUP** | | | | |
| 0.1 | Install .deb package | CLI | `dpkg -i` succeeds, service enabled | 4.4 | |
| 0.2 | Service starts, admin password in journal | CLI | `journalctl -u lorica` shows password | 1.2, 1.4 | |
| 0.3 | Binary shows version | CLI | `lorica --version` -> 0.1.3 | 1.2 | |
| 0.4 | Data directory created | CLI | `/var/lib/lorica/lorica.db` exists | 1.3 | |
| 0.5 | Encryption key created with 0600 perms | CLI | `encryption.key` exists, `-rw-------` | 4.5 | |
| 0.6 | Database has 0600 perms | CLI | `lorica.db` shows `-rw-------` | 4.5 | |
| 0.7 | systemd hardening active | CLI | PrivateTmp, NoNewPrivileges, ProtectSystem | 4.5 | |
| 0.8 | LimitNOFILE=65536 | CLI | `/proc/$(pgrep lorica)/limits` shows 65536 | 4.5 | |
| 0.9 | Workers spawned | CLI | `ps aux` shows 6 worker processes | 2.1 | |
| 0.10 | Log socket created | CLI | `/var/lib/lorica/log.sock` exists | - | |
| | **1. AUTHENTICATION** | | | | |
| 1.1 | Open dashboard in browser | Dashboard | Login page at `http://localhost:9443` | 1.5 | |
| 1.2 | Login with initial admin password | Dashboard | Redirected to "Change Password" | 1.4 | |
| 1.3 | Change password (weak) | Dashboard | Error: password too short/weak | 1.4 | |
| 1.4 | Change password (valid) | Dashboard | Redirected to Overview | 1.4 | |
| 1.5 | Login with new password | Dashboard | Overview displayed | 1.4 | |
| 1.6 | Login with wrong password | Dashboard | Error message displayed | 1.4 | |
| 1.7 | Login rate limiting | API | 5+ failed logins -> 429 | 4.5 | |
| 1.8 | Session cookie HTTP-only, Secure | API | Inspect Set-Cookie header | 4.5 | |
| 1.9 | Session expiry | Dashboard | Idle timeout -> redirected to login | 4.5 | |
| 1.10 | Logout | Dashboard | Click "Sign out" -> login page | 1.5 | |
| 1.11 | Graceful disconnect on restart | Dashboard | Restart Lorica -> error message, redirect to login | - | |
| | **2. OVERVIEW** | | | | |
| 2.1 | Getting started guide visible | Dashboard | Banner with 10 setup steps | - | |
| 2.2 | Steps expand/collapse animated | Dashboard | Click chevron, smooth open/close | - | |
| 2.3 | "Go" buttons navigate | Dashboard | Each "Go" -> correct page | - | |
| 2.4 | "Don't show this again" | Dashboard | Banner dismissed, persisted localStorage | - | |
| 2.5 | Settings toggle re-enables guide | Dashboard | Settings > Preferences > toggle on | - | |
| 2.6 | Section helpers ("?" buttons) | Dashboard | Click "?" -> description appears | - | |
| 2.7 | System section metrics | Dashboard | Uptime, connections, CPU, memory | 1.9 | |
| 2.8 | Routes & Backends section | Dashboard | Counts, health status colors | 1.6 | |
| 2.9 | Auto-refresh (30s) | Dashboard | "Last update" timestamp updates | 1.9 | |
| 2.10 | Color: orange for 0 routes | Dashboard | 0 routes/backends/certs -> orange | - | |
| 2.11 | Color: green for healthy | Dashboard | Backends healthy > 0 -> green | - | |
| | **3. BACKENDS** | | | | |
| 3.1 | Create backend | Dashboard | Add with address, name, group | 1.6 | |
| 3.2 | Health check TCP | Proxy | Reachable port -> healthy (green) | 1.8 | |
| 3.3 | Health check HTTP | Proxy | health_check_path -> healthy if 2xx | 1.8 | |
| 3.4 | Health check - degraded | Proxy | >2s latency -> degraded (orange) | 1.8 | |
| 3.5 | Health check - down | Proxy | Unreachable port -> down (red) | 1.8 | |
| 3.6 | TLS upstream | Dashboard | tls_upstream -> proxy connects via TLS | 1.8 | |
| 3.7 | HTTP/2 upstream | Dashboard | h2_upstream -> proxy uses h2c/h2 | - | |
| 3.8 | Weight | Dashboard | Set weight, observe distribution | 1.8 | |
| 3.9 | Edit backend | Dashboard | Change address/weight, verify | 1.6 | |
| 3.10 | Delete backend | Dashboard | Confirm dialog, removed | 1.6 | |
| 3.11 | Backend drain on removal | Proxy | Remove with active connections -> Closing | 2.4 | |
| 3.12 | EWMA score displayed | Dashboard | EWMA column shows latency | 4.3 | |
| 3.13 | Active connections counter | Dashboard | Connections visible per backend | 2.4 | |
| 3.14 | Search/filter/sort | Dashboard | Search name/group/address, sort | 1.6 | |
| 3.15 | backend_down notification | CLI | Backend goes down -> notification dispatched | 3.3 | |
| | **4. ROUTES** | | | | |
| 4.1 | Create route (minimal) | Dashboard | Hostname + backend -> created | 1.6 | |
| 4.2 | Traffic flows through route | Proxy | `curl -H "Host: ..." http://lorica:8080` | 1.8 | |
| 4.3 | Path prefix routing | Proxy | /api prefix only matches /api/* | 1.8 | |
| 4.4 | Assign TLS certificate | Dashboard | Select cert, HTTPS works | 1.8 | |
| 4.5 | Remove TLS certificate | Dashboard | Deselect cert, save -> cleared | - | |
| 4.6 | Route drawer: tabs work | Dashboard | General/Timeouts/Security/Headers/CORS/Caching/Protection | - | |
| 4.7 | Force HTTPS redirect | Proxy | force_https -> 301 to HTTPS | 6.1 | |
| 4.8 | Hostname redirect | Proxy | redirect_hostname -> 301 | 6.3 | |
| 4.9 | Hostname aliases | Proxy | Alias traffic reaches same backend | 6.3 | |
| 4.10 | Proxy headers (set) | Proxy | Custom header received by backend | 6.1 | |
| 4.11 | Proxy headers (remove) | Proxy | Header removed from backend request | 6.1 | |
| 4.12 | Response headers (set) | Proxy | Custom header received by client | 6.2 | |
| 4.13 | Security header preset (strict) | Proxy | HSTS, X-Frame-Options, CSP in response | 6.2 | |
| 4.14 | Security header preset (custom) | Dashboard | Create custom preset, assign to route | 6.2 | |
| 4.15 | Path rewrite: strip/add prefix | Proxy | /api/users -> /v2/users | 6.2 | |
| 4.16 | Path rewrite: regex | Proxy | Capture groups work | - | |
| 4.17 | Timeouts (connect/read/send) | Proxy | Low timeout + slow backend -> error | 6.1 | |
| 4.18 | Max request body size | Proxy | Exceed limit -> 413 | 6.1 | |
| 4.19 | WebSocket passthrough | Proxy | websocket_enabled -> WS works | 6.1 | |
| 4.20 | Access log toggle | Proxy | Disable -> no log for this route | 6.2 | |
| 4.21 | Per-route compression | Proxy | compression_enabled -> gzip response | - | |
| 4.22 | Retry attempts | Proxy | First backend fails -> retry next | - | |
| 4.23 | Load balancing: round-robin | Proxy | Even distribution | 1.8 | |
| 4.24 | Load balancing: Peak EWMA | Proxy | Lowest-latency backend preferred | 4.3 | |
| 4.25 | Load balancing: consistent hash | Proxy | Same client -> same backend | - | |
| 4.26 | Load balancing: random | Proxy | Random distribution | - | |
| 4.27 | Topology type | Dashboard | SingleVM/HA/Custom adapts health behavior | 3.2 | |
| 4.28 | Route enable/disable | Dashboard | Disabled -> 404 for that hostname | 1.6 | |
| 4.29 | Delete route | Dashboard | Confirm dialog, removed | 1.6 | |
| 4.30 | Search/filter/sort | Dashboard | Search hostname, sort health/enabled | 1.6 | |
| 4.31 | Nginx import wizard | Dashboard | Paste nginx.conf -> resources created | - | |
| 4.32 | Hot-reload on API change | Proxy | Edit route -> traffic reflects change immediately | 1.8, 2.2 | |
| | **5. CERTIFICATES** | | | | |
| 5.1 | Upload PEM certificate | Dashboard | Issuer/dates/SANs parsed correctly | 1.7 | |
| 5.2 | Certificate detail view | Dashboard | Eye icon -> full metadata, chain, routes | 1.7 | |
| 5.3 | Expiration thresholds config | Dashboard | Gear icon -> warning (30d) / critical (7d) | 1.7 | |
| 5.4 | Expiry badge colors | Dashboard | <7d red, <30d orange, >30d green | 1.7 | |
| 5.5 | Self-signed generation | Dashboard | "Self-signed" -> cert created | 1.7 | |
| 5.6 | Self-signed preference memory | Dashboard | Never/Once/Always prompt, persisted | 1.7 | |
| 5.7 | ACME HTTP-01 provision | Dashboard | Let's Encrypt via HTTP-01 (port 80) | 4.1 | |
| 5.8 | ACME DNS-01 automatic | Dashboard | Cloudflare/Route53 -> TXT auto-created | 4.1 | |
| 5.9 | ACME DNS-01 manual | Dashboard | Get TXT record, create manually, confirm | 4.1 | |
| 5.10 | ACME staging vs production | Dashboard | Staging checkbox -> test server | 4.1 | |
| 5.11 | Certificate shows ACME flag | Dashboard | is_acme + auto_renew in detail | 4.1 | |
| 5.12 | Manual renew button | Dashboard | Click renew icon on ACME cert | 4.1 | |
| 5.13 | Auto-renewal task | CLI | Logs: "ACME certificate approaching expiry" | 4.1 | |
| 5.14 | cert_expiring notification | CLI | Approaching expiry -> notification dispatched | 3.3 | |
| 5.15 | Edit certificate (rename) | Dashboard | Edit -> change domain name | 1.7 | |
| 5.16 | Edit certificate (replace PEM) | Dashboard | Edit -> new PEM, metadata re-parsed | 1.7 | |
| 5.17 | Delete certificate (no routes) | Dashboard | Delete succeeds, toast shown | 1.7 | |
| 5.18 | Delete certificate (with routes) | Dashboard | Error toast: "referenced by routes" | 1.7 | |
| 5.19 | SNI resolution: exact match | Proxy | SNI=example.com -> correct cert | 2.3 | |
| 5.20 | SNI resolution: wildcard | Proxy | *.example.com matches sub.example.com | 2.3 | |
| 5.21 | SNI resolution: SAN domains | Proxy | All SANs resolve correctly | 2.3 | |
| 5.22 | Certificate hot-swap | Proxy | Upload new cert -> new connections get new cert | 2.3 | |
| 5.23 | CertResolver hot-reload | Proxy | Upload cert via API -> TLS works immediately | - | |
| 5.24 | Private key encrypted at rest | CLI | `sqlite3 lorica.db` -> binary blob, not PEM | 4.5 | |
| 5.25 | HTTPS works in worker mode | Proxy | `--workers 6` + TLS cert -> HTTPS serves traffic | 2.1 | |
| | **6. SECURITY** | | | | |
| 6.1 | WAF rules listed (28 rules) | Dashboard | Security > Rules tab -> 28 rules | 3.1 | |
| 6.2 | WAF rule toggle | Dashboard | Disable/enable individual rule | 3.1 | |
| 6.3 | WAF custom rule | Dashboard | Create custom regex rule | 3.1 | |
| 6.4 | WAF detection mode | Proxy | waf_mode=detection -> logged, not blocked | 3.1 | |
| 6.5 | WAF blocking mode | Proxy | waf_mode=blocking -> 403 | 3.1 | |
| 6.6 | WAF: SQL injection | Proxy | `UNION SELECT` -> detected | 3.1 | |
| 6.7 | WAF: XSS | Proxy | `<script>alert(1)` -> detected | 3.1 | |
| 6.8 | WAF: Path traversal | Proxy | `../../../etc/passwd` -> detected | 3.1 | |
| 6.9 | WAF: Command injection | Proxy | `; cat /etc/passwd` -> detected | 3.1 | |
| 6.10 | WAF: SSRF | Proxy | `169.254.169.254` -> detected | - | |
| 6.11 | WAF: Log4Shell | Proxy | `${jndi:ldap://}` -> detected | - | |
| 6.12 | WAF: XXE | Proxy | `<!DOCTYPE SYSTEM>` -> detected | - | |
| 6.13 | WAF: CRLF | Proxy | `%0d%0a` -> detected | - | |
| 6.14 | WAF events displayed | Dashboard | Events tab -> category/severity | 3.1 | |
| 6.15 | WAF events filter by category | Dashboard | Filter dropdown works | 3.1 | |
| 6.16 | WAF stats cards | Dashboard | Events by category, top attack | 3.1 | |
| 6.17 | WAF < 0.5ms latency | API | Prometheus -> evaluation < 0.5ms | 3.1 | |
| 6.18 | waf_alert notification | CLI | WAF blocks request -> notification | 3.3 | |
| 6.19 | IP blocklist enable | Dashboard | Blocklist toggle ON -> ~80k IPs loaded | - | |
| 6.20 | IP blocklist blocks IP | Proxy | Blocklisted IP -> 403 | - | |
| 6.21 | IP blocklist refresh | Dashboard | Reload button -> fresh list | - | |
| 6.22 | IP blocklist at startup | CLI | Restart -> logs "loaded at startup" | - | |
| 6.23 | Rate limiting | Proxy | > rate_limit_rps -> 429 + Retry-After | 7.2 | |
| 6.24 | Rate limit headers | Proxy | X-RateLimit-Limit/Remaining/Reset | 7.2 | |
| 6.25 | Rate limit burst | Proxy | Burst tolerance allows spikes | 7.2 | |
| 6.26 | Auto-ban on repeated 429 | Proxy | N violations -> 403 (banned) | 7.3 | |
| 6.27 | Ban list visible | Dashboard | Bans tab -> IPs with expiry | 7.3 | |
| 6.28 | Manual unban | Dashboard | Click unban -> IP removed | 7.3 | |
| 6.29 | Ban auto-expiry | Proxy | Wait ban_duration_s -> unbanned | 7.3 | |
| 6.30 | ip_banned notification | CLI | Auto-ban -> notification dispatched | 7.3 | |
| 6.31 | Slowloris detection | Proxy | Slow headers -> 408 | 7.3 | |
| 6.32 | Per-route max connections | Proxy | max_connections=2, 3rd -> 503 | 7.2 | |
| 6.33 | Global connection limit | Proxy | max_global_connections -> 503 | 7.3 | |
| 6.34 | Flood defense | Proxy | RPS > threshold -> limits halved | 7.3 | |
| 6.35 | IP allowlist | Proxy | Non-allowed IP -> blocked | - | |
| 6.36 | IP denylist | Proxy | Denied IP -> blocked | - | |
| 6.37 | CORS headers | Proxy | Access-Control-* headers set | - | |
| | **7. CACHING** | | | | |
| 7.1 | Enable cache on route | Dashboard | cache_enabled=true, cache_ttl_s=60 | 7.1 | |
| 7.2 | Cache HIT | Proxy | 1st MISS, 2nd HIT (X-Cache) | 7.1 | |
| 7.3 | Cache bypass (Authorization) | Proxy | Authorization header -> BYPASS | 7.1 | |
| 7.4 | Cache bypass (Cookie) | Proxy | Cookie header -> BYPASS | 7.1 | |
| 7.5 | Cache respects Cache-Control | Proxy | no-cache -> not cached | 7.1 | |
| 7.6 | Cache purge | API | DELETE /cache/routes/:id -> cleared | 7.1 | |
| 7.7 | Cache stats | Dashboard | Hit rate in Overview + API | 7.1 | |
| 7.8 | Cache TTL expiry | Proxy | After TTL -> MISS again | 7.1 | |
| | **8. SLA AND PERFORMANCE** | | | | |
| 8.1 | Passive SLA data collected | Dashboard | SLA page shows data after traffic | 5.1 | |
| 8.2 | SLA percentiles (p50/p95/p99) | Dashboard | Latency percentile tables | 5.1 | |
| 8.3 | SLA rolling windows | Dashboard | 1h, 24h, 7d, 30d | 5.1 | |
| 8.4 | SLA config per route | Dashboard | Target SLA %, success criteria | 5.1 | |
| 8.5 | SLA breach alert | CLI | Below target -> notification | 5.1 | |
| 8.6 | SLA export (CSV/JSON) | Dashboard | Export button -> file download | 5.1 | |
| 8.7 | SLA data in Overview | Dashboard | Avg SLA, latency, breaches | 5.1 | |
| | **9. ACTIVE PROBES** | | | | |
| 9.1 | Create probe | Dashboard | Route, method, path, interval, status | 5.2 | |
| 9.2 | Probe executes | Dashboard | Results appear (latency, success) | 5.2 | |
| 9.3 | Enable/disable probe | Dashboard | Toggle on/off | 5.2 | |
| 9.4 | Active vs passive SLA | Dashboard | Side-by-side comparison | 5.2 | |
| 9.5 | Delete probe | Dashboard | Probe removed | 5.2 | |
| | **10. LOAD TESTING** | | | | |
| 10.1 | Create load test config | Dashboard | Concurrency, RPS, duration, URL | 5.3 | |
| 10.2 | Run load test | Dashboard | Real-time SSE progress | 5.3 | |
| 10.3 | Safe limit confirmation | Dashboard | Exceed limits -> confirmation popup | 5.3 | |
| 10.4 | Auto-abort on errors | Dashboard | >10% 5xx -> auto-aborted | 5.3 | |
| 10.5 | Abort button | Dashboard | Click abort -> stopped | 5.3 | |
| 10.6 | Historical results | Dashboard | Previous results listed | 5.3 | |
| 10.7 | Clone test config | Dashboard | Clone button -> duplicate | 5.3 | |
| 10.8 | Comparison deltas | Dashboard | Compare two results -> diff | 5.3 | |
| 10.9 | Load test in worker mode | Dashboard | Works with --workers N | 5.3 | |
| | **11. ACCESS LOGS** | | | | |
| 11.1 | Live log stream | Dashboard | Green pulse, real-time entries | 1.9 | |
| 11.2 | Log filtering | Dashboard | Filter by status, route | 1.9 | |
| 11.3 | Log entry details | Dashboard | Method, path, status, latency, backend, IP | 1.8 | |
| 11.4 | WebSocket streaming | Dashboard | Logs via WS (not polling) | 1.9 | |
| 11.5 | Worker mode logs forwarded | Dashboard | All workers' logs visible | - | |
| | **12. SYSTEM** | | | | |
| 12.1 | Version displayed | Dashboard | Lorica version shown | 1.9 | |
| 12.2 | Uptime displayed | Dashboard | Correct uptime | 1.9 | |
| 12.3 | CPU/Memory/Disk gauges | Dashboard | Color thresholds (green/orange/red) | 1.9 | |
| 12.4 | Process memory and CPU | Dashboard | Lorica process metrics | 1.9 | |
| 12.5 | Worker table (PIDs) | Dashboard | Real PIDs (not 0) | 2.1 | |
| 12.6 | Worker health status | Dashboard | Healthy/Unresponsive dot indicator | 2.1 | |
| 12.7 | Worker heartbeat latency | Dashboard | Latency in ms | 2.2 | |
| 12.8 | Auto-refresh (5s) | Dashboard | Metrics update automatically | 1.9 | |
| | **13. SETTINGS** | | | | |
| 13.1 | Global settings | Dashboard | Flood threshold, max connections, topology | 1.10 | |
| 13.2 | Notification channel: SMTP | Dashboard | Configure email, test button | 3.3 | |
| 13.3 | Notification channel: Webhook | Dashboard | Configure webhook, test button | 3.3 | |
| 13.4 | Notification test | Dashboard | "Test" -> dispatched | 3.3 | |
| 13.5 | Alert type filtering | Dashboard | Enable/disable per alert type | 3.3 | |
| 13.6 | Notification history | Dashboard | History table shows recent events | 3.3 | |
| 13.7 | Notification rate limiting | CLI | Burst -> rate limited (10/60s) | 3.3 | |
| 13.8 | Security header presets | Dashboard | Builtins + custom presets | 6.2 | |
| 13.9 | Preference memory | Dashboard | Stored preferences, delete option | 1.10 | |
| 13.10 | Getting started guide toggle | Dashboard | Toggle helper visibility | - | |
| 13.11 | Config export (TOML) | Dashboard | Download button -> file | 1.10 | |
| 13.12 | Config import with diff | Dashboard | Upload TOML, preview, apply | 1.10 | |
| 13.13 | Theme toggle (light/dark) | Dashboard | Persisted across sessions | 1.5 | |
| | **14. PROMETHEUS METRICS** | | | | |
| 14.1 | /metrics endpoint | API | `curl localhost:9443/metrics` | 4.2 | |
| 14.2 | Request count by route/status | API | `lorica_requests_total` | 4.2 | |
| 14.3 | Latency histogram | API | `lorica_request_duration_seconds_bucket` | 4.2 | |
| 14.4 | Active connections gauge | API | `lorica_active_connections` | 4.2 | |
| 14.5 | Backend health gauge | API | `lorica_backend_healthy` | 4.2 | |
| 14.6 | Certificate expiry days | API | `lorica_certificate_expiry_days` | 4.2 | |
| 14.7 | WAF events counter | API | `lorica_waf_events_total` | 4.2 | |
| 14.8 | System CPU/memory | API | `lorica_cpu_usage`, `lorica_memory_bytes` | 4.2 | |
| | **15. NOTIFICATIONS** | | | | |
| 15.1 | cert_expiring dispatched | CLI | Approaching expiry -> stdout log | 3.3 | |
| 15.2 | backend_down dispatched | CLI | Backend unreachable -> notification | 3.3 | |
| 15.3 | waf_alert dispatched | CLI | WAF blocks -> notification | 3.3 | |
| 15.4 | ip_banned dispatched | CLI | Auto-banned -> notification | 7.3 | |
| 15.5 | sla_breached dispatched | CLI | SLA below target -> notification | 5.1 | |
| 15.6 | Email channel delivery | CLI | SMTP notification received | 3.3 | |
| 15.7 | Webhook channel delivery | CLI | HTTP POST received | 3.3 | |
| | **16. WORKER MODE** | | | | |
| 16.1 | Config reload propagated | Proxy | Edit route -> all workers update | 2.2 | |
| 16.2 | Cert reload propagated | Proxy | Upload cert -> workers reload TLS | 2.3 | |
| 16.3 | Worker crash + restart | CLI | `kill -9` worker -> restart <1s | 2.1 | |
| 16.4 | Graceful shutdown | CLI | `systemctl stop` -> 30s drain, clean | 2.1 | |
| 16.5 | SLA metrics from workers | Dashboard | SLA data in worker mode | - | |
| 16.6 | Heartbeat monitoring | Dashboard | Latency <100ms | 2.2 | |
| 16.7 | SO_REUSEPORT active | CLI | `ss -tlnp` multiple processes same port | - | |
| 16.8 | TLS termination in workers | Proxy | HTTPS serves traffic with --workers N | 2.1 | |
| | **17. SERVICE DISCOVERY (optional)** | | | | |
| 17.1 | Docker Swarm discovery | API | `docker` feature -> backends auto-discovered | 3.2 | |
| 17.2 | Kubernetes discovery | API | `kubernetes` feature -> pods discovered | 3.2 | |

**Total: 200 test cases across 17 sections**

Last updated: 2026-04-03
