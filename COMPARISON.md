# Lorica - Competitive Feature Comparison

> Last updated: 2026-11-14 | Lorica v1.10.6
>
> **Legend:** Y = Yes | N = No | P = Partial | Paid = Paid/Enterprise only | Plug = Plugin, third-party module or external agent (not built-in) | ? = not verified | - = not applicable
>
> **Competitors:** Pingora (framework), Sozu, Nginx OSS, Traefik OSS v3, BunkerWeb, Caddy v2, HAProxy CE
>
> **Versions checked (2026-11-04):** Pingora 0.9.1, Sozu 2.3.4, Nginx OSS 1.30.6 (stable branch), Traefik OSS 3.7.17, BunkerWeb 1.6.17, Caddy 2.11.8, HAProxy CE 3.4.7 with Data Plane API 3.4.6.
>
> Every cell describes the FREE edition as documented by its own project. The
> Pingora column is a framework, not a shipped proxy: an `N` there usually
> means "no module exists to build on", not "a product is missing a feature".
> The HAProxy management rows rest on the Data Plane API (Apache-2.0, free and
> official), not on the `haproxy` binary.
>
> A feature that needs a plugin, a third-party module or an external agent (an
> SPOA agent, a CrowdSec agent and its bouncer, fail2ban) is `Plug`, for every
> product. Modules a project publishes itself (nginx.org's `nginx-module-acme`,
> `nginx-module-otel`, `nginx-module-geoip`) count as built-in. For Caddy,
> built-in means the standard `caddy` build; anything that needs `xcaddy build
> --with ...` is `Plug`.

---

## 1. Proxy & Routing

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| HTTP/HTTPS reverse proxy | Y | Y | Y | Y | Y | Y | Y | Y |
| Host-based routing | Y | P | Y | Y | Y | Y | Y | Y |
| Path-based routing | Y | P | Y | Y | Y | Y | Y | Y |
| Path rewriting (regex) | Y | N | Y | Y | Y | P | Y | Y |
| WebSocket proxying | Y | Y | Y | Y | Y | Y | Y | Y |
| gRPC proxying | Y | Y | Y | Y | Y | Y | Y | Y |
| gRPC-Web to gRPC bridge | Y | Y | ? | ? | ? | ? | ? | ? |
| HTTP/2 upstream (h2c) | Y | Y | Y | Y | Y | Y | Y | Y |
| HTTP/3 (QUIC) | N | N | N | P | Y | Y | Y | Y |
| TLS termination | Y | Y | Y | Y | Y | Y | Y | Y |
| SNI-based cert selection | Y | P | Y | Y | Y | Y | Y | Y |
| Wildcard cert support | Y | P | Y | Y | Y | Y | Y | Y |
| Catch-all fallback host | Y | P | Y | Y | Y | P | Y | Y |
| Domain redirects (301) | Y | N | Y | Y | Y | Y | Y | Y |
| Direct status responses | Y | P | Y | Y | Plug | Y | Y | Y |
| Custom error pages and maintenance mode per route | Y | ? | ? | ? | ? | ? | ? | ? |
| Response compression (gzip, brotli, zstd) | Y | ? | ? | ? | ? | ? | ? | ? |
| Connection pooling | Y | Y | Y | Y | Y | Y | Y | Y |
| Sticky sessions (cookie) | Y | P | Y | Y | Y | Paid | Y | Y |
| Forward auth | Y | N | N | Y | Y | Y | Y | P |
| Header-based routing | Y | P | Y | Y | Y | N | Y | Y |
| Canary / traffic split (weighted) | Y | N | N | Y | Y | N | P | Y |
| Response body rewriting | Y | N | N | Y | Plug | P | Plug | N |
| **TCP/L4 proxying** | **N** | Y | Y | Y | Y | Y | Plug | Y |
| **UDP proxying** | **N** | N | Y | Y | Y | Y | Plug | Paid |

### Lorica Notes

- **TLS termination** - Lorica terminates TLS with rustls only; no OpenSSL, BoringSSL or s2n is linked. The competitors terminate TLS with their own stacks (Go `crypto/tls` for Traefik, OpenSSL-family libraries for HAProxy).
- **Host matching** - case-insensitive, and a trailing dot or an IPv6 literal with a port resolves to the same route (canonical hostnames, fixed in v1.10.2); since v1.10.5 an IPv6 literal however it is written, and an IPv4 address only in dotted decimal, as browsers send it.
- **Clients dialing an IP** (v1.10.5) - a client that sends no SNI gets the certificate whose IP SAN is the address it connected to, so a route named by an IP is served over HTTPS without a DNS name. Every competitor treats this as table stakes, so it carries no row.

### Gaps for Lorica

- **TCP/L4 and UDP proxying** - Supported by most competitors. Enables database, MQTT, SSH, DNS and syslog proxying.
- **HTTP/3 (QUIC)** - Caddy (since 2.6), Traefik v3 and HAProxy (frontend QUIC since 2.8) have production support, BunkerWeb enables NGINX's QUIC by default, and Nginx still documents `ngx_http_v3_module` as experimental. Upstream Pingora has no QUIC code: [issue #95](https://github.com/cloudflare/pingora/issues/95) is open and labelled a long-term goal, and the `quiche::h3` PRs #514 and #524 were closed unmerged. Long-term gap.

---

## 2. Load Balancing

| Algorithm | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Round Robin (weighted) | Y | Y | Y | Y | Y | Paid | Y | Y |
| Least Connections | Y | N | Y | Y | Y | N | Y | Y |
| Peak EWMA | P | N | N | N | N | N | N | N |
| Consistent Hash | Y | Y | Y | Y | Y | N | Y | Y |
| Random | Y | Y | Y | Y | N | N | Y | Y |
| IP Hash | Y | Y | Y | Y | Y | Paid | Y | Y |
| Health-aware filtering | Y | Y | Y | P | Y | Paid | Y | Y |
| Traffic mirroring | Y | N | N | Y | Y | N | Plug | Plug |

### Lorica Notes

- **IP Hash** - Lorica has no algorithm under that name, and does not need one: `consistent_hash` is a ketama ring keyed on the client IP, X-Forwarded-For aware when the immediate peer is in `trusted_proxies`. The operator-visible property is the one Nginx's `ip_hash` delivers, a client that keeps reaching the same backend. What differs is the remap when the backend set changes: the ring moves roughly 1/N of the clients, a modulo over N backends moves nearly all of them. A separate modulo variant would be strictly worse and is not planned.
- **Consistent Hash** - the ring is keyed on the client IP only. Nginx, HAProxy and Caddy can also hash an arbitrary key (URI, header, cookie); Lorica cannot.
- **Peak EWMA** - the `PeakEwma` strategy is a plain latency EWMA: each response latency feeds a moving average, the backend with the lowest score wins, and a bounded share of calls explores backends that have no score yet. The score does not rise toward a latency peak or with in-flight load, which is what a peak EWMA does, hence `P`. Pingora ships no EWMA selector; the tracker is Lorica's own code (`lorica/src/proxy_wiring/lb.rs`).

### Lorica Strengths

- **Traffic mirroring** - Nginx (`ngx_http_mirror_module`, core since 1.13.4), Traefik, and Lorica ship this natively; Caddy and HAProxy need a plugin or an SPOA agent. Lorica's implementation adds request-body mirroring up to a configurable cap, deterministic sampling on a hash of the request id, and a configurable per-route concurrency cap under a global cap, so a slow shadow cannot starve other routes' mirrors - guardrails that the Nginx directive leaves to the operator.

### Gaps for Lorica

- ~~Least Connections~~ - Implemented in v1.2.0.

---

## 3. Security

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| WAF engine (OWASP rules) | Y (49) | N | N | Plug | Plug | Y | Plug | Plug |
| Custom WAF rules | Y | N | N | Plug | Plug | Y | Plug | Plug |
| IP blocklist (auto-fetched) | Y | N | N | Plug | Plug | Y | Plug | Plug |
| Rate limiting per route | Y | P | P | Y | Y | Y | Plug | Y |
| Auto-ban (repeat offenders) | Y | N | N | Plug | Plug | Y | Plug | P |
| Trusted proxies (XFF) | Y | N | P | Y | Y | Y | Y | P |
| DDoS protection (flood) | Y | N | P | P | N | P | N | P |
| Slowloris detection | Y | N | P | P | N | N | P | P |
| Security header presets | Y | N | N | N | Y | Y | N | N |
| IP allowlist/denylist | Y | N | N | Y | Y | Y | Y | Y |
| CORS per route | Y | N | N | P | Y | Y | P | P |
| Basic auth per route | Y | N | Y | Y | Y | Y | Y | Y |
| Bot detection (PoW / captcha / cookie) | Y | N | N | Plug | Plug | Y | Plug | Paid |
| Country blocking (GeoIP) | Y | N | N | P | Plug | Y | Plug | P |
| ASN-based bypass / filter | P | N | N | N | N | Y | Plug | N |
| Request body scanning | Y | N | N | Plug | Plug | Y | Plug | Plug |
| Request body size limit and connection cap per route | Y | ? | ? | ? | ? | ? | ? | ? |
| mTLS client verification | Y | Y | Y | Y | Y | Y | Y | Y |
| Connection pre-filter (pre-TLS CIDR) | Y | P | P | P | N | P | Plug | Y |
| AI / LLM crawler deny-list (verified) | Y | N | N | N | Plug | P | Plug | Paid |

### Lorica Notes

- **ASN** - an ASN only exempts a client from the bot challenge, as one category of the bypass matrix. There is no ASN block or allow filter, and it needs an ASN database configured, which is off by default. BunkerWeb's free core blacklists, whitelists and greylists by ASN.

### Lorica Strengths

- **Built-in WAF** with 49 OWASP CRS-inspired rules (Lorica's own regexes, numbered after the CRS; it does not run the CRS itself) - only BunkerWeb, which runs ModSecurity with the OWASP CRS, matches this out of the box. Nginx, Traefik and Caddy need a plugin, HAProxy the experimental Coraza SPOA agent.
- **Auto-ban** - Only BunkerWeb ships it turnkey (Bad Behavior plugin). HAProxy builds it from stick tables; Nginx, Traefik and Caddy need fail2ban or a CrowdSec agent and bouncer.
- **IP blocklist auto-fetch** - Only BunkerWeb has it built in (Blacklist plugin + BunkerNet). Nginx, Traefik, Caddy and HAProxy consume CrowdSec blocklists through a bouncer and an external agent.
- **Slowloris detection** - a per-route threshold on how long the request headers take to arrive, on top of the global header timeout. Nginx, Sozu, Caddy and HAProxy mitigate the same attack with header and body timeouts.
- **Connection pre-filter at TCP accept** - CIDR allow/deny evaluated before the TLS handshake, hot-reloaded without rebuilding listeners.
- **AI / LLM crawler deny-list** (v1.6.0) - the only built-in curated list with per-vendor verification outside HAProxy's Enterprise Bot Management Module. BunkerWeb's free `robotstxt` plugin ships community AI-crawler lists but only ADVERTISES them in `robots.txt`; Lorica serves the same advisory file AND enforces the policy per route, with forward-confirmed rDNS or bundled published IP ranges where the vendor offers one, a counted User-Agent-only match where it does not, and an explicit stance on a spoofed User-Agent.

### Gaps for Lorica

- ~~Basic auth per route~~ - Implemented in v1.2.0.
- ~~mTLS client verification~~ - Implemented in v1.3.0.
- ~~Bot detection~~ - Implemented in v1.4.0 (three modes: cookie, JavaScript PoW, image captcha). Five-category bypass matrix (IP CIDR, ASN, country, User-Agent regex, rDNS with forward confirmation).
- ~~Country blocking~~ - Implemented in v1.4.0 (GeoIP via DB-IP Lite Country, weekly auto-update once enabled, per-route allowlist / denylist).

---

## 4. Caching

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| HTTP response cache | Y | P | N | Y | Plug | Y | Plug | Y |
| Cache lock (thundering-herd protection) | Y | Y | N | ? | ? | Paid | ? | ? |
| LRU eviction | Y | Y | N | Y | ? | Y | Plug | Y |
| Per-route toggle | Y | P | N | Y | ? | Y | Plug | Y |
| Cache-Control respect | Y | P | N | Y | ? | Y | Plug | Y |
| Cache purge API | Y | P | N | Plug | ? | N | Plug | N |
| X-Cache-Status header | Y | N | N | P | ? | Y | Plug | P |
| Vary header partitioning | Y | P | N | Y | ? | Y | Plug | P |
| Stale-while-revalidate (background refresh) | Y | P | N | Y | ? | Paid | Plug | N |
| Cache predictor (learn-uncacheable) | Y | Y | N | N | ? | N | N | N |

### Lorica Notes

- **HTTP response cache** - in memory only, with a fixed size per process (`CACHE_SIZE_LIMIT` in `lorica/src/proxy_wiring.rs`), and each worker holds its own cache. There is no disk tier, where Nginx's `proxy_cache` lives on disk.

### Lorica Strengths

- **Built-in HTTP cache** - Nginx, HAProxy and BunkerWeb (NGINX `proxy_cache` in its free reverse-proxy plugin) match this natively. Traefik OSS and Caddy need the Souin or cache-handler plugin; Traefik's native cache is a paid Traefik Hub middleware.
- **Cache purge API** - Not available natively in Nginx OSS, HAProxy or BunkerWeb. Pingora provides the PURGE hooks Lorica builds on.
- **Stale-while-revalidate with background refresh** - shared with Nginx (`proxy_cache_background_update`, a background subrequest while the stale response is served). HAProxy has none, and BunkerWeb's background update is PRO.
- **Cache predictor** - shared 16-shard LRU remembers deterministically-uncacheable responses so future requests for the same key skip the cache state machine entirely. Only Pingora's framework ships the equivalent.

---

## 5. TLS & Certificates

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| ACME HTTP-01 | Y | N | N | Y | Y | Y | Y | Y |
| ACME DNS-01 | Y | N | N | N | Y | Y | Plug | Y |
| ACME TLS-ALPN-01 | N | N | N | Y | Y | Paid | Y | N |
| AD CS enrollment (CES, Kerberos) | Y | N | N | N | N | N | N | N |
| Auto-renewal | Y | N | N | Y | Y | Y | Y | Y |
| Multi-domain SAN | Y | N | N | Y | Y | Y | Y | Y |
| Wildcard via DNS-01 | Y | N | N | N | Y | Y | Plug | Y |
| SNI hot-swap | Y | P | Y | N | Y | N | Y | Y |
| CRL support | P | P | Y | Y | Plug | Y | Plug | Y |
| OCSP stapling | Y | N | N | Y | Y | Paid | Y | Y |
| mTLS client certs | Y | Y | Y | Y | Y | Y | Y | Y |
| Certificate export to the filesystem | Y | ? | ? | ? | ? | ? | ? | ? |

### Lorica Strengths

- **ACME DNS-01 with 3 providers** (Cloudflare, Route53, OVH) + manual mode. Traefik ships many more DNS providers built in, and Caddy offers many as caddy-dns plugins (none in the standard build); Lorica's spread covers the common European-centric set. Route 53 is an opt-in Cargo feature (not in the default `.deb` / `.rpm` build) to keep the AWS SDK dep graph out of the default binary.
- **Internal certificates from Active Directory Certificate Services** (v1.10.0, first packaged in v1.10.1) - Lorica enrolls, renews and adopts certificates from an AD CS authority through its Certificate Enrollment Web Service, with Kerberos and a TLS channel binding, so an internal PKI is served the way Let's Encrypt is. The others serve public names through ACME and leave an AD CS estate to a separate enrollment tool or a manual CSR workflow.
- **SNI hot-swap** via arc-swap - zero-downtime cert rotation.
- **Per-route mTLS policy** - chain verification at the TLS listener plus per-route enforcement knobs (`required`, org allowlist) that hot-reload without restart. Nginx, Caddy, Traefik and HAProxy also scope client-certificate verification per host name, and Nginx and HAProxy can express an organization allowlist in configuration; Lorica's difference is a turnkey per-route field.
- **One outbound TLS policy** (v1.10.2) - the outbound clients (ACME, DNS providers, notifications, GeoIP and blocklist downloads, OCSP, OIDC keys, forward auth, mirroring, the MCP client, the CLI) are built from `lorica-tls/src/http_client.rs`, and a clippy lint refuses a client built anywhere else; the opt-in Route 53 SDK keeps its own stack. Upstream TLS verifies against the system roots, with a per-backend SNI override and a per-backend skip-verify.

### Gaps for Lorica

- ~~mTLS client verification~~ - Implemented in v1.3.0.
- ~~OCSP stapling~~ - Implemented in v1.2.0.
- **CRL on downstream client certificates** - Lorica checks CRLs on upstream server certificates (`--upstream-crl-file`, reloaded on a timer) and on the fleet's own certificates, but not on client certificates presented to an mTLS route. Nginx, HAProxy, Sozu and BunkerWeb check those, hence `P`.

---

## 6. Monitoring & Observability

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Passive SLA monitoring | Y | N | N | N | N | N | N | N |
| Active SLA probes | Y | P | N | Paid | Y | Paid | Y | Y |
| Prometheus metrics | Y | P | P | Plug | Y | Paid | Y | Y |
| Grafana dashboard shipped with the project | Y | ? | ? | ? | ? | ? | ? | ? |
| Real-time access logs (WS) | Y | N | N | N | N | N | N | N |
| Built-in load testing | Y | N | N | N | N | N | N | N |
| SLA breach alerts | Y | N | N | N | N | N | N | N |
| OpenTelemetry tracing (OTLP) | Y | P | P | Y | Y | N | Y | Plug |
| Structured JSON logs | Y | P | P | Y | Y | Y | Y | Y |
| Syslog export (RFC 5424, TCP + TLS) | Y | N | N | N | N | P | N | Y |
| OTLP log export (logs signal) | Y | N | N | N | Y | N | Plug | Plug |
| Conditional request + response capture | Y | N | N | P | P | P | P | P |

### Lorica Notes

- **OpenTelemetry tracing and OTLP log export** - both need a binary built with `--features otel`; the `.deb`, the `.rpm` and the Dockerfile build without it. W3C `traceparent` propagation is always on.

### Lorica Strengths

- **Passive SLA monitoring** - Unique feature. No competitor offers built-in SLA tracking from real traffic.
- **Active SLA probes** - Combined with passive SLA, provides comprehensive uptime monitoring.
- **Built-in load testing** - Unique. No competitor includes this.
- **Real-time WebSocket log streaming** - Unique dashboard feature.
- **SLA breach alerts** - Unique: an alert on an SLA threshold, not only on a server state change (HAProxy's `email-alert`).
- **Syslog in RFC 5424 over TCP and TLS** (v1.7.0) - HAProxy is the only competitor that frames RFC 5424 and can wrap a log ring in TLS. Nginx's `syslog:` emits an RFC 3164 header over UDP or a unix datagram socket with no TLS path at all, BunkerWeb inherits exactly that, and Traefik and Caddy ship no syslog sink (Caddy's `net` writer is raw bytes with no framing).
- **OTLP LOG records** (v1.7.0, `--features otel`) - Traefik v3.3+ is the only other first-party logs exporter, and it is still behind `experimental.otlpLogs`. HAProxy's is an out-of-tree addon that requires rebuilding HAProxy; Caddy's is a third-party module. Everyone else exports traces or metrics and stops there.
- **Conditional capture of the whole exchange** (v1.8.0) - Nginx decides at log time (`access_log ... if=`, so on the status) but records headers and the request body only. Caddy's `log_append` can record the response body, in a mode its own documentation labels debug-only. BunkerWeb's ModSecurity audit log (`RelevantOnly`) keeps request and response bodies on WAF matches and relevant statuses, in ModSecurity's native multipart format. None of them combines request-side buffering predicates, credential redaction and one structured record. Lorica decides buffering on request-side predicates, emission on the status, latency or upstream error, redacts credentials, and emits one structured record that joins the access-log row on `request_id`.

### Gaps for Lorica

- ~~OpenTelemetry tracing~~ - Implemented in v1.4.0 as an off-by-default Cargo feature (`otel`), not built into the `.deb`, `.rpm` or Docker image. W3C trace context propagation, per-request spans with OTel HTTP semconv, log/trace correlation. Non-OTel users do not pay the dep-graph cost.
- ~~SIEM export~~ - Implemented in v1.7.0 (syslog RFC 5424 over UDP / TCP / TCP+TLS, and OTLP log records under `--features otel`), extended in v1.8.0 with capture records and a per-event-kind switch on each sink.
- ~~Structured JSON logs to file/syslog~~ - Implemented in v1.2.0.

---

## 7. Management & Dashboard

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Web dashboard (full CRUD) | Y | N | N | Paid | P (RO) | Y | N | P |
| REST API (full CRUD) | Y | N | N | Paid | P (RO) | Y | Y | Y |
| Config export/import | Y | N | Y | N | N | Y | Y | Y |
| Nginx config import | Y | N | N | - | N | N | Plug | N |
| Notification channels | Y | N | N | N | N | Plug | N | P |
| SMTP/Slack/Webhook alerts | Y | N | N | N | N | Plug | N | P |
| CLI management | P | N | Y | Y | Y | Y | Y | Y |
| Multi-user RBAC (management plane) | Y | N | N | N | Paid | P | P | P |
| Tamper-evident audit log (hash chain) | Y | N | P | N | N | N | N | P |
| Multi-node control plane (built-in) | Y | N | N | N | Paid | Y | P | Paid |
| Scoped API tokens (management plane) | Y | N | N | N | N | Y | P | N |
| OIDC / workload identity for CI | Y | N | N | N | N | N | N | N |
| Management MCP server (read / config / admin tiers) | Y | ? | ? | ? | ? | P | ? | ? |
| Ephemeral CI environments (route, backends and certificate in one call, with a TTL) | Y | ? | ? | ? | ? | ? | ? | ? |
| Automation writes cannot weaken a route's access controls | Y | ? | ? | ? | ? | ? | ? | ? |
| **Docker label discovery** | **N** | N | N | N | Y | Y | Plug | N |
| **Kubernetes Ingress** | **N** | N | N | Y | Y | Y | P | Y |
| **Config providers (etcd/Consul)** | **N** | N | N | N | Y | N | N | P |

### Lorica Notes

- **CLI management** - the `lorica` CLI covers key rotation, unban, hot upgrade, the cluster lifecycle and break-glass, and minting automation and MCP tokens. Route, backend and certificate CRUD goes through the dashboard or the API, hence `P`.

### Lorica Strengths

- **Full CRUD dashboard** - Only BunkerWeb matches this, with a separate web UI service on its own database where Lorica's is embedded in the binary. Traefik's dashboard is read-only. HAProxy's stats page is read-only by default; `stats admin` adds enabling and disabling servers.
- **Nginx config import** - a dashboard wizard. Caddy's official-org `nginx-adapter` plugin converts an nginx.conf to Caddy JSON but is incomplete by its own README and has no wizard; no other competitor offers migration tooling.
- **Notification channels** (SMTP, Slack, Webhook) - built in. BunkerWeb sends attack alerts through free official Slack, Discord, Matrix and WebHook plugins (its built-in SMTP and webhook reporting are PRO), and HAProxy CE mails server state changes through `mailers` and `email-alert`, SMTP only. The others have none.
- **Config export/import with diff preview** - Unique. Sozu, BunkerWeb, Caddy and HAProxy (Data Plane API) export and import configuration; Lorica previews the diff before applying it.
- **Multi-user RBAC** (v1.6.0) - three roles on the product's own management plane. Traefik's OSS dashboard has no accounts at all (RBAC is Hub). BunkerWeb's free web UI has a single admin (UI accounts and roles need the PRO User Manager), while its free API takes extra users with per-resource scopes from a bootstrap file. HAProxy's Data Plane API authenticates several users who are all full admins; its runtime API only has the coarse `level user | operator | admin` of the stats socket. Caddy scopes remote admin per client certificate, which is an ACL, not an account model.
- **Tamper-evident audit log** (v1.6.0) - Sozu records every command-socket mutation and HAProxy's Data Plane API versions each configuration with an MD5 and keeps backups, but neither CHAINS its entries nor ships a verification command. Lorica's chain is verifiable end to end and localises the earliest broken row; in a fleet each node's trail is its own chain, verified separately.
- **Multi-node control plane** (v1.7.0) - BunkerWeb is the only free competitor with a built-in equivalent: its scheduler pushes rendered configuration to instances listed in `BUNKERWEB_INSTANCES`, authenticated by an IP allowlist and an optional shared bearer token mirrored on every node. Lorica enrolls each follower under the fleet's own CA, so every node holds a distinct identity and the plane is mutually authenticated, and since v1.8.0 the control plane cuts the payload per recipient: a follower receives only the routes, backends, certificates and rules it serves, and never the rest of the fleet's topology. Bans apply fleet-wide, and a follower carries a break-glass command. Caddy coordinates ACME through shared storage and can push a configuration to one known address, but enumerates no roster; Traefik's clustered control plane is Traefik Enterprise and HAProxy's configuration push is Fusion, both paid. `peers` synchronises stick tables, not configuration.
- **Scoped API tokens** (v1.8.0) - BunkerWeb's free API is the one real peer, issuing Biscuit tokens with a TTL and per-resource permissions, on an API service separate from its web UI. Caddy's remote admin scopes paths and methods but the credential is a client certificate, and its local endpoint is unauthenticated; HAProxy's Data Plane API declares basic auth or mTLS with no scopes. Lorica's token also carries the hostname patterns and the backend CIDRs it may reach, which BunkerWeb's does not, and answers on an automation listener separate from the management plane, where BunkerWeb's scoped tokens and admin credentials share one API.
- **OIDC workload identity for CI** (v1.8.0) - unique. Every competitor's OIDC or JWT support authenticates PROXIED application traffic; none of them lets a CI job authenticate to the management plane with its own short-lived ID token. Lorica accepts a GitLab ID token under RS256 with a pinned issuer, audience and bound claims on project, ref and environment, which removes the shared secret from the CI variables entirely.
- **Management MCP server** (v1.9.0) - three tiers (read, config, admin) that are scope sets on the automation tokens, one tier per token (fixed for the process over stdio, checked on every request over Streamable HTTP), every call in the audit chain. BunkerWeb ships an official free MCP server as a separate image, with a single global read-only switch, no per-client roles, no per-call audit, and, by its own documentation, no built-in authentication on its `/mcp` endpoint.
- **Automation guard rails** (v1.8.0, v1.10.2) - one idempotent `environment` call binds a hostname, backends and a certificate for a review app, with a TTL and a reaper; since v1.10.2 an automation write cannot weaken a route's access controls, in place or through a delete, a rename or an alias drop (route protection records).

### Out of Scope by Design

- **Service discovery** (Docker labels, Kubernetes Ingress) and **config providers** (etcd, Consul, etc.) are deliberately out of scope. Lorica targets the **standalone edge / bastion** use case (runs in front of clusters, not inside them). Operators that need in-cluster service discovery are better served by Traefik. Lorica's positioning is "the bastion-class reverse proxy with a dashboard": cert auto-renewal, WAF, bot protection, GeoIP, SLA, auto-ban, audit trail, all in one binary that an SRE drops on a VM.

---

## 8. Reliability & Operations

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Worker process isolation | Y | N | Y | Y | N | Y | N | N |
| Zero-downtime reload | Y | Y | Y | Y | Y | Y | Y | Y |
| Health checks (TCP/HTTP) | Y | Y | Y | Paid | Y | Paid | Y | Y |
| Circuit breaker | Y | N | P | P | Y | N | P | P |
| Graceful drain | Y | Y | Y | Y | Y | Y | Y | Y |
| Encrypted storage (AES) | Y | N | N | N | N | N | N | N |
| Retry with backoff | P | P | Y | P | Y | N | Y | P |
| Hot binary upgrade | Y | Y | Y | Y | N | Y | N | Y |

### Lorica Strengths

- **Worker process isolation** with protobuf command channel - only Nginx, the NGINX-based BunkerWeb and Sozu have comparable models.
- **Circuit breaker** - failure tracking per (route, backend) with a half-open probe, so two routes sharing an upstream trip independently.
- **Encrypted storage** - No competitor encrypts its configuration store at rest built in. Nginx loads passphrase-protected private keys (`ssl_password_file`), BunkerWeb encrypts only its 2FA seeds, and Caddy needs the third-party `caddy-encrypted-storage` module for its certificate storage.

### Gaps for Lorica

- **Retry backoff** - Retries shipped in v1.2.0 (`retry_attempts`, `retry_on_methods`, through the fork's `max_request_retries` hook) as immediate re-attempts on errors the framework marks retryable; there is no delay or backoff between attempts. Sozu backs off exponentially per backend.
- ~~Hot binary upgrade~~ - Implemented in v1.6.0 (SuperAdmin-only, Ed25519-signature-verified; the old supervisor execs the new binary and hands over its listening sockets with `SCM_RIGHTS` over a Unix socket. Opt-in: every upload is refused until a public key is configured. Worker mode only: with `--workers 0` the binary is only staged. See `docs/hot-upgrade.md`).

---

## 9. Packaging & Deployment

| Feature | Lorica | Pingora | Sozu | Nginx | Traefik | BunkerWeb | Caddy | HAProxy |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| .deb package | Y | N | N | Y | N | Y | Y | Y |
| .rpm package | Y | N | N | Y | N | Y | Y | Y |
| Signed apt / dnf repository | Y | N | N | Y | N | ? | Y | ? |
| Docker image | P | N | Y | Y | Y | Y | Y | Y |
| Systemd hardened unit | Y | N | P | N | N | N | Y | P |
| Single binary | Y | N | Y | Y | Y | N | Y | Y |
| GPG-signed releases | Y | N | N | Y | N | N | Y | N |
| **Helm chart** | **N** | N | N | Y | Y | Y | P | Y |

### Lorica Notes

- **Single binary** - `lorica` holds the proxy, the API and the dashboard; the packages also ship the optional `lorica-mcp` binary.
- **Package repositories** (v1.10.6) - each release is also published as a signed apt repository and a signed dnf repository on GitHub Pages, holding the latest release only; both clients trust a local copy of the project key, never one fetched again from the site.

### Gaps for Lorica

- **Published Docker image** - a `Dockerfile` ships in the repository since v1.2.0 and builds locally (`docker build -t lorica .`); no image is published to a registry, hence `P`.
- **Helm chart** - Traefik, BunkerWeb and HAProxy publish official charts. Nginx's chart belongs to F5's NGINX Ingress Controller, a separate project (the Kubernetes `ingress-nginx` chart retired with that project in March 2026), and Caddy's sits in the work-in-progress `caddyserver/ingress` repository. Useful for Kubernetes adoption.

---

## Summary: Lorica's Unique Differentiators

These features are either unique to Lorica or extremely rare among competitors:

| Feature | Available In |
|---|---|
| Full CRUD web dashboard | Lorica, BunkerWeb (Lorica's is embedded in the binary; BunkerWeb's is a separate service on its own database) |
| Built-in SLA monitoring (passive + active) | Lorica only |
| Built-in load testing with live WebSocket progress | Lorica only |
| Real-time WebSocket log streaming | Lorica only |
| SLA breach notifications (SMTP/Slack/Webhook) | Lorica only |
| Nginx config import wizard | Lorica only (Caddy's incomplete `nginx-adapter` plugin converts the file, with no wizard) |
| Config export/import with diff preview | Lorica only |
| Encrypted secrets at rest (AES-256-GCM) | Lorica only, built in (BunkerWeb encrypts only its 2FA seeds; Caddy needs a third-party storage module) |
| Built-in WAF + auto-ban + IP blocklist | Lorica, BunkerWeb |
| Cache predictor (learn-uncacheable) | Lorica, Pingora |
| Forward-auth verdict cache (opt-in, TTL-capped, cookie-keyed) | Lorica only |
| Connection pre-filter at TCP accept (hot-reloaded CIDR) | Lorica, HAProxy |
| Tamper-evident, verifiable admin audit chain | Lorica only |
| Multi-node control plane with per-recipient configuration cuts | Lorica only (BunkerWeb pushes one fleet-wide configuration) |
| Predicate-driven request AND response capture as structured, redacted records | Lorica only (BunkerWeb's ModSecurity audit log keeps both bodies on WAF matches, in its native format) |
| Scoped automation tokens bounded by hostname patterns and backend CIDRs | Lorica only (BunkerWeb's scoped tokens and admin credentials share one API, with no host or CIDR constraints) |
| OIDC workload identity for the management plane | Lorica only |
| Built-in MCP server in three tiers (read, config, admin), one tier per token, each call audited | Lorica (BunkerWeb's MCP server has one read-only switch and no per-call audit) |
| Syslog RFC 5424 over TCP/TLS and OTLP log records | Lorica built in; HAProxy only with its out-of-tree OpenTelemetry addon (Traefik: OTLP only, experimental) |
| AI / LLM crawler deny-list with per-vendor verification | Lorica, HAProxy Enterprise |

---

## Summary: Remaining Gaps

All table-stakes features (forward auth, basic auth, mTLS, retries, custom error pages, etc.) are shipped. All major differentiators planned through v1.10.0 are shipped: v1.6.0 added the hot binary upgrade, multi-user RBAC and the AI/LLM crawler deny-list; v1.7.0 added the multi-node cluster and the syslog / OTLP log export; v1.8.0 added conditional request capture and the CI automation API with GitLab OIDC; v1.9.0 added the management MCP server in three tiers; v1.10.0 added certificate enrollment from Active Directory Certificate Services (first packaged in v1.10.1). Remaining gaps are by design or planned for future versions.

| Gap | Plan |
|---|---|
| HTTP/3 (QUIC) | Planned for v2.0.0. Upstream Pingora has no QUIC code yet: [issue #95](https://github.com/cloudflare/pingora/issues/95) is open and labelled a long-term goal, and the `quiche::h3` PRs #514 and #524 were closed unmerged |
| TCP/L4 proxying | Planned for v1.11.0 ([Epic 12](docs/prd/epic-12-v1.11.0.md)): TCP and UDP stream proxying at parity with nginx `stream {}`, then beyond parity in v1.12.0 |
| Service discovery (Docker labels, K8s Ingress) | Out of scope by design. Lorica targets standalone edge / bastion, not in-cluster deployment |
| Config providers (etcd, Consul) | Out of scope by design. Same rationale as service discovery |
| ACME TLS-ALPN-01 | Low priority. HTTP-01 and DNS-01 cover all real-world scenarios |
| Helm chart | Low priority. Out of the primary positioning; may ship on community demand |

---

## Pingora Framework: Untapped Capabilities

Lorica is a fork of Cloudflare Pingora. The forked crates already contain significant capabilities that the product does not yet expose. These represent **low-hanging fruit** - the code exists in the workspace, it just needs wiring into the product layer.

### ProxyHttp Trait Hooks

The `ProxyHttp` trait in `lorica-proxy/src/proxy_trait.rs` defines the hooks the proxy calls on each request, and `impl ProxyHttp for LoricaProxy` in `lorica/src/proxy_wiring.rs` overrides the ones the product needs; every other hook keeps the framework default. The trait and that `impl` block are the authority for the full lists. The tables below name the hooks that carry a Lorica feature and those that would still unlock one.

#### Tapped

| Hook | Shipped As | Version |
|---|---|---|
| `fail_to_proxy()` | Custom error pages + maintenance mode | v1.2.0 |
| `should_serve_stale()` | Stale-while-error, and stale-while-revalidate by answering `true` on `None` (the background refresh is the framework's own revalidation) | v1.2.0 / v1.3.0 |
| `logging()` | Structured access logs (JSON with `--log-format`) | v1.2.0 |
| `is_purge()` | Cache purge via the HTTP PURGE method, from loopback and trusted proxies only (`purge_response_filter()` keeps its default) | v1.2.0 |
| `response_body_filter()` | Response body rewriting | v1.3.0 |
| `cache_vary_filter()` | Cache Vary partitioning | v1.3.0 |
| Root span in `request_filter()` + `#[tracing::instrument]` on `upstream_request_filter()`, `response_filter()`, `fail_to_proxy()` and `logging()` + W3C traceparent | OpenTelemetry tracing (OTLP) | v1.4.0 |
| `suppress_error_log()` | No error line for downstream HTTP-status refusals | v1.9.0 |

Two shipped features use no Lorica hook. HTTP Range requests (v1.2.0) come from the default `range_header_filter()`. Forward auth (v1.3.0) is a `reqwest` call through the shared outbound TLS policy (`lorica/src/proxy_wiring/forward_auth.rs`), not a subrequest: `allow_spawning_subrequest()` keeps its default.

#### Still Untapped (remaining opportunities)

| Hook | Feature It Unlocks | Effort |
|---|---|---|
| `upstream_response_filter()` | **Header injection/removal** on upstream responses before caching | Low |
| `fail_to_connect()` | **Smarter retry decisions** - mark errors as retryable or not | Low |
| `error_while_proxy()` | **Error context enrichment** for better diagnostics | Low |

### Load Balancing (lorica-lb)

Lorica implements backend selection and health checks itself: the selectors, the EWMA tracker and the circuit breaker live in `lorica/src/proxy_wiring.rs` and `lorica/src/proxy_wiring/lb.rs`, and the health checker in `lorica/src/health.rs`. `lorica-lb` is compiled and re-exported by `lorica/src/lib.rs`, but the product does not use it. Least Connections (v1.2.0) is Lorica's own selector; upstream Pingora's selection module still carries its `// TODO: least conn`.

### Cache (lorica-cache)

All the cache capabilities are now wired:

| Capability | Location | What It Does | Effort | Status |
|---|---|---|---|---|
| ~~Cache Lock~~ | `lorica-cache/src/lock.rs` | Thundering-herd protection | Low | v1.2.0 |
| ~~Cache Predictor~~ | `lorica-cache/src/predictor.rs` | Learn-uncacheable short-circuit | Medium | v1.3.0 |
| ~~Vary/Variance~~ | `lorica-cache/src/variance.rs` | `Vary`-header cache partitioning | Medium | v1.3.0 |
| ~~Stale-while-revalidate~~ | `lock.rs` `stale_writer` | Serve stale + background refresh | Low | v1.2.0 / v1.3.0 |
| ~~Streaming Miss~~ | `storage.rs` `lookup_streaming_write()` | Serve partial content while still fetching from upstream - reduces TTFB for cache misses | Medium | Active by default: `MemCache` supports streaming partial writes (`lorica-cache/src/memory.rs`); no Lorica test covers it yet |

### TLS / mTLS (lorica-core)

| Capability | Location | What It Does | Effort | Status |
|---|---|---|---|---|
| ~~mTLS client verification~~ | `lorica-core/src/listeners/tls/rustls/mod.rs` `set_client_cert_verifier()` | Client-cert chain validation at the listener, per-route `required` and org allowlist | Medium | v1.3.0 |

### Protocol Support (lorica-core)

| Capability | Location | What It Does | Effort | Status |
|---|---|---|---|---|
| ~~gRPC-Web module~~ | `lorica-core/src/modules/http/grpc_web.rs` | gRPC-Web to gRPC translation (browser-compatible gRPC) | Low | v1.2.0 |
| ~~Connection filter~~ | `lorica-core/src/listeners/connection_filter.rs` | Per-connection admission control. CIDR allow/deny pre-TLS | Low | v1.3.0 |
| **Custom protocol connectors** | `lorica-core/src/connectors/http/custom/mod.rs` | Non-standard HTTP protocol handling via trait | High | Untapped |

### Error Handling

`fail_to_proxy()`, `should_serve_stale()` and `suppress_error_log()` carry Lorica code (see Tapped above). The two error hooks that still use their defaults would enable:

| Hook | Feature | Effort |
|---|---|---|
| `fail_to_connect()` | Smarter retry decisions (mark errors as retryable or not) | Low |
| `error_while_proxy()` | Error context enrichment for better diagnostics | Low |

### Priority Matrix: Pingora Quick Wins (consolidated ledger)

Baseline audit of Pingora-coded-but-unused capabilities, updated as each one ships.

| Feature | Effort | Impact | Status |
|---|---|---|---|
| ~~Cache lock (thundering herd protection)~~ | Very Low | High | v1.2.0 |
| ~~Stale-while-error~~ | Low | High | v1.2.0 |
| ~~Custom error pages~~ | Low | High | v1.2.0 |
| ~~Structured JSON logs~~ | Low | High | v1.2.0 |
| ~~HTTP Range requests~~ | Low | Medium | v1.2.0 |
| ~~Cache purge via PURGE method~~ | Low | Medium | v1.2.0 |
| ~~gRPC-Web module~~ | Low | Medium | v1.2.0 |
| ~~Least Connections LB~~ | Low | Medium | v1.2.0 |
| ~~Connection pre-filter~~ | Low | Medium | v1.3.0 |
| ~~Forward auth~~ | Medium | High | v1.3.0 |
| ~~Response body rewriting~~ | Medium | High | v1.3.0 |
| ~~mTLS client verification~~ | Medium | High | v1.3.0 |
| ~~Cache Vary support~~ | Medium | Medium | v1.3.0 |
| ~~Cache predictor~~ | Medium | Medium | v1.3.0 |
| ~~Stale-while-revalidate (background refresh)~~ | Low | High | v1.3.0 |
| ~~Request mirroring~~ | Medium | Medium | v1.3.0 |
| ~~Canary / traffic split~~ | Medium | High | v1.3.0 |
| ~~Header-based routing~~ | Low-Medium | High | v1.3.0 |
| ~~Streaming cache miss~~ | Medium | Medium | Active by default (`MemCache`), not yet tested |
| Upstream response header filter | Low | Low | Untapped |
| Custom protocol connectors | High | Low | Untapped |

---

Author: Romain G.
