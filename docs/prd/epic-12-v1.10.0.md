# Epic 12: TCP and UDP Stream Proxying (v1.10.0)

**Author:** Romain G.
**Target version:** 1.10.0
**Status:** Draft (2026-09-28, written against the v1.9.0 code on `feat/v1.9.0` and a parity survey of nginx 1.31.6, HAProxy 3.4 LTS, Traefik 3.7, Envoy 1.40-dev and caddy-l4 taken the same day.)

**Epic Goal:** Make Lorica a layer-4 reverse proxy on a par with nginx `stream {}` and HAProxy `mode tcp`, for TCP and UDP. An operator who needs to front a database, a DNS resolver, an SSH bastion or a TLS service that must not be terminated should not have to run a second proxy next to Lorica, and should not drop Lorica from a shortlist because a layer-4 box is empty. Where the survey shows a gap every open-source competitor leaves open, this epic fills it rather than stopping at parity.

**Why now, and why here rather than in 2.0:** the roadmap placed "TCP/L4 proxying" in v2.0.0 next to HTTP/3. The two are unrelated in the code: HTTP/3 is a new HTTP transport, stream proxying is a second data plane beside HTTP. Keeping them together delays the one that adopters ask about for no technical reason. HTTP/3 stays in 2.0.0 on its own.

## The gap is a checklist, and adopters read it

There is no single use case behind this epic, and that is deliberate. An adopter comparing reverse proxies reads a feature matrix. Lorica is ahead on most rows that concern HTTP (WAF, bot protection, capture, SLA probes, a replicated cluster with a tamper-evident audit chain, an automation API and an MCP surface), and it has **no row at all** for layer 4. Every competitor in the survey has one. An empty section loses the evaluation before the rows where Lorica is ahead get read.

It follows that:

- **The scope is the matrix.** Every row that every serious competitor ships in open source is a requirement of this epic. Every row this epic does not ship is refused in writing below, with the reason. "Coverage" is not an acceptance criterion; a closed list is.
- **A stream is a full citizen on day one.** Replicated across the fleet, targeted per node, exposed on the automation API and the MCP tiers, audited, observed, and editable from the dashboard. Shipping a node-local feature and replicating it later is debt, and this cycle carries none.
- **What Lorica already has for HTTP is reused, not reimplemented.** A backend is one object whether an HTTP route or a stream points at it. The certificate resolver and ACME serve stream TLS termination. The connection filter, GeoIP and the IP blocklist protect stream listeners.
- **Layer 4 has less to inspect, and the PRD says so.** No WAF, no bot challenge, no request capture on a stream: there is no request. What protects a stream listener is source address, geography, connection and session budgets, and protocol detection that refuses what it does not recognise.

## Decisions taken up front

**D1 - A reverse stream proxy, not a forward proxy.** Lorica listens on a port and forwards the byte stream (TCP) or the datagrams (UDP) to a backend it chose. An outbound forward proxy (CONNECT, Squid-style egress) is a different product with a different threat model and is not part of this epic.

**D2 - One backend object for HTTP and streams.** The `Backend` model (`lorica-config/src/models/backend.rs:16`) is shared. What is protocol-specific moves where it belongs: HTTP-only fields (`health_check_path`, `h2_upstream`) stay meaningful for HTTP consumers only, and the health check becomes a typed definition (HTTP probe, TCP connect, TCP send/expect, UDP send/expect). A backend referenced by both an HTTP route and a stream carries one health state, visible in one place. The schema migration and the HTTP non-regression tests ship in the same story.

**D3 - A stream is its own object, not a kind of route.** A route is matched on hostname, path and headers; a stream has none of those. Grafting streams onto the route form would leave half of it meaningless. `Stream` gets its own model, its own join with backends, its own dashboard page, API resource, scopes and MCP tools.

**D4 - Stream listeners exist only while a stream needs them.** Today the data plane binds two fixed ports once at startup (`lorica/src/cli.rs:98-109`, `lorica-worker/src/manager.rs:263-277`) and FR21's lazy bind was never built. Streams cannot work that way: creating a stream binds its port, deleting it releases the port, on a running process, without a restart. The supervisor binds (it holds `CAP_NET_BIND_SERVICE`, so ports below 1024 work) and hands the socket to live workers over the existing SCM_RIGHTS path (`lorica-worker/src/fd_passing.rs`). The HTTP listeners are not changed by this epic.

**D5 - Established connections survive a hot upgrade where that can be done safely, and the PRD states where it cannot.** Today the old generation drains for a hard-coded 30 s and then kills its workers (`lorica-worker/src/manager.rs:554-597`), so any stream longer than 30 s is cut by every upgrade. The survey found no competitor that hands over live layer-4 connections (Envoy documents that it drains or drops). This epic does:
- **TCP passthrough streams and UDP sessions are transferred** to the new generation. This is guaranteed.
- **Streams where Lorica terminates TLS are transferred only if the TLS state can cross the process boundary safely** (the candidate is kernel TLS, where the kernel holds the record state and the socket is all that moves). Where it cannot, the connection is drained for an operator-configured delay and then closed, and the close is recorded as caused by the upgrade.
- A transfer that fails part-way falls back to drain. A connection is never left split between generations.
- Before an upgrade runs, the operator sees how many connections will be transferred and how many will be drained, per stream.

**D6 - Safe by default on UDP.** A UDP listener is a potential amplifier. Defaults: a bounded number of response datagrams per client datagram, a short session idle timeout, a cap on concurrent sessions per source address, and no UDP stream bound to a wildcard address without either a source allowlist or an explicit session limit. An operator can lift the response bound; the stream then carries a permanent "unbounded responses" badge in the dashboard and in API listings. No confirmation modal: a badge that stays visible is read, a modal that interrupts every save is clicked through.

**D7 - Protocol detection refuses what it does not recognise.** On a shared port, the first bytes decide the backend within a bounded read and a bounded time. A connection whose bytes match no configured matcher is closed, never sent to a default backend: a default is an allowlist bypass. Protocols where the server speaks first (MySQL, SMTP, FTP) cannot be detected from client bytes, so they get an explicit "silent client after N ms" matcher that the operator points at one backend. A client that sends unrecognised bytes is still refused.

**D8 - A dependency decision for D5, needed before the upgrade story starts.** Kernel TLS needs either a crate that drives `setsockopt(SOL_TLS)` from rustls' extracted secrets, or a direct implementation over `nix`/`libc`, which the workspace already carries. rustls 0.23 (the workspace pin, `Cargo.lock`) exposes secret extraction; whether it covers every suite Lorica negotiates is to be verified, not assumed. Per the project rule, no new dependency without explicit approval. If neither path is sound, D5's drain fallback applies to every TLS-terminated stream and the documentation says so.

**Integration Requirements:** All work lands on a single `feat/v1.10.0` branch with one final PR to `main`. If a new crate is introduced for the stream data plane, the three-Dockerfile rule applies (`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`), `docs/BUMP-CHECKLIST.md` gains it, and its version follows the product line. The HTTP data plane's behaviour is unchanged: every existing e2e profile passes untouched. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings` under `RUSTFLAGS=-D warnings`, `cargo audit`, and the frontend gates stay green at every commit.

**Cross-cutting deliverables** (no single story owns them, all release-blocking):
- `docs/streams.md` as the user-facing reference, including a directive-by-directive equivalence table from nginx `stream {}` and HAProxy `mode tcp`.
- `docs/security/threat-model.md` gains the UDP amplification, slow ClientHello, PROXY-header spoofing and detection-bypass threats, each with its mitigation.
- `docs/security/hardening-guide.md` gains stream guidance, including the transparent-proxy capability drop-in.
- `lorica-api/openapi.yaml` updated for the stream resource and the new scopes, kept green against the contract test.
- `CHANGELOG.md` under Added and Security.
- The README feature list and roadmap: v1.10.0 carries stream proxying, v2.0.0 keeps HTTP/3 alone.
- `docs/prd/index.md` gains this epic.

---

## Prior Art

Verified against official documentation on 2026-09-28. nginx 1.31.x is the mainline branch; whether its most recent additions have reached a stable release was not checked.

### Coverage matrix and Lorica's commitment

| Feature | nginx `stream` | HAProxy `mode tcp` | Traefik | Envoy | caddy-l4 | Lorica 1.10.0 |
|---|---|---|---|---|---|---|
| TCP proxying | Yes | Yes | Yes | Yes | Plugin | Story 12.3 |
| UDP proxying with idle timeout | Yes | Paid (Enterprise) | Yes | Yes | Plugin | Story 12.5 |
| UDP request/response bounds | `proxy_responses`, `proxy_requests` | Paid | No | No | No | Story 12.5, on by default |
| TLS passthrough, SNI routing | Yes | Yes | Yes | Yes | Plugin | Story 12.4 |
| ALPN routing | Yes | Yes | Yes | Yes | Plugin | Story 12.4 |
| TLS termination at L4 | Yes | Yes | Yes, with ACME | Yes | Plugin | Story 12.4, with Lorica's ACME certificates |
| Upstream TLS / mTLS | Yes | Yes | Yes | Yes | Plugin | Story 12.4 |
| PROXY protocol v1/v2 send | Yes (v2 since 1.31.4) | Yes | Yes | Yes | Plugin | Story 12.3 |
| PROXY protocol v1/v2 accept | Yes | Yes | Yes | Yes | Plugin | Story 12.3, trusted sources only |
| Round robin, least conn | Yes | Yes | WRR only | Yes | Plugin | Story 12.3 |
| Hash / consistent hash on source | Yes | Yes | No | Yes | Plugin | Story 12.3 (`lorica-ketama`) |
| Random / power of two | Yes | Yes | No | Yes | Plugin | Story 12.3 |
| Latency-aware selection | `least_time` | No | No | No | No | Story 12.3 (`peak_ewma`) |
| Passive failure detection | Yes | Yes | No | Yes | Plugin | Story 12.3 (circuit breaker) |
| Active health: TCP connect | Paid | Yes | Yes | Yes | Plugin | Story 12.8 (exists today) |
| Active health: send/expect | Paid | Yes | Yes | Yes | No | Story 12.8 |
| Active health: UDP | Paid | Paid | No | No | Not stated | Story 12.8, **no open-source competitor** |
| Active health: agent check | No | Yes | No | No | No | Refused |
| Connection limit per source IP | Yes | Yes | No | No | No | Story 12.6 |
| Connection limit per listener / backend | Yes | Yes | Yes | Yes | No | Story 12.6 |
| New-connection rate limit | **No** | Yes | No | Yes | No | Story 12.6 |
| Bandwidth limit | Yes | No | No | No | No | Story 12.3 |
| IP allow/deny | Yes | Yes | Yes | Yes | Plugin | Story 12.6 |
| GeoIP | Yes | Paid (MaxMind module) | No | Yes | No | Story 12.6 |
| Port ranges | Yes | Yes | No | No | Yes | Story 12.2 |
| Dynamic reconfiguration | Reload; API paid | Runtime API | Provider | xDS | Admin API | Story 12.2, API and cluster |
| Hot binary upgrade | USR2 | Reload with fd passing, drain | No | Hot restart, drain | No | Story 12.9, **with live transfer** |
| Connection draining | Yes | Yes | Yes | Yes | Plugin | Story 12.9 |
| L4 access log | Yes | Yes | Not verified | Yes | Not verified | Story 12.10 |
| L4 metrics | Paid | Yes | Gauge only | Yes | Not verified | Story 12.10 |
| Timeouts connect / idle / total | Yes / Yes / No | Yes | Partial | Yes | Partial | Story 12.3 |
| Upstream DNS re-resolution | Yes | Yes | Provider | Yes | Not verified | Story 12.3 |
| IPv6 | Yes | Yes | Yes | Yes | Yes | Stories 12.2 to 12.5 |
| Transparent proxy | Yes | Yes | No | Yes | No | Story 12.3, opt-in |
| Session persistence | Hash | Stick tables | No | Hash | `ip_hash` | Story 12.3 (consistent hash); stick tables refused |
| Protocol detection on one port | Preread only | Payload ACLs | SNI/ALPN | Inspectors | Richest set | Story 12.7 |
| Arbitrary payload inspection | njs | `tcp-request content` | No | Wasm | Regexp | Refused |
| Import from an nginx config | n/a | n/a | n/a | n/a | n/a | Stories 12.0 and 12.12 |

"Paid" means nginx Plus or HAProxy Enterprise only. HAProxy community's lack of general UDP proxying is inferred from the Enterprise-only `udp-lb` module and its absence from the 3.4 manual, not from an explicit statement.

### What the survey says beyond the matrix

- **The table stakes** every serious competitor ships in open source: TCP, TLS passthrough with SNI routing, ALPN routing, L4 TLS termination, upstream TLS, PROXY protocol v1 and v2 both ways, round robin plus least conn or hash, passive failure detection, active TCP checks, allow/deny, IPv6, connect and idle timeouts, UDP with an idle timeout. Missing any one of these reads as "not a real L4 proxy".
- **UDP defaults across the field** are short: 3 s idle (Traefik), 10 s (HAProxy Enterprise), 30 s (caddy-l4), 1 min (Envoy). nginx and HAProxy Enterprise both expose a responses-per-request bound. D6's defaults are the state of the art, not caution.
- **Three gaps no open-source competitor fills:** active UDP health checks, a new-connection rate limit in nginx, and live-connection handover on upgrade. This epic ships all three.

### Sources

nginx: [ngx_stream_proxy_module](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html), [ngx_stream_upstream_module](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html), [ngx_stream_core_module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html), [ngx_stream_ssl_preread_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [ngx_stream_ssl_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html), [ngx_stream_upstream_hc_module](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html), [CHANGES](https://nginx.org/en/CHANGES). HAProxy: [3.4 configuration manual](https://docs.haproxy.org/3.4/configuration.html), [3.4 management guide](https://docs.haproxy.org/3.4/management.html), [Enterprise UDP load balancing](https://www.haproxy.com/documentation/haproxy-enterprise/enterprise-modules/udp-load-balancing/overview/). Traefik: [TCP services](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/service/), [UDP services](https://doc.traefik.io/traefik/reference/routing-configuration/udp/service/), [TCP routing rules](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/routing/rules-and-priority/). Envoy: [tcp_proxy](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto), [udp_proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/udp_filters/udp_proxy), [health checking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking), [hot restart](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart). caddy-l4: [repository](https://github.com/mholt/caddy-l4), [matchers](https://github.com/mholt/caddy-l4/blob/master/docs/matchers.md).

---

## Story 12.0: The nginx importer stops misreading `stream {}` blocks

As an operator importing an existing nginx configuration,
I want a `stream {}` block to be recognised as what it is,
so that a database port is never imported as an HTTP route.

Reading `lorica-dashboard/frontend/src/lib/nginx-parser.ts:690-708`, `server` and `upstream` blocks are recognised without looking at their parent block, so a `server` inside `stream {}` appears to become an HTTP server with no `server_name` and its `upstream` an HTTP backend. This was read from the code, not executed. The story starts by proving it.

### Acceptance Criteria

1. **A failing test comes first.** A Vitest case in `nginx-parser.test.ts` feeds a configuration with a `stream {}` block containing an `upstream` and a `server` with `listen` and `proxy_pass`, and asserts that no HTTP server and no HTTP backend come out of it. The test is committed red against the current parser. If it passes on the current code, the premise of this story is wrong and the story is closed with that finding rather than a fix.
2. **The parser tracks block context.** `server` and `upstream` inside `stream {}` are parsed into stream-shaped results, distinct from the `http` ones, and are never merged into them.
3. **Until Story 12.12 lands, stream results produce a diagnostic, never silence.** Each stream `server` yields a `warning` naming its line and stating it was not imported.
4. Existing importer tests pass unchanged.

### Integration Verification

- IV1: A mixed configuration with both `http {}` and `stream {}` imports exactly the HTTP routes it imported before this story, plus one diagnostic per stream server.

---

## Story 12.1: The stream model and shared backends

As an operator,
I want to declare a stream and point it at backends I already manage,
so that one list of backends and one health state serve both my HTTP routes and my streams.

### Acceptance Criteria

1. **New `Stream` model in `lorica-config`**: id, name, group name, protocol (`tcp` or `udp`), listen address and a single port or a port range, IPv4 and IPv6, a list of backends through a `stream_backends` join (the counterpart of `RouteBackend`, `backend.rs:77`), load-balancing algorithm, timeouts, limits, TLS mode (Story 12.4), protocol matchers (Story 12.7), PROXY protocol settings, `node_selector`, `managed_by`, timestamps.
2. **Backends are shared (D2).** The health check becomes a typed definition on the backend: HTTP probe (today's `health_check_path`), TCP connect (today's default), TCP send/expect, UDP send/expect. A migration converts every existing backend to the equivalent typed definition with no behaviour change. A backend used by a UDP stream refuses an HTTP-only health check with a validation error naming the stream.
3. **Validation at the boundary.** A stream is refused if its port or range overlaps the HTTP, HTTPS, management or automation port, or another stream on the same node and protocol, after `node_selector` resolution. A port range is capped. The error names the conflicting object.
4. **Replicated.** `Stream` and `stream_backends` join `CanonicalConfig` (`lorica-config/src/canonical.rs:436-477`), take part in two-phase replication, and honour `node_selector` exactly as routes do (`canonical.rs:712`). A follower never binds a stream it was not targeted by.
5. **Management API CRUD** for streams, with the same validation, audit and JSON GET secret filtering as routes. TOML export and import carry streams.
6. **HTTP non-regression.** The full existing backend, route and health-check test suites pass on the migrated schema, and a test asserts the migration is idempotent.

### Integration Verification

- IV1: A backend referenced by one HTTP route and one TCP stream shows a single health state; marking it down removes it from both.
- IV2: A stream targeted at one node of a three-node fleet appears in the other two nodes' canonical config and is bound on none of them.

---

## Story 12.2: Stream listeners on a running process

As an operator,
I want a stream's port to open when I create it and close when I delete it,
so that I never restart Lorica to add a layer-4 service and no port stays open without a reason.

### Acceptance Criteria

1. **Runtime bind by the supervisor (D4).** Creating or enabling a stream makes the supervisor bind its socket (TCP listener or UDP socket, port or range, IPv4 and IPv6) and hand it to every live worker over the existing SCM_RIGHTS channel with a new typed tag. Deleting or disabling it closes the listener in every worker and in the supervisor.
2. **Privileged ports work** without changing the systemd unit, because the supervisor already holds `CAP_NET_BIND_SERVICE` (`dist/lorica.service:81-82`).
3. **A bind failure is a configuration error, not a crash.** Port in use, permission denied or address not available is reported on the stream (API, dashboard, audit) with the OS error, the stream stays in a failed state, and every other listener is unaffected.
4. **Single-process mode** binds and releases stream listeners the same way.
5. **UDP session affinity to one worker.** A UDP session, identified by its client address and port, is served by exactly one worker for its whole lifetime, whichever way datagrams are distributed across workers. The mechanism is an architecture decision; the property is the requirement.
6. **Reconfiguration without cutting traffic.** Editing a stream's backends, algorithm, limits or timeouts applies to new connections and sessions. Established connections keep running on the settings they started with `[ASSUMPTION]`. Changing a stream's listen address or port rebinds, and connections on the old socket are drained with the drain delay of Story 12.9.

### Integration Verification

- IV1: Creating a TCP stream on port 5432 through the API makes `ss -ltn` show it on the node within one reload cycle; deleting it removes it, with no restart and no dropped HTTP request in between.
- IV2: Creating a stream on a port already held by another process leaves the stream in a failed state with the OS error, and HTTP traffic is unaffected.

---

## Story 12.3: The TCP stream engine

As an operator,
I want Lorica to forward TCP connections to my backends with the balancing, timeouts and source-address handling I expect from nginx or HAProxy,
so that moving a TCP service behind Lorica loses nothing.

### Acceptance Criteria

1. **Bidirectional byte forwarding** with half-close handled in both directions.
2. **Load balancing** with the operator-facing algorithms Lorica already exposes (`lorica-config/src/models/enums.rs:27`): round robin, least connections, random with power of two choices, peak EWMA for latency-aware selection, and consistent hash on the source address for persistence (`lorica-ketama`). Weights are honoured.
3. **Passive failure detection** reuses the per-backend circuit breaker (`lorica/src/proxy_wiring/lb.rs:160`), counting connect failures and connect timeouts, coordinated across workers as it is for HTTP.
4. **Retry on connect failure** to another backend, bounded by a per-stream attempt count. Once bytes have flowed, a connection is never retried.
5. **Timeouts**: connect, idle (no bytes either way) and optional total duration, each per stream, with documented defaults.
6. **PROXY protocol send**, v1 or v2 per stream, towards the backend.
7. **PROXY protocol accept**, v1 and v2, on a stream listener, **only from a configured list of trusted source CIDRs**. A PROXY header from any other source is refused and the connection closed, never interpreted: accepting it from anyone lets any client choose the source address every other control sees.
8. **Transparent proxying, opt-in.** A stream can connect to its backend from the client's source address (`IP_TRANSPARENT`). This needs `CAP_NET_ADMIN` and policy routing. The default systemd unit does not grant it; the hardening guide ships a documented drop-in. A stream configured transparent on a process that lacks the capability is in a failed state with that reason.
9. **Bandwidth limits** per stream, upload and download, per connection.
10. **Upstream DNS re-resolution.** A backend given as a hostname is re-resolved on a TTL-bounded schedule, and a resolution failure keeps the last known addresses and raises a health event.
11. **Bounded resources.** Per-connection buffers are fixed-size; a slow reader on one side applies backpressure to the other, never unbounded buffering.

### Integration Verification

- IV1: A TCP stream in front of three PostgreSQL backends balances connections by the configured algorithm, survives one backend being killed with no failed new connection after the breaker trips, and a `psql` session opened before the kill on a surviving backend is unaffected.
- IV2: A backend receiving PROXY v2 sees the real client address; a client outside the trusted CIDRs sending a PROXY header is disconnected.

---

## Story 12.4: TLS at layer 4

As an operator,
I want to route TLS connections by SNI without decrypting them, or terminate them with a certificate Lorica already manages,
so that end-to-end TLS services and plaintext services that need TLS in front are both covered.

### Acceptance Criteria

1. **Passthrough with SNI and ALPN routing.** A stream reads the ClientHello without terminating TLS and selects a backend by SNI (exact and wildcard) and ALPN. The read is bounded in size and time: a client that does not complete its ClientHello within the limit is disconnected and counted. No match means the connection is closed (D7), unless the stream names a backend for "no SNI".
2. **Termination with Lorica's certificates.** A stream can terminate TLS with a certificate from the existing `CertResolver` (`lorica-tls/src/cert_resolver.rs:81`), including ACME-issued certificates with automatic renewal and hot swap, then forward plaintext or re-encrypted to the backend. This is the row where no competitor except Traefik links L4 TLS to ACME.
3. **Upstream TLS** with verification by default, a configurable SNI, and client certificates for mTLS towards the backend.
4. **Client certificate verification** on terminated streams, against a configured CA, reusing the mTLS machinery routes already have.
5. The TLS mode of a stream (none, passthrough, terminate) is one field, and the fields that do not apply to the chosen mode are refused rather than ignored.

### Integration Verification

- IV1: One port serves two SNI names in passthrough to two different backends, each seeing the client's original ClientHello; a third SNI is refused.
- IV2: A stream terminating TLS with an ACME certificate keeps serving across a renewal, and new connections present the renewed certificate.

---

## Story 12.5: The UDP stream engine

As an operator,
I want to forward UDP traffic (DNS, syslog, RADIUS, game or VoIP signalling) with session semantics and safe defaults,
so that I can front UDP services without building an amplifier.

### Acceptance Criteria

1. **Sessions keyed on the client address and port**, each bound to one backend for its lifetime, with the load-balancing algorithms of Story 12.3 that make sense per session (round robin, random, consistent hash on source, least sessions).
2. **Safe defaults (D6)**: a bounded number of response datagrams per client datagram, a bounded number of datagrams per session where configured, a short idle timeout, a cap on concurrent sessions per source address, and a cap on total sessions per stream. Defaults are documented next to the survey's values.
3. **No wildcard UDP listener without a limit.** A UDP stream bound to a wildcard address is refused unless it has a source allowlist or an explicit per-source session cap.
4. **Unbounded responses are explicit.** Lifting the response bound is a separate field; the stream then carries a permanent badge in the dashboard and a flag in API and MCP listings.
5. **Bounded memory.** The session table has a hard ceiling per stream and per node; when full, new sessions are refused and counted, existing sessions are not evicted early.
6. **PROXY protocol v2 over UDP** towards the backend where the stream enables it.
7. **Datagram size** is bounded and oversized datagrams are dropped and counted.

### Integration Verification

- IV1: A UDP stream in front of two DNS resolvers answers queries, balances sessions, and a spoofed-source flood hitting the per-source cap is refused without affecting other clients.
- IV2: With default settings, one client datagram never produces more response datagrams towards the client than the documented bound.

---

## Story 12.6: Protecting stream listeners

As an operator,
I want the source-address, geography and rate controls Lorica applies to HTTP to protect my streams as well,
so that opening a layer-4 port does not open a hole in my perimeter.

### Acceptance Criteria

1. **Allow and deny CIDRs per stream**, evaluated before any byte is forwarded (TCP, at accept) or any session is created (UDP), in addition to the global connection filter (`lorica/src/connection_filter.rs:86`), which applies to stream listeners as well.
2. **GeoIP country allow/deny per stream** through `lorica-geoip`, and the global IP blocklist (`lorica-waf/src/ip_blocklist.rs`) applied to stream traffic.
3. **Concurrent connection caps** per source address, per stream and per backend.
4. **New-connection rate limit** per source address and per stream (TCP connections, UDP session creations), on the existing token-bucket machinery, local or cluster-authoritative as for HTTP rate limits. nginx `stream` has no such control.
5. **Every refusal is observable**: a counter per stream and reason, and an access-log row with the reason (Story 12.10). No refusal is silent.

### Integration Verification

- IV1: A source over its new-connection rate is refused at accept while another source on the same stream is served.
- IV2: A client from a denied country is refused on a TCP stream and on a UDP stream.

---

## Story 12.7: Protocol detection on a shared port

As an operator,
I want to serve several protocols on one port (for example SSH and TLS on 443),
so that I can cover the network setups where only one port is open.

### Acceptance Criteria

1. **Matchers** for TLS (with SNI and ALPN), HTTP/1.x, the HTTP/2 connection preface, SSH, PostgreSQL (including its SSLRequest), RDP and OpenVPN over TCP, each routing to its own backend set.
2. **A "silent client after N ms" matcher** for server-first protocols (MySQL, SMTP, FTP), pointed at one backend. It fires only when the client has sent no byte at all within N ms.
3. **Unrecognised bytes are refused (D7).** A connection that sends bytes matching no matcher is closed, never forwarded to a default.
4. **Bounded detection.** The peek is capped in bytes and in time; the bytes read are forwarded to the selected backend unchanged.
5. HTTP detected on a stream port is forwarded as bytes to the stream's backend. It is not handed to Lorica's HTTP pipeline; an operator who wants WAF and routing on HTTP uses a route.

### Integration Verification

- IV1: SSH, a TLS client and a PostgreSQL client on the same port each reach their own backend; a client sending random bytes is disconnected within the detection limit.
- IV2: A MySQL client on a port with a silent-client matcher reaches the MySQL backend.

---

## Story 12.8: Health checks for stream backends

As an operator,
I want active checks that prove a backend speaks its protocol, not only that its port is open,
so that a hung database or a dead DNS resolver leaves the pool before clients notice.

### Acceptance Criteria

1. **TCP send/expect**: optional bytes to send, bytes or a pattern to expect within a timeout. The existing TCP-connect probe (`lorica/src/health.rs:302`) remains the default.
2. **UDP send/expect**: a datagram to send, a response to expect within a timeout. No open-source competitor ships this.
3. Checks run on the existing health loop with the existing interval, thresholds and lifecycle states, and the result feeds the one health state of the shared backend (D2).
4. **Ready-made templates** in the dashboard for common protocols (DNS query, Redis `PING`, SMTP banner), expressed as send/expect values, not as protocol-specific code.
5. A check's payload is data configured by an operator and is validated in size.

### Integration Verification

- IV1: A DNS resolver that stops answering while its port stays open is marked down by the UDP check and removed from the stream within the configured thresholds.

---

## Story 12.9: Hot upgrade and reload with live streams

As an operator,
I want to upgrade Lorica without cutting the database sessions and SSH connections it carries,
so that an upgrade stops being a maintenance window.

### Acceptance Criteria

1. **Operator-configured drain delay**, replacing the hard-coded 30 s (`lorica-worker/src/manager.rs:554-597`), for HTTP and streams, with the current value as the default.
2. **Live transfer for TCP passthrough and UDP (D5).** During a hot upgrade, the old generation hands every established passthrough TCP connection (both sockets) and every UDP session (the session table and its backend sockets) to the new generation, which continues forwarding without the client or the backend seeing a reconnect. Transfer happens only at a point where no forwarded bytes are held in userspace buffers.
3. **TLS-terminated streams** are transferred when the mechanism chosen under D8 can move their TLS state safely. TLS secrets never touch a filesystem path, a log or a core dump; they cross only on the inherited socketpair. Where transfer is not possible, the connection drains for the configured delay and is then closed.
4. **All-or-fallback per connection.** A transfer that fails at any step leaves the connection with the old generation, which drains it. No connection is served by both generations or by neither.
5. **Preview before upgrade.** The upgrade path (CLI, API, dashboard) reports, per stream, how many connections will be transferred and how many will be drained, before the upgrade runs.
6. **Traced outcomes.** Every connection closed by a drain timeout is logged with that cause, distinct from a client close, a backend close and a refusal. The existing `lorica_hot_upgrade_total` outcome counter gains per-connection transfer and drain counts.
7. The same transfer applies when a worker is replaced for any other reason the supervisor controls.

### Integration Verification

- IV1: An SSH session through a passthrough stream stays open and interactive across a hot upgrade.
- IV2: A DNS client with a live UDP session keeps getting answers across a hot upgrade with no session re-creation on the backend.
- IV3: A transfer forced to fail mid-way (test hook) leaves the connection draining on the old generation, and it completes normally.

---

## Story 12.10: Stream observability

As an operator,
I want to see what my streams carry and why a connection ended,
so that layer 4 is not the blind spot of my monitoring.

### Acceptance Criteria

1. **An access-log row per TCP connection and per UDP session** at its end: stream, client address (after PROXY protocol where accepted), backend, bytes each way, duration, TLS mode, SNI, detected protocol, and a closed set of end reasons (client close, backend close, idle timeout, total timeout, refused with reason, drained by upgrade, transferred).
2. **The rows reach the existing sinks** (`lorica-api/src/log_sinks/mod.rs:58`): syslog, OTLP logs, the dashboard log view, with a stream kind distinct from HTTP access rows.
3. **Prometheus metrics** under the `lorica` namespace: active connections and sessions, accepted, refused by reason, bytes each way, connect latency to backend, per stream and per backend. Label cardinality is bounded: no client address in a label.
4. SLA views include streams: availability and backend connect latency per stream.

### Integration Verification

- IV1: A refused connection, an idle-timeout close and an upgrade drain each produce a row with the right end reason, visible in the dashboard and in a syslog collector.

---

## Story 12.11: Streams on every surface

As an operator running a fleet with automation and an MCP client,
I want streams to be managed wherever routes are,
so that layer 4 is not a second-class feature I can only reach through one door.

### Acceptance Criteria

1. **Dashboard**: a Streams page beside Routes (`lorica-dashboard/frontend/src/routes/Dashboard.svelte:24-38`), with the list, the form, the per-stream badges (unbounded UDP responses, transparent mode, failed bind), live counters, and the backend page showing which routes and streams use each backend.
2. **Automation API**: new scopes `streams:read` and `streams:write` in the closed `AutomationScope` enum (`lorica-config/src/models/automation_token.rs:135`), each justified where the enum is defined, following the rule Epic 11 set (no scope for symmetry). The `environment` resource stays HTTP-only: it binds a hostname, and a stream has none.
3. **MCP tiers**: the read tier gains stream listings and stream status; the config tier gains stream create, update and delete, each with its `_preview` twin, one named stream per call, in the Epic 11 catalogue (`lorica-mcp/src/tools.rs`). No tier gains a tool that affects many streams at once.
4. **Cluster**: the fleet view shows each stream's bind state per node.
5. **Audit**: every stream mutation from every surface lands in the tamper-evident chain with its origin (dashboard, API, automation, MCP).

### Integration Verification

- IV1: A stream created through the automation API with a `streams:write` token appears in the dashboard and in the MCP read tier, and its audit row names the automation origin.

---

## Story 12.12: Importing nginx `stream {}` configurations

As an operator migrating from nginx,
I want my `stream {}` blocks to become Lorica streams,
so that the migration costs me minutes, not an afternoon.

### Acceptance Criteria

1. The import wizard (`lorica-dashboard/frontend/src/components/nginx-wizard/`) turns each stream `server` into a Lorica stream and each stream `upstream` into shared backends, deduplicated against backends that already exist.
2. **Mapped directives**: `listen` (with `udp`, ranges, IPv6), `proxy_pass`, `proxy_connect_timeout`, `proxy_timeout`, `proxy_responses`, `proxy_requests`, `proxy_protocol`, `proxy_ssl*`, `ssl_preread` with its `map` on `$ssl_preread_server_name`, `ssl_certificate` (matched against Lorica's certificates), `allow`/`deny`, `limit_conn`, `proxy_upload_rate`/`proxy_download_rate`, and the upstream `server` parameters (`weight`, `max_fails`, `fail_timeout`, `backup`) and balancing directives (`hash`, `least_conn`, `random`).
3. **Every directive the importer does not map produces a diagnostic** with its line. No silent drop.
4. The preview step shows the streams and backends to be created before anything is applied, as it does for routes.
5. The equivalence table in `docs/streams.md` is generated from, or asserted against, the importer's directive map, so the documentation cannot drift from what the importer does.

### Integration Verification

- IV1: A reference nginx configuration with TCP, UDP, SNI preread and PROXY protocol imports into streams that pass the e2e L4 phase unchanged.

---

## Story 12.13: End-to-end and performance verification

As the maintainer,
I want the stream data plane proven end to end and measured against nginx on the same machine,
so that "on a par" is a measured claim.

### Acceptance Criteria

1. **An L4 phase in `tests-e2e-docker/`** with real backends (PostgreSQL, a DNS resolver, an SSH server, a TLS echo server) covering Stories 12.2 to 12.10, including a hot upgrade with live SSH and UDP sessions and a cluster-targeted stream.
2. **A performance phase** that runs nginx `stream` and Lorica side by side in the same compose and the same run, against the same backends, and compares **ratios**, never absolute numbers:
   - TCP passthrough throughput within 10 % of nginx `[ASSUMPTION]`;
   - added p99 connection-setup latency under 1 ms for non-TLS streams `[ASSUMPTION]`;
   - 100 000 concurrent UDP sessions per node with no loss, no premature eviction, and memory bounded and reported `[ASSUMPTION]`.
3. **Gating.** The performance phase gates the local release run, which has the machine to itself as the e2e suite already requires. In CI it runs and publishes its numbers in the job summary without gating, because shared runners are too noisy for a 10 % ratio.
4. Every existing e2e profile passes unchanged.

### Integration Verification

- IV1: The local release run of the full e2e suite, including the L4 and performance phases, passes on the release candidate.

---

## Non-Functional Requirements

- **NFR1 - No HTTP regression.** The HTTP data plane's latency and throughput are unchanged within measurement noise, and every existing e2e profile passes untouched.
- **NFR2 - Bounded everything.** Every per-connection buffer, session table, detection read, ClientHello read and port range has a hard ceiling with a documented default. No stream setting can make memory grow with attacker-controlled input.
- **NFR3 - Safe defaults.** A stream created with only a port and a backend is not an open relay: UDP bounds and caps of D6 apply, PROXY accept is off, transparent mode is off, detection refuses unknown bytes.
- **NFR4 - Performance.** The ratios of Story 12.13.
- **NFR5 - Observability is not optional.** Every way a connection can end has a named reason in logs and metrics.
- **NFR6 - Linux only**, as the rest of Lorica. Transparent mode and kernel TLS depend on kernel features whose minimum versions are documented.

## Refused, in writing

These rows of the survey are not shipped by this epic, and not deferred either: each is a decision.

- **An outbound forward proxy** (CONNECT, egress). D1: a different product and threat model.
- **HAProxy-style generic stick tables.** Persistence is covered by consistent hashing on the source address, which is what nginx offers; per-source counters are covered by Story 12.6. A general key-value table with expressions is a configuration language of its own.
- **Agent checks.** Only HAProxy has them; send/expect covers the need without running an agent protocol on every backend.
- **Arbitrary payload inspection** (HAProxy `tcp-request content` ACLs on payload, njs, Wasm filters). Story 12.7's closed matcher set covers the legitimate need; a programmable inspector is arbitrary execution on the data path.
- **UDP tunnelled over HTTP (MASQUE, Envoy's UDP over HTTP).** It belongs with HTTP/3 in 2.0.0.
- **DTLS termination.** No competitor in the survey ships it in open source at layer 4, and it has no user in the matrix.
- **WAF, bot protection and request capture on streams.** There is no request at layer 4. HTTP that needs them uses a route.
- **The automation `environment` resource for streams.** It is a hostname-bound review-app primitive; a stream has no hostname.

## Open Questions

- **OQ1 - PROXY protocol on the HTTP listeners.** Accepting PROXY protocol on Lorica's HTTP and HTTPS listeners (Lorica behind a cloud L4 load balancer) shares code with Story 12.3 and is a frequent request, but it is an HTTP-listener change this epic otherwise avoids. In or out?
- **OQ2 - The D8 dependency.** kTLS through a crate or directly over `nix`, to be decided with its approval before Story 12.9 starts.
