# Epic 12: TCP and UDP Stream Proxying (v1.10.0)

**Author:** Romain G.
**Target version:** 1.10.0
**Status:** Draft (2026-09-28). Written against `feat/v1.9.0` at `1b83cf0d` plus the v1.9.0 work then uncommitted in the tree, so line numbers in cited files may drift; function and type names are the stable reference. Parity survey of nginx 1.31.6, HAProxy 3.4 LTS, Traefik 3.7, Envoy 1.40-dev and caddy-l4 taken the same day. Revised the same day after three passes: a verification that executed the nginx importer and checked every assumption and citation, a rubric review, and an adversarial review.

**Epic Goal:** Make Lorica a layer-4 reverse proxy on a par with nginx `stream {}` and HAProxy `mode tcp`, for TCP and UDP. An operator who needs to front a database, a DNS resolver, an SSH bastion or a TLS service that must not be terminated should not have to run a second proxy next to Lorica, and should not drop Lorica from a shortlist because a layer-4 box is empty. Once parity is reached, the epic goes past it where the survey shows gaps the field leaves open.

**Why now, and why here rather than in 2.0:** the roadmap placed "TCP/L4 proxying" in v2.0.0 next to HTTP/3. The two are unrelated in the code: HTTP/3 is a new HTTP transport, stream proxying is a second data plane beside HTTP. Keeping them together delays the one that adopters ask about for no technical reason. HTTP/3 stays in 2.0.0 on its own.

## The gap is a checklist, and adopters read it

There is no single use case behind this epic, and that is deliberate. An adopter comparing reverse proxies reads a feature matrix. Lorica is ahead on most rows that concern HTTP (WAF, bot protection, capture, SLA probes, a replicated cluster with a tamper-evident audit chain, an automation API and an MCP surface), and it has **no row at all** for layer 4. Every competitor in the survey has one. An empty section loses the evaluation before the rows where Lorica is ahead get read.

It follows that:

- **Parity is defined against nginx and HAProxy open source**, the two references adopters migrate from. Every table-stakes row they ship is a requirement. Every surveyed row this epic does not ship is refused in writing below, with the reason. "Coverage" is not an acceptance criterion; a closed list is.
- **Parity first, then beyond.** The stories are ordered in two phases. Phase 1 reaches parity and ends with a verification checkpoint. Phase 2 goes past it. Nothing is cut and nothing is deferred to another release: the order says what gets built first, and if the cycle runs long, it says without debate what is still in flight.
- **A stream is a full citizen.** Replicated across the fleet, targeted per node, audited, observed, readable on the automation API and the MCP read tier, and managed from the dashboard and the management API. Shipping a node-local feature and replicating it later is debt, and this cycle carries none.
- **What Lorica already has for HTTP is reused, not reimplemented.** A backend is one object whether an HTTP route or a TCP stream points at it. The certificate resolver and ACME serve stream TLS termination. GeoIP and the IP blocklist protect stream listeners.
- **Layer 4 has less to inspect, and the PRD says so.** No WAF, no bot challenge, no request capture on a stream: there is no request. What protects a stream listener is source address, geography, connection and session budgets, and, in Phase 2, protocol detection that refuses what it does not recognise.

## Decisions taken up front

**D1 - A reverse stream proxy, not a forward proxy.** Lorica listens on a port and forwards the byte stream (TCP) or the datagrams (UDP) to a backend it chose. An outbound forward proxy (CONNECT, Squid-style egress) is a different product with a different threat model and is not part of this epic.

**D2 - One backend object for HTTP and TCP streams, UDP backends apart.** The `Backend` model (`lorica-config/src/models/backend.rs`, `struct Backend`) is shared by HTTP routes and TCP streams, with one health state visible in one place. What a state change does to live stream connections is defined per stream (Story 12.2). Fields that only mean something to HTTP consumers are named as such: `health_check_path`, `h2_upstream`, and the upstream TLS fields (`tls_upstream`, `tls_sni`, `tls_skip_verify`); a stream's upstream TLS lives on the stream (Story 12.4). A backend used by a UDP stream is UDP-only: one health state cannot prove both a TCP and a UDP service. The health check becomes a typed definition (HTTP probe, TCP connect, TCP send/expect, UDP send/expect) through an additive migration (Story 12.1).

**D3 - A stream is its own object, not a kind of route.** A route is matched on hostname, path and headers; a stream has none of those. `Stream` gets its own model, its own join with backends, its own dashboard page, API resource, read scope and MCP read tools.

**D4 - Stream listeners exist only while a stream needs them.** Today the data plane binds two fixed ports once at startup (port arguments in `lorica/src/cli.rs`, bind in `create_listen_sockets`, `lorica-worker/src/manager.rs`) and FR21's lazy bind was never built. Streams cannot work that way: creating a stream binds its port, deleting it releases the port, on a running process, without a restart.
- The supervisor binds. The unit's ambient `CAP_NET_BIND_SERVICE` is never dropped, so ports below 1024 work.
- Sockets reach live workers over SCM_RIGHTS with the typed tags of `lorica-worker/src/fd_passing.rs`. Today fds cross only once, at worker fork, and the command channel carries no ancillary data, so this epic adds a **runtime fd channel per worker**.
- A TCP stream listener is one socket shared by the workers. A **UDP stream gets one socket per worker**, created by the supervisor as a `SO_REUSEPORT` group, so the kernel keeps a client's datagrams on one worker for that worker's lifetime.
- Pingora's listener set is fixed before `Server::run` and cannot grow afterwards, so stream sockets are served by a **stream accept loop of their own**, outside Pingora's listeners.
- The HTTP listeners keep their fixed ports; the one change they receive is optional PROXY protocol accept (Story 12.8).

**D5 - Established connections survive a hot upgrade where that can be done safely, and the PRD states where it cannot.** Today the old generation drains for a hard-coded 30 s and then kills its workers (`drain_for_handoff`, `lorica-worker/src/manager.rs`), so any stream longer than 30 s is cut by every upgrade, even though `docs/hot-upgrade.md` already documents a `worker_drain_timeout_s` setting that does not exist. The survey found no competitor that hands over established layer-4 connections: Envoy documents that they drain or are dropped, and forwards only in-flight UDP datagrams to the new process, not session state.
- **Phase 1 (Story 12.11):** the drain delay becomes the real, configurable `worker_drain_timeout_s`, for HTTP and streams, and every connection an upgrade closes says so.
- **Phase 2 (Story 12.16):** TCP passthrough connections and UDP sessions are transferred to the new generation. A connection that does not reach a quiesce point within `transfer_timeout`, or whose transfer fails at any step, stays with the old generation and drains. A connection is never split between generations.
- **Streams where Lorica terminates or originates TLS always drain** (D8).

**D6 - Safe by default on UDP.** A UDP listener is a potential amplifier, and a UDP source address is spoofable, so every per-source control is a courtesy to honest clients, not a defence. The defaults bound the reflection itself:
- a bound on response datagrams per client datagram, **and** a bound on response bytes relative to request bytes per session;
- a bound on requests per session, and a session closes as soon as its request or response bound is reached (nginx closes on `proxy_responses`), so short request/response protocols such as DNS do not hold a socket until the idle timeout;
- a short idle timeout;
- a per-source datagram rate and byte rate, a cap on concurrent sessions per source, and a total session cap per stream;
- no UDP stream on a listen address that is not loopback, RFC 1918 or ULA without a source allowlist or an explicit per-source cap at or below a documented maximum.

An operator can lift the response bounds; the stream then carries a permanent "unbounded responses" badge in the dashboard and a flag in API and MCP listings. No confirmation modal: a badge that stays visible is read, a modal that interrupts every save is clicked through.

**D7 - No default backend, with two named, badged exceptions.** A connection that matches nothing is closed, never sent to a default backend: a default is an allowlist bypass. Two situations cannot be matched on client bytes and would otherwise force a default, so each gets an explicit matcher that the operator sets on purpose, that carries a permanent badge, and that is counted separately: the **"no SNI" matcher** for TLS clients that send no server name (Story 12.4), and the **"silent client after N ms" matcher** for server-first protocols such as MySQL, SMTP and FTP (Story 12.15). A stream using either requires a source allowlist or an explicit acknowledgement field.

**D8 - No live transfer of TLS streams in 1.10.0, by decision.** Moving a TLS connection between processes was examined through kernel TLS and rejected:
- rustls cannot rebuild a connection from extracted secrets in userspace. Its kernel-TLS path (`KernelConnection`, rustls 0.23.27+) keeps the TLS 1.3 traffic secret inside the process that did the handshake, and exists only on the unbuffered API, not on the tokio-rustls path Lorica uses.
- The kernel holds the derived key and sequence number, not the traffic secret. A transferred socket keeps its data path but the new process cannot answer the peer's next KeyUpdate, so the connection would die at the first rekey.
- Kernel TLS 1.3 rekey support needs Linux 6.14; Debian 12, Ubuntu 24.04 and RHEL 9 ship older kernels. Loading the `tls` module on demand needs `CAP_NET_ADMIN`, which Lorica does not hold.

TLS-terminated and TLS-originating streams therefore drain, and the documentation says so. No competitor transfers these connections either.

**D9 - Stream mutations stay on the management plane.** Opening a port is a perimeter change. The `SettingsWrite` scope's own definition (`automation_token.rs`) says the automation plane never touches "a listener", and a stream is a listener; an automation token has no axis that could confine a listen address or port (`allowed_hostnames` means nothing for a stream). So:
- the automation API gets `streams:read` only, and the MCP server gets stream tools in the read tier only;
- creating, changing and deleting a stream happens through the management API, from the dashboard or an operator session;
- the settings that open a hole (lifting UDP bounds, PROXY-accept trusted CIDRs, local backends, send/expect payloads) are refused on every automation and MCP surface, including on `backends:write`, which may pick a named health-check template but never write a payload.

What this gives up: creating streams from CI with a token. Adding listen-address and port confinement to tokens is possible later and would be its own decision.

**Integration Requirements:** All work lands on a single `feat/v1.10.0` branch with one final PR to `main`; the version is bumped once, after Phase 2. If a new crate is introduced for the stream data plane, the three-Dockerfile rule applies (`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`), `docs/BUMP-CHECKLIST.md` gains it, and its version follows the product line. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings` under `RUSTFLAGS=-D warnings`, `cargo audit`, and the frontend gates stay green at every commit.

**HTTP-visible changes, each with its non-regression test:** the typed health-check migration (Story 12.1); the configurable drain delay (Story 12.11); PROXY protocol accept on the HTTP listeners, off by default (Story 12.8); weighted P2C as a new balancing option (Story 12.13); the UDP-only backend validation (Story 12.1). With PROXY accept off and P2C unused, HTTP behaviour is unchanged and every existing e2e profile passes untouched.

**Cross-cutting deliverables** (no single story owns them, all release-blocking):
- `docs/streams.md` as the user-facing reference: a directive-by-directive equivalence table from nginx `stream {}` and HAProxy `mode tcp`; the UDP capacity formula (session ceiling divided by idle timeout for one-shot protocols) and the preconditions for high session counts (`LimitNOFILE` drop-in, wider `ip_local_port_range`, several source addresses through `proxy_bind`); the hairpin pattern for sharing port 443 with Lorica's HTTPS listener; ClientHello and ECH behaviour.
- `docs/security/threat-model.md` gains: UDP reflection and amplification, slow ClientHello and slow detection, PROXY-header spoofing, detection bypass, a stream exposing local services, forwarding loops, DNS rebinding of stream backends, log amplification, and the post-compromise consequence of the transparent-mode capability.
- `docs/security/hardening-guide.md` gains stream guidance: the transparent-mode drop-in, raising UDP session capacity, and the drain delay versus `TimeoutStopSec`.
- `docs/hot-upgrade.md` and `docs/installation.md` describe the `worker_drain_timeout_s` that now exists; `docs/cluster.md` "Running a Mixed-Version Fleet" covers the 1.9.0 to 1.10.0 step.
- `lorica-api/openapi.yaml` for the stream resource and the backend health-check shape, kept green against the contract test.
- `streams:read` turns red every artefact listed where `AutomationScope` is defined: the serde rename test, `AUTOMATION_AUDIT_REASONS`, `lorica-api/openapi.yaml`, `lorica-api/openapi-automation.yaml`, and `automation-scopes.generated.ts` checked by `lorica-api/tests/automation_scope_fixture.rs`. All move in one commit.
- `CHANGELOG.md` under Added and Security. The README feature list and roadmap.

---

## Prior Art

Verified against official documentation on 2026-09-28. nginx 1.31.x is the mainline branch; whether its most recent additions have reached a stable release was not checked.

### Coverage matrix and Lorica's commitment

"P1" is Phase 1 (parity), "P2" is Phase 2 (beyond parity).

| Feature | nginx `stream` | HAProxy `mode tcp` | Traefik | Envoy | caddy-l4 | Lorica 1.10.0 |
|---|---|---|---|---|---|---|
| TCP proxying | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.3 |
| UDP proxying with idle timeout | Yes | Paid (Enterprise) | Yes | Yes | Plugin | P1, Story 12.5 |
| UDP request/response bounds | `proxy_responses`, `proxy_requests` | Paid | No | No | No | P1, Story 12.5, on by default, plus byte bounds |
| TLS passthrough, SNI routing | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.4 |
| ALPN routing | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.4 |
| TLS termination at L4 | Yes | Yes | Yes, with ACME | Yes | Plugin, ACME through Caddy | P1, Story 12.4, with Lorica's ACME certificates |
| Upstream TLS / mTLS | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.4 |
| PROXY protocol v1/v2 send | Yes (v2 since 1.31.4, mainline) | Yes | Yes | Yes | Plugin | P1, Story 12.3 |
| PROXY protocol v1/v2 accept on streams | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.3, TCP only, trusted sources only |
| PROXY protocol accept on the HTTP listeners | Yes | Yes | Yes | Yes | n/a | P1, Story 12.8 |
| Round robin, least conn | Yes | Yes | WRR only | Yes | Plugin | P1, Story 12.3 |
| Hash / consistent hash on source | Yes | Yes | No | Yes | Plugin | P1, Story 12.3 (`lorica-ketama`) |
| Random / power of two | Yes | Yes | No | Yes | Plugin | Random P1; weighted P2C P2, Story 12.13 |
| Latency-aware selection | `least_time` | No | No | No | No | P1, Story 12.3 (`peak_ewma`) |
| Backup backends | Yes | Yes | No | Priority | No | P1, Story 12.3 |
| Passive failure detection | Yes | Yes | No | Yes | Plugin | P1, Story 12.3 (circuit breaker) |
| Active health: TCP connect | Paid | Yes | Yes | Yes | Plugin | P1 (exists today) |
| Active health: send/expect | Paid | Yes | Yes | Yes | No | P1, Story 12.7 |
| Active health: UDP | Paid | Paid | No | No | Not stated | P2, Story 12.14, **no open-source competitor** |
| Active health: agent check | No | Yes | No | No | No | Refused |
| Connection limit per source IP | Yes | Yes | Yes (InFlightConn) | No | No | P1, Story 12.6 |
| Connection limit per listener / backend | Yes | Yes | Yes | Yes | No | P1, Story 12.6 |
| New-connection rate limit | **No** | Yes | No | Yes | No | P1, Story 12.6 |
| Bandwidth limit | Yes | Yes (bwlim filter) | No | No | No | P1, Story 12.3 |
| IP allow/deny | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.6 |
| GeoIP | Yes | Maps in OSS; MaxMind module paid | No | Yes | No | P1, Story 12.6 |
| Chosen source address (`proxy_bind`) | Yes | Yes (`source`) | No | Yes | No | P1, Story 12.3 |
| Transparent proxy | Yes | Yes | No | Yes | No | P2, Story 12.13, opt-in |
| Backend TCP keepalive | Yes | Yes | No | Yes | No | P1, Story 12.3 |
| Port ranges | Yes | Yes | No | No | Yes | P1, Story 12.2 |
| Dynamic reconfiguration | Reload; API paid | Runtime API | Provider | xDS | Admin API | P1, Story 12.2, management API and cluster |
| Connection draining | Yes | Yes | Yes | Yes | Plugin | P1, Story 12.11 |
| Hot binary upgrade | USR2 | Reload with fd passing, drain | No | Hot restart, drain; in-flight UDP datagrams forwarded | No | Drain P1, Story 12.11; **live transfer of TCP passthrough and UDP sessions** P2, Story 12.16 |
| L4 access log | Yes | Yes | Not verified | Yes | Not verified | P1, Story 12.9 |
| L4 metrics | Paid | Yes | Gauge only | Yes | Not verified | P1, Story 12.9 |
| Timeouts connect / idle / total | Yes / Yes / No | Yes | Partial | Yes | Partial | P1, Story 12.3 |
| Upstream DNS re-resolution | Yes | Yes | Provider | Yes | Not verified | P1, Story 12.3 |
| IPv6 | Yes | Yes | Yes | Yes | Yes | P1, Stories 12.2 to 12.5 |
| Session persistence | Hash | Stick tables | No | Hash | `ip_hash` | P1, Story 12.3 (consistent hash); stick tables refused |
| Protocol detection on one TCP port | Preread only | Payload ACLs | SNI/ALPN | Inspectors | Richest set | P2, Story 12.15, closed matcher set; the rest refused |
| Arbitrary payload inspection | njs | `tcp-request content` | No | Wasm | Regexp | Refused |
| Import from an nginx config | n/a | n/a | n/a | n/a | n/a | Fix P1, Story 12.0; full import P2, Story 12.17 |

"Paid" means nginx Plus or HAProxy Enterprise only. On UDP, HAProxy states that "general-purpose UDP load balancing ... is available only in HAProxy Enterprise" ([source](https://www.haproxy.com/solutions/udp-load-balancing)); the community edition has QUIC and UDP syslog forwarding only.

### What the survey says beyond the matrix

- **The table stakes** nginx and HAProxy both ship in open source: TCP, TLS passthrough with SNI routing, ALPN routing, L4 TLS termination, upstream TLS, PROXY protocol v1 and v2 both ways, round robin plus least conn and hash, passive failure detection, allow/deny, IPv6, connect and idle timeouts, and, on the nginx side, UDP with request/response bounds. HAProxy adds active TCP checks with send/expect, which nginx keeps paid. Missing any one of these reads as "not a real L4 proxy".
- **UDP defaults across the field** are short: 3 s idle (Traefik), 10 s (HAProxy Enterprise), 30 s (caddy-l4), 1 min (Envoy). nginx and HAProxy Enterprise both expose a responses-per-request bound. D6's defaults are the state of the art, extended to bytes because a count alone does not bound reflection.
- **Three gaps the field leaves open:** no open-source product has active UDP health checks; nginx has no new-connection rate limit; no competitor transfers established TCP connections or UDP session state across an upgrade (Envoy forwards in-flight UDP datagrams, not sessions). The rate limit is Phase 1; the other two are Phase 2.

### Sources

nginx: [ngx_stream_proxy_module](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html), [ngx_stream_upstream_module](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html), [ngx_stream_core_module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html), [ngx_stream_ssl_preread_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [ngx_stream_ssl_module](https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html), [ngx_stream_upstream_hc_module](https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html), [CHANGES](https://nginx.org/en/CHANGES). HAProxy: [3.4 configuration manual](https://docs.haproxy.org/3.4/configuration.html), [3.4 management guide](https://docs.haproxy.org/3.4/management.html), [Enterprise UDP load balancing](https://www.haproxy.com/documentation/haproxy-enterprise/enterprise-modules/udp-load-balancing/overview/). Traefik: [TCP services](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/service/), [UDP services](https://doc.traefik.io/traefik/reference/routing-configuration/udp/service/), [TCP routing rules](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/routing/rules-and-priority/), [InFlightConn](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/middlewares/inflightconn/). Envoy: [tcp_proxy](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto), [udp_proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/udp_filters/udp_proxy), [health checking](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/health_checking), [hot restart](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart). caddy-l4: [repository](https://github.com/mholt/caddy-l4), [matchers](https://github.com/mholt/caddy-l4/blob/master/docs/matchers.md).

---

# Phase 1: Parity

Stories are built in number order. Story 12.0 lands before any other. Phase 1 ends when Story 12.12 passes: at that point Lorica covers every table-stakes row, and Phase 2 starts.

## Story 12.0: The nginx importer stops misreading `stream {}` blocks

As an operator importing an existing nginx configuration,
I want a `stream {}` block to be recognised as what it is,
so that a TLS passthrough on 443 is never imported as an HTTP route, and a database port does not produce a misleading "use a subdomain on 443" hint.

Executed on a copy of `lorica-dashboard/frontend/src/lib/nginx-parser.ts` (2026-09-28):
- `server` and `upstream` are recognised with no parent check, so a stream `server` and its `upstream` land in the HTTP-shaped output of `parseNginxConfig`.
- A stream server on a port other than 80 or 443 (for example 5432) is then skipped by `convertToLoricaRoutes` and produces no route; the only diagnostics are a "Non-standard port, consider a subdomain on 443" hint and an "Unexpected closing brace" error.
- **The real harm:** `stream { upstream tls { server 10.0.0.40:443; } server { listen 443; ssl_preread on; proxy_pass tls; } }` becomes an **HTTP route with an empty hostname** pointing at `10.0.0.40:443`. A TLS passthrough, one of the most common `stream {}` uses, is silently turned into an HTTP route.
- **A separate bug:** a block opener that is not `server`, `upstream`, `location` or `if` never pushes a frame, because `splitStatements` splits `{` into its own token and the `value.endsWith('{')` fallback can never match. Every `http {}` or `stream {}` wrapper therefore produces a spurious "Unexpected closing brace" error, and an unknown nested block inside a `location` (for example `limit_except`) would close the location early (inferred from the code, not executed).

### Acceptance Criteria

1. **The failing cases come first**, in `nginx-parser.test.ts`, each naming the layer it checks, committed as expected failures (`it.fails`) so the gates stay green, and flipped to passing in the fix commit:
   - (a) the `ssl_preread` sample above yields no route from `convertToLoricaRoutes`;
   - (b) the sample `stream { upstream db { server 10.0.0.10:5432; } server { listen 5432; proxy_pass db; } }` yields no entry in `parseNginxConfig(...).servers` or `.upstreams`;
   - (c) an `http {}` wrapper and a `stream {}` wrapper produce no "Unexpected closing brace" error.
2. **The parser tracks block context.** `server` and `upstream` inside `stream {}` are parsed into stream-shaped results, distinct from the `http` ones, and are never merged into them.
3. **Every block opener pushes a frame**, so unknown blocks, top-level or nested, close where they should. The dead `endsWith('{')` fallback is removed.
4. **Until Story 12.17 lands, stream results produce a diagnostic, never silence.** Each stream `server` yields a `warning` naming its line and stating it was not imported, in place of the port hint.
5. Existing importer tests pass unchanged.

### Integration Verification

- IV1: A mixed configuration with both `http {}` and `stream {}` imports exactly the HTTP routes it imported before this story, no route for any stream server, one diagnostic per stream server, and no brace error.

---

## Story 12.1: The stream model, shared backends and the release's schema decisions

As an operator,
I want to declare a stream and point it at backends I already manage,
so that one list of backends and one health state serve both my HTTP routes and my TCP streams.

### Acceptance Criteria

1. **New `Stream` model in `lorica-config`** with the fields this story gives meaning to: id, name, group name, protocol (`tcp` or `udp`), listen address and a single port or a port range, IPv4 and IPv6, a list of backends through a `stream_backends` join (the counterpart of `RouteBackend`), `node_selector`, `managed_by`, timestamps. Each later story adds its own fields, validation and migration; no field is stored before a story gives it a meaning.
2. **Port ranges map port to port.** A range stream forwards listen port N to backend port N; its backends are given without a port. A range is capped at 1,024 ports per stream by default.
3. **The typed health check, by additive migration (D2).** The migration adds the typed definition and keeps `health_check_path`. In 1.10.0 the typed definition is read and both are written; the management API, both OpenAPI documents, the dashboard backend form and `api.ts`, and the MCP and automation backend tools accept both shapes, with the old one documented as deprecated. A test proves the 1.9.0 binary still opens a 1.10.0 database, so a hot-upgrade rollback (`docs/hot-upgrade.md`) does not become an outage.
4. **UDP-only backends.** A backend attached to a UDP stream cannot be attached to an HTTP route or a TCP stream, and cannot carry a non-UDP health check; the validation error names the stream. Until Story 12.14 ships UDP checks, a UDP backend has active checks disabled and relies on passive detection.
5. **The canonical config decision is taken once, here, for the release.** `Stream` and `stream_backends` join `CanonicalConfig`, whose version check is strict equality and whose decoder refuses unknown fields. This story decides the `CANONICAL_FORMAT_VERSION` step for 1.10.0 and the fleet upgrade order it implies, and updates `docs/cluster.md` "Running a Mixed-Version Fleet". Later stories add fields inside that decision.
6. **Replicated and targeted.** Streams take part in two-phase replication and honour `node_selector` exactly as routes do. A follower never binds a stream it was not targeted by.
7. **Port conflicts are checked per node.** Followers report their reserved ports (HTTP, HTTPS, management, automation, cluster, enrollment) in their heartbeat. The control plane refuses a stream whose port or range overlaps a targeted node's reserved ports or another stream on that node and protocol, using the same rule as the CLI's `refuse_reserved` so the two cannot drift. The error names the conflicting node and object. The node refuses at bind as the backstop (Story 12.2).
8. **The closed set of end reasons** for stream connections and sessions is defined here, as one enum every later story uses: `client_close`, `backend_close`, `idle_timeout`, `total_timeout`, `connect_failed`, `no_healthy_backend`, `refused` with a reason, `clienthello_timeout`, `proxy_header_invalid`, `detection_timeout`, `request_bound_reached`, `response_bound_reached`, `backend_down`, `config_removed`, `drained_by_upgrade`. Transfer (Story 12.16) is an event, not an end.
9. **Management API CRUD** for streams, with the same validation, audit and JSON GET secret filtering as routes. TOML export and import carry streams.
10. **HTTP non-regression.** The existing backend, route and health-check suites pass on the migrated schema, and the migration is idempotent.

### Integration Verification

- IV1: A stream targeted at one node of a three-node fleet appears in the other two nodes' canonical config and is bound on none of them.
- IV2: A stream on a follower's HTTPS port is refused by the control plane with the follower's name in the error.

---

## Story 12.2: Stream listeners on a running process

As an operator,
I want a stream's port to open when I create it and close when I delete it,
so that I never restart Lorica to add a layer-4 service and no port stays open without a reason.

### Acceptance Criteria

1. **Runtime bind by the supervisor (D4)** over a new runtime fd channel per worker, with a new typed tag. TCP: one listener shared by the workers. UDP: one socket per worker in a `SO_REUSEPORT` group. Deleting or disabling a stream closes its sockets in every worker and in the supervisor.
2. **A stream accept loop outside Pingora** serves stream sockets in every worker.
3. **Privileged ports work** without changing the systemd unit.
4. **A bind failure is a configuration error, not a crash.** Port in use, permission denied or address not available is reported on the stream (API, dashboard, audit, a notification through `lorica-notify`) with the OS error; the stream stays in a failed state and every other listener is unaffected.
5. **An fd budget that protects HTTP.** A per-node cap on total stream listening sockets (default documented) and an fd reserve for HTTP that the stream plane can never consume, derived from the process fd limit. A stream create that would break the reserve is refused.
6. **Single-process mode** binds and releases stream listeners the same way.
7. **The drain delay exists.** `worker_drain_timeout_s`, already named in `docs/hot-upgrade.md`, becomes a real global setting with the current 30 s as default, capped below the unit's `TimeoutStopSec` minus a documented headroom; the hardening guide documents the matching drop-in for longer drains. Story 12.11 uses it for upgrades; this story uses it for configuration changes.
8. **Reconfiguration without cutting traffic.** Established connections and sessions keep the settings they were accepted with; an edit applies to new connections only. Removing a backend from a stream, deleting the backend, or disabling or deleting the stream drains established connections for `worker_drain_timeout_s`, then closes them with `config_removed`. Changing a stream's listen address or port rebinds, and connections on the old socket drain the same way.
9. **Every bind and release is visible per node** in the audit chain and in the fleet view from this story on, including a node that starts matching a stream's `node_selector` at enrollment; the enrollment preview lists the ports the node will open.

### Integration Verification

- IV1: Creating a TCP stream on port 5432 through the management API makes `ss -ltn` show it on the node within 5 s; deleting it removes it within 5 s, with no restart and no dropped HTTP request in between.
- IV2: Creating a stream on a port already held by another process leaves the stream in a failed state with the OS error, and HTTP traffic is unaffected.

---

## Story 12.3: The TCP stream engine

As an operator,
I want Lorica to forward TCP connections to my backends with the balancing, timeouts and source-address handling I expect from nginx or HAProxy,
so that moving a TCP service behind Lorica loses nothing.

### Acceptance Criteria

1. **Bidirectional byte forwarding** with half-close handled in both directions.
2. **Load balancing** with the algorithms Lorica already exposes (`LoadBalancing`, `lorica-config/src/models/enums.rs`), as they behave today: round robin (weighted), consistent hash on the source address for persistence (weighted, `lorica-ketama`), random (uniform), least connections, and peak EWMA for latency-aware selection. Weights apply to round robin and consistent hash; the documentation says so.
3. **Backup backends**, used only when every primary backend is down.
4. **Passive failure detection** reuses the circuit breaker (`CircuitBreaker`, `lorica/src/proxy_wiring/lb.rs`), keyed per (stream, backend) as it is keyed per (route, backend) for HTTP, counting connect failures and timeouts, coordinated across workers.
5. **Retry on connect failure** to another backend, bounded by a per-stream attempt count, ending with `connect_failed` or `no_healthy_backend`. Once bytes have flowed, a connection is never retried.
6. **Timeouts**: connect, idle and optional total duration, per stream, with documented defaults. **TCP keepalive** towards the backend, configurable.
7. **Live connections and backend health.** A backend marked down stops receiving new connections and does not cut established ones, unless the stream sets `close_on_backend_down` (default off, the equivalent of HAProxy's `on-marked-down shutdown-sessions`), in which case they close with `backend_down`.
8. **PROXY protocol send**, v1 or v2 per stream.
9. **PROXY protocol accept on TCP streams**, v1 and v2, only from a per-stream list of trusted source CIDRs. The header is bounded in size (4 KiB) and in time; a header from an untrusted source, an oversized one or a late one closes the connection with `proxy_header_invalid`. PROXY accept on UDP streams is refused in writing: a UDP source address is spoofable, so "trusted source" means nothing.
10. **Chosen source address** (`proxy_bind`): a stream can connect from a configured local address, which is also how UDP session capacity is raised past one address's ephemeral ports.
11. **Local backends are refused, at validation and at every connect.** A backend that resolves to a loopback, link-local or other local address on a reserved port (Story 12.1 AC #7) or on any stream listen port of the node is refused, which also prevents forwarding loops. Other local backends need an explicit per-stream `allow_local_backend` flag, badge-visible, never settable from the automation or MCP surfaces. The check runs again after every DNS resolution, so a hostname that re-resolves to a local address is marked down, not connected.
12. **Bandwidth limits** per stream, upload and download, per connection.
13. **Upstream DNS re-resolution** on a TTL-bounded schedule; a resolution failure keeps the last known addresses and raises a health event.
14. **Bounded resources.** Per-connection buffers are fixed-size; a slow reader applies backpressure to the other side, never unbounded buffering. A per-stream cap on concurrent TCP connections has a documented default.

### Integration Verification

- IV1: A TCP stream in front of three PostgreSQL backends balances connections by the configured algorithm and survives one backend being killed with no failed new connection after the breaker trips; a `psql` session opened before the kill on a surviving backend is unaffected.
- IV2: A backend shared by an HTTP route and a TCP stream is marked down: it leaves selection for both, and an established stream connection to it stays open.
- IV3: A backend receiving PROXY v2 sees the real client address; a client outside the trusted CIDRs sending a PROXY header is disconnected.
- IV4: A stream pointed at `127.0.0.1:<management port>` is refused at creation; a hostname backend that re-resolves to `127.0.0.1` is marked down and never connected.

---

## Story 12.4: TLS at layer 4

As an operator,
I want to route TLS connections by SNI without decrypting them, or terminate them with a certificate Lorica already manages,
so that end-to-end TLS services and plaintext services that need TLS in front are both covered.

### Acceptance Criteria

1. **Passthrough with SNI and ALPN routing.** A stream reads the ClientHello without terminating TLS, reassembling it across records within a size ceiling, and selects a backend by SNI (exact and wildcard) and ALPN. The read is bounded in size and time; a client that does not complete its ClientHello in time is closed with `clienthello_timeout`. No match closes the connection (D7). With Encrypted Client Hello, routing sees the outer public name; `docs/streams.md` says so.
2. **The "no SNI" matcher (D7)** is an explicit matcher, badged and counted, requiring a source allowlist or an explicit acknowledgement.
3. **Termination with Lorica's certificates.** A stream can terminate TLS with a certificate from the existing `CertResolver` (`lorica-tls/src/cert_resolver.rs`), including ACME-issued certificates with automatic renewal and hot swap, then forward plaintext or re-encrypted.
4. **Upstream TLS on the stream** (D2): verification by default, configurable SNI, client certificates for mTLS towards the backend. The backend's HTTP upstream TLS fields do not apply to streams.
5. **Client certificate verification** on terminated streams, against a configured CA.
6. The TLS mode of a stream (none, passthrough, terminate) and upstream TLS are explicit fields, and fields that do not apply to the chosen mode are refused rather than ignored. A stream with termination or upstream TLS is marked as draining on upgrade (D8) in the dashboard and API.

### Integration Verification

- IV1: One port serves two SNI names in passthrough to two different backends, each seeing the client's original ClientHello; a third SNI is refused.
- IV2: A stream terminating TLS with an ACME certificate keeps serving across a renewal, and new connections present the renewed certificate.

---

## Story 12.5: The UDP stream engine

As an operator,
I want to forward UDP traffic (DNS, syslog, RADIUS, game or VoIP signalling) with session semantics and safe defaults,
so that I can front UDP services without building an amplifier.

### Acceptance Criteria

1. **Sessions keyed on the client address and port**, each bound to one backend and served by one worker for that worker's lifetime (D4), with round robin, random, consistent hash on source and least sessions.
2. **The D6 defaults**, each documented next to the survey's values: response datagrams per request, response bytes relative to request bytes, requests per session, idle timeout, per-source datagram and byte rate, per-source session cap, total session cap per stream. A session closes as soon as its request or response bound is reached (`request_bound_reached`, `response_bound_reached`).
3. **Listen address rule (D6).** A UDP stream on an address that is not loopback, RFC 1918 or ULA is refused without a source allowlist or a per-source cap at or below the documented maximum.
4. **Unbounded responses are explicit**: a separate field, a permanent badge, a flag in API and MCP listings.
5. **Per-node caps on dedicated tables.** Stream caps are per node, shared across workers, on `lorica-shmem` tables of their own (not the WAF tables), sized per stream. A full table refuses new sessions on that stream only, counted as its own refusal reason. A concurrency slot is never evicted while it is held. The shared-memory layout version bump is part of this story.
6. **A ceiling derived from the host.** Each session holds one connected upstream socket, so the per-node session ceiling defaults below the fd budget left after the HTTP reserve (Story 12.2 AC #5) and below the usable ephemeral port count per source address (about 28,000 with the default `ip_local_port_range`). It is recomputed on every stream change, reported with the limit that bound it, and a change that would break it is refused. Receive buffers are shared per worker, never allocated per session.
7. **PROXY protocol v2 (DGRAM transport) prefixed to every datagram** sent to the backend where enabled; the per-datagram convention and the backends known to accept it are documented.
8. **Datagram size** is bounded; oversized datagrams are dropped and counted.

### Integration Verification

- IV1: With default settings, a flood from many spoofed sources aimed at reflecting towards one victim address keeps the reflected byte rate towards that address under the documented bound, and a legitimate client from another address is still served.
- IV2: A DNS stream in front of two resolvers, driven at a query rate above the documented capacity formula with default settings, answers every query with no refusal, because each session closes on its response.

---

## Story 12.6: Protecting stream listeners

As an operator,
I want the source-address, geography and rate controls Lorica applies to HTTP to protect my streams as well,
so that opening a layer-4 port does not open a hole in my perimeter.

### Acceptance Criteria

1. **Allow and deny CIDRs per stream**, evaluated before any byte is forwarded (TCP, at accept) or any session is created (UDP), in addition to the global connection filter, which applies to stream listeners too.
2. **GeoIP country allow/deny per stream** through `lorica-geoip`, and the global IP blocklist applied to stream traffic.
3. **Concurrent connection caps** per source address, per stream and per backend, per node on the dedicated tables of Story 12.5 AC #5. The settings UI states that the existing global per-IP cap is per process while stream caps are per node.
4. **New-connection rate limit** per source address and per stream (TCP connections, UDP session creations), on local or asynchronously synced token buckets, never a synchronous cluster round trip per connection.
5. **Pre-forwarding caps.** Connections still reading a PROXY header, a ClientHello or, in Phase 2, detection bytes count against the per-source cap from accept, and a per-stream cap bounds how many may be pending at once.
6. **No refusal is uncounted.** Every refusal increments a counter per stream and reason. Refusal log rows are rate-limited per stream and reason, with a periodic "N refusals suppressed" row, so an attacker cannot choose the write rate of the log sinks.

### Integration Verification

- IV1: A source over its new-connection rate is refused at accept while another source on the same stream is served.
- IV2: A client from a denied country is refused on a TCP stream and on a UDP stream.
- IV3: 10,000 connections that never send a ClientHello leave the stream serving other clients and never exceed the pending cap.

---

## Story 12.7: TCP health checks that speak the protocol

As an operator,
I want active checks that prove a TCP backend answers, not only that its port is open,
so that a hung database leaves the pool before clients notice.

### Acceptance Criteria

1. **TCP send/expect**: optional bytes to send, bytes or a pattern to expect within a timeout. The existing TCP-connect probe (`tcp_probe`, `lorica/src/health.rs`) remains the default.
2. Checks run on the existing health loop with its interval, thresholds and lifecycle states, and feed the one health state of the shared backend (D2).
3. **Named templates** for common protocols (Redis `PING`, SMTP banner, PostgreSQL SSLRequest), expressed as send/expect values.
4. **Payloads are written from the management API only (D9).** `backends:write` on the automation API and the MCP config tier may select a named template and nothing else. A payload is validated in size.

### Integration Verification

- IV1: A Redis backend that stops answering `PING` while its port stays open is marked down within the configured thresholds.
- IV2: An automation token with `backends:write` can set a template and is refused when it sends a raw payload.

---

## Story 12.8: PROXY protocol on the HTTP listeners

As an operator running Lorica behind a cloud layer-4 load balancer,
I want Lorica to take the client address from the PROXY header,
so that logs, WAF, rate limits and GeoIP see the real client instead of the load balancer.

### Acceptance Criteria

1. **PROXY protocol v1 and v2 accept on the HTTP and HTTPS listeners**, off by default, per listener.
2. **The accept path is reordered in the forked listener** (`lorica-core`, where the connection filter runs on the socket peer at accept): the header is read first, from a trusted peer only, then the connection filter runs on the address it carries. This modification of the fork is named in the fork's sync notes, since it will conflict with future upstream changes to that path.
3. **One trust list, and no stacking.** A dedicated `proxy_protocol_trusted_cidrs`, separate from `trusted_proxies`. On a connection whose client address came from a PROXY header, `X-Forwarded-For` from the client is never read.
4. **Header required from trusted peers**, unless the listener sets an `optional` flag for load balancers whose health checks send none. The same size and time bounds as Story 12.3 AC #9.
5. **When on, the carried address is the client address for every HTTP control**: access logs, WAF and bot verdicts, rate limits, GeoIP, the connection filter, and the `X-Forwarded-For` Lorica sends upstream.
6. **The setting is refused on every automation and MCP surface**, in the same family as the trusted proxies the Epic 11 admin tier already refuses.

### Integration Verification

- IV1: Behind an L4 load balancer sending PROXY v2, an HTTPS route logs, rate-limits, GeoIP-filters and forwards `X-Forwarded-For` with the original client address.
- IV2: A direct connection from outside the trusted CIDRs carrying a PROXY header is disconnected, and one carrying a forged `X-Forwarded-For` behind a trusted PROXY peer is logged with the PROXY address.
- IV3: With PROXY accept off, every existing HTTP e2e profile passes unchanged.

---

## Story 12.9: Stream observability

As an operator,
I want to see what my streams carry and why a connection ended,
so that layer 4 is not the blind spot of my monitoring.

### Acceptance Criteria

1. **An access-log row per TCP connection and per UDP session** at its end: stream, client address (after PROXY protocol where accepted), backend, bytes each way, duration, TLS mode, SNI, detected protocol when Phase 2 applies, and one end reason from the enum of Story 12.1 AC #8.
2. **The rows reach the existing sinks** (`SinkKind`, `lorica-api/src/log_sinks/mod.rs`) through a new stream kind: syslog, OTLP logs, the dashboard log view.
3. **Prometheus metrics** under the `lorica` namespace: active connections and sessions, accepted, refused by reason, dropped datagrams by reason, bytes each way, connect latency to backend, per stream and per backend. No client address in a label.
4. **SLA per stream**: availability and backend connect latency. This extends the per-route SLA model and its dashboard view, and `sla:read` covers it.
5. **Notifications** through `lorica-notify` for a failed bind, a stream backend down, and a UDP ceiling reached.

### Integration Verification

- IV1: A refused connection, an idle-timeout close and a `config_removed` drain each produce a row with the right end reason, visible in the dashboard and in a syslog collector.

---

## Story 12.10: Streams on every surface

As an operator running a fleet with automation and an MCP client,
I want to see streams wherever I see routes, and manage them from the dashboard,
so that layer 4 is not a second-class feature.

### Acceptance Criteria

1. **Dashboard**: a Streams page beside Routes (loader map in `lorica-dashboard/frontend/src/routes/Dashboard.svelte`, sidebar entry in `components/Nav.svelte`) with list, form, badges (unbounded UDP responses, "no SNI", silent client, local backend, transparent mode, drains on upgrade, failed bind), live counters, and the backend page showing which routes and streams use each backend.
2. **Automation API (D9)**: a new `streams:read` scope in the closed `AutomationScope` enum, justified where the enum is defined, with every artefact the enum's comment lists moving in the same commit. No stream write scope. The `environment` resource stays HTTP-only.
3. **MCP (D9)**: the read tier gains stream listings and stream status, paginated and capped like the other read tools. No tier gains a stream mutation.
4. **Cluster**: the fleet view shows each stream's bind state per node.
5. **Audit**: every stream mutation lands in the tamper-evident chain with its origin.

### Integration Verification

- IV1: A stream created from the dashboard appears in the automation API with a `streams:read` token and in the MCP read tier; an automation token has no way to create one.

---

## Story 12.11: Upgrades and reloads drain streams cleanly

As an operator,
I want an upgrade to give my long-lived streams the time I choose and tell me what it closed,
so that an upgrade never cuts a database session at an arbitrary 30 s.

### Acceptance Criteria

1. **Hot upgrade uses `worker_drain_timeout_s`** (Story 12.2 AC #7) for HTTP and streams, replacing the hard-coded 30 s in `drain_for_handoff`. `docs/hot-upgrade.md` and `docs/installation.md` describe the setting as it now exists.
2. **Every connection an upgrade closes** ends with `drained_by_upgrade`, distinct from every other end reason, and the existing `lorica_hot_upgrade_total` outcome counter gains per-stream drain counts.
3. **Preview before upgrade**: per stream, the number of established connections and the drain delay that will apply.

### Integration Verification

- IV1: With `worker_drain_timeout_s` set to 120 s, an SSH session through a stream survives a hot upgrade for up to 120 s after it starts and then ends with `drained_by_upgrade` in the log.

---

## Story 12.12: Parity verification

As the maintainer,
I want parity proven end to end and measured against nginx on the same machine,
so that "on a par" is a measured claim before Phase 2 starts.

### Acceptance Criteria

1. **An L4 phase in `tests-e2e-docker/`** with real backends, running every Integration Verification of Stories 12.1 to 12.11 as its own named scenario, plus the fd-reserve scenario (filling UDP sessions to the ceiling leaves HTTP accept unaffected).
2. **A performance phase** runs nginx `stream` (pinned version) and Lorica in the same compose, alternately, against the same backends, comparing **ratios, never absolute numbers**. The load generator, the proxy under test and the backends are pinned to disjoint `cpuset`s, and both proxies get the same core count. Each measurement is repeated at least 5 times per proxy, alternating; the phase reports median and spread, and proxy CPU per GiB forwarded.
   - TCP passthrough: Lorica median throughput at least 0.90 x the nginx median, and Lorica CPU per GiB at most 1.15 x nginx.
   - Connection setup: Lorica p99 accept-to-backend-connect latency at most 1.5 x the nginx p99, for non-TLS streams.
   - UDP: at a fixed session count equal to 80 % of Lorica's derived ceiling, both proxies hold every session with no loss and no premature eviction; Lorica's resident memory per 1,000 sessions is reported.
3. **Inconclusive is not a pass.** A result whose spread exceeds 5 % of its median is re-run, at most 3 times; still inconclusive, it blocks the release pending an owner decision.
4. **NFR1 by the same method**: HTTP throughput and p99 against the v1.9.0 binary in the same run, with and without one idle stream configured.
5. **Gating.** The performance phase gates the local release run, which has the machine to itself as the e2e suite already requires. In CI it runs and publishes its numbers in the job summary without gating, because shared runners are too noisy for these ratios. `lorica-bench` is Lorica's SLA and load-test feature, not this harness.
6. **New test artefacts are named and approved at the start of this story**: the nginx image and version, a TCP load generator, a DNS load generator, and the PostgreSQL, DNS resolver, SSH and TLS echo backend images.
7. Every existing e2e profile passes unchanged.

### Integration Verification

- IV1: The local release run of the full e2e suite, including the L4 and performance phases, passes on the Phase 1 head. Phase 2 starts from that commit.

---

# Phase 2: Beyond parity

## Story 12.13: Weighted P2C and transparent proxying

As an operator,
I want the balancing and source-address options the most capable proxies offer,
so that I do not trade them away by choosing Lorica.

### Acceptance Criteria

1. **Weighted power of two choices (P2C)** in the `LoadBalancing` enum, for HTTP routes and streams, weights honoured, with the HTTP balancing tests extended.
2. **Transparent proxying, opt-in.** A stream can connect to its backend from the client's source address (`IP_TRANSPARENT`). This needs `CAP_NET_RAW` or `CAP_NET_ADMIN` in the workers and policy routing configured outside Lorica. The default unit grants neither; the hardening guide ships a drop-in granting `CAP_NET_RAW` on both `CapabilityBoundingSet` and `AmbientCapabilities`, chosen because it grants no routing or firewall control. The guide and the threat model state the cost: every worker, HTTP workers included, can then open raw IP sockets and spoof packets if compromised.
3. A stream configured transparent on a process that lacks the capability is in a failed state with that reason.

### Integration Verification

- IV1: A backend behind a transparent stream sees the client's own address as the TCP peer.

---

## Story 12.14: Active health checks for UDP backends

As an operator,
I want a check that proves a UDP service answers,
so that a dead DNS resolver leaves the pool although its port is "open".

### Acceptance Criteria

1. **UDP send/expect**: a datagram to send, a response to expect within a timeout. No open-source competitor ships this.
2. **Named templates** (DNS query, RADIUS status) become the default check for new UDP backends; existing UDP backends keep passive detection until an operator picks one.
3. Payload rules of Story 12.7 AC #4 apply.

### Integration Verification

- IV1: A DNS resolver that stops answering is marked down by its UDP check and leaves the stream within the configured thresholds.

---

## Story 12.15: Protocol detection on a shared TCP port

As an operator,
I want to serve several protocols on one port,
so that I can cover network setups where only one port is open.

### Acceptance Criteria

1. **A closed matcher set**, each routing to its own backends: TLS (SNI and ALPN), HTTP/1.x, the HTTP/2 preface, SSH, PostgreSQL (SSLRequest, GSSENCRequest, CancelRequest, StartupMessage 3.x; PostgreSQL 17 direct SSL is matched by the TLS matcher on ALPN `postgresql`), RDP (TPKT and X.224 Connection Request), OpenVPN over TCP.
2. **The silent-client matcher (D7)** for server-first protocols, pointed at one backend, fired only when the client sent no byte within N ms, badged, counted, and requiring a source allowlist or an explicit acknowledgement. SSH clients that wait for the server banner are silent clients: they reach SSH only where the silent-client matcher points at it. Validation refuses a stream that mixes the silent-client matcher with a matcher whose clients may wait before sending (SSH, OpenVPN).
3. **Unrecognised bytes are refused** with `refused` (no match), never forwarded to a default.
4. **Bounded detection** in bytes and time, with a default timeout that accounts for OpenVPN clients that wait (sslh recommends 5 s), ending with `detection_timeout`; the bytes read are forwarded unchanged. Pending detections count against Story 12.6 AC #5.
5. HTTP detected on a stream port is forwarded as bytes. Sharing 443 with Lorica's own HTTPS is the documented hairpin: HTTPS moves to another port, the stream on 443 sends TLS to Lorica's HTTPS listener with PROXY v2, and that listener accepts PROXY from loopback (Story 12.8). This is the one documented use of `allow_local_backend` towards a reserved port, and validation allows it only in that shape.

### Integration Verification

- IV1: SSH, a TLS client and a PostgreSQL client on one port each reach their own backend; random bytes are disconnected within the detection limit.
- IV2: The 443 hairpin serves HTTPS routes with the client's real address and SSH on the same port.

---

## Story 12.16: Live transfer across hot upgrades

As an operator,
I want an upgrade to hand my SSH sessions and UDP sessions to the new binary,
so that an upgrade stops being a maintenance window for them.

### Acceptance Criteria

1. **Transfer of TCP passthrough connections** (both sockets) and **UDP sessions** (session entry and backend socket) from the old generation to the new, which continues forwarding with no reconnect seen by either side.
2. **Quiesce with a bound.** A connection transfers only when no forwarded bytes are held in userspace; one that does not reach that point within `transfer_timeout` (default 1 s, configurable) drains under Story 12.11. Connections still in a PROXY-header, ClientHello or detection read are not eligible and drain.
3. **State that moves with the connection**: stream and backend ids, start time, byte counters, the client address taken from an accepted PROXY header, the detection result, total-duration timer, bandwidth budget. Cap permits re-register in the new generation's tables before the old ones are released, so caps are never exceeded across the handover.
4. **All-or-fallback per connection.** A transfer that fails at any step leaves the connection with the old generation, which drains it. No connection is served by both generations or by neither.
5. **UDP affinity across worker replacement**: a worker the supervisor replaces hands its sessions over the same way, so a session keeps one worker for its whole life.
6. **Transfer is an event, not an end.** The old generation writes a transfer event; the final access-log row carries cumulative counters from the start of the connection, so nothing is counted twice in logs or SLA.
7. **Preview and report**: before the upgrade, per stream, the connections eligible for transfer and those that will drain (TLS, pending reads); after it, the actual split.
8. TLS-terminated and TLS-originating streams always drain (D8).

### Integration Verification

- IV1: An SSH session through a passthrough stream stays interactive across a hot upgrade.
- IV2: A DNS client with a live UDP session keeps getting answers across a hot upgrade with no session re-created on the backend.
- IV3: A transfer forced to fail mid-way (test hook) leaves the connection draining on the old generation, and it completes normally.

---

## Story 12.17: Importing nginx `stream {}` configurations

As an operator migrating from nginx,
I want my `stream {}` blocks to become Lorica streams,
so that the migration costs me minutes, not an afternoon.

### Acceptance Criteria

1. The import wizard (`lorica-dashboard/frontend/src/components/nginx-wizard/`) turns each stream `server` into a Lorica stream and each stream `upstream` into backends, deduplicated against existing ones and respecting the UDP-only rule.
2. **Mapped directives**: `listen` (with `udp`, ranges, IPv6), `proxy_pass`, `proxy_connect_timeout`, `proxy_timeout`, `proxy_responses`, `proxy_requests`, `proxy_protocol`, `proxy_bind`, `proxy_socket_keepalive`, `proxy_ssl*`, `ssl_preread` with its `map` on `$ssl_preread_server_name`, `ssl_certificate` (matched against Lorica's certificates), `allow`/`deny`, `limit_conn`, `proxy_upload_rate`/`proxy_download_rate`, the upstream `server` parameters (`weight`, `max_fails`, `fail_timeout`, `backup`) and balancing directives (`hash`, `least_conn`, `random`).
3. **Every directive the importer does not map produces a diagnostic** with its line.
4. The preview step shows the streams and backends before anything is applied.
5. The equivalence table in `docs/streams.md` is generated from, or asserted against, the importer's directive map.

### Integration Verification

- IV1: A reference nginx configuration with TCP, UDP, SNI preread and PROXY protocol imports into streams that pass the L4 e2e scenarios unchanged.

---

## Story 12.18: Beyond-parity verification

As the maintainer,
I want Phase 2 proven like Phase 1,
so that the release ships measured, not hoped for.

### Acceptance Criteria

1. The L4 e2e phase gains every Integration Verification of Stories 12.13 to 12.17 as a named scenario.
2. The performance phase of Story 12.12 is re-run on the Phase 2 head with the same method and thresholds, plus TCP passthrough throughput during a hot upgrade with live transfer.
3. Every existing e2e profile passes unchanged.

### Integration Verification

- IV1: The local release run of the full e2e suite passes on the release candidate.

---

## Non-Functional Requirements

- **NFR1 - No HTTP regression.** Against the v1.9.0 binary in the same run (Story 12.12 AC #4): HTTP median throughput at least 0.95 x and p99 latency at most 1.05 x, and every existing e2e profile passes untouched.
- **NFR2 - Bounded everything.** Every per-connection buffer, session table, cap table, PROXY header read, ClientHello read, detection read, pending-connection count and port range has a hard ceiling with a documented default. No stream setting can make memory or fd use grow with attacker-controlled input, and the HTTP fd reserve cannot be consumed by streams.
- **NFR3 - Safe defaults.** A stream created with only a port and a backend is not an open relay: D6's bounds apply, PROXY accept is off, transparent mode is off, local backends are refused, detection refuses unknown bytes.
- **NFR4 - Performance.** The ratios of Story 12.12.
- **NFR5 - Nothing ends or is refused silently.** Every way a connection can end has a named reason, and every refusal and drop is counted.
- **NFR6 - Linux only**, as the rest of Lorica. Transparent mode depends on kernel features whose minimum versions are documented.

## Refused, in writing

These rows are not shipped by this epic, and not deferred either: each is a decision.

- **An outbound forward proxy** (CONNECT, egress). D1.
- **Stream mutations through automation tokens or MCP.** D9. Read only.
- **Live transfer of TLS-terminated and TLS-originating streams.** D8. They drain.
- **HAProxy-style generic stick tables.** Persistence is covered by consistent hashing on the source address, as nginx does; per-source counters by Story 12.6. A general key-value table with expressions is a configuration language of its own.
- **Hashing on an arbitrary key** (nginx `hash $variable`). Layer 4 has no variables beyond the addresses Lorica already hashes on.
- **Agent checks.** Only HAProxy has them; send/expect covers the need.
- **Arbitrary payload inspection** (HAProxy `tcp-request content` on payload, njs, Wasm). Story 12.15's closed matcher set covers the legitimate need; a programmable inspector is arbitrary execution on the data path.
- **Matchers beyond Story 12.15's set** (caddy-l4's DNS, QUIC, WireGuard, SOCKS, XMPP, regexp) **and protocol detection on UDP.** Each has no user in the matrix, and UDP detection on spoofable traffic adds an attack surface for no parity row.
- **QUIC routing** at layer 4. It belongs with HTTP/3 in 2.0.0.
- **UDP tunnelled over HTTP** (MASQUE, Envoy's UDP over HTTP). It belongs with HTTP/3 in 2.0.0.
- **Per-packet UDP load balancing** (Envoy). Sessions pinned to one backend are what the UDP services in scope need; per-packet balancing breaks them.
- **PROXY protocol accept on UDP streams.** Story 12.3 AC #9: the source is spoofable.
- **Unix domain sockets as backends.** Lorica's backends are network addresses, and a local socket target reopens the local-exposure problem of Story 12.3 AC #11.
- **DTLS termination.** No competitor ships it in open source at layer 4.
- **Provider auto-discovery** (Traefik). Streams come from the management API and the cluster, like routes.
- **WAF, bot protection and request capture on streams.** There is no request at layer 4. HTTP that needs them uses a route.
- **The automation `environment` resource for streams.** It is hostname-bound; a stream has no hostname.
