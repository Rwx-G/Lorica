# Layer-4 streams (TCP and UDP)

A **stream** is a TCP or UDP listener that forwards the byte stream, or
the datagrams, to backends Lorica chooses. It is Lorica's counterpart of
nginx `stream {}` and HAProxy `mode tcp`, and it ships in 1.11.0: TCP and
UDP proxying, TLS passthrough with SNI and ALPN routing, TLS termination
with Lorica's own certificates, upstream TLS and mTLS, PROXY protocol both
ways, per-source and per-stream caps and rates, and per-node targeting in
a fleet.

This page is the operator's reference: how a stream maps to an nginx or
HAProxy configuration, what each field means, how a node budgets its file
descriptors, how TLS, UDP and the protections behave, what a connection
ends with, and what an upgrade or a configuration change does to it.

What a stream is not:

- **Not a forward proxy.** Lorica listens on a port and connects to a
  backend it chose. Outbound CONNECT or egress proxying is a different
  product and is not part of Lorica.
- **Not a route.** A route is matched on hostname, path and headers; a
  stream has none of those. There is no WAF, bot challenge or request
  capture on a stream: there is no request. HTTP that needs them uses a
  route.
- **Not writable by a token.** Streams are created, changed and deleted
  through the management API and the dashboard only (see
  [Management plane only](#management-plane-only)).

What is **not in 1.11.0** and is planned for 1.12.0 (PRD
[Epic 12](prd/epic-12-v1.11.0.md), Phase 2): weighted power of two
choices, transparent proxying from the client's address, active health
checks for UDP backends, protocol detection on a shared TCP port with its
"silent client" matcher, the **port 443 hairpin** that shares 443 between
a stream and Lorica's own HTTPS listener (Story 12.15), live transfer of
connections across a hot upgrade (Story 12.16), and import of nginx
`stream {}` blocks into streams (Story 12.17; in 1.11.0 the importer
reports each stream `server` as not imported, with its line).

**How numbers are given here.** A range or a default is the value of a
named constant in the code, and the constant is the authority. Where a
table below quotes a 1.11.0 value next to its constant, it is for
comparison only. `lorica-api/openapi.yaml` publishes every stream field
with its range and default, and a contract test holds those to the
constants, so it is the place to read them.

---

## Concepts

- **Protocol.** `tcp` or `udp`, fixed per stream.
- **Listen address and ports.** One IP address per stream (IPv4 or IPv6,
  stored in RFC 5952 form) and one port or a range of ports
  (`port_first`, `port_last`), at most `STREAM_PORT_RANGE_MAX`
  (`lorica-config/src/models/stream.rs`). `::` binds dual-stack and takes
  every IPv4 and IPv6 address on its ports; any other IPv6 address binds
  IPv6 only, whatever `net.ipv6.bindv6only` says. `0.0.0.0` takes every
  IPv4 address. A hostname or an IPv4-mapped IPv6 address is refused.
- **Port ranges map port to port.** A range forwards listen port N to
  backend port N, so a range stream takes backends given without a port
  (a hostname, an IPv4 literal or a bracketed IPv6 literal). A portless
  backend serves range streams only.
- **Backends are shared with routes.** A stream links the same backend
  objects HTTP routes use, with one health state. Fields that only mean
  something to HTTP (`health_check_path`, `h2_upstream`, `tls_upstream`,
  `tls_sni`, `tls_skip_verify`) never apply to a stream; a stream's own
  upstream TLS lives on the stream.
- **UDP-only backends.** A backend linked by a UDP stream belongs to UDP
  streams only and keeps its active checks off; attaching it to a route
  or a TCP stream, or turning its checks on, is refused naming the
  stream. In 1.11.0 a UDP backend relies on passive failure detection.
- **Backups.** A link is primary or backup; a backup is a candidate only
  when no primary is. A stream with links has at least one primary.
- **Targeting.** A stream replicates across the fleet like a route and
  honours `node_selector` the same way, with one difference: a stream
  opens a port, so a node binds it only where it is meant to run. A
  standalone node binds every enabled stream, a follower the streams its
  selector targets, and the **control plane only the streams with an
  empty selector** (`binds_here` in `lorica-config/src/models/stream.rs`).
- **Disabled.** A disabled stream is stored, replicated and
  conflict-checked, and bound on no node. Its ports stay reserved, so
  enabling it never fails on a conflict.
- **Port conflicts are checked per node.** A write is refused (`409`,
  `stream_port_conflict`) when a port overlaps a reserved listener of a
  node that would bind it (management, HTTP, HTTPS, cluster, enrollment,
  automation) or another stream of the same protocol there, disabled
  ones included. Followers report their reserved ports in the heartbeat;
  a targeted follower that has not reported yet refuses the stream until
  it connects once. The node refuses at bind too.

---

## Coming from nginx or HAProxy

Every competitor value and directive below was read on 2026-11-18 from
the page linked beside it: the nginx documentation of the `stream`
modules as published that day, the HAProxy 3.4 configuration manual
(3.4.7), Envoy's `latest` reference (1.41.0-dev), Traefik 3.7 and the
caddy-l4 repository. A value the page does not state is written "not
documented"; nothing here is filled from memory. HAProxy's community
edition proxies TCP; general UDP load balancing is
[HAProxy Enterprise only][hx-udp] (the community edition listens on UDP
in `log-forward` sections only).

### Directive by directive

| nginx `stream` | HAProxy `mode tcp` | Lorica |
|---|---|---|
| [`listen`][n-listen] `<port>` | [`bind`][h-bind] `:<port>` | `listen_address`, `port_first` = `port_last` |
| [`listen`][n-listen] `<a>-<b>` (port ranges, 1.15.10) | [`bind`][h-bind] `:<a>-<b>` with a [`server`][h-server] given no port ("the same port the client connected to") | `port_first`..`port_last`, backends without a port |
| [`listen`][n-listen] `... udp` | Enterprise only | `protocol: udp` |
| [`listen`][n-listen] `... proxy_protocol` + [`set_real_ip_from`][n-realip] | [`accept-proxy`][h-accept-proxy] on `bind` | `proxy_protocol_accept` + `proxy_protocol_trusted_cidrs` |
| [`proxy_pass`][n-pass] to an [`upstream`][n-server] | [`default_backend`][h-default-backend], [`use_backend`][h-use-backend] | the stream's backend links |
| [`server`][n-server] `... weight` | [`weight`][h-weight] | the backend's `weight` |
| [`server`][n-server] `... backup` | [`backup`][h-backup] | `backup_backend_ids` |
| [`server`][n-server] `... max_conns` | [`maxconn`][h-server-maxconn] on a `server` (excess is queued) | `backend_max_active` (excess is refused, `backend_cap`) |
| [`server`][n-server] `... max_fails`, `fail_timeout` | [`observe layer4`][h-observe] | the circuit breaker, per (stream, backend) |
| [`server`][n-server] `... resolve` + [`resolver`][n-resolver] | [`resolvers`][h-resolvers] on a `server` | automatic for a backend given as a host name |
| default (weighted round robin) | [`balance roundrobin`][h-balance] | `round_robin` |
| [`hash $remote_addr consistent`][n-hash] | [`balance source`][h-balance] + [`hash-type consistent`][h-hash-type] | `consistent_hash` (on the client address) |
| [`least_conn`][n-least-conn] | [`balance leastconn`][h-balance] | `least_conn` |
| [`random`][n-random] | [`balance random`][h-balance] | `random` |
| [`least_time connect`][n-least-time] | no equivalent | `peak_ewma` (connect latency) |
| [`random two`][n-random] | [`balance random(2)`][h-balance] | not in 1.11.0 (weighted P2C is 1.12.0) |
| [`health_check`][n-hc] (commercial subscription) | [`option tcp-check`][h-tcp-check], [`tcp-check send`][h-tcp-check-send], [`tcp-check expect`][h-tcp-check-expect] | the backend's `health_check`, `tcp_template` or `tcp_send_expect` ([health checks](health-checks.md)) |
| [`proxy_connect_timeout`][n-connect] | [`timeout connect`][h-t-connect] | `connect_timeout_ms` |
| [`proxy_timeout`][n-timeout] | [`timeout client`][h-t-client] and [`timeout server`][h-t-server] (or [`timeout tunnel`][h-t-tunnel]) | `idle_timeout_s` |
| none | none | `total_timeout_s` |
| [`proxy_next_upstream`][n-next], [`proxy_next_upstream_tries`][n-tries] | [`retries`][h-retries], [`option redispatch`][h-redispatch] | `max_connect_attempts` |
| [`proxy_socket_keepalive`][n-ka] | [`option srvtcpka`][h-srvtcpka] | `backend_keepalive`, `backend_keepalive_idle_s` |
| none | [`on-marked-down shutdown-sessions`][h-on-marked-down] | `close_on_backend_down` |
| [`proxy_protocol`][n-pp] `on` / `v2` | [`send-proxy`][h-send-proxy] / [`send-proxy-v2`][h-send-proxy-v2] | `proxy_protocol_send` `v1` / `v2` |
| [`proxy_bind`][n-bind] | [`source`][h-source] | `source_addresses` (a list) |
| [`proxy_bind ... transparent`][n-bind] | [`source ... usesrc client`][h-source] | not in 1.11.0 (1.12.0) |
| [`proxy_upload_rate`][n-up], [`proxy_download_rate`][n-down] | the [bandwidth limitation filters][h-bwlim] | `upload_rate_bps`, `download_rate_bps` |
| [`proxy_buffer_size`][n-buf] | [`tune.bufsize`][h-bufsize] | `FORWARD_BUFFER_SIZE`, a constant |
| [`proxy_half_close`][n-half] | [`timeout client-fin`][h-t-client-fin] | half-close always forwarded |
| [`ssl_preread on`][n-preread] + a [`map`][n-map] on `$ssl_preread_server_name` | [`tcp-request inspect-delay`][h-inspect-delay] + [`req.ssl_sni`][h-ssl-sni] in `use_backend` rules | `tls_mode: passthrough` + `match_rules` |
| `$ssl_preread_alpn_protocols` | [`req.ssl_alpn`][h-ssl-alpn] | `alpn` on a match rule |
| [`preread_timeout`][n-preread-timeout] | [`tcp-request inspect-delay`][h-inspect-delay] | `clienthello_timeout_ms` |
| [`preread_buffer_size`][n-preread-buf] | [`tune.bufsize`][h-bufsize] | `CLIENTHELLO_MAX_LEN`, a constant |
| [`listen`][n-listen] `... ssl` + [`ssl_certificate`][n-ssl-cert] | [`ssl`][h-bind-ssl] + [`crt`][h-bind-crt] on `bind` | `tls_mode: terminate` + `tls_terminate.certificate_ids` |
| [`ssl_handshake_timeout`][n-hs-timeout] | [`timeout client`][h-t-client] | `clienthello_timeout_ms`, which covers the handshake |
| [`ssl_verify_client`][n-verify-client] + [`ssl_client_certificate`][n-client-cert] | [`verify`][h-bind-verify] + [`ca-file`][h-bind-ca-file] on `bind` | `tls_terminate.client_auth` |
| [`proxy_ssl`][n-pssl], [`proxy_ssl_verify`][n-pssl-verify], [`proxy_ssl_trusted_certificate`][n-pssl-trusted] | [`ssl`][h-srv-ssl], [`verify`][h-srv-verify], [`ca-file`][h-srv-ca-file] on a `server` | `upstream_tls`, `ca_cert_pem`, `skip_verify` |
| [`proxy_ssl_server_name`][n-pssl-sn], [`proxy_ssl_name`][n-pssl-name] | [`sni`][h-srv-sni] on a `server` | `upstream_tls.server_name` |
| [`proxy_ssl_certificate`][n-pssl-cert] | [`crt`][h-srv-crt] on a `server` | `upstream_tls.client_certificate_id` |
| [`allow`][n-allow], [`deny`][n-deny] | [`tcp-request connection`][h-tcp-req-conn] `reject` on a `src` ACL | `source_allow_cidrs`, `source_deny_cidrs` |
| [`geoip_country`][n-geoip] | not documented | `geoip` |
| [`limit_conn`][n-limit-conn] | [`src_conn_cur`][h-src-conn-cur] tracked in a stick table | `source_max_connections`, `udp.source_session_cap` |
| no new-connection rate limit in the stream modules ([index][n-index]) | [`rate-limit sessions`][h-rate-limit], [`src_conn_rate`][h-src-conn-rate] | `open_rate`, `source_open_rate` |
| none | [`maxconn`][h-fe-maxconn] on a frontend | `max_connections` (TCP), `udp.max_sessions` (UDP) |
| [`proxy_responses`][n-responses] | Enterprise only | `udp.responses_per_request` |
| [`proxy_requests`][n-requests] | Enterprise only | `udp.requests_per_session` |
| [`access_log`][n-log] | [`option tcplog`][h-tcplog] | the stream access log, always on (see [Observability](#observability)) |

What has no row on purpose: hashing on an arbitrary key (`hash
$variable`; layer 4 has no variables beyond the addresses Lorica already
hashes on), HAProxy's generic stick tables, agent checks and payload
inspection (`tcp-request content` on payload bytes). These are refused
in writing in the PRD, not deferred.

### Defaults compared

Lorica's value is the constant's in 1.11.0 (the constant is the
authority); every other value is the documented default, with the page
it was read from.

| Setting | Lorica | nginx `stream` | HAProxy `mode tcp` | Envoy | Traefik |
|---|---|---|---|---|---|
| Connect, per attempt | 5 s (`DEFAULT_CONNECT_TIMEOUT_MS`) | 60 s ([source][n-connect]) | none, infinite, with a startup warning ([source][h-t-connect]) | 5 s, cluster `connect_timeout` ([source][e-connect]) | 30 s, `dialTimeout` ([source][t-dial]) |
| Idle, TCP | 600 s (`DEFAULT_TCP_IDLE_TIMEOUT_S`) | 10 min ([source][n-timeout]) | none, infinite, with a startup warning ([source][h-t-client]) | 1 h ([source][e-idle]) | not documented for TCP routers ([source][t-entry]) |
| Total duration | none | none | none | none ([source][e-duration]) | not documented |
| Connect attempts | 3, the first included (`DEFAULT_MAX_CONNECT_ATTEMPTS`) | every server (`proxy_next_upstream_tries 0`, no limit) ([source][n-tries]) | not documented in the `retries` section ([source][h-retries]) | 1 ([source][e-attempts]) | not documented |
| Backend TCP keepalive | on, first probe after 60 s (`DEFAULT_BACKEND_KEEPALIVE`, `DEFAULT_BACKEND_KEEPALIVE_IDLE_S`) | off ([source][n-ka]) | not documented ([source][h-srvtcpka]) | not documented | 15 s, `dialKeepAlive` ([source][t-keepalive]) |
| ClientHello wait | 5 s (`DEFAULT_CLIENTHELLO_TIMEOUT_MS`) | 30 s, `preread_timeout` ([source][n-preread-timeout]) | no wait unless `inspect-delay` is set ([source][h-inspect-delay]) | 15 s, `listener_filters_timeout` ([source][e-lf-timeout]) | not documented |
| ClientHello size | 16 KiB (`CLIENTHELLO_MAX_LEN`) | 16k, `preread_buffer_size` ([source][n-preread-buf]) | 16384, `tune.bufsize` ([source][h-bufsize]) | 64 KiB, `tls_inspector` ([source][e-tls-inspector]) | not documented |
| PROXY header wait (accept) | 5 s (`HEADER_READ_TIMEOUT`) | 30 s, `proxy_protocol_timeout` ([source][n-pp-timeout]) | not documented | not documented | not documented |
| Forwarding buffer | 16 KiB per direction (`FORWARD_BUFFER_SIZE`) | 16k ([source][n-buf]) | 16384 ([source][h-bufsize]) | not documented | not documented |
| Idle, UDP | 10 s (`DEFAULT_UDP_IDLE_TIMEOUT_S`) | 10 min, `proxy_timeout` ([source][n-timeout]) | Enterprise only: 10 s on the client side, `timeout client` of a `udp-lb` section; no default stated for `timeout server` ([source][hx-udp-ref]) | 1 min ([source][e-udp-idle]) | 3 s ([source][t-udp]) |
| UDP responses per request | 1 (`DEFAULT_RESPONSES_PER_REQUEST`) | unlimited unless set ([source][n-responses]) | not documented | not documented | not documented |
| UDP requests per session | 64 (`DEFAULT_REQUESTS_PER_SESSION`) | 0, no limit ([source][n-requests]) | not documented | not documented | not documented |
| TCP connections per source | none, `source_max_connections` off | none, `limit_conn` applies only where it is configured ([source][n-limit-conn]) | none, `src_conn_cur` counts only in a stick table a rule tracks ([source][h-src-conn-cur]) | not documented | not documented |

caddy-l4, for UDP: 30 s idle ([source][c-servers]). nginx's `least_time`
page states it is open source since 1.31.0 while its `random` section
still calls it commercial ([source][n-least-time]); the table above does
not rely on it.

**Where Lorica differs on purpose:**

- **Connect 5 s, in milliseconds.** A failover costs at most `attempts x
  connect timeout`; nginx's 60 s would hold a client three minutes
  before `connect_failed`. Milliseconds, because a LAN backend answers a
  SYN well under a second.
- **Backend keepalive is on**, where nginx and HAProxy leave it off: a
  stream may idle for 600 s through a cloud NAT gateway or a stateful
  firewall that forgets the mapping, and a backend host that died
  without a FIN is otherwise noticed only at the idle timeout. The cost
  is a probe every `BACKEND_KEEPALIVE_INTERVAL` on each idle backend
  connection past the idle time. Client-side keepalive is not set.
- **Idle 600 s on TCP** is nginx's value, so a migration keeps its
  behaviour. It is not unlimited: an idle connection holds two fds and
  a cap slot.
- **UDP idle 10 s, one response per request, 64 requests per session**:
  the bounds of D6 (see [UDP streams](#udp-streams)). nginx bounds
  neither by default.
- **ClientHello 5 s**: a client's first flight, sent the moment TCP
  completes; 5 s allows several retransmissions, and every pending
  second is a slot of the pending cap an attacker would hold. The range
  (`CLIENTHELLO_TIMEOUT_MS_RANGE`) keeps a client on a lossy link able to
  retransmit, and bounds how long a pending connection holds its fd and
  its read buffer.

[n-listen]: https://nginx.org/en/docs/stream/ngx_stream_core_module.html#listen
[n-preread-timeout]: https://nginx.org/en/docs/stream/ngx_stream_core_module.html#preread_timeout
[n-preread-buf]: https://nginx.org/en/docs/stream/ngx_stream_core_module.html#preread_buffer_size
[n-pp-timeout]: https://nginx.org/en/docs/stream/ngx_stream_core_module.html#proxy_protocol_timeout
[n-realip]: https://nginx.org/en/docs/stream/ngx_stream_realip_module.html#set_real_ip_from
[n-pass]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_pass
[n-connect]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_connect_timeout
[n-timeout]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_timeout
[n-next]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream
[n-tries]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_next_upstream_tries
[n-ka]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_socket_keepalive
[n-pp]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_protocol
[n-bind]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_bind
[n-up]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_upload_rate
[n-down]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_download_rate
[n-buf]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_buffer_size
[n-half]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_half_close
[n-responses]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_responses
[n-requests]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_requests
[n-pssl]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl
[n-pssl-verify]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_verify
[n-pssl-trusted]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_trusted_certificate
[n-pssl-sn]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_server_name
[n-pssl-name]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_name
[n-pssl-cert]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_ssl_certificate
[n-server]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#server
[n-hash]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#hash
[n-least-conn]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#least_conn
[n-random]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#random
[n-least-time]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#least_time
[n-resolver]: https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#resolver
[n-hc]: https://nginx.org/en/docs/stream/ngx_stream_upstream_hc_module.html#health_check
[n-preread]: https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html#ssl_preread
[n-map]: https://nginx.org/en/docs/stream/ngx_stream_map_module.html#map
[n-ssl-cert]: https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_certificate
[n-hs-timeout]: https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_handshake_timeout
[n-verify-client]: https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_verify_client
[n-client-cert]: https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html#ssl_client_certificate
[n-allow]: https://nginx.org/en/docs/stream/ngx_stream_access_module.html#allow
[n-deny]: https://nginx.org/en/docs/stream/ngx_stream_access_module.html#deny
[n-geoip]: https://nginx.org/en/docs/stream/ngx_stream_geoip_module.html#geoip_country
[n-limit-conn]: https://nginx.org/en/docs/stream/ngx_stream_limit_conn_module.html#limit_conn
[n-log]: https://nginx.org/en/docs/stream/ngx_stream_log_module.html#access_log
[n-index]: https://nginx.org/en/docs/
[h-bind]: https://docs.haproxy.org/3.4/configuration.html#4.2-bind
[h-server]: https://docs.haproxy.org/3.4/configuration.html#4.2-server
[h-accept-proxy]: https://docs.haproxy.org/3.4/configuration.html#5.1-accept-proxy
[h-default-backend]: https://docs.haproxy.org/3.4/configuration.html#4.2-default_backend
[h-use-backend]: https://docs.haproxy.org/3.4/configuration.html#4.2-use_backend
[h-weight]: https://docs.haproxy.org/3.4/configuration.html#5.2-weight
[h-backup]: https://docs.haproxy.org/3.4/configuration.html#5.2-backup
[h-server-maxconn]: https://docs.haproxy.org/3.4/configuration.html#5.2-maxconn
[h-fe-maxconn]: https://docs.haproxy.org/3.4/configuration.html#4.2-maxconn
[h-observe]: https://docs.haproxy.org/3.4/configuration.html#5.2-observe
[h-resolvers]: https://docs.haproxy.org/3.4/configuration.html#5.2-resolvers
[h-balance]: https://docs.haproxy.org/3.4/configuration.html#4.2-balance
[h-hash-type]: https://docs.haproxy.org/3.4/configuration.html#4.2-hash-type
[h-tcp-check]: https://docs.haproxy.org/3.4/configuration.html#4.2-option%20tcp-check
[h-tcp-check-send]: https://docs.haproxy.org/3.4/configuration.html#4.2-tcp-check%20send
[h-tcp-check-expect]: https://docs.haproxy.org/3.4/configuration.html#4.2-tcp-check%20expect
[h-t-connect]: https://docs.haproxy.org/3.4/configuration.html#4.2-timeout%20connect
[h-t-client]: https://docs.haproxy.org/3.4/configuration.html#4.2-timeout%20client
[h-t-server]: https://docs.haproxy.org/3.4/configuration.html#4.2-timeout%20server
[h-t-tunnel]: https://docs.haproxy.org/3.4/configuration.html#4.2-timeout%20tunnel
[h-t-client-fin]: https://docs.haproxy.org/3.4/configuration.html#4.2-timeout%20client-fin
[h-retries]: https://docs.haproxy.org/3.4/configuration.html#4.2-retries
[h-redispatch]: https://docs.haproxy.org/3.4/configuration.html#4.2-option%20redispatch
[h-srvtcpka]: https://docs.haproxy.org/3.4/configuration.html#4.2-option%20srvtcpka
[h-on-marked-down]: https://docs.haproxy.org/3.4/configuration.html#5.2-on-marked-down
[h-send-proxy]: https://docs.haproxy.org/3.4/configuration.html#5.2-send-proxy
[h-send-proxy-v2]: https://docs.haproxy.org/3.4/configuration.html#5.2-send-proxy-v2
[h-source]: https://docs.haproxy.org/3.4/configuration.html#4.2-source
[h-bwlim]: https://docs.haproxy.org/3.4/configuration.html#9.7
[h-bufsize]: https://docs.haproxy.org/3.4/configuration.html#3.2-tune.bufsize
[h-inspect-delay]: https://docs.haproxy.org/3.4/configuration.html#4.2-tcp-request%20inspect-delay
[h-ssl-sni]: https://docs.haproxy.org/3.4/configuration.html#7.3.5-req.ssl_sni
[h-ssl-alpn]: https://docs.haproxy.org/3.4/configuration.html#7.3.5-req.ssl_alpn
[h-bind-ssl]: https://docs.haproxy.org/3.4/configuration.html#5.1-ssl
[h-bind-crt]: https://docs.haproxy.org/3.4/configuration.html#5.1-crt
[h-bind-verify]: https://docs.haproxy.org/3.4/configuration.html#5.1-verify
[h-bind-ca-file]: https://docs.haproxy.org/3.4/configuration.html#5.1-ca-file
[h-srv-ssl]: https://docs.haproxy.org/3.4/configuration.html#5.2-ssl
[h-srv-verify]: https://docs.haproxy.org/3.4/configuration.html#5.2-verify
[h-srv-ca-file]: https://docs.haproxy.org/3.4/configuration.html#5.2-ca-file
[h-srv-sni]: https://docs.haproxy.org/3.4/configuration.html#5.2-sni
[h-srv-crt]: https://docs.haproxy.org/3.4/configuration.html#5.2-crt
[h-tcp-req-conn]: https://docs.haproxy.org/3.4/configuration.html#4.2-tcp-request%20connection
[h-src-conn-cur]: https://docs.haproxy.org/3.4/configuration.html#7.3.3-src_conn_cur
[h-src-conn-rate]: https://docs.haproxy.org/3.4/configuration.html#7.3.3-src_conn_rate
[h-rate-limit]: https://docs.haproxy.org/3.4/configuration.html#4.2-rate-limit%20sessions
[h-tcplog]: https://docs.haproxy.org/3.4/configuration.html#4.2-option%20tcplog
[hx-udp]: https://www.haproxy.com/solutions/udp-load-balancing
[hx-udp-ref]: https://www.haproxy.com/documentation/haproxy-enterprise/enterprise-modules/udp-load-balancing/reference/
[e-connect]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-field-config-cluster-v3-cluster-connect-timeout
[e-idle]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto#envoy-v3-api-field-extensions-filters-network-tcp-proxy-v3-tcpproxy-idle-timeout
[e-attempts]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto#envoy-v3-api-field-extensions-filters-network-tcp-proxy-v3-tcpproxy-max-connect-attempts
[e-duration]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto#envoy-v3-api-field-extensions-filters-network-tcp-proxy-v3-tcpproxy-max-downstream-connection-duration
[e-lf-timeout]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto#envoy-v3-api-field-config-listener-v3-listener-listener-filters-timeout
[e-tls-inspector]: https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/tls_inspector
[e-udp-idle]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/udp/udp_proxy/v3/udp_proxy.proto#envoy-v3-api-field-extensions-filters-udp-udp-proxy-v3-udpproxyconfig-idle-timeout
[t-dial]: https://doc.traefik.io/traefik/reference/routing-configuration/tcp/serverstransport/#opt-serverstransport-dialTimeout
[t-keepalive]: https://doc.traefik.io/traefik/reference/routing-configuration/tcp/serverstransport/#opt-serverstransport-dialKeepAlive
[t-entry]: https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/
[t-udp]: https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/#opt-udp-timeout
[c-servers]: https://github.com/mholt/caddy-l4/blob/master/docs/servers.md

---

## The fields, per protocol and TLS mode

Each field's type, range and default is in `lorica-api/openapi.yaml`
(`StreamResponse`, `StreamUdpSettings`, `StreamMatchRule`,
`StreamTlsTerminate`, `StreamUpstreamTls`); the constants are on `Stream`
and `UdpSettings` in `lorica-config/src/models/stream.rs`. Which protocol
takes which TCP-engine field, and why a UDP stream must leave the others
at their default, is decided in one place, `TCP_ENGINE_FIELDS` in the
same file: a UDP stream sending a non-default value of a TCP-only field
is refused with `422` naming the field and the reason.

"Per node" means counted across the node's workers: a stream placed on
three nodes admits up to the value on each. "Per worker" means each
worker process counts on its own.

### General

| Field | Applies to | Scope | Notes |
|---|---|---|---|
| `name` | both | fleet | Unique, the `node_selector` alphabet, up to `STREAM_NAME_MAX_LEN`. Logs, metrics and errors name the stream by it. |
| `group_name` | both | | Free label, as on a route. |
| `protocol` | both | | `tcp` or `udp`. |
| `enabled` | both | | Disabled: replicated, bound nowhere, ports kept. |
| `listen_address`, `port_first`, `port_last` | both | per node | See [Concepts](#concepts). |
| `node_selector` | both | fleet | Empty is fleet-wide, the control plane included; a non-empty selector is never bound on the control plane. |
| `backend_ids`, `backup_backend_ids` | both | | Empty on a TLS stream, whose links are per rule. |
| `backend_max_active` | both | per node | The cap of each capped link (nginx `max_conns`); HTTP routes sharing the backend do not count against it. Range `Stream::MAX_ACTIVE_RANGE`. |

### The engine (Story 12.3)

| Field | Applies to | Scope | Default and range |
|---|---|---|---|
| `load_balancing` | both (`peak_ewma` TCP only) | per worker for `least_conn`, `peak_ewma` | `round_robin` |
| `connect_timeout_ms` | TCP | per attempt | `DEFAULT_CONNECT_TIMEOUT_MS`, `CONNECT_TIMEOUT_MS_RANGE` |
| `idle_timeout_s` | both | per connection or session | TCP: `DEFAULT_TCP_IDLE_TIMEOUT_S`, `TCP_IDLE_TIMEOUT_S_RANGE`; UDP: `DEFAULT_UDP_IDLE_TIMEOUT_S`, `UDP_IDLE_TIMEOUT_S_RANGE` |
| `total_timeout_s` | both | per connection or session | off; `TOTAL_TIMEOUT_S_RANGE` |
| `max_connect_attempts` | TCP | per connection | `DEFAULT_MAX_CONNECT_ATTEMPTS`, `MAX_CONNECT_ATTEMPTS_RANGE` |
| `backend_keepalive`, `backend_keepalive_idle_s` | TCP | per backend socket | on; `DEFAULT_BACKEND_KEEPALIVE_IDLE_S`, `BACKEND_KEEPALIVE_IDLE_S_RANGE` |
| `close_on_backend_down` | both | | off |
| `proxy_protocol_send` | both (`v1` TCP only) | | `off` |
| `proxy_protocol_accept`, `proxy_protocol_trusted_cidrs` | TCP only, for good | | off; at most `PROXY_PROTOCOL_TRUSTED_CIDRS_MAX` entries |
| `source_addresses` | both | per attempt (TCP), per session (UDP) | empty; at most `SOURCE_ADDRESSES_MAX` |
| `allow_local_backend` | both | | off |
| `upload_rate_bps`, `download_rate_bps` | TCP | per connection | off; `RATE_BPS_RANGE` |
| `max_connections` | TCP | per node | `DEFAULT_MAX_CONNECTIONS`, `MAX_CONNECTIONS_RANGE` |
| `source_max_connections` | TCP | per node, per source | off (bounded by `max_connections`); `SOURCE_MAX_CONNECTIONS_RANGE` |
| `max_pending_connections` | TCP | per node | `DEFAULT_MAX_PENDING_CONNECTIONS`, `MAX_PENDING_CONNECTIONS_RANGE` |

### Source controls (Story 12.6), both protocols

| Field | Scope | Default and range |
|---|---|---|
| `source_allow_cidrs`, `source_deny_cidrs` | per stream | empty; at most `SOURCE_CIDRS_MAX` each, no `/0` |
| `geoip` | per stream | none |
| `source_open_rate`, `open_rate` | per node | off; `OPEN_RATE_RANGE`, one second of burst |

### UDP (Story 12.5), the `udp` object

Present on every UDP stream and `null` on every TCP stream. Defaults and
ranges are the `DEFAULT_*` and `*_RANGE` constants of `UdpSettings`.

| Field | Scope | What it bounds |
|---|---|---|
| `max_sessions` | per node, exact | The stream's share of the node's session ceiling. |
| `source_session_cap` | per node, per source key | `null` means `DEFAULT_SOURCE_SESSION_CAP`; see [the listen-address rule](#the-listen-address-rule). |
| `requests_per_session` | per session | Client datagrams before the session is retired; `null` for no bound. |
| `responses_per_request` | per session | Backend datagrams forwarded per client datagram; 0 for one-way protocols. |
| `response_bytes_ratio` | per session | Response bytes forwarded per request byte. |
| `unbounded_responses` | | Lifts the two response bounds; a permanent badge. |
| `source_datagram_rate`, `source_byte_rate` | per node, per source key | Client datagrams and bytes per second, one second of burst. |
| `max_datagram_bytes` | both directions | Larger datagrams are dropped and counted. |

### TLS (Story 12.4), TCP only

| Field | `none` | `passthrough` | `terminate` |
|---|---|---|---|
| `tls_mode` | default | | |
| `match_rules` | refused | at least one | at least one |
| `no_sni_acknowledged` | refused | with a `no_sni` rule and no source allowlist | same |
| `clienthello_timeout_ms` | refused | optional, `CLIENTHELLO_TIMEOUT_MS_RANGE`, default `DEFAULT_CLIENTHELLO_TIMEOUT_MS` | same |
| `tls_terminate` | refused | refused | required |
| `upstream_tls` | optional (origination) | refused | optional (re-encryption) |
| `drains_on_upgrade` | read-only: true when `upstream_tls` is set | false | true |

A field the chosen mode does not take is refused with `422` naming the
field and the mode, never ignored. A UDP stream refuses every TLS field:
there is no DTLS.

---

## Listeners and binding

Creating or enabling a stream binds its ports on the nodes that hold it,
on the running process, without a restart; deleting or disabling it
releases them. The supervisor binds, so ports below 1024 work under the
packaged unit (its ambient `CAP_NET_BIND_SERVICE` is never dropped), and
hands the sockets to its workers over a per-worker control channel. A TCP
port is one socket shared by every worker; a UDP port is one socket per
worker in a `SO_REUSEPORT` group, so the kernel keeps a client on one
worker. The same holds in single-process mode.

A range binds all its ports or none: if one fails, the ports already
bound are closed and the failing port is reported.

**Bind states** (`StreamBindState` in `openapi.yaml`, per stream and per
node):

| State | Meaning |
|---|---|
| `pending` | Wanted here, not bound yet. |
| `bound` | The node holds the sockets; `workers_serving` of `workers` acknowledged them. |
| `failed` | The last attempt failed, with `kind`, the OS error's text, the port and `since`. |

The failure kinds are `StreamBindFailureKind` in `openapi.yaml`. A port
held by another process (`address_in_use`) or an address not on the node
(`address_not_available`) is retried every 10 s; the others
(`permission_denied`, `reserved_port`, `fd_budget`, `source_ports`,
`other`) wait for the next configuration change. A failed bind is a
configuration error, not a crash: every other listener keeps serving. It
is reported on the stream in the API and the dashboard (a "failed bind"
badge naming each node), in the audit chain (`stream.bind_failed`, once
per entry into `failed`) and as a `stream_bind_failed` notification, once
per failure, never per retry. Every bind and release is audited per node
(`stream.bind`, `stream.release` with its cause), and the enrollment
preview lists the ports a node will open.

Where to read the state: `bind` on every stream read (this node), `GET
/api/v1/streams/status` (every stream; on a control plane, per active
node), the fleet view's `stream_plane`, and `lorica_stream_listener_up`.

---

## The fd budget

Every stream connection and session holds file descriptors, and a
process has a fixed number of them (`RLIMIT_NOFILE`, `LimitNOFILE=65536`
in the packaged unit). The stream plane works inside a budget that can
never eat into what HTTP needs. From the process's soft limit `L`
(`lorica-stream/src/budget.rs`):

- `B` = `BASE_RESERVE`: the process's own plumbing;
- `H` = `L / 2`: the **HTTP reserve**, never usable by streams;
- `S` = `L - B - H`: the stream budget of one process.

At the packaged limit, `S` is 31,744 (a test,
`packaged_limit_gives_the_documented_figures`, holds the figure).

Four constraints hold for the streams a node binds:

1. Their listening sockets (one per port) stay within the
   `stream_listen_socket_cap` setting (per node; default and maximum are
   `GlobalSettings::DEFAULT_STREAM_LISTEN_SOCKET_CAP` and
   `STREAM_LISTEN_SOCKET_CAP_MAX`).
2. In **any one worker**, listening sockets plus what each stream may
   hold at its cap stay within `S`. Caps are per node, so the worst case
   puts every connection on one worker, and that is what is counted: a
   TCP connection holds two fds (`TCP_FDS_PER_CONNECTION`), a UDP
   session one (`UDP_FDS_PER_SESSION`, its connected upstream socket).
3. In the **supervisor**, which keeps one socket per TCP port, one per
   worker per UDP port and one shared-memory region per UDP stream,
   `TCP ports + UDP ports x workers + UDP streams` stays within `S`.
4. Per **source pool**, the UDP sessions leaving from it stay within
   `U`, the usable ephemeral ports of one source address (see below).
   TCP connections do not count here.

A stream write that would break one is refused with `422`,
`error.code` `stream_fd_budget`, the message naming the node and the
constraint (`listen_socket_cap`, `worker_fds`, `supervisor_fds`,
`source_ports`). On a control plane every targeted node is checked from
the fd limit, worker count and usable ports its heartbeat reported; a
targeted node that has not reported is named in the answer's `warnings`
and refuses at bind (`fd_budget` or `source_ports`) if the stream does not
fit. A write that only lowers the demand always passes, even on a node
already over its budget.

### The budget view

`GET /api/v1/streams/budget` (Operator and above; the dashboard's System
page shows it as the stream budget panel) answers, per node: `fd_limit`,
`base_reserve`, `http_reserve`, `stream_budget`, the worker count, the
listening sockets used against the cap, what one worker and the
supervisor commit, and each stream's share: its listening sockets, its
`ceiling` (`max_connections` or `udp.max_sessions`), the fds per unit and
the fds it commits. On a control plane it lists the control plane, then
every reporting enrolled node by name. This is where the contention
between streams shows before it shows as refused sessions.

### The UDP session ceiling, and several UDP streams on one node

Each UDP session holds one connected upstream socket, hence one fd and
one ephemeral source port. The node's **session ceiling** is the smaller
of what `S` leaves after every other commitment and `U` times the number
of source pools, reported as `session_ceiling` with
`session_ceiling_bound_by` (`fd_budget` or `source_ports`).

`U` is the size of `net.ipv4.ip_local_port_range` (which governs IPv6
too), less the ports of `net.ipv4.ip_local_reserved_ports` inside it,
less `EPHEMERAL_PORT_MARGIN` left to the host's own clients
(`usable_udp_source_ports` in `lorica-worker/src/stream_sockets.rs`). It
is read at every reconcile, so a sysctl change is seen without a
restart. At the kernel's default range, `U` is 27,208.

Several UDP streams share that ceiling. **Each stream's share is its own
`udp.max_sessions`**, never "an equal part": a share that moved when
another stream was added would change streams nobody edited. The shares
cannot add up past the ceiling, because constraints 2 and 4 refuse the
write that would. The budget view's `udp_sessions_committed`,
`source_pools` (the `default` pool for UDP streams without
`source_addresses`, then one per address, each with `committed` and
`usable`) and per-stream `ceiling` show the split.

**Six default UDP streams fit at the packaged `LimitNOFILE`; the seventh
is refused.** With the default `max_sessions`, six streams commit 24,576
sessions of the default pool's 27,208 ports; a seventh would need 28,672
and is refused on `source_ports`, although its fds alone would still fit
in `S`. The arithmetic is a test,
`six_default_udp_streams_fit_and_the_seventh_breaks_the_source_ports` in
`lorica-stream/src/budget.rs`. Giving the seventh two
`source_addresses` puts its sessions in two pools of their own and it
fits (`a_seventh_stream_with_two_source_addresses_fits_in_their_pools`).

A node whose range is narrowed or whose fd limit is lowered under bound
streams does not unbind them: the view flags it `over_ceiling`, and every
write that raises the demand is refused until it fits again.

### Raising capacity

For high session or connection counts there are three levers. The
drop-in and the sysctl file are in the hardening guide,
[Stream capacity: descriptors and source ports](security/hardening-guide.md#stream-capacity-descriptors-and-source-ports).

1. **Raise `LimitNOFILE`.** It grows `S` and the HTTP reserve together,
   since `H` is half the limit. The limit is read at start, so it takes
   a restart; a hot upgrade inherits the old process's limit.
2. **Widen `net.ipv4.ip_local_port_range`**, or reserve fewer ports in
   `ip_local_reserved_ports`. It grows `U` for every pool and applies
   without a restart.
3. **Add `source_addresses`** to the UDP streams that need more than one
   address's ports: each address is a pool of its own, and a stream's
   sessions spread evenly over its addresses. The addresses must be
   assigned to the node's interfaces.

Raising `max_connections` or `udp.max_sessions` past what these allow is
refused, with the constraint named, rather than failing later at accept.

---

## TCP streams

### The life of a connection

One task per accepted connection, in five phases
(`lorica-stream/src/tcp/engine.rs`):

1. **Admit.** The peer address is canonicalised (a dual-stack `::`
   listener reports IPv4 clients as IPv4-mapped), then judged by the
   filters, rates and caps of [Protecting a stream](#protecting-a-stream),
   before a byte is read.
2. **Pre-forwarding reads**, each bounded in bytes and time and counted
   from accept: a trusted peer's PROXY header, then on a TLS stream the
   ClientHello. Bytes read past what a step needs are kept and replayed
   to the backend first, unchanged.
3. **Connect.** A candidate is chosen, checked (local address, source
   family, circuit breaker), resolved, the source address bound, then
   connected within `connect_timeout_ms`. Then `TCP_NODELAY` and keepalive
   are set, the PROXY header is written to the backend, then upstream TLS
   when set, then the replayed bytes.
4. **Forward** until both directions are closed, a timer fires, or a
   drain closes the connection.
5. **End.** One end reason, one access-log row, the counters.

A drain (`config_removed`, `node_shutdown`, `drained_by_upgrade`) can end
a connection in any of phases 2 to 4. Lorica closes with a FIN on both
sides (`shutdown`), never a reset.

### Balancing

`load_balancing` takes the algorithms routes use, as they behave for
routes:

- `round_robin` (weighted) and `consistent_hash` (weighted, on the
  client address, `lorica-ketama`) honour the backends' `weight`; the
  others ignore it. A stream hashes over resolved `ip:port`, so a
  backend given as a host name takes part.
- `random` is uniform.
- `least_conn` counts open connections, and `peak_ewma` is fed backend
  connect latency; **both are counted per worker process**, not per
  node.

A candidate is a linked backend whose health is not `down`, whose
lifecycle is normal (not draining or closed), whose name resolves, whose
address is not refused as local, and that this connection has not tried
yet; `degraded` and not-yet-probed backends are candidates. On a TLS
stream the choice is made among the matched rule's backends.

**Backups** are candidates only when no primary is.

### Passive failure detection and retries

The circuit breaker HTTP routes use (`CircuitBreaker`,
`lorica/src/proxy_wiring/lb.rs`) watches each (stream, backend) pair,
with the same thresholds, coordinated across workers. A refused,
unreachable, reset or timed-out connect counts against it; a refusal
Lorica makes itself (a local address, a name that does not resolve, a
source address that cannot be bound) does not. While the breaker is
open the backend is skipped (`lorica_stream_breaker_denied_total`).
Active health checks feed the same backend state as for routes
([health checks](health-checks.md)); a confirmed health change reaches every
worker's table at once.

**On a range stream, one breaker covers every port of a backend.** The
breaker is keyed by the stream and the backend as configured, and a
range stream's backends carry no port, so the failures of all its ports
count against one circuit, as a route's do across paths (HAProxy's
`observe layer4` also judges a server, not a port). The blast radius:
a backend whose service is down on one port of the range opens the
circuit for every port, so the healthy ports of that backend are
skipped too while it is open. A half-open probe then lands on whichever
port the next connection asks for; a healthy port closes the circuit
and the dead port opens it again, so the backend flaps for as long as
that port stays down. Keep the ports of a range served by the same
process on each backend, or split a port whose service can fail on its
own into a stream of its own. Keying per port would grow the
supervisor's breaker registry, which never prunes, by one entry per
port and backend (Story 12.3 D-g).

A failed connect moves to another backend at once, up to
`max_connect_attempts` attempts in all, each to a backend not yet tried.
A connection is **never retried once a byte has flowed**: the client's
first bytes wait in the kernel's receive buffer until a backend is
connected, which is what makes a retry safe. The connection ends
`no_healthy_backend` when no attempt could be made, `connect_failed`
when every attempt failed. A client waits at most `max_connect_attempts
x connect_timeout_ms` before that.

### Timeouts and keepalive

- `connect_timeout_ms` bounds each attempt (on a stream with upstream
  TLS, the TCP connect and the handshake together).
- `idle_timeout_s` closes a connection with no forwarded byte in either
  direction; it ends `idle_timeout`. One timer per connection is set to
  the last activity plus the timeout and set again when it finds the
  connection active since, so it fires at its value and an idle
  connection wakes once per idle window, with no timer set per read.
- `total_timeout_s`, off by default, runs from accept; it ends
  `total_timeout`.
- `backend_keepalive` sets TCP keepalive on the backend socket: the first
  probe after `backend_keepalive_idle_s` idle, then every
  `BACKEND_KEEPALIVE_INTERVAL`, `BACKEND_KEEPALIVE_PROBES` probes
  (`lorica-stream/src/tcp/connect.rs`). The reason it is on by default
  is under [Defaults compared](#defaults-compared).

**When a backend goes down**, it stops receiving new connections and
established ones are left alone, unless the stream sets
`close_on_backend_down` (HAProxy's `on-marked-down shutdown-sessions`):
then the connections it serves end at once with `backend_down`. The
setting is read from the snapshot each connection was accepted with.

### Forwarding, buffers and half-close

Each connection forwards through two fixed buffers of
`FORWARD_BUFFER_SIZE` (one per direction), allocated once and never
grown. A direction reads only into an empty buffer, so a slow reader on
one side stops Lorica reading the other: the kernel's receive buffer
fills and TCP flow control pushes back on the sender. Memory per
connection is the two buffers, whatever the peers do. `TCP_NODELAY` is
on both sides, so interactive protocols (SSH, database
request/response) do not wait on Nagle.

A FIN from one side is forwarded as a FIN to the other, and the
opposite direction keeps flowing (nginx keeps `proxy_half_close` off by
default). The natural end is `client_close` when the client side ended
first, `backend_close` otherwise.

There is **no `splice(2)` or zero-copy** path in 1.11.0: a splice
pipeline needs a pipe per direction, six fds per connection instead of
two, which would divide what the fd budget admits by three, and the
parity reference, nginx `stream`, copies through userspace buffers too.

### PROXY protocol towards the backend

`proxy_protocol_send` (`off`, `v1`, `v2`) writes a PROXY header to the
backend after connect, before anything else: before the replayed bytes
and, on a stream with upstream TLS, in plaintext before the handshake.
It carries the client address (the one a trusted PROXY header carried,
when one was accepted) and the address the client connected to. When
the two are not of the same family, `v1` sends `PROXY UNKNOWN` and `v2`
an `AF_UNSPEC` header. The header is not counted in the byte counters.

### PROXY protocol from a load balancer

`proxy_protocol_accept` makes a stream **require** a PROXY header (v1 or
v2, detected) from the peers in `proxy_protocol_trusted_cidrs`, which
must not be empty and refuses `/0`:

- a trusted peer must send a complete header within `MAX_HEADER_LEN`
  bytes and `HEADER_READ_TIMEOUT` of accept
  (`lorica-core/src/protocols/proxy_protocol.rs`), or the connection
  ends `proxy_header_invalid` before a backend is chosen;
- a peer outside the list is a direct client. It is not made to wait
  for a header, but if its first bytes are a PROXY signature the
  connection ends `proxy_header_invalid` with nothing forwarded, so a
  client cannot claim another address;
- there is no `optional` mode on streams in 1.11.0: a trusted peer that
  sends no header is refused;
- the address the header carries is the client for every source control
  of [Protecting a stream](#protecting-a-stream), the access log and the
  PROXY header sent on.

Outcomes are counted in `lorica_stream_proxy_header_total{outcome}`.
**PROXY accept is refused on UDP streams, for good**: a UDP source
address is spoofable, so "a trusted peer" means nothing there.

The HTTP and HTTPS listeners accept PROXY headers too, with their own
settings (`proxy_protocol_http`, `proxy_protocol_https`,
`proxy_protocol_trusted_cidrs`); see
[Client address from a PROXY header](security.md#client-address-from-a-proxy-header-v1110).

### Source addresses

`source_addresses` is nginx's `proxy_bind` as a list: backend
connections leave from these local addresses, in turn per attempt,
among those of the backend address's family. The addresses must be
assigned to the node's interfaces; empty lets the kernel choose. A TCP
connection binds with `IP_BIND_ADDRESS_NO_PORT`, so the kernel picks
the source port at connect time and can reuse it towards different
destinations: a source address runs out of ports per destination, not
overall.

A backend with no address of a matching family is skipped for the
connection, and an address the kernel refuses (`EADDRNOTAVAIL`, not on
this node) fails the attempt; both are counted in
`lorica_stream_candidates_skipped_total{reason}` and neither counts
against the breaker. A list that shares no family with an IP-literal
backend is refused at validation.

### Local backends

A backend is **local** when it is a loopback, unspecified or link-local
address (in either family, IPv4-mapped included), `localhost` or a name
under `.localhost`, or, at connect time, an address of one of the
node's own interfaces (read again every `INTERFACE_REFRESH_INTERVAL`).
Two rules hold, at validation and again at every connect:

- **Rule A:** a local backend needs `allow_local_backend` on the stream
  (`422` otherwise). The flag carries a permanent "local backend" badge
  and no automation or MCP surface can set it.
- **Rule B:** a local backend may never reach a reserved port of a node
  that binds the stream (management, HTTP, HTTPS, cluster, enrollment,
  automation) or a listen port of any stream that node binds, this one
  included, **flag or not** (`409`, `stream_local_backend`). This is
  also what keeps a stream from forwarding to itself.

What validation cannot see, and the connect-time check catches: a host
name is not resolved at validation, and a control plane does not know a
follower's interface addresses. At connect, a destination the rules
refuse is never connected; it is skipped and counted
(`lorica_stream_candidates_skipped_total{reason="local_destination"}`).
**A host name that re-resolves to a local address** is excluded from
that stream only, never marked down in the backend's shared health
(routes keep using it); every address refused is logged once, with a
warning, and counted in `lorica_stream_backend_dns_local_excluded_total`.
A name whose addresses are partly local keeps its other addresses.

Forwarding loops through another node are not detected; they are
bounded by the caps of each stream.

### DNS re-resolution

A backend given as a host name is resolved by each process, through
`/etc/resolv.conf` and the hosts file (`lorica-stream/src/resolver.rs`).
Other NSS sources (LDAP, mDNS, `systemd-resolved`'s own API) are not
consulted. A name is resolved again at its record's TTL, clamped between
`DNS_MIN_INTERVAL` and `DNS_MAX_INTERVAL`; a resolution is bounded by
`DNS_RESOLVE_TIMEOUT`. A failed or empty answer keeps the last good
addresses and retries at the floor; the first failure and the recovery
each log one warning per backend, and every failure counts in
`lorica_stream_backend_dns_failures_total`. No notification is raised
for a DNS failure. An IP literal is never resolved.

### Bandwidth

`upload_rate_bps` (client to backend) and `download_rate_bps` (backend to
client) cap one connection's throughput in bytes per second, nginx's
`proxy_upload_rate` and `proxy_download_rate`. The PROXY header and the
replayed pre-forwarding bytes are not charged.

### The connection cap

`max_connections` is the most concurrent connections of the stream on
one node, counted across its workers; the next one is refused
(`connection_cap`). In the fd budget each one counts two fds in one
worker, since one worker may hold them all: at the packaged limit,
fifteen streams at the default `max_connections` fit a node and a
sixteenth is refused on `worker_fds`
(`the_default_cap_admits_fifteen_tcp_streams_at_the_packaged_limit` in
`lorica-api/src/stream_budget.rs`).

---

## TLS at layer 4

A TCP stream treats TLS in one of three modes (`tls_mode`):

- **`none`**: bytes are forwarded as they come; nothing is read first.
  With `upstream_tls`, Lorica opens TLS towards the backend
  (origination).
- **`passthrough`**: Lorica reads the ClientHello to choose a rule, then
  forwards the ClientHello and everything after it, unchanged, to a
  backend that terminates TLS itself. Lorica holds no key.
- **`terminate`**: Lorica reads the ClientHello the same way, completes
  the handshake with a certificate of its own, and forwards plaintext,
  or re-encrypted with `upstream_tls`.

Which fields each mode takes is the table under
[The fields](#tls-story-124-tcp-only).

### Rules, and no default backend

A TLS stream routes by `match_rules`, each a name, a matcher, and the
backends serving it (`backend_ids`, `backup_backend_ids`,
`backend_max_active` per rule; a backend serves at most one rule of a
stream). Two matchers exist in 1.11.0:

- **`tls`**: a ClientHello naming one of `server_names`, exact or
  wildcard, optionally restricted to `alpn` protocols;
- **`no_sni`**: a ClientHello naming no server (see below).

For a ClientHello that names a server, the rules naming it exactly are
tried first, then the wildcard rules covering it, most specific first.
Within a level, a rule with `alpn` holds when the client offered one of
its protocols, the client's most preferred one winning, before a rule
with empty `alpn`; a level where no rule holds falls through to the next.
A ClientHello naming no server reaches only a `no_sni` rule. **When no
rule matches, the connection is closed before any byte is forwarded or
any handshake made** (`refused`, `no_match`): there is no default
backend, because a default backend is an allowlist bypass (D7). Two
rules a ClientHello could match alike are refused at write, so the
order of the rules never decides anything. A rule with no backend is
accepted; its clients end `no_healthy_backend`.

**Server names** are stored and matched in the canonical form routes use
(ASCII lowercase, no trailing dot), and the client's SNI is reduced to
it before matching. A wildcard `*.example.com` covers names at every
depth (`a.example.com`, `a.b.example.com`), as a route's does. An IP
address is refused as a server name: an SNI never carries one, and a
ClientHello whose SNI is an IP literal is read as naming none.

### The "no SNI" matcher

Some TLS clients send no server name (a client dialling an IP address,
some embedded devices). Matching them would otherwise need a default
backend, so the PRD's D7 gives them an explicit matcher instead:

- a `no_sni` rule is set on purpose, carries a permanent "no SNI" badge,
  and every client it admits is counted
  (`lorica_stream_no_sni_matched_total`);
- a stream with a `no_sni` rule needs a source allowlist
  (`source_allow_cidrs`) or `no_sni_acknowledged: true`. A stream without
  such a rule refuses the acknowledgement;
- on a terminating stream, such a client is served the certificate whose
  IP address SAN is the address it dialled, as the HTTPS listener does
  since 1.10.5, so one of the stream's certificates must carry an IP
  address SAN (the listen address, when the stream listens on a
  specific one).

### Reading the ClientHello

The ClientHello is read by Lorica's own bounded parser
(`lorica-stream/src/tls/client_hello.rs`), not by a TLS stack, so a
passthrough stream imposes no TLS policy on traffic it does not
terminate, and the bytes reach the backend exactly as read. It reads the
server name, the offered ALPN protocols in the client's order, and
whether an Encrypted Client Hello extension is present; it reassembles a
ClientHello spread over several records.

- **Size:** at most `CLIENTHELLO_MAX_LEN` bytes of handshake message over
  at most `CLIENTHELLO_MAX_RECORDS` records, read into a fixed buffer of
  `CLIENTHELLO_BUFFER` bytes per pending connection. Anything malformed,
  oversized, not TLS, or with a duplicated extension is refused as soon
  as the bytes show it (`refused`, `invalid_client_hello`).
- **Time:** the ClientHello must be complete by
  `clienthello_timeout_ms` after accept (a trusted PROXY header read
  before it included), or the connection ends `clienthello_timeout`. On a
  terminating stream the handshake must complete by the same deadline
  (`refused`, `tls_handshake` otherwise).
- **Pending connections are capped**: a connection still reading its
  ClientHello counts against `max_pending_connections` and its source's
  share of it (see [Protecting a stream](#protecting-a-stream)), so slow
  or silent clients cannot hold the stream's slots.

**Server-first protocols** (SMTP, FTP, MySQL, an SSH server waiting for
the client) cannot share a TLS stream: Lorica waits for a ClientHello
that never comes, and the connection ends `clienthello_timeout`.
**STARTTLS-style openings are not TLS here**: a PostgreSQL client with
`sslmode=require` opens with an 8-byte SSLRequest, which is not a TLS
record, and is refused `invalid_client_hello`. PostgreSQL 17's direct
TLS (`sslnegotiation=direct`) sends a real ClientHello with ALPN
`postgresql` and is served by a rule. Matching on a protocol's own
opening bytes is the protocol detection of 1.12.0.

**Encrypted Client Hello (ECH).** With ECH the real server name is
encrypted, and the ClientHello Lorica reads carries the outer, public
name of the client-facing server. A stream routes on that outer name, in
passthrough as in termination; Lorica does not decrypt ECH. A
ClientHello carrying the extension is counted in
`lorica_stream_ech_offered_total`. A client that sends a "GREASE" ECH
extension still puts its real name in the outer SNI and routes normally.

### Termination

A terminating stream serves certificates Lorica already manages,
including ACME and AD CS ones:

- `tls_terminate.certificate_ids` lists the stored certificates the
  stream serves. They decide which private keys reach the stream's nodes
  (in a fleet, a stream entitles exactly the nodes it targets to those
  keys, as a route does for its certificate). The write is refused
  unless every exact server name of the stream's `tls` rules is served
  by one of them, and every wildcard name by a certificate carrying that
  wildcard; a certificate a stream names cannot be deleted (`409`).
- The handshake answers from the node's certificate resolver, so a
  renewal is served on the next handshake, with no stream change.
- A certificate serves one label under its wildcard, so a rule
  `*.example.com` routes `a.b.example.com` while no `*.example.com`
  certificate can serve it: that handshake fails (`refused`,
  `no_certificate`), and the write answers a warning.
- TLS 1.2 and 1.3, no 0-RTT (a replayable first flight to a backend
  that cannot know it was replayed), and the HTTPS listener's resumption:
  stateful, from rustls' in-process session cache, with no stateless
  tickets (a TLS 1.3 client receives tickets that only name an entry of
  that cache, which a restart empties). A resumed session keeps the
  client certificate verified at its first handshake, as on the HTTPS
  listener. A rule's `alpn` is also what the handshake negotiates, in
  the rule's order.
- The server name rustls reads must be the one the rule was chosen by;
  a disagreement between the two parsers is refused
  (`invalid_client_hello`) and counted in `lorica_stream_sni_mismatch_total`.

**Client certificates.** `tls_terminate.client_auth` verifies clients
against the stream's own CA bundle, in the shape of a route's `mtls`,
with the same bundle checks and the same warning for a bundle that
trusts more than the CAs it lists. Two streams never share a listening
socket, so each handshake verifies against its own stream's bundle
only. `required: true` refuses a client presenting no certificate;
`required: false` lets it through as anonymous. **One difference from
routes:** on a stream, a certificate that does not chain to the bundle
fails the handshake whether or not `required` is set. An
`allowed_organizations` miss refuses the connection (`refused`,
`client_certificate`). The access log records whether a certificate was
verified, never its subject.

### Upstream TLS

`upstream_tls` opens TLS from Lorica to the backends, on a `none` stream
(origination) or a terminating one (re-encryption); a passthrough stream
refuses it. The backend's own `tls_upstream`, `tls_sni` and
`tls_skip_verify` are HTTP-route fields and never apply.

- The backend certificate is **verified by default**, against the public
  roots or the `ca_cert_pem` bundle that replaces them.
- `server_name` decides the name sent as SNI and verified:
  `backend_address` (the default: the backend's host; an IP literal
  sends no SNI and is verified against an IP address SAN), `client` (on
  a terminating stream, the name the client sent; the backend's host
  for a client that sent none), or `fixed` with a `name`.
- `client_certificate_id` presents a stored certificate to the backend
  (mTLS); its key reaches the stream's nodes like a terminated stream's,
  and a renewal is presented on the next connection.
- `skip_verify` accepts any backend certificate; it is refused beside
  `ca_cert_pem` or a client certificate, and carries a permanent
  "unverified upstream" badge.
- `alpn` is offered to the backend in order; empty offers none.
- Order on the wire: TCP connect, the PROXY header in plaintext when
  `proxy_protocol_send` is set, the TLS handshake, then the client's
  bytes. `connect_timeout_ms` covers the TCP connect and the handshake.
- Every failure is counted in
  `lorica_stream_backend_upstream_tls_failures_total{kind}`
  (`UpstreamTlsFailure` in `lorica-stream/src/counters.rs`). A failed
  or timed-out handshake counts against the breaker; a certificate that
  does not verify does not, since the configuration and the backend
  disagree rather than the backend being down. With `server_name =
  client`, a handshake the backend refuses (an alert or a reset) does
  not count either, when the name sent was the client's SNI: a backend
  that refuses names it does not serve (nginx `ssl_reject_handshake`,
  HAProxy `strict-sni`) would otherwise let a client pick names under a
  wildcard rule and open the circuit for everyone. A timed-out handshake
  still counts. A failure the breaker does not count answers a
  half-open probe as a success, since the backend did answer. A node
  that cannot build the stream's upstream TLS (its CA bundle or client
  key not held there) opens no connection and the client ends
  `connect_failed`.

### What the byte counters count

In passthrough, the bytes forwarded: TLS records, ciphertext. Where
Lorica terminates or originates TLS, the plaintext it forwards between
the two sides. The PROXY header sent to a backend is never counted.

### Upgrades

A TLS session Lorica terminates or originates holds keys no other
process can take over, so these streams carry `drains_on_upgrade: true`
and a "drains on upgrade" badge. In 1.11.0 a hot upgrade drains **every**
stream, TLS or not (see
[Configuration changes, stops and upgrades](#configuration-changes-stops-and-upgrades));
the flag names the streams that will keep draining once a later release
transfers the others. It promises nothing more in 1.11.0.

---

## UDP streams

A UDP listener is a potential amplifier, and a UDP source address is
spoofable. So a UDP stream is **bounded by default** (the PRD's D6): it
bounds the reflection itself, not only each source, and treats every
per-source control as a courtesy to honest clients rather than a
defence.

### Sessions

Datagrams are grouped into **sessions**, one per client address and port
(and the local address it targeted), each bound to one backend and one
worker. A session holds one connected upstream socket, so the backend
sees one stable source port per client session; there is no client-side
socket, and receive buffers are shared per worker, never allocated per
session. The backend must answer from the address it was sent to. A
session lives in its worker: if the worker dies, its sessions are lost
with no access-log row.

The algorithms are those of TCP except `peak_ewma` (a session has no
connect latency); `least_conn` counts sessions. Backups, the circuit
breaker, `close_on_backend_down`, `total_timeout_s`, `source_addresses`
and `allow_local_backend` apply per session, with the same meaning.
**The breaker judges a UDP backend by ICMP errors only** (port, host or
network unreachable before any response). A session that receives
nothing before its idle timeout, while it was owed a response, counts as
`no_response` on its link
(`lorica_stream_backend_connect_failures_total{kind="no_response"}`) and
as a failure in the stream SLA, but never against the breaker: whether a
datagram is answered is chosen by whoever sends it, and many protocols
drop bad input without a word by specification (RADIUS, SNMP, WireGuard,
a DNS server rate-limiting its answers), so counting silence would let
five spoofed datagrams open the circuit for every client. An unanswered
half-open probe closes the circuit, since it drew no ICMP error. A
backend that goes silent without sending ICMP is therefore not detected
passively; the UDP active checks of Story 12.14 are what will detect it.

### How a session ends

With `R` = `requests_per_session`, `K` = `responses_per_request` and the
`response_bytes_ratio`:

- each client datagram is forwarded and counted; at the `R`-th the
  session is **retired**: it takes no more requests and waits for the
  responses it is owed, and the client's next datagram opens a new
  session (nginx's `proxy_requests`);
- a backend datagram is forwarded only while the session has had fewer
  than `K` responses per request and the response bytes stay within the
  ratio times the request bytes; past either it is dropped and counted
  (`response_count_bound`, `response_byte_bound`);
- the session **ends as soon as every response it is owed has arrived**:
  `request_bound_reached` when it was retired, `response_bound_reached`
  otherwise, so a DNS query (`K` = 1) closes on its answer and frees its
  socket at once. A response dropped for the byte bound also ends it
  (`response_bound_reached`);
- with `K` = 0 (one-way protocols such as syslog or NetFlow) a session
  lives for `R` datagrams, then ends `request_bound_reached`, rather than
  writing one access-log row per message;
- otherwise it ends at `idle_timeout_s` with no datagram either way
  (`idle_timeout`), at `total_timeout_s` from its first datagram, or on
  an ICMP error from the backend (`connect_failed` before any response,
  `backend_close` after).

**`unbounded_responses`** lifts both response bounds, for protocols
whose backend speaks without being asked (games, VoIP signalling): the
session then ends only on `R` (when set), idle, total time, an ICMP error
or a drain. `responses_per_request` and `response_bytes_ratio` keep their
stored values, unapplied, and apply again when the flag is cleared. The
stream carries a permanent "unbounded responses" badge, and the flag is
in every API and MCP listing. There is no confirmation dialog: a badge
that stays visible is read, a dialog on every save is clicked through.

`requests_per_session: null` (no bound) needs no badge: the request
bound shortens a session's life, it bounds no reflection.

### The defaults, and why

The defaults, ranges and survey notes are on `UdpSettings`
(`lorica-config/src/models/stream.rs`); the values that have a
counterpart elsewhere are compared under
[Defaults compared](#defaults-compared). No surveyed product bounds
response bytes, rates per source, or the session count per listener by
default.

- **`response_bytes_ratio` and DNS.** A DNSSEC or large TXT answer (DKIM
  keys) to a query of about 50 bytes, inside the 1,232-byte EDNS buffer
  the 2020 DNS flag day recommends, is about 25 times the query. The
  default ratio serves it, so a validating resolver or a mail server
  works on the first day. What it gives up: a default UDP stream may
  amplify that much in bytes for one response. A stream that never needs
  large answers (RADIUS, NTP) lowers it.
- **`responses_per_request: 0`** is the setting for one-way protocols;
  **`unbounded_responses`** for stateful ones.
- **Idle 10 s** sits between the survey's 3 s (Traefik) and 1 min
  (Envoy): an idle session holds an upstream socket and an ephemeral
  port, which is also why the UDP range of `idle_timeout_s` stops far
  below the TCP one.

### The reflection bound

Towards one **source key** (an IPv4 address, or the /64 of an IPv6 one),
per node and per second, Lorica forwards at most

```
B = min(source_byte_rate x response_bytes_ratio,
        source_datagram_rate x responses_per_request x max_datagram_bytes)
```

response bytes, plus one second's worth again as burst
(`UdpSettings::reflection_bound`). With the 1.11.0 defaults this is
`min(524,288 x 32, 1,000 x 1 x 8,192)` = **8,192,000 bytes per second**
(about 65.5 Mbit/s), at most 16,384,000 bytes in any one second with the
burst. `B` is the worst case over request sizes: small requests reflect
at most `response_bytes_ratio` times their own bytes, which the
per-session ratio enforces whatever the rates. With
`unbounded_responses` there is no bound.

The bound is per source key and **per node that binds the stream**,
never per victim network: a spoofing attacker spreading across many
source keys, or a stream placed on many nodes, multiplies it. That is
why the listen-address rule below exists, and why the threat model
([T12](security/threat-model.md#t12-stream-listeners-and-proxy-protocol-v1110)) treats per-source controls as a
courtesy.

### The listen-address rule

A UDP stream listening on any address other than loopback, RFC 1918 or
ULA (`fc00::/7`) is **exposed** (`0.0.0.0` and `::` included, since they
bind every address of the host, and so are link-local and shared address
space). An exposed UDP stream is refused (`422`) unless it has a source
allowlist (`source_allow_cidrs`) or an **explicit**
`udp.source_session_cap` at or below
`UDP_EXPOSED_SOURCE_SESSION_CAP_MAX` (`udp_exposure_check` in
`lorica-config/src/models/stream.rs`). The default cap does not count:
the rule makes the operator choose a number. Removing the allowlist from
a stream that relies on it is refused too.

### Per-source caps across workers

Session totals per stream are exact on a node. The per-source cap is
shared by the workers through a memory region of their own, and workers
admitting one source at the same instant can pass it by at most the
worker count minus one: a source holds at most `source_session_cap +
(W - 1)` sessions per node, exactly `source_session_cap` with one
worker.

The region (`lorica-shmem/src/stream_caps.rs`, one per stream) is sized
from the stream: at the UDP default on eight workers, about 1 MiB of
rate cells and 2 MiB of per-worker source cells, growing with
`max_sessions` and the worker count (`layout_with_links`). Its pages are
backed only once touched.

### Capacity

The node's **session ceiling** and how several UDP streams share it are
under [The fd budget](#the-udp-session-ceiling-and-several-udp-streams-on-one-node).
For a protocol whose backend never answers, a stream sustains at most

```
max_sessions / idle_timeout_s   new sessions per second
```

since each session holds its slot until it idles out: 4,096 / 10, about
410 per second, at the defaults. Request/response traffic goes well past
that, because a session that receives the response it is owed ends at
once and frees its slot: a DNS stream is bounded by its backends, not by
this formula. Past the cap, new sessions are refused (`session_cap`)
and counted; existing ones are unaffected.

A stream that reaches its share of the ceiling is counted
(`lorica_stream_ceiling_reached_total`) and raises one
`stream_udp_ceiling_reached` notification per node per incident, re-armed
once its sessions fall below `CEILING_REARM_PERCENT` of the ceiling.

### Datagram size

`max_datagram_bytes` bounds the payload in both directions; a larger
datagram is dropped and counted (`request_oversize`,
`response_oversize`). A datagram whose PROXY v2 header would push it past
the largest UDP payload is dropped as `request_oversize`.

### PROXY protocol v2 over UDP

With `proxy_protocol_send: v2`, **every** datagram sent to the backend
carries a complete PROXY v2 header (`DGRAM` transport, the client's
address and port as source, the address the client targeted as
destination, no TLV); responses carry none. There is no session-level
header: this is the per-datagram convention receivers that accept PROXY
over UDP expect. `v1` is refused on UDP: its text format has no UDP
transport.

Receivers whose own documentation, read on 2026-11-18, states PROXY v2
over UDP: **Unbound** (`proxy-protocol-port`, "PROXYv2 is supported for
UDP and TCP/TLS listening interfaces",
<https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html>)
and **PowerDNS Recursor** (`proxy-protocol-from`, "a Proxy Protocol
version 2 header in front of UDP and TCP queries",
<https://doc.powerdns.com/recursor/settings.html#proxy-protocol-from>).
Neither has been run against Lorica in a test; check your receiver's
version.

### Replies on a wildcard address

A UDP stream on `0.0.0.0` or `::` receives on every local address of the
host. Lorica sends each reply from the address the client targeted, so a
client on a multi-homed host does not drop a reply that left from
another address. A stream on a specific address needs nothing.

### Draining a UDP stream

When a UDP stream is deleted, disabled, moved to another address or no
longer targeted at a node, its sockets stay open while it drains:
datagrams of existing sessions are still forwarded both ways, a datagram
that would open a session is dropped (`binding_draining`), and each
worker closes its socket at its last session or at the drain deadline.
**Cost:** an edit that rebinds a UDP stream on the same port (a new
listen address, same port) leaves it unserved for new clients for up to
`worker_drain_timeout_s` plus the 10 s bind retry, and the stream shows
`pending` meanwhile. Where UDP rebinds are common, keep the drain short.

---

## Protecting a stream

Layer 4 has less to inspect than HTTP: there is no request. What
protects a stream is the source address, its country, and connection and
session budgets. Every one of them is **per node**: a stream placed on
three nodes admits up to its values on each. Nothing is synchronised
across the cluster per connection.

> **A filter change does not end connections already open: disable and
> re-enable the stream to cut them.** Stream CIDRs, GeoIP, the global
> connection filter, the blocklist and the rates judge connections and
> sessions admitted after the change, as the HTTP connection filter
> does. Adding an attacker's address to a deny list does not end the
> connection or UDP session it already holds; disabling the stream
> drains it (`config_removed`), or it ends at its idle or total timeout.

> **The WAF auto-ban list does not apply to streams: an address banned
> on the HTTP listeners can still connect to a stream; deny it on the
> stream or in the global connection filter.**

### The order of the checks

Every check runs before a byte is forwarded (TCP) or a session is
created (UDP), cheapest and table-free first, so a refused source never
takes a slot in a rate or cap table (`lorica-stream/src/admission.rs`):

| # | Check | Refusal word |
|---|---|---|
| 1 | The stream's shared caps region is present in this worker | `caps_unavailable` |
| 2 | The global connection filter (Settings, the HTTP listeners' CIDR allow and deny lists) | `connection_filter` |
| 3 | The global IP blocklist, unless the global WAF whitelist holds the client | `ip_blocklist` |
| 4 | The stream's `source_deny_cidrs`, then `source_allow_cidrs` | `source_denied` |
| 5 | The stream's `geoip` | `geoip` |
| 6 | The stream's `open_rate`, then the source's `source_open_rate` | `open_rate`, `source_open_rate` |
| 7 | TCP: the stream cap, the pending cap, the source cap, the source's pending share. UDP: the stream's and the source's session caps | `connection_cap`, `pending_cap`, `source_connection_cap`, `source_pending_cap`; `session_cap`, `source_session_cap` |

A full rate or cap table refuses with `connection_table_full` (TCP) or
`session_table_full` (UDP), on this stream only. On UDP, the datagram and
byte rates per source are charged with the session's opening and drop
datagrams rather than refuse sessions. A datagram of a live session is
never judged again: it was admitted with its session. The open rate is
charged before the caps, so an opening a cap then refuses has spent its
token (charging after would let a source at its cap probe for free).

### Which address is judged

- **No PROXY accept, or a peer outside the trusted list:** the socket
  peer, at accept.
- **A trusted PROXY peer** (a load balancer funnelling many clients):
  only the per-stream checks run at accept (the region, the stream rate,
  the stream and pending caps); once the header is read, checks 2 to 5
  and the per-source rate and caps run on **the client the header
  carries**, still before any byte is forwarded. A `LOCAL` or
  `UNKNOWN` header carries no client, and the source checks run on the
  socket peer.

A source is an IPv4 address or the /64 of an IPv6 one.

### Allow and deny lists

`source_deny_cidrs` and `source_allow_cidrs` take CIDRs or bare
addresses. A deny entry always wins; a non-empty allow list refuses
every client outside it. `/0` is refused in both (to refuse everyone,
disable the stream), as are blank entries and IPv4-mapped networks.

**What counts as a source allowlist** (for the UDP listen-address rule
and the `no_sni` acknowledgement): any non-empty `source_allow_cidrs`,
however wide. A GeoIP allowlist does not count (a country is not an
address range, and an unknown country passes), nor does the PROXY trust
list (it names who may speak for a client, not which clients may
connect).

### GeoIP

`geoip` is a route's country allow or deny list, read through the node's
GeoIP database. A client whose country is unknown (no database on the
node, or an address it does not cover) **passes**, and is counted
(`lorica_stream_geoip_unknown_total`).

**GeoIP is not an access control.** A country allowlist on a node with
no GeoIP database loaded admits every client, as a route's does: one
rule for both planes (Story 12.6 D-d). Nothing refuses the stream and
nothing alerts; the one signal is `lorica_stream_geoip_unknown_total`
for that stream climbing with its connections or sessions. Watch it on
every node a stream with a country allowlist binds, and put the
addresses that must be kept out in `source_allow_cidrs` or
`source_deny_cidrs`, which do not depend on a database.

### The global filter and the blocklist

The global connection filter and the global IP blocklist apply to every
stream, through the same instances as the HTTP listeners, so a reload
reaches the next accept. The per-IP connection cap of the HTTP listeners
(Settings, `connection_limits_per_ip`) does **not** apply to streams: a
stream's own `source_max_connections` and `udp.source_session_cap` do
that job, per node where the HTTP cap is per process.

### Caps

- `max_connections` (TCP) and `udp.max_sessions` (UDP): the stream's
  total on the node, exact across workers.
- `source_max_connections` (TCP) and `udp.source_session_cap` (UDP): per
  source on the node. Workers admitting one source at the same instant
  can pass it by the worker count minus one.
- **`source_max_connections` is off by default: one source can hold the
  whole `max_connections` of a TCP stream.** Set it on every TCP stream
  reachable from untrusted sources. It stays off because the most common
  TCP stream is a database or a message broker behind one application
  host, whose connection pool opens many connections from one address,
  and no default fits every pool; a default cap would refuse that pool
  the day it grows. nginx (`limit_conn`) and HAProxy (`src_conn_cur`)
  leave the same cap to the operator ([Defaults
  compared](#defaults-compared)). A UDP stream does apply a per-source
  session cap by default (`DEFAULT_SOURCE_SESSION_CAP`), one of the
  bounds of [UDP streams](#udp-streams).
- `backend_max_active`, per link: the stream's connections or sessions
  to one backend on the node, nginx's `max_conns`. HTTP routes sharing
  the backend do not count against it. A backend at its cap is no
  candidate; with every candidate at its cap the connection is refused
  (`backend_cap`).

### Pending connections

A TCP connection is **pending** from accept while it still has a
pre-forwarding read to finish (a trusted peer's PROXY header, a
ClientHello), and gives its pending slot back once a backend is being
chosen. A plain TCP stream with neither reads nothing first and never
holds one. The stream holds at most `min(max_pending_connections,
max_connections)` pending connections on a node, and one source at most
that over `PENDING_SOURCE_SHARE_DIVISOR` (at least one), so filling the
pending slots takes that many sources. Pending connections count within
`max_connections`, so the setting adds nothing to the fd budget; it
bounds the read buffers that wait on slow clients. At the defaults, a
stream's pending ClientHello buffers take about 4.3 MiB per node at
most (`CLIENTHELLO_BUFFER` each).

### Rates

`open_rate` and `source_open_rate` bound new connections (TCP) or new
sessions (UDP) per second, per stream and per source, per node, each
with one second of burst. Both are **off by default**: a sensible rate
depends on the protocol (a connection pool opens a handful of
connections, a DNS client a session per query), and a wrong default
would refuse legitimate traffic. Set them on any stream exposed to the
internet; they are also what bounds the handshake CPU an attacker can
spend on a terminating stream. nginx's `stream` modules have no
counterpart.

### Refusals are counted, and their log rows are rate-limited

Every refusal increments `lorica_stream_refused_total{stream_id,reason}`.
The access-log rows of refusals are limited per stream and reason to one
row per worker every `REFUSAL_LOG_WINDOW` (`lorica-stream/src/refusal_log.rs`),
then one `refusals_suppressed` row carrying the count, so an attacker
cannot choose the write rate of the log sinks. The counters always count
everything.

---

## Management plane only

Opening a port is a perimeter change, and an automation token has no
axis that could confine a listen address or a port. So:

- streams are created, changed and deleted only through the management
  API (`/api/v1/streams`), from the dashboard or an operator session.
  Reads need Viewer, writes Operator, as for routes; every write is
  audited (`stream.create`, `stream.update`, `stream.delete`);
- the automation API has `streams:read` only (`GET
  /automation/v1/streams`, `GET /automation/v1/streams/status`), and the
  MCP server has stream tools in the read tier only (`lorica_streams`,
  `lorica_stream_status`, `lorica_stream_logs`). No scope and no tier
  writes a stream ([automation API](automation.md), [MCP](mcp.md));
- the settings that open a hole are refused on every automation and MCP
  surface: lifting the UDP response bounds, PROXY accept and its trusted
  CIDRs, local backends, and custom health-check payloads (a token with
  `backends:write` may pick a named template, never write a payload; see
  [health checks](health-checks.md));
- a token may not change the address of a backend that a stream with
  `allow_local_backend` forwards to, and may not delete a backend a
  stream links (`409`, naming the streams only to a token that holds
  `streams:read`).

Read-tier tokens minted before 1.11.0 do not carry `streams:read`; mint
a new one to see the stream reads and tools.

---

## How a connection ends, and why it was refused

Every stream connection and UDP session ends with exactly one **end
reason**, and every refusal and every dropped datagram is counted under a
reason of its own. The word lists are closed enums, and every surface
(log rows, metrics, the API's filters) derives its words from them:

| List | Source | Published in `openapi.yaml` |
|---|---|---|
| End reasons | `StreamEndKind` (`lorica-config/src/models/stream.rs`) | the `end_reason` filter of `/api/v1/stream-logs` |
| Refusal reasons | `StreamRefusal`, same file | `StreamRefusal` |
| Datagram drop reasons | `DatagramDropReason`, same file | `StreamDatagramDropReason` |
| Bind failure kinds | `lorica_stream::state` | `StreamBindFailureKind` |

Each variant's doc comment says when it is used. The families, briefly:

- **Natural ends**: the client or the backend closed, the idle or total
  timeout fired, no backend could be connected (`connect_failed`) or none
  was a candidate (`no_healthy_backend`).
- **Refused before any byte was forwarded**: `refused`, with the
  `StreamRefusal` word: no matching TLS rule (`no_match`, the D7 rule
  below), a cap, a rate, a source filter, a TLS handshake that failed.
- **Pre-forwarding reads that did not complete**: `clienthello_timeout`,
  `proxy_header_invalid` (and `detection_timeout`, reserved for the
  protocol detection of 1.12.0).
- **UDP session bounds**: `request_bound_reached`,
  `response_bound_reached` (see [UDP streams](#udp-streams)).
- **Closed by Lorica**: `backend_down` (with `close_on_backend_down`),
  `config_removed` (the stream, the backend or the link went away),
  `drained_by_upgrade`, `node_shutdown`.

A connection that ends on its own while draining keeps its natural
reason; one closed at the drain deadline gets the drain's reason.

---

## Observability

### The stream access log

Every TCP connection and every UDP session writes **one row when it
ends**, and so does every refusal (within the limit above). The row
(`StreamLogEntry` in `lorica-api/src/stream_logs.rs`) carries the
stream, the protocol, the local port (which tells the ports of a range
apart), the client address and port (the one a trusted PROXY header
carried, with the socket peer in `proxied_from`), the backend and the
address actually connected, the connect attempts, bytes each way (and
datagrams each way on UDP), the duration and the time to connect, the
TLS mode, SNI and ALPN, whether a client certificate was verified (never
its subject), the end reason and, for a refusal, the refusal word.
`detected_protocol` stays empty until the protocol detection of 1.12.0.

- **Stored** in its own table of the access-log database, kept to
  `stream_access_log_retention` rows (`0` for no limit; default
  `GlobalSettings::DEFAULT_STREAM_ACCESS_LOG_RETENTION`), pruned hourly.
  A full writer queue drops rows and counts them
  (`lorica_log_write_dropped_total{kind="stream"}`).
- **Read** with `GET /api/v1/stream-logs` (filters: `stream_id`,
  `end_reason`, `refusal_reason`, `client_ip`, a time window, paging; an
  unknown word is a `400`), exported with `/api/v1/stream-logs/export`
  (CSV or JSON), cleared with `DELETE` (audited). The dashboard's Logs
  page has an HTTP / Streams switch. On a control plane, `?node=<id>`
  reads a follower's rows, which the cluster fans in like access logs.
- **Exported** to the log sinks as the `stream` kind: syslog (MSGID
  `stream`, the access-log severity) and OTLP logs (`lorica.kind =
  stream`), each with its own toggle, `syslog_stream_enabled` and
  `otlp_logs_stream_enabled`, on by default and node-local.
- **Read by tokens** with `GET /automation/v1/stream-logs` and the MCP
  read tool `lorica_stream_logs`, which need both `streams:read` and
  `logs:read`.

### Metrics

The stream families are under the `lorica` namespace, rendered on
`/metrics` from the workers' counters. Their names, types and labels are
`StreamFamily` in `lorica-api/src/stream_metrics.rs`, the one place they
are defined. They cover, per stream: listener up, active and pending
connections or sessions, accepted, ended by end reason, refused by
refusal word, datagrams dropped by reason, bytes and datagrams each way,
connect attempts, retries, breaker denials and skipped candidates; the
PROXY header, ClientHello and handshake outcomes, the `no_sni`, ECH and
SNI-mismatch counts and the matches per rule; and per (stream, backend):
active connections, connects, bytes, connect failures by kind, connect
latency as a histogram, upstream TLS failures; per backend, DNS failures
and local exclusions. Examples:

```
lorica_stream_active{stream_id="<UUID>"}
lorica_stream_ended_total{stream_id="<UUID>",reason="idle_timeout"}
lorica_stream_refused_total{stream_id="<UUID>",reason="source_open_rate"}
lorica_stream_backend_connect_seconds_bucket{stream_id="<UUID>",backend_id="<UUID>",le="0.01"}
```

Labels carry ids, never a client address. `lorica_stream_info{stream_id,
stream_name, protocol}` joins an id to its name. Counters are summed
across workers and never go backwards when a worker is replaced; a UDP
stream's active sessions come from the node's exact count. A deleted
stream's series disappear with it.

Two families sit beside the stream ones:
`lorica_stream_sla_breach_total{stream_id, threshold_kind}`, and
`lorica_log_sink_up{sink}` (`syslog`, `otlp`), which is 1 when the sink
consumer is connected (syslog) or its last export succeeded (OTLP). With
several workers it reports the **lowest** worker's value, so one worker
that lost its sink shows as 0. A syslog sink over UDP is "up" when its
socket is open, which proves no delivery.

### SLA per stream

Each stream has a passive SLA, as routes do, with a target and a
connect latency bound (`max_connect_latency_ms`), whose defaults are
`StreamSlaConfig::DEFAULT_TARGET_PCT` and
`DEFAULT_MAX_CONNECT_LATENCY_MS` (`lorica-config/src/models/sla.rs`),
configured with `PUT /api/v1/sla/streams/{id}/config` and read with
`GET /api/v1/sla/streams` and `/api/v1/sla/streams/{id}` (its buckets,
export and data clear beside it). `sla:read` covers the automation reads
(`/automation/v1/sla/streams`) and the MCP tools (`lorica_sla_stream`,
`lorica_sla_streams`). On a control plane `?node=<id>` reads a
follower's figures.

- **TCP:** a connection that reached a backend is a success when its
  connect latency (from the start of the connect phase) is within the
  bound, and a latency sample either way; one that reached none
  (`connect_failed`, `no_healthy_backend`) is a failure.
- **UDP, owed responses:** a session answered by its backend is a
  success; one ended by an ICMP error, or that idled out unanswered, is a
  failure. **UDP availability carries no latency.**
- **UDP, owed none** (one-way or `unbounded_responses`): a session is
  judged at its end, a success unless an ICMP error ended it.

A breach or a recovery raises the existing `sla_breached` /
`sla_recovered` notifications with `target = stream`.

### Notifications

- `stream_bind_failed`: a node failed to bind a stream, once per
  failure, never per retry.
- `stream_backend_down`: a stream's circuit breaker opened on a backend,
  at most once per (stream, backend) every five minutes. The existing
  `backend_down` alert names the streams a backend serves.
- `stream_udp_ceiling_reached`: a UDP stream reached its share of the
  node's session ceiling, once per incident, with what bound the
  ceiling.

There is no notification for a DNS resolution failure: a failing name
keeps its last addresses, and the failure shows as a warning and in
`lorica_stream_backend_dns_failures_total`.

### In a fleet

Followers send their stream rows and stream SLA to the control plane
with the rest of their telemetry. While the control plane runs a release
older than its followers' (the mixed-version window of an upgrade), the
rows **wait** on the follower and are sent once the control plane is
upgraded; they are lost only if the follower's own retention removes
them first or it restarts in the window. See
[Running a Mixed-Version Fleet](cluster.md#running-a-mixed-version-fleet).

---

## Managing streams in the dashboard

The **Streams** page (after Routes in the sidebar) lists every stream
with its protocol, listen address and ports, backends, bind state, badges
and live counters, with search, a group filter and links to the stream's
logs and SLA. Enable and Disable act on `enabled` alone. Deleting a
stream says how long its connections will drain (`worker_drain_timeout_s`)
and that they end with `config_removed`.

**The form** is a drawer with up to six tabs, General, Backends, TLS,
Connection, UDP and Protection, showing only those the stream's protocol
and TLS mode take (`STREAM_TABS` and `tabsFor` in
`lorica-dashboard/frontend/src/lib/stream-form.ts`). The form copies no
range: the server validates, and an error is shown on the tab holding
the field. Every cap is labelled "per node". A Viewer gets the drawer
read-only.

**Badges** mark a setting that widens what a stream exposes, or a state
that needs attention. They are defined, with their tooltips, in
`STREAM_BADGES` (`lorica-dashboard/frontend/src/lib/streams.ts`), and
each corresponds to a setting described on this page: a failed bind (the
tooltip names each failing node, its kind, port and OS error), unbounded
UDP responses, a `no_sni` rule (suffixed "allowlisted" or
"acknowledged"), a local backend, upstream TLS that verifies nothing, and
"drains on upgrade". 1.11.0 has no silent-client or transparent-mode
badge, since neither feature is in this release.

**Live counters are this node's.** The page polls `GET
/api/v1/streams/status`, whose counters are the answering node's own
(the values its `/metrics` renders); on a control plane, the page says
so and links the SLA page, where the other nodes' traffic is. Rates are
computed in the browser between two polls. The bind state, by contrast,
is per node: on a control plane the status lists each active node that
should bind the stream as `bound`, `pending`, `failed` or `unknown` (a
node that drifted from the configuration or has not reported).

Elsewhere in the dashboard: the **Backends** page shows which routes and
streams use each backend, and its delete confirmation says that the
streams' connections drain; the **System** page shows the stream fd
budget and the UDP session ceiling; the **Cluster** page's node drawer
lists the bindings of the node that are not bound, by stream name; the
**Logs** and **SLA** pages have their stream views; Settings holds
`worker_drain_timeout_s`, `stream_listen_socket_cap`, the stream log
retention and the sink toggles.

---

## Configuration changes, stops and upgrades

One setting decides how long established stream connections and
sessions are given before Lorica closes them: **`worker_drain_timeout_s`**
(Settings, replicated across the fleet; default
`GlobalSettings::DEFAULT_WORKER_DRAIN_TIMEOUT_S`, at most
`WORKER_DRAIN_TIMEOUT_MAX_S`, never 0). A drain ends as soon as the
traffic is gone; the setting is its deadline, not its length. It is read
when a drain starts, so a change applies to the next drain without a
restart.

### A configuration change

An established connection or session keeps the settings it was accepted
with; **an edit applies to new connections only**. Changing a timeout, a
cap or a rule cuts nothing.

What does end connections, after a drain of `worker_drain_timeout_s`,
with `config_removed`:

- deleting or disabling the stream, or a node selector change that takes
  it off a node;
- removing a backend from the stream, or deleting the backend: the
  connections to that backend drain;
- changing the stream's listen address, protocol or ports: the stream is
  bound again, and connections on the old sockets drain.

A TCP stream's old listening socket is closed at once; a UDP stream's
stays open while it drains (see
[Draining a UDP stream](#draining-a-udp-stream)). A connection that
ends on its own during the drain keeps its own end reason.

**Every configuration change reloads both planes.** A stream edit runs
the HTTP workers' two-phase reload as any configuration change does,
and a route or backend edit makes every worker reload its stream table
(so does a backend's health change, without the HTTP reload). This is
kept on purpose: the two-phase reload is the tested path and is
hitless, so an HTTP request in flight is not affected by a stream edit,
and a stream connection already open keeps the settings it was accepted
with.

### A stop

On a stop (`systemctl stop`, `restart`), every stream stops accepting
and its connections drain for `worker_drain_timeout_s`, then those left
end with `node_shutdown`; in-flight HTTP requests get the same delay,
in worker and in single-process mode. While it drains, Lorica extends
systemd's stop timeout through `sd_notify` (`EXTEND_TIMEOUT_USEC`), so
the unit's `TimeoutStopSec` never cuts a drain short and no drop-in is
needed for a long drain (systemd 236 or later). Without systemd (a
container), nothing extends the runtime's own stop grace: set Docker's
`stop_grace_period` above the drain. `docs/installation.md` and the
hardening guide's [The drain on a stop](security/hardening-guide.md#the-drain-on-a-stop)
cover both.

### A hot upgrade

In 1.11.0, **every stream drains on a hot upgrade**: no connection or
session is handed to the new binary. The old generation stops accepting
at the handoff, while the new one listens on the same ports (a TCP
listener is passed to it; a UDP stream's sockets are handed over socket
by socket, so the kernel keeps each client on the same slot), and the old
generation serves what it holds for `worker_drain_timeout_s`, read at
the handoff, then closes what is left with `drained_by_upgrade`. HTTP
gets the same delay. What happens to a stream's connections is
`Stream::upgrade_policy` (`lorica-config/src/models/stream.rs`), shown
per stream in the preview as `on_upgrade`:

| Stream | `on_upgrade` | What the old generation does |
|---|---|---|
| TCP, any TLS mode | `drain` | Keeps forwarding each connection until it ends or the deadline closes it (`drained_by_upgrade`). |
| UDP owed responses (bounded, at least one response per request) | `relay_in_flight` | Takes no new request, relays the responses its sessions are still owed; a session ends on its bound with its own reason, or at the earlier of its idle timeout and the deadline with `drained_by_upgrade`. The client's next request reaches the new generation. |
| UDP owed none (one-way, or `unbounded_responses`) | `close` | Ends every session at once with `drained_by_upgrade`: none is owed a response, and the client's next datagram reaches the new generation. |

**Why UDP is not drained like TCP.** A stream's UDP sockets are handed
to the new generation, which reads every datagram from the handoff on;
the group keeps its size, so no client is moved to another worker and no
datagram meets an unbound port. The old generation stops reading and
keeps each session's socket only to send back what that session is
still owed. A UDP session with nothing owed (one-way, or unbounded
responses, where a backend speaks unasked) would otherwise answer a
client whose next datagrams already open a session in the new
generation: one client flow served by two generations. So it closes at
once. Each client datagram is read by exactly one generation, and its
responses come back through that one. During the overlap the two
generations count in their own caps, so a stream may hold up to twice
`udp.max_sessions` on the node for the drain, and ephemeral ports can
run short, which shows as `connect_failed`.

**Before upgrading,** `GET /api/v1/system/upgrade/preview` (SuperAdmin)
answers, for the node it is asked on: the drain delay that will apply,
whether the upload starts a live handoff (not in single-process mode),
whether an earlier generation is still draining, and per bound stream
its established connections or sessions, its `on_upgrade` and its
`drains_on_upgrade`. `lorica upgrade` prints it before uploading
(`--preview` prints it and exits), and the dashboard's binary upgrade
confirmation shows it.

**After the upgrade,** the new generation reports per stream how many
connections the old one closed at the deadline and how many finished on
their own, in `lorica_hot_upgrade_stream_connections_total{stream_id,
outcome}` (`drained`, `finished`), beside the unchanged
`lorica_hot_upgrade_total`. [Hot binary upgrade](hot-upgrade.md#what-the-drain-does) describes the whole
sequence, the report and chained upgrades.

`drains_on_upgrade` and its badge name the streams that will keep
draining once a later release transfers TCP passthrough connections and
UDP sessions to the new binary (Story 12.16, planned for 1.12.0 after a
feasibility spike): those whose TLS Lorica terminates or originates.

### A crash of the stream runtime

A process's streams run on their own thread, `lorica-stream`, beside
HTTP. If that thread panics, or a TCP accept loop or a UDP receive loop
panics or ends without having been told to stop, **the process exits**
rather than keep serving HTTP with a stream that no longer reads its
socket. A UDP loop that died silently would otherwise leave its slot in
the port's `SO_REUSEPORT` group, and the kernel would keep handing it a
share of the clients whose datagrams nobody reads.

- In worker mode the worker logs the cause once at error level
  (`the stream runtime died; exiting so the process restarts with its
  streams`, with the stream, protocol and panic message) and exits with
  status 70. The supervisor logs `worker exited` with that status,
  respawns the worker after its usual backoff and replays every live
  stream binding to it, as for any worker crash. The other workers keep
  serving throughout.
- In single-process mode the process logs the same line and exits with
  status 70; systemd restarts it (`Restart=on-failure` in the packaged
  unit). Without systemd, the container's restart policy decides.

What the exit costs: the HTTP requests and stream connections of that
process are cut, and its connections write no access-log row. A panic
inside one connection's or one session's own task is different: it ends
that connection only, the process keeps running, and that connection's
access-log row is lost.

### Which end reason, when

| What happened | End reason of the connections it closes |
|---|---|
| The stream, its backend or the link was removed or moved | `config_removed` |
| The node stopped or restarted | `node_shutdown` |
| A hot upgrade's drain deadline | `drained_by_upgrade` |
| A backend went down, with `close_on_backend_down` | `backend_down` |

A connection already draining keeps the reason of the first drain that
reached it.
