# Story 12.8: PROXY Protocol on the HTTP Listeners

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P1
**Author:** Romain G.
**Depends on:** nothing from the stream plane. This story touches the
HTTP listeners only (D4's last bullet) and can be built before Stories
12.1 to 12.7. One file-level ordering applies, named in the Lots: Story
12.2's Lot D also edits `lorica/src/startup/worker.rs` and
`lorica/src/startup/single.rs`.

**Blocks:**
- Story 12.3 AC #9 (PROXY accept on TCP streams) uses the parser and the
  bounds of Lot A through `lorica-core`, and Story 12.3 AC #8 (PROXY
  send) adds its encoder beside the parser in the same module.
- Story 12.15 AC #5 (the 443 hairpin) relies on the HTTPS listener
  accepting a PROXY header from loopback (D-l).
- Story 12.16 AC #3 carries "the client address taken from an accepted
  PROXY header" for streams; it reuses the parsed-header type of Lot A.

---

As an operator running Lorica behind a cloud layer-4 load balancer,
I want Lorica to take the client address from the PROXY header,
so that logs, WAF, rate limits and GeoIP see the real client instead of the load balancer.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **PROXY protocol v1 and v2 accept on the HTTP and HTTPS listeners**, off by default, per listener.
2. **The accept path is reordered in the forked listener** (`lorica-core`, where the connection filter runs on the socket peer at accept): the header is read first, from a trusted peer only, then the connection filter runs on the address it carries. This modification of the fork is named in the fork's sync notes, since it will conflict with future upstream changes to that path.
3. **One trust list, and no stacking.** A dedicated `proxy_protocol_trusted_cidrs`, separate from `trusted_proxies`. On a connection whose client address came from a PROXY header, `X-Forwarded-For` from the client is never read.
4. **Header required from trusted peers**, unless the listener sets an `optional` flag for load balancers whose health checks send none. The same size and time bounds as Story 12.3 AC #9.
5. **When on, the carried address is the client address for every HTTP control**: access logs, WAF and bot verdicts, rate limits, GeoIP, the connection filter, and the `X-Forwarded-For` Lorica sends upstream.
6. **The setting is refused on every automation and MCP surface**, in the same family as the trusted proxies the Epic 11 admin tier already refuses.

## Integration Verification

- IV1: Behind an L4 load balancer sending PROXY v2, an HTTPS route logs, rate-limits, GeoIP-filters and forwards `X-Forwarded-For` with the original client address.
- IV2: A direct connection from outside the trusted CIDRs carrying a PROXY header is disconnected, and one carrying a forged `X-Forwarded-For` behind a trusted PROXY peer is logged with the PROXY address.
- IV3: With PROXY accept off, every existing HTTP e2e profile passes unchanged.

## What the code does today

Read on `feat/v1.11.0` at `26597077`. Function names, not line numbers.
Read, not run, unless said otherwise.

- **No PROXY protocol code exists in the workspace or its lockfile.**
  `proxy_protocol` matches nothing in `lorica-core`, `lorica-proxy` or
  `lorica-http`, and `Cargo.lock` holds no PROXY protocol crate (`ppp`,
  `proxy-protocol` or similar). The only mention is
  `StreamEndReason::ProxyHeaderInvalid` in
  `lorica-config/src/models/stream.rs` (Story 12.1). Upstream Pingora had
  no PROXY protocol accept at the fork's last sync point (`3f87e92c`,
  `FORK.md`); whether upstream `main` gained one since was not checked.
- **The accept loop** is `ListenerEndpoint::accept`
  (`lorica-core/src/listeners/l4.rs`). With the `connection_filter`
  feature (Lorica enables it through `lorica/Cargo.toml`), it accepts,
  reads the socket peer from the stream's `SocketDigest`, calls
  `ConnectionFilter::try_accept(peer)`, drops a rejected stream and loops,
  attaches the `AcceptPermit` of an accepted one (`Stream::set_accept_permit`,
  Story 8.9) and applies socket options. This runs serially in the
  endpoint's accept task: anything that waits here waits for every
  connection behind it.
- **The per-connection task** is spawned in `Service::run_endpoint`
  (`lorica-core/src/services/listening.rs`): it calls
  `UninitializedStream::handshake()` under a fixed 60 s timeout, which
  calls `Stream::set_buffer()` and then the TLS handshake
  (`Acceptor::tls_handshake`) or nothing for plaintext.
  `TransportStack::accept` wraps the accepted `Stream` and the listener's
  TLS acceptor into the `UninitializedStream`.
- **The client address** every Lorica consumer reads is
  `SocketDigest::peer_addr()` (`lorica-core/src/protocols/digest.rs`), a
  lazy `getpeername` cached in a public `OnceCell`; `local_addr` is the
  same for `getsockname`. The TLS stream delegates `get_socket_digest` to
  the L4 stream, so one digest serves HTTP/1, HTTP/2 and TLS. The
  1.10.5 no-SNI certificate selection reads `local_addr` from this digest
  inside `Acceptor::tls_handshake` (`listeners/tls/rustls/mod.rs`).
- **`Stream::rewind`** (`protocols/l4/stream.rs`, `pub(crate)`) pushes
  bytes onto `rewind_read_buf`, which `poll_read` serves before the
  socket. `set_buffer` rebuilds the `BufferedStream` through
  `set_buffer_capacity`, which takes the inner stream out of the old
  buffer with `into_inner()`: bytes buffered there are lost, bytes in
  `rewind_read_buf` are not.
- **Client address resolution in Lorica**, all from
  `session.client_addr()`:
  - `resolve_client_ip` (`lorica/src/proxy_wiring/filters.rs`) reads the
    leftmost `X-Forwarded-For` entry when the socket peer is in
    `trusted_proxies`, and stamps `ctx.client_ip`, `ctx.client_ip_addr`,
    `ctx.is_xff`, `ctx.xff_proxy_ip`. Access logs, WAF, the ban list and
    blocklist, GeoIP, rate limits, bot protection, the consistent-hash
    key, capture and forward-auth all read `ctx`.
  - `check_bot_endpoints` (same file) repeats the `trusted_proxies` and
    `X-Forwarded-For` logic for the bot solve path, which returns before
    `resolve_client_ip` runs.
  - `is_purge` (`lorica/src/proxy_wiring.rs`) admits `PURGE` from a
    loopback or `trusted_proxies` socket peer.
  - `upstream_request_filter` (`lorica/src/proxy_wiring.rs`) sets
    `X-Real-IP` to the socket peer and appends it to the client's
    `X-Forwarded-For` (or starts one).
- **The connection filter** is `GlobalConnectionFilter`
  (`lorica/src/connection_filter.rs`): allow and deny CIDRs behind an
  `ArcSwap`, and the per-IP live-connection cap with its RAII permit.
  `commit_prepared_reload` (`lorica/src/reload.rs`) reloads it from the
  settings in every process. `run_worker` and `run_single_process` create
  it, call `set_connection_filter` on the proxy service, then add the
  HTTP endpoint (`add_tcp` / `add_tcp_with_settings`) and the HTTPS one
  (`add_tls_with_settings` with `TlsSettings::with_resolver`).
- **`trusted_proxies`** is a node-local `GlobalSettings` field (Epic 9
  PRD Story 9.4 AC #1: replicating it would let one control-plane
  compromise rewrite client-address trust on every edge). It is listed
  under "Node-local by decision" in the exhaustive destructure of
  `canonical.rs`, validated by
  `lorica_config::connection_filter::validate_cidr_list` through
  `apply_cidr_list` in `lorica-api/src/settings.rs`, and edited in the
  dashboard's `NetworkTab.svelte`. On a follower, a settings write
  answers 409 unless a break-glass window is open
  (`follower_read_only`, `lorica-api/src/middleware/authorize.rs`).
- **The automation admin tier is an allowlist.** `SETTINGS_ALLOWLIST`
  (`lorica-automation-policy/src/settings.rs`) is the whole surface
  `PUT /automation/v1/settings` and the MCP settings tool accept; any
  other key is a 403 before a validator runs. Its doc comment and
  `docs/mcp.md` ("What it refuses, by family") name the trusted proxies
  among the settings that can lock the operator out.
- **Worker counters** reach the supervisor's `/metrics` only when listed
  in `PER_WORKER_COUNTERS` and mapped in the match below it
  (`lorica-api/src/metrics.rs`), as
  `lorica_per_ip_connection_refused_total` is.
- **CI and the `connection_filter` feature (inferred, not run).** No
  `cargo test` line in `.github/workflows/ci.yml` enables
  `lorica-core/connection_filter` for a `lorica-core` test run: the
  forked-crate line uses default features and the rustls line adds
  `rustls` and `integration-tests`. `-p lorica` builds `lorica-core` with
  the feature but runs `lorica`'s tests, not `lorica-core`'s. If that
  reading is right, `test_connection_filter_inheritance` and every
  `cfg(feature = "connection_filter")` test in `lorica-core` never ran
  in CI. Lot 0 checks it and fixes the line before any fork change.

## Decisions taken in this story

Each with its reason and what it costs.

### D-a. One sans-IO parser, a Lorica-only module of `lorica-core`

The PROXY header parser is an additive, Lorica-only module of the fork:
`lorica-core/src/protocols/proxy_protocol.rs`, marked `Lorica:` at its
head, not behind any feature, std only. It reads bytes and returns a
verdict; it does no I/O, owns no timer and knows nothing of trust. Both
consumers do their own I/O around it: the listener code of `lorica-core`
for the HTTP listeners (this story) and `lorica-stream` for TCP streams
(Story 12.3 AC #9), which reaches it as
`lorica_core::protocols::proxy_protocol` and adds the encoder for PROXY
send (AC #8) beside it.

Public surface (names are the contract Lot B and Story 12.3 build on):

- `parse(buf: &[u8]) -> Result<Parsed<'_>, ParseError>`, where `Parsed`
  is `Incomplete` or `Complete { header: Header<'_>, consumed: usize }`.
  `consumed` is the header length; bytes after it belong to the client.
- `classify_prefix(buf: &[u8]) -> Prefix` with `V1`, `V2`, `NotProxy`,
  `NeedMore`: decides from the first bytes whether a stream opens with a
  PROXY signature, without parsing further (D-c).
- `Header { version, command, addresses, tlvs }`: `Command::{Local,
  Proxy}`; `Addresses::{Unspecified, Tcp { source, destination },
  Udp { source, destination }, Unix}`; `tlvs` an iterator of
  `(type: u8, value: &[u8])` over the validated TLV area.
- `ParseError::{Malformed, Oversized, Unsupported}`, each with a short
  static detail for the log line.
- `MAX_HEADER_LEN: usize = 4096` and `HEADER_READ_TIMEOUT: Duration` (5 s),
  the bounds both planes apply (D-e).

**Why a module of the fork, not a new crate (maintainer, Resolved 1):**
forked crates sit at `0.1.0` and depend only on forked crates. A
dependency of `lorica-core` on a product crate would put a
`version = "1.x"` pin in a fork manifest that every release bump must
edit, and would invert the layering (the fork below, the product
above). An additive file never conflicts with an upstream sync, since
upstream has no file of that name. **Cost:** `lorica-stream` gains a
dependency on `lorica-core` (Dev Notes, "`lorica-stream` on
`lorica-core`"), and the parser is recorded as a divergence of its own
(D-k). No new crate, no crate-list edit, no third-party crate.

### D-b. Where the header is read: the per-connection task, with a staged accept

The header is never read in the accept loop. `ListenerEndpoint::accept`
runs serially for the whole listener, so a trusted peer that opens a
connection and sends its header slowly (or never) would stall every
accept behind it. The read goes into the per-connection task, inside
`UninitializedStream::handshake`, which already runs under the 60 s
handshake timeout.

The reorder, per accepted connection on an endpoint that carries a PROXY
policy (D-d) whose mode for that listener is not `off`:

1. **Accept loop** (`l4.rs`). Read the socket peer. If the policy trusts
   it, **skip the connection filter** and hand the stream on marked
   *awaiting header*. Otherwise run the connection filter on the socket
   peer exactly as today and hand the stream on marked *direct*.
2. **Per-connection task** (`listeners/mod.rs`, `handshake`), before
   `set_buffer`:
   - *awaiting header*: read and parse the header within
     `HEADER_READ_TIMEOUT` (measured from accept) and `MAX_HEADER_LEN`
     (D-e); rewind any bytes read past it; install the carried addresses
     in the stream's digest (D-f); **then run the connection filter on
     the carried client address**, attach its permit, or drop the
     connection on a reject. On a refusal (D-j), close.
   - *direct*: sniff the prefix (D-c); a PROXY signature closes the
     connection, anything else is rewound and served as today.
3. TLS handshake or plaintext, as today.

With the mode `off` for the listener, step 1 runs today's code path and
step 2 does nothing: one atomic load per accept is the whole cost, which
NFR1 measures.

`ListenerEndpoint::accept` keeps its signature for upstream's callers;
the staged variant returns an enum (`Accepted::{Filtered, AwaitingHeader,
Direct}`) used by `TransportStack::accept`, and `UninitializedStream`
carries the stage, the policy and the filter it needs to run late.

**Why `handshake` and before `set_buffer`:** `set_buffer` swaps the
`BufferedStream` and drops what it buffered, while `rewind_read_buf`
survives it. Reading the header first, on the unbuffered stream, and
rewinding the excess is the one order that loses no client byte.
**Cost:** the filter, for trusted peers, now runs inside the connection
task instead of the accept loop. That is the reorder AC #2 asks for, and
it is the fork modification D-k records.

### D-c. Untrusted peers on a PROXY listener are direct clients, and a header from them closes

A listener with PROXY accept on still serves direct clients: a peer
outside `proxy_protocol_trusted_cidrs` is a direct client whose address
is its socket peer, as AC #4 implies ("required from trusted peers").
What it may not do is send a PROXY header (IV2). The per-connection task
reads the first bytes, asks `classify_prefix`, and reads more only while
the answer is `NeedMore` (at most 12 bytes: the v2 signature; `PROXY `
for v1). `V1` or `V2` closes the connection, counted as `untrusted_peer`.
`NotProxy` rewinds what was read and the handshake goes on.

This is decided on the first byte for every real client: a TLS record
starts with `0x16`, an HTTP method with an uppercase letter other than
`P`; `P` (a `POST`, `PUT`, `PATCH`) and `\r` (a leading empty line,
which RFC 9112 lets a server ignore) need one to five more bytes. The
wait is inside the 60 s handshake timeout every direct client already
has, so no new timer applies to them.

**Why not leave it to the HTTP parser and the TLS handshake**, which
would both fail on a PROXY header anyway: the failure would be a
handshake error or a 400 with no reason, uncounted, and a spoofing
attempt is the one refusal an operator most needs to see. **Cost:** a
read and a rewind per direct connection on a listener with PROXY on,
none on a listener with it off.

### D-d. Configuration: two listener modes and one node-local trust list

Three `GlobalSettings` fields, key/value rows like the rest (no
migration):

| Field | Type | Default |
|---|---|---|
| `proxy_protocol_http` | `ProxyProtocolMode`: `off`, `required`, `optional` | `off` |
| `proxy_protocol_https` | same | `off` |
| `proxy_protocol_trusted_cidrs` | list of CIDRs, a bare IP promoted to a host prefix as `trusted_proxies` does | empty |

- **A mode, not a boolean plus a flag.** `optional` is the AC #4 flag;
  folding it into one three-valued field leaves no meaningless
  combination (`optional` while off) to validate.
- **HTTP and HTTPS separately** (AC #1): an operator commonly puts an L4
  balancer in front of 443 only and keeps 80 direct for ACME and
  redirects, or the reverse.
- **One trust list for both listeners.** AC #3 names one field, and a
  node has one HTTP and one HTTPS listener behind, in practice, the same
  balancer. Per-listener lists would double the surface for no case the
  survey shows.
- **Node-local, not replicated**, like `trusted_proxies` and for the
  same reason (Epic 9 Story 9.4 AC #1): a replicated trust list would
  let one control-plane compromise make every edge accept forged client
  addresses from a network the attacker chose, which defeats every IP
  allowlist in the fleet at once. The listener modes are node-local with
  it: the listeners themselves are node-local (their ports are CLI
  arguments). All three join the "Node-local by decision" arm of
  `canonical.rs` and get no `CanonicalGlobalSettings` field.
  **Cost:** on a fleet, each node is configured on its own; on a
  follower that means before enrollment or inside a break-glass window,
  which is already true of `trusted_proxies`. No new follower write
  path; the docs say how (Resolved 2).
- **Live, no restart.** The listeners are fixed, but the policy each
  endpoint holds reads the current values through an `ArcSwap`, reloaded
  with the connection filter in `commit_prepared_reload`. A change
  applies to connections accepted after it.
- **Validation**, in `lorica_config::connection_filter` beside
  `validate_cidr_list` so import and the API share it: every entry
  parses; `0.0.0.0/0` and `::/0` are refused (trusting every address is
  the same as having no trust check); a mode other than `off` with an
  empty list is refused on the merged result, naming both fields (no
  peer could ever send a header, and `required` would then mean
  nothing).

### D-e. Parsing rules and bounds

- **Bounds, shared with Story 12.3 AC #9:** a header longer than
  `MAX_HEADER_LEN` (4,096 bytes) is `Oversized`; a header not complete
  `HEADER_READ_TIMEOUT` (5 s) after accept is `timeout`. Both are
  constants of the parser module, not settings (Resolved 5): a balancer writes the header with the
  connection, 5 s is already generous for that, and a setting nobody
  needs is surface. nginx's `proxy_protocol_timeout` defaults to 30 s;
  Lorica is stricter on purpose, since only trusted peers reach this
  read. A v1 header is at most 107 bytes by the specification; a longer
  line without CRLF is `Malformed` at 107 bytes, not at 4 KiB.
- **v1:** `PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n`, single
  spaces, decimal ports in 0..=65535, the family matching both
  addresses. `PROXY UNKNOWN ...\r\n` is accepted as `Unspecified`.
  Anything else is `Malformed`.
- **v2:** the 12-byte signature, version 2 (another version is
  `Unsupported`), command `LOCAL` or `PROXY` (another is
  `Unsupported`). `LOCAL` and `AF_UNSPEC` mean "use the socket
  addresses"; `AF_UNIX` is treated the same way, since a Unix path is not
  a client address any control can use. `AF_INET`/`AF_INET6` over
  `STREAM` give the carried addresses. `DGRAM` on an HTTP listener is
  `Unsupported` (the parser returns `Udp`; the HTTP caller refuses it,
  Story 12.5 is the one consumer that wants it). An address block
  shorter than its family requires is `Malformed`.
- **TLVs: structure validated, contents ignored.** Every TLV must fit
  inside the declared length; a TLV area that does not parse is
  `Malformed`. No TLV is acted on: `PP2_TYPE_SSL`, `ALPN` and `AUTHORITY`
  describe a TLS session a balancer terminated, and on these listeners
  Lorica terminates TLS itself; the cloud TLVs (AWS VPC endpoint, Azure
  link id, GCP PSC) carry nothing a control here uses. The parser still
  exposes them, so a later consumer reads them without a parser change.
  `CRC32C` is not verified, for the same reason.
- **IPv4-mapped IPv6** carried addresses are canonicalised to IPv4
  (`IpAddr::to_canonical`), so CIDR lists, GeoIP and the per-IP tables
  see one form.

### D-f. How the carried address replaces the peer

After a header with carried addresses, the per-connection task installs
a fresh `SocketDigest` on the stream with `peer_addr` pre-set to the
carried source and `local_addr` pre-set to the carried destination, and
records where they came from in a new field:
`SocketDigest::proxied_from() -> Option<&ProxiedFrom>`, with
`ProxiedFrom { peer: SocketAddr, local: Option<SocketAddr>, version }`
holding the balancer's socket address and the real local one. A `LOCAL`,
`UNKNOWN`, `AF_UNSPEC` or `AF_UNIX` header, and a trusted peer that sent
none under `optional`, leave the digest as it is: the socket peer is the
client, and `proxied_from` is `None`.

Every consumer reads the digest, so the replacement reaches each control
AC #5 lists without per-consumer code:

| AC #5 control | Path | Change needed |
|---|---|---|
| Connection filter, per-IP cap | deferred `try_accept` (D-b, D-h) | Lot B |
| Access logs | `ctx.client_ip` from `resolve_client_ip` | none beyond D-g |
| WAF verdicts, ban list, blocklist, auto-ban | `ctx.client_ip` / `ctx.client_ip_addr` | none |
| Bot verdicts | `ctx`, and the solve path's own resolution | D-g |
| Rate limits, flood counters | `ctx.client_ip` | none |
| GeoIP | `ctx.client_ip_addr` | none |
| `X-Forwarded-For` and `X-Real-IP` upstream | `session.client_addr()` | none (D-g) |

Also reached, and correct: the consistent-hash key, capture records,
forward-auth's `X-Forwarded-For`, and `is_purge`, which now judges the
real client (so a hairpinned or balanced client is no longer "loopback"
or "the balancer" for `PURGE`).

**`local_addr` follows the carried destination** because the one reader
is the 1.10.5 no-SNI certificate selection, and the address a client
dialed is the one it verifies an IP Address SAN against; behind a
balancer that is the balancer's address, not Lorica's interface. The
lazy `getsockname` the 1.10.5 test guards is not run for a proxied
connection either, since the cell is pre-set.

**Why the digest, not a Lorica-side override:** AC #5 is "every HTTP
control", and the controls read the digest in more places than any list
would stay accurate about. Replacing the address at the source makes a
consumer added next year right by default. **Cost:** `SocketDigest` gains
a field, part of the fork divergence D-k records.

### D-g. No stacking: one rule for when `X-Forwarded-For` is read

The `trusted_proxies` decision is written twice today
(`resolve_client_ip`, `check_bot_endpoints`). Lot D moves it into one
helper, `forwarded_for_is_trusted(session, config) -> bool`, used by
both, which answers `false` whenever `proxied_from()` is `Some`. So:

- a connection whose address came from a PROXY header never reads the
  client's `X-Forwarded-For` (AC #3), whatever `trusted_proxies` holds,
  even if the carried address is itself in `trusted_proxies`;
- a connection from a trusted PROXY peer that carried no address
  (`LOCAL`, `UNKNOWN`, or none under `optional`) is a direct connection
  from that peer and follows today's rule on its socket address;
- the two lists may overlap; nothing refuses it, and `docs/security.md`
  states the precedence above.

**Upstream headers keep today's semantics (Resolved 4):** `X-Real-IP` is
the client address, and Lorica appends it to whatever `X-Forwarded-For`
the client sent. A proxied connection is treated exactly as a direct
connection is today: the client's header is passed on as data Lorica
does not vouch for, and the entry Lorica appends, the carried address,
is the one hop it does vouch for, since it came from a peer in the trust
list. A backend that reads the rightmost entry gets the same guarantee
with or without a balancer in front. Stripping the client's header
instead would make what backends receive depend on whether a balancer
sits in front, for no gain in what they can trust.

### D-h. The connection filter and the per-IP permit on the carried address

- For a trusted peer, the filter's allow and deny lists and the per-IP
  live-connection cap (Story 8.9) run once, on the carried client
  address, after the header. The balancer itself is not filtered: the
  trust list is its gate. An operator who has `connection_allow_cidrs`
  set (allowlist mode) does not need to add the balancer to it, and
  does need the real clients in it; `docs/security.md` says so, because
  turning PROXY on changes what that list is matched against.
- A trusted peer with no carried address (`LOCAL`, absent under
  `optional`) is filtered and capped on its socket address, like any
  direct connection.
- **No pending-header cap.** Headers are read from trusted peers only,
  each bounded to 4 KiB and 5 s. A separate cap on connections still in
  the header read would be the per-endpoint pending cap of upstream
  `5104a3e0`, which Story 12.2 D-l ruled out for these listeners for
  reasons that hold here. **Cost:** a trusted balancer that opens
  connections and never writes holds one task and one fd per connection
  for up to 5 s; the balancer is the most trusted peer a node has.

### D-i. Refused on every automation and MCP surface, by construction and by test

The three fields are not added to `SETTINGS_ALLOWLIST`, so
`PUT /automation/v1/settings` answers 403 for each and the MCP settings
tool, whose body vocabulary is built from that constant, has no field
for them. Nothing in this story adds code to refuse them. What it adds:

- a test in `lorica-automation-policy` that no allowlisted key starts
  with `proxy_protocol_`, so the family stays out under any future name;
- a test in `lorica-api` that sends each `proxy_protocol_*` key of
  `GlobalSettings` (derived by serialising `GlobalSettings::default()`
  and filtering on the prefix, not typed out) to
  `PUT /automation/v1/settings` and gets 403, and one that the MCP
  settings tool refuses the same keys;
- the family line in `SETTINGS_ALLOWLIST`'s doc comment and in
  `docs/mcp.md` ("What it refuses, by family") becomes "the trusted
  proxies and the PROXY protocol listener settings", stated as a family
  with no field count.

### D-j. Refusals: closed reasons, counters, a rate-limited log

The outcome of every header read is one value of a closed enum in
`lorica-core` (`ProxyHeaderOutcome`), reported to the policy object that
Lorica implements:

- accepted: `v1`, `v2`, `local` (a header with no carried address),
  `absent` (a trusted peer with no header under `optional`);
- refused: `untrusted_peer` (D-c), `missing` (no header under
  `required`), `malformed`, `oversized`, `unsupported`, `timeout`.

Lorica records them as two per-worker counters, listed in
`PER_WORKER_COUNTERS` so the supervisor's `/metrics` sees them:
`lorica_proxy_protocol_accepted_total{listener, kind}` and
`lorica_proxy_protocol_refused_total{listener, reason}`, with
`listener` `http` or `https`. Label values come from the enum's
`as_str`; the docs name the enum and a test renders the table from it.

A refusal also writes one `warn` line (listener, reason, socket peer,
the parser's detail). Refusals are attacker-driven for
`untrusted_peer`, so lines are rate-limited per listener and reason: at
most one per 10 s, then one "N refusals suppressed" line when the window
closes with suppressions. The limiter is a small type in
`lorica/src/connection_filter.rs`; if Story 12.6 has shipped its own
refusal-log limiter (12.6 AC #6) before Lot D starts, Lot D uses that
one instead and says so in its Completion Notes.

A filter rejection after a header is counted where it is today (the
per-IP refusal counter and the filter's own path), not here.

### D-k. The fork modification and its sync note

`lorica-core` changes, each site marked `Lorica:` in a comment:

- `protocols/proxy_protocol.rs` (new, additive, Lot A): the sans-IO
  parser of D-a, declared in `protocols/mod.rs` with one `pub mod` line.
  Not feature-gated, so `lorica-stream` uses it without the
  `connection_filter` feature.
- `listeners/proxy_protocol.rs` (new, additive, Lot B): the
  `ProxyProtocolPolicy` trait (`mode() -> ProxyProtocolMode`,
  `is_trusted(&SocketAddr) -> bool`, `record(ProxyHeaderOutcome)`),
  `ProxyHeaderOutcome`, and the async header read built on
  `protocols::proxy_protocol::parse`.
- `listeners/l4.rs`: the staged accept (D-b).
- `listeners/mod.rs`: `TransportStackBuilder`, `TransportStack` and
  `UninitializedStream` carry the policy and the stage;
  `Listeners::add_endpoint_with_proxy_protocol(l4, tls, policy)`;
  `handshake` runs the header read or the sniff before `set_buffer`.
- `protocols/digest.rs`: `SocketDigest::proxied_from` and a constructor
  that pre-sets the two address cells.
- `protocols/l4/stream.rs`: nothing beyond using the existing `rewind`
  from inside the crate, unless Lot B finds the stage cannot ride on
  `UninitializedStream` (then a field here, recorded).

Everything but the parser compiles under the existing
`connection_filter` feature, which the reorder cannot exist without; no
new feature.

Records:

- `FORK.md`, "Lorica divergences in forked crates": one entry for the
  parser, "`lorica-core`, the PROXY protocol parser (v1.11.0, Story
  12.8)", naming `protocols/proxy_protocol.rs` as an additive Lorica-only
  file that an upstream sync leaves alone (Lot A).
- `FORK.md`, same section: one entry,
  "`lorica-core`, PROXY protocol accept and the reordered connection
  filter (v1.11.0, Story 12.8)", naming the sites above and what an
  upstream sync must keep: the staged accept in
  `ListenerEndpoint::accept`, the header read before `set_buffer` in
  `UninitializedStream::handshake`, and the extra `SocketDigest` field.
  It also says that upstream `5104a3e0` (ruled out by Story 12.2 D-l)
  lands on the same accept path, so any later upstream commit building
  on it conflicts here first.
- `docs/backlog.md` #81: one sentence that the next sync checks whether
  upstream gained a PROXY protocol accept of its own, and if so weighs
  it against this divergence before porting anything on
  `listeners/l4.rs` or `listeners/mod.rs`.
- The CI gap of "What the code does today" is not part of this
  modification: Lot 0 settles it first, as its own commit.

### D-l. The 443 hairpin of Story 12.15

Story 12.15 AC #5 moves HTTPS to another port and has a stream on 443
forward TLS to it with PROXY v2 from loopback. This story makes that
possible and grants nothing implicitly:

- loopback is never trusted by default; the operator (or 12.15's
  validation) puts `127.0.0.1/32` and `::1/128` in
  `proxy_protocol_trusted_cidrs`, which D-d's validation accepts;
- the recommended mode for the hairpinned HTTPS listener is `optional`:
  local processes that connect to it over loopback without a header
  (a load test from `lorica-bench`, an operator's `curl`) keep working
  as the loopback client they are today, while the hairpin stream's
  connections carry the real client;
- Lot D exposes `ProxyProtocolGate::trusts(listener, addr) -> bool` and
  the listener mode, so Story 12.15 validates the hairpin shape against
  the live policy instead of re-deriving it.

`docs/security/threat-model.md` states the cost: with loopback trusted,
any local process can present any client address to that listener.

### D-m. Management API, dashboard, import

- `UpdateSettingsRequest` gains the three fields; the handler validates
  through D-d's function; the change is audited by the existing settings
  audit; writes need the role `trusted_proxies` needs today.
- `GET /api/v1/settings` returns them; `lorica-api/openapi.yaml` gains
  them in both settings schemas, under the contract test.
- The dashboard's Network tab gets a "PROXY protocol" section beside
  "Trusted proxies": two mode selects and the CIDR list, with text
  saying the values are node-local, apply to new connections, and are
  not the same thing as trusted proxies (one line on which to use).
- TOML export and import carry the fields (serde defaults, so an older
  export imports with PROXY off).
- The management and automation listeners are not touched: AC #1 names
  the HTTP and HTTPS listeners only.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with `--all-targets
--features lorica/otel -- -D warnings` under `CARGO_BUILD_WARNINGS=deny`,
the CI `cargo test` lines, `cargo audit`), through Docker on Linux. Lot E
runs the frontend gates of `.claude/rules/lorica-frontend.md`. No agent
runs `git checkout`, `git restore` or `git stash`.

**Independent of the stream plane:** every Lot can run before Stories
12.1 to 12.7. Only Lot A matters to them, as the parser Story 12.3
consumes, so it is worth landing early.

Order: Lot 0 first, alone, as its own commit. Then A and C1 in
parallel. B after A (shared files: `FORK.md`, `lorica-core/Cargo.toml`
if A needs it). C2 and E after C1. D after B and C1, and after Story
12.2's Lot D if that Lot is in flight (shared files:
`lorica/src/startup/worker.rs`, `lorica/src/startup/single.rs`). F and G
after D. No Lot edits a crate list, so none conflicts with Story 12.2's
Lot B.

### Lot 0: the `connection_filter` tests in CI - cargo

Allowlist: `.github/workflows/ci.yml` (one `cargo test` line).
Depends on: nothing. Before every other Lot, since Lot B's tests are
`connection_filter` tests and must run in CI from the start.

- [x] Confirm, by reading every `cargo test` line of `ci.yml` and the
      feature lists of the packages each selects, whether any CI run
      builds `lorica-core`'s own tests with `lorica-core/connection_filter`.
      Record the answer and its evidence in the Debug Log.
- [x] If none does: add `lorica-core/connection_filter` to the rustls
      test line (`--features lorica-core/rustls,lorica-core/integration-tests,...`),
      run that exact line in Docker with `CARGO_BUILD_WARNINGS=deny`,
      and confirm the existing `cfg(feature = "connection_filter")`
      tests (`test_connection_filter_inheritance` among them) are listed
      and pass. A test that fails here is a pre-existing defect: stop and
      report it, do not fix it under this commit.
- [x] Commit alone as `fix(ci): ...`, before any fork change.
- [x] If one already does: no change, and the Debug Log says which line.
      (Not the case: none did, see the Debug Log.)

### Lot A: the parser in `lorica-core` - cargo

Allowlist: `lorica-core/src/protocols/proxy_protocol.rs` (new),
`lorica-core/src/protocols/mod.rs` (the `pub mod` line only),
`lorica-core/Cargo.toml` (only if a dev-dependency is missing),
`fuzz/Cargo.toml` (a `lorica-core` path dependency with
`default-features = false`, and the `[[bin]]` entry),
`fuzz/fuzz_targets/fuzz_proxy_protocol.rs` (new),
`.github/workflows/fuzz.yml` (the target matrix),
`docs/security.md` ("Fuzz Testing" list only), `FORK.md` (the parser's
divergence entry only), `Cargo.lock` (only if `fuzz/` keeps one of its
own and it moves).
Depends on: Lot 0.

- [ ] The module, marked `Lorica:` at its head, std only, not
      feature-gated: `parse`, `classify_prefix`, `Header`, `Command`,
      `Addresses`, the TLV iterator, `ParseError`, `MAX_HEADER_LEN`,
      `HEADER_READ_TIMEOUT` (D-a), with doc comments and one runnable
      example on `parse`.
- [ ] v1 per D-e: both families, `UNKNOWN`, the 107-byte line limit,
      strict spacing and port range, family mismatch refused.
- [ ] v2 per D-e: signature, version, command, the four families,
      `STREAM` and `DGRAM`, address-block length checks, TLV structure,
      the 4 KiB bound on the declared length, IPv4-mapped
      canonicalisation.
- [ ] `classify_prefix` on every prefix length of both signatures, on
      `GET`, `POST`, `PUT`, `PATCH`, a TLS record and a leading CRLF.
- [ ] Tests: vectors for every accepted shape and every `ParseError`;
      a header split at every byte boundary returns `Incomplete` until
      complete and the same `Complete` after; bytes after the header are
      never counted in `consumed`; randomized inputs (seeded `rand` 0.10,
      already a `lorica-core` dependency) never panic. Unit tests live in
      the module and run in the forked-crate CI line.
- [ ] Fuzz target `fuzz_proxy_protocol` over `parse` and
      `classify_prefix`, in `fuzz/` beside the existing targets and in
      `fuzz.yml`'s matrix; `docs/security.md` lists it.
- [ ] The `FORK.md` divergence entry for the parser (D-k).

### Lot B: the fork, `lorica-core` - cargo

Allowlist: `lorica-core/src/listeners/proxy_protocol.rs` (new),
`lorica-core/src/listeners/l4.rs`, `lorica-core/src/listeners/mod.rs`,
`lorica-core/src/protocols/digest.rs`,
`lorica-core/src/protocols/l4/stream.rs` (only if D-k's condition is
met), `lorica-core/Cargo.toml`, `lorica-core/tests/proxy_protocol.rs`
(new), `FORK.md` (the accept-path divergence entry only),
`docs/backlog.md` (#81 only).
Depends on: Lot 0, A.

- [ ] `ProxyProtocolPolicy`, `ProxyProtocolMode`, `ProxyHeaderOutcome`
      and the header read (D-k), the read bounded by
      `HEADER_READ_TIMEOUT` from accept and `MAX_HEADER_LEN`, excess
      rewound.
- [ ] Staged accept in `l4.rs` and the stage, policy and filter carried
      to `UninitializedStream` (D-b); `add_endpoint_with_proxy_protocol`.
- [ ] `handshake`: header read or sniff before `set_buffer`; the
      deferred `try_accept` on the carried address with its permit; the
      digest swap (D-f).
- [ ] `SocketDigest::proxied_from` and the pre-set constructor.
- [ ] `Lorica:` markers at every site; the `FORK.md` entry and the #81
      sentence (D-k).
- [ ] `lorica-core/Cargo.toml` lists its integration tests as explicit
      `[[test]]` entries: the new file needs one, gated on
      `connection_filter` (and `rustls` for the TLS case).
- [ ] Tests (Linux, real sockets): v1 and v2 accepted with the carried
      address in `peer_addr` and `local_addr` and `proxied_from` set;
      `LOCAL` keeps the socket addresses; client bytes in the same
      segment as the header reach the HTTP parser; TLS completes after a
      v2 header and the no-SNI certificate path reads the carried
      destination; untrusted peer with v1 and with v2 closed, without
      header served; `required` without header closed; `optional`
      without header served on the socket address; a header trickled
      past 5 s closed; 4,097 declared bytes closed; a deny list holding
      the carried address rejects the connection; a deny list holding
      only the balancer's address lets a proxied connection through; the
      per-IP permit is charged to the carried address and released on
      close; mode `off`: a PROXY header reaches the HTTP parser as bytes,
      as today; a slow trusted peer does not delay another connection's
      accept.

### Lot C1: the settings - cargo

Allowlist: `lorica-config/src/models/settings.rs`,
`lorica-config/src/models/enums.rs` (`ProxyProtocolMode`),
`lorica-config/src/store/settings.rs`, `lorica-config/src/canonical.rs`
(the node-local arm of the routing destructure only),
`lorica-config/src/connection_filter.rs`, `lorica-config/src/tests.rs`,
`lorica-api/src/settings.rs`, `lorica-api/openapi.yaml`,
`lorica-api/src/tests.rs`.
Depends on: nothing. Parallel with A.

- [ ] The three fields and the enum (D-d), load and save arms, an
      unparseable stored value is `ConfigError::Corrupt`.
- [ ] Node-local in `canonical.rs`, with no `CanonicalGlobalSettings`
      field.
- [ ] `validate_proxy_protocol` beside `validate_cidr_list` (D-d), used
      by the API handler and by import.
- [ ] `UpdateSettingsRequest`, `GET` and `PUT /api/v1/settings`,
      `openapi.yaml`.
- [ ] Tests: round trip of each field; the defaults; `/0` refused for
      both families; a mode on with an empty list refused, in one
      request and across two; clearing the list while a mode is on
      refused; TOML export and import round trip, and an export without
      the fields imports with PROXY off; the OpenAPI contract test.

### Lot C2: refusal on automation and MCP - cargo

Allowlist: `lorica-automation-policy/src/settings.rs` (doc comment and
a test), `lorica-api/src/automation/write.rs` (tests only),
`lorica-mcp/src/tools.rs` (tests only), `docs/mcp.md` (the family line).
Depends on: C1.

- [ ] The three tests and the two doc lines of D-i.

### Lot D: Lorica wiring - cargo

Allowlist: `lorica/src/connection_filter.rs`, `lorica/src/reload.rs`,
`lorica/src/startup/worker.rs` and `lorica/src/startup/single.rs` (the
endpoint registration only), `lorica/src/proxy_wiring/filters.rs`,
`lorica/src/proxy_wiring.rs` (the `trusted_proxies` reads only),
`lorica/src/proxy_wiring/tests.rs`, `lorica-api/src/metrics.rs`.
Depends on: B, C1; after Story 12.2's Lot D on the two startup files.

- [ ] `ProxyProtocolGate` in `connection_filter.rs`: the live policy
      behind an `ArcSwap`, one `ProxyProtocolPolicy` view per listener,
      `trusts(listener, addr)` for Story 12.15 (D-l), and the refusal
      log limiter (D-j).
- [ ] `commit_prepared_reload` reloads it with the filter; the prepared
      reload carries the three settings.
- [ ] `run_worker` and `run_single_process` register both endpoints
      through `add_endpoint_with_proxy_protocol` with their view, always
      (the mode is read live).
- [ ] `forwarded_for_is_trusted` (D-g) used by `resolve_client_ip` and
      `check_bot_endpoints`; `is_purge` left on the client address.
- [ ] The two counters in `metrics.rs` and `PER_WORKER_COUNTERS` (D-j).
- [ ] Tests: XFF ignored on a proxied session whose carried address is
      in `trusted_proxies`; XFF read for a trusted socket peer without
      a carried address; upstream `X-Real-IP` and `X-Forwarded-For` on a
      proxied session; `PURGE` refused for a proxied client behind a
      loopback peer; the gate reflects a reload; the limiter's window and
      suppressed count; the counters aggregate across workers.

### Lot E: dashboard - frontend gates

Allowlist: `lorica-dashboard/frontend/src/components/settings-tabs/NetworkTab.svelte`,
`lorica-dashboard/frontend/src/components/settings-tabs/NetworkTab.test.ts`,
`lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/routes/Settings.svelte` (only if the
save payload is built there).
Depends on: C1.

- [ ] The section of D-m, with the same CIDR input and error display as
      "Trusted proxies"; the API's 422 messages shown as returned.
- [ ] Tests: renders the stored values; sends the three fields; shows a
      refusal.

### Lot F: documentation - no cargo

Allowlist: `docs/security.md`, `docs/security/threat-model.md`,
`docs/cluster.md` (the node-local paragraph), `README.md` (feature list),
`CHANGELOG.md`.
Depends on: D.

- [ ] `docs/security.md`: a "Client address from a PROXY header
      (v1.11.0)" section: when to use it rather than `trusted_proxies`,
      the modes, mixed listeners (D-c), the precedence of D-g, what
      changes for `connection_allow_cidrs` (D-h), node-local and how to
      set it on a follower (before enrollment, or in a break-glass
      window; Resolved 2), the counters and log lines.
- [ ] `docs/security/threat-model.md`: PROXY-header spoofing (the
      cross-cutting deliverable), the loopback trust of D-l.
- [ ] `docs/cluster.md`: the PROXY protocol settings join the node-local
      family.
- [ ] `CHANGELOG.md` `[Unreleased]`: Added (PROXY accept on the HTTP
      listeners), Security (spoofing refused and counted).

### Lot G: end-to-end, IV1 to IV3 - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-proxy-protocol-smoke.sh`
(new), `tests-e2e-docker/test-runner/proxy_protocol_client.py` (new),
`tests-e2e-docker/test-runner/Dockerfile` (the `COPY` and `chmod`
lines), `tests-e2e-docker/test-runner/run-geoip-smoke.sh` and
`tests-e2e-docker/test-runner/run-tests-workers.sh` (one call each),
`tests-e2e-docker/docker-compose.yml` (only if the geoip profile needs
an environment variable).
Depends on: D.

- [ ] A Python client (the runner already ships `python3`; no new
      image, no HAProxy) that opens TCP, writes a v1 or v2 header with a
      chosen source, then speaks HTTP or TLS (`ssl` module) over the
      same socket.
- [ ] In the geoip profile (it has the MaxMind test database): with the
      runner's address trusted and HTTPS `required`, a v2 header
      carrying a test-database address of a denied country gets 403 and
      another gets 200; the access-log row shows the carried address;
      the echo backend receives it in `X-Real-IP` and as the last
      `X-Forwarded-For` entry; a per-IP rate limit hit for one carried
      address does not limit another (IV1). A forged `X-Forwarded-For`
      behind the header is logged with the carried address (IV2, second
      half).
- [ ] With the runner removed from the trust list, a v1 and a v2 header
      are disconnected and `lorica_proxy_protocol_refused_total{reason="untrusted_peer"}`
      counts both, while a plain request from the same runner is served
      (IV2, first half).
- [ ] In the workers profile, the accepted and untrusted cases once
      more, since settings reach workers through the reload RPC.
- [ ] IV3: the full suite with PROXY off, untouched profiles.

## Dev Notes

### Where to extend, verified

- Accept loop: `ListenerEndpoint::accept` (`lorica-core/src/listeners/l4.rs`).
- Per-connection path: `TransportStack::accept`,
  `UninitializedStream::handshake` (`lorica-core/src/listeners/mod.rs`),
  spawned by `Service::run_endpoint` (`lorica-core/src/services/listening.rs`)
  under `timeout(Duration::from_secs(60), io.handshake())`.
- Digest: `SocketDigest` (`lorica-core/src/protocols/digest.rs`);
  `GetSocketDigest::set_socket_digest` on the L4 stream; the TLS stream
  delegates (`protocols/tls/rustls/stream.rs`).
- Rewind: `Stream::rewind` and `rewind_read_buf`
  (`lorica-core/src/protocols/l4/stream.rs`).
- Lorica's filter, reload and endpoints: `GlobalConnectionFilter`,
  `commit_prepared_reload`, `run_worker`, `run_single_process`.
- Client IP: `resolve_client_ip` and `check_bot_endpoints`
  (`lorica/src/proxy_wiring/filters.rs`), `is_purge` and
  `upstream_request_filter` (`lorica/src/proxy_wiring.rs`).
- Settings: `GlobalSettings` (`lorica-config/src/models/settings.rs`),
  `store/settings.rs`, the routing destructure in `canonical.rs`,
  `lorica_config::connection_filter::validate_cidr_list`,
  `apply_cidr_list` in `lorica-api/src/settings.rs`.
- Automation surface: `SETTINGS_ALLOWLIST`
  (`lorica-automation-policy/src/settings.rs`), re-exported by
  `lorica-api/src/automation/write.rs`.

### `lorica-stream` on `lorica-core`

Story 12.3 reaches the parser by adding
`lorica-core = { version = "0.1.0", path = "../lorica-core", default-features = false }`
to `lorica-stream`, the form `lorica` and `lorica-proxy` already use.
Checked on this tree, not built:

- **No cycle.** `lorica-core` depends only on forked crates
  (`lorica-runtime`, `lorica-pool`, `lorica-error`, `lorica-timeout`,
  `lorica-http`, optional `lorica-tls`); `lorica-stream` (on the 12.2
  branch: `lorica-config`, `lorica-worker`) is depended on by none of
  them.
- **The right direction.** A product crate depending on the fork is the
  layering every product crate that touches the data plane already
  follows; the fork's manifest is unchanged.
- **No new third-party crate.** `lorica`, which links `lorica-stream`,
  already links `lorica-core`, so the lockfile does not move beyond the
  new edge.
- **Cost:** `lorica-stream` compiles after `lorica-core` and its
  unconditional dependencies (tokio, the HTTP stack), even though it
  uses one std-only module of it. The parser is not feature-gated, so
  `default-features = false` is enough. Story 12.4 may want more of
  `lorica-core` (or of `lorica-tls`) for stream TLS, which this edge
  then already provides.

### Pitfalls

- **Read the header before `set_buffer`.** After it, the read-ahead
  buffer swallows client bytes that `set_buffer_capacity` would later
  drop on a rebuild, and `rewind` is the only safe hand-back (D-b).
- **Do not read the socket peer through the digest you will replace and
  then expect the new cell.** The accept loop initialises
  `peer_addr` on the original digest; the carried address goes into a
  new digest set on the stream, never into the old cell.
- **The deferred filter must keep the RAII contract.** The permit is
  attached to the same `Stream` before the TLS handshake, so a handshake
  failure still releases it on drop.
- **A refused connection is dropped, not answered.** No 400 and no TLS
  alert on a PROXY refusal: the peer is either an attacker or a
  misconfigured balancer, and the counter and log line are the signal.
- **`classify_prefix` must not wait for 12 bytes from a direct client**
  that sent fewer; it decides as soon as the prefix diverges (D-c).
- **Heredocs with apostrophes break the Bash tool** (project memory):
  write test scripts with the Write tool, and keep `.sh` files LF.

### Tests per Lot

Listed in each Lot. Lots 0, A, B and D need Linux and run through the
`run-tests` skill in Docker; Lot G is the e2e suite, run alone on the
machine. NFR1 (mode off costs nothing measurable) is measured by Story
12.12's performance phase, not here.

## Resolved (maintainer, 2026-11-14)

1. **No new crate, and no forked-crate dependency on a product crate.**
   Forked crates sit at `0.1.0` and depend only on forked crates; a
   product-crate dependency would put a `1.x` pin in a fork manifest
   that every release bump must edit, and invert the layering. The
   parser is the additive Lorica-only module
   `lorica-core/src/protocols/proxy_protocol.rs`, with its own `FORK.md`
   divergence line and its fuzz target; Story 12.3 reaches it through
   `lorica-core` and adds the send encoder beside it (D-a, Lot A, Dev
   Notes "`lorica-stream` on `lorica-core`").
2. **Follower writes:** documented (before enrollment, or in a
   break-glass window), no new write path (D-d, Lot F).
3. **No access-log column** for the balancer's address in 1.11.0; it
   stays in `proxied_from` and in the refusal log (D-f).
4. **Upstream `X-Forwarded-For`:** appended, as today, with the
   reasoning in D-g.
5. **The 5 s header timeout** is a constant (D-e).
6. **The CI gap** is Lot 0, its own `fix(ci)` commit with the existing
   tests passing, before any fork change.

## Dev Agent Record

### Debug Log

- **Lot 0, the CI gap was real (read, then run).** Read: of the four
  `cargo test` lines of `ci.yml`, the forked-crate line selects
  `lorica-core`, `lorica-proxy`, `lorica-lb`, `lorica-cache` and the
  other forks with default features, and none of them enables
  `lorica-core/connection_filter` by default (`lorica-proxy` exposes it
  only as its own opt-in `connection_filter` feature); the rustls line
  adds `rustls` and `integration-tests`; `-p lorica --features otel`
  builds `lorica-core` with the feature through `lorica`'s defaults but
  runs `lorica`'s tests. Only the workspace clippy compiled the gated
  tests. Run: the full gate chain on `a3bdcaf3` printed no
  `test_connection_filter` line in any test step. With
  `lorica-core/connection_filter` added to the rustls line, that exact
  line (Docker, `CARGO_BUILD_WARNINGS=deny`) lists and passes
  `listeners::test::test_connection_filter_inheritance`,
  `listeners::l4::test::test_connection_filter_accept` and
  `listeners::l4::test::test_connection_filter_blocks_all` (512
  `lorica-core` unit tests passed, 0 failed). No pre-existing defect
  surfaced.

### Completion Notes

## File List

- `.github/workflows/ci.yml` (Lot 0: the rustls test line and its comment)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in: the parser moves into `lorica-core` as an additive module (no new crate), Lot 0 for the CI feature gap, `X-Forwarded-For` reasoning stated, open questions resolved. Status Draft. | Romain G. |
| 2026-11-14 | 0.3 | Lot 0: the rustls test line of CI enables `lorica-core/connection_filter`, so the gated listener tests run. Status InProgress. | Romain G. |
