# Story 12.4: TLS at Layer 4

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:**
- Story 12.1 (Review): the `Stream` model, `stream_backends`,
  `StreamEndReason::ClienthelloTimeout`, `StreamRefusal`,
  `check_backend_attachments` and its `AttachmentSnapshot`, canonical
  format 3.
- Story 12.2 (InProgress): `lorica-stream` (`StreamHandler`,
  `AcceptedConnection`, `ConnectionTracker`, `StreamTable`,
  `StreamTableSource`, `Engines`), the stream plane driver
  `lorica/src/startup/stream_plane.rs`, the drain semantics.
- Story 12.3 (Draft, being implemented): the TCP engine this story plugs
  into. Its connection pipeline (D-b), the preamble, the forwarding loop
  and `DirectionState` (D-c), the connect step and retry (D-h), PROXY
  send (D-j) and accept (D-k), the seams in `lorica/src/stream_engine.rs`
  (D-a, D-e), the counters and connection record (D-r), the field and
  migration conventions (D-q). Every 12.3 name below is the one its
  draft fixes; "Interface with Story 12.3" lists the edits this story
  needs from it.
- Story 12.5 (Draft): shares `lorica-stream` and `lorica-config` files
  with this story; each Lot below names the ordering.

**Blocks:** Story 12.6 (its pending cap of AC #5 wraps the phase-2 scope
this story's ClientHello read and handshake run in), 12.9 (logs the TLS
fields of the connection record and exports the TLS counters), 12.10
(the "no SNI" and "drains on upgrade" badges, the form for every field
of D-k), 12.11 (the upgrade preview reads `drains_on_upgrade`), 12.15
(its TLS matcher is this story's parser and rule selection; PostgreSQL 17
direct SSL on ALPN `postgresql`), 12.16 (excludes every stream whose
`drains_on_upgrade` is true, D8).

---

As an operator,
I want to route TLS connections by SNI without decrypting them, or terminate them with a certificate Lorica already manages,
so that end-to-end TLS services and plaintext services that need TLS in front are both covered.

## Problem

After Story 12.3 a TCP stream forwards bytes and knows nothing of TLS.
This story adds three things on top of that engine: reading the
ClientHello to choose a backend by SNI and ALPN without terminating
(passthrough), terminating TLS with the certificates Lorica already
holds (terminate), and opening TLS towards the backend (upstream TLS,
with or without a client certificate). It also has to answer four
questions the PRD left to it: the spelling of SNI names (2026-11-04
amendment), whether a terminating stream answers a client without SNI
from `LocalIpConfigs` and how that relates to the D7 "no SNI" matcher
(2026-11-12 amendment), client certificate verification on the 1.10.3
per-route model (2026-11-14 amendment), and which stream fields D8 turns
into "drains on upgrade".

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Passthrough with SNI and ALPN routing.** A stream reads the ClientHello without terminating TLS, reassembling it across records within a size ceiling, and selects a backend by SNI (exact and wildcard) and ALPN. The read is bounded in size and time; a client that does not complete its ClientHello in time is closed with `clienthello_timeout`. No match closes the connection (D7). With Encrypted Client Hello, routing sees the outer public name; `docs/streams.md` says so.
2. **The "no SNI" matcher (D7)** is an explicit matcher, badged and counted, requiring a source allowlist or an explicit acknowledgement.
3. **Termination with Lorica's certificates.** A stream can terminate TLS with a certificate from the existing `CertResolver` (`lorica-tls/src/cert_resolver.rs`), including ACME-issued certificates with automatic renewal and hot swap, then forward plaintext or re-encrypted.
4. **Upstream TLS on the stream** (D2): verification by default, configurable SNI, client certificates for mTLS towards the backend. The backend's HTTP upstream TLS fields do not apply to streams.
5. **Client certificate verification** on terminated streams, against the stream's own CA bundle, in the shape routes use (`MtlsConfig`, `lorica-config/src/models/route.rs`) and with the same bundle checks, including the 1.10.3 warning for a bundle that holds a root next to other certificates. Two streams never share a listening socket (Story 12.1 AC #7), so the defect 1.10.3 fixed for routes, one handshake verifying against the union of several bundles, cannot arise; the test suite proves it with two terminated streams trusting different CAs.
6. The TLS mode of a stream (none, passthrough, terminate) and upstream TLS are explicit fields, and fields that do not apply to the chosen mode are refused rather than ignored. A stream with termination or upstream TLS is marked as draining on upgrade (D8) in the dashboard and API.

## Integration Verification

- IV1: One port serves two SNI names in passthrough to two different backends, each seeing the client's original ClientHello; a third SNI is refused.
- IV2: A stream terminating TLS with an ACME certificate keeps serving across a renewal, and new connections present the renewed certificate.

## What the code does today

Read on `feat/v1.11.0` at `7ea2ae70`. Function names, not line numbers.
Read, not run, unless said otherwise.

- **`CertResolver`** (`lorica-tls/src/cert_resolver.rs`) keeps an
  `ArcSwap` of two maps: lowercase domain (primary and every SAN) to
  entries sorted longest-lived first, and `iPAddress` SAN to entries.
  `resolve` answers an SNI by exact name, then by **one** wildcard key
  (`*` plus the suffix from the first dot): `*.example.com` serves
  `a.example.com`, never `a.b.example.com`. A ClientHello without SNI
  gets `None` from `resolve`; the IP map is read only through
  `resolve_by_local_ip` (local address canonicalised with
  `to_canonical`). `reload` swaps both maps atomically and skips a bad
  row with a warning; `refresh_staples` replaces OCSP staples by
  `LeafFingerprint`.
- **`LocalIpConfigs`** (same file) holds a listener's base
  `ServerConfig` and, per canonical local address a loaded certificate
  carries, a copy whose resolver is a `LocalIpResolver`: SNI present goes
  to the shared resolver, SNI absent to `resolve_by_local_ip`.
  `for_connection(|| local_ip)` skips the `getsockname` when no
  certificate carries an address. Its doc comment already says "any
  listener that terminates TLS over the shared resolver builds one".
- **One resolver per process.** `run_worker` creates
  `Arc<CertResolver>` (`lorica/src/startup/worker.rs`) and fills it with
  `worker_load_certs_into_resolver` (`list_certificates`, then
  `lorica::reload::cert_data_for_resolver`); `run_single_process` does
  the same (`single.rs`). Every later reload, the ACME renewal included,
  calls `reload` on that same instance (`lorica/src/reload.rs`), so any
  `ServerConfig` built over the `Arc` serves a renewed certificate on
  its next handshake.
- **The HTTPS listener** (`lorica-core/src/listeners/tls/rustls/mod.rs`,
  `TlsSettings::build`) builds its `ServerConfig` with
  `builder_with_protocol_versions(&[TLS12, TLS13])` on the process
  default provider, an optional client verifier, the resolver, and
  wraps it in `LocalIpConfigs`. Defaults otherwise: no 0-RTT, in-memory
  session cache, no tickets.
- **mTLS for routes** (`lorica/src/mtls.rs`): the listener trusts the
  union of every route's bundle with `allow_unauthenticated()`
  (`build_from_routes`); each route re-verifies the chain against its
  own bundle (`RouteClientVerifier::from_pem`, an explicit `ring`
  provider). The policy is `evaluate_mtls`
  (`lorica/src/proxy_wiring/helpers.rs`): no certificate passes unless
  `required`; a verified certificate must have one `O=` value listed in
  `allowed_organizations` when the list is not empty, compared whole and
  case-sensitively. The `O=` values come from
  `lorica_core::utils::tls::rustls::get_organizations_serial_bytes`.
- **The bundle checks** live in the API (`lorica-api/src/routes/mtls.rs`,
  both `pub(super)`): `build_mtls_config` (non-empty, at most 1 MiB,
  every `CERTIFICATE` block a valid X.509, at least one, the
  organization list trimmed, deduplicated, at most 100, no control
  character) and `mtls_bundle_trust_warnings` (a self-signed root next to
  other certificates, a CA next to a certificate it issued), logged at
  save by `log_mtls_bundle_trust_warnings` and returned by
  `POST /api/v1/validate/mtls-pem`.
- **Outbound TLS policy** (`lorica-tls/src/http_client.rs`): the `ring`
  provider named, rustls' safe default versions. `config_builder()` is
  the entry for a client that is not HTTP (the syslog sink's mTLS). The
  finished configs (`public`, `verified`, `unverified`) set ALPN to
  `http/1.1`, which a stream must not offer to an arbitrary backend.
  `AcceptAnything`, the verifier behind `unverified()`, is private.
  `public_roots()` reads the platform store, a costly call. `clippy.toml`
  refuses `rustls::ClientConfig::builder` everywhere but this module.
- **Host names** (`lorica-config/src/route_selection.rs`):
  `canonical_hostname` (ASCII lowercase, one trailing dot dropped, an
  IPv6 literal in RFC 5952 form) is the one form stored route names and
  protection records are in, pinned by `store::tests` together with
  migration 70. `validate_hostname_syntax` checks a field against a
  `HostnameShape`. `wildcard_covers(pattern, host)` matches **any depth**
  (`*.example.com` covers `a.b.example.com`), and `HostIndex::new`
  orders wildcards longest pattern first, then by spelling. HTTP route
  wildcards and certificate wildcards therefore already differ in depth.
- **Certificate keys in a fleet** (`lorica-config/src/store/cluster_nodes.rs`):
  `cert_key_recipients(cert_id)` and its inverse
  `certificates_entitling_node(node_id)` derive which nodes may hold a
  certificate's private key from the routes whose `certificate_id`
  names it, folding their `node_selector` through `SelectorUnion`. A
  certificate no route names entitles nobody. Followers pull every
  certificate stored without a key (`pull_missing_certs`,
  `lorica/src/startup/cluster_follower.rs`) and the control plane
  answers from `cert_key_recipients` (`cluster_plane.rs`); issuance
  pushes through `distribute_certificate` (`lorica-api/src/cluster/boundary.rs`).
  **A stream that terminates TLS on a follower would today find no key
  for its certificate**, because no route entitles it there.
- **Certificate deletion** (`lorica-api/src/certificates.rs`,
  `delete_certificate`) refuses while a route's `certificate_id` names
  the certificate; streams are not consulted.
- **Stream model hooks.** `StreamEndReason::ClienthelloTimeout` exists
  (12.1 AC #8). `StreamRefusal` has `NoMatch`, 12.3 adds
  `ConnectionCap`, 12.5 adds three session refusals. `stream_backends`
  has `PRIMARY KEY (stream_id, backend_id)` (migration 71); 12.3 adds
  `backup`.
- **Migrations.** `MIGRATIONS` ends at
  `(74, migrate_subscribe_stream_alerts)`. 12.3 D-q expects 75 and
  12.5 D-l expects 76.
- **Dependencies already in the lockfile** that this story uses:
  `rustls` 0.23 and `tokio-rustls` 0.26 (re-exported by `lorica-tls`:
  `TlsAcceptor`, `TlsConnector`, `ServerTlsStream`, `ClientTlsStream`,
  `WebPkiClientVerifier`), `rcgen` (dev, in `lorica` and `lorica-api`
  tests), the `rustls` feature of `lorica-core` (enabled by the binary).
  No new third-party crate.

## Decisions taken in this story

Each with its reason and what it costs.

### D-a. Where the TLS code lives

A new module tree `lorica_stream::tls` beside 12.3's `tcp`:
`client_hello.rs` (the parser, D-b), `matcher.rs` (rule selection,
D-d), `server.rs` (termination, D-f), `client_auth.rs` (D-h),
`upstream.rs` (D-i), `rewind.rs` (the preamble replay adapter, D-f).
The TCP engine calls into it at its two seams: the phase-2 reader of
12.3 D-b and the connect step of 12.3 D-h.

`lorica-stream` gains two dependency edges, both workspace crates
already in the lockfile: `lorica-tls = { version = "0.1.0", path =
"../lorica-tls" }`, and the `rustls` feature on the `lorica-core` edge
12.3 adds (for `get_organizations_serial_bytes`, so the `O=` reading is
the one HTTP uses). `rcgen` joins its dev-dependencies. *Why not the
binary crate:* 12.3 D-a's reasons, and every AC here is testable on real
sockets inside the crate. *Cost:* `lorica-stream` now compiles rustls,
which the binary compiled anyway.

The only things the engine needs from the binary are handed to its
constructor, not reached through a new seam: the process's
`Arc<CertResolver>` (as `Arc<dyn ResolvesServerCertByLocalIp>`), and the
public root store built once per process (D-i).

### D-b. The ClientHello reader: our own parser, not rustls' `Acceptor`

**Decision.** A minimal, bounded, allocation-light parser in
`tls/client_hello.rs`, fuzzed like the PROXY parser, used by both TLS
modes (and by Story 12.15's TLS matcher). It reads the TLS record layer
and the ClientHello only far enough to answer four things: the server
name, the offered ALPN list in client order, whether an
`encrypted_client_hello` extension (0xfe0d) is present, and how many
bytes the ClientHello took.

*Why not `rustls::server::Acceptor` (or tokio-rustls'
`LazyConfigAcceptor`):*
- Passthrough must not impose the acceptance policy of a TLS stack
  Lorica does not run for that traffic. rustls refuses ClientHellos a
  backend may legitimately accept (duplicate extensions, legacy shapes);
  I'm fairly sure, not certain, that it also refuses some TLS 1.0 and
  1.1 hellos at that stage. A passthrough stream in front of a legacy
  service should behave like nginx's `ssl_preread`, which reads and
  forwards.
- The bytes must be captured exactly, under a ceiling and a buffer this
  story sets, and replayed to the backend unchanged (AC #1, IV1).
  `Acceptor` consumes into its own buffers with its own limits.
- One reader serves both modes and 12.15, which runs before any mode
  is known.
- No rustls state per pending connection: Story 12.6 IV3 holds 10,000
  of them.

*Cost:* a second ClientHello parser in a terminating stream's process
(rustls parses the same bytes again). The two could disagree on the
server name; D-f closes that gap by comparing them after the handshake.

**Record layer and reassembly.**
- The first byte must be 22 (handshake). Anything else, an SSLv2
  compatible hello (high bit set) included, ends the connection
  `refused(invalid_client_hello)` with nothing forwarded.
- Records: a 5-byte header, content type 22 on every record until the
  ClientHello is complete (another type before then is invalid), record
  version `0x0301` to `0x0304` (a ClientHello record may carry 1.0 for
  compatibility), length 1 to 16,384 (TLSPlaintext's limit).
- The handshake message (type 1, 24-bit length) is reassembled across
  as many records as it spans, up to `CLIENTHELLO_MAX_LEN` = 16,384
  bytes of handshake message and `CLIENTHELLO_MAX_RECORDS` = 64 records
  (a fragmenting client cannot make the reader hold 16,384 one-byte
  records). Past either: `refused(invalid_client_hello)`, counted
  `oversized`.
- **The read buffer is fixed** at `CLIENTHELLO_BUFFER` = 17,408 bytes
  (16 KiB plus headers), allocated once per connection in phase 2 and
  dropped after it. It is the 12.3 preamble: bytes left from the PROXY
  read are already in it, the reader appends, and whatever the client
  sent past the ClientHello stays in it. In passthrough the whole
  buffer is replayed to the backend, byte for byte.

**ClientHello body.** `legacy_version`, `random` (32), `session_id`
(at most 32), `cipher_suites` (even, at least 2), `compression_methods`
(at least 1), then extensions if any bytes remain (a hello without
extensions is valid and has no SNI). Every length is checked against
what encloses it. Extensions:
- **Duplicate extension types**: invalid (RFC 8446 section 4.2).
- **`server_name` (0)**: the first `host_name` entry. Its bytes must be
  ASCII letters, digits, `-`, `_` and `.`, at most 253, else invalid.
  A name that parses as an IP address is treated as **absent**: RFC
  6066 forbids it, and rustls reports none for it too, so passthrough
  and terminate read it the same way. The name is then put in
  `canonical_hostname` form (D-c).
- **`application_layer_protocol_negotiation` (16)**: every protocol
  name (1 to 255 bytes), in the client's order.
- **`encrypted_client_hello` (0xfe0d)**: presence only.
- Everything else is skipped by length.

**Time.** The read must complete by `accept + clienthello_timeout_ms`
(D-k, default 5,000 ms), else the connection ends `clienthello_timeout`.
Counted from accept, like every pre-forwarding bound (12.3 D-d), so
phase 2 as a whole, PROXY header included, ends by that instant, which
is what Story 12.6 AC #5 caps. A client-first protocol is assumed: a
server-first protocol on a TLS stream waits for its banner and ends
`clienthello_timeout`, which `docs/streams.md` states.

**STARTTLS-style openings are not TLS here.** A PostgreSQL client with
`sslmode=require` opens with an 8-byte SSLRequest, which is not a
record: `invalid_client_hello`. Matching it is Story 12.15's PostgreSQL
matcher; PostgreSQL 17 direct SSL (`sslnegotiation=direct`) is a real
ClientHello with ALPN `postgresql` and is served by a rule here.

### D-c. SNI names: the route spelling, the route wildcard

**Canonical form: yes, the same one** (the 2026-11-04 amendment's
question). A stream's server names are stored, compared and matched in
`canonical_hostname` form, and the parsed SNI is reduced to it before
matching. One spelling of a host across routes, protection records,
streams and the access log is what the 1.10.2 change exists for; two
forms would let `App.Example.com.` miss a stream rule written
`app.example.com` while matching the route of the same name. The doc
comment of `canonical_hostname` gains "and stream server names", and a
future change to it rewrites those too (its own rule).

**Validation** through `validate_hostname_syntax` with a new
`STREAM_SERVER_NAME_SHAPE` beside the route shapes: wildcard allowed,
empty refused, catch-all refused, IPv6 literal refused, and any name
that `host_shape::names_an_address` reads as an address refused (an SNI
never carries one).

**Wildcards match at any depth, as routes do.** `*.example.com` covers
`a.example.com` and `a.b.example.com`, by `wildcard_covers`, and among
wildcards the longest pattern wins, then the spelling: the ordering
`HostIndex::new` applies, moved into a `pub fn wildcard_precedence`
both call so they cannot drift. *Why:* an operator reading a stream
rule reads it like a route, and the survey's references match deeper
names too (nginx `server_name` wildcards, HAProxy `-m end`). *Cost:*
certificate selection stays one-label (`CertResolver`, and RFC 6125 for
the client), so on a terminating stream a rule `*.example.com` routes
`a.b.example.com` while no `*.example.com` certificate can serve it;
the handshake then fails `no_certificate` (D-f). `docs/streams.md` says
so in one sentence, and the API's certificate coverage check (D-k)
checks only what a certificate can serve.

### D-d. Match rules, ALPN, and the "no SNI" matcher

**Rules.** A TLS stream (passthrough or terminate) routes through
`match_rules`, a list whose order never decides anything (precedence
below). Each rule has a `name` (1 to 64 of
`[a-z0-9_-]`, unique in the stream) and a `matcher`:

```rust
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StreamMatcher {
    Tls { server_names: Vec<String>, alpn: Vec<String> },
    NoSni { alpn: Vec<String> },
}
```

`server_names` 1 to 64 per rule (canonical, D-c), at most 1,024 per
stream; `alpn` 0 to 8 per rule, each 1 to 255 bytes of visible ASCII
(0x21 to 0x7e), empty meaning "any, or none". At most 64 rules. Story
12.15 adds its matcher kinds to the same enum; the rule wrapper is a
struct with `matcher` as a field, not `#[serde(flatten)]`, because the
canonical decoder refuses unknown fields and serde cannot combine the
two.

**Backends per rule.** Each `stream_backends` link names the rule it
serves in a new nullable `rule` column (D-l). A TLS stream's every link
names one of its rules, every rule has at least one primary link (12.3
D-f's rule, per rule), and backups serve their own rule only. A
non-TLS stream's links name none. One backend serves at most one rule
of a stream: the primary key stays `(stream_id, backend_id)` (Open
question 3). Selection, retry and the breaker are 12.3's, run over the
matched rule's links.

**Precedence, for one ClientHello.**
1. SNI present: the rules naming it exactly; if none at that level
   matches on ALPN (below), the wildcard rules covering it, most
   specific first, one pattern level at a time. A level where no rule's
   ALPN condition holds falls through to the next, as a route level
   falls through on path.
2. SNI absent: the `no_sni` rules, with the same ALPN step.
3. Nothing: `refused(no_match)`, closed before any byte is forwarded or
   any handshake starts (D7).

**ALPN step within a level.** A rule with a non-empty `alpn` holds when
the client offered at least one of its values; among several such
rules the one holding the client's most preferred offered value wins.
If none holds, a rule of that level with an empty `alpn` holds (it
matches any offer, and no offer). A client that offers no ALPN matches
only empty-`alpn` rules. *Why the client's order:* in passthrough the
backend picks the protocol and nobody in the middle knows which; the
client's first choice is the best predictor, and HAProxy and Traefik
also match on any offered value.

**Ambiguity is refused at validation.** Two rules of a stream that
share a canonical server name (or are both `no_sni`) and whose `alpn`
sets intersect, or are both empty, are refused, naming both rules.
With that, the outcome never depends on rule order.

**The "no SNI" matcher (AC #2, D7).**
- **Explicit**: the `no_sni` kind, nothing else. A client without SNI
  never reaches a `tls` rule, whatever its names.
- **Acknowledged**: a stream with a `no_sni` rule requires a source
  allowlist or `no_sni_acknowledged = true`; validation names both
  remedies. Story 12.6 AC #1 adds the per-stream allow CIDRs, after this
  story: the rule is one function,
  `Stream::no_sni_needs_acknowledgement(has_source_allowlist: bool)`,
  that this story calls with `false` and 12.6 calls with its field, so
  until 12.6 lands only the acknowledgement satisfies it. No release
  carries the interim. `no_sni_acknowledged = true` on a stream without
  a `no_sni` rule is refused (AC #6).
- **Counted**: `no_sni_matched` per stream in the counters (D-n).
- **Badged**: the badge is Story 12.10 AC #1's ("no SNI"), read from
  the rule kinds; this story adds nothing the badge cannot derive.

### D-e. Passthrough

- Phase 2 reads the ClientHello (D-b), the matcher picks a rule (D-d),
  the connect step runs over that rule's links (12.3 D-h), and the
  backend receives, in order: the PROXY header when the stream sends
  one (12.3 D-j), then the preamble, which is the ClientHello and any
  bytes after it exactly as read. Then 12.3's forwarding loop, on plain
  sockets, unchanged.
- **Nothing about the bytes changes**: no record is re-framed, no
  extension rewritten. IV1's backend checks the ClientHello it received
  against the one the client sent, byte for byte.
- **Retry** stays safe (12.3 D-h): the preamble is held and replayed to
  whichever attempt connects.
- `upstream_tls` and `tls_terminate` are refused on a passthrough
  stream (AC #6): Lorica neither terminates nor originates there.
- **ECH (AC #1).** With ECH, the SNI Lorica reads is the outer
  ClientHello's public name, and the true name is encrypted to the
  backend's keys. Routing uses the public name, so a rule for an ECH
  service names its public name. `docs/streams.md` says so, and that a
  client sending a GREASE ECH extension (indistinguishable to Lorica)
  carries its real name in the outer SNI. The `ech_offered` counter
  (D-n) shows how much traffic carries the extension.

### D-f. Termination

**Certificates come from the process's `CertResolver`** (AC #3), the
one instance the HTTPS listener uses. A renewal (ACME, AD CS or a
manual replace) reloads that instance, so a terminating stream serves
the renewed certificate on its next handshake with no stream-side
reload path, and OCSP staples attached by the refresh loop are served
too. IV2 holds by construction; a test in Lot E proves it.

**Fleet entitlement: explicit `certificate_ids`.** On a follower the
resolver holds only the certificates whose keys reached the node, which
is decided per certificate from the routes that name it (`cert_key_recipients`).
A terminating stream therefore names its certificates:
`tls_terminate.certificate_ids` (1 to 16), the analogue of
`Route::certificate_id`. Each entitles the stream's `node_selector`
through the same `SelectorUnion` fold, in `cert_key_recipients` and
`certificates_entitling_node` alike, so the push, the pull and the
node drawer agree. A disabled stream still entitles, as a disabled
route does. *Why explicit rather than matching rule names against
certificate names:* entitlement is a need-to-know decision about a
private key, and an implicit match would hand a key to every node of
any stream whose rule happens to cover the name. *Cost:* the operator
lists the certificates, and the API checks the list (D-k).

The handshake does not filter the resolver down to those ids: a name
has one certificate on a node, whichever object entitled it, and the
HTTPS listener and the stream answer it the same. The rules already
bound which names a stream admits (D-d), and a terminating stream must
have rules (Resolved 1).

**No SNI and `LocalIpConfigs`** (the 2026-11-12 amendment's question).
The two answer different questions and never stand in for each other:
the **matcher decides the backend** (D7), the **local address decides
the certificate**. A ClientHello without SNI on a terminating stream:
- without a `no_sni` rule: `refused(no_match)` before any handshake,
  even when a certificate carries the local address;
- with one: the handshake runs on the config `LocalIpConfigs` gives for
  the connection's local address, so the client gets the certificate
  whose `iPAddress` SAN is the address it dialed, as on the HTTPS
  listener since 1.10.5; no such certificate means the handshake fails
  `no_certificate`.
The API requires that a terminating stream with a `no_sni` rule lists
at least one certificate carrying an `iPAddress` SAN, and the listen
address among them when the stream listens on a specific one (D-k).

**The configs.** Per terminating stream, per rule, built by the engine
when it sees the stream in the table (`table_changed`, 12.3 D-i) and
kept until the stream changes:
- `ServerConfig::builder_with_provider(lorica_tls::http_client::crypto_provider())`,
  TLS 1.2 and 1.3 (the versions the HTTPS listener accepts), the
  stream's client verifier or none (D-h), the shared resolver;
- `alpn_protocols` = the rule's `alpn` in its order (rustls picks the
  first one the client offers); empty means no ALPN negotiated;
- `max_early_data_size` 0 (no 0-RTT: a replayable first flight to a
  backend that cannot know it was replayed), rustls' default session
  cache, no tickets: the HTTPS listener's choices;
- wrapped in `LocalIpConfigs::new(base, resolver)`; the connection uses
  `for_connection(|| local_ip)`.

**The handshake.** On the accepted socket wrapped in
`tls::rewind::Rewind`, an `AsyncRead + AsyncWrite` that serves the
preamble first, then the socket: rustls reads the exact ClientHello
the parser read. It must complete by `accept + clienthello_timeout_ms`;
past that instant a handshake that started ends
`refused(tls_handshake)`. Failures are classified, not gated:
- `no_certificate`: the resolver serves neither the SNI
  (`serves_server_name`, D-o) nor, for a `no_sni` rule, the local
  address. Checked before the handshake to classify only; rustls still
  runs and sends its alert, so the client sees a TLS failure rather
  than a bare close.
- `client_certificate`: rustls refused the client's certificate or its
  absence (D-h).
- `tls_handshake`: anything else, the deadline included.
Each ends the connection `refused(<that reason>)`, counted.

**The parsers must agree.** After the handshake the engine compares
rustls' `server_name()` (canonicalised) with the name the matcher used;
a difference ends the connection `refused(invalid_client_hello)` before
any backend is chosen. A hello crafted so that two parsers read two
names cannot route by one and present the certificate of the other.

**After the handshake.** The rule was chosen before the handshake, on
the offered ALPN; the negotiated protocol is one of the rule's values
by construction. Then the connect step (12.3 D-h, with upstream TLS if
set), then forwarding: plaintext bytes rustls already decrypted past
the handshake are the new preamble, and the loop runs between the
server TLS stream and the backend stream (Interface edit I2).
- **Half-close over TLS**: a `close_notify` (read of 0) is a FIN to
  the other side; shutting the TLS side down sends `close_notify` then
  the TCP FIN (tokio-rustls' `poll_shutdown`). A TCP FIN without
  `close_notify` (rustls `UnexpectedEof`) ends that direction as a
  close, `client_close`, never as an error to log above debug.
- **Memory**: rustls' plaintext send buffer is capped with
  `set_buffer_limit(Some(FORWARD_BUFFER_SIZE))` on each connection, so
  a terminated connection holds 12.3's two buffers plus rustls' fixed
  record buffers, never a growing queue (12.3 AC #14). The fd cost is
  12.3's two per connection.
- **Bytes counted** in the record and counters are what the loop
  forwarded: ciphertext in passthrough, plaintext where Lorica
  terminates or originates. `docs/streams.md` says which.

### D-g. Fields that do not apply are refused (AC #6)

The mode is `tls_mode` (`none`, `passthrough`, `terminate`), and each
other TLS field exists only where it means something:

| Field | `none` | `passthrough` | `terminate` | UDP |
|---|---|---|---|---|
| `match_rules` | refused if non-empty | required, at least one | required, at least one | refused |
| `no_sni_acknowledged` | refused if true | only with a `no_sni` rule | only with a `no_sni` rule | refused |
| `clienthello_timeout_ms` | refused if set | optional | optional | refused |
| `tls_terminate` | refused | refused | required | refused |
| `upstream_tls` | allowed (TLS origination) | refused | allowed (re-encryption) | refused |
| `upstream_tls.server_name = client` | refused | n/a | allowed | n/a |
| link `rule` | refused | required | required | refused |

"Refused" means a 400 naming the field and the mode, never a silent
drop. UDP refusals are permanent (no DTLS in this epic) and say so.
`clienthello_timeout_ms` is `Option<u32>` so that "not set" is
representable and a value set on a mode that ignores it is refused.

**`terminate` without rules is refused** (Resolved 1): every TLS
stream states the names it answers, and the D7 rule "no default" then
holds for both modes the same way.

### D-h. Client certificate verification per stream (AC #5)

- **Field** `tls_terminate.client_auth: Option<MtlsConfig>`, the
  route's type unchanged: `ca_cert_pem`, `required`,
  `allowed_organizations`.
- **The bundle checks are the route's**, not a copy: the API calls
  `build_mtls_config` and `mtls_bundle_trust_warnings` from
  `routes/mtls.rs`, made `pub(crate)`. A stream write logs the trust
  warnings like a route write (`log_mtls_bundle_trust_warnings`), and
  `POST /api/v1/validate/mtls-pem` serves the stream form unchanged.
- **The verifier is the stream's alone.** Built from `ca_cert_pem` with
  `lorica_tls::http_client::pem_roots` (strict: a bundle that does not
  load in full is refused) and
  `WebPkiClientVerifier::builder_with_provider(roots, crypto_provider())`,
  with `allow_unauthenticated()` when `required` is false. One stream,
  one socket, one `ServerConfig`: there is no union, so no second
  verification is needed, and a stream's bundle change takes effect on
  the next connection (the config is rebuilt with the stream), not at
  restart as the HTTP listener's union does.
- **Semantics, matched to the route's where they can be:**
  - `required = true`: no certificate, or one that does not chain to
    the bundle, fails the handshake: `refused(client_certificate)`.
  - `required = false`: no certificate passes as anonymous. A
    certificate that does not chain fails the handshake, as it does on
    the HTTP listener for a CA no route trusts; on a route it can pass
    as anonymous only because another route's CA admitted it at the
    handshake, which cannot happen on a stream. `docs/streams.md`
    states the difference.
  - `allowed_organizations`, after a successful handshake: the leaf's
    `O=` values (`get_organizations_serial_bytes`) must hold one listed
    value, compared by `organizations_admitted(allowed, presented)`, a
    new `pub fn` in `models/route.rs` that `evaluate_mtls` is changed to
    call, so routes and streams share one predicate. A miss ends the
    connection `refused(client_certificate)` before any backend
    connect. As on routes, the allowlist does not apply to a client
    that presented no certificate.
- **The two-CA proof (AC #5).** Two terminating streams, A trusting CA
  A and B trusting CA B, on two ports: a client certificate from CA A
  completes the handshake on A and fails it on B, and the reverse; a
  third client with no certificate passes on a `required = false`
  stream and fails on a `required = true` one. In Lot D (real sockets,
  `rcgen` certificates) and in Lot H end to end.

### D-i. Upstream TLS (AC #4)

**Field** `upstream_tls: Option<StreamUpstreamTls>`:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `server_name` | `UpstreamServerName` | `backend_address` | the name sent as SNI and verified |
| `ca_cert_pem` | `Option<String>` | none (public roots) | replaces the public trust with this bundle |
| `skip_verify` | `bool` | false | accept any certificate (badged, Resolved 5) |
| `client_certificate_id` | `Option<String>` | none | a stored certificate presented to the backend |
| `alpn` | `Vec<String>` | empty | protocols offered to the backend |

- **`UpstreamServerName`**: `backend_address` (the backend's host
  part: a DNS name is sent and verified; an IP literal sends no SNI and
  is verified against an `iPAddress` SAN, rustls' `ServerName::IpAddress`),
  `client` (terminate only: the client's SNI as matched; a client
  without SNI falls back to `backend_address`), `fixed { name }` (a DNS
  name or IP literal, validated with the redirect hostname shape or
  `IpAddr`). nginx's `proxy_ssl_name` / `proxy_ssl_server_name` and
  HAProxy's `sni` cover the same three cases.
- **Built on the outbound policy, as the amendment requires.**
  `lorica_tls::http_client::config_builder()` (the `ring` provider,
  safe default versions), then `with_root_certificates(roots)` or, for
  `skip_verify`, `dangerous().with_custom_certificate_verifier(...)`
  over a new `http_client::accept_any_server()` that `unverified()` is
  changed to use, then `with_client_auth_cert(chain, key)` or
  `with_no_client_auth()`, then `alpn_protocols` from the field. Not
  the finished HTTP configs: their `http/1.1` ALPN would make a backend
  with its own ALPN list (PostgreSQL 17, an `h2`-only gRPC server)
  refuse the handshake. No `#[allow]` for `clippy.toml` is needed.
- **Roots.** `ca_cert_pem` through `pem_roots` (strict, checked with
  `build_mtls_config`'s shape rules at write). Public roots: one
  `public_roots()` call per process, at engine construction, shared as
  `Arc<RootCertStore>`; if it fails, streams that need it end their
  connect attempts `upstream_tls(no_trust)`, counted, and the error is
  logged once.
- **Client certificate by reference.** `client_certificate_id` names a
  row of the certificate store, never a pasted key: no secret in the
  stream, `STREAM_WITHHELD_FIELDS` stays empty, AD CS and ACME renew it
  in place, and it is entitled to the stream's nodes like D-f's
  certificates. `StoreStreamTable::load` reads the referenced
  certificates through the same path the resolver loads from
  (`list_certificates`, `cert_data_for_resolver`'s decoding) into the
  table as `ClientIdentity` values wrapped in `lorica_tls::NoDebug`, so
  a debug print of the table never shows a key. A renewal is a
  configuration change, which sends the stream `refresh` (12.3 D-i), so
  new connections present the renewed certificate; Lot E proves it.
- **`skip_verify` with `client_certificate_id` is refused**, after the
  policy `http_client` states for `unverified()` ("never for a client
  that carries a credential"); `skip_verify` with `ca_cert_pem` is
  refused as contradictory.
- **The backend's HTTP TLS fields** (`tls_upstream`, `tls_sni`,
  `tls_skip_verify`) are never read by the stream engine (D2). They are
  not refused on a backend a stream uses, since an HTTP route may share
  it (Resolved 4); the field descriptions in `openapi.yaml` say
  "HTTP routes only".

**Where it runs, and what an attempt is.** An attempt with upstream
TLS is: TCP connect, the PROXY header in plaintext (Interface edit I1),
the TLS handshake, then the preamble over TLS. **The attempt is
connected when the handshake completes**, and one deadline,
`connect_timeout_ms`, covers TCP and TLS together, so 12.3's bound
"attempts x connect timeout" still holds. A failed handshake is a
failed attempt and the next candidate is tried (12.3 D-h): no client
byte has been forwarded yet. Breaker accounting extends 12.3 D-g:
- counted as a backend failure: reset, timeout or a TLS alert during
  the handshake (the backend is not serving TLS correctly);
- not counted: a certificate verification failure
  (`upstream_tls(verify)`), which says the configuration and the
  backend disagree, not that the backend is down, and would otherwise
  trip every backend's breaker on one wrong bundle. Counted per
  (stream, backend) and logged once per transition;
- not counted: `no_trust` (above).
A connection whose attempts all fail ends `connect_failed`, as in 12.3.

Session resumption towards backends uses rustls' default client cache,
one per stream config; resumption across streams never happens.

### D-j. "Drains on upgrade" (AC #6, D8)

- `Stream::drains_on_upgrade(&self) -> bool` in `models/stream.rs`:
  true when `tls_mode` is `terminate` or `upstream_tls` is set. One
  function: the API, Story 12.10's badge, Story 12.11's preview and
  Story 12.16's transfer exclusion all call it.
- `StreamResponse.drains_on_upgrade`, read-only, never accepted in a
  request; `openapi.yaml` documents it with D8's reason.
- In 1.11.0 every stream drains on upgrade (live transfer is Story
  12.16, 1.12.0); the flag says which streams will keep draining once
  1.12.0 transfers the others, and `docs/streams.md` and
  `docs/hot-upgrade.md` say so in those words, so nobody reads the flag
  as "the others survive an upgrade today".
- The dashboard half of AC #6 is the "drains on upgrade" badge of Story
  12.10 AC #1, which lands in the same release and has no page to sit
  on before it (Resolved 6).

### D-k. The new fields, the migration, and every surface they reach

**`Stream`** gains, in `models/stream.rs`:

| Field | Type | Default |
|---|---|---|
| `tls_mode` | `StreamTlsMode` | `none` |
| `match_rules` | `Vec<StreamMatchRule>` | empty |
| `no_sni_acknowledged` | `bool` | false |
| `clienthello_timeout_ms` | `Option<u32>` | none, meaning 5,000 |
| `tls_terminate` | `Option<StreamTlsTerminate>` (`certificate_ids`, `client_auth`) | none |
| `upstream_tls` | `Option<StreamUpstreamTls>` | none |

and `StreamBackend` gains `rule: Option<String>`. `clienthello_timeout_ms`
ranges 1,000 to 60,000 ms. Every new type is
`#[serde(deny_unknown_fields)]`.

**Defaults against the survey.** Recalled, not re-read, and not to be
quoted as they stand: Lot G verifies each against the PRD's sources and
writes the URL beside it, as 12.3 Resolved 9 does.

| Setting | Lorica | nginx `stream` | HAProxy `mode tcp` | Envoy | Traefik |
|---|---|---|---|---|---|
| ClientHello time | 5 s (`clienthello_timeout_ms`) | 30 s (`preread_timeout`) | no default (`tcp-request inspect-delay`) | 15 s (`listener_filters_timeout`) | not verified |
| ClientHello size | 16 KiB message, constant | 16 KiB (`preread_buffer_size`) | `tune.bufsize` | not verified (`tls_inspector`) | not verified |

*Why 5 s:* the ClientHello is a client's first flight, sent the moment
TCP completes; 5 s already allows several retransmissions, and every
pending second is a slot of Story 12.6's pending cap an attacker holds.
A field, not a constant, because the PROXY header's 5 s constant
applies to a trusted peer, while a TLS client may be on a poor mobile
link the operator knows about.

- **One migration** at **the next free number at implementation time**
  (after 12.3's and 12.5's, expected 77 if they take 75 and 76; recorded
  in the Completion Notes): `add_column_if_absent` for `tls_mode TEXT
  NOT NULL DEFAULT 'none'`, `match_rules TEXT NOT NULL DEFAULT '[]'`
  (JSON), `no_sni_acknowledged INTEGER NOT NULL DEFAULT 0`,
  `clienthello_timeout_ms INTEGER`, `tls_terminate TEXT` and
  `upstream_tls TEXT` (JSON, nullable), and `stream_backends.rule TEXT`
  (nullable). No `CHECK` on enumerated text (12.1 D-1's rule).
  Idempotent; a test runs it twice. `STREAM_COLUMNS` extended.
- **Rollback to 1.10.6** stays safe: 1.10.6 never names these tables.
- **Canonical config**: inside format 3, `#[serde(default)]` on each
  field, `CANONICAL_SHAPE_DIGEST` updated deliberately (12.1 D-3). TOML
  export and import, and `compute_diff`, carry every field and the link
  `rule`.
- **Validation in `lorica-config`** (pure, every writer: management
  API, replica apply, import): `Stream::validate` for D-c, D-d's caps
  and ambiguity rule, D-g's table, D-i's combinations and the
  `no_sni` acknowledgement; `check_backend_attachments` for the links:
  new `AttachmentRule` variants `LinkWithoutRule`, `UnknownRule`,
  `RuleWithoutPrimary`, `RuleOnNonTlsStream`.
- **Validation in the API**, where the certificate rows are (a new
  `lorica-api/src/streams/tls_checks.rs`, used by stream create, update
  and the TOML import):
  - every `certificate_ids` and `client_certificate_id` entry exists;
  - **coverage**: every exact server name of a terminating stream's
    `tls` rules is served by one of its `certificate_ids` (a domain or
    SAN equal to one of `cert_resolver::lookup_keys(name)`, the
    function `CertResolver::resolve` itself uses, D-o), and every
    wildcard rule name has a certificate with that exact wildcard. A
    miss is a 400 naming the rule, the name and the listed
    certificates. Coverage is checked at write only: a renewal that
    drops a SAN is seen in the `no_certificate` counter, not refused;
  - a `no_sni` rule on a terminating stream needs a listed certificate
    with an `iPAddress` SAN (`ip_sans_of_leaf`), and the listen address
    among them when it is not unspecified;
  - `client_auth` through `build_mtls_config`, trust warnings logged;
    `upstream_tls.ca_cert_pem` through the same shape rules.
- **Management API.** `CreateStreamRequest` and `UpdateStreamRequest`
  gain the fields; on a TLS stream the links travel inside each rule as
  `backend_ids` and `backup_backend_ids`, and the stream-level lists
  must be empty (and the reverse on a non-TLS stream). `StreamResponse`
  gains every field and `drains_on_upgrade`. 400 for validation.
- **Certificate deletion** refuses while a stream names the certificate
  (`certificate_ids` or `client_certificate_id`), naming the streams,
  beside the route check.
- **Entitlement** (`cluster_nodes.rs`): `cert_key_recipients` and
  `certificates_entitling_node` fold the selectors of the streams that
  reference a certificate, through `SelectorUnion`, failing closed on a
  corrupt selector exactly as for routes. Read from the streams table
  in Rust (the references are in JSON columns), never by a `LIKE`.
  Tests mirror the route ones: a fleet-wide stream entitles every
  active node, a scoped stream only its nodes, a node not active
  nothing, the node view agrees with the certificate view.
- **`lorica-api/openapi.yaml`**: the stream schemas, `StreamTlsMode`,
  the matcher kinds, `UpstreamServerName`, the refusal enum with this
  story's reasons, all derived from the Rust enums where the contract
  test checks them. `openapi-automation.yaml` untouched (Story 12.10).
- **Dashboard**: none in this story (Story 12.10 AC #1).

### D-l. Refusals and end reasons

`StreamRefusal` gains `invalid_client_hello`, `no_certificate`,
`tls_handshake`, `client_certificate`. `no_match` (D7) is reused for a
ClientHello no rule matches. `clienthello_timeout` is the existing end
reason. Upstream TLS failures are failed attempts, so the connection
ends `connect_failed` or `no_healthy_backend` (12.3 D-h), with the kind
in the counters. Words come from the enums' `VARIANTS`, never typed out.

### D-m. What 12.6, 12.9, 12.11, 12.15 and 12.16 rely on

- **12.6:** the ClientHello read and the terminate handshake run inside
  12.3's phase 2, one scope from the PROXY read to the backend choice;
  AC #5's pending slot wraps that scope, nothing more. A handshake is
  the expensive part of a terminating stream; 12.6's per-source and
  per-stream new-connection rates are its bound, which the threat model
  states.
- **12.9:** the connection record gains `tls: Option<TlsRecord>`:
  mode, SNI (canonical), offered ALPN, negotiated ALPN (terminate),
  matched rule, `ech_offered`, client certificate outcome (`absent` or
  `verified`, no subject: whether the subject joins the access log is
  12.9's decision), upstream TLS used. The counters of D-n.
- **12.11:** `drains_on_upgrade` for the preview.
- **12.15:** `tls::client_hello::parse` and `tls::matcher` are its TLS
  matcher; the `StreamMatcher` enum is where its kinds go; IV4's ALPN
  `postgresql` is a `tls` rule with that value.
- **12.16:** a passthrough connection is at 12.3's quiesce point only
  after phase 2 (the ClientHello replayed); a stream with
  `drains_on_upgrade` is never transferred.

### D-n. Counters

Added to 12.3's `StreamCounters` (D-r), created per stream on first use
and pruned by `table_changed`:
- per stream: `clienthello` per outcome (`parsed`, `timeout`,
  `invalid`, `oversized`); `no_sni_matched`; `ech_offered`;
  `handshakes` per outcome (`ok`, `no_certificate`,
  `client_certificate`, `tls_handshake`); `sni_mismatch` (D-f);
- per (stream, rule): `matched`;
- per (stream, backend): `upstream_tls_failures` per kind (`handshake`,
  `verify`, `timeout`, `no_trust`).
Prometheus names and labels are Story 12.9's.

### D-o. What `lorica-tls` gains

- `cert_resolver::lookup_keys(name) -> (exact, Option<wildcard>)`, the
  two keys `resolve` looks up, factored out of `resolve`, which then
  calls it; the API's coverage check and the next item call it too, so
  "which certificate serves this name" has one statement.
- `ResolvesServerCertByLocalIp::serves_server_name(&self, name) ->
  bool`, defaulted to `true` (always correct, only gives up the
  classification), overridden by `CertResolver` over `lookup_keys`.
- `http_client::accept_any_server() -> Arc<dyn ServerCertVerifier>`,
  the verifier `unverified()` already uses, made reachable for a
  non-HTTP client built from `config_builder()`.
These modules are Lorica's own inside the fork; nothing upstream
changes.

## Interface with Story 12.3

Aligned with the 12.3 draft (Draft, 2026-11-14). What this story uses
as 12.3 defines it: the pipeline phases and the preamble (D-b), the
forwarding loop, `DirectionState` and `FORWARD_BUFFER_SIZE` (D-c),
`connect_timeout_ms` and retry (D-d, D-h), backups (D-f), the breaker
key and fail-open (D-g), `table_changed` (D-i), PROXY send and accept
(D-j, D-k), the local-backend checks (D-m), the field and migration
conventions (D-q), `StreamCounters` and the record (D-r).

Edits, and who makes them:

- **I1, the order on the backend socket (12.3 D-s wording; code
  unaffected).** 12.3 D-s says upstream TLS "wraps the backend socket
  after connect and before the PROXY header and preamble". The PROXY
  header goes **in plaintext before** the TLS handshake: HAProxy's
  `send-proxy` with `ssl` and nginx's `proxy_protocol` with `proxy_ssl`
  both send it on the raw connection, and a backend that parses PROXY
  expects it there. The order is: TCP connect, PROXY header, TLS
  handshake, preamble over TLS. 12.3's D-j already writes the header
  right after connect, so 12.3's code needs nothing; this story's Lot D
  inserts the handshake between the header and the preamble, and 12.3's
  D-s sentence is corrected by whoever next edits that story.
- **I2, a forwarding loop over any stream (12.3 Lot C preferred,
  otherwise this story's Lot D).** 12.3 D-c names `TcpStream::split`.
  Terminate and originate need the same loop over
  `S: AsyncRead + AsyncWrite + Unpin` on either side (server TLS
  stream, client TLS stream, plain socket). A hand-written future that
  owns both streams and polls each direction in turn (the shape of
  tokio's `copy_bidirectional`) needs no split and no lock, and keeps
  `DirectionState`, `held_bytes` and the half-close rules as 12.3
  states them. If 12.3 lands on `TcpStream::split`, Lot D generalises
  it with no behaviour change, as a `refactor(proxy)` commit of its own.
- **I3, selection per rule (this story's Lot E).** 12.3's
  `BackendSelector` keys per-stream state (smooth WRR) by stream id;
  with rules it is keyed by (stream id, rule), candidates are the
  matched rule's links, and the per-rule primary rule replaces the
  per-stream one. The breaker stays keyed per (stream, backend): a
  backend's health does not depend on which rule reached it.
- **I4, "connected" with upstream TLS (this story's Lot D).** 12.3 D-h's
  decision point "the established connect" becomes "the established
  connect, and the TLS handshake when upstream TLS is set", under one
  connect deadline; D-i above lists what the breaker counts.

## Tasks

Lots with hard file allowlists. A Lot touches only its files; two Lots
that share a file are sequential, never parallel, and say so. Every Lot
that runs cargo ends on a tree that passes the gate chain CI runs
(`cargo fmt --all -- --check`, the workspace clippy with
`--all-targets --features lorica/otel -- -D warnings` under
`CARGO_BUILD_WARNINGS=deny`, the CI `cargo test` lines, `cargo audit`),
through Docker on Linux. No agent runs `git checkout`, `git restore`,
`git stash` or `git reset` in the shared tree.

**Order.** A first, in parallel with anything (its files are its own).
B after 12.3 Lot C (`lorica-stream/src/lib.rs`), never concurrently
with 12.5 Lots D or E (same file). C after 12.3 Lot B and 12.5 Lot C
(same files). D after A, B, C, 12.3 Lot C and 12.5 Lots D and E. E
after D, 12.3 Lot D2 and 12.5 Lot F. F after C, 12.3 Lot E and 12.5
Lot G. G after D, E and F. H after E, F, 12.3 Lot G and 12.5 Lot I
(sequential on `docker-compose.yml`).

### Lot A: `lorica-tls` additions - cargo

Allowlist: `lorica-tls/src/cert_resolver.rs`, `lorica-tls/src/http_client.rs`.
Depends on: nothing.

- [x] `lookup_keys`, `resolve` rewritten over it with no behaviour
      change; `serves_server_name` on the trait (default `true`) and on
      `CertResolver` (D-o).
- [x] `accept_any_server()`; `unverified()` built on it (D-o).
- [x] Tests: the existing resolver tests pass unchanged;
      `serves_server_name` agrees with `resolve` on exact, one-label
      wildcard, two-label miss, uppercase and unknown names;
      `accept_any_server()` behind `config_builder()` completes a
      handshake against a self-signed server.

### Lot B: the ClientHello parser - cargo

Allowlist: `lorica-stream/src/tls/mod.rs` (new),
`lorica-stream/src/tls/client_hello.rs` (new), `lorica-stream/src/lib.rs`
(the module line), `fuzz/fuzz_targets/fuzz_client_hello.rs` (new),
`fuzz/Cargo.toml` (the `[[bin]]` entry and the `lorica-stream` path
dependency).
Depends on: 12.3 Lot C; not concurrently with 12.5 Lots D or E.

- [x] `parse(buf) -> Result<Parsed, NeedMore | Invalid(kind)>` over a
      byte slice, incremental (the caller reads more on `NeedMore`),
      with `CLIENTHELLO_MAX_LEN`, `CLIENTHELLO_MAX_RECORDS`,
      `CLIENTHELLO_BUFFER`; `Parsed { server_name, alpn, ech_offered,
      consumed }` (D-b). No I/O in this module.
- [x] Tests: hellos captured from rustls' client (TLS 1.2 and 1.3, with
      and without SNI and ALPN), a hello split over 2 and over 64
      records, 65 records, a 16,385-byte message, a record of 16,385, a
      non-handshake record mid-hello, SSLv2 shape, duplicate extension,
      SNI with an IP literal (absent), SNI with an invalid byte, an
      uppercase SNI with a trailing dot (canonicalised), ECH present,
      no extensions block, every length field one past its enclosure.
- [x] Fuzz target: arbitrary bytes never panic, `consumed` never
      exceeds the input, and a hello re-serialised from a parse of
      rustls' output parses to the same fields.

### Lot C: model, schema, validation, entitlement - cargo

Allowlist: `lorica-config/src/models/stream.rs`,
`lorica-config/src/models/route.rs` (`organizations_admitted` only),
`lorica-config/src/models/mod.rs`, `lorica-config/src/route_selection.rs`
(`STREAM_SERVER_NAME_SHAPE`, `wildcard_precedence` and its use in
`HostIndex::new`, the `canonical_hostname` doc sentence),
`lorica-config/src/store/mod.rs` (the migration only),
`lorica-config/src/store/streams.rs`, `lorica-config/src/store/row_helpers.rs`,
`lorica-config/src/store/cluster_nodes.rs`, `lorica-config/src/canonical.rs`,
`lorica-config/src/diff.rs`, `lorica-config/src/export.rs`,
`lorica-config/src/import.rs`, `lorica-config/src/tests.rs`, and every
file holding a `Stream { .. }` or `StreamBackend { .. }` literal that the
new fields break, as `grep` lists them when the Lot starts (literal
sites only, no behaviour).
Depends on: 12.3 Lot B and 12.5 Lot C (same files). Runs alone.

- [ ] The fields and types of D-k, D-d's `StreamMatcher` and
      `StreamMatchRule`, `StreamTlsMode`, `StreamTlsTerminate`,
      `StreamUpstreamTls`, `UpstreamServerName`; `StreamBackend::rule`;
      the refusals of D-l; `drains_on_upgrade` (D-j);
      `no_sni_needs_acknowledgement` (D-d).
- [ ] `Stream::validate` and `check_backend_attachments` (D-k).
- [ ] `organizations_admitted` (D-h).
- [ ] Migration, store columns, the link `rule` in
      `set_stream_backends` and its readers; canonical digest; diff;
      export and import.
- [ ] Entitlement in `cert_key_recipients` and
      `certificates_entitling_node` (D-f, D-k), which the control
      plane's pull answer, the issuance push and the node drawer already
      read, so replication follows with no change outside this file.
- [ ] Tests: each default; every D-g cell refused with the field and
      mode named; ambiguity (same name, intersecting ALPN; both empty;
      two `no_sni`), accepted when ALPN sets are disjoint; rule caps at
      both bounds; server names canonicalised on write (`App.Example.COM.`
      stored as `app.example.com`), IP-shaped names refused; the
      acknowledgement rule both ways; link rules (missing, unknown, rule
      without primary, rule on a non-TLS stream); `drains_on_upgrade`
      for each mode with and without upstream TLS; migration idempotence;
      a 12.3-shaped TOML imports with defaults; canonical round trip;
      `HostIndex` ordering unchanged; the entitlement tests of D-k.
- [ ] Replication tests (Resolved 2), on a store with a control plane
      and three active followers A, B and C, certificates X, Y and Z,
      no route naming any of them: a terminating stream targeted at A
      naming X and re-encrypting with client identity Y gives
      `cert_key_recipients(X) == cert_key_recipients(Y) == [A]`,
      `cert_key_recipients(Z) == []`, `certificates_entitling_node(A)
      == [X, Y]` and nothing for B and C; retargeting the stream to B
      moves both to B alone; a fleet-wide stream entitles A, B and C; a
      disabled stream still entitles its nodes; a pending node receives
      nothing; a route and a stream naming the same certificate yield
      the union of their nodes; a corrupt stream selector fails closed
      with `ConfigError::Corrupt`.

### Lot D: the TLS engine in `lorica-stream` - cargo

Allowlist: `lorica-stream/src/tls/**` (`matcher.rs`, `server.rs`,
`client_auth.rs`, `upstream.rs`, `rewind.rs`, new; `mod.rs`),
`lorica-stream/src/tcp/engine.rs`, `lorica-stream/src/tcp/connect.rs`,
`lorica-stream/src/tcp/forward.rs`, `lorica-stream/src/counters.rs`,
`lorica-stream/src/handler.rs` (the record's `tls` field),
`lorica-stream/src/table.rs` (client identities, link rules),
`lorica-stream/Cargo.toml` (the `lorica-tls` edge, the `rustls` feature
on `lorica-core`, `rcgen` dev), `lorica-stream/tests/tls_*.rs` (new),
`Cargo.lock`.
Depends on: A, B, C; 12.3 Lot C; 12.5 Lots D and E (same files).

- [ ] Matcher (D-d) over the parsed hello and the stream's rules.
- [ ] Phase-2 ClientHello reader on the preamble with the deadline
      (D-b); passthrough (D-e).
- [ ] Termination (D-f): per-rule configs, `LocalIpConfigs`, `Rewind`,
      the deadline, classification, the SNI agreement check, buffer
      limit, half-close over TLS.
- [ ] Client auth (D-h); upstream TLS (D-i) inside the attempt, with
      I1's order and I4's decision point; I2 if 12.3 did not.
- [ ] `StreamTable` carries `ClientIdentity` values (`NoDebug`) and
      link rules; counters (D-n); the record's `tls` (D-m).
- [ ] Tests (Linux, real sockets, `rcgen`, fake seams): IV1 in-crate
      (two names to two echo backends that report the ClientHello they
      received, compared byte for byte with what the client sent; a
      third name `no_match` with nothing forwarded); wildcard depth and
      precedence; ALPN by client preference; a client without SNI
      refused without a `no_sni` rule and routed with one; a trickled
      hello past the deadline ends `clienthello_timeout`; a hello in 3
      records is replayed whole; PROXY accept then a ClientHello in one
      segment; terminate with an exact and an IP-SAN certificate (no
      SNI on a `no_sni` rule gets the IP certificate); `no_certificate`
      classified; the two-CA proof of D-h; `allowed_organizations` hit
      and miss; upstream TLS with public-style roots from a test CA,
      `server_name` in each mode, a client certificate seen by the
      backend, `skip_verify`, a verification failure not counted by the
      breaker while a handshake reset is; PROXY header in plaintext
      before the backend's TLS; half-close both ways over TLS; a
      resolver `reload` mid-test makes the next handshake present the
      new certificate while an open connection keeps working; a tracker
      drain in the middle of a handshake ends with the drain reason.

### Lot E: wiring in the binary - cargo

Allowlist: `lorica/src/stream_engine.rs`, `lorica/src/startup/worker.rs`,
`lorica/src/startup/single.rs`, `lorica/src/startup/stream_plane.rs`,
`lorica/src/proxy_wiring/helpers.rs` (`evaluate_mtls` over
`organizations_admitted` only), `lorica/tests/stream_tls_*.rs` (new),
`Cargo.lock`.
Depends on: D; 12.3 Lot D2 and 12.5 Lot F (same files).

- [ ] The engine is built with the process's `CertResolver` and one
      `public_roots()` store, in `run_worker` and `run_single_process`
      (check the order against `StreamRuntime::spawn`; the resolver
      exists earlier in both today).
- [ ] `StoreStreamTable::load` reads the referenced client certificates
      through the resolver's loading path (D-i).
- [ ] The selector keyed per (stream, rule) (I3).
- [ ] `evaluate_mtls` calls `organizations_admitted`; its tests pass
      unchanged.
- [ ] Tests: IV2's mechanism in-process (a certificate replaced through
      the reload path the ACME renewal takes; the next connection to a
      terminating stream presents it); an upstream client certificate
      renewed in the store reaches the stream table through `refresh`.

### Lot F: API surfaces - cargo

Allowlist: `lorica-api/src/streams.rs`, `lorica-api/src/streams/tests.rs`,
`lorica-api/src/streams/tls_checks.rs` (new), `lorica-api/src/routes/mtls.rs`
(visibility only), `lorica-api/src/certificates.rs` (the delete guard
only), `lorica-api/src/config.rs` (the import's stream TLS checks only),
`lorica-api/openapi.yaml`, `lorica-api/src/tests.rs`.
Depends on: C; 12.3 Lot E and 12.5 Lot G (same files).

- [ ] Request and response fields, links per rule,
      `drains_on_upgrade` (D-k, D-j).
- [ ] `tls_checks.rs`: existence, coverage, IP SAN for `no_sni`, the
      bundle checks (D-h, D-k), on create, update and import.
- [ ] Certificate delete guard for streams.
- [ ] `openapi.yaml`, contract test green; the backend's HTTP TLS field
      descriptions say "HTTP routes only".
- [ ] Tests: each D-g refusal answers 400 naming field and mode;
      coverage hit and miss (exact, one-label wildcard, a deep wildcard
      rule against a wildcard certificate); `no_sni` without an IP-SAN
      certificate refused; a bundle with a root and its issuing CA
      saves and logs the warning; deleting a referenced certificate is
      a 409 naming the stream; the response key-set test updated.

### Lot G: documentation - no cargo

Allowlist: `docs/streams.md` (the TLS sections), `docs/security/threat-model.md`,
`docs/hot-upgrade.md` (the D8 paragraph), `docs/cluster.md` (the
certificate entitlement paragraph), `CHANGELOG.md`.
Depends on: D, E, F.

- [ ] **Verify the survey values first**, as 12.3 Resolved 9: each
      competitor value of D-k's table read from the PRD's sources, the
      URL beside it in `docs/streams.md`, "not documented" where the
      source states none, D-k corrected where a value differs, each
      check listed in the Completion Notes.
- [ ] `docs/streams.md`: the three modes and the D-g table; rules,
      precedence, ALPN by client preference, wildcard depth and the
      certificate one-label difference; `clienthello_timeout_ms` with
      its minimum and maximum and their NFR2 reason (Resolved 7); the
      "no SNI" matcher and its
      acknowledgement; ClientHello bounds and `clienthello_timeout`;
      server-first and STARTTLS protocols; ECH; termination,
      `certificate_ids` and fleet entitlement, the no-SNI certificate by
      local address; client certificates and the `required = false`
      difference from routes; upstream TLS, the three `server_name`
      modes, `skip_verify` and its badge, the PROXY-before-TLS order;
      which bytes are counted; `drains_on_upgrade` and what it does not
      promise in 1.11.0.
- [ ] Threat model: slow ClientHello (bounded, 12.6's pending cap);
      handshake CPU on terminating streams (12.6's rates); parser
      disagreement between the preread and rustls (the agreement
      check); SNI is a routing hint, not an identity; ECH hides the
      true name from routing; no 0-RTT.
- [ ] `docs/cluster.md`: a stream's certificates entitle its nodes.
- [ ] `CHANGELOG.md` `[Unreleased]`: Added (TLS passthrough with SNI and
      ALPN routing, termination, upstream TLS and mTLS); Security
      (per-stream client CA, no default backend for clients without
      SNI, certificate keys entitled by streams only to their nodes).

### Lot H: end-to-end, IV1, IV2, the two-CA proof and key replication - Docker e2e

Allowlist: `tests-e2e-docker/test-runner/run-streams-tls.sh` (new, LF),
`tests-e2e-docker/test-runner/tls_backend.py` (new, LF, standard
library only: a TCP backend that reports the first bytes it received,
and a TLS backend over `ssl` that reports the SNI and client
certificate it saw), `tests-e2e-docker/test-runner/Dockerfile` (the
`COPY` and `chmod` lines), `tests-e2e-docker/docker-compose.yml` (the
`streams`, `acme` and `cluster` profiles only), `tests-e2e-docker/run.sh`
(one call per profile).
Depends on: E, F; 12.3 Lot G and 12.5 Lot I (same compose file). The
machine to itself, orphan containers torn down first.

- [ ] IV1: two names in passthrough to two backends, each reporting a
      ClientHello identical to the one `openssl s_client` (or Python's
      `ssl`) sent, captured on the runner side; a third name is closed
      and counted `no_match`.
- [ ] IV2 in the `acme` profile (Pebble): a terminating stream on a
      Pebble-issued certificate; a renewal triggered the way the ACME
      smoke triggers one; new connections present the new serial, an
      open connection keeps echoing. If a renewal cannot be forced in
      that profile, the certificate is replaced through the store write
      the renewal performs, and the Completion Notes say so.
- [ ] AC #5 end to end: two terminating streams with two CAs, each
      client certificate accepted on its own stream only.
- [ ] Upstream mTLS: a terminate-and-re-encrypt stream presents a
      stored client certificate the TLS backend reports.
- [ ] Key replication (Resolved 2), in the `cluster` profile: a
      terminating stream targeted at one follower, naming a certificate
      no route names and a client identity no route names. After
      convergence the targeted follower holds both keys (non-empty
      `key_pem` through its own management API) and completes a
      handshake on the stream; the other follower holds both rows
      without a key. Retargeting the stream to the other follower gives
      it both keys; what the first follower keeps is asserted the same
      way the existing cluster smoke asserts it for a retargeted route
      (the Lot reads that smoke first and records the assertion in the
      Completion Notes).

## Dev Notes

### Where to extend, verified on `7ea2ae70`

- `lorica-tls/src/cert_resolver.rs`: `CertResolver::resolve` (the two
  lookups `lookup_keys` takes over), `resolve_by_local_ip`,
  `ResolvesServerCertByLocalIp`, `LocalIpConfigs::{new, for_connection}`,
  `ip_sans_of_leaf`.
- `lorica-tls/src/http_client.rs`: `config_builder`, `crypto_provider`,
  `pem_roots`, `public_roots`, `unverified`, `AcceptAnything`.
- `lorica-tls/src/lib.rs`: the re-exports (`TlsAcceptor`,
  `TlsConnector`, `ServerTlsStream`, `ClientTlsStream`,
  `WebPkiClientVerifier`, `NoDebug`).
- `lorica-core/src/listeners/tls/rustls/mod.rs`: `TlsSettings::build`,
  the shape a terminating stream copies (versions, verifier, resolver,
  ALPN, `LocalIpConfigs`).
- `lorica/src/mtls.rs`: `RouteClientVerifier::from_pem` (the explicit
  provider pattern); `lorica/src/proxy_wiring/helpers.rs`:
  `evaluate_mtls`.
- `lorica-core/src/utils/tls/rustls.rs`: `get_organizations_serial_bytes`.
- `lorica-api/src/routes/mtls.rs`: `build_mtls_config`,
  `mtls_bundle_trust_warnings`, `log_mtls_bundle_trust_warnings`,
  `validate_mtls_pem`.
- `lorica-config/src/route_selection.rs`: `canonical_hostname`,
  `validate_hostname_syntax`, `HostnameShape`, `wildcard_covers`,
  `HostIndex::new` (the wildcard sort).
- `lorica-config/src/store/cluster_nodes.rs`: `cert_key_recipients`,
  `certificates_entitling_node`, `SelectorUnion`.
- `lorica-api/src/certificates.rs`: `delete_certificate`.
- `lorica/src/startup/worker.rs`: `worker_load_certs_into_resolver`;
  `lorica/src/reload.rs`: `cert_data_for_resolver` and the reload of the
  shared resolver.
- `lorica/src/startup/cluster_follower.rs`: `pull_missing_certs`;
  `lorica/src/startup/cluster_plane.rs`: the pull answer;
  `lorica-api/src/cluster/boundary.rs`: `distribute_certificate`.

### Pitfalls

- **The stream runtime has one thread per process** (12.3 Pitfalls). A
  TLS handshake is CPU on that thread: a terminating stream under a
  handshake flood slows every stream of the worker. 12.6's rates are
  the bound; Story 12.12 measures it. Building a config (roots,
  verifier) is done in `table_changed`, never per connection, and
  `public_roots()` once per process.
- **`LocalIpConfigs` caches one config per local address**; build one
  per (stream, rule) config, never per connection.
- **rustls refuses ALPN mismatch.** A server config with an ALPN list
  and a client offering none of it fails the handshake
  (`no_application_protocol`); the matcher guarantees an offered value
  is in the rule's list, so this happens only if the parsers disagree,
  which the SNI check does not cover. Test it.
- **IPv4-mapped local addresses** on `[::]` listeners:
  `LocalIpConfigs` canonicalises; pass the socket's local address as is.
- **`close_notify` after a FIN**: tokio-rustls returns `UnexpectedEof`;
  it is an end, not an error.
- **Keys in the table**: `ClientIdentity` is `NoDebug`; never derive
  `Debug` through it, never log it.
- **Heredocs with apostrophes break the Bash tool** (project memory):
  write scripts with the Write tool; keep `.sh` files LF.

### Tests per Lot

Listed in each Lot. Lots A to F need Linux and run through the
`run-tests` skill in Docker. Lot H is the e2e suite, run alone. What no
automated test here proves: handshake throughput and accept-to-first-byte
latency on a terminating stream against nginx, which is Story 12.12's
performance phase.

### Handed to other stories

- **12.6:** the pending slot around phase 2 (ClientHello and handshake);
  `no_sni_needs_acknowledgement` called with the allow-CIDR field.
- **12.9:** the record's `tls` field and the counters of D-n; whether
  the client certificate subject is logged.
- **12.10:** the form for D-k's fields; the "no SNI", "drains on
  upgrade" and "unverified upstream" badges.
- **12.11:** `drains_on_upgrade` in the preview.
- **12.15:** the parser and matcher; new `StreamMatcher` kinds.
- **12.16:** `drains_on_upgrade` excludes a stream from transfer.

## Resolved (maintainer, 2026-11-14)

The draft's eight open questions, each accepted as recommended.
The decisions above cite each one as "Resolved N".

1. **A terminating stream must have match rules**, like a passthrough
   one (D-g). Every TLS stream names the hosts it answers, and D7's "no
   default" reads the same in both modes. What it gives up: a
   one-backend terminating stream lists its server names.
2. **Explicit `certificate_ids` on a terminating stream** are the fleet
   entitlement for the keys (D-f), with the API checking that they
   cover the rule names, while the handshake keeps the node's shared
   resolver. Entitlement covers replication end to end: a follower
   receives exactly the keys that the streams targeting it name
   (`certificate_ids` and `upstream_tls.client_certificate_id`), and no
   other key on account of a stream. Proved by Lot C's store tests and
   by Lot H's cluster check.
3. **One backend serves at most one rule of a stream** in 1.11.0. The
   `(stream_id, backend_id)` key stays and the link gains a nullable
   `rule` column. Lifting it later is a table rebuild migration of
   `stream_backends`.
4. **The backend's HTTP TLS fields are not refused** on a backend a
   stream uses. They are documented as HTTP-only in `openapi.yaml` and
   `docs/streams.md`.
5. **`upstream_tls.skip_verify` is offered**, default off, refused with
   a client certificate or a CA bundle, flagged in the API and badged
   "unverified upstream" by Story 12.10.
6. **The dashboard half of AC #6** is Story 12.10 AC #1's "drains on
   upgrade" badge, in the same release; this story delivers the API
   flag it reads (D-j).
7. **`clienthello_timeout_ms` is a per-stream field**, default 5,000 ms,
   range 1,000 to 60,000 ms. `docs/streams.md` documents the minimum and
   the maximum with their NFR2 reason: the maximum bounds how long one
   pending connection holds an fd, a slot of Story 12.6's pending cap
   and the 17 KiB buffer of D-b, so the memory and fds of the pending
   phase stay bounded per stream; the minimum
   keeps a client on a lossy link able to retransmit its first flight.
8. **Stream SNI wildcards match at any depth** (route semantics) while
   certificates serve one label (D-c). The coverage check and
   `docs/streams.md` state the gap.

## Dev Agent Record

### Debug Log

### Completion Notes

**Lot B (the ClientHello parser).**

- API, `lorica_stream::tls::client_hello`: `parse(buf: &[u8]) ->
  Result<Parsed, ClientHelloError>`, `ClientHelloError::{NeedMore,
  Invalid(InvalidClientHello)}`, `Parsed { server_name: Option<String>,
  alpn: Vec<Vec<u8>>, ech_offered: bool, consumed: usize }`.
  `InvalidClientHello` is `not_handshake`, `record_version`,
  `record_length`, `not_client_hello`, `oversized`, `truncated`,
  `malformed`, `duplicate_extension`, `server_name`, with `ALL` and
  `as_str` (the crate's own word-list pattern, as `counters.rs`; no
  `strum` edge). Lot D counts `Oversized` as D-n's `oversized` and every
  other kind as `invalid`. Constants: `CLIENTHELLO_MAX_LEN` (16,384, the
  handshake header's 24-bit length), `CLIENTHELLO_MAX_RECORDS` (64),
  `CLIENTHELLO_BUFFER` (17,408, with a compile-time assertion that the
  largest accepted hello over 64 records fits), `RECORD_HEADER_LEN`,
  `MAX_RECORD_LEN`, `SERVER_NAME_MAX_LEN`, and the three extension
  numbers.
- Incremental by reparsing: the engine calls `parse` on the whole buffer
  after each read. Every refusal is made at the first byte that rules
  the hello out (a record version as soon as its two bytes are in, the
  handshake type at its first byte, an oversized length at the header),
  so every strict prefix of an accepted hello is `NeedMore` and a
  refusal never changes with what follows. Both properties are pinned by
  the tests and by the fuzz target.
- One refinement of D-b, recorded here: **a record that runs past the
  end of the ClientHello is refused** (`malformed`) as soon as the two
  headers show it. Nothing follows a ClientHello in a client's first
  handshake flight, and accepting a coalesced record would let
  `consumed` (the end of the record) exceed `CLIENTHELLO_BUFFER`, so the
  reader would wait for bytes that can never fit. `consumed` is
  therefore at most 16,388 plus 64 headers.
- `alpn` holds bytes, not strings: a client offers GREASE values that
  are not ASCII, and the matcher compares them against the rules'
  visible-ASCII values. The first `host_name` entry of `server_name` is
  the name; other name types are skipped by length. A server name that
  is `.` alone canonicalises to nothing and is refused `server_name`.
- Tests (25 unit, 1 doc): rustls' own client hellos (TLS 1.2 and 1.3,
  with and without SNI and ALPN, an IP literal sending none), every
  prefix of each asking for more; bytes past the hello not consumed;
  reassembly over 2 records, over exactly 64, a handshake header split
  over three records; the 65th record refused at its first byte; a
  16,385-byte message refused from its header and 16,384 accepted; a
  record of 16,385 and of 0; a non-handshake record mid-hello (alert,
  ChangeCipherSpec); SSLv2 and PostgreSQL's SSLRequest; record versions;
  a handshake other than a ClientHello; a record past the message;
  duplicate extensions (known and unknown types); an IP literal SNI
  (absent); seven invalid server names and both length bounds; an
  uppercase name with a trailing dot (canonicalised); ECH present with
  ALPN kept in client order, GREASE included; no extensions block; the
  body's field rules; each of the twelve length fields of a full hello
  raised by one; the largest accepted hello inside the buffer.
- Fuzz target `fuzz/fuzz_targets/fuzz_client_hello.rs`, in `fuzz.yml`'s
  matrix: arbitrary bytes never panic, `consumed` stays within the input
  and the buffer, the prefix and finality properties, and rustls' hello
  for a name and ALPN list the input picks, cut into records at sizes
  the input picks, parses to the canonical name and that list, then a
  hello re-serialised from the parse parses to the same fields. Run on
  nightly for 120 s: 1,743,892 runs, no crash. The fuzz build must run
  without `CARGO_BUILD_WARNINGS=deny`, as the CI fuzz job does: nightly
  raises a warning in `lorica-worker` that stable does not.
- Outside the allowlist: `lorica-stream/Cargo.toml` gains `rustls` as a
  dev-dependency (ring only, already in the lockfile through
  `lorica-tls`) for the captured hellos, and `Cargo.lock` its entry;
  `fuzz/Cargo.toml` gains `rustls` beside the `lorica-stream` path
  dependency; `.github/workflows/fuzz.yml` gains the matrix entry.

**Lot A (`lorica-tls`).**

- `cert_resolver::lookup_keys(name: &str) -> (String, Option<String>)`:
  the name lowercased, then `*` plus the suffix from its first dot,
  `None` without a dot or past 256 bytes. One private
  `probe_lookup_keys(name, probe)` holds the rule and keeps audit M-13's
  allocation-free path (no lowercase copy for a lowercase name, the
  wildcard key in a stack buffer); `resolve`, `lookup_keys` and
  `serves_server_name` all run it, so they cannot disagree. The
  `expect` the old wildcard path carried became an `ok()?` on a
  conversion that cannot fail.
- `ResolvesServerCertByLocalIp::serves_server_name(&self, name: &str) ->
  bool`, defaulted to `true`; `CertResolver` answers from its domain map
  over `probe_lookup_keys`.
- `http_client::accept_any_server() -> Arc<dyn ServerCertVerifier>`;
  `unverified()` is `with_verifier(accept_any_server())`.
- Tests: the existing resolver and client tests are unchanged and pass.
  `serves_server_name_agrees_with_resolve` runs a real in-memory
  handshake per name (exact, one-label wildcard, two-label miss,
  uppercase, unknown, the wildcard's parent) and asserts the handshake
  and `serves_server_name` agree with the expected answer;
  `accept_any_server_behind_config_builder_completes_a_handshake`
  completes one against a self-signed server for its own and another
  name, with no ALPN offered.

## File List

Lot B:

- `lorica-stream/src/tls/mod.rs`, `lorica-stream/src/tls/client_hello.rs`
  (new), `lorica-stream/src/lib.rs`
- `lorica-stream/Cargo.toml` (the `rustls` dev-dependency), `Cargo.lock`
- `fuzz/fuzz_targets/fuzz_client_hello.rs` (new), `fuzz/Cargo.toml`,
  `.github/workflows/fuzz.yml`
- `docs/stories/story-12.4-tls-l4.md`

Lot A:

- `lorica-tls/src/cert_resolver.rs`, `lorica-tls/src/http_client.rs`
- `docs/stories/story-12.4-tls-l4.md`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD and its 2026-11-04, 2026-11-12 and 2026-11-14 amendments, against the 12.3 and 12.5 drafts. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in as Resolved 1 to 8, all as recommended; `certificate_ids` entitlement extended to replication with store tests (Lot C) and a cluster-profile check (Lot H); `clienthello_timeout_ms` bounds documented with their NFR2 reason. Status Draft. | Romain G. |
| 2026-11-15 | 0.3 | Lot A landed: `lookup_keys` as the one statement of which certificate serves a name, `serves_server_name` on the resolver trait, `accept_any_server` behind `unverified`. Status InProgress. | Romain G. |
| 2026-11-15 | 0.4 | Lot B landed: the bounded ClientHello reader `tls::client_hello::parse`, refusing at the first byte that rules a hello out, a record past the hello refused, and its fuzz target in the weekly matrix. | Romain G. |
