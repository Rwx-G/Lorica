# Lorica Cluster Plane

**Author:** Romain G.
**Since:** v1.7.0

## Overview

A Lorica fleet has exactly one **control plane** node and any number of
**follower** nodes. The control plane owns the authoritative
configuration and the fleet's certificate authority; followers hold a
replicated copy and serve traffic with it.

Two properties shape the whole design:

- **Followers are outbound-only.** A follower dials the control plane
  over a long-lived, mutually authenticated TLS connection and never
  opens an inbound cluster port. A follower in a DMZ needs no new
  firewall opening.
- **The cluster plane is opt-in and separate from the management API.**
  The management API stays localhost-only (127.0.0.1:9443); fleet
  traffic never rides on it. A node that never passes
  `--cluster-listen` exposes no cluster surface at all.

## Ports and Listeners

The control plane's cluster surface is bound via `--cluster-listen
<host:port>` (9444 by convention in the documentation and packaging
examples). The flag is strict on purpose:

- A bare port is refused; the bind must be an explicit `host:port`.
- `0.0.0.0` and `::` are refused unless the separate explicit
  opt-in flag for wildcard binds is also present.
- A bind equal to the management port is refused.
- The effective bind is logged at WARN so it is unmistakable in the
  journal.

Two distinct listeners live behind that surface:

- The **operational listener** carries all steady-state fleet traffic.
  Client authentication is mandatory at the TLS layer: the server is
  built with a rustls `WebPkiClientVerifier` that does NOT allow
  unauthenticated peers, and the only trust anchor is the fleet's own
  cluster CA. A peer without a valid node certificate never completes
  the handshake. Protocol version and schema negotiation happen after
  certificate verification.
- The **enrollment listener** exists so that a node with no certificate
  yet can join. It binds the same host as the operational listener on
  the next port (`--cluster-listen 192.0.2.1:9444` puts enrollment on
  9445). It is the only unauthenticated network surface in the
  product and is treated accordingly: it is closed unless at least one
  join token is live, auto-closes when the last unexpired token is
  burned or expires, and enforces pre-authentication budgets (handshake
  timeout, concurrent-handshake cap, a per-source cap keyed by IPv4
  address or IPv6 /64, in-flight enrollment cap, per-connection byte
  and time budgets) before any token verification runs. On the wire it
  answers refusals with an opaque code; the real diagnostic is logged
  locally only. The operational listener applies the same handshake,
  concurrency and per-source bounds to every connection before and
  during its TLS handshake, so a handful of silent sockets cannot lock
  legitimate followers out; past the handshake, an authenticated node
  may open at most ten sessions per minute (a reconnect loop is
  answered `RETRY_LATER` instead of costing a registry write each
  time). When the last token dies, the enrollment socket closes at
  once and the connections still in flight get five seconds to finish:
  the one that just burned that token is still writing its
  certificate, and everything else is refused by the post-handshake
  liveness check.

During a hot binary upgrade the operational socket is handed to the
new process so there is no rebind gap; established follower sessions
are closed by the outgoing process as soon as the new one is confirmed
and reconnect once, to the new process. Followers dial the control
plane by name and resolve it on every attempt, so a control plane that
moves to another address is followed by the fleet on its next
reconnect.

Telemetry and configuration will never share a queue: the transport is
one FIFO byte stream per endpoint by design, so telemetry (Story 9.6)
rides its own connection rather than competing with a large
configuration or certificate push and turning a delayed heartbeat into
a false liveness timeout. In v1.7.0 the operational connection carries
the handshake and heartbeats.

Two further flags shape the plane: `--cluster-enrollment-listen
host:port` overrides the derived enrollment bind (to put the
unauthenticated surface on an admin interface, for instance), and
`--cluster-advertise <host>` sets the name followers dial - it lands in
the control plane's certificate SAN, so it is required whenever
followers reach the control plane through DNS, NAT or a load balancer
rather than the bound IP itself. Both listeners refuse the management
and proxy ports, the derived enrollment port included.

## Trust Model

`lorica cluster init` generates the fleet's certificate authority on
the control plane. Node certificates are issued `clientAuth`-only and
the control-plane certificate `serverAuth`-only, so neither side can
impersonate the other even inside the fleet.

**Read this paragraph before clustering a production node.** The
cluster CA private key is stored in the control plane's database,
encrypted with AES-256-GCM under the node master key at
`<data_dir>/encryption.key`. That file is 32 raw bytes with mode 0600:
there is no KDF, no passphrase, and no machine binding. On a
single-node install it protects that node's certificate keys and
channel secrets; on a clustered control plane it is promoted to the
**identity root of the entire fleet**. An attacker holding that file
and the database can mint certificates that every follower trusts.
Protecting `encryption.key` is protecting the fleet: keep the
filesystem permissions and the packaged systemd sandbox intact, follow
the firewall guidance in `docs/security/hardening-guide.md`, and back
the file up like the root credential it is.

Key rotation covers the CA: `lorica rotate-key` re-encrypts every
secret listed in the store's encrypted-column registry, including the
cluster CA private key, and the registry is guarded by tests so a new
encrypted column cannot silently escape rotation.

## Enrollment

Joining a fleet is one short-lived token and one command. The design
is shaped by what a token must NOT become: a standing credential, a
CA-wide pass, or a certificate-signing request an attacker can enrich.

### Tokens

A SuperAdmin mints a join token on the control plane, from the
dashboard's join dialog, from `POST /api/v1/cluster/tokens`, or with
`lorica cluster token --user <superadmin> --password-file <path>` (the
password also comes from `--password-stdin` or `LORICA_ADMIN_PASSWORD`;
`--password` on the command line is accepted with a warning, because it
would leak the credential that mints the tokens the next paragraph
keeps off argv). A token
is `<public_id>.<payload>`: the public half is the registry's lookup
key, the payload carries a 256-bit secret and the SHA-256 of the
control plane's current leaf public key. The registry stores only an
HMAC-SHA256 of the secret under a server-side key (itself encrypted at
rest and rotated with the master key); a stolen database yields no
usable token, and a redemption is exactly one lookup and one
constant-time verification whether or not the id exists, so the
enrollment path cannot be turned into a CPU or memory amplifier.

Tokens live at most 24 hours (one hour by default) and can be bound at
mint time to an expected node name and a source CIDR, both enforced at
redemption. Minting opens the enrollment listener; the window closes
on its own when the last token is redeemed, withdrawn
(`DELETE /api/v1/cluster/tokens/{public_id}`) or expires.

**The token is shown once and never belongs on a command line.**
`lorica cluster join` reads it from `--token-file`, `--token-stdin` or
the `LORICA_JOIN_TOKEN` environment variable and refuses everything
else, because argv is readable through `/proc`, lands in shell
history, and is logged verbatim by CI and configuration-management
`command` modules.

### Joining

```bash
# On the control plane (or in the dashboard): mint a token.
lorica cluster token --user admin --password-file <path-to-0600-file>

# On the new node, with the service stopped:
lorica cluster join --control-plane cp.example.com:9444 --token-stdin < token.txt
systemctl start lorica
```

The joiner authenticates the control plane before it holds any CA: it
pins the leaf public key carried by the token (not the CA - pinning
the CA would admit any certificate the cluster CA ever issued, i.e. a
compromised follower posing as the control plane), checks the SAN
against the `--control-plane` host (or `--server-name`), the validity
window and the `serverAuth` EKU. It then sends its bare public key,
never a CSR: the control plane assigns the subject, the `clientAuth`
EKU, `CA:FALSE`, the serial and the 90-day validity itself, and only
accepts Ed25519, P-256 and RSA keys of at least 2048 bits. The private
key never leaves the node. The token is burned by one conditional
database update before any certificate is signed, so three
simultaneous joiners with one token yield exactly one enrolled node.

A freshly enrolled node is **Pending**: it holds a certificate, can
open its session, and shows up in the roster, but receives no
configuration and no certificates until a SuperAdmin activates it
(`POST /api/v1/cluster/nodes/{id}/activate`). A control plane started
with `--cluster-auto-activate` skips that step; the flag is logged at
WARN because it turns a one-hour token into a fleet member without an
operator looking.

### Identity, renewal, revocation

A node's identity is the SHA-256 fingerprint of its certificate,
recorded at enrollment and matched on every session; nothing in any
payload can rename a session. A valid certificate with no registry
entry is dropped before a single byte is read, and audited.

Node certificates last 90 days and renew themselves at two thirds of
that lifetime over the established session (the exact lead is drawn
per node between 25 and 30 days before expiry, so a batch of nodes
enrolled together does not renew in the same minute): the node
generates a new key, sends the public half, and the control plane
issues the replacement only to an `Active` node whose certificate is
actually due, at most once an hour. The node then reconnects on the
new certificate at once; the previous one stays valid until that first
session, then goes on the revocation list as superseded, so a crash
between issuance and persistence cannot lock a node out: a node that
comes back on the superseded certificate is re-issued a grant on
request, without the "is it due" check, and leaves the grace window on
its own. A refused renewal is retried an hour later, not at the next
check.

Revocation (`DELETE /api/v1/cluster/nodes/{id}`, or the dashboard) is
enforced at the TLS handshake: the node's serials go on a CRL signed
by the cluster CA, the operational listener's configuration is rebuilt
with it and swapped without dropping the socket, and the node's live
session is ended synchronously rather than at its next heartbeat. The
registry row stays, marked revoked, for the audit trail.

### Leaving

`lorica cluster leave` wipes the node's fleet identity (its private
key and the CA bundle). It is authorised one of two ways: a SuperAdmin
credential on the local management API (`--user` with
`--password-file`, `--password-stdin` or `LORICA_ADMIN_PASSWORD`), in
which case the running instance tells the control plane over the live
session so it revokes, audits and alerts, then wipes and audits
locally; or, without credentials, proof that the control plane already
deregistered the node: it must answer the node's certificate with a
certificate-level TLS alert. A reset, a closed connection or an
unreachable control plane proves nothing and the command refuses, so a
disturbed network cannot be turned into an identity wipe. A node the
control plane still accepts cannot be dropped from a local shell
alone. Replicated certificate private keys arrive with
certificate distribution (Story 9.5) and are wiped by the same
command.

### Status

`lorica cluster status` prints the persisted role (control plane,
follower with its node id, or standalone) and, with management
credentials, the live connection state and the roster from
`GET /api/v1/cluster/status`.

### Firewalling the window

- An enrollment window opens when an operator mints a join token and
  closes on its own: the enrollment listener starts refusing
  connections as soon as the last unexpired token is burned or
  expires. There is no standing unauthenticated surface.
- While a window is open, mirror it at the firewall: allow the joining
  node's address for the duration of the window and remove the rule
  once the token is burned (examples in the hardening guide).

## Configuration Replication

The control plane owns the fleet's configuration. An operator changes a
route, a backend, a WAF rule or a fleet-policy setting once, on the
control plane, and every active node serves it.

### What replicates, and what never does

The payload is one canonical blob: a byte-stable JSON encoding of the
replicated tables, hashed with SHA-256. Node-local machine facts are
excluded **by construction**, not by a filter: the canonical settings
type simply has no field for the certificate-export directory, the
ownership and mode it writes with, the management port and its
certificate paths, the GeoIP and ASN database paths, the upgrade
signing key, the scrape token, the bot HMAC secret or the log-sink
endpoints. A compromised control plane therefore cannot turn
replication into an arbitrary-path file write on every edge. Users,
sessions and preferences are never touched either: operator accounts
stay node-local.

Secret material is never in the blob. Certificate private keys,
notification-channel payloads and DNS-provider credentials are carried
as a `sha256:` digest, which moves when the secret changes (so drift
detection still covers it) and discloses nothing to a follower that
holds the blob.

Certificates replicate as **metadata only** in this story. A follower
keeps its local private key when the digest matches; a certificate
whose key it does not hold gets its row with an empty key, is skipped
by the TLS resolver with a warning, and the routes bound to it serve
under the default certificate until certificate distribution delivers
the key over its own need-to-know path.

Notification channels and DNS providers are in the blob for the drift
hash but are never applied: they are control-plane concerns. A fleet
that configures either of them centrally will see its nodes report
drift permanently until each node carries its own.

### The two phases, and what the guarantee actually is

Every mutation increments a persisted generation, encodes the blob and
its hash, and fans out a Prepare to every connected active node under a
per-node ten-second deadline. A node that stages it answers prepared; a
node that refuses the blob **semantically** (an unknown field, a
version or hash mismatch) aborts the round fleet-wide and raises an
alert on the follower that refused it. A node that fails Prepare on
**transport** is evicted from the commit set and the commit proceeds
without it: a wedged or hostile follower cannot veto every
configuration change in the fleet. Three consecutive evictions
quarantine a node, which then converges by pull instead of by push.

The honest statement of the guarantee: **all-or-none holds on Prepare,
best-effort on Commit, eventually consistent after.** There is no
rollback once nodes have committed. A Commit that fails after others
succeeded leaves the fleet split; that is counted, reported on the
replication endpoint, and reconciled by the next heartbeat, not undone.

Pending nodes never receive a blob (a node awaiting activation gets no
configuration), and neither do quarantined nodes or nodes in a
break-glass window.

### Convergence

A follower reports what it runs in its session opener and in every
heartbeat; the control plane answers with its current version. A node
that is behind pulls the current generation and applies it, so a missed
commit converges within one heartbeat interval and a reconnect
converges at the handshake. When the follower already holds the current
hash the answer carries no blob at all.

Applying a replica is one transaction: the fleet-policy settings are
merged into the local settings (node-local fields untouched), the
replicated tables are brought to the blob's state, then the generation
and hash are recorded and the existing reload path swaps the running
configuration. A failure rolls the whole thing back; the node keeps
serving what it had.

### Targeting a subset

A route carries a `node_selector`: a list of node names, empty meaning
fleet-wide. A follower whose name is absent does not serve that route
and deletes it locally. This is the same predicate certificate
distribution needs for need-to-know key delivery, so it is defined once
on the entity it scopes.

### Follower read-only, and break-glass

On a follower, a configuration mutation through the management API
answers `409 Conflict` naming the control plane. What stays reachable
is what is follower-local by design: every read, authentication,
operator accounts, the audit log, the cluster commands the node owns
(leave, status, break-glass), the validation and connectivity test
endpoints, configuration export and import preview, and load-test start
and abort.

`lorica cluster break-glass --duration <seconds>` (max 24 hours)
re-enables local mutations on a follower. It exists because an attacker
who takes the control plane down would otherwise freeze incident
response on every edge at once: no route disable, no ban, no
certificate replacement, no WAF change, anywhere. The window is audited
locally, bannered in `cluster status` and in the dashboard, reported to
the control plane in every heartbeat, and excludes the node from commit
sets while it is open. It is persisted, so a restart in the middle of
an incident does not silently reconcile the edits away, and
`cluster status` reads it from the local database so the banner is
legible with the management API down. When the window ends, the next
heartbeat tells the follower it is behind, and it pulls the current
generation and applies it wholesale: local edits are reconciled away.
That is the documented meaning of the control plane owning the
configuration, and the reason break-glass is a window and not a mode.

### Watching it

`GET /api/v1/cluster/replication` returns the last round (prepared,
evicted, rejected, committed, split) and the generation in flight, so
the dashboard can show the fleet outcome of a mutation without the
mutation itself blocking on fleet latency. `GET /api/v1/cluster/drift`
lists nodes whose applied generation or hash differs, with the age of
the divergence. Drift alerts are suppressed per node by an exponential
backoff, from one minute up to one hour, so a flapping node cannot
consume the notification budget that genuine certificate-expiry and
backend-down alerts share. Prometheus carries
`lorica_cluster_config_generation{node_id}`,
`lorica_cluster_config_apply_total{node_id, outcome}` and
`lorica_cluster_drift_nodes`.

## Node Identity in Telemetry

Log-sink events (RFC 5424 syslog and OTLP) carry the emitting node's
identity via the sink configuration's node-identity fields, so a
collector receiving the whole fleet's stream can attribute every event
to its node. Fleet metrics label series with the server-side `node_id`
recorded at enrollment, never a node-supplied name, so a compromised
follower cannot mint unbounded label cardinality.
