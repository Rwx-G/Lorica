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

Tokens live at most 24 hours (one hour by default). Every token is
bound at mint time to the node name it may be redeemed under, and may
additionally be bound to a source CIDR; both are enforced at
redemption, and a token carrying no name binding is refused rather
than treated as good for any name.

The name is mandatory because it is an authorization input, not a
label. A route's `node_selector` lists node names, and that list is
what decides which certificate private keys a node is entitled to
receive. If a joining node could choose its own name it could join
under a name a selector already lists and be handed those keys the
moment an operator activates it. Binding the name to the token moves
that choice back to the operator who mints it. The name must use the
same character set as a selector entry, so the two vocabularies
cannot drift apart, and when an operator reviews a pending node the
roster shows which hostnames that name is already selected for.

Minting opens the enrollment listener; the window closes
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
# On the control plane (or in the dashboard): mint a token, naming
# the node it is for. The name is mandatory and enforced at join.
lorica cluster token --user admin --password-file <path-to-0600-file> \
  --node-name edge-01

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

### What may ride the heartbeat

The heartbeat also carries a node's current CPU, memory and disk usage,
for the dashboard's node drawer. That is a different class of payload
from the rest of the frame, which is fleet-protocol state, so the rule
that admitted it is written here rather than left as precedent:

**The heartbeat carries current values that are cheap to sample and
meaningless as history. Anything with a series, a cursor or a quota
goes to the telemetry fan-in channel instead.**

Two consequences follow, and both are the point. A gauge is replaced on
every beat, so it needs no cursor, no acknowledgement and no retention;
putting it on the fan-in channel would mean building all three for data
that is worthless a beat later. And the heartbeat's own latency is a
liveness input, so anything that rides it must stay cheap to produce:
a payload whose sampling can block is a payload that can turn a slow
disk into a false disconnect.

A reading is optional on the wire. A node whose runtime installs no
sampler omits it and the dashboard shows a dash; scalar fields would
report zero, which reads as an idle node rather than an unknown one.
It is session state on the control plane, never persisted: it is
re-learned within one interval after a reconnect, and a figure from
before a restart would look live while describing a process that no
longer runs.

### Targeting a subset

A route carries a `node_selector`: a list of node names, empty meaning
fleet-wide. A follower whose name is absent does not serve that route
and deletes it locally.

**It scopes serving, not disclosure.** The blob is fleet-wide: every
follower receives every route and filters on arrival. So a node that
serves nothing still holds, in memory and on the wire, the definition of
every other node's routes, including upstream addresses, IP allow and
deny lists, mTLS configuration and Basic-auth password hashes. Compromise
of the least-trusted edge therefore discloses the fleet's routing
topology. Treat `node_selector` as a deployment filter and the blob as
readable by any enrolled node.

That is acceptable while the payload carries no secret material, which
is the case here: private keys and channel credentials travel as digests
only. It stops being acceptable the moment real keys are distributed,
because a predicate the recipient evaluates on a payload it already holds
is not need-to-know. Certificate distribution therefore has to filter on
the CONTROL PLANE, per recipient, and match on the node id rather than
the display name (a name is chosen by the joining node and is not
unique). Each node then converges on its own payload, which is a real
change to the single fleet-wide hash this chapter describes.

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

## Certificate Issuance and Key Distribution

Certificates are issued once, on the control plane, and the resulting
key material is delivered to the nodes that need it. Three edges serving
the same hostname produce one certificate, not three, and burn one
issuance against the certificate authority's rate limit instead of
three.

### What runs where

On a follower, certificate issuance, automatic renewal and the
expiry notifier are all off. They are the control plane's job, and a
follower running them would renew certificates the control plane
already renewed and raise one duplicate fleet-wide expiry alert per
node.

Stapling is the exception, and deliberately so. The OCSP refresh loop
runs on every node, because stapling is a serving concern and the
followers are precisely the nodes terminating client TLS. Disabling it
on followers would strip stapling from the whole data plane with
nothing to replace it.

### Need to know

A follower receives the private key for a hostname only when it is
selected to serve a route bound to that certificate. An edge in a
low-trust network does not hold the key for a hostname it never
answers for.

The selection is resolved **on the control plane**, and this is the
part that matters. A route carries a list of node names; the control
plane resolves those names against its own registry into node ids, and
a node id is what the mutual-TLS certificate on the session actually
proves. The recipient is never asked to decide whether it is entitled
to a key. A follower may ask for a certificate by id, and that list is
treated as a hint about what it is missing, never as an authorization
input: an id it is not selected for is answered with silence, which
also means the answer does not reveal whether that certificate exists.

Node names are unique from this version on, and enrollment refuses a
name already taken. That is for the operator writing a route selector,
not for the security model, which does not rest on names.

### What distribution actually means

Stated plainly, because it is a real trust decision and not an
implementation detail: the control plane holds every distributed
private key in usable form. It decrypts the key from its own store,
ships it over the mutually-authenticated TLS session, and the follower
writes it through the same path any local key takes, which encrypts it
at rest under that node's own master key.

So the mutual-TLS channel is the confidentiality boundary. There is no
envelope encryption to a per-node public key, because no such key
exists: enrollment presents a public key to prove possession during
issuance, and the control plane does not keep it. A compromised control
plane therefore yields the private keys of every hostname in the fleet.
That is inherent to central issuance, it is why the control plane is
the node to protect hardest, and it is why need-to-know exists at all:
it bounds what a compromised *follower* yields, which is the far more
likely event.

Each key travels with the same digest the configuration blob carries
for it. The receiving node recomputes that digest before writing
anything, so a key that does not match the configuration announcing it
is refused rather than installed.

### Two channels, on purpose

Key delivery does not ride the configuration commit. If it did, one
slow follower could hold up renewals for the entire fleet until
certificates expired, which is the same veto problem the configuration
path was designed to avoid, with a worse outcome.

The control plane pushes a key when it issues or renews one. That is
the fast path and it is best effort: a node that is down, unreachable
or not yet connected is simply not in that round, and nothing about the
issuance fails because of it.

The guarantee is the other direction. After a follower applies a
configuration it knows exactly which certificates it holds no key for,
because the apply just counted them, and it asks for those on the
session it already has open. A node that was offline through an
issuance therefore catches up at the first configuration it converges
on, before it is asked to serve that hostname.

A certificate whose key has not arrived yet is skipped by the TLS
resolver with a warning, and routes bound to it serve under the default
certificate until the key lands.

### Break-glass does not stop keys

Break-glass suspends configuration replication, but not key delivery.
A private key overwrites no operator edit, so the reason the window
exists does not apply to it, and freezing delivery for a window of up
to a day could expire a certificate in the middle of the incident the
window was opened for. This is the one control-plane-originated flow
that a break-glass window does not suspend.

### HTTP-01 across a fleet

The certificate authority chooses which node it validates against, so
an HTTP-01 token has to be present on every node that could answer for
that hostname before validation is requested. The control plane
distributes the token to those nodes and only then declares the
challenge ready.

Two kinds of failure are told apart, because they are not the same
situation. A node that is connected and refuses the token, or whose
exchange times out, aborts the order: it is up, the authority will
reach it, and it will answer 404. Aborting turns an opaque validation
failure into a specific one naming that node. A node that has no live
cluster session does NOT abort the order. It is answering nothing at
all, so an authority that resolves the hostname to it gets a
connection failure whether or not a token was published there;
refusing to attempt validation would prevent no failure while stopping
every renewal on a fleet-wide route for as long as one follower stays
down. The attempt proceeds, and the skipped nodes are named in a
warning.

That warning is worth acting on. If DNS still points at a node that is
down, validation will fail, and modern authorities validate from
several vantage points that each resolve the name independently. A
node that is out of the fleet for more than a moment should also be
out of the hostname's DNS.

Challenge entries carry their own deadline. Before that, an order that
crashed between publishing a token and cleaning it up left a node
serving that key authorization indefinitely, because cleanup was the
only thing that ever removed one.

DNS-01 is unchanged. The control plane holds the provider credentials
and completes the challenge itself; no follower is involved.

### The export zone

The filesystem export zone keeps working on every node. Its settings
are node-local and never replicate: the directory, whether export is on
at all, the ownership and the file modes belong to the machine. The
per-pattern access rules do replicate, because they are fleet policy.

On a follower the export runs when a key is installed, not when
configuration is applied. Exporting at apply time would write an empty
private-key file for every certificate whose key had not arrived yet.

## Telemetry Fan-In

Every node keeps its own logs. A follower additionally ships them to
the control plane, so one place can answer "what happened across the
fleet at 03:14" without three SSH sessions.

### What travels, and what stamps it

Access-log rows and WAF events travel; so does a snapshot of the live
bans. Nothing else. Audit entries are Story 9.9's, and they need a
different mechanism because the audit chain cannot simply be copied.

**No message carries a node identity.** The control plane stamps every
row it stores with the `node_id` that node's mutual-TLS session
proved. A node id in the payload would be a node-supplied identity,
and a compromised follower could then file rows under another node's
name, which is precisely the confusion an incident view must not
have. It is the same rule the node name follows at enrollment.

For the same reason the LOCAL tables on each node carry no `node_id`
column: in a per-node database that value is a constant, and paying
per-row storage on the request path to record a constant is waste.

### Where it lands

In `cluster-telemetry.db`, beside `lorica.db` and `access-log.db` in
the data directory, with its own connection.

Not in the control plane's own access-log database, and the reason is
arithmetic. That store is one connection behind one mutex shared by
every insert, every dashboard query, every retention pass and the
audit verify. Fan-in multiplies the write rate by the fleet size, and
the control plane serves its own traffic on top. Putting the fleet's
telemetry there would make the fleet's traffic volume a latency input
to the control plane's own dashboard and audit paths.

### The drain never touches the request path

A follower's request path writes to its local log store exactly as a
standalone node does. A background task on the supervisor then walks
that store by row id and ships batches every ten seconds.

That store already is a bounded, drop-on-overflow buffer written off
the hot path, shared across worker processes, with its own drop
counter. Putting a second queue in front of it would have duplicated a
bound that already exists and still not solved worker mode, where the
ban map and the log writer live in the worker processes while the
cluster connection lives in the supervisor.

With the control plane unreachable the drain simply stops advancing
its cursor. Nothing is queued and nothing grows: the rows wait in the
local store, where local retention bounds them exactly as it does on a
standalone node. The cursor is persisted, so a restart does not
re-send everything retention still holds, and a node that has never
drained starts at the present rather than replaying its history.

The cursor advances only past what the control plane **accepted**. If
a quota sheds part of a batch, the cursor stays behind and those rows
are offered again on the next tick.

### The ceiling, stated rather than discovered

SQLite is not a fleet log sink, and access-log fan-in is the part that
tests that. Write amplification is exactly N: every request is written
once on its own node and once on the control plane, which is also
serving its own traffic.

The supported envelope for access-log fan-in is **up to five nodes at
a sustained few hundred requests per second each**. This figure is
derived from the write ceiling the log-writer module documents for
SQLite with batched inserts, halved for the retention passes and
dashboard queries that contend for the same connection. It has not
been measured on production hardware, and that is stated plainly here
rather than implied by a number that looks measured.

The drain is not the binding constraint, though it was: it used to
ship one batch per ten-second tick, about fifty rows a second, so a
node at the envelope above would never have caught up and its backlog
would have grown until local retention silently dropped rows the
control plane had not yet seen. A tick now keeps shipping while
batches come back full, so the drain sustains roughly a thousand rows
a second per node and yields as soon as it is caught up or the
control plane asks it to back off.

Beyond that envelope, the supported topology is: **fan in WAF events,
bans and health, and send access logs to the Story 9.8 syslog or OTLP
sinks instead.** WAF events are orders of magnitude rarer than access
rows, so they fan in comfortably at any fleet size this product
targets. That split is a supported configuration, not a degraded one.

### Retention is per node

Each node gets its own row budget in the fan-in database, not a share
of a global one.

A global cap would make the fleet view shallower than each node's own
local log, and would let one noisy edge evict every quiet edge's rows
— exactly the incident-correlation case fan-in exists for. Retention
deletes in chunks and releases the database lock between them, so a
large reclaim does not stall ingest.

### What protects the control plane

The follower-side bound protects the follower. Two separate
mechanisms protect the control plane, because they answer different
questions.

A **per-node quota** bounds rows and bytes per minute for each node
independently. Bytes as well as rows, because rows are variable length
and a node sending maximum-length paths in every row costs far more
disk than the same count of ordinary ones. A node over its budget has
the excess dropped and counted; the others are unaffected.

A **storage watermark** sheds every node at once when the fan-in
database reaches its cap, including a node well inside its quota. It
caps that database's own size rather than watching free disk: free
disk moves for reasons that have nothing to do with the fleet, so a
floor on it would shed telemetry because something else filled the
volume, and would keep accepting long after the database had become
unmanageable. Reaching the cap means retention is not keeping up, and
shedding is what stops the growth while an operator finds out why.

Telemetry is the first thing dropped and configuration and audit
writes are the last. A fleet that cannot record what happened is
inconvenient; a fleet that cannot be configured or audited is broken.

Both mechanisms are visible:
`lorica_cluster_telemetry_dropped_total{node_id, reason}` separates
one node over its budget (`node_quota`) from the watermark shedding
everyone (`storage_watermark`), and
`lorica_cluster_telemetry_ingested_total{node_id}` is the denominator
without which a drop count says nothing.

### Reading it

```
GET /api/v1/cluster/logs?node=<node_id>&route=shop.example.com&from=...&to=...
GET /api/v1/cluster/waf-events?node=<node_id>
```

Both are cursor-paginated and return no total. Pass the previous
page's `next_cursor` as `before_id`; a null `next_cursor` is the last
page. The absent total is deliberate: a `COUNT(*)` per page on an
aggregated table is a full scan under the store lock, so a dashboard
polling it would stall the ingest writer.

### Bans

Bans fan in for visibility, and an operator can ban across the fleet:

```
POST /api/v1/cluster/bans   {"client_ip": "192.0.2.10", "duration_s": 3600}
```

Two things about this are worth knowing before relying on it.

**Automatic per-node auto-ban is not replicated.** A WAF flood or a
rate-limit trip bans that client on the node that saw it, and nowhere
else. Replicating it would turn one node's view of one client into a
fleet-wide outage for that client, so a false positive on the least
trusted edge would become everyone's false positive. Fleet-wide
banning is an operator decision, taken deliberately.

**A fleet-wide ban is best effort and does not converge.** A node that
was down when the ban was issued does not receive it when it comes
back; the response names the nodes that did not answer. Unlike
configuration and certificate keys, a ban has no pull path, because
the ban map is in-memory state that a node rebuilds from nothing on
restart. For anything that must survive a restart, use a deny rule in
the configuration, which does replicate.

The same restart caveat applies to the fan-in view: it is a snapshot
of live state, so it is lossy across a node restart by construction.

## Fleet Metrics

Per-node scrape or Prometheus federation, not a fleet-wide `/metrics`
on the control plane.

The reason is cardinality. Data-plane counters already carry route and
rule labels; `lorica_ai_bot_total{crawler, route_id, action}` alone is
roughly twenty thousand series on a node with twenty routes. Adding a
`node` label at fleet level multiplies that by the fleet size, and it
would invert the choice this product already made one level down,
where per-worker counters are aggregated into a single supervisor-side
counter with no `worker` label rather than being labelled per worker.
`/metrics` is also pass-through by default, which would put the whole
fleet's traffic profile on an unauthenticated endpoint.

Only the cluster-plane series carry `node_id`, and those are bounded
by fleet size.

Scrape each node directly where you can. Where the nodes are not
reachable from the monitoring network but the control plane is, federate:

```yaml
scrape_configs:
  - job_name: lorica-fleet
    honor_labels: true
    metrics_path: /federate
    params:
      "match[]":
        - '{__name__=~"lorica_cluster_.*"}'
        - '{__name__=~"lorica_waf_.*"}'
        - '{__name__=~"lorica_requests_.*"}'
    static_configs:
      - targets:
          - "prometheus-edge-01.internal.example.org:9090"
          - "prometheus-edge-02.internal.example.org:9090"
```

`honor_labels: true` matters: without it the federating Prometheus
overwrites the `instance` label and every node's series collapse into
one.

## Migrating a Standalone Node into a Fleet

An existing standalone install becomes the control plane without
reinstalling.

1. **Back up** `/var/lib/lorica/` while the service is stopped. The
   encryption key becomes the identity root of the fleet, so this
   backup is now more valuable than it was.
2. `lorica cluster init` on the node that will be the control plane.
   It generates the cluster CA from the existing master key.
3. Start it with `--cluster-listen`. Its own routes and certificates
   are untouched; it is now a control plane that also serves traffic.
4. On each new node, `lorica cluster token --node-name edge-01` on the
   control plane, then `lorica cluster join` on the node. The name is
   mandatory and is bound to the token.
5. Approve each node (`POST /api/v1/cluster/nodes/{id}/activate`, or
   the dashboard). Nothing flows to a node before activation.

The direction that does not work is merging two configured nodes: a
follower's local configuration is REPLACED by the control plane's on
its first apply. Bring a node in empty, or expect to lose what it had.

What each node keeps as its own: the listening addresses, the data
directory, the export zone's directory and file modes, the log sinks'
endpoints, and its master key. Everything else replicates.

