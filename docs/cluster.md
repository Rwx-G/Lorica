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
  legitimate followers out.

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
`lorica cluster token --user <superadmin> --password <...>`. A token
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
lorica cluster token --user admin --password '...'

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
that lifetime over the established session: the node generates a new
key, sends the public half, and the control plane issues the
replacement. The previous certificate stays valid until the node's
first session on the new one, then goes on the revocation list as
superseded, so a crash between issuance and persistence cannot lock a
node out.

Revocation (`DELETE /api/v1/cluster/nodes/{id}`, or the dashboard) is
enforced at the TLS handshake: the node's serials go on a CRL signed
by the cluster CA, the operational listener's configuration is rebuilt
with it and swapped without dropping the socket, and the node's live
session is ended synchronously rather than at its next heartbeat. The
registry row stays, marked revoked, for the audit trail.

### Leaving

`lorica cluster leave` wipes the node's fleet identity (its private
key and the CA bundle). It is authorised one of two ways: a SuperAdmin
credential on the local management API (`--user/--password`), in
which case the running instance tells the control plane over the live
session so it revokes, audits and alerts, then wipes and audits
locally; or, without credentials, proof that the control plane already
deregistered the node (its certificate is refused at the handshake).
A node the control plane still accepts cannot be dropped from a local
shell alone. Replicated certificate private keys arrive with
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

## Node Identity in Telemetry

Log-sink events (RFC 5424 syslog and OTLP) carry the emitting node's
identity via the sink configuration's node-identity fields, so a
collector receiving the whole fleet's stream can attribute every event
to its node. Fleet metrics label series with the server-side `node_id`
recorded at enrollment, never a node-supplied name, so a compromised
follower cannot mint unbounded label cardinality.
