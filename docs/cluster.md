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
  yet can join. It is the only unauthenticated network surface in the
  product and is treated accordingly: it is closed unless at least one
  join token is live, auto-closes when the last unexpired token is
  burned or expires, and enforces pre-authentication budgets (handshake
  timeout, concurrent-handshake cap, in-flight enrollment cap,
  per-connection byte and time budgets) before any token verification
  runs. On the wire it answers refusals with an opaque code; the real
  diagnostic is logged locally only.

Telemetry and configuration never share a queue: they ride separate
connections so a large configuration or certificate push cannot
head-of-line-block a heartbeat into a false liveness timeout.

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

This section describes the listener lifecycle that ships with the
transport layer; the token issuance and certificate enrollment flow is
documented in the enrollment section as it lands.

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
