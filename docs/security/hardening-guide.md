# Lorica Hardening Guide

**Author:** Romain G.
**Version:** 1.1
**Date:** 2026-09-30

## Overview

This guide covers security best practices for deploying Lorica in production. Lorica ships with secure defaults, but operators should review these settings for their specific environment.

## 1. Network Configuration

### Management API

The management API binds to **localhost only** (127.0.0.1:9443) by default. Never expose it to the network.

```bash
# CORRECT - default, localhost only
lorica --management-port 9443

# WRONG - do NOT put management behind a public reverse proxy
# The dashboard has no CSRF tokens for cross-origin requests
```

If remote access to the dashboard is needed, use an SSH tunnel:
```bash
ssh -L 9443:localhost:9443 user@lorica-host
```

### Proxy Ports

- **HTTP (8080)**: Use for redirect-to-HTTPS only, or for internal-only traffic
- **HTTPS (8443)**: Primary public-facing port with TLS termination

### Cluster Plane (v1.7.0+, opt-in)

The cluster plane only exists when a control plane is started with `--cluster-listen <host:port>` (9444 in the examples below). Two listeners share that surface:

- **Operational listener**: mutual TLS is mandatory; only nodes holding a certificate issued by the fleet's cluster CA can complete the handshake. Still, do not expose it wider than needed: allow only the addresses of enrolled nodes.
- **Enrollment listener** (cluster port + 1 by default, so 9445 below; `--cluster-enrollment-listen host:port` moves it, for example onto an admin interface): the only unauthenticated surface in the product. It is closed unless a join token is live and auto-closes when the last token is burned or expires, but the firewall should mirror that lifecycle: open it only for the duration of an enrollment window, and only from admin-controlled source addresses.

Followers dial out to the control plane and expose no inbound cluster port; no follower-side firewall opening is needed.

Enrollment hygiene (Story 9.3):

- Mint join tokens with the shortest lifetime the operation allows (`ttl_seconds`, default one hour, cap 24 hours) and bind them to the expected node name and source CIDR whenever they are known.
- Hand the token to the joining node through a file with mode 0600, standard input, or `LORICA_JOIN_TOKEN`; never on a command line, never in a ticket. `lorica cluster join` refuses a token on argv.
- The same goes for the admin password every management CLI command needs (`unban`, `upgrade`, `cluster token`, `cluster leave`, `cluster status`): use `--password-file` (mode 0600), `--password-stdin` or `LORICA_ADMIN_PASSWORD`; `--password` on argv only prints a warning. An explicit source wins over the environment variable.
- Leave `--cluster-auto-activate` off in production: review each `pending` node in the roster and activate it deliberately.
- Revoke decommissioned nodes on the control plane before wiping them (`DELETE /api/v1/cluster/nodes/{id}`); `lorica cluster leave` on the node then proves the deregistration and wipes the fleet identity.
- Revocation cuts access, not possession: a revoked node keeps the certificate private keys it was entitled to. The revocation response and the `cluster.node.revoke` audit row list them as `certificates_to_reissue`; re-issue every one before considering the incident closed. A node you cannot run `leave` on is exactly the case this bullet is for.

### Automation Plane (v1.8.0+, opt-in)

The automation plane only exists when a node is started with
`--automation-listen <host:port>` (9446 in the examples below, the port
`docs/automation.md` uses). It is the only listener in the product a CI runner
is meant to reach, and unlike the management API it is expected to be remote,
so its controls sit in the process rather than in the firewall alone.

- **The source allowlist is mandatory and runs before the TLS handshake.**
  `automation_allowed_cidrs` names the runner networks; the listener refuses to
  open on an empty list, and an address outside it gets no handshake, no
  certificate and no byte read from it. Keep it as narrow as the runner fleet
  allows. It is a setting, not a flag, so narrowing it during an incident takes
  effect on the next connection with no restart.
- **Credentials are bearer-only.** A scoped token minted on the management
  plane, or a GitLab ID token from a registered issuer. There is no session, no
  cookie and no CSRF pairing on this plane, so a stolen dashboard session
  cannot be replayed against it.
- **The token's grant is the real boundary, not the listener.** Scopes, the
  hostname patterns it may bind and the backend CIDRs it may point at all
  travel with the token, and an empty backend CIDR list means deny-all, not
  allow-all. Mint one token per pipeline with the narrowest hostname pattern
  that works; revoke a decommissioned runner's token rather than reusing it.
- **Prefer OIDC to a static token** where the CI platform supports it. The job
  authenticates with its own short-lived ID token bound to project, ref and
  environment, which removes the shared secret from the CI variables
  altogether. On a self-hosted GitLab, pin the issuer's CA with `ca_pem` on the
  issuer entry so the JWKS fetch does not rest on the platform root store.
- **A follower refuses to open the listener at all.** The automation plane
  belongs on a standalone node or on the control plane; a follower's
  configuration is replaced at the next replication round, so a write there
  would be silently undone.

### The MCP Server Tiers (v1.9.0+, opt-in)

The management MCP server (`docs/mcp.md`) lets a language model drive the
automation plane, and exists only where that plane does. Its three tiers are
three token shapes: the **read tier** reads logs, WAF events, SLA, cluster
status and the configuration; the **config tier** changes routes, backends and
certificate bindings inside a hostname and backend grant; the **admin tier**
changes the operational settings on the plane's allowlist. The node refuses a
token whose scopes span two tiers, on both transports. What it cannot refuse
is how tokens are wired to models, and that is what this section is about:
the text the read tier returns was largely written by whoever is attacking
the node, and a model that reads it and holds a mutating tool can be steered
into using it (`docs/security/threat-model.md`, T9).

**Which tier for which task.**

- *Investigating, reporting, asking why a route fails*: the read tier. It is
  the only one to leave configured for day-to-day use, and it changes nothing.
- *One named change to a route, a backend, a certificate binding or a
  renewal*: the config tier, minted for that change and revoked after it. Read
  the logs with the read tier first if the change needs them, then hand the
  conclusion, not the rows, to the config session.
- *A bounded settings job*, such as keeping more access-log and WAF-event
  history ahead of an investigation or raising the certificate expiry warning
  before a renewal campaign: the admin tier, for that job only.
- *Anything the tiers have no tool for* (WAF rules, notification channels,
  users, tokens, the cluster), and content end users receive (`error_page_html`,
  response rewrites and headers, redirects): the dashboard, by a human.

**One token per tier, minted with `--tier`.** `lorica mcp token create --tier
read|config|admin` mints exactly one tier's scopes and prints what the token
can do next to it. A token minted with `lorica automation token create` and a
hand-picked scope list works when it stays inside one tier, and is refused by
the server when it does not; `--tier` is the way not to have to check.

**One client per tier where possible.** The isolation is per process, and a
client configured with a server of each tier is one model holding all of
them: it reads hostile text through one and holds route writes through the
other. Give each tier its own client, or at least its own client profile or
workspace, so that the conversation that reads logs is not the one that can
change the node. **Never give a read-tier client a config-tier token**: the
server is then a config server, refuses nothing, and the operator believes a
reader is configured.

**Configure the admin tier only for the task, and remove it afterwards.**
Mint its token with the shortest lifetime the task allows (`--tier admin`
defaults to the tier's own, the shortest of the three, and the node refuses a
`settings:write` token past `AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS`
whichever surface mints it), run it in its own `lorica-mcp` process that reads
no logs, and revoke the
token and drop the client entry once the task is done. On a cluster's control
plane every setting it reaches is fleet policy and replicates to every
follower, so a standing admin-tier token there is a standing path from a model
to the whole fleet's behaviour, not one node's. Every setting it can reach is
an editable field of the dashboard's settings form, so an operator puts any of
them back in the time it takes to describe it; the tier earns its place for a
bounded job, not as a permanent fixture. What it can reach, and how far, is
the table in `docs/mcp.md` ("The admin tier, and where it stops"), which a
test holds to the plane's allowlist; it never reaches identity, tokens, OIDC
issuers, the cluster's membership, the listeners, the connection allowlists
or the log level, whatever the token carries. That boundary is the node's;
the exposure window is the operator's to keep short. An OIDC issuer entry
cannot carry `settings:write`: it would be a standing grant to every matching
pipeline job.

**The shortest lifetime.** Without `--lifetime-days`, `lorica mcp token
create` mints each tier with its own default from the tier table, shorter the
further the tier reaches, and prints it with the blast radius. Pass a shorter
one whenever the task is shorter: a read-tier token for as long as the client
is meant to exist, a config-tier token for the change, an admin-tier token for
the task. A token minted any other way (`lorica automation token create`, the
dashboard, the API) with no lifetime lives the node's default, a year, except
one carrying `settings:write`, which the node refuses past its ceiling.

**Grants as narrow as the change.** A config-tier token's `--hostname` and
`--backend-cidr` are the real boundary on what a steered model can write:
name the hostnames and the address range the change touches, not the parent
zone and not the whole private range. The grants also bound what a config-tier
session reads: its route, backend and certificate listings answer only the
rows inside them, so text another principal wrote elsewhere never reaches the
model. The read and admin tiers carry no grant at all, and the mint refuses
one.

**Prefer stdio on the Lorica host to a hosted client over Streamable HTTP.**
A local stdio server connects from loopback and needs nothing else in
`automation_allowed_cidrs`; a hosted client connects from its provider's
addresses, which the allowlist then has to name. Wherever the model runs, the
rows the read tier returns go there too: the automation plane withholds the
values that can carry a credential (a route's `proxy_headers` values, query
values in a path), and WAF events still carry the span a signature matched,
verbatim. Keep the token out of files that get committed and off any command
line: `lorica-mcp` refuses arguments, and `docker exec -e LORICA_MCP_TOKEN`
passes the variable without its value. Mint into a file under `umask 077`.

**When Lorica runs in a container, run `lorica-mcp` on the client's host.**
The `docker exec` route into the node's container needs the client's account
to reach the Docker daemon, which is root on the host, and runs the server as
the proxy's own user with the data directory readable. **A client with
Docker access, or any other root-equivalent right, and a shell or command tool
is outside the tier model**: a model steered through the read tier needs no
Lorica write scope to change the host. Give MCP clients an account without
those rights, and keep `docker exec` for an operator who has accepted that.

**Watch the audit rows.** Everything a model does that reaches the node lands
in the tamper-evident trail (`GET /api/v1/audit`, verified with
`GET /api/v1/audit/verify`), and MCP rows are easy to pick out: the target
`POST /automation/v1/mcp tool=...` on Streamable HTTP, and
`asserted[transport=mcp-stdio...]` over stdio, both under the token's
`public_id`, with a second row under the role `automation` for each change.
What reaches the node differs by binding, and so do the alerts.

Over **Streamable HTTP**, the node runs the server, so every refusal is a row.
Worth an alert:

- `automation.request.forbidden:spans_tiers`: somebody minted a token spanning
  two tiers and tried it.
- `automation.request.forbidden:<scope>` or `forbidden:unknown_tool` from an
  MCP token: a model reaching for a tool it was not given, which is what a
  steered model looks like.
- `automation.request.refused:rate_limited`: a model in a loop.

Over **stdio**, the server runs on the client's side and refuses those three
by itself, before anything reaches the node: a token spanning two tiers exits
at startup (code 78), and a tool of another tier or a spent invocation budget
is one line on the server's stderr. The node sees the startup `whoami` and the
calls the server forwarded, nothing else, so none of the three rows above can
appear. Keep the client's stderr where someone reads it, and on the node watch
for a `whoami` row asserting `transport=mcp-stdio` with no call following it:
a server that started and was refused, or that nobody used.

On **both** bindings:

- a `forbidden` row from an MCP token on a write: a hostname or a backend
  outside its grant, which a steered model reaching past its brief looks like;
- write 429s from an MCP token: a model in a loop, on the plane's own budget;
- any `settings.update` row under the role `automation`, and any change row
  from a config-tier token outside the window it was minted for;
- `last_used_at` moving on a token that should be idle, on the dashboard's
  Automation tokens page.

Revoke from the Automation tokens page or with
`DELETE /api/v1/automation/tokens/{public_id}`; nothing is cached, so the next
call fails.

### Firewall Rules

```bash
# Allow proxy traffic
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Block management from network (redundant with localhost binding, defense-in-depth)
iptables -A INPUT -p tcp --dport 9443 -j DROP

# Cluster plane (control plane only, when --cluster-listen is set):
# default-deny, then allow ONLY enrolled-node sources on the
# operational port. 192.0.2.10 / 192.0.2.11 stand in for your
# followers' addresses.
iptables -A INPUT -p tcp --dport 9444 -s 192.0.2.10 -j ACCEPT
iptables -A INPUT -p tcp --dport 9444 -s 192.0.2.11 -j ACCEPT
iptables -A INPUT -p tcp --dport 9444 -j DROP
# Enrollment listener (cluster port + 1): closed by default. During
# an enrollment window, insert a temporary allow for the joining
# node's address ahead of the drop, and remove it once the token is
# burned.
iptables -I INPUT -p tcp --dport 9445 -s 192.0.2.12 -j ACCEPT
iptables -A INPUT -p tcp --dport 9445 -j DROP

# Automation plane (when --automation-listen is set): default-deny,
# allow only the CI runner sources. 192.0.2.20 stands in for your
# runner network. This mirrors automation_allowed_cidrs rather than
# replacing it: the process-side list is the one that still holds
# when a firewall rule is flushed by mistake.
iptables -A INPUT -p tcp --dport 9446 -s 192.0.2.20 -j ACCEPT
iptables -A INPUT -p tcp --dport 9446 -j DROP
```

The same policy in nftables form:

```bash
nft add rule inet filter input tcp dport { 8080, 8443 } accept
nft add rule inet filter input tcp dport 9443 drop
nft add rule inet filter input ip saddr { 192.0.2.10, 192.0.2.11 } tcp dport 9444 accept
nft add rule inet filter input tcp dport 9444 drop
# Enrollment window only (remove after the token is burned):
nft add rule inet filter input ip saddr 192.0.2.12 tcp dport 9445 accept
nft add rule inet filter input tcp dport 9445 drop
# Automation plane (when --automation-listen is set):
nft add rule inet filter input ip saddr 192.0.2.20 tcp dport 9446 accept
nft add rule inet filter input tcp dport 9446 drop
```

## 2. TLS Configuration

### Certificate Management

- Use **ACME/Let's Encrypt** for automatic certificate provisioning when possible
- Use **DNS-01 challenge** if port 80 is not reachable from the Internet
- Set certificate **warning threshold** to 30 days and **critical threshold** to 7 days
- Enable **auto-renewal** for ACME certificates
- Self-signed certificates should only be used for testing

### TLS Backend

Lorica uses **rustls** exclusively (no OpenSSL). This provides:
- TLS 1.2 and 1.3 only (no SSLv3, TLS 1.0, 1.1)
- Strong cipher suites only (ring crypto provider)
- Certificate verification for upstream TLS backends

## 3. Authentication

### Admin Password

- Lorica generates a random password on first run - **change it immediately**
- Minimum password length: 14 characters, with complexity classes enforced by default (`password_min_length` / `password_require_complexity`)
- The password is hashed with **Argon2** (memory-hard, resistant to GPU attacks)
- Failed login attempts are rate-limited (429 after threshold)

### Session Management

- Sessions use **HTTP-only** cookies (not accessible via JavaScript)
- Sessions are stored in-memory (cleared on restart)
- No session persistence across restarts by design (forces re-authentication)

## 4. WAF Configuration

### Recommended Setup

1. **Enable WAF in Detection mode** first to observe traffic patterns
2. Review WAF events in the dashboard for false positives
3. **Switch to Blocking mode** once confident
4. Add **custom rules** for application-specific threats

### IP Blocklist

- Enable the IPv4 blocklist (~80k known malicious IPs from Data-Shield)
- The list auto-refreshes every 6 hours
- Manual reload available via dashboard or API

### Custom Rules

- Use the Security > Custom Rules tab to add application-specific patterns
- Severity 5 = critical, 4 = high, 3 = medium, 1-2 = low
- Test patterns in Detection mode before switching to Blocking

## 5. Process Isolation

### Worker Mode

For production deployments, use worker mode:
```bash
lorica --workers 4  # one per CPU core
```

This provides:
- Process-level isolation between workers
- Crash recovery with automatic restart and exponential backoff
- Independent memory spaces (one worker crash doesn't affect others)

### File Permissions

```bash
# Data directory: owned by lorica user
chown -R lorica:lorica /var/lib/lorica
chmod 700 /var/lib/lorica

# Database file: read-write for lorica only
chmod 600 /var/lib/lorica/lorica.db
```

### systemd Hardening

The packaged systemd unit (`lorica.service`) ships with a defense-in-depth stack so a future Lorica RCE has a much smaller blast radius. Settings below are grouped by what they deny ; all are active by default in the Debian / RPM package.

**Privilege + capability surface :**

- `NoNewPrivileges=yes`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (only capability the proxy needs ; operators who run the cert-export feature with a non-`lorica` owner should add `CAP_CHOWN` to both the bounding and ambient sets)
- `RestrictSUIDSGID=yes`
- `PrivateUsers=yes` is intentionally **not** set : incompatible with `CAP_NET_BIND_SERVICE` (a user-namespaced process cannot inherit that capability from its parent). Operators who do not need port 80 / 443 can flip it on manually for a stronger sandbox.

**Filesystem :**

- `ProtectSystem=strict` + `ReadWritePaths=/var/lib/lorica`
- `ProtectHome=yes`
- `PrivateTmp=yes`
- `PrivateDevices=yes` (no `/dev/*` raw access)
- `ProtectKernelTunables=yes` + `ProtectKernelModules=yes` + `ProtectControlGroups=yes`
- `ProtectClock=yes` (blocks `settimeofday` / `clock_adjtime`)
- `ProtectHostname=yes` (blocks `sethostname` / `setdomainname`)
- `ProtectProc=invisible` + `ProcSubset=pid` (hides other services' `/proc` entries and non-pid `/proc` leaks)
- `UMask=0077`

**Namespaces + memory :**

- `RestrictNamespaces=yes`
- `LockPersonality=yes`
- `MemoryDenyWriteExecute=yes`
- `RestrictRealtime=yes`
- `KeyringMode=private` (per-service kernel keyring)
- `RemoveIPC=yes` (cleanup POSIX shm / SysV IPC owned by the `lorica` user on service stop ; Lorica itself uses `memfd_create` so this is a no-op on the happy path)

**Syscall + socket family allowlist :**

- `SystemCallFilter=@system-service` (whitelist baseline)
- `SystemCallFilter=~@privileged @resources` (subtract `CAP_SYS_ADMIN`-class syscalls and `setrlimit` / `prlimit`)
- `SystemCallArchitectures=native` (no 32-bit syscall table on x86_64, prevents ABI-switching evasion)
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK` (everything else - `AF_PACKET`, `AF_CAN`, `AF_BLUETOOTH`, `AF_AX25` etc. - is denied)

An operator who wants to verify the sandbox is active :

```bash
systemctl show lorica | grep -E '(Protect|Restrict|Private|Capability|SystemCall)'
```

## 6. Monitoring

### SLA Monitoring

- Configure **SLA targets** per route (default 99.9%)
- Enable **active probes** for critical routes to detect outages during low-traffic periods
- Set up **notification channels** (email/webhook) for SLA breach alerts

### Prometheus Metrics

- The `/metrics` endpoint requires authentication by default since v1.7.0
  (`metrics_require_auth`, default `true`). A scrape presents either a
  dashboard session cookie or `Authorization: Bearer <prometheus_scrape_token>`,
  and the token is best injected through `LORICA_PROMETHEUS_SCRAPE_TOKEN`
  rather than stored in the settings. Leave the setting on: the document
  exposes the full backend topology and the certificate inventory, which on a
  shared host any local user could otherwise read
- Keep network-level access control on top of it (firewall or the Prometheus
  scrape config), not instead of it
- Key metrics to alert on:
  - `lorica_http_requests_total` with high error rates
  - `lorica_backend_health` transitions to unhealthy
  - `lorica_cert_expiry_days` below threshold

### Load Testing

- Use built-in load testing with **safe limits** (configurable in settings)
- The **CPU circuit breaker** (90% threshold) automatically aborts tests that threaten proxy performance
- Always test in staging before production

### Log Export and Capture Sinks (v1.7.0+)

Everything below leaves the node by an operator's decision, which makes each
one a boundary to scope deliberately.

- **Syslog export.** Prefer TCP with TLS, and mutual TLS where the collector
  supports it. Plain UDP is neither authenticated nor encrypted: on anything
  but a trusted management segment it publishes the access log, the WAF events
  and the audit trail to whoever is on the path.
- **OTLP log export.** Set the exporter's `Authorization` header when the
  collector expects one. The records carry the same content as the syslog lane.
- **Capture records (v1.8.0) are the most sensitive thing this proxy emits.**
  A record is a copy of a request and its response taken after TLS
  termination. Redaction covers credentials (`Authorization`, `Cookie`,
  `Set-Cookie`, the session and CSRF names, plus whatever the rule adds) and no
  rule can turn that off, but it does NOT cover bodies: a capture of a route
  carrying personal data is a file holding personal data. Point the sink where
  that is acceptable, and keep the rule's TTL as short as the investigation
  needs.
- **`output.dir` writes files, so treat it as a data store.** The directory
  must be absolute and must not be a symlink, checked on every write rather
  than once at configuration time; files land mode `0640` owned by the service
  user. Set `max_dir_bytes` so it prunes oldest-first, and keep it off shared
  or network storage.
- **A stalled sink never becomes a 5xx.** A full disk, a wedged collector or a
  read-only mount increments `lorica_captures_total{outcome="dropped_sink"}`
  and drops the record. Alert on that counter: silence there means captures are
  being lost, not that nothing matched.

## 7. Backup and Recovery

### Database Backup

```bash
# SQLite with WAL mode - safe to copy while running
cp /var/lib/lorica/lorica.db /backup/lorica-$(date +%Y%m%d).db
```

### Configuration Export

Use the dashboard Settings > Export to create a TOML backup of all configuration. This includes routes, backends, certificates, and settings but **excludes** private keys for security.

### Recovery

1. Install Lorica on new host
2. Copy database file to `/var/lib/lorica/lorica.db`
3. Or: use Settings > Import with the TOML backup

## 8. Audit Checklist

Run this checklist periodically:

- [ ] Admin password changed from default
- [ ] Management API not exposed to network
- [ ] TLS certificates not expired or expiring soon
- [ ] WAF enabled on all public-facing routes
- [ ] IP blocklist enabled and refreshing
- [ ] SLA monitoring active on critical routes
- [ ] Notification channels configured and tested
- [ ] Worker mode enabled for production
- [ ] File permissions correct on data directory
- [ ] Prometheus metrics collected by monitoring system
- [ ] `/metrics` authentication left on, scrape token injected out of band
- [ ] Config backup taken within last 7 days
- [ ] (Clustered) Cluster port reachable from enrolled-node sources only
- [ ] (Clustered) No enrollment window left open (no live join token, enrollment listener closed)
- [ ] (Automation) Listener reachable from CI runner sources only, and `automation_allowed_cidrs` no wider than the runner fleet
- [ ] (Automation) One token per pipeline, tokens of decommissioned runners revoked, OIDC used instead of a static secret where the platform allows it
- [ ] (MCP) One token per tier, minted with `--tier` and an explicit `--lifetime-days`; no client holding servers of two tiers, and no read-tier client holding a config-tier token
- [ ] (MCP) No `settings:write` token live beyond the task it was minted for, and no admin-tier client entry left configured
- [ ] (MCP) Config-tier grants no wider than the change; MCP audit rows (`spans_tiers`, `forbidden` from an MCP token, `rate_limited`, `settings.update` under `automation`) alerted on
- [ ] (Capture) No rule left armed past the investigation that justified it, and every `output.dir` sized, pruned and off shared storage
- [ ] (Capture) `lorica_captures_total{outcome="dropped_sink"}` alerted on
