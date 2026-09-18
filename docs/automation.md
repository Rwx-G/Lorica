# Lorica Automation API

**Author:** Romain G.
**Since:** v1.8.0

## Overview

The automation plane is the door a CI pipeline uses to make
`https://<slug>.review.example.com` reach the container it just
started, in one call that is safe to repeat and safe to abandon. It
serves one resource, the environment: a route, its backends, a
certificate binding and a lifetime, created or replaced by a single
idempotent `PUT`, readable, and removed by `DELETE` or by a reaper once
its lifetime has run out.

One sentence decides everything else in this document. **The
management API stays on loopback with a session cookie; the automation
listener is a second door that is narrow by construction: a different
port, a different credential, a different router, and a scope set that
does not contain the management API's verbs.** Every way of bridging
the gap by widening the management plane, a management port on the
network, a service account holding a dashboard session, a reverse proxy
in front of the proxy, is worse than the problem it solves. So the two
planes share no credential at all: a request on the automation listener
carrying a valid `lorica_session` cookie and no `Authorization` header
is a 401, and the cookie is never read, because the automation router
has no cookie layer, no CSRF layer and no session store to read it
with. A valid automation credential presented to the management port is
ignored the same way.

What administers the plane lives on the management API, SuperAdmin and
audited: `GET|POST /api/v1/automation/tokens`,
`DELETE /api/v1/automation/tokens/{public_id}`,
`GET|POST /api/v1/automation/oidc-issuers` and
`DELETE /api/v1/automation/oidc-issuers/{id}`, plus the Automation
tokens sub-page under Settings in the dashboard. The automation listener
serves none of it, so a token can never mint a token, widen its own
scopes or extend its own expiry. What the listener serves is
`GET /automation/v1/whoami`, `GET /automation/v1/environments` and
`GET|PUT|DELETE /automation/v1/environments/{name}`, described in
`lorica-api/openapi-automation.yaml`, a separate document from the
management API's because it is a different socket with a different
security scheme.

## The listener

`--automation-listen <host:port>` starts the listener; without the flag
there is no automation surface at all. The flag is strict, and the rule
is the one every listener family in Lorica shares, so it cannot drift
between them:

- A bare port is refused; the bind is an explicit `host:port`.
- `0.0.0.0` and `::` are refused unless `--automation-listen-any` is
  also passed. A configuration API that accepts writes from off-box
  must never land on every interface by accident; the refusal names the
  opt-in flag.
- A port another listener in the process already holds is refused, and
  the refusal names which one: management, HTTP, HTTPS, or the cluster
  plane's operational and enrollment ports. The cluster plane takes
  9444 and 9445 by convention, so this document uses 9446.
- The effective bind is logged at WARN, not INFO, for the reason the
  cluster plane logs its own: a listener that accepts configuration
  writes from off-box is a fact an operator must be able to spot in the
  journal.

TLS is the management plane's: the same self-signed leaf or the
operator-supplied pair named by `management_cert_pem_path` and
`management_key_pem_path`. One node presents one identity, and a second
certificate to renew is a second thing to let expire.

**The source allowlist is checked on the accepted socket, before the
TLS handshake.** `automation_allowed_cidrs` is a global setting, a list
of CIDRs or bare addresses, and it is mandatory: the listener does not
open while the list is empty. The check runs in the accept loop on the
peer address of the raw `TcpStream`, before the acceptor ever sees it,
so a caller outside the list gets no handshake, no certificate and no
byte read from them; it never sees a 401 or a 403 because it never
reaches HTTP. The rule is the same `ConnectionFilterPolicy` the proxy's
TCP pre-filter uses, held with an empty deny list and never empty on
the allow side, so it is default-deny in practice. It is fixed when the
listener opens. An entry that is neither a CIDR nor an address refuses
the listener rather than being skipped with a warning: a typo that
silently narrows an allowlist is the failure an operator discovers
during an incident.

Behind the allowlist, and still before the handshake, the accept loop
takes the same pre-authentication budgets the cluster plane's
enrollment listener takes, in the same order, held across the handshake
and released when the connection ends. The numbers are this plane's
own, sized for a pipeline rather than for an enrollment:

| Budget | Automation listener | Enrollment listener |
| --- | --- | --- |
| Concurrent handshakes, whole listener | 256 | 256 |
| Concurrent connections per source | 32 | 8 |
| Connection attempts per source per minute | 300 | 20 |
| Handshake timeout | 3 s | 3 s |
| Sources tracked by the attempt window | 4096 | 4096 |

Size a pipeline against the middle two rows. A source is one IPv4
address or one IPv6 /64, so every job on a shared runner counts against
the same budget, and one HTTP call over a fresh connection is one
attempt: a job that runs `curl` thirty times makes thirty attempts. A
source that goes past either bound has its connection dropped before
TLS, with no HTTP response and therefore no 429 to read, which is the
denial-of-service floor and not a rate limit to tune against. A runner
that needs more than 300 calls a minute should reuse its connection
(`curl --next`, or a client with keep-alive) rather than ask for the
bound to be raised.

Each refusal has its own counter (see Metrics), because the three
answer different questions: is the node saturated, is one source
holding every slot, is one source retrying too fast.

Past the handshake the router caps request bodies at 64 KiB, far below
the management plane's 1 MiB. An environment declaration is a hostname,
a handful of backends and at most sixteen labels; a cap is easier to
raise for one endpoint that needs it than to notice once it is wide.

**The listener never runs on a follower.** A follower's configuration
is replaced by the control plane on every replication round, so an
environment written there would be silently undone. The check is the
one the cluster plane already makes at startup, a follower identity in
the store, and a follower started with `--automation-listen` exits
non-zero with:

```
automation listener: this node holds a follower identity (it joined a
fleet) and --automation-listen was passed; a follower's configuration is
replaced by the control plane on the next replication round, so an
automation write here would be silently lost. Point the automation at
the control plane, or run `lorica cluster leave` first
```

The other startup refusal is the empty allowlist, and it exits the same
way:

```
automation listener: `automation_allowed_cidrs` is empty and
--automation-listen was passed; the listener will not open without one,
because a network-reachable configuration API with no source allowlist
is not a default anyone should get by omission. Set it in the global
settings first
```

Both are refusals and not warnings on purpose. The flag is opt-in, so
an operator who passed it and got a silent no-op would learn about it
from the automation that never connected. On a control plane the
listener serves the whole fleet: an environment written there
replicates to every active follower like any other route.

**Hot upgrade hands the socket over.** `lorica upgrade` passes the
listening socket to the new binary with the others, over the same
descriptor table, and the new process accepts on the SAME kernel socket
with no rebind gap and no `EADDRINUSE` during the overlap. The new
process adopts only a socket bound where its own `--automation-listen`
says, and closes any other it was handed; if the new command line has
no `--automation-listen` at all, the inherited socket is closed with a
WARN. The bind and `--automation-listen-any` travel on the upgrade
command line, so the two binaries agree on where the listener sits.

## Static tokens

A static token is `<public_id>.<secret>`: 12 random bytes as lowercase
hex, a dot, and 32 random bytes as URL-safe base64 without padding. The
public half is the indexed lookup key, so presenting a token is one
lookup and one verification; the secret half is 256 bits of machine
entropy, not a human password.

It is minted once, on the management API with
`POST /api/v1/automation/tokens` (SuperAdmin, audited as
`automation.token.create`), from the dashboard's Automation tokens page,
or with the CLI:

```bash
lorica automation token create \
  --name acme-ci \
  --scope environments:read --scope environments:write \
  --hostname '*.review.example.com' \
  --backend-cidr 10.0.0.0/8 \
  --max-ttl-seconds 604800 \
  --lifetime-days 90 \
  --user admin --password-file <path-to-0600-file> > token.txt
```

The command goes through the local management API like
`lorica cluster token` does, because the mint is a SuperAdmin operation
on a running node and not a database edit. **Standard output carries
the token and nothing else**: no banner, no confirmation, no trailing
advice, so a redirect into a file and a pipe into a secret store both
store exactly the credential. The one line naming the `public_id` and
the expiry goes to standard error, where a pipe never sees it. There is
deliberately no `--token` flag on this command and none should be
added: the secret is only ever an OUTPUT here, so there is nothing to
keep off argv on the way in, and the command that CONSUMES a token is
the automation's own client, which reads it from a file, standard input
or the environment. Argv is readable through `/proc`, lands in shell
history and is echoed verbatim by CI and by configuration-management
`command` modules. The server side is symmetric: the mint's log line
and its audit row carry the `public_id` only.

The answer to the mint is the only place the full string ever exists.
The node stores HMAC-SHA256 of the secret half under a dedicated
server-side key, never the cluster join-token key, so rotating or
burning one credential family never touches the other. No later read
can produce the token again, the listing carries neither the secret nor
its HMAC, and an operator who loses the string mints a new one. A
memory-hard KDF would buy nothing against 256 bits of entropy and would
turn an unauthenticated endpoint into a memory-exhaustion primitive.
Verification is constant-time (`ring::hmac::verify`), and when the
`public_id` names no row the verification still runs, against a dummy
digest, so an unknown id and a known id with a wrong secret cost the
same work and answer in the same time; the shape of the string is
checked before any store access, so a mistyped token costs no lookup at
all.

A token carries:

| Field | Meaning | Rule |
|---|---|---|
| `name` | Operator-facing label, and the ownership principal (see Ownership). | Not blank. |
| `scopes` | What it may do. | At least one, from the closed list below. |
| `allowed_hostnames` | Hostname patterns it may claim. | At least one. An exact name or a single leading `*.`; a bare `*` is refused. |
| `allowed_backend_cidrs` | CIDRs or bare addresses it may point a hostname at. | At least one. There is no node-wide default backend policy to fall back on, and the filter reads an empty allow list as allow-every-address, so an empty list is refused at mint time and the grant covers nothing at use time. |
| `max_ttl_seconds` | Ceiling on the lifetime any environment it creates may request. | Default seven days, hard cap thirty. |
| `expires_at` | Absolute UTC instant after which the token is refused. | Mandatory. Given as `expires_at` or as `lifetime_days` from now, never both; default 365 days. |
| `last_used_at` | When the token was last accepted. | Stamped at most once a minute per token, best effort: the field answers "is anybody still using this", and one SQLite write per request on the single store lock is not what that question costs. The signal to retire a token nobody presents. |
| `revoked_at` | When an operator withdrew it. | `DELETE /api/v1/automation/tokens/{public_id}` stamps it and keeps the row. |

Revocation is immediate: nothing about a token is cached, so a revoked
or expired token fails on its very next request, an in-flight
automation included. Revoking twice is a 200 that keeps the first
stamp, because moving it forward would rewrite when the credential
actually stopped working; revoking an unknown id is a 404, because a
typo must not read as a revocation. The row stays, so after an incident
the audit trail still says the credential existed, who minted it and
when it was last presented.

**The scope set is a closed list**: `environments:write`,
`environments:read`, `routes:read`, `certificates:read`. An unknown
scope string fails to deserialise rather than being dropped, so a token
minted against a newer Lorica is refused instead of silently losing a
grant an operator wrote down. `routes:write`, `certificates:write` and
`settings:*` are absent on purpose in 1.8.0. The automation surface is
the environment resource, not the management API behind a different
door; an automation that needs to reshape routing or issue a
certificate is asking for an operator's credential, and it should have
to say so rather than find the capability already attached to the token
it uses for ephemeral environments.

**`allowed_hostnames` uses single-label wildcard semantics.**
`*.review.example.com` covers `mr-42.review.example.com` and refuses
`a.b.review.example.com`, `review.example.com` and `.review.example.com`;
a bare `*` matches nothing; a trailing root dot is stripped from both
sides before comparing. This is DELIBERATELY narrower than the
certificate-export ACL, whose wildcard covers a parent at any depth,
and the two matchers live side by side in one module so a reader meets
the sibling before picking one. They differ because the two callers
answer different questions. The ACL decides which uid and gid own an
exported file an operator already controls; over-matching costs
precision. A token grant decides whether a caller may claim a name at
all, and an operator reads a wildcard there the way they read one in a
certificate. A grant that covered deeper names would hand out authority
nobody wrote down, and would let a token create a host that no
certificate can cover, which is a broken environment the moment it is
served.

## Authentication and authorisation

`Authorization: Bearer <credential>` is the only credential the
listener reads. The scheme match is case-insensitive per RFC 7235; the
value is either a static token or a GitLab ID token, and the listener
picks the mode by the SHAPE of the value and by nothing the caller can
say separately: a value with a minted token's shape takes the static
path, a three-segment JWT takes the OIDC path, anything else is refused
without touching the store. The two shapes cannot collide, because a
static token's secret half is base64url with no dot in it and a JWT has
exactly two.

Every refusal to authenticate is the same 401: the body says
`a valid automation bearer credential is required`, the
`WWW-Authenticate` header says `Bearer realm="lorica-automation"`, and
nothing on the wire says which mode was tried or how close the caller
got. Telling a caller that their token is known but revoked would
confirm the id; telling them that their JWT reached the verifier would
confirm that an audience is registered. The precise reason is written
to the audit row alone, in the `reason` field of the
`automation.request.unauthenticated` row: on the static path
`no_bearer`, `not_a_credential`, `token_unknown_or_wrong_secret`,
`token_revoked`, `token_expired` or `store_error`; the OIDC reasons are
listed under GitLab OIDC below. An operator reads the row; an attacker
cannot.

**401 versus 403.** By the time the scope gate runs, the caller has
proved which credential they hold. A missing scope is therefore a 403,
never a 401: answering 401 would tell them to present a credential they
already presented successfully, and would send a scope mistake down the
same path as a credential mistake, where the automation retries, or an
operator re-mints a token that was never the problem. 403 says the
credential is real and the grant is not there, which is the one
sentence that leads to the right fix, and its message names the missing
scope. That is not a disclosure: the caller holds the credential and
can read its own scopes from `whoami`; what they cannot do is guess
which scope this path wanted.

The whole scope matrix lives in one function, `required_scope`, the
way the management API's role matrix does, and it returns an `Option`.
**A path with no declared scope is reachable by no token**, including
one carrying every scope in the enum, and the refusal is logged at
ERROR. The tempting default, the widest scope, reads as fail-closed and
is not: a route added without a declaration would stay reachable by
exactly the tokens that can do the most damage, and nothing would say
so. Refusing outright turns a missing declaration into a 403 for
everyone on the first call, which is a bug someone reports rather than
a grant nobody notices. The same rule is what keeps the management
paths off this listener: the router declares none of them and the
matrix declares no scope for them, so two things refuse them, not one.
The OpenAPI contract test cross-checks every `x-required-scope` in
`openapi-automation.yaml` against what the gate applies.

`GET /automation/v1/whoami` reports the credential back to its holder
(`name`, `public_id`, `kind`, `scopes`, and `pipeline` for an ID token)
and reaches nothing else. It needs `environments:read`, the narrowest
scope any token that talks to this plane carries, and it exists so the
whole chain, source filter, TLS, bearer check, scope gate and audit,
can be exercised on its own.

**Every request is audited, not only the mutations.** On the
management plane a read is a human looking at a page they are already
allowed to see; here the caller is a credential, and the questions
after an incident, which token was this and what was it reaching for,
are answered by a read as much as by a write. The audit layer is the
outermost one, so a request the bearer gate refuses still lands a row.
Each row is `automation.request.<outcome>` where the outcome is the
word derived from the response status (`ok`, `unauthenticated`,
`forbidden`, or `refused` for any other non-success), with
`operator_role` set to `automation`, the target `METHOD path`, the
source address and the user agent. An accepted request names its
principal as `<name> (<public_id>)` for a static token and
`<project_path> (oidc:<entry id>)` for an ID token, the label an
operator reads and the id they revoke in one column; a refused request
names `-` and carries the reason in its payload. The environment
handlers add a second, resource-level row beside it:
`automation.environment.create`, `.update`, `.delete`, and `.forbidden`
when the ownership rule refuses a read, an update or a delete.

## The environment resource

`PUT /automation/v1/environments/{name}` creates or replaces an
environment. `name` is an RFC 1123 label, 1 to 63 characters of
lowercase ASCII letters, digits and hyphens, neither starting nor
ending with one; lowercase is required rather than folded, because the
name becomes a group name and is compared byte for byte. The body is
`deny_unknown_fields`, so a field from a later version is a 422 on the
first call rather than a value silently ignored:

| Field | Meaning | Rule |
|---|---|---|
| `hostname` | The exact host the environment answers on. | Lowercase-folded, trailing dot stripped. No wildcard, no scheme or path, no address literal, not `localhost` or under it, DNS label rules. Must match one of the credential's `allowed_hostnames` (403). |
| `backends[]` | The upstreams: `address`, optional `tls_upstream`, `tls_sni`, `weight`. | At least one, at most 32. `address` is `ip:port` with a non-zero port; a name is refused because it cannot be checked against a CIDR grant without a resolution the caller controls. Every address inside `allowed_backend_cidrs` (403); a credential naming no CIDR reaches no address at all. `tls_sni` is an RFC 1123 DNS name, no wildcard and no address literal. `weight` between 1 and 1000, default 1. |
| `certificate` | `"auto"`, or an explicit certificate id. | An explicit id needs the `certificates:read` scope (403), must exist (422) and must cover the hostname under the same one-label wildcard rule `auto` uses (422): naming an id does not widen what the certificate carries. |
| `waf_enabled` | Whether the WAF inspects the route, in detection mode. | Default off. |
| `force_https` | Whether plain HTTP redirects to HTTPS. | Default off. |
| `path_prefix` | The route's path prefix. | Default `/`; must start with `/`, no whitespace, `?`, `#` or `..`. |
| `ttl_seconds` | How long the environment lives. | Greater than zero, at or under the credential's `max_ttl_seconds` (422). Recomputed from now on every `PUT`. |
| `labels` | Free-form `key: value` pairs. | At most 16, keys and values at most 128 bytes, no empty key. `shared: "true"` opens the environment to every principal; only the owner may rewrite the labels, so a caller who reached a shared environment cannot close the door behind them. |

One principal owns at most 100 environments. The cap is counted on
create alone, inside the transaction, and a 422 names it: every `PUT`
writes a route, its backends and the joins and starts a fleet
replication round, so a looping pipeline without a ceiling is a write
amplifier for every node. A pipeline that legitimately needs more
splits the work across credentials, which is also how an operator sees
which project is growing.

Every rule above is checked before the store lock is taken, so a
refusal a caller can provoke writes nothing and rolls back nothing.
What follows runs inside one `ConfigStore::in_transaction`, on the
single store lock, and it is all or nothing: a database error anywhere
in the middle leaves no route, no backend, no join and no environment
row behind.

**What the transaction writes.** A `Route` row whose hostname, path
prefix, WAF flag, HTTPS flag and certificate are the request's and
whose every other setting is the route API's own default, so an
environment's route behaves like one an operator created with the same
four settings. One `Backend` row per entry, named `<name>-<index>`,
health-checked every 10 seconds, exclusively owned. The route-to-backend
joins. And one `automation_environments` row: the name, the route id,
the owner, the certificate mode, the labels, `expires_at`, `created_at`,
`updated_at`, the last pipeline id, and for an ID token the job
identity. Both the route and the backends carry `group_name =
automation:<name>` and `managed_by = {kind: automation, environment:
<name>}`. On an update the route is rewritten in place under the same
`route_id`, so dashboards and metrics keep continuity; the backend set
is replaced (rows the environment owns are deleted, a row that somehow
got linked without being owned is unlinked and never deleted, because
it is somebody else's); and `expires_at` is recomputed from now. The
resource replicates: the route and backend rows ride the canonical blob
like any other, and so does the environment row, under the format
version Story 10.1 set, so a follower serving the route knows it
belongs to an environment.

**The hostname rules.** Beyond the shape rules in the table, the
hostname must not be held by another route: any route's `hostname` or
`hostname_aliases` entry equal to it, case-insensitively, other than
this environment's own route, is a 409 whose message names the hostname
and nothing about the route holding it. The caller is a credential from
one project, and which manual route sits on a name is an operator's
business. `localhost`, `*.localhost` and any address literal are
refused outright rather than compared against the listeners' binds: the
management listener is loopback by construction and the automation
listener binds an address, so those are the only names a route could
collide with, and neither bind is something the handler needs to know.

**`certificate: "auto"`.** Lorica picks the certificate whose `domain`
or one of whose `san_domains` covers the hostname under the same
one-label wildcard rule the token grant uses. Among the candidates an
exact name beats a wildcard, then the latest `not_after` wins, then the
lowest `id`, so two nodes holding the same rows pick the same
certificate. An expired certificate still resolves: expiry is the
renewal path's business, the ACME loop replaces the body in place, and
refusing here would strand every environment at the moment a renewal is
already under way. No covering certificate is a 422 whose message
starts with `no_certificate_covers_hostname` and names the wildcard an
operator could provision (`*.review.example.com` for
`pr-42.review.example.com`; a name with fewer than three labels yields
no suggestion, because `*.com` is not a certificate a public CA issues),
pointing at `POST /api/v1/acme/provision-dns` (DNS-01). The environment
resolves against existing certificates only and never orders one: an
order takes minutes and a pipeline cannot wait on it, and a wildcard
provisioned once serves every review app under it.

The mode is STORED, not a resolved id frozen at creation. At every
configuration snapshot build, the supervisor or the single-process node
re-resolves every `auto` environment against the current certificates
with the same resolver and the same tie-break, lands a changed id on
the route row, and bumps the reload counter once more so the
replication round that wakes on it reads the new id. Replacing the
wildcard certificate with a new id, rather than renewing it in place,
therefore moves every environment over with no pipeline re-run,
settling in one extra round: the next build finds nothing to rewrite
and does not bump. The route row still carries an explicit
`certificate_id`, so the proxy's configuration path and a follower,
which never resolves the mode itself, see an ordinary route. When no
certificate covers the hostname any more, because the wildcard was
deleted and not replaced, the route KEEPS the last id that worked and
the build logs one WARN naming the environment and its hostname. An
environment that served yesterday must not stop serving silently over
a certificate change it had no part in.

**The response.** 201 on create, 200 on update, an `ETag` header
either way, and a body of `name`, `url`
(`https://<hostname><path_prefix>`), `route_id`, `backend_ids[]` in
request order, `certificate_id`, `certificate_not_after`, `expires_at`
and `applied_generation`.

`applied_generation` is a FLOOR, not a target. It is the fleet
configuration generation the control plane had PUBLISHED when the
response was built, and 0 on a standalone node, which has no fleet to
wait for. The write itself starts the replication round that publishes
the next generation, so a pipeline that waits for the fleet polls
`GET /api/v1/cluster/status` until every node's
`applied_config_generation` EXCEEDS the value it received, not equals
it. It is the generation and never the hash: since Story 10.0 the
control plane cuts one payload per recipient, so two converged nodes
legitimately report two different hashes and a poll on hash agreement
would wait forever; the generation stayed fleet-wide precisely so that
this sentence still works. Two concurrent writers can move the
generation by two, in which case a node one past the floor has the
first environment and not necessarily the second; a strict pipeline
re-reads its own environment and compares against the latest. The poll
is a management-API read: it runs from wherever the management port is
reachable, not through the automation listener, which declares no
cluster path.

**Reading.** `GET /automation/v1/environments` lists the environments
the caller may access under the ownership rule, filtered by
`label=key:value` (exactly that label), `hostname` (folded the way the
`PUT` folds it) and `expiring_before` (RFC 3339, strictly before).
Environments the caller may not access are absent, not refused: a
listing is not the place to reveal that a name exists.
`GET /automation/v1/environments/{name}` answers 404 when no such
environment exists and 403, audited, when one exists that the caller
may not access, and returns the row with `hostname`, `path_prefix`,
`url`, `route_id`, `backend_ids`, the `certificate_id` currently on the
route, `certificate_mode`, `labels`, `owner`, the three timestamps,
`last_pipeline` and, after an ID-token write, `pipeline`.

**`ETag` and `If-Match`.** The `ETag` is the environment's `updated_at`,
quoted; every `PUT` moves `updated_at`, so the tag changes exactly when
the row does. Two pipelines racing on one name serialise on the store
lock, which the whole transaction holds, so the later `PUT` sees the
earlier one's rows and wins in full. `If-Match` is the opt-in for a
pipeline that would rather get a 412 than silently win: it takes a
strong tag, a weak `W/` tag compared by value, a comma-separated list,
or `*`, which matches any existing row and no missing one. A stale
tag, or any `If-Match` on a name that does not exist, is a 412 in the
same error envelope as every other refusal, with the code
`precondition_failed` and the current tag in the message.

**Deleting.** `DELETE /automation/v1/environments/{name}` removes the
route, the backends the environment owned and the joins in one
transaction; the environment row cascades away with the route. It
answers 204 whether or not the environment exists, and "never existed"
and "already deleted" both answer 204 on purpose: telling them apart
would mean consulting the audit trail, which is a forensics log that
may be absent in worker mode and is truncated by retention, and an API
answer must not depend on log retention. A pipeline's cleanup job wants
"gone" to be success; a typo in the name is a diagnostic the audit row
of this very call gives the operator. The one refusal is 403, audited,
when the environment exists and belongs to another owner.

## Ownership

Two projects sharing a Lorica must not be able to delete each other's
review apps. The rule is an authorization input, not a convenience, and
it gates all three verbs: a rule enforced on delete but not on update
is not a rule.

Every environment records its owner as a `kind` and a `principal`: for
a static token the kind is `static_token` and the principal is the
token's `name`; for an ID token the kind is `oidc_project` and the
principal is the job's `project_path`. A caller may read, update or
delete an environment when all of the following hold:

- The caller is a principal of the SAME kind as the owner. A different
  kind never matches, even on an identical string: a static token named
  `acme` and an OIDC project `acme` were issued by different
  authorities and are not the same owner.
- The two principals are the SAME string, byte for byte. `acme-ci`
  reaches only `acme-ci`; `acme-deploy`, `acme` and `globex-ci` are
  strangers to it.

The rule used to compare the text before the first `-`, so `ci-acme`
and `ci-globex` were one owner and so were the projects `acme/web` and
`acme/web-docs`. A naming convention is not an authorization boundary:
whoever picks the token name or the project name would be picking who
else they can reach, and on a shared GitLab anybody can pick. This is a
deliberate departure from the PRD's "same name prefix" wording, and it
is recorded in the story Debug Logs of 10.4 and 10.5.

The only opt-in is the label `shared` with the exact value `"true"`,
which opens the environment to every principal of either kind. `"yes"`,
`"True"`, `"1"` and `" true"` do not: an authorization rule must not be
reachable by a near miss.

A shared environment stays its owner's. A `PUT` by anybody else
rewrites the route, the backends, the certificate binding and the
lifetime; the stored `owner` is never replaced and the stored `labels`
are kept as they are. Without that, reaching a shared environment and
`PUT`ting it with `"labels": {}` would take it over and lock its owner
out of it.

A caller that may not access an environment is told the environment
does not exist: `GET`, `DELETE` and a `PUT` carrying `If-Match` all
answer the 404 an unknown name answers, with the same body. A 403 would
confirm that the name is taken and by somebody else, which is the one
fact a neighbour on a shared node must not be able to enumerate. The
refusal reason is in the `automation.environment.forbidden` audit row,
which an operator can read and a caller cannot.

For an ID token the same rule runs on `project_path`: `acme/web`
reaches only `acme/web`, and `acme/api` and `acme/web-docs` are both
strangers to it. Ownership is therefore per PROJECT, which is GitLab's
own model: an environment belongs to the
project whose pipeline deployed it, and a job of another project in the
same group has no say over it in GitLab either. A group that wants one
grant across its projects expresses that on the issuer entry, with
`"project_path": "acme/*"`; it does not thereby make them one owner.

## The reaper

A background task sweeps every minute and deletes every environment
whose `expires_at` is at or before now, each in its own transaction so
an environment whose rows cannot be removed does not keep every other
expired one standing. Each removal is audited as
`automation.environment.expired` with the node as the actor (`reaper`,
role `node`), since no credential is behind an expiry, and a sweep that
removed something bumps the reload counter so the proxy drops the
routes and, on a control plane, the fleet gets the generation without
them.

The reaper runs on a standalone node or a control plane and never on a
follower, for the reason the listener does not: a follower's
configuration is replaced by replication, a delete performed locally
would be undone on the next round, and the control plane's sweep
removes the rows for the whole fleet. The gate is checked twice, at
spawn on the role the process started with and at every tick on the
stored identity, so a node that joins a fleet after boot stops sweeping
without a restart. A tick that cannot read the identity skips the
sweep rather than guessing.

**Set `ttl_seconds` strictly greater than GitLab's `auto_stop_in`.**
GitLab stops a review environment by running the `on_stop` job, which
issues the `DELETE`; that is the lifecycle, and it should stay GitLab's.
The TTL exists for the environment whose stop job never ran, because
the pipeline was cancelled, the runner died, or the branch was deleted
with the environment left dangling. With the TTL longer than
`auto_stop_in`, every environment that GitLab manages is gone before
Lorica ever looks at it, and Lorica only collects orphans. With the TTL
shorter, Lorica tears down environments GitLab still believes are up,
and the review URL on the merge request goes dark before the stop
button does. A re-run of the deploy job moves `expires_at` forward
again, so a long-lived branch stays served as long as it keeps
deploying.

## `managed_by`

Routes and backends an environment creates carry
`managed_by = {kind: automation, environment: <name>}`. Both the
management API and the dashboard read it, and the API is the guard: the
dashboard only makes the refusal visible before the call.

On the management API, a `PUT` on a managed route or backend answers
`409 Conflict` naming the environment and saying to update it through
the pipeline, because the next automation `PUT` would overwrite a manual
change in full. There is no separate maintenance endpoint; maintenance
mode is a field of the route `PUT`, so it is refused with it. A `DELETE`
on a managed backend is refused the same way: removing one backend from
an environment's set is an edit of that set, which only the pipeline
owns, and the message says to delete the environment or update it
through the pipeline. A `DELETE` on a managed route is allowed, and it
deletes the whole environment with it, because
`automation_environments.route_id` is `ON DELETE CASCADE`; the audit row
names the environment so the deletion is attributable.

The dashboard mirrors that. The Routes and Backends pages show an
`automation` badge naming the environment; the edit button, the
maintenance toggle and, on a backend, the delete button are disabled
with the hint that the row is managed by the automation API for that
environment; a route drawer opened on such a row shows the same hint,
disables every field and refuses Save. Deleting a managed route stays
available behind a confirmation that says the environment goes with it.

Nobody can hand-create a row that claims automation ownership. The
management API refuses `managed_by` on input with `422`: only the
automation plane writes it. And `automation:<name>` as a group name is
refused by the group-name validator on both the route and the backend
paths, whose alphabet is lowercase ASCII letters, digits, `-` and `_`
and does not include the colon. That looked like an inconsistency during
implementation and is a guard: the mark and the group name agree by
construction.

## GitLab OIDC

A static token is a long-lived shared secret sitting in a CI variable.
It is masked, it is scoped, and it is still a secret that outlives every
job that uses it. A GitLab job can instead present the ID token the
instance mints for it: a JWT that lives for minutes, that states which
project, ref and environment the job actually runs for, and that no
Lorica credential has to exist for at all. That last part is what makes
this more than credential hygiene: the authorisation stops being
"whoever holds this string" and becomes "a job for project X deploying
environment Y".

Both modes coexist on the listener, on the same bearer header, picked
by shape as described above, with the same 401 for every refusal.

### The job snippet

Ask GitLab for a token whose audience names your Lorica instance, and
present it as the bearer credential:

```yaml
deploy-review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://$CI_ENVIRONMENT_SLUG.review.example.com/
    on_stop: stop-review
    auto_stop_in: 3 days
  id_tokens:
    LORICA_ID_TOKEN:
      aud: lorica-prod
  script:
    - |
      printf 'header = "Authorization: Bearer %s"\n' "$LORICA_ID_TOKEN" |
        curl --fail-with-body --silent --show-error --config - \
          --header "Content-Type: application/json" \
          --request PUT --data @environment.json \
          "https://lorica.internal.example.org:9446/automation/v1/environments/${CI_ENVIRONMENT_SLUG}"
```

`aud` is the only value the job chooses. It must equal the `audience`
of an issuer entry registered on this Lorica instance, and it should
name the instance (`lorica-prod`, `lorica-staging`), so that a token
minted for one Lorica cannot be replayed against another.

The token is an environment variable, never argv: `id_tokens:` puts it
in `${LORICA_ID_TOKEN}`, `printf` is a shell builtin, and `curl
--config -` reads the header from standard input, so the credential
never appears on a command line that `/proc` or a job log could show.
A job that writes it into a file or a log has published a five-minute
credential for its project.

### Registering the issuer

An issuer entry is the trust configuration behind an ID token: who
signs, which audience the job must name, which claims must match, and
the grant a matching token receives. Registration is SuperAdmin on the
management API and is audited (`automation.oidc_issuer.create`).

```bash
curl --fail-with-body --silent --show-error \
  --cookie "$LORICA_SESSION" \
  --header "Content-Type: application/json" \
  --request POST https://127.0.0.1:9443/api/v1/automation/oidc-issuers \
  --data '{
    "issuer": "https://gitlab.example.com",
    "audience": "lorica-prod",
    "bound_claims": {
      "project_path": "acme/*",
      "ref_protected": "true"
    },
    "allowed_hostnames": ["*.review.example.com"],
    "allowed_backend_cidrs": ["10.0.0.0/8"],
    "max_ttl_seconds": 259200,
    "scopes": ["environments:read", "environments:write"]
  }'
```

Field by field:

| Field | Meaning | Rule |
|---|---|---|
| `issuer` | The GitLab instance URL, which is the token's `iss`. | `https` only, no credentials in the URL, no query string or fragment. |
| `audience` | The value the job puts in `id_tokens.<NAME>.aud`. | Identifies THIS Lorica instance. Several entries may share one. |
| `jwks_url` | Where the signing keys are fetched from. | `https` only. Defaults to `<issuer>/oauth/discovery/keys`, which is where GitLab publishes them. |
| `ca_pem` | A CA this entry pins for its own JWKS fetch. | Optional. One or more PEM certificates, 64 KiB at most; at least one must parse or the registration is refused. Never returned: a listing answers with `ca_fingerprint`. |
| `bound_claims` | Claims that must match exactly. | Keys from the closed set `project_path`, `namespace_path`, `ref_protected`, `environment_protected`, `deployment_tier`. At least one of `project_path` and `namespace_path`: `aud` is not a secret, so an entry binding neither accepts a token from every project on the instance. A `*` glob is accepted in `project_path` ONLY, must carry a `/` before its first `*` (`acme/*`, never `acme*`, which would also cover `acme-evil/pwn`), and never spans a `/`, so `acme/*` is the acme group's own projects and `acme/sub/*` is how a subgroup is granted. The two `_protected` claims take exactly `true` or `false`. |
| `allowed_hostnames` | Hostname patterns a token may claim. | At least one. Same one-label wildcard rule as a static token; a bare `*` is refused. |
| `allowed_backend_cidrs` | CIDRs a token may point a hostname at. | Same rule as a static token: at least one, and an empty list is refused rather than read as every address. |
| `max_ttl_seconds` | Ceiling on the lifetime an environment may request. | Defaults to seven days, capped at thirty. |
| `scopes` | What a token may do. | At least one; the same closed list as a static token. |

**Which CA signs the JWKS endpoint.** The fetch runs on the node's own
trust: webpki's public root bundle plus the platform store, which is
where a distribution's `ca-certificates` bundle and anything
`SSL_CERT_FILE` points at end up. A public `gitlab.com` needs nothing.
A self-hosted GitLab behind a corporate PKI has two ways to work:
install that CA on the host, where the platform store picks it up for
every entry, or pin it on the entry itself with `ca_pem`.

Pinning REPLACES the node's trust for that entry rather than adding to
it. That is deliberate: an operator who names a CA is naming the
authority they expect to have signed that endpoint, and keeping the
public bundle alongside it would leave a few hundred commercial CAs
able to vouch for the issuer too, which is the outcome pinning exists
to refuse. Pin on the entry when the CA should be trusted for this one
issuer and nothing else; install it on the host when the whole node
should trust it. A listing never echoes the certificate back; it
reports `ca_fingerprint`, the lowercase-hex SHA-256 of the first
certificate's DER, which is what `openssl x509 -fingerprint -sha256`
prints, so the pinned CA can be confirmed without the material leaving
the node.

**One entry is one authorisation policy.** Several entries may share
an issuer and an audience with different bound claims: the verifier
tries every entry whose audience the token names, in registration
order, and the first whose bound claims all hold accepts the token. A
group of projects with one grant is one entry with
`"project_path": "acme/*"`; a production project with a wider grant is
a second entry with `"project_path": "acme/web"` and
`"deployment_tier": "production"`. The glob spans slashes, so `acme/*`
covers `acme/team/web` too; everywhere but `project_path` a `*` is a
literal star, which no real claim holds.

**Why globs are allowed on one claim and not the others.**
`project_path` takes a glob because a group of projects is a real
authorisation unit. `ref_protected`, `environment_protected` and
`deployment_tier` are booleans and enums whose whole value is being
exact; a glob there would silently widen a decision an operator
believed they had narrowed, so the model refuses it at registration.

**Binding to a protected environment.** An entry whose bound claims
include `"environment_protected": "true"` only accepts tokens minted
for a job deploying a protected GitLab environment, and additionally
ties the environment NAME to that job: a `PUT` on
`/automation/v1/environments/{name}` is refused with a 403 unless
`name` equals the GitLab slug of the job's `environment` claim, which
is what `$CI_ENVIRONMENT_SLUG` holds. A job for `review/mr-42` can
therefore create `review-mr-42-<suffix>` and nothing else, and a job
with no `environment` claim at all can create nothing under that entry.
The slug rule (lowercase, non-alphanumerics to `-`, an `env-` prefix
when the name does not start with a letter, squeezed dashes, and for a
name that is not already a slug or exceeds 24 characters the first 17
characters plus `-` plus six base-36 digits of its SHA-256) is
reimplemented from GitLab's source and tested for shape, not against a
value captured from a live instance; a mismatch would surface as a 403
naming both the sent name and the expected slug on the first protected
deployment.

Listing (`GET`) and removal (`DELETE .../{id}`) are SuperAdmin too, and
removal is audited as `automation.oidc_issuer.delete` with everything
the entry said, since the row holds no credential whose history
matters. Removal takes effect on the very next request: the listener
reads the entries for a token's audience from the store on every
request and caches nothing, so there is no invalidation step to get
wrong. The key cache and the replay set are per process and per URL,
not per entry, and neither can admit a token an entry no longer vouches
for.

### What the listener checks

For every presented ID token, in this order:

1. The header's `alg` must be exactly `RS256`, by string comparison on
   the header before any library code runs; the `Validation` handed to
   the library then lists RS256 alone, so the algorithm is pinned twice
   and never read from the token to choose. A token whose header says
   `HS256`, signed with the issuer's public key as the MAC secret, is
   refused before any key is looked up, and so is `alg: none`. The
   header's `kid` must be present and non-empty.
2. The token's `aud` is read WITHOUT verification, only to select the
   issuer entries to try; a forged `aud` selects entries whose keys then
   refuse the forgery. No entry for that audience is a refusal. The
   list is capped at 8 entries and the bearer value itself at 8 KiB,
   both before any store access: the audience list is attacker-chosen
   and each entry is one indexed read inside the single closure that
   holds the store mutex, plus one audit row per attempt.
3. The `kid` is looked up in the key set fetched from the entry's
   `jwks_url` over HTTPS on the node's trust roots, with a 5 second
   connect timeout, a 10 second total timeout, a 256 KiB body cap, and
   a redirect policy that follows at most three redirects and only to
   the same scheme, host and port, so a compromised or mistyped issuer
   cannot turn the control plane into a probe of its own network. Only
   RSA keys carrying a `kid` are kept. The set is refreshed every six
   hours, and on an unknown `kid` at most once per minute per URL
   regardless of how many unknown kids arrive; the cap is on ATTEMPTS,
   so a failing issuer is also asked once a minute and not once per
   request. Without it a caller sending tokens with random `kid` values
   would drive one outbound fetch each, at request rate. The cache
   lock is NEVER held across the fetch: one unreachable issuer would
   otherwise stall every OIDC authentication on the node for the full
   ten-second timeout, cached issuers included. A burst on one issuer
   still produces one fetch and not a herd, because the attempt stamp
   is claimed under the lock before it is dropped, so the second
   request through finds itself inside the minute and answers from what
   the cache holds. A fetch failure keeps the cached keys until
   their refresh interval elapses; once it has elapsed with no
   successful fetch there is no key the node can vouch for, and
   verification fails closed until the issuer answers again.
4. The signature, `iss`, `exp` and `nbf` are checked by the library
   with 60 seconds of leeway; `iat` is checked by the verifier itself
   against the same skew, because a token issued in the future is not
   one the issuer could have minted. `jti`, `iat`, `exp` and
   `project_path` must be present.
5. Per entry sharing that key source, `aud` must name the entry's
   audience and every bound claim must hold; the first entry that
   accepts wins.
6. `jti` must not have been accepted before. Only an accepted token
   consumes its `jti`, so a mismatch on one entry cannot turn a later
   request on another entry into a replay. Accepted ids are kept, keyed
   by issuer and `jti`, until their `exp` in a bounded in-memory set of
   50 000 entries; an ID token lives for minutes, so reaching the cap
   at all means several hundred accepted tokens per second sustained,
   which is not a CI pipeline. When the set is full the entries expiring
   soonest are evicted, a WARN is logged, and
   `lorica_automation_oidc_replay_evictions_total` counts them. A value
   that moves is worth an alert: every evicted id was still valid, and
   the window until its expiry is a replay window. A silent eviction
   would have turned a full set into exactly that.

The accepted token becomes a principal whose grant is the entry's
(scopes, hostnames, backend CIDRs, TTL ceiling) and whose identity is
the token's: the ownership rule runs on `project_path` as described
above, and every environment the job writes records `project_path`,
`ref`, `pipeline_id`, `job_id` and `user_login` in its `pipeline` field,
where `GET` and `whoami` report them and the audit trail keeps them.

### Reading a refusal

Every refusal is the same 401 on the wire, and every missing grant the
same 403. The audit row is where the precise cause is written, and it
is written in the two places an operator looks:

- **`GET /api/v1/audit`**, and the Audit page that reads it. The reason
  rides inside the row's `action`, after a colon:
  `automation.request.unauthenticated:wrong_alg`,
  `automation.request.forbidden:environments:write`. Filtering the
  endpoint on `action=automation.request.unauthenticated` still returns
  every refusal, because the filter is a prefix match.
- **syslog, OTLP and the file log**, which carry the `lorica::audit`
  tracing event. The same text is a `reason` field of its own there, so
  a SIEM rule matches on a field instead of parsing a dotted verb.

The row is durable within the audit writer's next drain, not before
the 401 comes back. Both planes hand their rows to one bounded queue
that a single writer drains in arrival order, which is what keeps the
hash chain in the order the requests were served; the write no longer
sits between the request and its response. In practice the row is
there before an operator can look, but a script that refuses a request
and reads `GET /api/v1/audit` in the same breath can race it. If the
queue stays full, rows are dropped rather than made to wait, and
`lorica_audit_rows_dropped_total` counts exactly how many: a non-zero
value is the only evidence that the trail has a gap, so alert on it.

What it is never written into is a payload. Payloads are hashed and
never stored (Story 9.9) because they may carry secrets; the reason
vocabulary below is a closed list of words the node chooses, with no
caller-supplied material in it, which is exactly why it may travel in
clear where a payload may not. The one list the code and this table
both answer to is `AUTOMATION_AUDIT_REASONS` in
`lorica-api/src/automation/audit.rs`, and a test refuses any reason the
gates can emit that is not in it.

#### 401, the credential

| `reason` | Meaning |
|---|---|
| `no_bearer` | No `Authorization: Bearer` header, or another scheme, or an empty value. |
| `bearer_too_long` | The bearer value is over 8 KiB; refused before its shape is looked at. |
| `not_a_credential` | Neither a `<public_id>.<secret>` static token nor anything JWT-shaped. |
| `token_unknown_or_wrong_secret` | No such static token, or the secret half does not verify. The two are one reason on purpose: telling them apart would confirm a public id. |
| `token_revoked` | The static token was withdrawn. |
| `token_expired` | The static token is past its `expires_at`. |
| `malformed` | Not a decodable JWT, or a payload with no usable `aud`. |
| `too_many_audiences` | The token names more than 8 audiences; refused before any store read. |
| `wrong_alg` | The header's `alg` is not `RS256` (`HS256`, `none`, `RS512`, ...). |
| `no_issuer` | No registered entry names the token's `aud`. |
| `unknown_kid` | The header's `kid` is absent, or the current key set does not carry it. |
| `jwks_unavailable` | The key set could not be fetched and no cached set is within its refresh interval. |
| `invalid_key` | The key set carries the `kid` but the key could not be used. |
| `bad_signature` | The signature does not verify under the named key. |
| `expired` | `exp` is past, beyond the skew. |
| `not_yet_valid` | `nbf` or `iat` is in the future, beyond the skew. |
| `wrong_iss` | `iss` is not the entry's issuer. |
| `wrong_aud` | `aud` does not name the entry's audience. |
| `bound_claim_mismatch:<claim>` | The named bound claim does not hold; the first one, in name order. |
| `missing_claim:<claim>` | A claim the verifier needs (`jti`, `iat`, `exp`, `iss`, `project_path`) is absent. |
| `replayed` | The `jti` was already accepted and has not expired. |
| `store_error` | The issuer entries could not be read; the node's problem, not the caller's. |

When several entries were tried, the row carries the reason of the last
one. A pipeline that cannot authenticate therefore asks an operator,
who reads the row; the wire tells an attacker nothing about which mode
was tried or how close they got.

#### 403, the grant

The credential authenticated and the scope gate turned it away. The
reason is the grant the path wanted, spelled exactly as the token
spells it, so an operator can compare it against `whoami` without
translating:

| `reason` | Meaning |
|---|---|
| `environments:read` | The path reads environments and the credential does not carry the scope. |
| `environments:write` | The path writes environments and the credential does not carry the scope. |
| `routes:read` | Same, for the routes an environment resolves to. |
| `certificates:read` | Same, for certificate metadata. |
| `no_declared_scope` | The path has no entry in the scope matrix, so no token can reach it. A bug in Lorica, not in the caller: the scope gate also logs it at ERROR. |

A 403 a handler raised rather than the scope gate (an ownership rule, a
hostname outside the credential's grant) carries no reason at all: the
verb is a bare `automation.request.forbidden`. Naming the path's scope
there would send an operator off to re-mint a token that was never the
problem; the handler's own message on the wire is what explains those.

#### The node's own faults

`automation.request.error` is a 5xx: the node broke rather than
deciding. It is its own outcome word so that a trail scanned for
Lorica's faults does not have to pick them out of the requests Lorica
turned away on purpose. A handler that panics lands here too, with a
500 on the wire and a row like any other request.

### Static token vs ID token

| | Static token | GitLab ID token |
|---|---|---|
| What the job holds | A long-lived secret in a masked, protected CI variable. | Nothing before the job starts; GitLab mints the token per job. |
| Lifetime | Until its `expires_at` (default one year) or revocation. | The job timeout or five minutes, whichever is shorter. |
| What Lorica stores | HMAC of the secret half, per token. | The issuer entry only; no per-job state beyond the `jti` until `exp`. |
| Who is the principal | The token's name; ownership by that exact name. | The job's `project_path`; ownership by that exact path, per project. |
| What the authorisation is bound to | Whoever holds the string. | The project, ref and environment GitLab signed into the claims. |
| Rotation | An operator mints a new token and updates the CI variable. | Automatic; the key set rotates at the issuer and Lorica follows on the next unknown `kid`. |
| Revocation | `DELETE /api/v1/automation/tokens/{public_id}`, immediate. | `DELETE /api/v1/automation/oidc-issuers/{id}` for the whole policy, immediate; a single job cannot be revoked short of its five minutes. |
| Blast radius of a leak | Every hostname and backend range the token allows, until revoked. | The same grant, for at most five minutes, from a token that also names the job that leaked it. |
| Outbound dependency | None. | HTTPS to the issuer's `jwks_url`, cached six hours, fail-closed after. |
| Works without GitLab | Yes. | No: the verifier is written against GitLab's claim set. |
| Choose it when | The automation is not a GitLab job, or the node cannot reach the GitLab instance. | The automation is a GitLab job and an operator would rather bind authority to a project than to a string. |

Neither mode replaces the other. A deployment with no GitLab keeps the
mode it has; a deployment with both picks per issuer entry and per
token, and the audit trail names which credential each request came
through.

## A GitLab job, end to end

Both pipelines below do the same three things: a deploy job writes
`environment.json` and `PUT`s it under `$CI_ENVIRONMENT_SLUG`, the
`environment.url` on the merge request is the same URL the response
returns, and a manual `on_stop` job issues the `DELETE`. `ttl_seconds`
is four days against an `auto_stop_in` of three, so GitLab stops the
environment first and Lorica only collects the ones GitLab never got
to. `REVIEW_BACKEND_ADDR` is the `ip:port` of the container the job
started, inside the credential's `allowed_backend_cidrs`.

The body is the same in both modes:

```yaml
.write-environment-json:
  script:
    - |
      cat > environment.json <<EOF
      {
        "hostname": "${CI_ENVIRONMENT_SLUG}.review.example.com",
        "backends": [{ "address": "${REVIEW_BACKEND_ADDR}" }],
        "certificate": "auto",
        "force_https": true,
        "ttl_seconds": 345600,
        "labels": { "project": "${CI_PROJECT_PATH_SLUG}", "ref": "${CI_COMMIT_REF_SLUG}" }
      }
      EOF
```

**Static-token mode.** `LORICA_AUTOMATION_TOKEN` is a CI/CD variable
marked both masked and protected, holding the string
`lorica automation token create` printed once.

```yaml
deploy-review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://$CI_ENVIRONMENT_SLUG.review.example.com/
    on_stop: stop-review
    auto_stop_in: 3 days
  script:
    - !reference [.write-environment-json, script]
    - |
      printf 'header = "Authorization: Bearer %s"\n' "$LORICA_AUTOMATION_TOKEN" |
        curl --fail-with-body --silent --show-error --config - \
          --header "Content-Type: application/json" \
          --request PUT --data @environment.json \
          "https://lorica.internal.example.org:9446/automation/v1/environments/${CI_ENVIRONMENT_SLUG}"

stop-review:
  stage: deploy
  when: manual
  variables:
    GIT_STRATEGY: none
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    action: stop
  script:
    - |
      printf 'header = "Authorization: Bearer %s"\n' "$LORICA_AUTOMATION_TOKEN" |
        curl --fail-with-body --silent --show-error --config - \
          --request DELETE \
          "https://lorica.internal.example.org:9446/automation/v1/environments/${CI_ENVIRONMENT_SLUG}"
```

**ID-token mode.** No variable to store; the entry registered above
accepts any job of the `acme` group on a protected ref.

```yaml
deploy-review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://$CI_ENVIRONMENT_SLUG.review.example.com/
    on_stop: stop-review
    auto_stop_in: 3 days
  id_tokens:
    LORICA_ID_TOKEN:
      aud: lorica-prod
  script:
    - !reference [.write-environment-json, script]
    - |
      printf 'header = "Authorization: Bearer %s"\n' "$LORICA_ID_TOKEN" |
        curl --fail-with-body --silent --show-error --config - \
          --header "Content-Type: application/json" \
          --request PUT --data @environment.json \
          "https://lorica.internal.example.org:9446/automation/v1/environments/${CI_ENVIRONMENT_SLUG}"

stop-review:
  stage: deploy
  when: manual
  variables:
    GIT_STRATEGY: none
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    action: stop
  id_tokens:
    LORICA_ID_TOKEN:
      aud: lorica-prod
  script:
    - |
      printf 'header = "Authorization: Bearer %s"\n' "$LORICA_ID_TOKEN" |
        curl --fail-with-body --silent --show-error --config - \
          --request DELETE \
          "https://lorica.internal.example.org:9446/automation/v1/environments/${CI_ENVIRONMENT_SLUG}"
```

Three things about these jobs are load-bearing. The runner's address
must be inside `automation_allowed_cidrs`, or the `PUT` never gets a
TLS handshake, let alone an answer. A re-run of the deploy job is a
second `PUT` under the same name: it answers 200 with the same
`route_id`, replaces the backend set, and moves `expires_at` forward,
so nothing needs cleaning up between runs. And the stop job's `DELETE`
answers 204 even when the reaper got there first, so a stop button
pressed after the TTL ran out is still a green job.

## Metrics

Every family below is in the node's `/metrics`, and every label set is
a closed enum spelled at the call site: no token name, no environment
name and no hostname ever becomes a label. Under `--workers` all of
them are supervisor-only, because the listener, the handlers and the
reaper all run in the supervisor.

- **`lorica_automation_environments{state}`** (gauge): environments by
  state, `active` (before `expires_at`) or `expired` (at or past it and
  not yet collected). Refreshed under the store lock after every write
  that changes the set, a `PUT`, a `DELETE` or a reaper sweep, so it
  never describes a row set other than the one just committed.
  `expired` is a window of at most one reaper interval on a healthy
  node; a value that stays above zero across scrapes means the reaper
  cannot remove a row.
- **`lorica_automation_environment_ops_total{op, outcome}`** (counter):
  `op` is `create`, `update`, `delete` or `expire`; `outcome` is `ok`,
  `refused` (a 4xx the caller provoked, a 412 included) or `error` (a
  failure on the node's side).
- **`lorica_automation_reaper_runs_total`** (counter): sweeps, whether
  or not one removed anything. A counter that stops moving on a control
  plane is the reaper task having died, which nothing else reports.
- **`lorica_automation_requests_total{outcome}`** (counter): one per
  request on the listener, `outcome` being the word the audit row
  gets, `ok`, `unauthenticated`, `forbidden`, `error` (a 5xx, the
  node's own fault, a panicking handler included) or `refused`, so the
  scrape and the log never disagree on what a request was.
- **`lorica_automation_source_refused_total`** (counter): connections
  dropped before the handshake because the source was outside
  `automation_allowed_cidrs`.
- **`lorica_automation_rejected_concurrent_handshakes_total`**,
  **`lorica_automation_rejected_per_source_total`**,
  **`lorica_automation_rejected_attempt_window_total`** (counters):
  connections dropped by each of the three pre-authentication budgets,
  one counter each because they answer different questions.
- **`lorica_automation_tls_handshake_failed_total`** (counter):
  handshakes that failed or timed out after the budgets admitted the
  connection.
- **`lorica_automation_oidc_jwks_fetch_total{outcome}`** (counter):
  key-set fetches from registered issuers, `ok` or `error`.
- **`lorica_automation_oidc_replay_evictions_total`** (counter): `jti`
  entries evicted before their expiry because the replay set was full.
  Alert on any movement.

## Troubleshooting

**401 or 403?** A 401 means the credential was not accepted: missing,
malformed, unknown, wrong, revoked, expired, or an ID token that failed
any check. Retrying with the same credential will not help; read the
`automation.request.unauthenticated` audit row for the reason. A 403
means the credential WAS accepted and the grant is not there: the path
wants a scope the credential does not carry (the message names it), the
hostname is outside `allowed_hostnames`, a backend address is outside
`allowed_backend_cidrs` (or the credential names no CIDR at all), an
explicit certificate id was named without `certificates:read`, or the
entry binds `environment_protected` and the name is not the job's
slug. Do not re-mint a token for a 403; fix the grant or the request.

**A 404 on an environment a colleague says exists.** It exists and it
is not yours: it belongs to another principal and carries no
`shared: "true"` label. Foreign and unknown answer alike on purpose,
so the status cannot be used to enumerate the neighbours' names. The
`automation.environment.forbidden` audit row of that very call says
which it was.

**`no_certificate_covers_hostname`.** No certificate's `domain` or
`san_domains` covers the hostname under the one-label wildcard rule.
The message names the wildcard to provision, `*.review.example.com`
for `pr-42.review.example.com`, through
`POST /api/v1/acme/provision-dns` (DNS-01, the only challenge that can
issue a wildcard). Provision it once; every review app under it then
resolves, and a later replacement of that certificate moves them over
at the next snapshot build. A certificate for `*.example.com` does not
cover `pr-42.review.example.com`: the wildcard stands for exactly one
label, here as in TLS.

**409 on a hostname.** Another route holds the hostname, as its
`hostname` or one of its `hostname_aliases`. The message names the
hostname and nothing about that route, because the caller is a
credential and the route is an operator's. Look it up on the Routes
page; if it is a stale environment under another name, its owner
deletes it or the reaper will.

**A managed row cannot be edited.** The row carries `managed_by` and
the dashboard refuses in-place edits on it, because the next `PUT` from
the pipeline overwrites the whole route and backend set. Change the
pipeline's `environment.json` and re-run the deploy job, or delete the
environment and let the pipeline recreate it. `automation:<name>` as a
group name is refused on a hand-made route: only the automation plane
writes that mark.

**My environment vanished.** The reaper collected it: look for an
`automation.environment.expired` audit row by the node (`reaper`,
role `node`) naming it, or for `automation.environment.delete` from a
principal, or for a route deletion by an operator, which cascades the
environment row. If it was the reaper, `ttl_seconds` was shorter than
the time between deploys, or shorter than GitLab's `auto_stop_in`, so
Lorica got there before GitLab. Set the TTL strictly longer than
`auto_stop_in`; every re-run of the deploy job moves `expires_at`
forward.

**The fleet has not picked it up.** The `PUT` answered before the
replication round it started had published. Poll
`GET /api/v1/cluster/status` on the control plane until every node's
`applied_config_generation` EXCEEDS the `applied_generation` the `PUT`
returned; do not compare hashes, which legitimately differ per node.
A node that stays behind is a drift question, not an automation one:
see `docs/cluster.md`, "Convergence".

**The listener refuses to start.** Two refusals depend on node state,
and both exit non-zero with their reason in the journal. "This node
holds a follower identity" means the automation belongs on the control
plane, whose environments replicate to this node anyway; point the
pipeline there, or `lorica cluster leave` first if this node is meant
to stand alone. "`automation_allowed_cidrs` is empty" means the global
setting has no entry; add the runners' ranges on the Settings page and
restart. An entry that does not parse refuses the listener too, naming
the entry. The bind refusals (a bare port, a wildcard host without
`--automation-listen-any`, a port another listener holds) are the CLI
validator's and name the flag.

**The runner gets a connection reset, not a 401.** Its address is
outside `automation_allowed_cidrs`: the socket is dropped before the
TLS handshake and `lorica_automation_source_refused_total` moves. A
handshake that starts and fails is
`lorica_automation_tls_handshake_failed_total`, usually a runner that
does not trust the management certificate.

**Which mode am I in?** `GET /automation/v1/whoami` with the credential
the pipeline holds answers `kind` (`static_token` or `oidc_project`),
`name` (the token's label or the project path), `public_id` (the
token's lookup half or the issuer entry's id, the thing an operator
revokes), `scopes`, and for an ID token the `pipeline` identity GitLab
signed. It needs `environments:read`; a token minted with
`environments:write` alone cannot call it, which is the first thing to
check when `whoami` itself answers 403.
