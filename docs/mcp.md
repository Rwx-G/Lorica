# The Lorica management MCP server

**Author:** Romain G.
**Since:** v1.9.0

`lorica-mcp` lets an operator talk to Lorica from a Model Context
Protocol client. It has three tiers, and a server is one of them by the
token it was started with. The **read tier** asks what Lorica is
seeing: access-log rows, WAF events, SLA windows, cluster status and the
configuration as it stands, and cannot change anything. The **config
tier** creates and adjusts routes, backends and certificate bindings,
through the same validators the dashboard uses, with a preview of every
change before it is made. The **admin tier** changes a short, named
list of operational global settings and nothing else; it is defined by
what it refuses.

It speaks two transports over one core: **stdio**, for a client that
launches it as a subprocess, and **Streamable HTTP**, as one path on
the automation listener. The tools, the scopes, the paging, the
untrusted-text marking and the protocol revision are the same on both,
because both run the same code; what differs is what carries the
messages and what each one can honestly put in an audit row.

## What it is not

- **Not a client of the management API.** It never holds a dashboard
  session or a management credential. It is a client of the automation
  plane ([automation.md](automation.md)), with a scoped automation
  token, and it can do nothing that token's scopes and grants do not
  allow. An operator who has not enabled `--automation-listen` has no
  MCP surface at all.
- **Not a service.** Neither binding opens a socket of its own: the
  stdio server is a subprocess the MCP client launches for the length
  of its session, and the Streamable HTTP endpoint is a path on a
  listener that already exists. No systemd unit starts it (see
  [Running it](#running-it)).
- **Not a way to reach identity, tokens or the fleet's membership.** No
  path on the automation plane reaches users, roles, the automation
  tokens, the OIDC issuer entries, the cluster's nodes, its enrolment
  tokens or its fleet-wide bans, for any verb and any token, and no
  tool of any tier names one.
- **Not a key-material channel.** No tool takes or returns a private
  key, a certificate body or a CSR.
- **Not a filter on what users and attackers wrote.** Log rows and WAF
  events reach the model as recorded, less a short list of values the
  plane withholds; see
  [What it cannot see, and why](#what-it-cannot-see-and-why) for which,
  and for what the rest means when the model is hosted.

## Why there are tiers, and why they are separate processes

The text an operator most wants to reason about is text Lorica
collected from whoever was attacking them: User-Agent strings, request
paths, WAF matched payloads, TLS SNI values, usernames from failed
Basic-auth attempts. Handing that to a language model is the whole
feature, and it is also the attack. A request path is a string an
attacker chose, and if the session reading it also holds a tool that
deletes a route, that path is an instruction channel into production.

So the authority a session holds is decided by the token it was started
with, not by a mode it can switch. A read-tier server has no mutating
tool to be talked into using, because the tools were never registered:
every mutating tool sits behind a write scope, and a token carrying
read scopes alone registers none of them. That is a property of the
process, not a rule it follows. The config tier is therefore a
**separate token and a separate server process**: one that holds write
scopes, started for the work of changing things, and not the one an
operator reads hostile text through.

**One process serves one tier, and the server enforces it.** Which
scopes make a token which tier is one table, `TIERS` in
`lorica-mcp/src/tier.rs`: for each tier the scopes it requires and the
scopes of another tier it tolerates because its own tools need them.
Every automation scope is required by exactly one tier, which a test
derives from the token model's enum. The read tier tolerates no write
scope. The config tier tolerates the read scopes its previews answer
and its tools find ids through, and nothing else; the admin tier
tolerates nothing. A token whose scopes span two tiers is refused
before any tool registers, with the offending scopes named: `logs:read`
beside `routes:write` is refused, because the config tier does not
tolerate a read of attacker-authored text. A token carrying a scope no
tier knows is refused the same way.

Both refusals come from the one constructor both bindings build their
server through, so neither binding can serve a token the other refuses:

- **stdio** refuses at startup. The message goes to stderr and names
  the scopes that anchor the tier, the ones it does not allow and the
  tier each belongs to, then the process exits with code **78**, the
  code it uses for every configuration fault:

  ```
  lorica-mcp: this token's scopes span more than one MCP tier, and one
  process serves one tier. routes:write makes it the config tier, which
  does not allow logs:read (read tier). Mint one token per tier with
  `lorica mcp token create --tier read|config|admin`.
  ```

  A test renders that refusal and holds this example to it. A token
  carrying a scope this build does not know, minted on a newer node, is
  told so and told to run the `lorica-mcp` that ships with that node,
  rather than to split tiers.

- **Streamable HTTP** refuses on every request that presents such a
  token, with a **`403`** whose body is a JSON-RPC error (`-32600`)
  carrying the same text under the request's id, followed by the remedy
  for the credential that presented it: a static token is minted again
  per tier, and an OIDC issuer entry, which grants its scopes to every
  job it matches, is split into one entry per tier. No server is built
  and nothing runs, and the audit row reads
  `automation.request.forbidden:spans_tiers`.

Where each refusal runs matters. Over Streamable HTTP the node refuses:
the check is in the handler, and no client can skip it. Over stdio it
runs in the `lorica-mcp` process the client launched, and the node
itself knows scopes, not tiers. Against the actor the tiers exist for, a
model steered by what it reads, that is enough: the model cannot swap
the binary its client launches. Against an operator who points some
other MCP client at the automation plane with a token spanning two
tiers, it is no control at all; the check guards the operator from a
mistake, not the node from a hostile client.

What the check cannot refuse is an operator who mints three tokens and
hands all three to one client, or who keeps the admin tier configured
because it was convenient once. Processes are separate; a model given
a server of each tier is still one model reading hostile text with a
mutating tool in reach. Those are the
[hardening guide's](security/hardening-guide.md#the-mcp-server-tiers-v190-opt-in).

## Setting it up, the first time

1. **Enable the automation listener** on a standalone node or a
   control plane: `--automation-listen <host:port>` and a non-empty
   `automation_allowed_cidrs` naming where the MCP server or client
   will connect from ([automation.md](automation.md#the-listener)). A
   stdio server on the Lorica host itself connects from loopback, so
   the allowlist must name it; nothing is allowed by default.
2. **Mint one token per tier you need**, with
   `lorica mcp token create --tier` ([Minting a token](#minting-a-token)).
   Start with the read tier alone; mint the config tier for a change
   and the admin tier for a task, each with a short lifetime.
3. **Configure one client entry per tier**, over stdio or Streamable
   HTTP ([Running it](#running-it)), and hand each entry its own token.
4. **Check what it registered.** The stdio server prints one line on
   stderr at startup naming the token's `public_id`, its tier and the
   tools it registered, and what it did not register for want of a
   scope. `tools/list` answers the same set.
5. **Revoke what you are done with** ([Revocation](#revocation-and-expiry)).

## Minting a token

```bash
(umask 077; lorica mcp token create --tier read|config|admin [--name <label>] \
  [--hostname <pattern>]... [--backend-cidr <cidr>]... \
  [--lifetime-days <days>] [--user <superadmin>] \
  --password-file <path-to-0600-file> > <tier>.token)
```

The `umask 077` subshell is what makes the redirect create the file
`0600`: a shell creates it with the ambient umask, `0644` on most
systems, and the file holds a live credential. Piping the output
straight into the client's secret store is better still.

`lorica mcp token create` is a front end over
`lorica automation token create`, not an alternative to it. It resolves
the tier to its scope set from the same `TIERS` table the server
enforces (`Tier::minted_scopes`), and mints through the same request on
the local management API, as a SuperAdmin, so the token is the same
credential, validated by the same model and audited as the same
`automation.token.create` row. The SuperAdmin password is read from
`--password-file` (mode 0600), `--password-stdin` or
`LORICA_ADMIN_PASSWORD`, as for every management CLI command.

Like every management CLI command, it sends the password only to a
listener presenting the certificate the node records as served,
`<data-dir>/management/served-cert.pem`, which the management listener
rewrites each time it starts. The management port is unprivileged, so
this is what keeps a local process that took the port while Lorica was
restarting from receiving the password. The file is in the node's
`0700` directory: run the command as root or as the `lorica` user (the
container examples below run as `lorica`), and pass `--data-dir` when
the node does not use `/var/lib/lorica`. A peer presenting another
certificate is refused with the password unsent, and there is no switch
that skips the check.

The scopes it mints are the tier's tools' scopes and the scopes the
tier tolerates. The config tier therefore carries the read scopes of the
rows its previews answer and its tools find ids through: a config token
without them would register previews the plane refuses. The environment
scopes belong to a tier for the refusal but are never minted, because
no MCP tool uses them. `--name` defaults to `mcp-<tier>`.

**Standard output carries the token and nothing else**, as the command
it fronts, so `> read.token` stores exactly the credential. Standard
error carries the minted `public_id` and expiry, then the tier's blast
radius: the scopes, every tool the token registers with the scope it
sits behind and whether it reads or changes, the grants for the config
tier, and for the admin tier every setting the plane's allowlist names
with its bound, its reach and when it takes effect. That text is
computed from the tier table, the tool catalogue and the allowlist when
it is printed, never written beside them, so it is the authoritative
answer to "what can this token do" for the build you run.

**Lifetime.** Without `--lifetime-days` a token lives its tier's
default, the `default_lifetime_days` column of the same `TIERS` table,
shorter the further the tier reaches; the command prints it with the
blast radius. Pass a shorter one when the task is shorter: a read-tier
token for as long as the client is meant to exist, a config-tier token
for the change, an admin-tier token for the task. **A token carrying
`settings:write` has a ceiling the node enforces**,
`AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS` in `lorica-config`:
`AutomationToken::validate` refuses a longer one with a `422` naming it,
whichever surface mints it (this command, `lorica automation token
create`, the dashboard or the management API), and a test holds the
admin tier's default beneath it. Every other token defaults to
`AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS` when it is minted by a surface
that names no lifetime.

### Grants: required exactly when a scope needs them

A token's hostname and backend grants (`allowed_hostnames`,
`allowed_backend_cidrs`) bound what a write may claim and reach. Only
the grant-bounded scopes consult them, and which scopes those are is
decided in one place, `AutomationScope::is_grant_bounded` in
`lorica-config`: the config tier's write scopes, which a test pins
against the tier table. The rule is typed absence
([automation.md](automation.md#static-tokens)):

- **The config tier requires both.** `--hostname` and `--backend-cidr`
  at least once each, or the command refuses before it logs in. Set
  them to exactly what the model may touch: `'*.app.example.com'`
  rather than a parent zone, a /24 rather than a /8.
- **The read and admin tiers refuse both.** No path those tiers reach
  reads a grant, and a grant that bounds nothing would read as a blast
  radius the token does not have.
- **An empty list means nothing, never everything.** A hostname grant
  with no pattern matches no host, and a CIDR grant with no entry admits
  no address.

```bash
umask 077

# Read tier: no grant, a lifetime chosen for the client.
lorica mcp token create --tier read --lifetime-days 30 \
  --password-file <path-to-0600-file> > read.token

# Config tier: both grants, as narrow as the change; the tier's
# default lifetime.
lorica mcp token create --tier config \
  --hostname '*.app.example.com' --backend-cidr 10.0.4.0/24 \
  --password-file <path-to-0600-file> > config.token

# Admin tier: no grant, the tier's default lifetime, the shortest.
lorica mcp token create --tier admin \
  --password-file <path-to-0600-file> > admin.token
```

A narrower token than a whole tier (routes only, say) is minted with
`lorica automation token create --scope ...`: any subset of one tier's
required scopes and the scopes it tolerates is one tier and is served.
The management API, the plain CLI and the dashboard's Automation tokens
page mint any scope set at all; it is the server that refuses a token
spanning two tiers, rather than serving both kinds of tool: the node
over Streamable HTTP, the `lorica-mcp` process the client launched over
stdio.

**An OIDC issuer entry cannot carry `settings:write`.** An entry is a
standing grant to every pipeline job whose claims match, the opposite
of a token minted for one task, and the node refuses it. It may carry
the config tier's write scopes: a keyless, short-lived CI credential is
what OIDC is for. That is a CI pipeline's credential rather than an MCP
client's, and the threat model records the decision. It is also a
credential for one message on the MCP endpoint: an ID token's `jti` is
single-use, so a second POST with the same token is a replay, answered
401, and an MCP exchange (discover, list, call) is several POSTs. A
pipeline calls the automation paths themselves.

## The read tier

The read tier is one tool per read the automation plane serves: the
access log with the filters the dashboard offers, WAF events and their
aggregate counts, the SLA summary and one route's SLA windows, this
node's cluster status, and the route, backend and certificate listings.
Each tool sits behind the read scope of its family. The catalogue is
`READS` in `lorica-mcp/src/tools.rs`; `lorica mcp token create --tier
read` prints it with each tool's scope, and `tools/list` answers it.

Over stdio which tools register is decided once, at startup, from the
token the server was started with: a server whose token carries a
scope of the tier that no tool uses starts with no tools and says so on
stderr rather than failing every call. Over Streamable HTTP it is
decided per request, from the token that request presented, because
there is no startup to decide it at. Either way a tool the token cannot
reach is not in the list and is unknown to a call.

## What it cannot see, and why

**No secret of Lorica's own leaves through it.** Certificate private
keys, notification-channel credentials, DNS-provider credentials,
Basic-auth hashes and session cookies are absent from every answer,
because the management plane's own views never carry them. A test walks
every answer for credential-shaped field names, and a second test pins
the entire set of field names each read answers, so a field added to a
management view tomorrow turns a gate red and forces a decision instead
of arriving here unnoticed.

**Values the plane withholds.** Some fields of those views carry a
credential an operator put there for the dashboard's sake, and the
automation plane replaces their values with `[redacted]`, keeping every
key: a route's `proxy_headers` (the header names stay, so a model still
sees that a route sends one), the match `value` of each of a route's
`header_rules` (where a secret shared between a client and its canary
goes; the header name, match type and backends stay), the userinfo and
query values of a route's `forward_auth` address, the query values of a
backend's `health_check_path`, and the query values and fragment of an
access-log row's `path`. It does so wherever it answers such a row: the
listings, every write answer and every preview, including a preview's
list of changed fields. The dashboard and the log sinks are unchanged.
A config-tier model that edits one header rule sends the whole list
back, and a rule returned with the `[redacted]` value it was read with
keeps the value stored for the rule at the same position with the same
header name and match type; a marker the node cannot place that way, on
a rule added, moved, renamed or retyped, is refused and names the rule
by position, and the marker is never stored. The environment a route or
backend belongs to (its `managed_by` mark) is named only to a token the
environment endpoint would answer for that environment; every other
token reads the mark with the name `[redacted]`, so the row still says
it is managed without saying whose. The
function and the reasoning are `lorica-api/src/automation/redact.rs`,
and a test walks a route carrying an upstream credential through the
listing, an apply, two previews and the MCP tool, asserting the value
never appears.

**What does cross.** The rest of each row is text end users and
attackers wrote: request paths, client addresses, User-Agent strings,
WAF matched values, SNI names, usernames from failed Basic-auth
attempts. The access log records the request path without its query
string (the proxy logs the URI's path), so no query value of a proxied
request reaches a row, and one that did would be withheld as above. A
WAF event is different on purpose: it carries the span of the request (the path,
the query, a header or the body) that a signature matched, verbatim,
because that span is the attack the event exists to show. A span can
include part of something a user sent, a query value or a header's,
when the signature matched across it. Those values reach the model as recorded, and
through it whatever hosts the model. Pointing a hosted model at this
tier is a decision that this node's WAF events and access-log rows
leave the node; make it knowing that.

**A token with grants sees what its grants cover.** For a token
carrying a scope a grant bounds (the config tier), the route, backend
and certificate listings answer only the rows inside its grants: a
route whose hostname and every alias are inside `allowed_hostnames`, a
backend whose address is inside `allowed_backend_cidrs`, a certificate
whose domain and every SAN are inside `allowed_hostnames`. Those are
the write guard's own predicates, so the rows a config-tier session can
see are the rows it can act on. Free text in a route or a backend (an
error page, a rewrite, a name) is written by every principal holding a
write scope, OIDC pipelines included, and a config-tier model no longer
reads what a lower-trust writer planted outside its own grant. Paging
walks the filtered set. A token carrying no bounded scope (the read
tier) sees every row. No read on the plane fetches one of these rows by
id, so there is no single-row answer to hide; a write or a preview
naming an id outside the grant is refused with a `403` that names the
id and nothing about the row.

**No fleet roster.** `/cluster/status` is served;
`/cluster/nodes` is not. The roster discloses each follower's source
address, the hostnames whose routes name it, and the ids of the
certificates whose private key it receives. The management API gates
that at the Operator role on purpose, and an automation credential
carries scopes and no role, so there is no honest way to serve it at
the same level of trust. Serving it behind a projection that strips
those three fields was considered and refused: this tier's answers are
the management plane's own views, with nothing projected away but the
withheld values above, and that property is what makes a field arriving
here a visible event rather than a silent one.

**No certificate PEM body.** The listing answers metadata. The
single-certificate endpoint that returns the public certificate is
deliberately not on this plane.

## The config tier

The config tier is a set of mutations over the automation plane's write
surface, each with a preview: create, update and delete a route by id;
bind a stored certificate to a route or unbind it; create, update and
delete a backend by id, the delete with the dashboard's graceful drain;
renew an ACME certificate in place. Each sits behind the write scope of
its family. The catalogue is `MUTATIONS` in `lorica-mcp/src/tools.rs`,
from which each apply tool and its `_preview` are built;
`lorica mcp token create --tier config` prints them with their scopes.
A config-tier server also registers the read tools of the scopes the
tier tolerates, which is how it finds the ids it acts on.

**Every mutation is the dashboard's own.** A tool's call runs the
management handler's body, in process on the Streamable HTTP binding
and over the automation listener from stdio, with the token as the
actor where the dashboard's session would be. The validators, the
defaults, the refusal of a row an environment owns and the
management-side audit row are that handler's; `lorica-mcp` does not
reimplement a single field check, so the two surfaces cannot drift, and
a route created through the tier is the dashboard's route byte for byte
in the canonical configuration. What the tool checks is shape: the body
is an object, its keys are ones the handler deserialises, at the top
level and inside every nested object the tool's schema declares
(`path_rules[]`, `rate_limit`, `bot_protection.bypass` and the rest,
each pinned against the struct behind it), and it weighs under the
listener's cap. A field the handler does not know is refused before
the call leaves. That check is the only one a body gets: the node's
own request structs ignore a key they do not know at every depth, so
a mistyped nested key that reached the plane would be dropped there
with nothing said. The one query the plane reads on a write,
`?dry_run`, is strict on its side: a key it does not declare is a 400,
so `?dryrun=true` typed into a direct client is not an apply.

**The token's grants bound what a write claims and what it targets.**
A hostname and every alias a route write claims must be inside the
token's `allowed_hostnames`, and a backend's address must be an
`ip:port` inside its `allowed_backend_cidrs`, both refused with a 403
before the handler runs. The row a write names by id is held to the
same grant, inside the store closure that writes it, so the check and
the write see one row: a route update, delete or certificate binding
needs the route's current hostname and every current alias inside the
hostname grant; a backend update or delete needs the backend's stored
address inside the CIDR grant; a renewal needs every name the
certificate carries, `domain` and each SAN, inside the hostname grant,
and so does a certificate a route write binds anew, since otherwise the
grant said which routes a token may reach and nothing of which
certificates it may deploy on them; and a route or a backend an
environment owns is refused unless the environment's own rules would
let this token reach it: its ownership rule, and for an ID token bound
to `environment_protected = true` the rule that a job writes only the
environment it deploys, since a route delete cascades its environment.
Every backend a route write links anew, at the top level or inside
`path_rules`, `header_rules` or `traffic_splits`, must point inside the
CIDR grant and belong to no other pipeline's environment. The fields of
`WITHHELD_ROUTE_FIELDS` (`lorica-api/src/automation/write.rs`) are
refused from an automation token outright, in either direction, each
with the reason beside it there: the Basic-auth password, a credential
a model would be choosing or relaying, and whose clearing switches the
route's Basic auth off; `forward_auth`, a URL the CIDR grant cannot
weigh, to which the proxy forwards every downstream `Cookie` and
`Authorization` header; `mirror`, which ships a copy of every request
to a second set of backends; `mtls`, the route's client-authentication
trust anchor, the CA bundle whose client certificates the route
accepts, which a model reading attacker text must not be able to
replace; and `proxy_headers`, a static header map to the upstream,
where a credential would go. None of them is offered by the tools. A
config-tier token is bounded by the same two fields an operator reads
on it, on what it may claim and on what it may reach, and a preview is
refused exactly where the apply would be, so a token learns nothing
about a row outside its grant by previewing a change to it.

### Protections move one way

Inside its grant, a token may strengthen a route's access control and
an upstream's TLS trust and never weaken either (the maintainer's
decision of 2026-09-30, "safe direction only"). The rule is a property
of the node, not of the tools: the plane weighs each control in the
guard that runs inside the store closure, on the row as stored against
the row about to be written, so a direct automation client meets it
exactly as a tool call does, and a preview is refused where the apply
would be, with a `403` naming the field and the rule and echoing no
value. The dashboard is not bound by it: the other direction is a
human's. The controls are `ROUTE_PROTECTIONS` and `BACKEND_PROTECTIONS`
in `lorica-api/src/automation/write.rs`, each with its reason; this
table restates their rules, and a test renders each row from the
constant and asserts it is here:

| Control | From an automation token |
|---|---|
| `basic_auth_username` | the Basic-auth credential in force is neither cleared nor changed |
| `ip_allowlist` | added, or narrowed so every entry sits inside one already there; never removed or widened |
| `ip_denylist` | extended, every entry already there staying covered; never shortened |
| `geoip` | added, or tightened in the same mode (fewer countries allowed, more denied); never removed or switched to the other mode |
| `bot_protection`, `bot_protection_disable` | added where none is set; never changed or removed once set |
| `waf_enabled` | switched on, never off |
| `waf_mode` | moved to blocking, never back to detection |
| `rate_limit` | added, or tightened with its capacity and refill never raised and its scope unchanged; never removed |
| `rate_limit_rps`, `rate_limit_burst` | added, or lowered; never raised or cleared |
| `auto_ban_threshold` | added, or lowered; never raised or cleared |
| `tls_skip_verify` | switched off, never on |
| `tls_upstream` | switched on, never off |
| `tls_sni` | left unchanged while the upstream certificate is verified |

A create weighs nothing it does not set against the row it would have
had: every route control above is at its weakest on the row the
management create stores when the body names none of them, so a route
create is not bounded by the table, and a backend create is weighed
against the create's own default, which verifies the upstream
certificate whenever TLS is on, so a create asking for
`tls_skip_verify` is refused. The Basic-auth username is not offered
by the tools at all: where Basic auth is in force it may not change,
and elsewhere a username without the password a token never sends
protects nothing.

What is deliberately outside the rule, each for the reason recorded
beside the constant: the capacity limits (`max_connections`,
`max_request_body_bytes`, `slowloris_threshold_ms`,
`waf_body_scan_max_bytes`, the auto-ban duration), which price a
request rather than decide whether it is admitted; the browser-facing
hardening (`force_https`, `security_headers`, the CORS lists,
`response_headers`), which shapes how a browser treats an answer the
route already admits and is on the list of what not to delegate below;
the AI-crawler policy, a content policy toward clients that declare
themselves, which a hostile client does not; and the routing fields,
where a request goes, bounded by the hostname and CIDR grants.

The rule bounds a write in place, not a sequence of them: a token that
may delete a route inside its grant may create it again without its
protections, in two audited rows, `route.delete` and `route.create`.
A hostname whose protections no model may remove belongs in no
config-tier grant.

**A backend create is not idempotent.** A route create is refused on
a hostname already held, and every other write names its resource by
id, but a backend create that timed out on the client's side may have
committed: a model that retries it without looking creates a second
backend. Check `lorica_backends` for the address before retrying a
create that did not answer.

**The scopes are boundaries too.** A route write that names
`certificate_id`, the empty string included, needs `certificates:write`
beside `routes:write`: the binding tool sits behind the certificate
scope, and a route body that could bind under the route scope alone
made withholding it mean nothing. A preview needs the read scope of the
row it answers, since a preview answers the full row; a token minted
with `--tier config` carries those, and the apply needs nothing more
than its write scope.

**A renewal from a token is budgeted per certificate.** Each renewal
places an ACME order the CA counts against a per-name budget, and
rotates the node's bot-protection HMAC. From a token, a renewal of a
certificate with an order already open answers 409, one issued less
than `MIN_TOKEN_RENEWAL_INTERVAL_HOURS` (in `lorica-api/src/acme`) ago
answers 429 with a `Retry-After`, and one the background loop holds in
a CA rate-limit cooldown answers 429 as well; the preview answers what
the apply would. The dashboard's own renew is bounded by none of it.
The per-token call limit below is the wrong bound for this: it counts
calls per token, and the scarce resource is orders per certificate.

**One named resource per call.** Every tool that acts on an existing
resource takes exactly one `id`, a string, and the body of the one
change. There is no argument that takes a list of ids, a pattern or a
selector, and no tool that deletes what matches. That is the tool
schema's doing, not a check in a handler: the schema admits nothing
undeclared at either level.

**No key material, anywhere.** A certificate is selected by naming its
id, bound and renewed; it is not uploaded, replaced or generated
through the tier, because no path on the automation plane takes a PEM
body. No field a tool accepts, at any depth of the request struct
behind it, is named for a key, a certificate body or a CSR. Two tests
say so, and the second is the one that counts: one walks every tool's
published schema, and one walks the Rust request struct the handler
deserialises, from each field the tool offers into every struct it
nests, because a body field's schema does not spell out what sits
below it and `mtls.ca_cert_pem` travelled under `mtls` while the schema
sweep stayed green. A route's Basic-auth password is refused by the
plane from every automation token and offered by no tool: a model would
be choosing or relaying a credential, and it would cross the model's
host in the clear. Set it in the dashboard; the tier reads the username
alone, as the read tier does.

### Preview before apply

Every mutation has a preview taking the same arguments: the tool's
name with `_preview` appended. It runs the same validators, answers the
change it would make against the configuration as it stands, and writes
nothing: no row, no reload, no management audit row. The answer is the
node's own JSON, fenced as data like every other answer, not a diff
written in words:

```json
{
  "dry_run": true,
  "operation": "update",
  "before": { "id": "...", "waf_enabled": false, "...": "..." },
  "after": { "id": "...", "waf_enabled": true, "...": "..." },
  "changes": { "waf_enabled": { "from": false, "to": true } }
}
```

A create's `after` is the row it would insert, less the id and the
clock the apply would mint; a delete's and a renewal's `before` is the
row that would go or be renewed. A backend delete's preview says what
its apply does: for a backend in normal service, `after` is the row
marked `closing`, since the apply drains it for up to a minute before
the row leaves; for one already closing, `after` is null, since the
apply removes it at once. A renewal's preview resolves the method and
the DNS provider the apply would use, so a certificate the apply cannot
renew is refused by the preview with the same words. What only the
store refuses, a duplicate hostname or a backend id that names
nothing, is refused by the apply and not by the preview, since the
preview inserts nothing. On the wire a preview is the apply's own
request with `?dry_run=true`, so it spends from the same write budget
as the apply (see [Rate limits and write budgets](#rate-limits-and-write-budgets)).

**The preview is an affordance, not a control.** MCP revision
2026-07-28 has no server-initiated confirmation: a server cannot make a
client show a human the change before calling the apply tool, and a
client is free to call the apply tool without ever calling the preview.
The tool descriptions say which is which so a client can be configured
to show the diff first, and that configuration is where the control is.
Lorica's own guarantees are elsewhere: every tool is narrow, named
unambiguously and impossible to invoke in bulk, and every change lands
in the audit trail under the token that made it.

### What is safe to delegate to this tier, and what is not

The tier is safe to hand a change that is **one named resource, fully
described by its arguments, reversible from the trail, and whose blast
radius is the resource itself**. Adding a backend to a route's pool,
switching the WAF on or to blocking on a route, binding an already-uploaded
certificate, renewing an ACME certificate, deleting a review route
whose environment has gone: each is the work of one sentence in the
dashboard, the preview shows exactly what will move, the audit trail
records what moved and under which token, and undoing it is the same
kind of call.

It is not the tier to hand a change that reaches beyond the resource
it names, or whose arguments are text a model wrote for other people
to execute:

- **Anything the tier does not have a tool for**, which is most of the
  configuration: global settings (a few of which are the admin tier's,
  below), WAF rules, notification channels, DNS providers, users,
  tokens and the cluster. Their absence is a
  decision, not a gap to work around through a route field.
- **A route's `error_page_html`**, `response_rewrite` rules and
  `response_headers`: they are text and code served to or acted on by
  end users, and a model writing them while reading attacker-authored
  text is the exact channel the tiering exists to close. The tier
  accepts them, inside the hostname grant; review them in the
  dashboard, where a human writes them.
- **Redirects and rewrites** (`redirect_to`, `redirect_hostname`,
  `path_rewrite_*`, `strip_path_prefix`, `add_path_prefix`): a wrong one
  sends every request on the route somewhere else, and a preview shows
  the field and not the traffic.
- **`hostname`, `hostname_aliases`, `backend_ids` and `node_selector`
  on a route that carries production traffic**: the change is one
  field, the consequence is every request on it. The grant bounds
  which hostnames a token may claim and which routes and backends it
  may reach, which is what to narrow rather than the model.
- **Deleting a backend** shared by several routes, or a route whose
  environment the token's own pipeline owns: the drain and the cascade
  are the dashboard's own behaviour and are correct, and they are also
  more than the one sentence the model was asked for. A route or a
  backend another pipeline's environment owns is refused outright.
- **A Basic-auth credential, `forward_auth`, `mirror`, `mtls` and
  `proxy_headers`**, which the tier refuses to take at all. The last is
  a static header map sent to the upstream on every request, which is
  where a credential would go; the tier reads its header names, as the
  read tier does, never their values, and sets nothing in it.

The rule underneath: give the tier a token whose grants name the
hostnames and address ranges the model is meant to touch and no
others, run it as a separate process from the one reading logs, and
treat the preview as a way to look before applying rather than as a
gate that applies itself.

## The admin tier, and where it stops

One mutation with its preview, over one path of the automation plane,
behind one scope.

| Tool, and its `_preview` | Does | Scope |
|---|---|---|
| `lorica_settings_update` | change operational global settings, as the dashboard's settings page would, inside the tier's bounds | `settings:write` |

The call is `PUT /automation/v1/settings`, and it runs the dashboard's
own settings write with the token as the actor: the same validators,
the same cross-field checks, the same reload. What makes it a tier and
not the management API behind a different door is the list of keys it
accepts, and how far it lets each one move:

| Setting | Tier bound | Reach | Takes effect |
|---|---|---|---|
| `access_log_retention` | raise-only, 1..=1000000 | fleet | live |
| `waf_event_retention` | raise-only, 1..=1000000 | fleet | live |
| `sla_purge_retention_days` | raise-only, 1..=3650 | fleet | live |
| `cert_warning_days` | 14..=365 | fleet | live |
| `cert_critical_days` | 3..=365 | fleet | live |
| `waf_ban_threshold` | 3..=100 | fleet | live |
| `waf_ban_duration_s` | 60..=86400 | fleet | live |
| `default_health_check_interval_s` | 5..=60 | fleet | live |
| `health_max_concurrent_probes` | 16..=512 | fleet | live |

The list is `SETTINGS_ALLOWLIST` in
`lorica-api/src/automation/write.rs`, where each entry carries the
reason it is in, its bound, its direction, its reach and when it acts.
This table, the tool's description and `inputSchema`, and the
`SettingsPatch` schema in `openapi-automation.yaml` restate it, and a
test pins each of them against the constant, so none of them can
drift from what the node enforces.

**Every key has a safe direction and a bound.** A key is on the list
only when a model reading attacker-authored text can move it in a
direction that harms nothing. The three retentions only go up: a
retention lowered deletes rows that setting it back does not bring
back, and 0, which means unlimited, is refused because the table then
grows until the disk fills. The certificate alert thresholds cannot go
low enough to hide an expiry. The WAF auto-ban cannot be switched off,
cannot ban on one false positive, and cannot ban for more than a day,
because a ban keeps the duration it was issued with and reverting the
setting shortens none already standing. The probe budget cannot go low
enough for a few unreachable backends to starve the checks of every
other. The bound is the tier's; the dashboard's own validator still
runs after it and may be narrower, as the cross-field rule that keeps
`cert_critical_days` below `cert_warning_days` is.

**The node enforces the list and the bounds, not the tool.** The body
is read as a JSON object and a key outside the list is refused with a
403 naming the key, before any value is read and before any validator
runs, whoever sends it: the MCP tool, a direct call with the same
token, or a token carrying every scope there is. A value outside its
key's bound, or a retention below the stored one, is refused with a 422
naming the key and the bound, checked on the document the write is
about to store, under the store lock. The tool's schema lists the same
keys and its description the same bounds, so a model is offered
nothing the node would refuse; the schema is the affordance and the
node is the control.

**On a control plane, it changes the fleet.** Every setting on the
list is fleet policy: on a cluster's control plane a write replicates
to every follower, so the tier changes every node at once and not the
one it is connected to. On a standalone node it changes that node. The
automation listener does not start on a follower, so the tier is never
run there.

**Every setting on the list acts without a restart.** Each is read
where it is used, by the reload or by the loop that uses it on its
next run: the retention loop on its next hourly pass, the certificate
expiry check on its next run, the WAF auto-ban on the next ban, the
health loop on its next cycle.

**Every setting on the list is undone from the dashboard.** Each is an
editable field of the dashboard's settings form, written through the
same function, so an operator who has lost the MCP client, or who does
not like what a model did, puts it back in seconds. A test reads the
dashboard's own form to hold that true. A setting only a full
configuration import or a hand-built request can write is not on the
list for that reason alone.

**What it refuses, by family.** Each of these is out on purpose, and
the story that built the tier names every field:

- **Anything that can lock the operator out of the management plane**:
  the management port and its TLS pair, the connection allow and deny
  lists, the automation listener's own allowlist, the trusted proxies.
  A wrong value there ends the session that would have fixed it.
- **Credentials and trust anchors**: the bot-protection HMAC secret,
  the metrics scrape credential and its switch, the upgrade signing
  key, the whole certificate export family, which writes key material
  to disk.
- **Identity policy**, the password rules, and every user and role
  operation.
- **Reversible and not harmless**: the global connection limit, the
  per-IP connection limits and the mirroring concurrency caps, and the
  flood-defence threshold, which lowered makes every per-IP rate-limited
  route answer 429 and at 0 switches flood defence off. Each is undone
  in seconds and takes production traffic down, or silently stops a
  protection, for as long as it stands. The OTLP and log-sink
  destinations are out for the adjacent reason: a redirect of where
  telemetry goes is not visibly wrong.
- **No safe direction**: the log level. Raised, it floods the disk and
  writes request detail into the logs; lowered, it blinds the
  investigation. The SLA purge switch and its schedule are out for the
  same reason from the other side: off means the table grows without
  bound, and the schedule only moves purges closer together.
- **`audit_log_retention_days`**, although it reads as retention:
  shortening it destroys the trail that tells a model's actions from a
  person's.
- **The settings the dashboard's form cannot write**: `max_active_probes`
  and the load-test ceilings, the flood strict rate and the header
  timeout. A value set here could not be undone there, which fails the
  rule above. They can join the tier the day the dashboard gains a
  field for them, and not before.

**Where it stops.** The paths listed in [What it is not](#what-it-is-not)
are declared for nobody in the scope matrix, so they answer 403 to the
widest token there is: there is no tool for an injected instruction to
name and no check in a handler for a later change to weaken. The
settings document itself is not readable on the plane either: there is
no `GET`.

**The answer is what the scope writes, and nothing more.** The apply
answers the listed settings as they now stand; the preview answers the
same part of the document before and after, with the fields that
differ, in the shape every preview has. Neither answers the rest of the
settings document, so the preview needs no read scope beside
`settings:write`: a token that may write these keys reads back these
keys and no others. That is the one preview on the plane that needs no
read scope, and the property, not the scope, is what exempts it. A
write that changes no stored value writes nothing, reloads nothing and
is answered with the settings as they stand.

**What the audit records.** The request row, as for every call on this
plane, and beside it the dashboard's own `settings.update` row under
the role `automation` and the token's name and `public_id`, whose
target lists each key the write changed with its value before and
after, `waf_ban_threshold:3->5` for instance. The values are safe to
record because every key on the list is a non-secret number. A key
sent with the value it already had is not listed. The dashboard's own
row names the keys its write changed, without their values, since the
dashboard also writes secrets.

**Keep it configured only for the task.** Mint the admin-tier token
with the shortest lifetime the task allows (the node refuses one past
`AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS` whatever is asked), give
it to a client entry of its own that reads no logs, and revoke the
token and remove the entry when the task is done. The
[hardening guide](security/hardening-guide.md#the-mcp-server-tiers-v190-opt-in)
says why.

## Attacker-authored text arrives as data

Log rows and WAF payloads come back inside a delimited block whose tool
description states, in terms, that the delimited content is data and
not instructions. The server never writes prose about what it read: the
only sentence it produces is that notice, `NOTICE` in
`lorica-mcp/src/untrusted.rs`. A tool cannot summarise a log row in its
own words, because no tool builds a result from anything but the bytes
the plane returned. The same bytes travel as `structuredContent` under
a single key, `untrusted`, whose schema description carries the same
notice. A refusal from the plane arrives the same way: the plane's own
words, fenced.

The fence around that block grows its marker until the marker occurs
nowhere in the body, so a WAF payload that spells the terminator cannot
close the block it is quoted in.

None of this makes the text safe. It makes its provenance unambiguous,
which is what the reader, human or model, needs in order to treat it
correctly. A model can still be persuaded by what it reads; the tier is
what bounds what a persuaded model can do.

## Running it

### Which transport

**stdio** when the client and Lorica are on the same box, or when the
client can launch a subprocess and hand it a token. The client starts
`lorica-mcp`, which dials the automation listener over HTTPS and
reaches the read and write paths like any other automation client.

**Streamable HTTP** when the client speaks MCP over HTTP and there is
no subprocess to launch: a hosted client, a client on another machine,
a client you do not control. Nothing is installed beside it. The
endpoint is a path on the automation listener, so it exists exactly
when that listener does and not otherwise. A hosted client connects
from its provider's addresses, which `automation_allowed_cidrs` then
has to name; that is a wider allowlist than a local stdio server needs.

Neither binding opens a socket of its own. `lorica-mcp` is a subprocess
and a library; the automation listener stays the only thing that binds.

### From the packages, and why no unit starts it

The `.deb` and the `.rpm` install `/usr/bin/lorica-mcp` beside
`/usr/bin/lorica`, from the same build, so the server and the node it
drives never drift apart in version. **No systemd unit starts it, and
that is deliberate.** An MCP server is launched by the client that
talks to it, for the length of that client's session, with the token
the operator hands it; it exits when the client closes its standard
input. A long-running service holding an automation token would be an
ambient credential waiting for whoever reaches it, which is exactly
what this design refuses. `dist/lorica.service` says so in its header
so nobody adds one.

### When Lorica runs in a container

**Prefer stdio from the client's own host.** Run the `lorica-mcp` that
matches the node's version (from the packages, or the release binary)
on the machine the MCP client runs on, against the automation listener
published by the container, with `automation_allowed_cidrs` naming that
machine and nothing wider, and a copy of the listener's certificate as
`LORICA_MCP_CA_BUNDLE`. The client then needs no access to Docker, and
`lorica-mcp` runs as the client's user with nothing but its token.

**`docker exec` into the node's container is a fallback, with two
costs.** The production image carries `/usr/bin/lorica-mcp` beside
`lorica`, and only `lorica` runs, so a client can launch the server
inside the running container for each session with `docker exec -i`,
which keeps standard input open for the protocol:

```bash
LORICA_MCP_TOKEN="$(cat read.token)" \
docker exec -i \
  -e LORICA_MCP_ENDPOINT=https://127.0.0.1:9446 \
  -e LORICA_MCP_CA_BUNDLE=/var/lib/lorica/management/cert.pem \
  -e LORICA_MCP_TOKEN \
  lorica lorica-mcp
```

- **The client's account needs the Docker daemon**, which is
  root-equivalent on the host. Most MCP clients also give the model a
  shell or command tool; a model steered by what it reads through the
  read tier then needs no Lorica write scope to change the host. **A
  client with Docker access and a shell tool is outside the tier
  model**, whatever token it holds.
- **The server runs as the proxy's own identity.** The exec inherits
  the image's `lorica` user, which owns the data directory: the
  configuration database, the encryption key and the management key. A
  defect in the process that parses the plane's answers and the
  client's input is then a node compromise rather than a token
  compromise. The packaged binary on a host runs as the client's user,
  with no access to the `0750` data directory.

`-e LORICA_MCP_TOKEN` with no value passes the variable from the
calling environment: `-e LORICA_MCP_TOKEN=<token>` would put the token
on the `docker` command line, in the process table of the host, which
is what the server refuses to accept on its own. The endpoint is the
automation listener as the container sees it; with host networking and
`--automation-listen 127.0.0.1:9446` added to the container's command,
that is loopback, which `automation_allowed_cidrs` must then name, and
every process on the host then passes the listener's source check. The
bundle names the node's own self-signed leaf, readable by the `lorica`
user, and follows its rotation. A token can be minted in the same
container:
`(umask 077; docker exec -i lorica lorica mcp token create --tier read --lifetime-days 30 --password-stdin < <path-to-0600-file> > read.token)`.

### Configuring a client, stdio

The server reads its endpoint and its token from the environment or
from a TOML file, and **never from the command line**: an argument
would put the token in the process table where every user on the box
can read it. Any argument at all refuses the start.

| Variable | Carries |
|---|---|
| `LORICA_MCP_ENDPOINT` | the automation listener's origin, `https://host:port`, no path |
| `LORICA_MCP_TOKEN` | the token, as minted |
| `LORICA_MCP_CONFIG` | path to a TOML file carrying the same keys |
| `LORICA_MCP_CA_BUNDLE` | PEM file of certificate authorities to trust |

The four are the constants of `lorica-mcp/src/config.rs`. The
environment wins over the file, so a client that always writes both
variables does not silently shadow a file an operator maintains. A
blank variable reads as unset rather than as an empty value.

The TOML file takes `endpoint`, `token` and `ca_bundle`, and refuses
any other key. A malformed file is reported by path and not by the
parser's message, because that message quotes the offending line and
the offending line may be the token. A file carrying `token` must be
readable by its owner alone: one granting any permission to its group
or to others is refused at startup with its mode and the fix
(`chmod 600`). A file naming only the endpoint or the bundle is not
checked.

The endpoint must be `https://`, must carry no user information and
must be an origin with no path, query or fragment; each is refused at
startup with a message saying which.

`LORICA_MCP_CA_BUNDLE` matters more than it looks. The automation
listener presents the management plane's certificate: by default a
self-signed leaf the node generates under `<data_dir>/management/`,
valid for `localhost`, the machine's hostname, `127.0.0.1` and `::1`,
and regenerated in place when it nears expiry; or the operator's own
pair named by `management_cert_pem_path` and `management_key_pem_path`.
The bearer token travels over it. Name the bundle that signs it (for
the default leaf, a copy of the leaf itself, readable by the user the
client runs as) rather than reaching for a switch that disables
verification: there is no such switch. The bundle is trusted in
addition to the platform's roots, never instead of them, and the
endpoint's host must be a name the certificate carries.

A client entry looks like this, with the token supplied by whatever
secret mechanism the client offers rather than typed into a file that
gets committed:

```json
{
  "mcpServers": {
    "lorica-read": {
      "command": "/usr/bin/lorica-mcp",
      "env": {
        "LORICA_MCP_ENDPOINT": "https://lorica.internal.example.org:9446",
        "LORICA_MCP_CA_BUNDLE": "/etc/lorica/internal-ca.pem"
      }
    }
  }
}
```

One entry per tier, each with its own token, and preferably in a client
or a profile of its own: see
[the hardening guide](security/hardening-guide.md#the-mcp-server-tiers-v190-opt-in).

stdout carries JSON-RPC messages and nothing else, one per line.
Everything the server writes for a human goes to stderr: the version
and the endpoint, the startup notice naming the token's `public_id` and
the tools it registered, and one line for each call it did not serve.
A client must not read stderr into the conversation.

### Configuring a client, Streamable HTTP

```
POST https://<automation host>:<automation port>/automation/v1/mcp
Authorization: Bearer <the token, as minted>
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
Mcp-Method: <the body's method>
Mcp-Name: <params.name, on a tools/call only>
```

A client entry looks like this, with the token supplied by whatever
secret mechanism the client offers:

```json
{
  "mcpServers": {
    "lorica-read": {
      "type": "http",
      "url": "https://lorica.internal.example.org:9446/automation/v1/mcp",
      "headers": {
        "Authorization": "Bearer <the read-tier token>"
      }
    }
  }
}
```

The client must trust the listener's certificate as a stdio server
would, and must speak revision 2026-07-28 (see
[The protocol revision](#the-protocol-revision-and-keeping-up-with-it)).

The same three things gate it that gate every other path on that
listener, and they gate it first: the source-CIDR allowlist drops a
connection from outside it at TCP accept, before the TLS handshake and
before any header is read; the connection caps and the per-IP limiter
apply; and the bearer token is verified. So the MCP endpoint is not a
way around the automation listener's admission rules, it is behind all
of them.

**What the endpoint requires of the token.** Any live token reaches the
path, and every `tools/call` is authorized against the scopes that
token carries, in the same matrix the read and write paths use. A tool
the token cannot reach is absent from that request's `tools/list` and
unknown to its `tools/call`, and the call a registered tool makes runs
through the plane's own router in process, scope gate included, so the
matrix refuses it a second time if the two ever disagreed. The
specification permits exactly this: a tool set may vary by the
authorization presented on the request, since credentials are
per-request input rather than connection state, while it must not vary
per connection.

That is why the endpoint is not declared behind one scope. It cannot
be: the request names its own tool and each tool has its own. On this
binding the tier is per request too: a POST presenting a config-tier
token is served the config tier, the next POST presenting a read-tier
token the read tier, and a POST presenting a token that spans two is
refused with a `403` as above.

**What the transport requires of the client.** Every POST carries
`MCP-Protocol-Version`, `Mcp-Method` mirrored from the body's `method`,
and on a `tools/call` `Mcp-Name` mirrored from `params.name`. Lorica
validates each against the body rather than trusting it, and a
disagreement is a `400` carrying JSON-RPC code `-32020`. A header value
may arrive Base64-sentinel encoded as `=?base64?...?=`, and is decoded
before it is compared: comparing the raw header would make the whole
check bypassable, which is the reason the check exists.

An unknown protocol version is a `400` naming the versions this server
speaks. An unimplemented method is a **`404`**, which is unusual for a
JSON-RPC server and deliberate: it is how a client tells a server on
this revision from one on the era its method belonged to. A
notification is a `202` with no body.

**What is not there.** Revision 2026-07-28 removed protocol-level
sessions, the standalone `GET` stream and `Last-Event-ID`
resumability. `GET` and `DELETE` on the endpoint answer `405`. An
`Mcp-Session-Id` is ignored and never echoed; a `Last-Event-ID` is
ignored. An answer is one JSON object, not an SSE stream: every method
this server implements answers in one message.

**Every `Origin` is refused with a `403`.** The specification's one
MUST on this transport is against DNS rebinding, and the usual
same-host check is precisely what rebinding defeats, since the
attacker's page and the attacker's DNS name agree with each other.
This plane serves no browser: no cookie layer, no CSRF layer, no
session store, and an MCP client speaking to it directly sends no
`Origin` at all. A present one means a page is driving the endpoint. If
a browser front end ever needs it, an operator-configured allowlist is
the additive change; refusing by default is what keeps that an explicit
decision.

## Paging

Every collection answers `{"items": [...], "page": {...}}`. The window
is the server's: `AUTOMATION_READ_MAX_ROWS` (200) is the ceiling
whatever the caller asks for, `AUTOMATION_READ_DEFAULT_ROWS` (50) the
default, and there is a byte ceiling on the row data as well as a row
ceiling (all three in `lorica-api/src/automation/read.rs`).

**Advance `offset` by the answer's `returned`, never by `limit`.** The
two differ when the byte ceiling ended an answer early, and stepping by
`limit` would skip rows.

**The access log walks back by cursor.** `lorica_logs` answers a
`page.next_cursor`, the id of the last row it returned (`null` on the
last window); sent back as `before_id` with the same filters, it
reads the next window directly, where a deep `offset` has the node read
and discard every row above it on every call. The rows are the same
either way, which a test walks on both log sources. `offset` stays for
a model that wants a few windows and no cursor.

The access log and the WAF events answer only as deep as the node keeps
them. An offset past that depth is refused with a message naming the
depth and the deepest window the requested `limit` can reach, rather
than answered with an empty page. An empty page is the one failure that
reads as "there was nothing", and it is exactly the wrong conclusion
for a model to draw and report to an operator.

## Rate limits and write budgets

Two budgets apply to a model, both per credential, and a third bounds
certificate renewals.

**Tool invocations, in the server.** `RATE_BUDGET` calls per
`RATE_WINDOW` (120 a minute, in `lorica-mcp/src/server.rs`), per token,
in a fixed window, on both bindings and for every tier, a preview and a
read counting as a call like any other. The specification requires a
server to rate limit tool invocations, and nothing outside the server
does: the automation listener's connection caps and per-IP limiter
count connections at accept, and a keep-alive or HTTP/2 client issues
requests without opening one. Going over is a tool execution error
naming the budget, so the model sees it and can wait, rather than a
protocol error it would read as a malfunction. The call never reaches
the plane.

Over stdio the window is the process's, since one process serves one
token. Over Streamable HTTP the tool registry is rebuilt per request
but the window is not: the node holds one limiter for the process,
keyed by the credential (`AutomationPrincipal::budget_key`: a token's
`public_id`, or an ID token's issuer entry and project), and a
credential's window survives every request that spends from it. The limiter holds at most
`MAX_TRACKED_TOKENS` live windows; a window is opened only by a token
that authenticated, and a token that finds no room while that many are
live is refused for that call rather than handed somebody else's
window, since evicting a live one would give a caller holding more
tokens than the ceiling a fresh budget per call.

**Writes, on the plane.** The automation plane budgets writes on its
own and per credential, whether a write arrives over the socket from a
stdio server or from a tool call in process: `RL_SETTINGS_UPDATE`
settings writes a window (30 a minute, the dashboard's figure for its
settings page), and `RL_ROUTES_CUD` of every other write together (100,
its figure for route writes), both in `lorica-api/src/server.rs`. The
dashboard's budgets are layers on its own routes, which the plane does
not mount, and every settings write is a reload and, on a control
plane, a replication round to the fleet, so the plane holds its own.
Going over is a 429 with `Retry-After` and a message naming the figure.
A preview is the apply's own request with `?dry_run`, so it spends from
the same budget; a request the scope gate refuses spends nothing, and a
read spends nothing. "Per credential" means a static token, or one
project under an OIDC issuer entry: an entry whose bound claims match
several projects gives each its own window rather than one they share.
The environment resource's writes, unbudgeted in 1.8.0, spend from the
same `RL_ROUTES_CUD` window since 1.9.0.

**Renewals, per certificate.** Neither budget counts what a call
spends. A certificate renewal spends an ACME order against the CA's
per-name budget, and is bounded per certificate on the plane, as the
config tier section says: one order at a time, none within the minimum
interval of the last issuance, none during a CA cooldown.

## What the audit records, and what it merely repeats

Every call that reaches the node lands an audit row there, in the same
tamper-evident chain as everything else on the automation plane, readable from the
dashboard's audit view or `GET /api/v1/audit` and verified with
`GET /api/v1/audit/verify`. The row distinguishes two kinds of fact,
because they are not the same kind:

- **Established by the node**: the principal, from verifying the
  credential; the method, the path and the names of the query
  parameters, from the request it parsed; the status it answered.
- **Asserted by the caller**: recorded inside an `asserted[...]` clause
  and nowhere else.

Over **stdio**, both the transport and the tool name are assertions.
The MCP server is a separate process and the node sees HTTP requests,
not tool calls; a tool is a concept of the protocol the server speaks,
not of the one it speaks over. It declares them in
`lorica-asserted-transport` and `lorica-asserted-tool`, and the row
reads `GET /automation/v1/logs?limit,search asserted[transport=mcp-stdio,tool=lorica_logs]`,
or for a write `POST /automation/v1/routes asserted[transport=mcp-stdio,tool=lorica_route_create]`
and for its preview `POST /automation/v1/routes?dry_run asserted[...]`.
The startup `whoami` lands a row too, with the transport asserted and
no tool, since no tool has run. A call the server refuses by itself - a
tool the token does not hold, arguments outside the schema, a body
field the tool does not declare, the invocation budget - never reaches
the node and lands no row there; the server writes one line about it on
stderr, in its own words, and that is the only trace.

A mutation that ran lands a second row beside the request row: the
management-side one, `route.create`, `backend.update`,
`certificate.renew`, `settings.update` and so on, under the role
`automation` and the principal `<token name> (<public_id>)`, exactly as
a write over the automation listener does and exactly as the
environment resource's rows are written. A preview lands the request
row alone, since nothing was written for a management row to describe.
A write the node committed lands both rows and signals the reload even
when the client hung up before the answer: the request runs as a task
the connection does not own, so a store commit, its rows and its reload
are one unit a disconnect cannot split. A mutation's rows also keep a
reserved share of the audit queue that the rows of reads and of refused
requests cannot take, so a flood of those does not shed them.

Over **Streamable HTTP**, both are established. The node routed the
request to `/automation/v1/mcp` itself, so the path in the row is the
transport. The node parsed the body, refused it unless `Mcp-Name`
equalled the tool it named, and resolved that name against the
catalogue, so the tool is a fact the node holds and is written outside
any clause, with the declared argument names the call carried and never
their values: `POST /automation/v1/mcp tool=lorica_logs?limit,search`,
or `POST /automation/v1/mcp tool=lorica_route_update?id,route` for a
mutation, whose body's own field names stay out of the row. The
management-side row of a mutation names the address the MCP POST came
from, since the call runs in process with the caller's connection info.
The two `lorica-asserted-*` headers are ignored on this path; a caller
sending them could otherwise put a different tool in the row than the
one the node ran. Only a POST the core never saw - refused by the
bearer gate, by the header rules, or because the `Mcp-Name` and the
body disagreed - records the decoded `Mcp-Name` as
`asserted[tool=...]`, because on that row it is a claim.

The row's outcome on this binding is the core's, not the status's.
Every message the core produced is answered with a `200`, a refused
call included, so the outcome word comes from what the call came to:
`ok`; `forbidden:<scope>` for a tool the token does not hold, the same
word and the same scope the read path behind that tool would have
written; `forbidden:unknown_tool` for a name no tool has;
`forbidden:spans_tiers` for a token spanning two tiers, which unlike
the others in this list is answered `403`, since no server was built to
produce a message; `refused:invalid_params`,
`refused:rate_limited` and `refused:protocol_error` for the refusals
the core makes by itself; and when the tool ran and the plane refused
its call, the word that HTTP status already has on every other row of
this plane: `forbidden` for a hostname outside the token's grant,
`refused` for a validator's 400 or a row an environment owns. The
request metrics count the same word. The whole vocabulary is
`AUTOMATION_AUDIT_REASONS` in `lorica-api/src/automation/audit.rs`,
and [automation.md](automation.md#reading-a-refusal) explains each.

Anyone holding a live token can send any header they like, so every
asserted value is bounded in length and character set before it reaches
a row, and none is ever presented as something the node checked.

An audit trail that cannot tell a claim from a proof is telling a story
that is not true.

**A trace follows the call.** With the `otel` build, every request the
automation listener takes runs in an `automation_request` span, method
and path, and over Streamable HTTP each tool call is an `mcp_tool_call`
span under it naming the tool (`mcp.tool`), the verb and the path the
tool reached, never its query; the handler the tool ran, its
management-side audit event included, runs inside that span. Over
stdio the node sees one HTTP request per call, each its own
`automation_request` span; `lorica-mcp` itself exports no trace.

## Revocation and expiry

A token is revoked on the management API,
`DELETE /api/v1/automation/tokens/{public_id}` (SuperAdmin), or from the
dashboard's Automation tokens page; there is no CLI command for it.
The `public_id` is the one the mint printed on stderr and the one the
stdio server prints in its startup notice. Nothing about a token is
cached, so revocation and expiry bite on the very next request:

- **Over Streamable HTTP**, the next POST presenting it is a `401` from
  the bearer gate, before the core sees it, and the row reads
  `automation.request.unauthenticated:token_revoked` (or
  `token_expired`).
- **Over stdio**, a server already running keeps its tool list, since
  the list was built at startup, but every call it forwards is refused
  by the plane with a 401, which the model reads as an execution error
  carrying the plane's own words. A server started with a revoked or
  expired token fails its startup `whoami` and exits with code 69.

Revoking stops the credential, not what it already did. Every change it
made is in the trail under its `public_id`, and each is undone the way
it was made: a route or backend from the dashboard, a setting from the
dashboard's settings form. After revoking, remove the client entry
that held the token, so nothing launches a server with a dead
credential.

## Troubleshooting

**The stdio server exits before the client sees a tool.** Read its
stderr; the exit code says where to look (the constants are in
`lorica-mcp/src/main.rs`):

| Exit | Means | Look at |
|---|---|---|
| 78 | Configuration refused: an argument on the command line, a missing or malformed endpoint or token, an unreadable or malformed TOML file, an unusable CA bundle, or a token whose scopes span two tiers or name no tier | the message, which names the variable, the file or the scopes |
| 69 | The plane could not be reached, or refused the token at `whoami` | the network path, the allowlist, the certificate, then the token |
| 74 | The session failed: a standard stream broke, a message ran past the size limit (with or without a newline), or the process could not start its async runtime | the client, then the host |

**69, and nothing reaches the node.** A source outside
`automation_allowed_cidrs` is dropped before the TLS handshake, so the
client sees a reset connection and no HTTP status, and the node counts
it in `lorica_automation_source_refused_total`. A stdio server on the
Lorica host connects from loopback, which the allowlist must name.

**69, a certificate error.** The endpoint's host is not a name the
listener's certificate carries, or `LORICA_MCP_CA_BUNDLE` does not name
what signed it. For the default self-signed leaf, use `localhost`,
`127.0.0.1`, `::1` or the machine's hostname, and a copy of the leaf as
the bundle; after the node regenerates the leaf, refresh the copy.

**69, a 401.** The token is unknown, wrong, revoked or expired. The
node's `automation.request.unauthenticated` row carries the reason.
Mint a new one; a 401 is never fixed by retrying.

**The server started with no tools, or fewer than expected.** The
startup notice names what was registered and what was not for want of
a scope. A token minted with `lorica automation token create` may carry
a scope of the tier that no tool uses (`environments:read` alone, for
instance), or lack the reads a config tier tolerates; mint it with
`--tier` instead.

**A tool is "not registered", naming another tier.** One process serves
one tier; that tool belongs to a server started with a token of the
tier it names.

**The config tier lists fewer routes, backends or certificates than the
dashboard.** A token with grants lists only the rows inside them (see
[What it cannot see](#what-it-cannot-see-and-why)). A row it cannot see
is one it could not act on either; widen the grant by minting a new
token if the row is genuinely the model's to touch.

**A mint carrying `settings:write` is refused with a 422 naming a number
of days.** That is the node's lifetime ceiling for the admin tier's
scope. `lorica mcp token create --tier admin` stays under it by default;
with `lorica automation token create` or the dashboard, name a lifetime
within it.

**A call failed with "refused this call with HTTP 403".** The token
held the tool's scope and the plane refused the call: a hostname or a
backend address outside the token's grants, a row another pipeline's
environment owns, or a setting outside the admin allowlist. The fenced
answer is the plane's own message. Do not re-mint for it; narrow the
request or, if the grant is genuinely wrong, mint a token with the
right one.

**A call failed with a 422 or a 400.** A validator refused the value;
the fenced answer says which field and why. A 429 is a write budget or
a renewal bound, with `Retry-After`.

**Streamable HTTP answers 400 with `-32020`.** A mirrored header is
missing or disagrees with the body; the message names which. A `404`
for `initialize` means the client speaks an older revision. A `403`
whose JSON-RPC error is about `Origin` means a browser page, or a
client that sends `Origin`, is driving the endpoint. A `403` naming
scopes is a token spanning two tiers.

**"over that" on every call.** The token spent its invocation budget
for the window; wait, and narrow reads with their filters rather than
paging through everything.

## The protocol revision, and keeping up with it

This crate implements MCP revision **2026-07-28** and no other era.

That revision removed the `initialize` handshake, protocol-level
sessions and the standalone GET stream. Every request carries its own
metadata in `_meta.io.modelcontextprotocol/*`, and the discovery call
that replaced the handshake is `server/discover`. A client that speaks
only an older era will not interoperate: `initialize` answers
method-not-found over stdio and a `404` over Streamable HTTP, rather
than the server guessing which era its caller is in. The `404` is the
revision's own answer and is how a client makes that determination.

**This is a maintenance obligation, not a footnote.** The specification
has moved three times in eighteen months. The revision this crate
implements is stated in one constant, `MCP_PROTOCOL_REVISION` in
`lorica-mcp/src/lib.rs`, and in this section, and a change to it is a
release note. When the specification moves again, the crate does not
follow automatically and nothing in the build will notice: a human has
to read the changelog for that revision and decide.
