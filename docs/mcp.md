# The Lorica management MCP server

`lorica-mcp` lets an operator talk to Lorica from a Model Context
Protocol client. It has two tiers, and a server is one of them by the
token it was started with. The **read tier** asks what Lorica is
seeing: access-log rows, WAF events, SLA windows, cluster status and the
configuration as it stands, and cannot change anything. The **config
tier** creates and adjusts routes, backends and certificate bindings,
through the same validators the dashboard uses, with a preview of every
change before it is made.

It speaks two transports over one core: **stdio**, for a client that
launches it as a subprocess, and **Streamable HTTP**, as one path on
the automation listener. The tools, the scopes, the paging, the
untrusted-text marking and the protocol revision are the same on both,
because both run the same code; what differs is what carries the
messages and what each one can honestly put in an audit row.

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

## The read tier

Nine tools, one per read the automation plane serves. Each needs the
scope beside it.

Over stdio that is decided once, at startup, from the token the server
was started with: a server whose token carries none of these scopes
starts with no tools and says so on stderr rather than failing every
call. Over Streamable HTTP it is decided per request, from the token
that request presented, because there is no startup to decide it at.
Either way a tool the token cannot reach is not in the list and is
unknown to a call.

| Tool | Reads | Scope |
|---|---|---|
| `lorica_logs` | access-log rows, with the filters the dashboard offers | `logs:read` |
| `lorica_waf_events` | WAF events, narrowed by category | `waf:read` |
| `lorica_waf_stats` | WAF aggregate counts | `waf:read` |
| `lorica_sla_overview` | the SLA summary across routes | `sla:read` |
| `lorica_sla_route` | one route's SLA windows | `sla:read` |
| `lorica_cluster_status` | this node's cluster status | `cluster:read` |
| `lorica_backends` | the backend listing | `backends:read` |
| `lorica_routes` | the route listing | `routes:read` |
| `lorica_certificates` | certificate metadata | `certificates:read` |

## What it cannot see, and why

**No secret of Lorica's own leaves through it.** Certificate private
keys, notification-channel credentials, DNS-provider credentials,
Basic-auth hashes and session cookies are absent from every answer.
That is inherited rather than re-filtered: these are the management
plane's own views, so what they withhold there they withhold here. A
test walks every answer for credential-shaped field names, and a second
test pins the entire set of field names each read answers, so a field
added to a management view tomorrow turns a gate red and forces a
decision instead of arriving here unnoticed.

**What does cross, and is not filtered.** That sentence is about
Lorica's secrets and only those. The rows themselves are text end users
and attackers wrote: request paths including their query strings,
client addresses, User-Agent strings, WAF matched values, SNI names,
usernames from failed Basic-auth attempts. A query string routinely
carries somebody's own credential - a password-reset token, an OAuth
`code`, a signed-URL signature, an API key a client put in the URL -
and this plane does not redact it, because it cannot recognise it: a
filter that stripped what it thought was a token would leave the rest
and read as if it had stripped everything. Those values reach the model
verbatim, and through it whatever hosts the model. Pointing a hosted
model at this tier is a decision that this node's access log, with
everything its users put in a URL, leaves the node; make it knowing
that.

**No fleet roster.** `/cluster/status` is served;
`/cluster/nodes` is not. The roster discloses each follower's source
address, the hostnames whose routes name it, and the ids of the
certificates whose private key it receives. The management API gates
that at the Operator role on purpose, and an automation credential
carries scopes and no role, so there is no honest way to serve it at
the same level of trust. Serving it behind a projection that strips
those three fields was considered and refused: this tier's answers are
the management plane's own views, unfiltered, and that property is what
makes a field arriving here a visible event rather than a silent one.

**No certificate PEM body.** The listing answers metadata. The
single-certificate endpoint that returns the public certificate is
deliberately not on this plane.

## The config tier

Eight mutations, each with a preview, over the automation plane's
write surface. Each pair needs the scope beside it, and a token
carrying that scope registers the pair; a token carrying read scopes as
well registers the read tools they cover beside them, which is how the
tier finds the ids it acts on.

| Tool, and its `_preview` | Does | Scope |
|---|---|---|
| `lorica_route_create` | create a route, as the dashboard's route form would | `routes:write` |
| `lorica_route_update` | patch one route by id; only the fields sent change | `routes:write` |
| `lorica_route_delete` | delete one route by id | `routes:write` |
| `lorica_route_bind_certificate` | bind a stored certificate to one route by id, or unbind with the empty string | `certificates:write` |
| `lorica_backend_create` | create a backend | `backends:write` |
| `lorica_backend_update` | patch one backend by id | `backends:write` |
| `lorica_backend_delete` | delete one backend by id, with the graceful drain | `backends:write` |
| `lorica_certificate_renew` | renew one ACME certificate by id, in place | `certificates:write` |

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
certificate carries, `domain` and each SAN, inside the hostname grant;
and a route or a backend an environment owns is refused unless the
environment's own ownership rule would let this token reach it. Every
backend a route write links anew, at the top level or inside
`path_rules`, `header_rules` or `traffic_splits`, must point inside the
CIDR grant and belong to no other pipeline's environment. `forward_auth`,
`mirror`, `mtls` and `proxy_headers` are refused from an automation
token outright, in either direction: the first is a URL the CIDR grant
cannot weigh, to which the proxy forwards every downstream `Cookie` and
`Authorization` header; the second ships a copy of every request to a
second set of backends; the third is the route's client-authentication
trust anchor, the CA bundle whose client certificates the route
accepts, which a model reading attacker text must not be able to
replace; the fourth is a static header map to the upstream, where a
credential would go. None of the four is offered by the tools. A config-tier token is bounded by the
same two fields an operator reads on it, on what it may claim and on
what it may reach, and a preview is refused exactly where the apply
would be, so a token learns nothing about a row outside its grant by
previewing a change to it.

**The scopes are boundaries too.** A route write that names
`certificate_id`, the empty string included, needs `certificates:write`
beside `routes:write`: the binding tool sits behind the certificate
scope, and a route body that could bind under the route scope alone
made withholding it mean nothing. A preview needs the read scope of
the row it answers (`routes:read` for a route or a binding,
`backends:read` for a backend, `certificates:read` for a renewal),
since a preview answers the full row; a token minted as the section
below says carries them already, and the apply needs nothing more than
its write scope.

**A renewal from a token is budgeted per certificate.** Each renewal
places an ACME order the CA counts against a per-name budget, and
rotates the node's bot-protection HMAC. From a token, a renewal of a
certificate with an order already open answers 409, one issued less
than 48 hours ago answers 429 with a `Retry-After`, and one the
background loop holds in a CA rate-limit cooldown answers 429 as well;
the preview answers what the apply would. The dashboard's own renew is
bounded by none of it. The per-token call limit below is the wrong
bound for this: it counts calls per token, and the scarce resource is
orders per certificate.

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
sweep stayed green. A route's Basic-auth password is deliberately not
offered either: a model would be choosing or relaying a credential, and
it would cross the model's host in the clear. Set it in the dashboard;
the tier reads the username alone, as the read tier does.

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
preview inserts nothing.

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
toggling the WAF or its mode on a route, binding an already-uploaded
certificate, renewing an ACME certificate, deleting a review route
whose environment has gone: each is the work of one sentence in the
dashboard, the preview shows exactly what will move, the audit trail
records what moved and under which token, and undoing it is the same
kind of call.

It is not the tier to hand a change that reaches beyond the resource
it names, or whose arguments are text a model wrote for other people
to execute:

- **Anything the tier does not have a tool for**, which is most of the
  configuration: global settings, WAF rules, notification channels,
  DNS providers, users, tokens and the cluster. Their absence is a
  decision, not a gap to work around through a route field.
- **A route's `error_page_html`**, `response_rewrite` rules and
  `response_headers`: they are text and code served to or acted on by
  end users, and a model writing them while reading attacker-authored
  text is the exact channel the tiering exists to close. Review them in
  the dashboard, where a human writes them.
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
  where a credential would go; the tier reads it, as the read tier
  does, and sets nothing in it.

The rule underneath: give the tier a token whose grants name the
hostnames and address ranges the model is meant to touch and no
others, run it as a separate process from the one reading logs, and
treat the preview as a way to look before applying rather than as a
gate that applies itself.

### Minting a config-tier token

Mint a token carrying the write scopes the work needs, plus the read
scopes the tier uses to find ids and that every preview requires:
`routes:write` with `routes:read`, `backends:write` with
`backends:read`, `certificates:write` with `certificates:read` and
`routes:read`. A token that is to bind certificates through a route
write needs `certificates:write` beside `routes:write`. Set
`allowed_hostnames` and `allowed_backend_cidrs` to exactly what the
model may touch. Start a server with that token for the change, and
keep the read-tier server, with its read-tier token, for reading.

## Attacker-authored text arrives as data

Log rows and WAF payloads come back inside a delimited block whose tool
description states, in terms, that the delimited content is data and
not instructions. The server never writes prose about what it read: the
only sentence it produces is that notice. A tool cannot summarise a log
row in its own words, because no tool builds a result from anything but
the bytes the plane returned.

The fence around that block grows its marker until the marker occurs
nowhere in the body, so a WAF payload that spells the terminator cannot
close the block it is quoted in.

None of this makes the text safe. It makes its provenance unambiguous,
which is what the reader, human or model, needs in order to treat it
correctly.

## Which transport to use

**stdio** when the client and Lorica are on the same box, or when the
client can launch a subprocess and hand it a token. The client starts
`lorica-mcp`, which dials the automation listener over HTTPS and
reaches the read and write paths like any other automation client.

**Streamable HTTP** when the client speaks MCP over HTTP and there is
no subprocess to launch: a hosted client, a client on another machine,
a client you do not control. Nothing is installed on the Lorica host
for it. The endpoint is a path on the automation listener, so it exists
exactly when that listener does and not otherwise: an operator who has
not enabled `--automation-listen` has no MCP surface, which is the
point rather than a side effect.

Neither binding opens a socket of its own. `lorica-mcp` is a subprocess
and a library; the automation listener stays the only thing that binds.

## Configuring a client, stdio

The server reads its endpoint and its token from the environment or
from a TOML file, and **never from the command line**: an argument
would put the token in the process table where every user on the box
can read it. Any argument at all refuses the start.

```
LORICA_MCP_ENDPOINT   https origin of the automation listener
LORICA_MCP_TOKEN      the token, as minted, once
LORICA_MCP_CONFIG     path to a TOML file carrying the same keys
LORICA_MCP_CA_BUNDLE  PEM file of certificate authorities to trust
```

The environment wins over the file, so a client that always writes both
variables does not silently shadow a file an operator maintains. A
blank variable reads as unset rather than as an empty value.

The TOML file takes `endpoint`, `token` and `ca_bundle`. A malformed
file is reported by path and not by the parser's message, because that
message quotes the offending line and the offending line may be the
token.

`LORICA_MCP_CA_BUNDLE` matters more than it looks. The automation
listener's default certificate is self-signed, and the bearer token
travels over it. Name the bundle that signs it rather than reaching for
a switch that disables verification: there is no such switch.

A client entry looks like this, with the token supplied by whatever
secret mechanism the client offers rather than typed into a file that
gets committed:

```json
{
  "mcpServers": {
    "lorica": {
      "command": "/usr/bin/lorica-mcp",
      "env": {
        "LORICA_MCP_ENDPOINT": "https://lorica.internal.example.org:9446",
        "LORICA_MCP_CA_BUNDLE": "/etc/lorica/internal-ca.pem"
      }
    }
  }
}
```

## Configuring a client, Streamable HTTP

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
    "lorica": {
      "type": "http",
      "url": "https://lorica.internal.example.org:9446/automation/v1/mcp",
      "headers": {
        "Authorization": "Bearer <the token>"
      }
    }
  }
}
```

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
token the read tier.

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
this tier implements answers in one message.

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

## Minting the token

The tier is the token's scope set, so mint a token carrying exactly the
scopes the tier needs and nothing else: the read scopes for a read-tier
server, the write scopes with the reads they need for a config-tier
one. Use the automation token surface documented in
[automation.md](automation.md): the management API, the CLI, or the
Automation tokens page. The token is shown once, by the request that
creates it, and the node stores only an HMAC of it.

Give a read-tier server a read-tier token. A token that also carries a
write scope would start a server that reads attacker-authored text
while holding a mutating tool, which is the one session this design
exists to prevent. Nothing in this release refuses such a token: a
token carrying both kinds of scope is served both kinds of tool, and
keeping the two apart is the operator's, by minting two tokens and
running two processes. Story 11.4 is where the server itself refuses
a token that spans two tiers.

## Paging

Every collection answers `{"items": [...], "page": {...}}`. The window
is the server's: 200 rows is the ceiling whatever the caller asks for,
50 is the default, and there is a byte ceiling on the row data as well
as a row ceiling.

**Advance `offset` by the answer's `returned`, never by `limit`.** The
two differ when the byte ceiling ended an answer early, and stepping by
`limit` would skip rows.

Two sources answer only so deep: the access log to ten thousand rows,
WAF events to five hundred. An offset past that depth is refused with a
message naming the deepest window the requested `limit` can reach,
rather than answered with an empty page. An empty page is the one
failure that reads as "there was nothing", and it is exactly the wrong
conclusion for a model to draw and report to an operator.

## What the audit records, and what it merely repeats

Every call lands an audit row on the node, in the same tamper-evident
chain as everything else on the automation plane. The row distinguishes
two kinds of fact, because they are not the same kind:

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
A call the server refuses by itself - a tool the token does not hold,
arguments outside the schema, a body field the tool does not declare,
the invocation budget - never reaches the node and lands no row there;
the server writes one line about it on stderr, in its own words, and
that is the only trace.

A mutation that ran lands a second row beside the request row: the
management-side one, `route.create`, `backend.update`,
`certificate.renew` and so on, under the role `automation` and the
principal `<token name> (<public_id>)`, exactly as a write over the
automation listener does and exactly as the environment resource's rows
are written. A preview lands the request row alone, since nothing was
written for a management row to describe.

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
`refused:invalid_params`, `refused:rate_limited` and
`refused:protocol_error` for the refusals the core makes by itself; and
when the tool ran and the plane refused its call, the word that HTTP
status already has on every other row of this plane: `forbidden` for a
hostname outside the token's grant, `refused` for a validator's 400 or
a row an environment owns. The request metrics count the same word.

Anyone holding a live token can send any header they like, so every
asserted value is bounded in length and character set before it reaches
a row, and none is ever presented as something the node checked.

An audit trail that cannot tell a claim from a proof is telling a story
that is not true.

## Rate limiting

Tool invocations are limited inside the server, per token: 120 calls a
minute, in a fixed window, on both bindings and for both tiers, a
preview counting as a call like any other. The specification requires
a server to rate limit them, and nothing outside the server does: the
automation listener's connection caps and per-IP limiter count
connections at accept, and a keep-alive or HTTP/2 client issues
requests without opening one. Going over is a tool execution error, so
the model sees it and can wait, rather than a protocol error it would
read as a malfunction.

Over stdio the window is the process's, since one process serves one
token. Over Streamable HTTP the tool registry is rebuilt per request
but the window is not: the node holds one limiter for the process,
keyed by the token's `public_id`, and a token's window survives every
request that spends from it. The limiter holds at most 1024 live
windows; a window is opened only by a token that authenticated, and a
token that finds no room while that many are live is refused for that
call rather than handed somebody else's window, since evicting a live
one would give a caller holding more tokens than the ceiling a fresh
budget per call.

This budget counts calls and not what a call spends. A certificate
renewal spends an ACME order against the CA's per-name budget, and is
bounded per certificate on the plane, as the config tier section says:
one order at a time, none within 48 hours of the last issuance, none
during a CA cooldown.

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
implements is stated in one constant and in this section, and a change
to it is a release note. When the specification moves again, the crate
does not follow automatically and nothing in the build will notice: a
human has to read the changelog for that revision and decide.
