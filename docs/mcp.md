# The Lorica management MCP server

`lorica-mcp` lets an operator ask a Model Context Protocol client what
Lorica is seeing: access-log rows, WAF events, SLA windows, cluster
status and the configuration as it stands. It is a read tier. It
cannot change anything, and that is the point rather than a limitation
of the first release.

It speaks two transports over one core: **stdio**, for a client that
launches it as a subprocess, and **Streamable HTTP**, as one path on
the automation listener. The tools, the scopes, the paging, the
untrusted-text marking and the protocol revision are the same on both,
because both run the same code; what differs is what carries the
messages and what each one can honestly put in an audit row.

## Why the tier exists before the tools do

The text an operator most wants to reason about is text Lorica
collected from whoever was attacking them: User-Agent strings, request
paths, WAF matched payloads, TLS SNI values, usernames from failed
Basic-auth attempts. Handing that to a language model is the whole
feature, and it is also the attack. A request path is a string an
attacker chose, and if the session reading it also holds a tool that
deletes a route, that path is an instruction channel into production.

So the authority a session holds is decided by the token it was started
with, not by a mode it can switch. A read-tier server has no mutating
tool to be talked into using, because the tools were never registered.
That is a property of the process, not a rule it follows.

## What this tier can see

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
reaches the read paths like any other automation client.

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
token carries, in the same matrix the read paths use. A tool the token
cannot reach is absent from that request's `tools/list` and unknown to
its `tools/call`. The specification permits exactly this: a tool set
may vary by the authorization presented on the request, since
credentials are per-request input rather than connection state, while
it must not vary per connection.

That is why the endpoint is not declared behind one scope. It cannot
be: the request names its own tool and each tool has its own.

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
read scopes the tier needs and nothing else. Use the automation token
surface documented in [automation.md](automation.md): the management
API, the CLI, or the Automation tokens page. The token is shown once,
by the request that creates it, and the node stores only an HMAC of it.

Give a read-tier server a read-tier token. A token that also carries a
write scope would start a server that reads attacker-authored text
while holding a mutating tool, which is the one session this design
exists to prevent.

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
reads `GET /automation/v1/logs?limit,search asserted[transport=mcp-stdio,tool=lorica_logs]`.
A call the server refuses by itself - a tool the token does not hold,
arguments outside the schema, the invocation budget - never reaches
the node and lands no row there; the server writes one line about it
on stderr, in its own words, and that is the only trace.

Over **Streamable HTTP**, both are established. The node routed the
request to `/automation/v1/mcp` itself, so the path in the row is the
transport. The node parsed the body, refused it unless `Mcp-Name`
equalled the tool it named, and resolved that name against the
catalogue, so the tool is a fact the node holds and is written outside
any clause, with the declared argument names the call carried and never
their values: `POST /automation/v1/mcp tool=lorica_logs?limit,search`.
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
when the tool ran and the plane refused its read, the word that HTTP
status already has on every other row of this plane. The request
metrics count the same word.

Anyone holding a live token can send any header they like, so every
asserted value is bounded in length and character set before it reaches
a row, and none is ever presented as something the node checked.

An audit trail that cannot tell a claim from a proof is telling a story
that is not true.

## Rate limiting

Tool invocations are limited inside the server, per token: 120 calls a
minute, in a fixed window, on both bindings. The specification requires
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
