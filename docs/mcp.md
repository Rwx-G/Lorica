# The Lorica management MCP server

`lorica-mcp` lets an operator ask a Model Context Protocol client what
Lorica is seeing: access-log rows, WAF events, SLA windows, cluster
status and the configuration as it stands. It is a read tier. It
cannot change anything, and that is the point rather than a limitation
of the first release.

This document covers the read tier over the stdio transport. The
Streamable HTTP binding is a later increment and gets its own section
when it lands.

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
scope beside it on the token the server was started with, and a server
started with a token that carries none of them starts with no tools and
says so.

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

**No secret leaves through it.** Certificate private keys,
notification-channel credentials, DNS-provider credentials, Basic-auth
hashes and session cookies are absent from every answer. That is
inherited rather than re-filtered: these are the management plane's own
views, so what they withhold there they withhold here. A test walks
every answer for credential-shaped field names, and a second test pins
the entire set of field names each read answers, so a field added to a
management view tomorrow turns a gate red and forces a decision instead
of arriving here unnoticed.

**No fleet roster.** `/cluster/status` is served;
`/cluster/nodes` is not. The roster discloses each follower's source
address, the hostnames whose routes name it, and the ids of the
certificates whose private key it receives. The management API gates
that at the Operator role on purpose, and an automation credential
carries scopes and no role, so there is no honest way to serve it at
the same level of trust. Whether it returns behind a projection that
strips those three fields is an open question.

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

## Configuring a client

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

Every call this server makes lands an audit row on the node, in the
same tamper-evident chain as everything else on the automation plane.
The row distinguishes two kinds of fact, because they are not the same
kind:

- **Established by the node**: the principal, from verifying the
  credential; the method, the path and the names of the query
  parameters, from the request it parsed; the status it answered.
- **Asserted by the caller**: the transport and the tool name, sent as
  headers and recorded inside an `asserted[...]` clause.

The second pair cannot be established at that layer. The MCP server is
a separate process and the node sees HTTP requests, not tool calls; a
tool is a concept of the protocol the server speaks, not of the one it
speaks over. Anyone holding a live token can send any header they like,
so both values are bounded in length and character set before they
reach a row, and neither is ever presented as something the node
checked.

An audit trail that cannot tell a claim from a proof is telling a story
that is not true.

## Rate limiting

Tool invocations are limited inside the server, because the
specification requires a server to rate limit them and the stdio
binding has no listener budget to inherit. Going over is a tool
execution error, so the model sees it and can wait, rather than a
protocol error it would read as a malfunction.

## The protocol revision, and keeping up with it

This crate implements MCP revision **2026-07-28** and no other era.

That revision removed the `initialize` handshake, protocol-level
sessions and the standalone GET stream. Every request carries its own
metadata in `_meta.io.modelcontextprotocol/*`, and the discovery call
that replaced the handshake is `server/discover`. A client that speaks
only an older era will not interoperate; the server answers
`initialize` with method-not-found rather than guessing which era its
caller is in.

**This is a maintenance obligation, not a footnote.** The specification
has moved three times in eighteen months. The revision this crate
implements is stated in one constant and in this section, and a change
to it is a release note. When the specification moves again, the crate
does not follow automatically and nothing in the build will notice: a
human has to read the changelog for that revision and decide.
