# Active health checks

Lorica probes each backend that has `health_check_enabled` on, from the
supervisor (or the single process), and keeps one health state per
backend: `healthy`, `degraded` or `down`. Routes and streams that share a
backend share that state. This page says what a probe is, how often it
runs, when a backend changes state, and how to read a failure.

A backend attached to a UDP stream, or given without a port, keeps its
active checks off: there is nothing a TCP probe could reach.

## The kinds of check

A backend's check is `health_check`, an object tagged by `kind`. It is
replaced whole by an update. Every kind refuses a field it does not
have.

| `kind` | What one probe does | Healthy when |
|---|---|---|
| `tcp_connect` | Opens a TCP connection to the backend's address. The default. | The connection completes. |
| `http` | Sends a GET of `path` to the backend (`https://` when `tls_upstream` is on). HTTP routes only. | The answer has a success status. |
| `tcp_template` | Connects, sends the bytes of a template the release ships, reads the answer. Plaintext TCP. | The answer matches one of the template's expected answers. |
| `tcp_send_expect` | Connects, sends bytes the operator chose (or nothing), reads the answer. Plaintext TCP. | The answer matches one of the operator's expected answers. |

```json
{"kind": "tcp_connect"}
{"kind": "http", "path": "/healthz"}
{"kind": "tcp_template", "template": "redis_ping"}
{"kind": "tcp_send_expect",
 "send": {"text": "PING\r\n"},
 "expect": [{"match": "prefix", "bytes": {"text": "+PONG"}}],
 "timeout_ms": 2000}
```

**Why `tcp_connect` is not enough.** The kernel completes a TCP
handshake from the listen backlog, so a connection succeeds against a
process that is frozen, deadlocked or still loading its data. A
database or a cache in that state stays in rotation under a connect
check until clients time out. A template or a send/expect check asks
the backend to answer, which a hung process does not do.

`health_check_path` is the deprecated, older spelling of the same thing:
a path is an `http` check, the empty string a `tcp_connect`. It is still
accepted and still answered beside `health_check`. On a `tcp_template`
or `tcp_send_expect` check it is `null`, and sending it empty leaves
such a check as it is: the field only ever speaks of an HTTP path.

### Templates

A template is referenced by name, not copied into the backend: the
backend stores `"template": "redis_ping"`, and the bytes come from the
release. A template corrected in a later release reaches every backend
that names it. A name the release does not ship is refused (`422`).
`timeout_ms` is optional.

The templates, their bytes and their answers are in the table below,
which is rendered from the catalogue
(`TCP_CHECK_TEMPLATES` in `lorica-automation-policy/src/health_templates.rs`)
and checked against it by a test, so it is the list this release ships.
`redis_ping` accepts `-NOAUTH`: a Redis that requires authentication
answers an unauthenticated `PING` with it, which proves the server is up
and speaking its protocol. Any other answer, `-LOADING` while the
dataset loads included, is a failure.

### A custom send/expect check

- `send` is optional. Absent, the probe sends nothing and reads what the
  backend says first (a banner). Present, it may not be empty.
- `expect` lists the accepted answers, at least one; the probe is
  healthy when **any** of them matches. Each is `{"match": "prefix" |
  "contains", "bytes": <payload>}`: `prefix` when the bytes read start
  with it, `contains` when it occurs anywhere in what the probe read.
  Matching is literal: there is no regular expression and no wildcard.
  List the alternatives instead.
- A payload, in `send` or in an answer, is spelled one of two ways,
  exactly one per payload: `{"text": "PING\r\n"}`, the UTF-8 bytes of
  the string with its JSON escapes, or `{"hex": "0000000804d2162f"}`, an
  even number of hexadecimal digits, stored lowercased. Use hex for any
  byte above `0x7f`, which a JSON string cannot carry as itself.
- `timeout_ms` is optional and bounds the whole probe.

The limits a custom check is held to, and the timeout's bounds and
default, are in the table below. A check that breaks one is refused with
`422`, the message naming the field (`health_check.expect[2].bytes`)
and the limit; an empty `send`, an empty `expect`, an empty answer and a
malformed hex string are refused the same way. Every writer checks them:
the management API, the automation plane, the TOML import and a
follower applying a replicated configuration.

In the dashboard, the backend form's "Health Check Type" offers both
kinds. The text field of a payload takes the escapes `\r`, `\n`, `\t`
and `\\`, since a text input cannot hold a carriage return; any other
byte is sent as hex. The backend list badges a template check
`TCP <template>` and a custom one `TCP send/expect`.

## TCP check templates and the limits of a custom check

<!-- BEGIN health-check-templates: rendered by lorica-api/tests/health_check_template_fixture.rs, never edit by hand -->
| Template | Sends | Expects, any of | What it proves |
|---|---|---|---|
| `redis_ping` | `PING\r\n` (hex `50494e470d0a`) | prefix `+PONG`, prefix `-NOAUTH` | Redis: PING answered by +PONG, or by -NOAUTH from a server that requires authentication (it is up and speaking its protocol) |
| `smtp_banner` | nothing | prefix `220` | SMTP: the server's greeting starts with 220 |
| `postgresql_ssl_request` | `\x00\x00\x00\x08\x04\xd2\x16/` (hex `0000000804d2162f`) | prefix `S`, prefix `N` | PostgreSQL: an SSLRequest answered by S (TLS offered) or N (TLS declined) |

| Limit | Meaning | Value |
|---|---|---|
| `SEND_MAX_BYTES` | most bytes a custom `send` carries, decoded | 1024 |
| `EXPECT_MAX_ALTERNATIVES` | most alternatives a custom `expect` lists | 8 |
| `EXPECT_MAX_BYTES` | most bytes one expected alternative carries, decoded | 256 |
| `PROBE_READ_MAX_BYTES` | most bytes one probe reads, whatever the check says | 4096 |
| `PROBE_TIMEOUT_MS_MIN` | shortest `timeout_ms` a check may set | 100 |
| `PROBE_TIMEOUT_MS_MAX` | longest `timeout_ms` a check may set | 10000 |
| `PROBE_TIMEOUT_MS_DEFAULT` | `timeout_ms` of a check that sets none | 5000 |

<!-- END health-check-templates -->

## How a send/expect probe decides

A `tcp_template` or `tcp_send_expect` probe (`send_expect_probe` in
`lorica/src/health.rs`):

1. Takes one deadline, `timeout_ms` from now, for the whole probe:
   connect, send and read. No step gets a timeout of its own, so no
   probe outlives the check's timeout.
2. Connects, with `TCP_NODELAY` on, and writes `send` when there is one.
   It does not half-close the connection, since some servers close on a
   FIN before answering.
3. Reads into one buffer. When every expected answer is a `prefix`, the
   buffer is the length of the longest one: no byte after it can change
   the outcome. Otherwise it is `PROBE_READ_MAX_BYTES`. A backend that
   floods is bounded by the buffer, one that dribbles by the deadline.
4. After each read, compares the bytes read with the expected answers.
   A match ends the probe healthy. When every answer is a `prefix` and
   the bytes read already differ from all of them, the probe fails at
   once, without waiting for more bytes or the deadline. The end of the
   stream or a full buffer settles the outcome on what was read. The
   matching is incremental: each byte is compared a bounded number of
   times however the backend splits its answer.
5. Closes the connection once decided. It sends no farewell (no SMTP
   `QUIT`).

A healthy probe that took longer than `DEGRADED_THRESHOLD_MS`
(`lorica/src/health.rs`) from the start of the connect makes the backend
`degraded`, as for the other kinds.

A stored custom payload that does not decode, which no validated write
can produce, makes the probe a TCP connect rather than a failure, and a
stored `timeout_ms` outside the bounds is held to them.

## TLS upstreams

Both protocol kinds speak plaintext TCP. A backend's `tls_upstream` is
an HTTP route setting, and a stream configures its upstream TLS on the
stream, so a backend shared by two streams has no single TLS setting a
probe could use. A plaintext exchange can never succeed against a TLS
port, so a `tcp_template` or `tcp_send_expect` check on a backend with
`tls_upstream` on is refused (`422`, naming both fields). A TLS-only
service (`rediss`, SMTPS) is checked by `tcp_connect`.

## How often a backend is probed, and when it changes state

- The health loop wakes every second. It probes a backend once the
  backend's own `health_check_interval_s` has passed since its last
  probe started, never more often than `MIN_PROBE_INTERVAL`
  (`lorica/src/health.rs`). A backend not probed yet is probed at once.
  An edited interval acts from the next probe.
- A backend created without an interval takes
  `default_health_check_interval_s` from Settings at the create. Changing
  that setting changes no stored backend.
- Probes run concurrently, at most `health_max_concurrent_probes` at a
  time. A backend that is draining (`Closing`) is not probed.
- A backend changes state only when `HEALTH_FLIP_THRESHOLD`
  (`lorica/src/health.rs`) consecutive probes report the same new state,
  so one lost probe moves nothing. A hung backend is therefore marked
  `down` after that many of its own intervals, plus the timeout of the
  last probe. A confirmed change reloads the proxy configuration and
  refreshes the stream plane's backend table.
- The loop writes only the health state, or only the lifecycle state, of
  the backend it changes: an edit saved while a cycle was running is
  never overwritten.

## When a check fails

Every failed probe has a reason. The reasons are a closed set,
`ProbeFailure` in `lorica/src/health.rs`, where each one's doc comment
says when it applies. They group as: the connection (refused, or not
completed before the deadline), the send, the read (an error, or no byte
before the deadline), the answer (the backend closed before sending a
byte, or sent bytes none of the expected answers matched, whether by
end of stream, full buffer, early mismatch or deadline), and the two
HTTP outcomes (a non-success status, no answer). Each reason is
published as its snake_case name, `response_timeout` for a backend that
accepted the connection and said nothing, `no_match` for one that
answered something else.

The reason is visible in three places:

- **The metric.** `lorica_backend_health_probe_failures_total`, labelled
  `backend_id` and `reason`, counts every failed probe of every kind,
  whether or not it changed the backend's state. A rising count on a
  backend still `healthy` is a backend failing some probes and not
  enough in a row to be marked down. It is served on `/metrics` by the
  process that runs the health loop, beside `lorica_backend_health`, and
  carries no address and no byte read.
- **The log.** Each probe logs at `debug`. When a backend is confirmed
  `down`, one `info` line, "backend marked down by its health check",
  names the backend id, the address, the kind, the template (`-` for
  none), the reason and how many bytes were read; for `no_match` it adds
  the first bytes read (`LOGGED_READ_BYTES`), printable ASCII as is and
  every other byte, the backslash included, as `\xNN`. It is written
  once per change of state and never per probe, so a backend cannot
  choose how fast Lorica writes its log.
- **The alert.** The `backend_down` notification carries `check` (the
  template's name, or the kind) and `reason`, beside the backend's id,
  address and name. It carries no payload and no byte the backend sent.

## A custom payload is the dashboard's, and it is not a secret store

A custom check makes the node send bytes an operator chose to the
backend's address on every probe. So:

- **It is written from the management plane only.** The dashboard and
  the management API (Operator and above) create and change it. An
  automation token, and the MCP config tier through it, may set
  `tcp_connect`, `http` and `tcp_template`, may keep a stored custom
  check exactly as it is, and may move a backend from one to any of
  those kinds; it may not create one or change one (`403`, preview
  included). The rule is `HEALTH_CHECK_PAYLOAD` in
  `lorica-automation-policy/src/protections.rs`; `docs/automation.md`
  and `docs/mcp.md` say how each surface applies it.
- **`send` is withheld below Operator.** A Viewer session, every
  automation answer and every MCP answer read `send` as
  `{"text": "[redacted]"}`, which still decodes as a payload. `expect`
  and template names are shown everywhere: they are what the backend
  answers, or bytes the release ships. On the management API and the
  automation API, a check sent back exactly as it was read, its `send`
  masked, keeps the stored payload; the mask with anything else changed
  (an `expect`, the timeout) is a `400`, so the mask is never stored.
  The MCP backend tools refuse a `send` or an `expect` key outright, so
  a model keeps a custom check by leaving `health_check` out of its
  patch.

**Never put a credential in a payload** (an `AUTH <password>` before a
`PING`, for one). The mask hides it from a Viewer and from tokens, but
the payload is stored in clear in the configuration database,
replicated to every follower the backend reaches, written by the
configuration export, and shown to every Operator and SuperAdmin. Use a
check that needs no credential: `redis_ping` treats `-NOAUTH` as
healthy for exactly that reason.

## What the backend sees

Every probe of a protocol kind is a connection that exchanges a few
bytes and closes, at each interval, and many servers log that. What
Redis, Postfix and PostgreSQL log for each template has not been
checked. Postfix is commonly reported to log a lost connection after
`CONNECT`, and PostgreSQL may log an incomplete startup packet after an
SSLRequest followed by a close. If the noise matters, raise the
backend's `health_check_interval_s` or filter the probe's source address
in the backend's logging.

## Rolling back, and checks a binary does not know

Rolled back to 1.10.7, a node probes a backend with a template or a
custom check by TCP connect, and the check comes back on re-upgrade
unless a probe path was set meanwhile: `docs/hot-upgrade.md`,
"Rollback".

More generally, a stored check of a kind or a template this binary does
not know (written by a later release, then rolled back) reads as
`tcp_connect`, with a warning, and is left in the database as it is:
the health loop never rewrites it. Editing that backend under the older
binary saves the check that binary shows.
