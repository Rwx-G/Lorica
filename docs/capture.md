# Lorica Traffic Capture

**Author:** Romain G.
**Since:** v1.8.0

## Overview

A capture rule keeps the full request and response for a subset of the
traffic on one route, and writes each kept exchange out as one JSON
record that joins the access-log row on `request_id`. It exists for the
incident the access log cannot explain: a backend returning 502 for one
client in twenty, where the status, the latency and the request id are
known and what was actually sent is gone.

A capture is the most sensitive thing this proxy emits. It is a verbatim
copy of a request and its response, taken after TLS has been terminated,
written to wherever an operator pointed it. Every limit in this document
exists for that reason, and two design decisions follow from it:

- **The record carries less than the operator can see.** Credentials in
  headers and in named query parameters are redacted, and no rule can
  turn that off. The operator who armed the rule could already read the
  traffic; the record travels further than they do.
- **A capture rule cannot hurt the traffic it records.** Every cap is
  enforced before a byte is kept, a sink that stops accepting records
  loses records and never delays a request, and a rule that spends its
  budget stops on its own.

The management surface is `GET|POST /api/v1/capture/rules`,
`GET|PUT|DELETE /api/v1/capture/rules/{id}`,
`POST /api/v1/capture/rules/{id}/disable`, `GET /api/v1/capture/recent`
and `GET /api/v1/capture/recent/{request_id}`, and the **Capture** page
of the dashboard. Creating, editing, reading back and deleting a rule is
SuperAdmin; listing rules, stopping one and reading recent records is
Operator. The asymmetry is deliberate: arming a recorder decides that
production bodies get written to disk, and stopping one only decides
that they stop, which an operator paged at 3am has to be able to do
without waking anyone.

## The two-phase model

Whether an exchange is worth keeping depends on the response, and the
response arrives long after the point where the request body has to be
either buffered or let go. So a rule has two predicate blocks, evaluated
at two different moments:

- **`match`, the request side**, is evaluated once when the request head
  arrives (`request_filter`). It decides whether this request is a
  *candidate*: whether the proxy pays the cost of copying its body as it
  streams through. `route_id` is mandatory and is part of this phase; the
  optional narrowers are `source_cidrs` (evaluated against the same
  client address the access log reports, `X-Forwarded-For` aware),
  `methods` (uppercase, compared verbatim), `path_prefix`, `path_regex`
  and `headers` (name plus exact, prefix or regex value, the same
  semantics a route's header rules use). All populated fields must hold;
  an empty `match` considers every request on the route. A rule past its
  `expires_at` is never a candidate.
- **`emit`, the response side**, is evaluated once the response verdict
  exists (`logging`). It decides whether a buffered candidate becomes a
  record or is discarded: `status` (exact codes, or the classes
  `client_error` for 4xx, `server_error` for 5xx, `client_aborted` for
  the 499 client-hung-up marker), `min_latency_ms`, and `upstream_error`
  (the backend produced no response at all: connect, read or TLS
  failure). Conditions inside `emit` are ORed. An empty `emit` is refused
  unless the rule says `"always": true` explicitly, and `always` cannot be
  combined with a condition: a forgotten condition must not become a
  silent full dump, and an `always` next to a `status` list would hide
  what the operator meant.

`client_error` excludes 499 on purpose. 499 is not a status a backend
returned, it is the proxy's marker for a client that hung up
mid-response, and a rule asking for "client errors" would otherwise
collect every aborted request too. `client_aborted` is the only way to
ask for it.

Everything expensive is gated on phase one, which is why `route_id` is
mandatory and why `source_cidrs` exists: a rule that only matches the
internal network's addresses on one route buffers nothing for anyone
else.

Between the two phases the bodies are copied, never altered. A request
being captured reaches the upstream byte for byte; a body that exceeds
its cap keeps the prefix and lets the rest through untouched. Response
bodies whose content type is stream-by-design (SSE, multipart push,
gRPC) are never buffered, because such a stream has no end. The buffers
are released at `logging` however that hook returns; there is no path
that holds a body past the request.

## The caps

Every dial is capped, because a capture rule is an operator-authored
memory allocation on a node that also terminates production TLS. A value
of zero, or over the cap, is refused at write time with the field named.

| Dial | Default | Hard limit | Why |
| --- | --- | --- | --- |
| `capture.request_body_max_bytes` | 64 KiB | 4 MiB | Held in memory per in-flight candidate until the response verdict. |
| `capture.response_body_max_bytes` | 64 KiB | 4 MiB | Same, for the upstream body. |
| `limits.max_captures` | 100 | 10 000 | Past that a rule is a standing recorder, not a diagnostic. |
| `limits.rate_per_minute` | 10 | 10 000 | A busy route degrades into a sample instead of a firehose. Zero is refused. |
| `limits.ttl_seconds` | 1 hour | 7 days | Captured bodies carry whatever the client sent; retention is a policy limit. |
| `output.max_dir_bytes` | unset | 10 GiB | The only thing that makes the directory writer prune. |
| `match.path_regex`, regex header values | | 4 KiB of source, 512 KiB compiled | The same budgets a custom WAF pattern gets. |
| `redact.headers`, `redact.query` | | 64 names of 128 bytes each | Both lists are walked per captured header and parameter. |
| `name` | | 200 bytes | Rendered verbatim in a dashboard column and an audit line. |
| `match.path_prefix` | | 2048 bytes | Longer than any request target the proxy accepts. |

Two ceilings are node-wide rather than per rule:

- **In-flight bytes: 64 MiB per process.** One counter covers every rule
  and every candidate on the process. A request that cannot fit under it
  is not buffered; if its `emit` block then matches, the record is still
  written with `body_skipped: "budget"` and
  `lorica_captures_total{outcome="dropped_budget"}` increments. Without
  this ceiling `rule count x request rate x body cap` is unbounded.
- **Tracked rules: 1024 per process.** The per-rule budget map is keyed
  by rule id and nothing else caps how many rows `capture_rules` may
  hold. A rule past this cap records nothing and reports no metric.

**Under `--workers` the in-flight ceiling is PER WORKER.** Each worker
runs its own budget against its own copy of the 64 MiB, so a node
running eight workers can hold up to 512 MiB of capture buffers, not
64. Size the box against workers times ceiling.

## Budgets: total, rate and clock

Three things stop a rule, and every rule has all three.

- **The total.** `max_captures` is spent one admission at a time, under
  one lock, so two requests racing for the last capture cannot both
  take it. The moment the last one is taken the rule is queued for a
  self-disable: within about five seconds its stored `enabled` flag is
  cleared and an audit row `capture.rule.auto_disabled` names the rule,
  its route, the budget that was spent and the value it stood at. The
  rule is **never deleted**. An operator who comes back to a rule that
  stopped on its own sees it, sees why, and can re-arm it.
- **The rate.** `rate_per_minute` is a sliding minute counted in
  per-second buckets. A refused exchange is
  `lorica_captures_total{outcome="dropped_rate"}`; nothing is disabled,
  the rule recovers as the window slides. A zero rate is refused rather
  than read as unlimited, because a rule that can never emit is what
  `enabled = false` is for, and accepting zero would produce a rule that
  looks armed and is not.
- **The clock.** `ttl_seconds` is turned into an absolute UTC
  `expires_at` at creation, anchored on `created_at`. An edit recomputes
  it from the same anchor, so no sequence of edits carries a rule past
  seven days from when it was created. A rule past `expires_at` is never a
  candidate: it records nothing, and the dashboard shows it as expired.
  The clock does not clear the stored `enabled` flag; the total does.

**Counters and the rate window are per process.** Under `--workers` that
means per worker: a node running four workers admits up to four times
`rate_per_minute` and stops at up to four times `max_captures`, and the
`captures_emitted` / `captures_dropped` columns the dashboard reads are
the sum of what each worker flushed. This is the documented semantics,
not an oversight: making either bound fleet-consistent would put a
shared counter, a cross-process lock or an RPC, on the path that decides
whether to record one exchange, on a node whose main job is terminating
TLS. **`expires_at` is the only fleet-consistent bound.** It is the one
instant every node in a fleet agrees on without talking to any other,
which is why it is stored as an absolute time and not as a duration.

The per-rule counters the API returns are flushed to the store every few
seconds, so the dashboard lags the enforcement by that much. The
enforcement itself is immediate.

## The record

One JSON document per capture, with a fixed field order and no map
anywhere in it, so two records of the same exchange are byte-identical.

```json
{
  "kind": "capture",
  "rule_id": "6f1c...-...",
  "rule_name": "checkout 5xx",
  "route_id": "2b9a...-...",
  "request_id": "0123456789abcdef0123456789abcdef",
  "timestamp": "2026-01-01T00:00:00.123456789+00:00",
  "client_ip": "10.0.0.7",
  "is_xff": true,
  "backend": "10.0.0.2:8080",
  "latency_ms": 1234,
  "error": "upstream timed out",
  "request": {
    "method": "POST",
    "uri": "/checkout?token=<redacted:6 bytes>&cart=42",
    "version": "HTTP/1.1",
    "headers": [
      ["Host", "shop.example.com"],
      ["Content-Type", "application/json"],
      ["Authorization", "<redacted:43 bytes>"],
      ["X-Trace", "first"],
      ["X-Trace", "second"]
    ],
    "body": "{\"cart\":42}",
    "body_encoding": "utf8",
    "body_bytes_total": 11,
    "truncated": false,
    "body_skipped": null
  },
  "response": {
    "status": 503,
    "headers": [["Content-Type", "text/html"], ["Set-Cookie", "<redacted:19 bytes>"]],
    "body": "PGh0bWw+...",
    "body_encoding": "base64",
    "body_bytes_total": 70213,
    "truncated": true,
    "body_skipped": null
  }
}
```

Field by field:

- `kind` is always `capture`, so a consumer reading a mixed stream can
  tell a capture from an access-log row.
- `rule_id`, `rule_name`, `route_id`: the rule that admitted the
  exchange, its name at the time, and the route it records. Two rules
  admitting the same exchange produce two records that differ here and
  in whatever their caps and redaction lists make of the shared buffers.
- `request_id`, `timestamp`, `client_ip`, `is_xff`, `backend`,
  `latency_ms`, `error`: copied from the access-log row for the same
  request, built first and passed in rather than re-derived. That is
  what makes a capture joinable on `request_id` and guaranteed to agree
  with the row on everything else. `backend` is `-` when no upstream was
  selected; `error` is the row's error text or `null`.
- `request.method`, `request.uri`, `request.version`: as received.
  `uri` is the request target (path and query) with the query parameters
  the rule names masked.
- **`headers` is a list of `[name, value]` pairs, never a map.** A map
  loses duplicates, and duplicated headers are exactly the thing worth
  seeing when a proxy and a backend disagree about a request. Every
  occurrence is kept, in the order sent, so the record stays honest
  about order too. Names keep the case they were sent with when the
  connection preserved it (HTTP/1.1), and are lowercase otherwise
  (HTTP/2). The response headers are the ones written downstream, which
  is also what the access-log row reports.
- `body` is the kept bytes in `body_encoding`, `null` when
  `body_skipped` says why; an empty string is a body that was genuinely
  empty.
- **`body_encoding`** is `utf8` only when BOTH hold: the content type is
  textual (`text/*`, `application/json`, `application/xml`,
  `application/x-www-form-urlencoded`, and any `+json` or `+xml`
  structured-syntax suffix) and the kept bytes are valid UTF-8. Anything
  else is `base64`, standard alphabet with padding: a binary type, a
  textual type carrying bytes that are not UTF-8, a body with no content
  type, and a truncated text body whose cut fell inside a multi-byte
  character. The record never repairs bytes to make them readable,
  because a repaired body is not the body that was sent. A `base64` body
  decodes byte for byte to the original.
- **`body_skipped`** is `null` when a body is present, and otherwise one
  of: `streaming` (the response content type is stream-by-design and was
  never buffered), `budget` (the node-wide in-flight ceiling was reached
  when this request arrived), `disabled` (the rule's `capture.request_body`
  or `capture.response_body` is off).
- **`truncated`** is true when `body` is a prefix of what was sent: the
  rule's cap was reached. **`body_bytes_total`** is what the body carried
  on the wire, so it exceeds the kept length when `truncated`, and it is
  still counted when the body was skipped.

## Redaction

Two things are redacted, and in both the NAME stays while the value is
replaced by the marker `<redacted:N bytes>`, N being the byte length of
what was removed. A reader can see the header or parameter was present
and how large its value was, without seeing the value; an empty
`Authorization` and a 2 KiB one are told apart.

- **Headers.** `Authorization`, `Proxy-Authorization`, `Cookie` and
  `Set-Cookie` are redacted in every record, whatever the rule says. This
  set is a compile-time constant that no setting, no automation scope and
  no dashboard field reaches. A rule's `redact.headers` list is ORed in:
  it can add names (compared case-insensitively, as HTTP compares header
  names) and no value it can hold subtracts one. A rule that names
  `Authorization` changes nothing; a rule that names `X-Api-Key` redacts
  it and still redacts `Authorization`.
- **Query parameters.** `redact.query` names parameters whose values are
  masked in `request.uri`. The query is walked as raw text and never
  decoded: a percent-encoded value is masked as the bytes it was sent as,
  and everything that is not a masked value is copied byte for byte.
  Decoding and re-encoding would alter the record for parameters the
  rule never named, and a record that differs from the wire is worse
  than one that is harder to read. Consequences, all deliberate: a
  parameter that repeats is masked at every occurrence, each with its
  own byte count; `name=` (present, empty) becomes
  `name=<redacted:0 bytes>`; `name` alone with no `=` is left as it is,
  because adding an `=` would put a byte on the record that was not on
  the wire; and a name sent percent-encoded does not match its decoded
  spelling. Names are compared exactly, unlike header names: HTTP makes
  no promise that query parameters are case-insensitive, and a masker
  that folded case would mask a parameter the application treats as a
  different one.

**Bodies are NOT redacted.** The body is the thing the operator asked to
see, and a body scrubber that guessed at secrets would make the record
lie in the one place it must not. A body-level redaction pass an operator
can trust is a different feature; pretending to have one would be worse
than not having it. The controls are the rule's body caps
(`capture.request_body: false` keeps no request body at all), the
retention TTL, the always-redacted headers, and who can read the sink.
Treat a capture directory and a SIEM index that receives captures as
holding credentials.

## Two things to know before the first incident

**The response body is the UPSTREAM's, before any rewrite this proxy
applied.** The response buffer is filled ahead of the response-rewrite
path on purpose: the feature's own motivation is a backend returning
something wrong, and for that the raw upstream bytes are the evidence.
On a route that rewrites bodies, a capture therefore disagrees with what
the client received, and an operator comparing the two would be right to
be confused. The status and the headers in the record are the ones
written downstream; only the body predates the rewrite. This is a
semantic choice, not an implementation detail.

**A capture rule cannot be disabled on a follower without break-glass.**
Capture rules replicate from the control plane like routes do, and a
follower is read-only: `POST .../disable` there answers `409 Conflict`
naming the control plane. Disable the rule on the control plane and the
change reaches every follower on the next replication round. If the
control plane is unreachable and a capture is filling a follower's disk
now, open a break-glass window on that follower and disable it locally,
knowing that a local change is overwritten on the next round once the
window closes: the follower pulls the current generation and applies it
wholesale, and the rule comes back armed unless the control plane
disabled it too. See `docs/cluster.md`, "Follower read-only, and
break-glass".

## Sinks

Every record reaches the same outputs, in this order, and nothing on the
path blocks, awaits or panics: the request was answered before the
record was built, and the one way a sink could still hurt it is by
stalling the hook that builds it.

1. **The structured log, always on.** One `tracing` event at target
   `lorica::capture` whose `record` field is the JSON document. It lands
   wherever the process log lands (stdout, or the rolling file) in
   whatever format `--log-format` selected. A log filter on the target
   routes or silences captures without touching the access log.
2. **The recent-captures ring.** The last 50 records this process
   emitted, in memory, read by `GET /api/v1/capture/recent` and the
   dashboard's "Recent captures" panel. The listing cuts each body at
   4 KiB of its JSON string form and marks the cut (`body_elided: true`,
   `body_elided_total`); `GET /api/v1/capture/recent/{request_id}`
   downloads the whole record, byte for byte what the other sinks
   received, under the same file name the directory sink uses, until
   the ring has evicted it. The ring is per process (see
   Troubleshooting for what that means under `--workers`).
3. **Syslog and OTLP logs.** The capture kind rides the same export lanes
   as access-log rows, WAF events and audit rows, each with its own
   switch: `syslog_capture_enabled` and `otlp_logs_capture_enabled`, both
   `true` by default, both on the Settings page under Log export, both
   hot-reloaded. On the wire the record is flattened at the top level of
   the message body with `v` (body version) and `kind: "capture"` stamped
   on it; the syslog message carries `kind="capture"` in its structured
   data and its `MSGID`. Each lane is a bounded queue: a collector that
   stops draining costs records, not latency.
4. **A directory, per rule and optional.** `output.dir` writes one file
   per capture, `<timestamp>-<request_id>.json`, where the timestamp is
   the record's in basic ISO 8601 with nanoseconds
   (`20260101T000000.123456789Z`), fixed width so names sort
   chronologically and free of `:` and `-` so a name splits on its first
   `-`. Mode `0640`, owned by the running user (`lorica` under the
   shipped unit). The directory must already exist and be writable; the
   writer never creates it, because a directory that appears at the
   first capture is a directory nobody set the permissions on. The
   document is written to a hidden temporary name in the same directory
   with `create_new`, flushed to disk, then published under its final
   name with a hard link, which fails when the name is taken. That gives
   the final name the **`create_new` guarantee** (an existing file is
   never replaced) and an atomic publish: a reader sees the complete
   document or nothing, never a prefix of one. When `max_dir_bytes` is
   set, pruning runs after every successful write, **oldest first** by
   name, until the directory is under budget or 64 files went in one
   pass; it counts and removes only the names this writer produces, and
   the file just written is never a candidate, so a budget smaller than
   one record keeps the newest and nothing else. The write is queued to a
   dedicated thread through a bounded channel (64 jobs, 64 MiB of
   documents); a full queue refuses the record.

Captures never enter the SQLite access-log database. A 64 KiB body per
row would break the bounded writer's memory model.

**A sink failure drops the record, counts it, and never touches the
request.** A full directory, a read-only mount, a missing directory, a
name already taken, a full lane, a lane whose consumer died, a full
write queue: each ends the same way, the copy is dropped and
`lorica_captures_total{rule_id, outcome="dropped_sink"}` increments once
per lost copy. The counter is per delivery, not per record: with syslog
and a directory both failing, one record counts two. Requests keep
flowing with zero 5xx. The first failure on a directory is logged at
WARN, the following ones at DEBUG until the directory writes again, so a
read-only mount at the rate cap is one operator problem and not ten
thousand log lines.

### A SIEM example

Every capture joins its access-log row on `request_id`. With both kinds
shipped to the same collector, the two events for one exchange look like
this (both bodies abridged):

```json
{"v":1,"kind":"access","timestamp":"2026-01-01T00:00:00.123456789+00:00","method":"POST","path":"/checkout","host":"shop.example.com","status":503,"latency_ms":1234,"backend":"10.0.0.2:8080","error":"upstream timed out","client_ip":"10.0.0.7","is_xff":true,"request_id":"0123456789abcdef0123456789abcdef"}
{"v":1,"kind":"capture","rule_id":"6f1c...","rule_name":"checkout 5xx","request_id":"0123456789abcdef0123456789abcdef","timestamp":"2026-01-01T00:00:00.123456789+00:00","request":{"method":"POST","uri":"/checkout","headers":[["Authorization","<redacted:43 bytes>"]],"body":"{\"cart\":42}","body_encoding":"utf8"},"response":{"status":503,"body":"...","body_encoding":"base64"}}
```

The access row is the index: it is small, it is one per request, and it
is what alerting already reads. The capture is the evidence for the rows
that matter. A query that starts from the rows (`kind=access AND
status>=500 AND host="shop.example.com"`) and joins `kind=capture` on
`request_id` yields, for each failing request, the exact bytes the
backend was sent and the exact bytes it returned, with the credential
headers replaced by their byte counts. `timestamp`, `client_ip`,
`backend`, `latency_ms` and `error` are the same values in both events
by construction, so a join that also checks them is checking that the
node did its job, not that the two events belong together.

## Metrics

Three families, all in the node's `/metrics`.

- **`lorica_capture_rules_active`** (gauge): capture rules loaded and
  enabled on this node, set when a configuration snapshot is built. It
  answers "is anything recording right now".
- **`lorica_captures_total{rule_id, outcome}`** (counter): one increment
  per decision. `rule_id` is the rule's id. `outcome` is `emitted` (the
  budgets admitted the exchange and a record was built), `dropped_rate`
  (the sliding minute was full), `dropped_budget` (the total is spent,
  the node-wide in-flight ceiling refused the candidate, or the
  tracked-rule cap refused the rule), or `dropped_sink` (one copy of a
  built record was lost by one output). `dropped_sink` is counted IN
  ADDITION to the `emitted` decision, so `emitted - dropped_sink` is not
  "records delivered" when more than one sink is on; the counter answers
  "how many deliveries failed".
- **`lorica_capture_inflight_bytes`** (gauge): bytes currently held by
  capture buffers on this process, against the 64 MiB ceiling.

The `rule_id` label is operator-controlled but bounded: the proxy only
ever reports ids for rules it tracks a budget for, and that map is capped
at 1024 per process. No label derived from a request (route, path,
status, client) is ever added to this family; those are unbounded in a
way the rule id is not, and this is the one metric family fed from the
per-request path.

**Under `--workers`** every decision is made in a worker and `/metrics`
is served by the supervisor, so the three travel on the workers' periodic
metrics report and are aggregated there. `lorica_captures_total` is
summed across workers, like every counter. The two gauges aggregate
differently, and the difference is the thing to remember:

- `lorica_capture_rules_active` is the **MAXIMUM** across workers. Every
  worker compiles the same configuration snapshot, so this is the same
  value in every worker and a sum would report the operator's rule count
  multiplied by the worker count: eight workers with three rules each
  are one node with three rules, not twenty-four. The maximum equals the
  common value and does not read 0 because a freshly respawned worker has
  no snapshot yet.
- `lorica_capture_inflight_bytes` is the **SUM** across workers. Each
  worker reserves against its own copy of the ceiling, so the node
  figure is what they hold together, and it can legitimately exceed
  64 MiB.

## Troubleshooting

**Why did my rule expire?** Because its clock ran out. `expires_at` is
`created_at` plus `limits.ttl_seconds`, one hour by default and seven
days at most, computed once at creation. Editing the rule recomputes
`expires_at` from the same `created_at`, so an edit cannot push it later
than seven days from creation. A rule past `expires_at` records nothing
on any node, whatever its `enabled` flag says, and the dashboard shows
it as expired with its counters intact. To record again, create a new
rule: a fresh `created_at` is a fresh clock. If the rule seems to have
expired early, compare the node's clock with the control plane's; the
bound is absolute UTC and a node that is minutes behind stops minutes
late, one that is minutes ahead stops minutes early.

**Why is my rule disabled?** Look at the audit log for the rule id. A row
`capture.rule.auto_disabled` says the rule spent its `max_captures` (the
payload names the budget and the value it stood at); the flag was cleared
within about five seconds of the last capture. A row `capture.disable`
says an operator stopped it, with their identity. If the rule is
disabled and neither row exists on this node, the node is a follower and
the flag arrived by replication: the audit row is on the control plane.
Under `--workers`, each worker spends its own copy of `max_captures`, so
the stored `captures_emitted` at the moment of the disable can be as high
as workers times `max_captures`; that is the documented semantics, not a
miscount. For the same reason you may see MORE THAN ONE
`capture.rule.auto_disabled` row for one rule: the self-disable task runs
in every worker, and two workers that spend their last capture close
together both write a row before either sees the other's `enabled = 0`.
The store's filter makes that unlikely rather than impossible, and the
rows are identical but for the worker that wrote them. One row, or three,
means the same thing.

**Why is the "Recent captures" panel unavailable under `--workers`?**
The ring is per process. Under `--workers` every capture is emitted in a
worker, into that worker's ring, and the management API runs in the
supervisor, whose ring stays empty for the life of the process. Rather
than show an empty ring on a node that is capturing normally,
`GET /api/v1/capture/recent` answers `503` on a `--workers` node, with a
message naming the outputs that do carry the records: the `lorica::capture`
log target, the syslog or OTLP lane, and the rule's `output.dir`. The
rule list and its counters are unaffected: they are read from the store,
which the workers flush into. The same applies to the dashboard counter
`lorica_capture_rules_active` reading 0 on the supervisor's own registry
before the first worker report has arrived; it settles at the workers'
common value within one report interval.

**Why does the capture differ from what the client got?** Because the
response body in the record is the upstream's, captured before any
response-rewrite rule on the route ran. The status and the headers are
the ones written downstream; only the body predates the rewrite. If the
route rewrites bodies, the client received the rewritten bytes and the
record holds the original ones, which is the evidence the feature exists
to provide. A second difference is the request body under
`truncated: true`: the record holds the first `request_body_max_bytes`
bytes and `body_bytes_total` says how much was really sent; the upstream
received all of it.

**Why is `body` `null`?** Read `body_skipped`. `streaming` means the
response content type is stream-by-design (SSE, multipart push, gRPC)
and was never buffered. `budget` means the node's 64 MiB in-flight
ceiling was full when the request arrived; look at
`lorica_capture_inflight_bytes` and at how many rules with large caps are
armed, and remember the ceiling is per worker. `disabled` means the
rule's `capture.request_body` or `capture.response_body` is off.

**Why is the record `base64` when the body is text?** Either the content
type is not one the record treats as textual (no `Content-Type` at all
counts), or the bytes are not valid UTF-8, including a text body
truncated inside a multi-byte character. Decode it; the bytes are the
bytes that were sent.

**Why is `dropped_sink` climbing?** One output is losing records. The
first failure on a directory is a WARN line naming the directory and the
error (missing, read-only, full, name taken); after that the failures are
DEBUG until the directory writes again. For the lanes, check the
collector and `lorica_log_sink_dropped_total{sink, kind="capture"}`.
Requests are unaffected either way.
