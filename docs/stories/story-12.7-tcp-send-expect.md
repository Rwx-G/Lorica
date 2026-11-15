# Story 12.7: TCP Health Checks that Speak the Protocol

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** InProgress
**Priority:** P1
**Author:** Romain G.
**Depends on:**
- Story 12.1 Lot 1 (committed in `1b5d1c51`): the `HealthCheck` enum
  (`lorica-config/src/models/health_check.rs`), `HealthCheck::reconcile`,
  `Backend::set_health_check`, the `backends.health_check_json` column
  (migration 72), the dual write in `health_check_columns`
  (`lorica-config/src/store/backends.rs`) and the "unparseable reads as
  absent" rule in `row_to_backend` (`store/row_helpers.rs`).
- Story 12.1 Lot 2 (not implemented at drafting): `CANONICAL_FORMAT_VERSION`
  3, `prepare_replica` and `validate_structure` carrying streams. This
  story's Lot 1 edits the same three files after it.
- Story 12.1 Lot 4 (not implemented at drafting): the typed health check
  on every surface. This story extends what Lot 4 builds and must not
  start any Lot before it lands; D-11 says, surface by surface, what
  Lot 4 does and what this story adds.
- Story 12.1 Lot 5 shares `lorica-api/openapi.yaml`; this story's Lot 2
  runs after it.
- Lot 0 of this story: two pre-existing health-loop defects fixed as
  their own `fix(health)` commits before Lot 1 (maintainer decision 4).

**Blocks:** Story 12.14 (UDP send/expect reuses the payload types, the
limits, the catalogue module and the D9 predicate defined here), Story
12.12 (IV1 joins its L4 phase as a named scenario).

---

As an operator,
I want active checks that prove a TCP backend answers, not only that its port is open,
so that a hung database leaves the pool before clients notice.

## Problem

Today a backend is probed by an HTTP GET when it has a
`health_check_path`, and by a bare TCP connect otherwise. A TCP connect
succeeds as soon as the kernel completes the handshake from the listen
backlog, which it does for a process that is frozen, deadlocked or
stuck loading its dataset. For a database or a cache behind a stream,
the connect probe therefore keeps a hung backend in rotation until
clients time out. HAProxy (`tcp-check send` / `expect`) ships the
missing check in open source; nginx keeps it paid. It is a parity row
(PRD coverage matrix, "Active health: send/expect").

D9 adds a constraint the HTTP path never had: a raw payload makes
Lorica send operator-chosen bytes to an address, so it is written from
the management plane only, and the automation plane and MCP may pick a
named template and nothing else.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **TCP send/expect**: optional bytes to send, bytes or a pattern to expect within a timeout. The existing TCP-connect probe (`tcp_probe`, `lorica/src/health.rs`) remains the default.
2. Checks run on the existing health loop with its interval, thresholds and lifecycle states, and feed the one health state of the shared backend (D2).
3. **Named templates** for common protocols (Redis `PING`, SMTP banner, PostgreSQL SSLRequest), expressed as send/expect values.
4. **Payloads are written from the management API only (D9).** `backends:write` on the automation API and the MCP config tier may select a named template and nothing else. A payload is validated in size.

## Integration Verification

- IV1: A Redis backend that stops answering `PING` while its port stays open is marked down within the configured thresholds.
- IV2: An automation token with `backends:write` can set a template and is refused when it sends a raw payload.

IV1 is automated twice: in Lot 1 against a scripted fake Redis on
loopback (one that answers `+PONG`, then accepts connections and never
answers), driving the health cycle directly; and handed to Story
12.12's L4 phase against a real Redis frozen with `docker pause`, which
keeps the listening socket's backlog completing handshakes while the
process answers nothing ("Handed to Story 12.12"). IV2 is automated in
Lot 2 on the automation API, and its MCP half in the same Lot.

## What the code does today

Read on `feat/v1.11.0` at `26597077`. Function names, not line numbers.
Read, not run, unless said otherwise.

- `health_check_loop` (`lorica/src/health.rs`) runs in the supervisor
  (and in single-process mode), spawned by `spawn_health_check_loop`
  (`lorica/src/startup/mod.rs`). Each cycle: sleep `next_interval`,
  which re-reads the **global** `default_health_check_interval_s` with a
  floor of 5 s; `list_backends`; Phase 0 moves `Closing` backends to
  `Closed` after `DEFAULT_DRAIN_TIMEOUT` (30 s) or when drained; Phase A
  probes every backend with `health_check_enabled` and not `Closing`,
  concurrently, bounded by `health_max_concurrent_probes`; Phase B
  applies `confirm_status_flip` with `HEALTH_FLIP_THRESHOLD` (3
  consecutive probes); Phase C persists confirmed flips, sends
  `AlertType::BackendDown` on a flip to `Down`, reloads the proxy config
  and signals workers.
- Probe selection is inline in Phase A: `health_check_path` set gives
  `http_probe` (`status().is_success()` through `HEALTH_HTTP_CLIENT`), otherwise
  `tcp_probe` (`TcpStream::connect` within `TCP_CONNECT_TIMEOUT`, 5 s).
  Latency above `DEGRADED_THRESHOLD_MS` (2,000 ms) gives `Degraded`.
  Failures are logged at `debug` only; no metric counts them.
- **The per-backend `health_check_interval_s` is stored, validated and
  shown, and the loop never reads it** (grep: only the doc comment of
  `HEALTH_FLIP_THRESHOLD` and tests name it in `lorica/src`). Lot 0
  fixes it.
- **Phase 0 and Phase C write the whole row from a clone taken at the
  start of the cycle** (`let mut updated = backend.clone();
  store.update_backend(&updated)`), and `update_backend_unchecked`
  writes every column (`store/backends.rs`). An operator edit committed
  between the cycle's `list_backends` and its Phase C write (up to a
  probe timeout later) is overwritten. Today that loses a weight or a
  path; with this story it would also revert a freshly chosen check to
  the one that was failing, which is exactly when an operator changes
  it. Lot 0 fixes it.
- **Releases affected by both defects, verified per tag:** every Lorica
  release tag, `v0.1.2` to `v1.10.6` (38 `v*` tags), carries
  `lorica/src/health.rs`; in none of them does the loop read a
  backend's `health_check_interval_s`, and in every one Phase 0 and
  Phase C call `update_backend(&updated)` on a clone of the row listed
  at the start of the cycle. The field itself already exists at
  `v0.1.2` (`lorica-config/src/models.rs`, `lorica-api/src/backends.rs`).
  Checked with `git show <tag>:lorica/src/health.rs` over every tag.
- `HealthCheck` has `Http { path }` and `TcpConnect`, internally tagged
  by `kind`, `deny_unknown_fields`. `legacy_path()` projects
  `Http` onto `health_check_path`, every other kind onto `None`.
  `reconcile(stored, legacy_path)` honours the stored typed definition
  only while its projection equals the stored path.
- `row_to_backend` reads a `health_check_json` it cannot parse as
  absent, with a WARN, so the legacy path decides. `health_check_columns`
  persists the reconciled definition on every write, so a binary that
  read a definition as absent writes `TcpConnect` back on its next write
  of that row.
- `create_backend_as` / `update_backend_as` (`lorica-api/src/backends.rs`)
  take `CreateBackendRequest` / `UpdateBackendRequest`, which carry
  `health_check_path` and not yet `health_check` (12.1 Lot 4 adds it).
  Both run the caller's `BackendGuard` inside the store closure:
  `restore_withheld` first, then `check` on before and after.
- The automation plane's backend writes (`create_backend`,
  `update_backend` in `lorica-api/src/automation/write.rs`) deserialize
  **the management request structs** and call the `_as` functions with
  `backend_guard(principal)`: the CIDR grant, `BACKEND_PROTECTIONS`
  (one-way TLS rules), and `restoring_withheld(redact::restore_health_check_path)`.
  Whatever field the management body gains, a token can send, unless
  the guard refuses it. The environment resource builds its backends
  with `HealthCheck::TcpConnect` and its bodies
  (`EnvironmentRequest`, `EnvironmentBackendRequest`) are
  `deny_unknown_fields` with no health-check field.
- `redact::backend_row` masks the query values of `health_check_path`
  on every automation and MCP answer, preview and audit read.
- The MCP server never writes on its own: the stdio binary dials the
  automation listener, and the Streamable HTTP binding runs the plane's
  own router in process (`InProcessPlane`,
  `lorica-api/src/automation/mcp.rs`). A plane refusal is therefore a
  refusal on both MCP bindings. Before the call, `lorica-mcp` checks the
  **key names** of a body against `BACKEND_FIELDS` and the `Nested`
  lists (`lorica-mcp/src/tools.rs`); values are the plane's.
- `lorica-mcp` depends on `lorica-automation-policy` and not on
  `lorica-config` (its `Cargo.toml` says why: no SQLite in the stdio
  subprocess). `lorica-config` depends on `lorica-automation-policy`.
- The canonical shape guard (`the_canonical_shape_digest_matches_the_blob_s_field_set`,
  `lorica-config/src/canonical.rs`) reads field names from
  `deny_unknown_fields` structs; `HealthCheck` is an enum and is not in
  its inventory, so a new kind or a new template name moves no digest
  today.
- The dashboard backend form (`routes/Backends.svelte`) edits
  `health_check_path` ("empty = TCP only") and badges `HTTP <path>` or
  `TCP`. `**/*.generated.ts` is in the ESLint ignore list
  (`lorica-dashboard/frontend/eslint.config.js`).
- `backend_health` (gauge, `lorica-api/src/metrics.rs`) is refreshed
  from the store by the metrics refresh in the same process as the
  health loop.

## Decisions taken in this story

Each decision states its reason and what it gives up.

### D-1. Two new kinds: `tcp_template` and `tcp_send_expect`

```rust
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    Http { path: String },
    #[default]
    TcpConnect,
    TcpTemplate {
        template: TcpCheckTemplateName,
        #[serde(default = "default_probe_timeout_ms")]
        timeout_ms: u32,
    },
    TcpSendExpect {
        #[serde(default)]
        send: Option<Payload>,
        expect: Vec<Expectation>,
        #[serde(default = "default_probe_timeout_ms")]
        timeout_ms: u32,
    },
}
```

Wire examples:

```json
{"kind":"tcp_template","template":"redis_ping"}
{"kind":"tcp_send_expect",
 "send":{"hex":"0000000804d2162f"},
 "expect":[{"match":"prefix","bytes":{"hex":"53"}},
           {"match":"prefix","bytes":{"hex":"4e"}}],
 "timeout_ms":2000}
{"kind":"tcp_send_expect","expect":[{"match":"prefix","bytes":{"text":"220"}}]}
```

- **A template is a reference, not a copy.** Reason: D9 is then a
  property of the kind (a token may write `tcp_template`, never
  `tcp_send_expect`), checkable with one `match`, with no byte
  comparison against a catalogue; and a template corrected in a later
  release reaches every backend that names it.
- **Two kinds, not one kind with "a template or a payload".** Serde's
  `flatten` does not combine with `deny_unknown_fields`, which the
  canonical decoder relies on; two kinds keep the wire strict and make
  the OpenAPI `oneOf` by `kind` direct. Gives up: a client switching
  from a template to a custom payload changes `kind`, not one field.
- `HealthCheck::carries_raw_payload(&self) -> bool`, an exhaustive
  `match`, `true` for `TcpSendExpect` only. Every D9 enforcement point
  (D-7) calls it, never a `matches!` of its own, so Story 12.14's
  `udp_send_expect` is covered by adding one arm.
- `legacy_path()` gives `None` for both new kinds (D-5).
- **No TLS.** Both kinds speak plaintext TCP. A backend's
  `tls_upstream` is HTTP-only (PRD D2, Story 12.1 D-11), and a stream's
  upstream TLS lives on the stream (Story 12.4), so a backend shared by
  two streams has no single TLS configuration a probe could use. Since
  a plaintext exchange can never succeed against a TLS port, a
  `tcp_template` or `tcp_send_expect` on a backend with `tls_upstream`
  on is refused (D-6) rather than left to mark the backend down. Gives
  up: an application-level check of a TLS-only service (`rediss`,
  SMTPS); it is checked by TCP connect.

Story 12.14 adds `UdpTemplate` and `UdpSendExpect` with the same
`Payload`, `Expectation` and limits.

### D-2. Payload encoding and size limits

`Payload` is externally tagged, so exactly one form is present:
`{"text": "PING\r\n"}` (the UTF-8 bytes of the string, JSON escapes
included, sent as is) or `{"hex": "0000000804d2162f"}` (an even number
of hexadecimal digits, stored lowercased). Hex exists because a JSON
string cannot carry a byte above `0x7f` as itself (PostgreSQL's
SSLRequest is binary). Decoding is a dozen lines in
`health_check.rs`; no dependency is added.

Limits, constants in `lorica-config/src/models/health_check.rs`, each
with its reason in its doc comment:

| Constant | Value | Reason |
|---|---|---|
| `SEND_MAX_BYTES` | 1,024 (decoded) | Every surveyed protocol greeting fits in a few dozen bytes; a payload is a probe, not a request body. |
| `EXPECT_MAX_ALTERNATIVES` | 8 | Alternatives exist for "S or N" style answers, not for a grammar. |
| `EXPECT_MAX_BYTES` | 256 (decoded, per alternative) | Bounds the matching cost of D-3. |
| `PROBE_READ_MAX_BYTES` | 4,096 | The most a probe ever reads; not configurable (NFR2). |
| `PROBE_TIMEOUT_MS_MIN` / `_MAX` / `_DEFAULT` | 100 / 10,000 / 5,000 | The default is today's `TCP_CONNECT_TIMEOUT`; the maximum keeps one probe within two cycles at the 5 s interval floor. |

Refused: an empty `send` (absent means "send nothing"), an empty
`expect` list (that is `tcp_connect`), an empty alternative, a hex
string of odd length or with a non-hex digit, any limit exceeded. Each
refusal names the field path (`health_check.expect[2].bytes`) and the
limit read from the constant, never a typed-out number. Limits are
checked at write (D-6), not in `Deserialize`, so a later release that
raises one does not make an older binary's decode fail.

### D-3. What "a pattern" is: literal alternatives, prefix or contains, no regex

An `Expectation` is `{"match": "prefix" | "contains", "bytes": Payload}`.
The probe is healthy when **any** alternative matches the bytes read:
`prefix` when they start with the alternative, `contains` when it
occurs anywhere in the first `PROBE_READ_MAX_BYTES`.

- **No regular expression.** Reason: the three templates and the common
  custom cases (`+PONG`, `220`, `S`/`N`, a version string) are literal
  prefixes or substrings; literals cost nothing to compile, have no
  per-backend compiled cache to keep in step with edits, and leave the
  "arbitrary payload inspection" refusal of the PRD untouched. Rust's
  `regex` would be linear time, so this is a choice of surface, not a
  safety necessity. Gives up: an answer with alternatives inside it
  (HAProxy's `rstring`); an operator lists literal alternatives instead.
- **Bounded cost.** Matching is incremental: after each read, a
  `contains` alternative searches only from `filled - (len - 1)`, so
  every byte is compared at most `len` times per alternative, at worst
  `PROBE_READ_MAX_BYTES x EXPECT_MAX_BYTES x EXPECT_MAX_ALTERNATIVES`
  byte comparisons per probe, whatever the read pattern. A naive rescan
  after each one-byte read would be quadratic in the read size; the
  tests feed one byte at a time to pin that it is not.
- **Early decision.** `evaluate(expect, read, finished) -> Verdict
  { Match, Mismatch, NeedMore }`, a pure function. When every
  alternative is a prefix, the probe reads at most the longest prefix
  and decides `Mismatch` as soon as the bytes read diverge from every
  alternative, without waiting for the timeout.

### D-4. The templates are data in `lorica-automation-policy`, referenced by name

New module `lorica-automation-policy/src/health_templates.rs`:

```rust
pub enum MatchAnchor { Prefix, Contains }          // serde snake_case
pub struct TemplateExpectation { pub anchor: MatchAnchor, pub bytes: &'static [u8] }
pub struct CheckTemplate {
    pub name: &'static str,
    pub summary: &'static str,
    pub send: Option<&'static [u8]>,
    pub expect: &'static [TemplateExpectation],
}
pub const TCP_CHECK_TEMPLATES: &[CheckTemplate] = &[ ... ];
pub fn tcp_check_template(name: &str) -> Option<&'static CheckTemplate>;
```

The three templates of AC #3:

| `name` | `send` | `expect` (any of) |
|---|---|---|
| `redis_ping` | `PING\r\n` | prefix `+PONG`; prefix `-NOAUTH` (resolved 1) |
| `smtp_banner` | nothing | prefix `220` |
| `postgresql_ssl_request` | `00 00 00 08 04 d2 16 2f` | prefix `S` (`0x53`); prefix `N` (`0x4e`) |

This table is the decision; the code is the authority from then on, and
the operator documentation renders it (D-12).

- **Why the policy crate.** The template set is the allowlist of bytes
  an automation token may cause Lorica to send, which is what the
  crate states for the settings tier (`SETTINGS_ALLOWLIST`); and
  `lorica-mcp`, which cannot reach `lorica-config`, needs the names to
  render the tool schema (D-7). The crate stays `serde`-only: the
  catalogue is `&'static` data. Gives up: the crate now holds protocol
  bytes beside policy words; its module doc says why (resolved 3).
- **Why not stored in the database.** A template is a payload no
  operator wrote; adding one is a release decision, the same as adding
  a setting to the allowlist.
- **The reference type.** `TcpCheckTemplateName` (in
  `health_check.rs`) serializes as the name and deserializes **only**
  a name `tcp_check_template` finds. An unknown name is then a decode
  failure: in the store it reads as absent (the existing rule, D-5), in
  the canonical blob it refuses the blob, in an API body it is a 422.
- **Every template is a valid `tcp_send_expect`.** A test converts each
  catalogue entry to the `TcpSendExpect` it stands for and runs D-6's
  validation on it, so AC #3's "expressed as send/expect values" is
  checked, not asserted.
- **The canonical shape guard watches kinds and template names.**
  `shape_lines` gains a line `HealthCheck(kinds)` read by probing the
  enum with an unknown `kind` (serde answers with the list of variants,
  parsed the way `field_names` parses fields), one line per struct-like
  variant read by probing it with an unknown field, the `Payload` and
  `Expectation` field sets, and a line `TcpCheckTemplate(names)` built
  from `TCP_CHECK_TEMPLATES`. `CANONICAL_SHAPE_DIGEST` moves in Lot 1
  with its paragraph ("rides version 3, the release's one step"). From
  then on, adding a template or a kind turns the guard red and forces
  the version decision: a peer that does not know the name would refuse
  a blob carrying it. Template bytes are not in the digest: they do not
  change what decodes.

### D-5. Rollback, forward compatibility, and the health loop's own writes

**1.10.6 rolled back on a 1.11.0 database.** Both new kinds project
onto `health_check_path = NULL`. 1.10.6 reads that column only, so it
probes such a backend by TCP connect: weaker (a hung backend can stay
in rotation) and never wrong in the other direction (a healthy backend
is never marked down by it). Its writes name explicit columns without
`health_check_json`, so the typed definition survives the rollback, and
`reconcile` restores it on re-upgrade unless a path was set meanwhile.
The D-2 matrix of Story 12.1 gains these rows, pinned in the same vector
test and in `config_db_upgrade.rs` with the frozen 1.10.6 statements:

| Stored typed | Stored path | Read as | Who wrote it |
|---|---|---|---|
| `tcp_template{redis_ping}` | NULL | `tcp_template{redis_ping}` | 1.11.0 |
| `tcp_send_expect{..}` | NULL | `tcp_send_expect{..}` | 1.11.0 |
| `tcp_template{redis_ping}` | `/x` | `http{/x}` | 1.10.6 set a path after 1.11.0 |
| `tcp_send_expect{..}` | `/x` | `http{/x}` | 1.10.6 set a path after 1.11.0 |
| a kind or a template name this binary does not know | NULL | `tcp_connect`, WARN | a later release, then a rollback |

`docs/hot-upgrade.md` states the first consequence (Story 12.1 D-2
assigned it to the story adding such a kind).

**The health loop no longer writes whole rows** (the race described
under "What the code does today"), fixed in Lot 0 before this story's
own code: `ConfigStore` gains `set_backend_health_status(id, status)`
and `set_backend_lifecycle_state(id, state, updated_at)`, each one
`UPDATE` of the named columns, used by Phase C and Phase 0. This story
depends on it for two reasons: an operator switching a failing backend
to a send/expect check is not reverted by the cycle that was probing
the old one; and a binary that read a definition as absent (last row of
the table) does not persist `tcp_connect` over it on every status flip,
which would otherwise make any rollback across a new kind or template
destroy the definition within a few cycles. Neither write touches what
the attachment rule reads, so neither runs it. Phase C never set
`updated_at` and still does not.

What remains: an operator **editing** that backend on the older binary
writes the definition that binary shows (`tcp_connect`). The binary that
writes is the truth, as in Story 12.1 D-2.

### D-6. One validation, run by every writer

`HealthCheck::validate(&self) -> Result<(), String>` (D-2 limits and
refusals, template existence by construction) and
`Backend::validate_health_check(&self)` (the kind's own validation, plus
the TLS refusal of D-1: `tcp_template` or `tcp_send_expect` with
`tls_upstream` on is refused naming both fields), in
`health_check.rs`. Called from:

- `create_backend_unchecked` and `update_backend_unchecked`
  (`store/backends.rs`), beside `validate_backend_address`, so every
  writer validates, the checked and the unchecked ones alike;
- `prepare_replica` (`store/replica.rs`), over the whole blob, as a
  semantic refusal naming the backend, before anything is written;
- `validate_structure` (`import.rs`), before `clear_all`.

A violation is `ConfigError::Validation`, which the management API
already maps to `400`. The automation plane answers it the same way.

### D-7. D9, enforced on every surface that can write a backend

The rule, stated once in `lorica-automation-policy/src/protections.rs`
as `backend::HEALTH_CHECK_PAYLOAD` (fields `["health_check"]`, the rule
and the reason in the words a refusal and `docs/mcp.md` use): a token
may set `http`, `tcp_connect` and `tcp_template`, and may leave a stored
`tcp_send_expect` exactly as it is; it may not create one or change
one. Moving a backend **away** from a custom payload (to a template, a
connect check, or checks off) is allowed: a health check is not an
access control, and switching checks off is already a token's right.

| Surface | Enforcement point | Proof (test) |
|---|---|---|
| Automation `POST /automation/v1/backends` | `backend_guard` (`automation/write.rs`), on `after`: `carries_raw_payload()` with no `before` is `403` | plane test: create with a payload is 403 and stores nothing; create with `tcp_template` is 201 |
| Automation `PUT /automation/v1/backends/{id}` | `backend_guard`, after `restoring_withheld`: `after.health_check.carries_raw_payload()` and `after.health_check != before.health_check` is `403` | plane tests: weight-only patch of a backend holding a payload is 200 and the payload is unchanged; the masked check sent back as read is 200 and keeps the stored one (D-8); a changed payload is 403; payload to template is 200 |
| Dry run of either | the same guard, run by the preview (`WriteMode::Preview`) | plane test: a preview with a payload is 403 |
| Automation environment resource | no field: `EnvironmentRequest` and `EnvironmentBackendRequest` are `deny_unknown_fields` and build `tcp_connect` | plane test: a `health_check` key in an environment backend is 422 |
| MCP config tier, stdio and Streamable HTTP | the plane above (both bindings reach it), and before it the tool's key check: the `health_check` `Nested` entry of `BACKEND_FIELDS` offers `kind`, `path`, `template`, `timeout_ms`, never `send` or `expect` | `lorica-mcp` test: `lorica_backend_update` with a payload is refused by the tool naming `send` without a plane call; MCP plane test: `tcp_template` through the in-process binding is applied |
| MCP read tier, automation reads | no write; masking only (D-8) | read plane test |
| Admin tier settings | no health-check key exists in `SETTINGS_ALLOWLIST` | nothing to add |
| Management API, dashboard | allowed (Operator, the backend write floor) | handler tests |
| Replica apply, TOML import | allowed: the source is the management plane of the control plane or an operator's file; validated by D-6 | replica and import tests |

The `403` names the field and the rule's words, never the payload.
The MCP tool's schema renders the `template` property's `enum` from
`TCP_CHECK_TEMPLATES` at schema build, and the backend tools' summaries
say that a custom send/expect check is set in the dashboard.

### D-8. A payload is shown to Operator and SuperAdmin, withheld from Viewer and from tokens

A custom `send` is where an operator who did not read the docs puts a
credential (`AUTH <password>\r\nPING\r\n`). The Viewer role's contract
is "secrets are scrubbed or blocked" (`Role::Viewer`,
`lorica-config/src/models/enums.rs`), so a payload is treated as a
secret below Operator (maintainer decision 2):

- **Management API.** `list_backends` and `get_backend`
  (`lorica-api/src/backends.rs`) take the `Session`, which they do not
  today, and `backend_to_response` masks `send` for a Viewer with the
  same `{"text": "[redacted]"}` the automation plane uses. Operator and
  SuperAdmin see it in full and edit it in the dashboard. A Viewer
  cannot write a backend (`required_role` floors writes at Operator),
  so the restore-on-echo rule below is reachable from the management
  plane only by a session that sees the real value; the management
  write path still runs it, so an Operator saving a form a Viewer
  session had loaded cannot store the mask. Every other Viewer-readable
  GET that serializes a backend is found by grep in Lot 2 and masked
  the same way; the audit log is Operator and above (`required_role`),
  and the config export is a POST outside the Viewer floor.
- **Automation and MCP.** On every answer, preview and audit read,
  `redact::backend_row` replaces a `tcp_send_expect`'s `send` with
  `{"text": "[redacted]"}`, which still deserializes as a `Payload`.
- `expect` and templates are not masked anywhere: they are what the
  backend answers, or public catalogue bytes.
- The docs still say never to put a credential in a payload: a masked
  value is still stored in clear, replicated, exported and shown to
  every Operator.

`redact::restore_health_check_payload(before, after)` follows the
`restore_health_check_path` precedent: an `after` whose `send` is the
mask is replaced by the stored check when the whole `after` check
equals the stored check as `backend_row` masks it; otherwise any
`[redacted]` send is `400`. The guard's `restoring_withheld` takes one
function, so it gets `restore_backend_withheld`, which runs both
restores. The management write path (`create_backend_as`,
`update_backend_as` with `BackendGuard::unbounded()`) runs
`restore_health_check_payload` too, so the mask is never stored
whichever plane sent it. The notification and the log line of D-10
never carry `send`.

### D-9. The probe

`probe_for(&Backend) -> ProbeTarget` (built by 12.1 Lot 4) gains
`ProbeTarget::TcpExchange { address, exchange: Exchange }`, where
`Exchange { send: Option<Cow<'static, [u8]>>, expect: Vec<(MatchAnchor,
Cow<'static, [u8]>)>, timeout: Duration }` is resolved once per probe by
`HealthCheck::exchange()`: a template borrows the catalogue's bytes, a
custom check its decoded payload. `send_expect_probe(address, &exchange)`:

1. One deadline, `now + timeout`, for the whole probe: connect, write,
   read. `TCP_NODELAY` on.
2. `write_all(send)` when there is one. No half-close: a server may
   close on FIN before answering.
3. Read into one buffer of `min(PROBE_READ_MAX_BYTES, need)` bytes,
   `need` being the longest prefix when every alternative is a prefix.
   After each read, `evaluate` (D-3): `Match` ends healthy, `Mismatch`
   ends down, `NeedMore` reads again. EOF or a full buffer evaluates with
   `finished = true`. A server dribbling one byte per second is bounded
   by the deadline; a flood is bounded by the buffer.
4. The connection is dropped (FIN) once decided. No farewell bytes
   (SMTP `QUIT`): see Dev Notes, "Backend-side noise".
5. Healthy above `DEGRADED_THRESHOLD_MS` from the start of the connect
   is `Degraded`, as for the other kinds.

Lot 0 extracts the cycle body of `health_check_loop` into
`run_health_cycle(...)`, so tests drive cycles without sleeping; this
story's tests use it. Probe concurrency stays bounded
by `health_max_concurrent_probes`; flips by `HEALTH_FLIP_THRESHOLD`;
`Closing` backends are still not probed (AC #2).

### D-10. A failing expect is visible: reason, metric, one log line, the alert

- `ProbeResult::Down` gains a reason, `ProbeFailure`, a closed enum in
  `health.rs` covering every kind: `connect_failed`, `connect_timeout`,
  `send_failed`, `read_failed`, `response_timeout` (no byte read before
  the deadline), `closed_before_match`, `no_match` (bytes read, none
  matched, by EOF, full buffer, early mismatch or deadline),
  `http_status`, `http_failed`. It derives `strum::VariantArray` and
  `IntoStaticStr` (snake_case); every published word list is derived
  from `VARIANTS`.
- **Metric**: `lorica_backend_health_probe_failures_total{backend_id,
  reason}`, a counter incremented on every failed probe, flip or not,
  registered beside `backend_health` in `lorica-api/src/metrics.rs`.
  Cardinality is backends times the closed reason set; no address, no
  byte in a label. The health loop runs in the process that serves
  `/metrics`, as the `backend_health` gauge does, so no cross-worker
  aggregation is involved.
- **Log**: probes keep logging at `debug`. On a **confirmed** flip to
  `Down` only, one `info` line with backend id, address, kind, template
  name when there is one, reason, bytes read, and for `no_match` the
  first 64 bytes read, printable ASCII kept and every other byte as
  `\xNN`. Once per flip, never per probe, so a backend cannot choose the
  log write rate (the PRD's log-amplification concern).
- **Alert**: the existing `BackendDown` event gains the details
  `check` (the kind, or the template name) and `reason`. No payload, no
  bytes read.
- Not in this story: a "last failure" field on the backend view
  (maintainer decision 5).

### D-11. Surface by surface: what 12.1 Lot 4 does, what this story adds

| Surface | 12.1 Lot 4 (prerequisite) | This story |
|---|---|---|
| `lorica/src/health.rs` | `probe_for` for `http` and `tcp_connect` | `TcpExchange`, `send_expect_probe`, `evaluate`, `ProbeFailure`, the cycle extraction, the narrow writes, the metric, the log line, the alert details |
| Management API (`backends.rs`) | `health_check: Option<HealthCheck>` on both requests, both shapes, `400` when both disagree, both on the response | the new kinds ride the model; D-6 errors surface as `400`; the two GET handlers take the `Session` and mask `send` for a Viewer; both write paths run `restore_health_check_payload` (D-8) |
| Management OpenAPI (`openapi.yaml`) | `HealthCheck` `oneOf` `http`, `tcp_connect`; `health_check_path` deprecated | `tcp_template`, `tcp_send_expect`, `Payload`, `Expectation`; the `template` enum and the limits asserted by the contract test (D-12) |
| Automation API (`automation/write.rs`, `redact.rs`) | typed path masked; `restore_health_check_path` restores both fields | D-7 rule in `backend_guard`, D-8 mask and restore, `restore_backend_withheld` |
| Automation OpenAPI (`openapi-automation.yaml`) | the typed shape on reads and writes | reads: all four kinds, `send` documented as masked; writes: `AutomationHealthCheck`, a `oneOf` of `http`, `tcp_connect`, `tcp_template` only |
| `lorica-automation-policy` | nothing | `health_templates.rs` (D-4), `backend::HEALTH_CHECK_PAYLOAD` (D-7) |
| MCP (`lorica-mcp/src/tools.rs`) | `health_check` in `BACKEND_FIELDS` (and its `Nested` entry with `kind`, `path`; if Lot 4 did not declare it nested, this story does) | `template`, `timeout_ms` in the nested list, `send` and `expect` deliberately absent, the `template` enum rendered from the catalogue, the summaries |
| Dashboard (`api.ts`, `Backends.svelte`) | kind picker with HTTP path and TCP connect | TCP template (select from the generated fixture, showing each template's bytes) and TCP send/expect (send as text or hex, alternatives with prefix/contains, timeout); the list badge names the template or "TCP send/expect" |

### D-12. The template list reaches the dashboard and the docs by rendering, never by retyping

Per `.claude/rules/derived-not-transcribed.md`: the dashboard and the
operator documentation both need the template names, bytes and limits,
and neither may hold a copy nothing checks.

- `lorica-dashboard/frontend/src/lib/health-check-templates.generated.ts`
  is rendered from `TCP_CHECK_TEMPLATES` and the D-2 constants, and
  pinned byte for byte by `lorica-api/tests/health_check_template_fixture.rs`,
  the `automation_scope_fixture.rs` pattern: the test renders it in
  memory and refuses a stale file, printing the expected content. Its
  name matches the existing `**/*.generated.ts` ESLint ignore; no
  formatter rewrites it.
- `docs/health-checks.md` carries the template table and the limits
  between two markers, asserted by the same test against the same
  rendering.
- `lorica-api/tests/openapi_contract.rs` asserts, in both documents, the
  `template` enum against the catalogue's names and `maxItems` of
  `expect` against `EXPECT_MAX_ALTERNATIVES`.
- Rejected: a `GET /api/v1/health-check-templates` endpoint. It would
  add a path, a role rule and two OpenAPI entries to serve data that
  ships in the same binary as the dashboard.

## Tasks

Five Lots with hard file allowlists. A Lot touches only its files; two
Lots that share a file are sequential. Every Lot that runs cargo ends on
a tree that passes the gate chain CI runs (`cargo fmt --all -- --check`,
the workspace clippy with `--all-targets --features lorica/otel -- -D
warnings` under `CARGO_BUILD_WARNINGS=deny`, `cargo test --workspace`,
`cargo audit`), through Docker on Linux. No agent runs `git checkout`,
`git restore`, `git stash` or `git reset` in the shared tree.

**Start condition:** Lot 0 needs only Story 12.1 Lot 4 committed (it
owns `lorica/src/health.rs` until then). Lots 1 to 4 need Story 12.1
Lots 2, 4 and 5 committed. Before each Lot, the orchestrator checks
that no in-flight Lot of another story holds a file of its allowlist
(`lorica/src/health.rs`, `lorica-api/src/metrics.rs` and the OpenAPI
documents are the likely collisions).

**Order:** Lot 0 first, as two commits. Lot 1 alone after it. Lots 2
and 3 in parallel after Lot 1 (disjoint allowlists). Lot 4 last.

**Cargo:** Lots 0, 1 and 2 run cargo (per-crate tests and clippy while
in parallel; the orchestrator runs the full chain once the wave is
merged). Lot 3 runs the frontend gates of
`.claude/rules/lorica-frontend.md` and
`cargo test -p lorica-api --test health_check_template_fixture` only.
Lot 4 runs nothing.

### Lot 0: two pre-existing health-loop defects, as their own `fix(health)` commits (first; cargo)

Both defects predate Epic 12: every Lorica release from `v0.1.2` to
`v1.10.6` carries them ("What the code does today", verified per tag).
They ship in this cycle, before Lot 1, each as one commit with its own
tests and its own `CHANGELOG.md` `[Unreleased]` "Fixed" entry naming
the affected releases.

Allowlist: `lorica/src/health.rs`, `lorica-config/src/store/backends.rs`
(the two status-only writers only), `lorica-config/src/tests.rs` (their
store tests only), `CHANGELOG.md` (the two Fixed entries only); and for
commit 2 only, `lorica-api/src/backends.rs` (the create default only),
`lorica-api/src/automation/environments.rs` (the backend interval
default only), `lorica-api/src/tests.rs` and
`lorica-api/src/automation/environments/tests.rs` (their tests only).

Commit 1, `fix(health): stop the health loop overwriting backend edits made during a cycle`:

- [x] `run_health_cycle(...)` extracted from `health_check_loop`, no
      behaviour change, so tests drive cycles without sleeping.
- [x] `ConfigStore::set_backend_health_status(id, status)` and
      `set_backend_lifecycle_state(id, state, updated_at)`: one `UPDATE`
      of the named columns each, `NotFound` on an unknown id, no
      attachment rule (they change nothing it reads).
- [x] Phase C uses the first, Phase 0 the second; neither clones and
      writes a whole row any more.
- [x] Tests: an edit of the backend (weight, address, check) committed
      between a cycle's listing and its flip is still stored after the
      flip; the same for the `Closing` to `Closed` transition; both
      writers leave every other column byte-identical.
- [x] CHANGELOG Fixed: the health loop no longer reverts a backend edit
      committed while a check cycle was running (all releases up to
      1.10.6).

Commit 2, `fix(health): probe each backend at its own health_check_interval_s`:

- [x] The loop wakes on a fixed one-second tick and probes, each tick,
      the eligible backends whose last probe started at least their own
      `health_check_interval_s` ago (at least the existing 5 s floor), a
      backend never probed yet being due at once. Last-probe instants
      live in loop state beside `pending_health` and are dropped for a
      backend that leaves the list. Concurrency, hysteresis and the
      `Closing` exclusion are unchanged.
- [x] The global `default_health_check_interval_s` no longer paces the
      loop and becomes what its name says (resolved 7): the interval a
      backend gets when its create names none. `create_backend_as`
      reads it from the stored settings inside its store closure in
      place of `unwrap_or(10)`, so the automation create, which runs the
      same function, follows; the environment resource reads it in place
      of its `DEFAULT_HEALTH_CHECK_INTERVAL_S` constant, which goes. An
      existing backend keeps its stored interval: the setting is read at
      create only, never applied to stored rows. `HEALTH_FLIP_THRESHOLD`'s
      doc comment, which already says the confirmation time is the
      threshold times "the operator's `health_check_interval_s`", becomes
      true, and the setting's own doc comments (model, API defaults
      block) say "default for new backends".
- [x] Tests: two backends at 5 s and 15 s over 30 simulated seconds are
      probed 6 and 2 times; an interval edited between cycles takes
      effect from the next probe; a deleted backend's state is dropped;
      with the setting at 30, a management create without an interval
      stores 30 and one naming 15 stores 15; an automation create and an
      environment `PUT` without one store 30; changing the setting leaves
      every stored backend's interval as it was.
- [x] CHANGELOG Fixed, one entry covering both effects: a backend's own
      health-check interval is honoured, where every backend used to be
      probed at the global interval; and `default_health_check_interval_s`
      is now the interval a backend created without one gets, where such
      a backend used to get 10 s whatever the setting (both in all
      releases up to 1.10.6). The entry states that probe timing changes
      for every backend whose interval differs from the global setting.

### Lot 1: catalogue, model, validation, store, probe (sequential, first; cargo)

Allowlist (new files marked +):
`lorica-automation-policy/src/health_templates.rs`+,
`lorica-automation-policy/src/lib.rs`,
`lorica-config/src/models/health_check.rs`, `lorica-config/src/models/mod.rs`,
`lorica-config/src/store/backends.rs`, `lorica-config/src/store/replica.rs`
(`prepare_replica` only), `lorica-config/src/import.rs`
(`validate_structure` only), `lorica-config/src/canonical.rs` (the shape
guard test module only), `lorica-config/src/tests.rs`,
`lorica-config/tests/config_db_upgrade.rs`, `lorica/src/health.rs`,
`lorica-api/src/metrics.rs` (the new counter and its setter only), and
any file holding an exhaustive `match` on `HealthCheck` the new variants
break, for the new arms only. Print them with
`grep -rn --include=*.rs -e "HealthCheck::" . | grep -v "^./target" | grep -v "^./.claude"`;
the grep is the authority.

- [x] `health_templates.rs`: `MatchAnchor`, `TemplateExpectation`,
      `CheckTemplate`, `TCP_CHECK_TEMPLATES` with the three templates of
      D-4, `tcp_check_template`; module doc saying why protocol bytes
      live in the policy crate; re-exports in `lib.rs`.
- [x] `health_check.rs`: `TcpTemplate`, `TcpSendExpect`,
      `TcpCheckTemplateName` (custom serde, D-4), `Payload`,
      `Expectation`, the D-2 constants, `default_probe_timeout_ms`,
      `legacy_path` arms, `carries_raw_payload`, `validate`,
      `Backend::validate_health_check`, `exchange()` and `Exchange`, the
      hex codec.
- [x] `store/backends.rs`: `validate_health_check` in both unchecked
      writers.
- [x] `prepare_replica` and `validate_structure` call D-6, naming the
      backend.
- [x] `canonical.rs` tests: the shape lines of D-4 and the digest moved
      with its paragraph.
- [x] `health.rs`: `ProbeTarget::TcpExchange`, `evaluate` and `Verdict`,
      `send_expect_probe`, `ProbeFailure` on every probe kind, the
      counter, the flip log line, the alert details.
- [x] `metrics.rs`: `lorica_backend_health_probe_failures_total` with
      the `lorica_metrics` counter-vec helper the module already uses
      for counters, and its setter.
- [x] Tests listed under Dev Notes, Lot 1.

### Lot 2: management, automation and MCP surfaces (after Lot 1; parallel with Lot 3; cargo)

Allowlist: `lorica-automation-policy/src/protections.rs`,
`lorica-automation-policy/src/lib.rs` (re-export only),
`lorica-api/src/backends.rs` (the Viewer mask, the restore on both
write paths, doc comments),
`lorica-api/src/tests.rs` (backend handler tests only), and any other
handler serializing a backend on a Viewer-readable GET that the grep of
D-8 finds, for the mask only,
`lorica-api/src/automation/write.rs`, `lorica-api/src/automation/redact.rs`,
`lorica-api/src/automation/write/plane_tests.rs`,
`lorica-api/src/automation/read/plane_tests.rs`,
`lorica-api/src/automation/mcp/plane_tests.rs`,
`lorica-api/src/automation/environments/tests.rs`,
`lorica-api/openapi.yaml` (backend schemas only),
`lorica-api/openapi-automation.yaml`, `lorica-api/tests/openapi_contract.rs`,
`lorica-mcp/src/tools.rs`.

- [x] `protections.rs`: `backend::HEALTH_CHECK_PAYLOAD` with its rule
      and reason; the existing words test covers it.
- [x] `write.rs`: `ensure_no_new_raw_payload(before, after)` in
      `backend_guard`, calling `carries_raw_payload`, refusing with
      `403` in the policy's words; `restore_backend_withheld` passed to
      `restoring_withheld`; handler doc comments name the rule.
- [x] `redact.rs`: `backend_row` masks a custom `send`;
      `restore_health_check_payload`; module doc gains the field.
- [x] `backends.rs`: `list_backends` and `get_backend` take the
      `Session`; `backend_to_response` masks `send` for a Viewer (the
      mask helper shared with `redact.rs`, not a second copy);
      `create_backend_as` and `update_backend_as` run
      `restore_health_check_payload` on every plane. Grep every GET
      handler that serializes a `Backend` or `BackendResponse` and
      record the list in the Completion Notes.
- [x] `tools.rs`: the `health_check` nested list (`kind`, `path`,
      `template`, `timeout_ms`), the rendered `template` enum, the two
      backend summaries.
- [x] OpenAPI per D-11, both documents; the contract assertions of D-12.
- [x] Tests listed under Dev Notes, Lot 2.

### Lot 3: dashboard and the rendered template fixture (after Lot 1; parallel with Lot 2; frontend gates)

Allowlist: `lorica-dashboard/frontend/src/lib/health-check-templates.generated.ts`+,
`lorica-api/tests/health_check_template_fixture.rs`+,
`docs/health-checks.md`+ (the marked template and limits section only;
Lot 4 writes the rest), `lorica-dashboard/frontend/src/lib/api.ts`,
`lorica-dashboard/frontend/src/routes/Backends.svelte`,
`lorica-dashboard/frontend/src/routes/Backends.test.ts`.

- [x] The fixture test renders the TS module and the doc section from
      `TCP_CHECK_TEMPLATES` and the D-2 constants, refuses either file
      when stale, and prints the expected content.
- [x] `api.ts`: the `HealthCheck` union gains both kinds, `Payload`,
      `Expectation`.
- [x] `Backends.svelte`: the two new choices of the kind picker (D-11),
      client-side limits read from the generated module, the badge.
- [x] Vitest: each kind sends its typed shape; a template shows its
      bytes; a hex field refuses an odd length; a backend read with a
      custom payload loads into the form and saves back unchanged.

### Lot 4: documentation (last; no cargo)

Allowlist: `docs/health-checks.md` (outside the marked section),
`docs/automation.md`, `docs/mcp.md`, `docs/hot-upgrade.md`,
`docs/security/threat-model.md`, `docs/architecture/source-tree.md`,
`CHANGELOG.md`.

- [ ] `docs/health-checks.md`: the four TCP-side kinds, how a probe
      decides (D-3, D-9), the per-backend interval (Lot 0), the TLS
      refusal, the reasons of D-10 and where to read them, backend-side
      noise, and "never put a credential in a payload: it is masked for
      Viewer and tokens, but stored in clear, replicated, exported and
      shown to every Operator" (D-8).
- [ ] `docs/automation.md` and `docs/mcp.md`: the D-7 rule beside the
      backend one-way rules, the masked `send` beside the masked
      `health_check_path`.
- [ ] `docs/hot-upgrade.md`: a backend with a template or a custom
      send/expect check is probed by TCP connect while rolled back to
      1.10.6, and gets its check back on re-upgrade unless a path was set.
- [ ] `docs/security/threat-model.md`: payloads as an operator-chosen
      traffic source (management only; tokens bounded to the catalogue
      and their CIDR grant), payload confidentiality, bounded reads and
      bounded logging of backend bytes.
- [ ] `CHANGELOG.md` `[Unreleased]`: Added (send/expect checks,
      templates, the failure counter); Security (payloads refused on
      every automation and MCP surface, masked for Viewer and on every
      token read). The two Fixed entries are Lot 0's.
- [ ] `docs/architecture/source-tree.md`: the new files.

## Dev Notes

### Where to extend, verified on `26597077`

- `lorica-config/src/models/health_check.rs`: `HealthCheck`,
  `legacy_path`, `reconcile`, `Backend::set_health_check`, the
  `reconcile_reads_every_row_of_the_rollback_matrix` vector test.
- `lorica-config/src/store/backends.rs`: `BACKEND_COLUMNS`,
  `health_check_columns`, `create_backend_unchecked`,
  `update_backend_unchecked`, `validate_backend_address`,
  `check_attachments_of`.
- `lorica-config/src/store/row_helpers.rs`: `row_to_backend` (the
  unparseable-reads-as-absent branch; read only).
- `lorica-config/src/canonical.rs`: `field_names`, `shape_lines`,
  `CANONICAL_SHAPE_DIGEST` and its guard test.
- `lorica/src/health.rs`: `health_check_loop`, `next_interval`,
  `tcp_probe`, `http_probe`, `ProbeResult`, `confirm_status_flip`,
  `HEALTH_FLIP_THRESHOLD`, `DEGRADED_THRESHOLD_MS`,
  `TCP_CONNECT_TIMEOUT`, `DEFAULT_DRAIN_TIMEOUT`; `probe_for` once 12.1
  Lot 4 lands.
- `lorica/src/startup/mod.rs`: `spawn_health_check_loop` (read only).
- `lorica-api/src/backends.rs`: `CreateBackendRequest`,
  `UpdateBackendRequest`, `BackendResponse`, `create_backend_as`,
  `update_backend_as` (the guard's two calls).
- `lorica-api/src/automation/write.rs`: `backend_guard`,
  `as_created_by_default`, `ensure_not_weakened`, `create_backend`,
  `update_backend`.
- `lorica-api/src/automation/redact.rs`: `backend_row`,
  `restore_health_check_path`, `REDACTED`, `query_values`.
- `lorica-automation-policy/src/protections.rs`: `ProtectionRule`,
  `backend`, `BACKEND_PROTECTION_RULES`, the words test.
- `lorica-mcp/src/tools.rs`: `Body`, `Nested`, `BACKEND_FIELDS`, the
  `lorica_backend_create` and `lorica_backend_update` entries of
  `MUTATIONS`.
- `lorica-api/tests/automation_scope_fixture.rs`: the rendering and
  stale-file pattern the new fixture test copies.
- `lorica-api/src/metrics.rs`: `BACKEND_HEALTH`, `set_backend_health`,
  the refresh that sets it.
- `lorica-notify`: `AlertEvent::with_detail`, `AlertType::BackendDown`.

### Pitfalls

- **Every D9 check goes through `carries_raw_payload`.** A `matches!`
  on `TcpSendExpect` somewhere else is the place 12.14's UDP payload
  will slip through.
- **The guard sees the row after the patch, not the body.** A
  weight-only patch on a backend holding a payload carries the payload
  in `after`; refusing on "after has a payload" instead of "after
  changed a payload" would lock every automation edit of such a backend.
- **Restore before check.** `restoring_withheld` runs before `check`;
  the D-7 comparison must see the restored check, or a copied-back row
  is refused.
- **The mask must still deserialize.** `"send": "[redacted]"` (a bare
  string) is a 422 at the body; `{"text": "[redacted]"}` is a `Payload`.
- **Incremental search window.** Searching the whole buffer after every
  read is quadratic; the one-byte-at-a-time test catches it only if it
  measures comparisons (a counter in the test build of `evaluate`) or
  bounds the time, so do one of them.
- **One deadline.** A separate connect timeout plus a read timeout lets
  a probe run past `timeout_ms`.
- **IPv6 and hostnames.** `TcpStream::connect(&str)` takes
  `host:port` and `[v6]:port` as `tcp_probe` does; keep the same call.
  Portless backends never reach the probe (12.1 D-6 refuses checks on
  them).
- **The narrow writes must not run the attachment rule and must not
  touch `updated_at` for a status flip**, which Phase C never did.
- **Unparseable is not invalid.** A stored check that parses but breaks
  a D-2 limit (a later release raising a limit, then a rollback) is
  probed as stored; the probe's own hard bounds (`PROBE_READ_MAX_BYTES`,
  the deadline) hold whatever the definition says. Validation runs on
  writes only.
- **No real infrastructure names** in fixtures, banners or logs in
  tests: `192.0.2.0/24`, `2001:db8::/32`, `mail.example.com`.
- **`CARGO_BUILD_WARNINGS=deny`** in every local Docker gate run.

### Backend-side noise (not verified)

A probe that connects, exchanges a few bytes and closes is visible in
the backend's own logs at every interval. I have not checked what each
server logs: Postfix is commonly reported to log "lost connection after
CONNECT", and PostgreSQL may log an incomplete startup after an
SSLRequest followed by a close. Lot 1's fake servers say nothing about
it; Story 12.12's scenario against real images is where to observe it,
and `docs/health-checks.md` states what was observed there, or says it
was not checked.

### Tests each Lot must add

**Lot 1**

- `health_templates.rs`: names unique and in the snake_case alphabet;
  every template non-empty `expect`.
- `health_check.rs`: each catalogue template converted to its
  `TcpSendExpect` passes `validate` (AC #3); wire round trip of both
  kinds; an unknown template name and an unknown kind fail to
  deserialize; `{"text":..}` and `{"hex":..}` each decode, both at once
  and neither are refused; hex lowercased on write; every D-2 refusal,
  each at its limit (accepted) and one past it (refused), the limit read
  from the constant; `tls_upstream` with each new kind refused;
  `carries_raw_payload` per kind.
- The reconcile vector test gains the D-5 rows;
  `config_db_upgrade.rs` gains them through the frozen 1.10.6
  statements.
- `evaluate`: prefix match, prefix early mismatch, contains across a
  read boundary, any-of semantics, EOF before match, full buffer; every
  vector fed whole and one byte at a time gives the same verdict, with a
  bound on comparisons.
- `send_expect_probe` against scripted loopback servers: each template
  healthy against its canonical answer (`+PONG\r\n`, `-NOAUTH ...`,
  `220 mail.example.com ESMTP\r\n`, `S`, `N`); `-LOADING` and `554` are
  `no_match`; a silent server is `response_timeout` at the deadline; a
  server that closes is `closed_before_match`; a refused port is
  `connect_failed`; a server sending 1 MiB is decided within
  `PROBE_READ_MAX_BYTES`; a slow match is `Degraded`.
- **IV1, automated**: a fake Redis that answers `+PONG`, then keeps
  accepting and never answers; a store with one backend on
  `tcp_template{redis_ping}` and a 1,000 ms timeout; `run_health_cycle`
  run until the flip: healthy first, `Down` exactly on the
  `HEALTH_FLIP_THRESHOLD`-th failing cycle, one `BackendDown` alert with
  `check = redis_ping` and `reason = response_timeout`, the counter
  incremented once per failing probe.
- On top of Lot 0's race test: a backend switched from a failing
  `tcp_connect` to `tcp_template` between a cycle's listing and its flip
  keeps the template; a row whose `health_check_json` this binary cannot
  parse keeps it, byte for byte, across a status flip.
- Replica and import: a blob or file with an oversized payload is
  refused naming the backend, the store untouched.
- The shape guard green with the new digest; a test-only extra template
  name moves the digest (the guard really watches names).

**Lot 2**

- Every row of the D-7 table (IV2 among them): automation create with a
  payload 403 and nothing stored, with a template 201; dry run with a
  payload 403; weight-only patch on a payload backend 200, payload
  unchanged; masked check read back 200, stored payload kept; changed
  payload 403; masked `send` with a changed `expect` 400; payload to
  template 200; environment backend with `health_check` 422.
- MCP: `lorica_backend_update` with `send` refused by the tool without
  a plane call; `tcp_template` through the in-process binding applied;
  the `template` enum in the tool schema equals the catalogue's names.
- Reads: `backend_row` masks `send` on listings, previews and audit
  reads; `expect` and templates unmasked.
- Management reads by role: `GET /api/v1/backends` and
  `GET /api/v1/backends/{id}` mask `send` for a Viewer session and show
  it to Operator and SuperAdmin; every other Viewer-readable GET the
  grep found masks it too.
- Management writes: an Operator update carrying the masked `send`
  with the rest of the check unchanged keeps the stored payload; a
  masked `send` with a changed `expect` is `400`; the mask is never
  stored.
- Management handler tests: Operator creates each kind; each D-2
  refusal is `400` naming the field; a legacy write of an empty
  `health_check_path` on a `tcp_template` backend leaves the template
  (the deprecated field only speaks of the HTTP path).
- `openapi_contract.rs`: the D-12 assertions; the automation write
  schema has no `tcp_send_expect`; the existing field-name contracts
  green.

**Lot 3**

- The fixture test (stale TS module refused, stale doc section refused).
- The Vitest cases of the Lot.

### Handed to Story 12.12

**An addition to Story 12.12 AC #6's artefact list** (maintainer
decision 6): the official `redis` image, pinned by digest. 12.12 AC #6
names the PostgreSQL, DNS resolver, SSH and TLS echo images and no
Redis; IV1 names Redis. Story 12.12's file must carry it in its
approved list.

IV1 joins Story 12.12's L4 phase as a named scenario: that Redis image
behind a TCP stream, its
backend on `tcp_template{redis_ping}`; `docker pause` on the Redis
container; the backend is `Down` within `HEALTH_FLIP_THRESHOLD` x the
interval plus the timeout, the stream stops selecting it, and
`docker unpause` brings it back. `docker pause` needs no configuration
change, unlike `DEBUG SLEEP`, which Redis 7 disables by default. The
same run records what Redis, Postfix and PostgreSQL log per probe (Dev
Notes, "Backend-side noise"). Story 12.12's file must list this
scenario by name.

## Resolved (maintainer, 2026-11-14)

1. **Redis `-NOAUTH` counts as healthy.** Yes. A Redis with
   `requirepass` or ACLs answers an unauthenticated `PING` with
   `-NOAUTH`, which proves the server is up and speaking its protocol;
   `-LOADING` and `-DENIED` stay down. The `redis_ping` template keeps
   both alternatives (D-4).
2. **Who reads a custom payload.** Not Viewer. The Viewer role's
   contract is "secrets scrubbed" (`Role::Viewer`,
   `lorica-config/src/models/enums.rs`) and a payload can carry an
   `AUTH` or a probe credential, so the management API masks `send` for
   a Viewer as D-8 masks it on the automation plane and MCP, with the
   same restore-on-echo rule on writes. Operator and SuperAdmin see it.
   The docs keep "no credentials in payloads" (D-8, Lot 2, Lot 4).
3. **The catalogue in `lorica-automation-policy`.** Accepted (D-4).
4. **The per-backend interval the loop never reads, and the loop
   writing whole rows from a stale copy.** Both are pre-existing
   defects, present in every Lorica release from `v0.1.2` to `v1.10.6`
   (verified per tag). They ship in this cycle as two `fix(health)`
   commits before Lot 1, as Lot 0, each with a CHANGELOG Fixed entry.
5. **Last failure reason on the backend view.** Out of this story
   (D-10).
6. **A Redis image for Story 12.12.** The official `redis` image, pinned
   by digest, is an addition to Story 12.12 AC #6's artefact list
   ("Handed to Story 12.12").
7. **What `default_health_check_interval_s` means after Lot 0.** Once
   each backend is probed at its own interval the setting paces
   nothing, and it has never been the default its name says: every
   Lorica release from `v0.1.2` to `v1.10.6` creates a backend without
   an interval at a hard-coded 10 s (`unwrap_or(10)` in the management
   create, verified per tag), and the environment resource at its own
   `DEFAULT_HEALTH_CHECK_INTERVAL_S` of 10. It becomes the interval a
   new backend gets when its create names none, on the management
   create, the automation create and the environment resource, in Lot
   0's second commit, whose tests and CHANGELOG entry cover both
   effects. Stored backends keep their interval.

## Open questions for the maintainer

None open.

## Dev Agent Record

### Debug Log

- Lot 0, affected releases re-checked on 2026-11-15 with `git log -S`:
  the whole-row `update_backend(&updated)` writes come from `ac09f95e`
  and `cc1ca5b4`, the hard-coded `unwrap_or(10)` create from `5f2df297`,
  all three contained in every tag `v0.1.2` to `v1.10.6` and never
  removed before Lot 0; `git show v0.1.2:` and `v1.10.6:lorica/src/health.rs`
  read no `health_check_interval_s` (1.10.6 names it in a doc comment
  only).

### Completion Notes

- Lot 0, commit 1: `run_health_cycle` takes the loop's fixed context
  (`HealthLoop`) and its carried state (`HealthLoopState`); Phase 0 and
  Phase C are `close_drained_backends` and `persist_health_flips`, each
  testable with a stale listing. `on_change` and the reload signal still
  fire only when a write succeeded, so a flip of a backend deleted during
  the cycle (`NotFound`) signals nothing.
- Lot 0, commit 2: `run_health_cycle` takes `now`; `take_due` (pure)
  picks the due backends and records their probe start, and
  `HealthLoopState::forget_unlisted` drops the drain, flip and
  last-probe state of a backend gone from the listing. The loop ticks
  with `interval_at(now + 1 s)` and `MissedTickBehavior::Delay`, so the
  first cycle runs one tick after start and a cycle outlasting a tick
  (a probe timing out) is not followed by catch-up cycles. The drain
  pass now runs every tick. `health_check_loop` lost its
  `default_interval_s` parameter, so `spawn_health_check_loop`
  (`lorica/src/startup/mod.rs`) no longer reads the setting.
- Lot 0, commit 2, outside the allowlist, all doc text: the setting's
  doc comments in `lorica-config/src/models/settings.rs`,
  `lorica-config/src/canonical.rs` and `lorica-api/src/settings.rs`,
  its `why` in `lorica-automation-policy/src/settings.rs` (it said "a
  probe budget read on every cycle"), and `openapi.yaml`'s create
  schema, which documented `default: 10`.
- An environment `PUT` replaces the environment's backend rows, so its
  backends take the setting of the latest `PUT`; pinned by the test.
- Lot 0 follow-up (`fix(ui)`): the dashboard's backend form started its
  interval field at 10 (`Backends.svelte`), so a dashboard create always
  named an interval and never got the setting. A create now leaves the
  field empty and omits the interval unless the operator types one, as
  the form already does for name, group and SNI.
- Lot 1, two commits. The first adds the catalogue, the two kinds, the
  validation on every writer and the shape guard, with the new kinds
  probed by TCP connect (the rollback behaviour); the second adds the
  probe, the failure reasons, the counter, the log line and the alert
  details.
- Lot 1, D-3: `evaluate` is a method of a `Matcher` built per probe,
  not a free function of `(expect, read, finished)`. Comparing only the
  new bytes needs to know where the previous call stopped and which
  prefixes already diverged; the matcher holds exactly that and does no
  I/O, so it is as deterministic as the free function. Its comparison
  counter exists in the test build only.
- Lot 1, D-9: `HealthCheck::exchange` returns `None` for a custom payload
  that does not decode (a row no write validated), and `probe_for` then
  probes by TCP connect, so a bad stored payload never marks a backend
  down. The exchange's timeout is clamped to the written bounds, so no
  probe outlives `PROBE_TIMEOUT_MS_MAX` whatever a row says. A deadline
  reached while writing `send` is `send_failed`.
- Lot 1, D-10: the alert keeps its place before the status write, as
  before; the log line is written after the write succeeded, so a flip
  of a backend deleted during the cycle logs nothing.
- Lot 1, D-4: `TcpCheckTemplateName` holds the catalogue entry, compares
  and prints by name. A hex payload is lowercased both when read and when
  written, so a value built in code is stored lowercased too.
- Lot 1, shape guard: `field_names` became a case of `names_refused_with`,
  which also reads an enum's variants and a variant's fields from serde's
  refusals. The lines the inventory already had were checked to hash to
  the previous digest before it moved.
- Lot 1, outside the allowlist: `lorica/Cargo.toml` gains `strum` for
  `ProbeFailure`'s derives (already in the graph through `lorica-config`,
  so `Cargo.lock` gains an edge and no package); `import_to_store` runs
  the same health-check validation as `validate_structure` before
  `clear_all`, as it already re-runs the stream rules, so an
  `ImportData` built without `parse_toml` cannot clear the store and then
  fail; `metrics.rs` gains `backend_health_probe_failures_value`, a
  read-back the health loop's tests need, on the precedent of
  `proxy_protocol_refused_value`.
- Until Lot 2 lands, the automation plane and MCP accept a
  `tcp_send_expect` (the management request structs carry the typed
  check since Story 12.1 Lot 4) and return `send` unmasked. Lot 2 closes
  both; the branch must not ship without it.
- Lot 2, D-7: `ensure_no_new_raw_payload` runs in `backend_guard` on
  the row after the patch, after the grant, through
  `carries_raw_payload` only. `HEALTH_CHECK_PAYLOAD` is a
  `ProtectionRule` of `protections::backend` but not one of
  `BACKEND_PROTECTION_RULES`: that list is "may only be strengthened",
  paired one to one with `BACKEND_PROTECTIONS` and tabulated in
  `docs/mcp.md`, and this rule has no direction. Its own words test sits
  beside the existing one.
- Lot 2, D-8, deviation: `restore_health_check_payload` runs in
  `create_backend_as` and `update_backend_as` themselves, on every plane,
  before the guard's restore; the guard keeps `restore_health_check_path`.
  No `restore_backend_withheld`: the payload restore would otherwise run
  twice on the automation plane for one rule.
- Lot 2, D-8: the mask has one statement,
  `redact::health_check_payload_withheld` (typed, exhaustive match).
  `backend_row` decodes the row's check and applies it, and fails closed
  on a check it cannot decode by masking any `send` key. The management
  plane masks below Operator (`as_read_by`, `Role < Operator`) in
  `list_backends` and `get_backend`, which now take the `Session`; the
  automation listing reads through `list_backends_as(.., Role::Viewer)`
  and masks again (`automation/read.rs`, one line, outside the
  allowlist).
- Lot 2, the D-8 grep of Viewer-readable GETs serializing a backend:
  `GET /api/v1/backends` and `GET /api/v1/backends/{id}` only. Streams
  answer backend ids, `status` counts, the drift and replication reports
  and the audit log sit at the Operator floor, and the config export is
  a POST outside the Viewer floor.
- Lot 2, disclosure: none before this cycle. Payloads were added by Lot
  1 on this branch and never released, so the masking is new-feature
  hardening, not the fix of a shipped disclosure.
- Lot 2, deviation from D-6 and the Lot 2 test list: a D-2 limit or the
  TLS refusal answers 422, not 400. `ConfigError::Validation` maps to
  `Unprocessable` by a deliberate rule (`error.rs`, "a rule the store
  enforces is a request refused on its merits"); the story's "already
  maps to 400" is wrong against the code. Tests and both OpenAPI
  documents say 422.
- Lot 2, D-7 table, one test each: automation create, update and dry run
  `iv2_a_token_sets_a_template_and_never_authors_a_custom_payload`
  (`write/plane_tests.rs`); environments
  `an_environment_backend_takes_no_health_check_and_so_no_payload`;
  MCP Streamable HTTP
  `iv2_on_this_binding_a_payload_is_refused_by_the_tool_and_a_template_is_applied`
  (`mcp/plane_tests.rs`); MCP stdio
  `over_stdio_a_custom_health_check_payload_never_leaves_and_a_template_crosses`
  (`lorica-mcp/src/stdio.rs`, outside the allowlist, the transport's own
  harness) and the tool check
  `a_custom_health_check_payload_is_refused_by_the_tool_naming_it_and_a_template_passes`;
  reads
  `a_custom_payload_reads_masked_on_every_token_read_and_its_answers_and_templates_do_not`;
  admin tier `the_admin_tier_carries_no_health_check_and_so_no_payload`
  (`write/admin_tier_tests.rs`, outside the allowlist); management
  `a_viewer_reads_a_custom_payload_masked_and_an_operator_reads_it_whole`,
  `a_masked_payload_sent_back_by_an_operator_keeps_the_stored_one_and_is_never_stored`,
  `an_operator_creates_every_kind_and_each_check_limit_is_a_422_naming_its_field`;
  import `a_custom_check_exports_and_imports_through_the_management_api`;
  replica: Lot 1's
  `a_replica_with_an_oversized_payload_is_refused_naming_the_backend`
  already applies a valid payload through `prepare_replica`. The
  management tests sit in `backends.rs`'s own test module, where the
  backend handler tests live, not in `src/tests.rs`.
- Lot 2, legacy path: an update sending only `health_check_path: ""`
  leaves a check without a path (template, custom) as stored; on an
  `http` check it still clears to `tcp_connect`
  (`an_empty_legacy_path_speaks_of_the_http_path_only_and_leaves_a_template_alone`).
- Lot 2, MCP: `Nested` gains `withheld` (keys refused by name with the
  policy's reason, before any call) and `choices` (a field's `enum`,
  rendered when the schema is built: `template` from
  `TCP_CHECK_TEMPLATES`). `openapi_contract.rs` pins the `health_check`
  vocabulary against the enum's own serialised fields, every kind sampled
  and held to serde's variant list, with offered and withheld disjoint
  and covering; the automation write schema `AutomationHealthCheck`
  carries no payload kind, its fields are the tier's offered fields, and
  both documents' template enum, timeout bounds and default, `maxItems`
  and decoded-byte limits (`x-max-decoded-bytes`) are the constants'.
- Lot 3: the dashboard's text payload field takes the escapes `\r`,
  `\n`, `\t` and `\\` (a text input cannot hold a CR), and a stored text
  payload is shown escaped, so a payload loaded into the form saves back
  byte for byte, the masked one included; any other byte goes as hex.
  The client mirrors every D-2 limit, the TLS refusal and the timeout
  bounds from the generated module; the server's refusal is shown as it
  comes. Badges: `TCP <template>` and `TCP send/expect`.
- Lot 3: `docs/health-checks.md` is created with its title and the
  marked section only; Lot 4 writes the rest. The fixture test compares
  that section with CRLF folded to LF, since Markdown files check out
  CRLF on a Windows clone and `.gitattributes` (outside the allowlist)
  pins only `*.generated.ts` and the OpenAPI documents to LF.

## File List

- `lorica/src/health.rs` (Lot 0)
- `lorica-config/src/store/backends.rs` (Lot 0)
- `lorica-config/src/tests.rs` (Lot 0)
- `CHANGELOG.md` (Lot 0)
- `lorica/src/startup/mod.rs` (Lot 0)
- `lorica-api/src/backends.rs` (Lot 0)
- `lorica-api/src/automation/environments.rs` (Lot 0)
- `lorica-api/src/tests.rs` (Lot 0)
- `lorica-api/src/automation/environments/tests.rs` (Lot 0)
- `lorica-api/src/settings.rs` (Lot 0, doc comment)
- `lorica-api/openapi.yaml` (Lot 0, create schema)
- `lorica-config/src/models/settings.rs` (Lot 0, doc comment)
- `lorica-config/src/canonical.rs` (Lot 0, doc comment)
- `lorica-automation-policy/src/settings.rs` (Lot 0, `why` text)
- `lorica-dashboard/frontend/src/routes/Backends.svelte` (Lot 0 follow-up)
- `lorica-dashboard/frontend/src/routes/Backends.test.ts` (Lot 0 follow-up)
- `lorica-automation-policy/src/health_templates.rs` (Lot 1, new)
- `lorica-automation-policy/src/lib.rs` (Lot 1)
- `lorica-config/src/models/health_check.rs` (Lot 1)
- `lorica-config/src/models/mod.rs` (Lot 1)
- `lorica-config/src/store/backends.rs` (Lot 1)
- `lorica-config/src/store/replica.rs` (Lot 1, `prepare_replica`)
- `lorica-config/src/import.rs` (Lot 1, `validate_structure` and `import_to_store`)
- `lorica-config/src/canonical.rs` (Lot 1, shape guard tests)
- `lorica-config/src/tests.rs` (Lot 1)
- `lorica-config/tests/config_db_upgrade.rs` (Lot 1)
- `lorica/src/health.rs` (Lot 1)
- `lorica-api/src/metrics.rs` (Lot 1, the counter, its setter and read-back)
- `lorica/Cargo.toml` and `Cargo.lock` (Lot 1, `strum`)
- `lorica-automation-policy/src/protections.rs` (Lot 2)
- `lorica-automation-policy/src/lib.rs` (Lot 2, module doc)
- `lorica-api/src/backends.rs` (Lot 2, Viewer mask, restore, legacy path, tests)
- `lorica-api/src/automation/redact.rs` (Lot 2)
- `lorica-api/src/automation/write.rs` (Lot 2)
- `lorica-api/src/automation/read.rs` (Lot 2, one line, outside the allowlist)
- `lorica-api/src/automation/write/plane_tests.rs` (Lot 2)
- `lorica-api/src/automation/write/admin_tier_tests.rs` (Lot 2, outside the allowlist)
- `lorica-api/src/automation/read/plane_tests.rs` (Lot 2)
- `lorica-api/src/automation/mcp/plane_tests.rs` (Lot 2)
- `lorica-api/src/automation/environments/tests.rs` (Lot 2)
- `lorica-api/openapi.yaml` (Lot 2, backend schemas)
- `lorica-api/openapi-automation.yaml` (Lot 2)
- `lorica-api/tests/openapi_contract.rs` (Lot 2)
- `lorica-mcp/src/tools.rs` (Lot 2)
- `lorica-mcp/src/stdio.rs` (Lot 2, one test, outside the allowlist)
- `lorica-api/tests/health_check_template_fixture.rs` (Lot 3, new)
- `lorica-dashboard/frontend/src/lib/health-check-templates.generated.ts` (Lot 3, new)
- `docs/health-checks.md` (Lot 3, new: title and the marked section)
- `lorica-dashboard/frontend/src/lib/api.ts` (Lot 3)
- `lorica-dashboard/frontend/src/routes/Backends.svelte` (Lot 3)
- `lorica-dashboard/frontend/src/routes/Backends.test.ts` (Lot 3)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD and Story 12.1. Status Draft. | Romain G. |
| 2026-11-14 | 0.2 | Maintainer answers folded in: `-NOAUTH` healthy, `send` masked for Viewer on the management API, catalogue in the policy crate, Lot 0 with the two pre-existing `fix(health)` defects (affected releases verified per tag), last-failure view out, Redis image added to 12.12 AC #6. OQ-7 raised. Status Draft. | Romain G. |
| 2026-11-14 | 0.3 | OQ-7 resolved: `default_health_check_interval_s` becomes the default for new backends in Lot 0's second commit (`backends.rs` and `environments.rs` added to its allowlist, tests and CHANGELOG entry extended). Status Draft. | Romain G. |
| 2026-11-15 | 0.4 | Lot 0 commit 1: the health loop writes the health status and the lifecycle state alone (`set_backend_health_status`, `set_backend_lifecycle_state`), cycle extracted into `run_health_cycle`. Status InProgress. | Romain G. |
| 2026-11-15 | 0.5 | Lot 0 commit 2: each backend probed at its own `health_check_interval_s` on a one-second tick; `default_health_check_interval_s` is the interval of a backend created without one (management, automation, environment). Lot 0 done. Status InProgress. | Romain G. |
| 2026-11-15 | 0.6 | Lot 0 follow-up: the dashboard backend create omits the interval unless typed, so it takes the setting. Status InProgress. | Romain G. |
| 2026-11-15 | 0.7 | Lot 1: template catalogue, `tcp_template` and `tcp_send_expect` validated by every writer, shape guard over kinds and template names, send/expect probe with failure reasons, counter, log line and alert details, IV1 automated. Status InProgress. | Romain G. |
| 2026-11-15 | 0.8 | Lot 2: D9 on every automation and MCP surface (a token never creates or changes a custom payload), `send` masked for tokens and for Viewer with restore on echo, MCP schema offers templates and withholds payload keys, both OpenAPI documents and their contract assertions. Status InProgress. | Romain G. |
| 2026-11-15 | 0.9 | Lot 3: rendered template module and documentation section with their fixture test, dashboard template and send/expect editors with client-side limits. Status InProgress. | Romain G. |
