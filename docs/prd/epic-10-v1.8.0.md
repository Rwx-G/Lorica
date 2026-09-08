# Epic 10: Conditional Request Capture & CI Automation API (v1.8.0)

**Author:** Romain G.
**Target version:** 1.8.0
**Status:** Draft (2026-09-08, written after a prior-art study of Envoy, Caddy, HAProxy, Kong, APISIX, nginx, Traefik and the GitLab Review Apps pattern, and after a code walk of the seams each story reuses)

**Epic Goal:** Two operator needs that today require either a packet sniffer on the box or a human in the dashboard. First, **conditional request capture**: an operator declares "on this route, for this source range, when the response is a 5xx, keep the full request and response for the logs", and Lorica does it with bounded memory, a time limit, and secrets redacted. Second, a **CI automation API**: a GitLab pipeline that has just deployed a review environment creates or updates a Lorica route, its backend and its certificate binding in one authenticated call, gets a public URL back, and tears it down from its `on_stop` job, with Lorica reaping whatever the pipeline forgot.

**The security boundary this epic must not break:** the management API and dashboard stay bound to `127.0.0.1` (NFR9). The automation API is a **separate** listener on a separate port with separate, token-only authentication, off by default and enabled by explicit operator opt-in, exactly like the cluster plane in Epic 9. An operator who does not run CI against Lorica gains no open port. Capture rules are a data-exfiltration primitive by construction (they write request bodies, cookies and bearer tokens to disk or to a remote sink), so every rule carries a hard expiry, redacts credential headers by default, and is SuperAdmin-only to create.

**The security boundary this epic does move, and must document:** `docs/security/threat-model.md` gains a trust boundary and an actor for the automation plane (a CI runner holding a scoped token, which is a machine identity that will leak into pipeline logs sooner or later). `docs/security/hardening-guide.md` gains a firewall stanza for the automation port with a default-deny, allow-runner-subnets-only policy, and a paragraph on capture-rule hygiene.

**Integration Requirements:** All work lands on a single `feat/v1.8.0` branch with one final PR to `main`. Stories 10.1 and 10.2 (capture) are independent of 10.3 to 10.5 (automation); the two tracks can land in either order and 10.1 should land first to de-risk the release. Worker-mode parity is mandatory: capture rules are evaluated inside worker processes and every story must answer "which process does this run in, and how does the state get there". The data plane is sacred: an active capture rule may cost memory on the matched route and nothing else; a capture sink outage, a full capture directory or an automation listener under attack may never block, slow, or fail a proxied request. In a cluster, the automation API runs on the control plane only and mutations flow through the Story 9.4 replication path unchanged. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo audit`, `pnpm lint`, `pnpm tsc --noEmit` and `pnpm exec svelte-check` must stay green at every commit.

**Cross-cutting deliverables** (no single story owns them, all are release-blocking): `lorica-api/openapi.yaml` updated for every new endpoint and kept green against `lorica-api/tests/openapi_contract.rs`; threat model and hardening guide as above; `docs/capture.md` and `docs/automation.md` as user-facing references; `dist/build-deb.sh` and `dist/rpm/lorica.spec` post-install banners mention the automation port when enabled; `CHANGELOG.md` `[Unreleased]` under Added and Security.

---

## Prior Art

What other reverse proxies do, and what Lorica borrows from each. Verified against vendor documentation on 2026-09-08 where a source is cited.

### Conditional request capture

| Product | Mechanism | Body capture | Conditional on | Limits | Verdict |
|---|---|---|---|---|---|
| Envoy | HTTP `tap` filter (static config or `POST /tap` on the admin port) | Request and response, buffered or streamed | `http_request_headers_match`, `http_response_headers_match`, body pattern match, `and`/`or`/`any` | `max_buffered_rx_bytes` / `max_buffered_tx_bytes` (1 KiB default), `truncated` flag, `max_traces`, sinks `file_per_tap`, `streaming_admin`, `buffered_admin`, gRPC | The reference design. Only product that does the full thing |
| Apache httpd | `mod_dumpio` | Everything, into the error log at trace level | Nothing | None | All-or-nothing, unusable on a production vhost |
| nginx | `debug_connection <cidr>` and `access_log ... if=$cond` | No (headers and variables only; body needs OpenResty) | Source CIDR for debug; any variable for access log | None | Good idea for "debug this source range", no body |
| HAProxy | `http-request capture`, `capture request header`, `http-request set-log-level ... if <acl>` | No (sample of a header or expression) | Any ACL, including status via `http-response` | `len` per capture | ACL-driven log verbosity, not a dump |
| Traefik | Access-log filters (`statusCodes`, `retryAttempts`, `minDuration`), header keep/drop | No | Status, duration | None | Filtering, not capture |
| Caddy | `log` with `log_skip` and `log_name`, no body | No | Route | None | Nothing to borrow |
| Kong / APISIX | `http-log` / `file-log` style plugins with optional body | Request and response, capped | Route or service attachment, no status condition | Plugin size caps | Confirms the per-route attachment model |

Sources: Envoy `tap_filter` configuration reference; nginx `ngx_http_core_module` and `ngx_http_log_module`; HAProxy configuration manual section 4; Traefik access-log reference; Caddy `log` directive; Kong `http-log` plugin.

What Lorica borrows: the two-phase predicate model (Envoy evaluates request-side and response-side matchers separately, and a response-side condition implies buffering the request from the start), the byte caps with an explicit truncation flag, the notion of an ephemeral tap that expires on its own, and the file-per-capture sink. What Lorica adds that none of them ship: credential redaction by default, a capture budget per rule, and a rule lifetime. Vocabulary: at L7 Lorica terminates TLS, so "the packet" that is useful to an operator is the decrypted HTTP request and response. A wire-level pcap belongs to the v2.0 L4 proxy, not here.

### CI automation API

| Product | Write API | Addressing and idempotency | Concurrency | Certificate for a new hostname | Auth and exposure | Verdict |
|---|---|---|---|---|---|---|
| Caddy | Admin API on `localhost:2019`: `POST`/`PUT`/`PATCH`/`DELETE /config/<path>` and `/id/<@id>` | `@id` tags on any JSON object | ETag on `GET`, `If-Match` on mutations, 412 on conflict | On-Demand TLS: certificate obtained at first handshake, gated by an `ask` endpoint that returns 200 for allowed hostnames; wildcard needs DNS challenge | Loopback by default, remote admin via mTLS or permissioned unix socket; config persisted to disk, graceful reload, rollback on failure | Closest design. Borrow `@id`, ETag, the `ask` allowlist idea |
| HAProxy Data Plane API | REST CRUD on frontends, backends, servers, certificates | Names | Transactions with a `version` number, commit or abort | Certificate storage API plus `crt-list` | Basic auth or mTLS, own port (5555) | Borrow the transactional, all-or-nothing composite change |
| Kong | Admin API: services, routes, certificates, SNIs | Names or UUIDs, `PUT` upserts by name | None | SNI objects map hostname to certificate, wildcard SNIs allowed | Own port (8001), RBAC in enterprise | Borrow upsert-by-name and wildcard SNI matching |
| APISIX | Admin API: routes, upstreams, SSL objects with `snis` | `PUT /routes/{id}` upserts | None | `snis` on SSL objects, wildcard allowed | `X-API-KEY`, own port (9180), IP allowlist | Same as Kong |
| Traefik | No write API (read-only API). Configuration through providers: Docker labels, Kubernetes, KV stores, file, HTTP provider polling | n/a | n/a | Certificate resolvers, `domains` per router | n/a | Nothing to borrow; the provider model is out of scope per `COMPARISON.md` |
| nginx OSS / Plus | OSS: none (reload). Plus: `/api/<v>/http/upstreams/.../servers` for upstream membership only | n/a | n/a | n/a | n/a | Nothing to borrow |
| Envoy | xDS from a control plane, not a REST API | n/a | Versioned resources | SDS | mTLS to the control plane | Confirms "the control plane owns the config" |
| GitLab Review Apps (reference pattern) | Kubernetes Ingress per environment, wildcard certificate from cert-manager | `CI_ENVIRONMENT_SLUG` as the hostname label | n/a | Wildcard `*.review.example.com` issued once via DNS-01 | `environment.url`, `on_stop` job, `auto_stop_in` | The workflow Lorica must plug into |

Sources: Caddy API reference and "Automatic HTTPS" (On-Demand TLS section); HAProxy Data Plane API reference; Kong Admin API reference; APISIX Admin API reference; Traefik providers overview; GitLab "Environments and deployments" and "ID token authentication".

GitLab-side facts that shape the design: `CI_ENVIRONMENT_SLUG` is already RFC 1123-safe and at most 24 characters; `environment.url` can be set statically or from a `dotenv` artifact; `auto_stop_in` triggers the `on_stop` job on a timer but only if the runner and the branch still exist; `id_tokens:` issues a per-job OIDC JWT (RS256, issuer = the GitLab instance URL, JWKS at `/oauth/discovery/keys`, lifetime = job timeout or 5 minutes) with claims `project_path`, `namespace_path`, `ref`, `ref_protected`, `environment`, `environment_protected`, `pipeline_id`, `job_id`, `user_login`, and an `aud` chosen in the job. HashiCorp Vault consumes exactly that token with `bound_claims`, which is the model for Story 10.5.

What Lorica borrows: a composite resource addressed by name with upsert semantics (Caddy `@id`, Kong `PUT` by name), atomic apply of backend + route + certificate binding (HAProxy transactions), certificate resolution by hostname against existing wildcard certificates (Kong and APISIX SNI objects, Caddy's `ask` endpoint reinterpreted as a per-token hostname allowlist), and a lifetime on the resource as a safety net under GitLab's `auto_stop_in`. What Lorica refuses: on-demand ACME issuance per environment. A review environment appears and disappears in minutes, Let's Encrypt rate-limits per registered domain, and a held TLS handshake on first connection is a bad first impression for a reviewer. A wildcard certificate issued once through the existing DNS-01 path covers every environment.

---

## Story 10.1: Capture Rules, Two-Phase Matching and Budgets

As an operator debugging an intermittent backend failure,
I want to declare a rule that keeps the full request and response for a subset of traffic on one route,
so that the next 502 from the internal network shows me exactly what was sent, without a packet sniffer and without dumping the whole route.

### Acceptance Criteria

1. **Model and storage.** New `CaptureRule` in `lorica-config` with its own migration and CRUD in the store: `id`, `name`, `route_id` (mandatory, foreign key), `enabled`, `match` (request-side predicates), `emit` (response-side predicates), `capture` (what to keep and how much), `limits`, `output`, `created_by`, `created_at`, `expires_at`, counters `captures_emitted`, `captures_dropped`. Rules replicate to followers through the Story 9.4 allowlist; `expires_at` is absolute UTC so every node agrees.
2. **Request-side predicates (phase 1, evaluated once at `request_filter`)** decide whether this request is a capture candidate and therefore whether its body is buffered: `source_cidrs` (list, `ipnet` via the same parser as `ConnectionFilterPolicy::from_cidrs`, `lorica/src/connection_filter.rs:57`, evaluated against the same client IP the access log uses, XFF-aware), `methods`, `path_prefix`, `path_regex`, `headers` (name plus `HeaderMatchType::{Exact,Prefix,Regex}` reused from `Route`). An empty predicate set matches every request on the route. `route_id` is not optional: a rule always names one route, so the buffering cost is bounded to that route's traffic times the CIDR filter.
3. **Response-side predicates (phase 2, evaluated at `logging`)** decide whether a buffered candidate is emitted or discarded: `status` (list of exact codes or classes `4xx` / `5xx`, plus `499` for client-aborted), `min_latency_ms`, `upstream_error` (connect refused, timeout, TLS failure, no healthy backend). Predicates inside `emit` are ORed; `match` and `emit` are ANDed. An empty `emit` emits every candidate, which the API accepts only with an explicit `"emit": {"always": true}` so that a forgotten condition is not a silent full dump.
4. **Body buffering reuses the existing seams, with the mirror overflow stance.** Request body accumulates in `request_body_filter` (`lorica/src/proxy_wiring.rs:974`) into a capture buffer distinct from `ctx.waf_body_buffer` (`proxy_wiring/context.rs:89`), because the WAF buffer is released before the response exists. Response body accumulates in `response_body_filter` (`proxy_wiring.rs:2160`). Both stop at `request_body_max_bytes` / `response_body_max_bytes` (default 64 KiB, hard cap 4 MiB) and flip to an `Overflowed` state exactly like `mirror_rewrite.rs:352-374`: the bytes kept so far are retained, the flag `truncated: true` is set, and the stream continues untouched. Streaming content types listed in `STREAM_CONTENT_TYPE_PREFIXES` are never buffered on the response side; the record says `body_skipped: "streaming"`. Buffering never copies more than once and never holds the body past the `logging` callback.
5. **Budgets are mandatory and enforced per rule.** `max_captures` (default 100, hard cap 10 000), `rate_per_minute` (default 10, sliding window), `ttl` (default 1 h, hard cap 7 days) which the API materialises into `expires_at` at creation. Reaching `max_captures` or `expires_at` flips `enabled = false` on the rule and audits it; the rule is never deleted automatically so the operator sees what happened. Counters and the rate window are per process; in worker mode the documented semantics are "per worker" and `docs/capture.md` says so, with the absolute `expires_at` as the fleet-consistent bound.
6. **Memory ceiling per node.** A global `capture_max_inflight_bytes` (default 64 MiB) across all rules and all in-flight candidates. When exceeded, new candidates are not buffered, the record is emitted with `body_skipped: "budget"` if the response-side predicate matches, and `lorica_captures_total{outcome="dropped_budget"}` increments. A capture rule may never turn into a memory-exhaustion primitive on a node that also terminates production TLS.
7. **Hot reload.** Rules live in the `ProxyConfig` snapshot behind the existing `ArcSwap` and are compiled (regexes, CIDR sets) at snapshot build time, never per request. Regex size and compile budgets reuse the WAF custom-rule caps (`lorica-waf/src/engine/custom_rules.rs`).
8. **API.** `GET /api/v1/capture/rules` (Operator+), `POST /api/v1/capture/rules` (SuperAdmin), `GET|PUT|DELETE /api/v1/capture/rules/{id}` (SuperAdmin), `POST /api/v1/capture/rules/{id}/disable` (Operator+, so an on-call operator can stop a capture without being able to start one). `POST` returns 422 with a field-level error on an unbounded rule (no `route_id`, `emit.always` without acknowledgement, caps above the hard limits).
9. Prometheus: `lorica_capture_rules_active`, `lorica_captures_total{rule_id, outcome=emitted|dropped_rate|dropped_budget|dropped_sink}`, `lorica_capture_inflight_bytes`.

### Integration Verification

- IV1: A rule with `source_cidrs = ["172.30.0.0/16"]`, `status = ["5xx"]` on route R, against a backend that returns 200 for `/ok` and 502 for `/fail`: requests from `172.30.1.10` to `/fail` produce exactly one record each with the full request body, requests to `/ok` produce none and hold no buffer past `logging`, and requests from `10.0.0.5` to `/fail` produce none and are never buffered.
- IV2: A 10 MiB request body against a 64 KiB cap emits a record with `truncated: true`, 65 536 body bytes, and the upstream receives all 10 MiB unchanged; p99 on the unmatched sibling route is unchanged with the rule active.
- IV3: A rule with `max_captures = 3` disables itself after the third emission and audits; a rule with `ttl = "2m"` disables itself after two minutes on a control plane and on a follower within one heartbeat of each other.

---

## Story 10.2: Capture Records, Redaction, Sinks and Dashboard

As a security-conscious operator,
I want captured traffic to leave the proxy in a stable, redacted, structured format,
so that I can ship it to the SIEM that already receives the access log without leaking credentials into it.

### Acceptance Criteria

1. **Record format.** One JSON document per capture, `kind = "capture"`, carrying `rule_id`, `rule_name`, `route_id`, `request_id` (same value as the access-log row so the two join), `timestamp`, `client_ip`, `is_xff`, `backend`, `latency_ms`, `error`, then `request { method, uri, version, headers[], body, body_encoding, body_bytes_total, truncated, body_skipped }` and `response { status, headers[], body, body_encoding, body_bytes_total, truncated, body_skipped }`. `body_encoding` is `utf8` when the content type is textual and the bytes are valid UTF-8, `base64` otherwise (Envoy's `as_string` / `as_bytes` split). Headers are an ordered list of pairs, not a map, so duplicates survive.
2. **Redaction by default.** `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and any header named in `redact_headers` are replaced by `<redacted:N bytes>`. Query-string parameters named in `redact_query` are masked the same way. Redaction cannot be disabled through the API; a rule may only extend the list. Body redaction is out of scope and documented as such (the body is the thing the operator asked to see).
3. **Sinks.** `SinkKind` (`lorica-api/src/log_sinks/mod.rs:47`) gains `Capture`, with the same per-kind toggles as `access` / `waf` / `audit` on syslog and OTLP logs (this also closes backlog item 50 for the new kind). The default output is the structured stdout / rolling-file log through the existing `tracing` layer at target `lorica::capture`. An optional `output.dir` writes one file per capture (`<timestamp>-<request_id>.json`, `0640`, owner `lorica`) under a directory that must already exist and be writable, with a per-rule `max_dir_bytes` and oldest-first pruning. Captures never enter the SQLite access-log database; a 64 KiB body per row would blow the bounded writer's memory model (`log_writer.rs`, 8192 rows).
4. **Sink failure never touches the request.** A full directory, a slow syslog collector or a closed OTLP exporter increments `lorica_captures_total{outcome="dropped_sink"}` and drops the record. Same stance as Story 9.8.
5. **Dashboard.** A new "Capture" page under Observability: rule list with live counters, remaining budget and time to expiry; a create form that refuses to submit without a route, a status or latency condition (or the explicit "always" acknowledgement), and shows the resulting `expires_at`; a "Recent captures" panel fed by a bounded in-memory ring (last 50 records, bodies elided past 4 KiB) with a download button for the full record while it is still in the ring. Role gating mirrors the API.
6. **Audit.** Rule creation, update, manual disable, auto-disable (budget or expiry) and deletion are audited with the operator identity, the route, and the effective predicates.
7. Documentation: `docs/capture.md` with the two-phase model, the caps, the worker-mode semantics, a SIEM example, and a "why the rule expired" troubleshooting section.

### Integration Verification

- IV1: A captured request carrying `Authorization: Bearer x` and `Cookie: s=y` produces a record where both values are `<redacted:...>` on stdout, in the syslog collector and in the OTLP collector, and the collector-side record joins the access-log row on `request_id`.
- IV2: With `output.dir` on a read-only mount, requests keep flowing with zero 5xx and the drop counter increments.
- IV3: A binary `application/octet-stream` body round-trips through `base64` and decodes byte-for-byte to the original.

---

## Story 10.3: Automation Listener and Scoped API Tokens

As a platform engineer,
I want a network-reachable, token-authenticated API surface that a CI runner can call,
so that pipelines can configure Lorica without the management port ever leaving loopback.

### Acceptance Criteria

1. **A separate listener, off by default.** `--automation-listen <host:port>` (and the matching `[automation]` settings block) starts a second axum server with its own TLS config (reusing `lorica-api/src/management_tls.rs`), its own router, and none of the session middleware. Per the Story 9.2 AC #11 precedent: a bare port is refused, `0.0.0.0` and `::` are refused without an explicit `--automation-listen-any` flag, a bind equal to the management or cluster port is refused, and the effective address is logged at WARN on startup. Hot upgrade (`hot_upgrade.rs`) hands the listener off with the others.
2. **Cluster placement.** The listener runs on a standalone node or on the control plane. A follower started with `--automation-listen` refuses to start with a message naming the control plane, because a follower's config is replaced on the next replication and any automation write there would be silently lost.
3. **Source allowlist at the listener.** `automation_allowed_cidrs` (mandatory, non-empty when the listener is enabled) evaluated with `ConnectionFilterPolicy` before the TLS handshake; a connection from outside the allowlist is closed with no bytes read. Listener-level connection caps and a sliding-window per-IP limiter as in Story 9.3 AC #11; the loopback-scale axum limiter is not sufficient here.
4. **Scoped API tokens.** New `api_tokens` table and `AutomationToken` model. Token shape `<public_id>.<secret>` (Story 9.3 AC #1): the secret is 256 bits of generated entropy, shown once at creation, stored as HMAC-SHA256 under the server-side key, verified in constant time with identical timing whether `public_id` exists or not. Fields: `name`, `scopes`, `allowed_hostnames` (list of exact hostnames or single-label wildcards, matched with `pattern_matches` / `specificity` from `lorica-config/src/models/cert_export_acl.rs:52-72`), `allowed_backend_cidrs` (where an environment's backends may point), `max_ttl` (cap on any environment lifetime this token can request, default 7 days), `expires_at` (token lifetime, default 1 year, mandatory), `last_used_at`, `revoked_at`.
5. **Scopes** are a closed enum: `environments:write` (create, update, delete environments), `environments:read`, `routes:read`, `certificates:read`. There is deliberately no `routes:write`, no `certificates:write`, and no `settings:*` in 1.8.0: the automation surface is the environment resource, not the whole management API behind a different door.
6. **Token administration is management-API only.** `GET|POST /api/v1/automation/tokens`, `DELETE /api/v1/automation/tokens/{public_id}` (revoke), all SuperAdmin, all audited, plus a dashboard sub-page under Settings. Tokens are never creatable through the automation listener itself. Revocation is immediate: in-flight requests holding a revoked token fail on their next authorisation check.
7. **Automation requests are authenticated by `Authorization: Bearer <token>` only.** No cookies, no CSRF exemption needed because there is no ambient credential. Every request is audited with `token public_id`, `token name`, source IP, method, path and outcome, and `lorica_automation_requests_total{outcome}` increments.
8. **The token never appears in argv or logs.** The CLI helper `lorica automation token create` prints the token once to stdout and nothing else; server-side logs record the `public_id` only; the OpenAPI document marks the scheme `bearerAuth` with a description pointing to GitLab masked variables.

### Integration Verification

- IV1: A request to the automation port from outside `automation_allowed_cidrs` is closed before the TLS handshake completes; one from inside with no token gets 401 with `WWW-Authenticate: Bearer realm="lorica-automation"`; one with a revoked token gets 401 and an audit row.
- IV2: A session cookie from the dashboard presented to the automation port is ignored (401), and a valid automation token presented to the management port is ignored (401), proving the two planes share no credential.
- IV3: A follower started with `--automation-listen` exits non-zero with the documented message; the control plane in the `cluster` e2e profile serves it and the resulting environment replicates to both followers.

---

## Story 10.4: The Environment Resource

As a GitLab pipeline,
I want one idempotent call that makes `https://<slug>.review.example.com` reach the container I just started,
so that the review URL works before the job ends, survives a re-run, and disappears when the environment is stopped.

### Acceptance Criteria

1. **Composite resource, upsert by name.** `PUT /automation/v1/environments/{name}` creates or replaces an environment in one transaction: `name` (RFC 1123 label, 1 to 63 characters, the natural value is `CI_ENVIRONMENT_SLUG`), `hostname` (must match one of the token's `allowed_hostnames`), `backends[]` (`address`, optional `tls_upstream`, `tls_sni`, `weight`; every address must fall inside `allowed_backend_cidrs`), `certificate` (`"auto"` or an explicit certificate id the token can read), `waf_enabled`, `force_https`, `path_prefix` (default `/`), `ttl` (duration, capped by the token's `max_ttl`), `labels` (string map, at most 16 entries, keys and values at most 128 bytes). Anything else is 422 with `deny_unknown_fields`.
2. **What the transaction writes.** A `Route` row, one `Backend` row per entry (exclusively owned, `group_name = automation:<name>`), the `RouteBackend` joins, and one `automation_environments` row (`name`, `route_id`, `token_public_id`, `certificate_mode`, `labels`, `expires_at`, `created_at`, `updated_at`, `last_pipeline`). On update the backend set is replaced, the route is updated in place (same `route_id`, so dashboards and metrics keep continuity), and `expires_at` is recomputed from now. All or nothing: a failed certificate resolution rolls back the backend rows (HAProxy transaction semantics).
3. **Hostname rules.** The hostname must match the token allowlist, must not collide with any existing route hostname or alias that this environment does not already own (409, naming the conflict without revealing the owning route's details), and must not be the management or automation listener host. Wildcard aliases are not accepted on environments.
4. **`certificate: "auto"` resolves against existing certificates only.** Lorica picks the certificate whose `domain` or a `san_domains` entry covers the hostname, exact match preferred over single-label wildcard (`*.review.example.com` covers `mr-42.review.example.com`, not `a.b.review.example.com`), then the latest `not_after`. No match is 422 `no_certificate_covers_hostname` with the list of wildcard patterns the operator could provision; the error text points at the DNS-01 provisioning endpoint. `certificate_mode = auto` is persisted and re-resolved at every config snapshot build, so replacing the wildcard certificate with a new id (rather than renewing in place) moves the environments over without a pipeline re-run. The route row itself keeps an explicit `certificate_id` (`lorica/src/proxy_wiring/config.rs:376-379` stays untouched); the resolver at the TLS layer (`lorica-tls/src/cert_resolver.rs:325-338`) already handles the wildcard fallback at handshake.
5. **Response.** 201 on create, 200 on update, body `{ name, url, route_id, backend_ids[], certificate_id, certificate_not_after, expires_at, applied_generation }`. `url` is `https://<hostname><path_prefix>` and is what the pipeline writes into `environment.url` (or a `dotenv` artifact). `applied_generation` lets a strict pipeline poll `GET /automation/v1/environments/{name}` until every cluster node reports it, using the Story 9.4 per-node applied generation.
6. **Read and delete.** `GET /automation/v1/environments` (filter by `label`, `hostname`, `expiring_before`), `GET /automation/v1/environments/{name}`, `DELETE /automation/v1/environments/{name}` (204, idempotent, 404 only if never existed). Delete removes the route, the owned backends and the joins in one transaction. A token may only read, update or delete environments created by a token with the same `name` prefix or an explicit `shared` label, so two projects sharing a Lorica do not step on each other.
7. **Reaper.** A background task on the standalone node or control plane sweeps every minute and deletes environments past `expires_at`, auditing each as `automation.environment.expired`. This is the safety net under GitLab's `auto_stop_in`; `docs/automation.md` recommends `ttl` strictly greater than `auto_stop_in` so GitLab stays in charge of the lifecycle and Lorica only cleans up orphans.
8. **Ownership is visible.** Routes and backends created this way carry `managed_by = "automation"` and the environment name; the dashboard shows a badge, allows read and delete (delete goes through the same transaction), and refuses in-place edits with a hint to update through the pipeline, so a manual fix is not silently overwritten by the next `PUT`.
9. **Concurrency.** Two pipelines racing on the same `name` serialise on the environment row; the later `PUT` wins in full (last writer wins is acceptable for a resource whose whole payload is regenerated by the pipeline). `If-Match` with the `ETag` returned by `GET` is supported for pipelines that want a 412 instead.
10. Prometheus: `lorica_automation_environments{state=active|expired}`, `lorica_automation_environment_ops_total{op, outcome}`, `lorica_automation_reaper_runs_total`.

### Integration Verification

- IV1: `PUT` with a hostname covered by a pre-provisioned `*.review.example.com` certificate returns 201 with that certificate id; an immediate `curl --resolve` through the proxy reaches the backend over TLS with a chain that validates for the hostname; a second identical `PUT` returns 200 with the same `route_id`; a `PUT` with a new backend address moves traffic without a 5xx in between.
- IV2: `PUT` with a hostname outside the token allowlist, a backend outside `allowed_backend_cidrs`, a `ttl` above `max_ttl`, or a hostname already owned by a manual route each return the documented 4xx and leave zero rows behind.
- IV3: An environment with `ttl = "90s"` is gone from the config, the route table and the TLS resolver within 150 s with an audit row; a `DELETE` from the pipeline removes it immediately and a second `DELETE` returns 204.

---

## Story 10.5: GitLab OIDC ID Tokens (Optional Authentication Mode)

As a GitLab administrator,
I want pipelines to authenticate to Lorica with the job's own ID token instead of a long-lived shared secret,
so that no Lorica credential has to live in CI variables at all and the authorisation is bound to the project and environment that the job actually runs for.

**Dependency note:** this story needs a JWT library. `jsonwebtoken` is the candidate; it is **not** in the workspace today and requires explicit approval before the story starts (no new dependency without approval). If refused, the story is deferred and Story 10.3 tokens remain the only mode, which is a complete and shippable outcome for 1.8.0.

### Acceptance Criteria

1. **Trust configuration on the management API.** `POST /api/v1/automation/oidc-issuers` (SuperAdmin): `issuer` (the GitLab instance URL, must be `https`), `audience` (the value the job puts in `id_tokens.<NAME>.aud`, unique per Lorica instance), `jwks_url` (defaults to `<issuer>/oauth/discovery/keys`), `bound_claims` (exact-match map over `project_path`, `namespace_path`, `ref_protected`, `environment_protected`, `deployment_tier`, with glob support on `project_path` only), and the same `allowed_hostnames`, `allowed_backend_cidrs`, `max_ttl` and `scopes` as a static token. One issuer entry is one authorisation policy; several entries may share an issuer with different bound claims.
2. **Verification.** RS256 only; `iss`, `aud`, `exp`, `nbf` and `iat` checked with 60 s of skew; `kid` looked up in a JWKS cache refreshed every 6 hours and on unknown `kid` at most once per minute (the fetch goes through the existing `reqwest` client with the same TLS roots as ACME); every `bound_claims` entry must match exactly. Any failure is 401 with a generic reason on the wire and the precise reason in the audit row.
3. **The token's claims become the environment's identity.** `project_path`, `ref`, `pipeline_id`, `job_id` and `user_login` are recorded on the environment row and in the audit trail; the ownership rule from Story 10.4 AC #6 is enforced on `project_path` instead of the token name. A token bound to `environment_protected = true` cannot create an environment whose `name` does not equal the job's `environment` claim slug.
4. **Replay resistance.** `jti` is remembered until `exp` (a bounded in-memory set, 5 minutes is the typical lifetime); a replayed token is 401 and audited.
5. **Documentation.** `docs/automation.md` gains the GitLab job snippet (`id_tokens:` with `aud`), the issuer registration walk-through, and a comparison table "static token vs ID token" so an operator picks the mode deliberately.

### Integration Verification

- IV1: A token minted by a local OIDC fixture (the e2e profile ships a tiny issuer serving a JWKS) with matching bound claims creates an environment; the same token with `project_path` changed, with `aud` changed, expired, or presented twice is refused each time with a distinct audit reason.
- IV2: Rotating the fixture's signing key is picked up on the next unknown-`kid` refresh without a restart, and a JWKS endpoint outage keeps already-cached keys working until their refresh interval elapses, then fails closed.
- IV3: Removing the issuer entry on the management API makes the next ID-token request 401 immediately.

---

## Worked Example

The pipeline this epic is designed around. `LORICA_CI_TOKEN` is a masked, protected GitLab variable holding a Story 10.3 token whose scope is `environments:write`, `allowed_hostnames = ["*.review.example.com"]`, `allowed_backend_cidrs = ["10.0.0.0/16"]`, `max_ttl = "7d"`.

```yaml
deploy_review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://$CI_ENVIRONMENT_SLUG.review.example.com
    on_stop: stop_review
    auto_stop_in: 3 days
  script:
    - |
      curl -fsS -X PUT "https://lorica.internal.example.org:9444/automation/v1/environments/$CI_ENVIRONMENT_SLUG" \
        -H "Authorization: Bearer $LORICA_CI_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"hostname\":\"$CI_ENVIRONMENT_SLUG.review.example.com\",
             \"backends\":[{\"address\":\"10.0.0.10:8080\"}],
             \"certificate\":\"auto\",
             \"waf_enabled\":true,
             \"ttl\":\"4d\",
             \"labels\":{\"project\":\"$CI_PROJECT_PATH\",\"ref\":\"$CI_COMMIT_REF_SLUG\",\"pipeline\":\"$CI_PIPELINE_ID\"}}"

stop_review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    action: stop
  when: manual
  script:
    - curl -fsS -X DELETE "https://lorica.internal.example.org:9444/automation/v1/environments/$CI_ENVIRONMENT_SLUG" -H "Authorization: Bearer $LORICA_CI_TOKEN"
```

`ttl` (4 days) is deliberately longer than `auto_stop_in` (3 days): GitLab stops the environment first in the normal case, and Lorica's reaper only ever removes what GitLab could not.

And the capture rule from the original request, as the API accepts it:

```json
{
  "name": "api-5xx-from-lan",
  "route_id": "6f1c…",
  "match":   { "source_cidrs": ["172.30.0.0/16"] },
  "emit":    { "status": ["5xx"], "upstream_error": true },
  "capture": { "request_body_max_bytes": 65536, "response_body_max_bytes": 65536,
               "redact_headers": ["x-internal-token"] },
  "limits":  { "max_captures": 200, "rate_per_minute": 10, "ttl": "2h" },
  "output":  { "sink": "log" }
}
```

---

## End-to-End Test Topology

Two new `tests-e2e-docker` profiles, each costing the seven touchpoints documented in Epic 9 (compose service, runner service, volumes, entrypoint, Dockerfile COPY, runner script, `run.sh` phase plus `ALL_PROFILES` entry):

- **`capture`** and **`capture-workers`**: one node, the existing `backend` fixture extended with a `/fail` handler returning 502 and a `/slow` handler, the syslog and OTLP collectors from `log-sinks` reused for sink assertions. Covers Stories 10.1 and 10.2. The workers variant exists because body buffering and the per-worker budget semantics are precisely the kind of thing that passes in single-process mode and breaks in a worker.
- **`automation`**: the Story 9 `cluster` topology (control plane plus two followers) with a pre-provisioned wildcard certificate from the Pebble fixture via the mock DNS provider, a "fake CI" runner script performing the `PUT` / `GET` / `DELETE` sequence with `curl --resolve` through each node, and a tiny OIDC issuer fixture for Story 10.5. Covers Stories 10.3 to 10.5 and the replication of automation-created environments.

---

## Out of Scope (deferred)

- **Wire-level packet capture (pcap).** Meaningless behind TLS termination and belongs to the v2.0 L4 proxy.
- **Body redaction** (masking JSON fields or form values inside captured bodies). The body is what the operator asked to see; masking it correctly needs a content-aware parser per media type.
- **Streaming taps** (Envoy `HttpStreamedTraceSegment`). Buffered-with-cap covers the debugging use case; a streaming tap is a live-tailing feature with its own UI and is a separate epic if ever needed.
- **On-demand ACME issuance per environment** (Caddy On-Demand TLS). Refused by design, see Prior Art.
- **A general-purpose write API for routes, backends, certificates and settings on the automation listener.** The 1.8.0 surface is the environment resource. Widening it is a deliberate future decision, not a scope creep here.
- **GitHub Actions and Jenkins OIDC issuers.** Story 10.5 is written against GitLab's claim set; the verifier is generic enough that adding an issuer profile later is small, but it is not tested in this cycle.
- **Kubernetes Ingress, service discovery, external configuration providers.** Out of scope by design per `COMPARISON.md`, unchanged from Epic 9.
- **Control-plane high availability.** Carried over from Epic 9; the automation listener inherits the same "no writes while the control plane is down" failure mode, and `docs/automation.md` says so.
