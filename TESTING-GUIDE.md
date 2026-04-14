# Testing Guide - v1.2.0 and v1.3.0

Author: Romain G.

Hands-on walkthrough of the features shipped in the last two releases,
with concrete click-paths from the dashboard and quick `curl` checks to
prove each feature is wired up.

## v1.2.0 - Cache, load balancing, robustness

| Feature | Where to find it |
|---|---|
| Cache lock (thundering herd protection) + stale-while-error 60 s | Caching tab |
| Cache PURGE method to invalidate a cached URL | `PURGE` HTTP method on the URL |
| gRPC-Web to gRPC/HTTP-2 bridge | automatic on gRPC routes |
| Least Connections load balancing algorithm | Route > LB algorithm |
| HTTP Basic Auth per route (Argon2id) | Security tab |
| Maintenance mode (503 + `Retry-After` + custom HTML) | Route tab |
| Custom error pages (502/504 with `{{status}}`/`{{message}}`) | Route tab |
| Retry filtered by HTTP method (GET/HEAD only, never POST) | Route tab |
| JSON/text logs, file output | `--log-format`, `--log-file` CLI |
| Automatic OCSP stapling | transparent |
| Per-route `stale_while_revalidate_s` and `stale_if_error_s` | Caching tab |

## v1.3.0 - 10 new features + scoped breaker

| Feature | Where to find it |
|---|---|
| Connection pre-filter (IP allow/deny at TCP accept, before TLS) | **Settings** tab |
| Cache predictor (short-circuits repeated uncacheable responses) | automatic |
| Cache Vary by request headers (Accept-Encoding / Language) | **Caching** tab |
| Header-based routing (Exact / Prefix / Regex -> backend group) | **Header Rules** tab |
| Canary traffic split (sticky per client IP) | **Canary** tab |
| Forward auth (Authelia, Authentik, Keycloak, oauth2-proxy) | **Security** tab |
| Request mirroring (shadow testing, POST/PUT body forwarded) | **Security** tab |
| Stale-while-revalidate background refresh | active when `stale_while_revalidate_s > 0` |
| Response body rewriting (Nginx `sub_filter` equivalent) | **Rewrite** tab |
| mTLS client verification (CA bundle + `O=` allowlist) | **Security** tab |
| Prometheus counters per feature | `GET /metrics` |
| Validate endpoints (PEM parse, forward-auth test connection) | inline buttons in Security tab |
| **Circuit breaker scoped per (route, backend)** | transparent, clearer log field |

## Hands-on tests

### 1. Header routing (safe, 2 min)

1. Open any route (for example `gitlab.rwx-g.fr`) > **Header Rules** tab.
2. Add a rule: `X-Version: beta` -> backend group B.
3. Save.

```bash
curl -H 'X-Version: beta' https://gitlab.rwx-g.fr/...   # -> backend B
curl https://gitlab.rwx-g.fr/...                        # -> default backends
```

Check `lorica_header_rule_match_total{rule_index="..."}` in `/metrics`.

### 2. Canary 5% traffic split (safe)

1. On a stable route, open the **Canary** tab.
2. Send 5% to an alternate backend group.

From two distinct client IPs: one stays on the primary, the other may
land in the canary bucket (sticky per IP). Watch
`lorica_canary_split_selected_total{split_name="..."}` to see the
distribution.

### 3. Response rewrite (very visible, safe)

1. On a test route pointing at a simple HTML page, open the **Rewrite**
   tab.
2. Add a rule: replace `Hello` with `Bonjour`.
3. Reload the page.

The text changes on the wire. Works across chunked transfer encoding.
`Content-Length` is dropped from the response (rewritten size differs
from origin). `Content-Encoding: gzip` responses stream through
unchanged.

### 4. Forward auth (more ambitious)

1. Deploy Authelia or any endpoint that returns 200/401 based on a
   cookie.
2. Security tab > set the Forward auth URL > click **Test connection**
   (hits the new `POST /api/v1/validate/forward-auth` endpoint).
3. Enable on a test route with `verdict_cache_ttl_ms = 5000`.

```bash
curl -v https://test.example/secret                 # -> 401 or 3xx to the auth login
curl -v --cookie 'session=...' https://test.example/secret   # -> 200 with upstream body,
                                                             #    Remote-User header forwarded
```

`lorica_forward_auth_cache_total{outcome="hit"}` grows on repeated
requests within the TTL.

### 5. Mirroring (observe without impact)

1. Route with `mirror.backends = [shadow.example]`,
   `sample_percent = 100`.

Send real traffic, confirm the primary is not affected and the shadow
receives the same requests carrying `X-Lorica-Mirror: 1`.
`lorica_mirror_outcome_total{outcome="spawned"}` climbs.

### 6. Cache Vary (anti cache poisoning)

1. Route with caching enabled and `cache_vary_headers=["Accept-Encoding"]`.

```bash
curl -H 'Accept-Encoding: identity' https://...   # entry A
curl -H 'Accept-Encoding: gzip'     https://...   # entry B, distinct
```

The second curl does not get the gzipped body served to an
`identity`-only client.

### 7. mTLS (client certificate required)

1. Security tab > paste a CA PEM > click **Validate PEM**. The server
   lists the per-cert subjects so you can confirm the bundle before
   saving.
2. Save with `required = true` and optionally
   `allowed_organizations = ["MyOrg"]`.

```bash
curl https://protected.example/                                     # -> 496 (no cert)
curl --cert wrong-org.pem --key wrong-org.key https://...           # -> 495 (O= not allowed)
curl --cert myorg.pem     --key myorg.key     https://...           # -> 200
```

Note: changing `ca_cert_pem` requires a restart (rustls `ServerConfig`
is immutable after build). Toggling `required` and editing the
organization allowlist hot-reload.

### 8. Connection pre-filter (network layer, fast feedback)

1. Settings tab > add a scanner IP to `connection_deny_cidrs`.
2. The connection is refused at TCP accept, before the TLS handshake.
   You will see zero `Downstream handshake error` for that IP in the
   logs - the CPU cost of the handshake is avoided.

### 9. Scoped circuit breaker (already validated in production)

Two routes on the same backend IP:port (typical when one Teleport
front-door serves several virtual hosts): failures on one route no
longer punish the other. Confirmed on svl15lorica with
`lorica.bastion.rwx-g.fr` and `bastion.rwx-g.fr` both behind
`192.168.15.254:3080`.

---

## v1.3.0 - Worker-parity (WPAR) tests

All the v1.3.0 cross-worker behaviour is active **only under
`--workers N >= 1`**. Start Lorica with e.g. `lorica --workers 2` (or
configure `Workers=2` in the systemd unit / `--workers 2` on the deb
init). In single-process mode (`--workers 0`) every feature below
stays on its per-process fallback path, so to validate the WPAR
work you must run workers.

### 10. Per-route token-bucket rate limit (cross-worker)

1. Route > **Protection** tab > set `rate_limit`:
   `{ capacity: 4, refill_per_sec: 0, scope: per_route }`.
2. From one client IP, fire a burst of 10 requests in parallel:

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" https://route.example/ &
done | sort | uniq -c
```

Expected: **at most 4 + small over-admission** (~capacity + 0.1 s *
N_workers * refill_per_sec admissions) succeed with 200; the rest
return `429` with a `Retry-After` header. Without the supervisor-
sync path, each worker would admit its own capacity=4 independently
-> up to 8 (N_workers=2) successes.

The `Retry-After` value should be realistic (1 s when
`refill_per_sec >= 1`, 60 s when `refill_per_sec == 0`).

### 11. Forward-auth verdict cache cross-worker

1. Route with Forward auth enabled + `verdict_cache_ttl_ms = 30000`.
2. Hit `/secret` many times with the same cookie:

```bash
# The cookie hits different workers (round-robin). All should get
# 200 without invoking the auth backend past the first call.
for i in $(seq 1 20); do
  curl -s -H 'Cookie: session=abc' https://test.example/secret
done
```

Check `lorica_forward_auth_cache_total{outcome="hit"}` in `/metrics`:
it should grow at ~N-1 requests out of N (first request misses on the
worker that serves it, subsequent ones hit because the supervisor's
cache is populated and served to every worker). In v1.2.x without
cross-worker cache, each worker had its own cache and hit rate was
~(N-1)/N^2.

### 12. Circuit breaker cross-worker

1. Deploy a route with two backends where one returns 5xx.
2. Send 5 requests to the failing backend; the breaker opens for
   that `(route, backend)` on every worker, not just the one that
   saw the failures.

```bash
# Fire 20 requests; after ~5 failures the breaker opens and every
# worker refuses that backend until cooldown. Success rate on the
# OTHER backend stays at 100%.
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" https://test.example/
done | sort | uniq -c
```

A `BreakerDecision::AllowProbe` slot is allocated atomically by the
supervisor during HalfOpen, so two workers cannot both believe they
hold the probe. **Regression guard for audit H-1**: kill a worker
while it holds the probe and confirm the breaker recovers after
`cooldown` instead of locking the backend out forever:

```bash
# In another shell, run a request that you then ^C to simulate
# the probe-admitted worker crashing:
curl -X POST https://test.example/slow-endpoint   # ^C after 1s

# After `cooldown` (default 10 s) the breaker admits a fresh probe:
curl -v https://test.example/
```

Without the H-1 fix, the backend would stay 502 until supervisor
restart. With the fix, it admits a fresh probe ~`cooldown` later
and closes on success.

### 13. Two-phase config reload (WPAR-8)

1. Create a route via the API or dashboard.
2. Fire a burst of `curl` requests at the route and watch
   `grep 'ConfigReloadPrepare\|ConfigReloadCommit' /var/log/lorica*`
   in the supervisor logs.

Expected: **no worker serves the old config after the supervisor
logs `"config reload coordinated via pipelined RPC"`**. Previously
(legacy one-shot reload) there was a ~10-50 ms window where one
worker had the new config and another still had the old one.

Force a partial failure: temporarily break the database
(`chmod 000 /var/lib/lorica/lorica.db`) then trigger a reload; the
supervisor should log `"two-phase config reload had failures;
falling back to legacy broadcast"` and the workers should drop
their pending prepared slot via `ConfigReloadAbort` instead of
leaking an orphan `Arc<ProxyConfig>`. Restore permissions.

### 14. /metrics pull-on-scrape freshness (WPAR-7)

1. Fire a load burst, then quickly scrape `/metrics`.

```bash
# Background load
ab -n 10000 -c 20 https://test.example/ > /dev/null &
# Scrape immediately
curl -s https://127.0.0.1:9443/metrics | grep lorica_http_requests_total
```

Expected: the counter reflects activity within the last ~500 ms
instead of the periodic-pull interval (~10 s). Concurrent scrapes
dedup - run 10 `curl` at once and you should see only one
supervisor -> worker fan-out in the logs.

Check `lorica_supervisor_rpc_outcome_total{kind="metrics_pull"}`:
the `ok` label grows 1 per scrape window (dedup'd), `timeout` stays
at 0 in normal operation. A stuck worker pushes `timeout` up while
`ok` keeps climbing for healthy workers.

### 15. Shmem WAF auto-ban cross-worker

1. Configure `waf_ban_threshold = 5` and pick a test IP.
2. From that IP, send 10 requests carrying an SQLi payload:

```bash
for i in $(seq 1 10); do
  curl -s -H "X-Forwarded-For: 10.0.0.99" \
    "https://test.example/?id=1'OR'1'='1"
done
```

On the 5th blocked request the supervisor broadcasts `BanIp` to
every worker; subsequent requests from `10.0.0.99` (on any worker)
return `403 Banned` without evaluating the WAF rules.

Check the cross-worker counter via `lorica_shmem` logs:
`shmem hashtable saturated at probe limit` must NOT appear under
normal load. If it does, bump the table size in
`lorica-shmem::region`.

### 16. Supervisor RPC outcomes (audit-added observability)

`/metrics` now exposes `lorica_supervisor_rpc_outcome_total{kind,
outcome}` with 4 kinds (`metrics_pull`, `config_reload_prepare`,
`config_reload_commit`, `config_reload_abort`) and 3 outcomes (`ok`,
`timeout`, `error`). Useful alerts:
- `rate(kind="metrics_pull", outcome="timeout") > 0` - a worker is
  stuck past the 500 ms budget.
- `rate(kind="config_reload_prepare", outcome="timeout") > 0` - DB
  contention during reload; bump the `PREPARE_TIMEOUT` or
  investigate.
- `rate(kind="config_reload_abort", outcome="ok") > 0` - partial
  reload failures happening; check the legacy-broadcast fallback
  log lines.

### 17. Worker shutdown drain (audit H discovered + fixed)

```bash
# SIGTERM Lorica under load. The supervisor drains task trackers
# with a 10 s budget. Without the RpcEndpoint::Inner::drop fix the
# worker RPC listener would hang forever past that budget and
# systemd would SIGKILL it.
systemctl stop lorica
journalctl -u lorica -n 20 | grep 'RPC listener exiting\|worker drained'
```

Expected: every worker logs `"supervisor RPC loop exiting"` within
a fraction of a second after the supervisor closes the socket, and
`systemctl stop` returns cleanly under 10 s.

---

## v1.4.0 preview (on `feat/v1.4.0` branch)

### 18. OpenTelemetry tracing (OTLP)

Lorica builds spans for every proxied request when compiled with the
`otel` feature and configured with an OTLP endpoint. Off by default;
no dep-graph cost on standard builds.

**Build with the feature:**

```bash
cargo build --release --features otel
# Or inside the Docker harness:
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$PWD:/workspace" -w /workspace rust:1-bookworm bash -c "
    apt-get update -qq && apt-get install -y -qq cmake protobuf-compiler
    cargo build --release --features otel
"
```

**Configure the endpoint (dashboard):**

1. Settings > Observability (new section, v1.4.0).
2. Set `OTLP endpoint` to `http://jaeger:4318` (HTTP/proto) or
   `http://jaeger:4317` (gRPC).
3. Choose protocol: `http-proto` (default, accepted by Tempo /
   Jaeger v2 / Datadog), `grpc`, or `http-json`.
4. Sampling ratio: `0.1` default (10 % of traces exported). Set to
   `1.0` to export everything during testing.
5. Save. Lorica reloads config without a restart; the previous
   provider is torn down atomically.

**Quick Jaeger smoke test:**

```bash
# Stand up Jaeger in one container:
docker run -d --name jaeger \
  -p 4317:4317 -p 4318:4318 -p 16686:16686 \
  jaegertracing/all-in-one:latest

# In Lorica, set otlp_endpoint to http://host.docker.internal:4318
# and sampling_ratio to 1.0. Fire a request:
curl -i https://gitlab.rwx-g.fr/

# Open the Jaeger UI:
open http://localhost:16686
# Service: "lorica". You should see one span per curl, tagged with:
#   http.request.method, url.path, http.response.status_code,
#   server.address, network.peer.address, lorica.route_id,
#   lorica.latency_ms, lorica.trace.origin
```

**W3C trace context passthrough (always on, does not need `otel`):**

```bash
# Even on a default build, Lorica parses and forwards traceparent.
# Pick a valid W3C header (32 hex trace, 16 hex parent, 01 sampled):
curl -i -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' \
  https://gitlab.rwx-g.fr/

# Check on the backend: the `traceparent` it sees from Lorica keeps the
# same trace_id (4bf92f3577...4736) but a new parent_id (Lorica's
# own span id, deterministically derived from the request_id).
```

Malformed headers are rejected silently and Lorica synthesises a
fresh trace from `X-Request-Id`, so the backend always sees a valid
header regardless of what the client sent.

**Expected startup log line** (when `otel` is on and endpoint is
configured):

```
INFO role="supervisor" endpoint="http://jaeger:4318" protocol="http-proto" service_name="lorica" sampling_ratio=0.1 "OpenTelemetry tracing enabled"
```

One line per role: `supervisor`, each `worker`, or `single-process`.

**Automated E2E smoke test (docker-compose `otel` profile):**

```bash
cd tests-e2e-docker
# Build Lorica with --features otel, start Jaeger, run the smoke test:
docker compose --profile otel up --build -d jaeger lorica-otel
docker compose --profile otel run --rm otel-smoke
# On success: exits 0 and prints "Tests: N | Passed: N | Failed: 0".
# On failure: the failed assertion names the missing tag / status.

# Inspect the traces visually:
open http://localhost:16686
```

The smoke test sends a request through Lorica carrying a known W3C
traceparent, then polls the Jaeger HTTP query API for the trace id
and asserts the span has the expected HTTP semconv tags
(`http.request.method`, `url.path`, `http.response.status_code`,
`lorica.route_id`). Default sampling is forced to 1.0 so the bench
is deterministic.

**Known limitations:**

- Child spans for per-stage timing (waf.eval, forward_auth, mtls,
  cache.lookup, upstream.connect, upstream.response) are not yet
  emitted; only the request-level root span with final-state
  attributes is exported. Follow-up in story 1.4c.
- Workers lose up to the last ~5 s of spans on abrupt shutdown
  because `lorica_core::Server::run_forever()` exits the process
  without a pre-exit hook. Supervisor + single-process flush
  cleanly. Follow-up noted in CHANGELOG.

### 19. GeoIP country filter

Per-route country allow / deny via DB-IP Lite Country (CC-BY 4.0,
no account required). The `.mmdb` format is compatible with
MaxMind's GeoLite2 so operators with a paid license can swap the
file.

**Preflight: install a database.**

```bash
# Fetch the current month's DB manually the first time:
curl -fsSL \
  "https://download.db-ip.com/free/dbip-country-lite-$(date -u +%Y-%m).mmdb.gz" \
  | gunzip -c > /var/lib/lorica/geoip.mmdb
sudo chown lorica:lorica /var/lib/lorica/geoip.mmdb
sudo chmod 644 /var/lib/lorica/geoip.mmdb
```

**Configure globally (dashboard Settings tab):**

1. Set `geoip_db_path` = `/var/lib/lorica/geoip.mmdb` (absolute).
2. Set `geoip_auto_update_enabled` = true to let Lorica refresh
   the DB weekly. The supervisor downloads a fresh copy and
   atomic-renames onto the same path; workers pick up the new DB
   on restart.
3. Save. Supervisor log: `"GeoIP auto-update task spawned"`.
   Worker log (in each worker): `"worker: GeoIP database loaded"`.

**Per-route rule (Protection tab > GeoIP country filter section):**

- **Denylist mode** (default): list the countries to block. Every
  other country passes.
- **Allowlist mode**: list the countries allowed. Every other
  country returns 403.
- Country codes are ISO 3166-1 alpha-2, uppercase, comma-separated
  (`FR, DE, IT`). Normalisation, dedup, and validation happen
  server-side.

**End-to-end test with a faked source IP:**

```bash
# Requires trusted_proxies to include your test client address so
# X-Forwarded-For is honoured. Then:

# Known US IP (Google DNS), US is in the denylist = expect 403:
curl -v -H 'X-Forwarded-For: 8.8.8.8' https://your-route.rwx-g.fr/

# Known FR IP, FR is NOT in the denylist = expect 200:
curl -v -H 'X-Forwarded-For: 193.203.239.1' https://your-route.rwx-g.fr/
```

**Metrics to watch:**

```
# Total blocks per route / country / mode:
lorica_geoip_block_total{route_id, country, mode}
```

**Traces (when OTel is on):**

Every traced request carries
`client.geo.country_iso_code = "<code>"` as a span attribute (even
on requests that are not blocked — useful for traffic analytics
per country). Requests where the DB is missing or the IP is in a
reserved range (RFC 1918, link-local, ...) simply omit the
attribute.

**Known limitations:**

- Multi-worker mode: the supervisor's auto-update task refreshes
  the on-disk DB, but workers load their own copy at fork time;
  a fresh download after fork requires a proxy restart for
  workers to pick it up. A `ReloadGeoIp` broadcast command is a
  future follow-up.
- Unknown country (reserved / private IP, DB miss) falls through
  WITHOUT blocking. For fail-close semantics, layer
  `ip_allowlist` on top of the GeoIP rule.
- DB-IP Lite Country attribution lives in `NOTICE` per CC-BY 4.0
  requirements. Commercial deployments that redistribute the
  Lorica binary must preserve that attribution.
