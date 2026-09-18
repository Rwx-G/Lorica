#!/usr/bin/env bash
# =============================================================================
# Lorica traffic-capture E2E smoke: WORKER MODE (v1.8.0 Epic 10)
#
# Pre-requisite: the `capture-workers` compose profile is up. Same
# topology as `capture` (one `--features otel` node, the socat syslog
# collector, the logs-only OTel collector, a writable /shared/captures),
# with the node started by entrypoint-capture-workers.sh: `--workers 2`.
#
# run-capture-smoke.sh runs first against the same node with
# CAPTURE_SMOKE_WORKERS=1 and re-proves every mode-independent assertion
# there. This file holds only what a workers node can show and a
# single-process one cannot:
#
#   sinks    a record produced INSIDE a worker reaches all four outputs:
#            the `lorica::capture` stdout target, the syslog collector,
#            the OTLP collector, and the rule's output.dir, with the file
#            byte-identical to the logged document. The worker side of
#            the emit path has never been exercised anywhere else.
#   ring     and yet `GET /api/v1/capture/recent` answers 503 for that
#            very request id, naming the outputs that do carry it, as
#            does the per-record download. The ring is per worker and
#            this API runs in the supervisor, whose ring stays empty
#            (docs/capture.md, Troubleshooting). An empty 200 would be
#            the bug this design avoids, so the refusal is asserted, not
#            an empty listing. The store-backed rule surface is
#            unaffected and still answers 200.
#   budget   `max_captures` is spent per worker: a rule with a budget of
#            2 on a two-worker node emits MORE than 2 before it disarms,
#            and at most 2 times the worker count. That is the documented
#            semantics, not a miscount, and this asserts what actually
#            happens rather than what would be convenient.
#   metrics  the three capture families aggregate on the supervisor's
#            /metrics: `lorica_captures_total` summed across workers (the
#            supervisor never increments it itself, so a non-zero value
#            IS the aggregation), and the two gauges as ONE series each,
#            `lorica_capture_rules_active` reading the armed-rule count
#            rather than that count times the worker count.
#
# What this does NOT prove: that the 64 MiB in-flight ceiling is per
# worker. Showing a node hold more than 64 MiB of capture buffers needs
# more than 64 MiB of concurrent bodies, which is not a smoke's job. The
# observable half of that claim, the gauge aggregating as one series, is
# asserted above.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
INSIDE_HOST="${INSIDE_HOST:-lorica-capture-workers-inside}"
BACKEND1="${BACKEND1_ADDR}"
SYSLOG_LOG="${SYSLOG_LOG:-/shared/syslog.log}"
OTLP_LOG="${OTLP_LOG:-/shared/otlp-logs.json}"
LORICA_LOG="${LORICA_LOG:-/shared/lorica.log}"
CAPTURE_DIR="${CAPTURE_DIR:-/shared/captures}"
INSIDE_CIDR="${INSIDE_CIDR:-172.30.0.0/16}"
SYSLOG_ENDPOINT="${SYSLOG_ENDPOINT:-syslog-collector-capture-workers:6601}"
OTLP_ENDPOINT="${OTLP_ENDPOINT:-http://otelcol-logs-capture-workers:4318}"
WORKERS="${CAPTURE_WORKERS:-2}"

source "$SCRIPT_DIR/capture-helpers.sh"

HOST_SINKS="capture-workers-sinks.local"
HOST_BUDGET="capture-workers-budget.local"
# The per-rule budget under test, and how many exchanges are thrown at
# it. Small budget, many connections: the point is to spend every
# worker's copy of it, not to measure throughput.
BUDGET=2
FIRE=40
# The password run-capture-smoke.sh rotates the first-run one to. Which
# of the two works here depends on which runner reached the node first.
ROTATED_PW="CaptureSmokePassword!42"
# A configuration write reaches the workers over the supervisor RPC.
SETTLE=5

metrics() { curl -sk -b "$SESSION" "$API/metrics" 2>/dev/null || true; }
# The supervisor's own value for one rule's decisions. Summed across
# workers by the per-worker counter aggregation; the supervisor never
# increments this family itself.
metric_capture_outcome() {
    metrics | grep '^lorica_captures_total' | grep "rule_id=\"$1\"" \
        | grep "outcome=\"$2\"" | awk '{sum += $NF} END {printf "%d", sum}'
}
# The sample lines of one unlabelled family, to count the series and
# read the value.
gauge_lines() { metrics | grep "^$1 " || true; }

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== capture workers smoke: preflight ==="
for i in $(seq 1 30); do
    curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1 && break
    sleep 1
done
log "backend1 ready"

for i in $(seq 1 120); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/" 2>/dev/null || true)
    [ "$HTTP_CODE" != "000" ] && [ -n "$HTTP_CODE" ] && break
    sleep 2
done
log "Lorica API ready"

IN_IP=$(resolve_v4 "$INSIDE_HOST")
PROXY_IN="http://${IN_IP}:8080"
if [ -n "$IN_IP" ] && in_cidr "$IN_IP" "$INSIDE_CIDR"; then
    ok "the node is reachable at $PROXY_IN"
else
    fail "no node address inside $INSIDE_CIDR ($INSIDE_HOST resolved to '$IN_IP')"
    print_results
fi

# --- Login ---
# The bootstrap password on a fresh node, the rotated one when
# run-capture-smoke.sh has already been through here.
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(tr -d '[:space:]' < /shared/admin_password)
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; print_results; }

LOGIN_HEADERS=$(mktemp)
LOGIN_BODY=$(mktemp)
LOGIN_HTTP=$(curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" \
    -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}")
if [ "$LOGIN_HTTP" = "200" ]; then
    SESSION=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
    if [ "$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")" = "true" ]; then
        CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$ROTATED_PW" \
            '{"current_password":$cur,"new_password":$new}')
        CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
            "$API/api/v1/auth/password" -X PUT \
            -H "Content-Type: application/json" -d "$CHANGE_JSON")
        [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; print_results; }
        SESSION=$(login_as admin "$ROTATED_PW")
    fi
else
    SESSION=$(login_as admin "$ROTATED_PW")
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
[ -n "$SESSION" ] || { fail "neither the bootstrap password nor the rotated one logged in"; print_results; }
ok "session ready"

# --- The export lanes, idempotently: this runner may go first ---
SETTINGS=$(api_get /api/v1/settings)
assert_json "$SETTINGS" '.data.syslog_capture_enabled' 'true' 'syslog_capture_enabled defaults to true'
assert_json "$SETTINGS" '.data.otlp_logs_capture_enabled' 'true' 'otlp_logs_capture_enabled defaults to true'
SINKS_UPDATE=$(api_put /api/v1/settings "{
    \"syslog_endpoint\": \"${SYSLOG_ENDPOINT}\",
    \"syslog_transport\": \"tcp\",
    \"otlp_endpoint\": \"${OTLP_ENDPOINT}\",
    \"otlp_protocol\": \"http-proto\",
    \"otlp_logs_enabled\": true
}")
assert_json "$SINKS_UPDATE" '.data.syslog_endpoint' "$SYSLOG_ENDPOINT" 'syslog sink configured'
assert_json "$SINKS_UPDATE" '.data.otlp_logs_enabled' 'true' 'OTLP logs sink configured'
sleep "$SETTLE"

# --- Backend and the two routes this file owns ---
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"capture-workers-backend1\",
    \"group\": \"capture-workers\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; print_results; }

mk_route() {
    api_post /api/v1/routes "{\"hostname\":\"$1\",\"path_prefix\":\"/\",\"backend_ids\":[\"${BACKEND_ID}\"],\"enabled\":true}" \
        | jq -r '.data.id // empty'
}
ROUTE_K=$(mk_route "$HOST_SINKS")
ROUTE_B=$(mk_route "$HOST_BUDGET")
if [ -n "$ROUTE_K" ] && [ -n "$ROUTE_B" ]; then
    ok "routes K ($ROUTE_K) and B ($ROUTE_B) created"
else
    fail "route creation: K='$ROUTE_K' B='$ROUTE_B'"
    print_results
fi
sleep "$SETTLE"

# ---------------------------------------------------------------------
# Sinks: a record built in a worker reaches every output.
# ---------------------------------------------------------------------
log "=== workers: a record produced in a worker reaches every sink ==="
mk_rule "{\"name\":\"workers sinks\",\"route_id\":\"$ROUTE_K\",\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":1000,\"ttl_seconds\":3600},\"output\":{\"dir\":\"$CAPTURE_DIR\"}}"; RULE_SINKS="$RULE_ID"
[ -n "$RULE_SINKS" ] || { fail "rule create: $RULE_OUT"; print_results; }
ok "rule with output.dir $CAPTURE_DIR created (id=$RULE_SINKS)"
sleep "$SETTLE"

PROBE="workers-sink-probe"
px "$PROXY_IN" "$HOST_SINKS" /ok -X POST -H 'Content-Type: application/json' -d "{\"probe\":\"$PROBE\"}"
[ "$PX_CODE" = "200" ] && ok "the probe request answered 200" || fail "the probe request answered $PX_CODE"
SINK_RID=$(px_request_id)
[ -n "$SINK_RID" ] || { fail "the backend echoed no X-Request-Id"; print_results; }
ok "the backend echoed the request id ($SINK_RID)"

REC_TEXT=""
for _ in $(seq 1 30); do
    REC_TEXT=$(stdout_record_text "$SINK_RID" "$RULE_SINKS")
    [ -n "$REC_TEXT" ] && break
    sleep 1
done
if [ -n "$REC_TEXT" ]; then
    ok "stdout: a lorica::capture record for the exchange, emitted by a worker"
    assert_json "$REC_TEXT" '.rule_id' "$RULE_SINKS" 'stdout: the record names the rule'
    assert_json "$REC_TEXT" '.route_id' "$ROUTE_K" 'stdout: the record names the route'
    assert_json "$REC_TEXT" '.request.body' "{\"probe\":\"$PROBE\"}" 'stdout: the record carries the request body'
    assert_json "$REC_TEXT" '.request.truncated' 'false' 'stdout: the body is whole'
else
    fail "stdout: no lorica::capture record for $SINK_RID in $LORICA_LOG"
    print_results
fi

SYS_N=0
for _ in $(seq 1 30); do
    SYS_N=$(syslog_count capture "\"request_id\":\"$SINK_RID\"")
    [ "${SYS_N:-0}" -ge 1 ] && break
    sleep 1
done
[ "$SYS_N" = "1" ] && ok "syslog: exactly one capture frame carries the worker's record" \
    || fail "syslog holds $SYS_N capture frame(s) for $SINK_RID, expected 1"
SYS_BODY=$(syslog_body capture "\"request_id\":\"$SINK_RID\"")
assert_json "$SYS_BODY" '.kind' 'capture' 'syslog: the frame is stamped kind=capture'
assert_json "$SYS_BODY" '.rule_id' "$RULE_SINKS" 'syslog: the frame names the rule'

OTLP_LINE=""
for _ in $(seq 1 30); do
    OTLP_LINE=$(grep "$SINK_RID" "$OTLP_LOG" 2>/dev/null | grep 'capture' | head -1 || true)
    [ -n "$OTLP_LINE" ] && break
    sleep 1
done
if [ -n "$OTLP_LINE" ]; then
    ok "OTLP: the collector received the worker's record"
else
    fail "OTLP: no capture record for $SINK_RID in $OTLP_LOG"
    tail -c 800 "$OTLP_LOG" 2>/dev/null || true
fi

CAP_FILE=""
for _ in $(seq 1 30); do
    CAP_FILE=$(find "$CAPTURE_DIR" -maxdepth 1 -name "*-${SINK_RID}.json" 2>/dev/null | head -1)
    [ -n "$CAP_FILE" ] && break
    sleep 1
done
if [ -n "$CAP_FILE" ]; then
    CAP_NAME=$(basename "$CAP_FILE")
    ok "output.dir: the worker wrote $CAP_NAME"
    echo "$CAP_NAME" | grep -qE "^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-${SINK_RID}\.json$" \
        && ok "output.dir: $CAP_NAME is <timestamp>-<request_id>.json" \
        || fail "output.dir: $CAP_NAME is not the documented name shape"
    CAP_MODE=$(stat -c '%a' "$CAP_FILE")
    [ "$CAP_MODE" = "640" ] && ok "output.dir: the file has mode 0640" \
        || fail "output.dir: the file has mode $CAP_MODE, expected 640"
    if [ "$(sha256sum < "$CAP_FILE" | awk '{print $1}')" = "$(printf '%s' "$REC_TEXT" | sha256sum | awk '{print $1}')" ]; then
        ok "output.dir: the file is byte-identical to the document on stdout"
    else
        fail "output.dir: the file differs from the stdout document ($(wc -c < "$CAP_FILE") bytes on disk)"
    fi
else
    fail "output.dir: no file named *-${SINK_RID}.json in $CAPTURE_DIR"
fi

# ---------------------------------------------------------------------
# The ring: refused, not empty. Asserted on the very record the four
# sinks were just shown to hold, which is what makes it a refusal to
# show records that exist rather than a node with nothing to show.
# ---------------------------------------------------------------------
log "=== workers: the recent-captures ring answers 503 and names the sinks ==="
RECENT_BODY=$(mktemp)
RECENT_CODE=$(curl -sk -b "$SESSION" -o "$RECENT_BODY" -w '%{http_code}' \
    "$API/api/v1/capture/recent" 2>/dev/null || echo "000")
[ "$RECENT_CODE" = "503" ] && ok "GET /capture/recent answers 503 on a workers node" \
    || fail "GET /capture/recent answered $RECENT_CODE, expected 503"
RECENT=$(cat "$RECENT_BODY")
rm -f "$RECENT_BODY"
assert_json "$RECENT" '.error.code' 'service_unavailable' 'the refusal carries the service_unavailable code'
assert_json "$RECENT" '.data' 'null' 'nothing in the body pretends to be an empty ring'
RECENT_MSG=$(echo "$RECENT" | jq -r '.error.message // ""')
case "$RECENT_MSG" in
    *"--workers"*) ok "the message says the node runs --workers" ;;
    *) fail "the message does not mention --workers: '$RECENT_MSG'" ;;
esac
case "$RECENT_MSG" in
    *"lorica::capture"*) ok "the message names the lorica::capture log target" ;;
    *) fail "the message does not name the lorica::capture target: '$RECENT_MSG'" ;;
esac
case "$RECENT_MSG" in
    *syslog*) ok "the message names the syslog lane" ;;
    *) fail "the message does not name the syslog lane: '$RECENT_MSG'" ;;
esac
case "$RECENT_MSG" in
    *OTLP*) ok "the message names the OTLP lane" ;;
    *) fail "the message does not name the OTLP lane: '$RECENT_MSG'" ;;
esac
case "$RECENT_MSG" in
    *output.dir*) ok "the message names the rule's output.dir" ;;
    *) fail "the message does not name output.dir: '$RECENT_MSG'" ;;
esac

DL_BODY=$(mktemp)
DL_CODE=$(curl -sk -b "$SESSION" -o "$DL_BODY" -w '%{http_code}' \
    "$API/api/v1/capture/recent/${SINK_RID}?rule_id=${RULE_SINKS}" 2>/dev/null || echo "000")
[ "$DL_CODE" = "503" ] \
    && ok "the per-record download answers 503 for a record the four sinks hold" \
    || fail "the download of $SINK_RID answered $DL_CODE, expected 503"
assert_json "$(cat "$DL_BODY")" '.error.code' 'service_unavailable' 'the download refusal carries the same code'
rm -f "$DL_BODY"

# The store-backed half of the surface is untouched by any of this.
assert_status GET "$API/api/v1/capture/rules" 200 "the rule listing still answers 200: it reads the store"
assert_json "$(rule_get "$RULE_SINKS")" '.data.id' "$RULE_SINKS" 'a single rule still reads back from the store'

# ---------------------------------------------------------------------
# The budget: per worker, and the test asserts that rather than the
# tidier number a per-node budget would produce.
# ---------------------------------------------------------------------
log "=== workers: max_captures is spent per worker, not per node ==="
mk_rule "{\"name\":\"per-worker budget\",\"route_id\":\"$ROUTE_B\",\"emit\":{\"status\":[\"server_error\"]},\"limits\":{\"max_captures\":$BUDGET,\"rate_per_minute\":1000,\"ttl_seconds\":3600}}"; RULE_BUDGET="$RULE_ID"
[ -n "$RULE_BUDGET" ] || { fail "rule create: $RULE_OUT"; print_results; }
ok "rule with max_captures $BUDGET created (id=$RULE_BUDGET)"
sleep "$SETTLE"

# One sequential exchange first, so a route that does not answer 502
# fails here with the status rather than as a silent zero-record count
# after the barrage. It spends one of the budget's admissions, which is
# why the barrage below is sized well past it.
px "$PROXY_IN" "$HOST_BUDGET" /fail -X POST -H 'Content-Type: application/json' -d '{"budget":0}'
[ "$PX_CODE" = "502" ] && ok "route B answers 502 on /fail" || fail "route B /fail answered $PX_CODE"

# Fired in parallel on purpose. The workers accept from one shared
# listener, so concurrency is what spreads the connections over them,
# and all of it has to land before the five-second self-disable tick
# writes the first cleared flag, or the node stops at one worker's copy
# of the budget and the comparison below says nothing.
for n in $(seq 1 "$FIRE"); do
    curl -s -o /dev/null --max-time 60 -H "Host: $HOST_BUDGET" \
        -X POST -H 'Content-Type: application/json' -d "{\"budget\":$n}" \
        "${PROXY_IN}/fail" &
done
wait || true
ok "$FIRE concurrent 5xx exchanges sent through the proxy"

DISABLED=false
for _ in $(seq 1 30); do
    [ "$(rule_get "$RULE_BUDGET" | jq -r '.data.enabled')" = "false" ] && { DISABLED=true; break; }
    sleep 1
done
[ "$DISABLED" = "true" ] && ok "a worker spent its own copy of max_captures and disarmed the rule" \
    || fail "the rule is still enabled 30 s after $FIRE 5xx exchanges"

EMITTED=$(stdout_count_for_rule "$RULE_BUDGET")
CEILING=$(( BUDGET * WORKERS ))
if [ "${EMITTED:-0}" -gt "$BUDGET" ]; then
    ok "the node emitted $EMITTED records against max_captures $BUDGET: the budget is per worker"
else
    fail "the node emitted $EMITTED record(s) for max_captures $BUDGET; on $WORKERS workers a per-worker budget emits more than $BUDGET (unless all $FIRE connections landed on one worker)"
fi
if [ "${EMITTED:-0}" -le "$CEILING" ]; then
    ok "and no more than $CEILING, the budget times the worker count"
else
    fail "$EMITTED records exceed $CEILING, the documented ceiling of workers times max_captures"
fi

STORED=0
for _ in $(seq 1 20); do
    STORED=$(rule_get "$RULE_BUDGET" | jq -r '.data.captures_emitted')
    [ "${STORED:-0}" -ge "$EMITTED" ] && break
    sleep 1
done
if [ "${STORED:-0}" = "$EMITTED" ]; then
    ok "captures_emitted reads $STORED: the sum of what each worker flushed"
else
    fail "captures_emitted reads '$STORED', the sinks hold $EMITTED records"
fi

ROWS=""
for _ in $(seq 1 20); do
    ROWS=$(api_get "/api/v1/audit?action=capture.rule.auto_disabled&limit=200" \
        | jq -c --arg t "$RULE_BUDGET" '[(.data.entries // [])[] | select(.target_id == $t)]')
    [ "$(echo "$ROWS" | jq 'length')" -ge 1 ] && break
    sleep 1
done
ROW_COUNT=$(echo "$ROWS" | jq 'length')
if [ "${ROW_COUNT:-0}" -ge 1 ] && [ "${ROW_COUNT:-0}" -le "$WORKERS" ]; then
    ok "$ROW_COUNT capture.rule.auto_disabled row(s): one per worker that spent its own copy"
else
    fail "$ROW_COUNT auto_disabled row(s) for the rule, expected between 1 and $WORKERS"
fi
assert_json "$ROWS" '.[0].operator_username' 'capture' 'the actor is the node (capture)'
assert_json "$ROWS" '.[0].target_id' "$RULE_BUDGET" 'the row names the rule'

# ---------------------------------------------------------------------
# Metrics: the three families aggregate on the supervisor.
# ---------------------------------------------------------------------
log "=== workers: the capture metric families aggregate across workers ==="
# The supervisor's copy of `lorica_captures_total` is fed only by the
# workers' reports: it has no capture path of its own, so any non-zero
# value here IS the aggregation working.
COUNTED=0
for _ in $(seq 1 30); do
    COUNTED=$(metric_capture_outcome "$RULE_BUDGET" emitted)
    [ "${COUNTED:-0}" -ge "$EMITTED" ] && break
    sleep 1
done
if [ "${COUNTED:-0}" = "$EMITTED" ]; then
    ok "lorica_captures_total{outcome=\"emitted\"} reads $COUNTED on the supervisor, summed across workers"
else
    fail "lorica_captures_total{outcome=\"emitted\"} reads '$COUNTED', the sinks hold $EMITTED records"
fi

# A rule creation is what rebuilds the configuration snapshot in every
# worker, and the gauge is published when that snapshot is built. Arming
# one here pins the expected value instead of racing whatever the last
# self-disable left behind.
mk_rule "{\"name\":\"metrics probe\",\"route_id\":\"$ROUTE_K\",\"match\":{\"path_prefix\":\"/never\"},\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":1000,\"ttl_seconds\":3600}}"; RULE_PROBE="$RULE_ID"
[ -n "$RULE_PROBE" ] || { fail "rule create: $RULE_OUT"; print_results; }
sleep "$SETTLE"
ARMED=$(api_get /api/v1/capture/rules | jq -r '[(.data.rules // [])[] | select(.enabled == true)] | length')
if [ "${ARMED:-0}" -ge 2 ]; then
    ok "$ARMED capture rules are armed on the node"
else
    fail "$ARMED armed rule(s); the gauge assertion needs at least 2 to tell a max from a sum"
fi

ACTIVE=""
for _ in $(seq 1 30); do
    ACTIVE=$(gauge_lines lorica_capture_rules_active | awk '{print $NF}' | head -1)
    [ "${ACTIVE:-}" = "$ARMED" ] && break
    sleep 1
done
ACTIVE_SERIES=$(gauge_lines lorica_capture_rules_active | wc -l | tr -d ' ')
[ "$ACTIVE_SERIES" = "1" ] \
    && ok "lorica_capture_rules_active is one series on the supervisor, not one per worker" \
    || fail "$ACTIVE_SERIES lorica_capture_rules_active series, expected 1"
if [ "${ACTIVE:-}" = "$ARMED" ]; then
    ok "lorica_capture_rules_active reads $ACTIVE, the armed-rule count: the MAXIMUM across workers"
else
    fail "lorica_capture_rules_active reads '$ACTIVE', expected $ARMED (a summed gauge would read $(( ARMED * WORKERS )))"
fi

INFLIGHT_SERIES=$(gauge_lines lorica_capture_inflight_bytes | wc -l | tr -d ' ')
[ "$INFLIGHT_SERIES" = "1" ] \
    && ok "lorica_capture_inflight_bytes is one series too, the SUM across workers" \
    || fail "$INFLIGHT_SERIES lorica_capture_inflight_bytes series, expected 1"

api_post "/api/v1/capture/rules/$RULE_PROBE/disable" '{}' >/dev/null
api_post "/api/v1/capture/rules/$RULE_SINKS/disable" '{}' >/dev/null

capture_helpers_cleanup

# --- Summary ---
log "=== capture workers smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
