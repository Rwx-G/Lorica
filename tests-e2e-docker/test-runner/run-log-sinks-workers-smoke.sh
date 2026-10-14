#!/usr/bin/env bash
# =============================================================================
# Lorica log-sinks E2E smoke: WORKER MODE (backlog #53)
#
# Pre-requisite: the `log-sinks-workers` compose profile is up. Same
# topology as `log-sinks` (one `--features otel` node, a socat syslog
# collector, the logs-only OTel collector), with the node started by
# entrypoint-log-sinks-workers.sh: `--workers 2`. The syslog collector
# writes one file per TCP connection under /shared/syslog/, so the frames
# of each worker's sink stay whole and countable even when both workers
# write at once.
#
# run-log-sinks-smoke.sh proves delivery, framing and failure isolation
# on a single-process node. This file holds what only a workers node can
# show: the three log-sink counter families are incremented inside the
# workers, where the access events are published, and the supervisor's
# /metrics reports them only through the per-worker counter aggregation.
# The supervisor proxies nothing, so it has no access event of its own:
# every `kind="access"` sample it reports came from a worker report.
#
#   sent       lorica_log_sink_sent_total{sink="syslog",kind="access"}
#              equals the number of access frames the collector received,
#              and those frames carry at least two distinct worker PIDs:
#              the supervisor reports the SUM, not one worker's share.
#              The OTLP lane's series reads the same request count.
#   truncated  lorica_log_sink_truncated_total{sink="syslog"} counts the
#              one access message cut to the stream size ceiling.
#   dropped    with the collector re-pointed at a dead port, the access
#              events the workers shed reach
#              lorica_log_sink_dropped_total{sink="syslog",kind="access"}.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
SYSLOG_DIR="${SYSLOG_DIR:-/shared/syslog}"
SYSLOG_ENDPOINT="${SYSLOG_ENDPOINT:-syslog-collector-log-sinks-workers:6601}"
SYSLOG_HOST="${SYSLOG_ENDPOINT%:*}"
OTLP_ENDPOINT="${OTLP_ENDPOINT:-http://otelcol-logs-log-sinks-workers:4318}"
WORKERS="${LOG_SINKS_WORKERS:-2}"

HOST="log-sinks-workers.local"
# Fired in parallel: the workers accept from one shared listener, so
# concurrency is what spreads the connections over them.
FIRE=40
DEAD_FIRE=20
# The stream transport cuts a message body at 7168 bytes; a query string
# past that guarantees one truncated access message.
OVERSIZE_PAD=7500
# A configuration write reaches the workers over the supervisor RPC.
SETTLE=5

# Sum of one counter family's samples on the supervisor's /metrics,
# keeping only the samples that carry every label given after the name.
metric_sum() {
    local family="$1"
    shift
    local lines
    lines=$(curl -sk -b "$SESSION" "$API/metrics" 2>/dev/null | grep "^${family}{" || true)
    local label
    for label in "$@"; do
        lines=$(printf '%s\n' "$lines" | grep -F "$label" || true)
    done
    printf '%s\n' "$lines" | awk 'NF {sum += $NF} END {printf "%d", sum}'
}

# The PID field of every access frame the collector holds, one per line.
# RFC 5424 header: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID.
access_frame_pids() {
    cat "$SYSLOG_DIR"/*.log 2>/dev/null \
        | grep -aoE '<[0-9]+>1 [^ ]+ [^ ]+ lorica [0-9]+ access \[lorica@32473' \
        | awk '{print $5}' || true
}

# Fire N requests at once and print how many did not answer 200.
fire_parallel() {
    local count="$1"
    local codes
    codes=$(mktemp)
    local n
    for n in $(seq 1 "$count"); do
        curl -s -o /dev/null --max-time 30 -w '%{http_code}\n' \
            -H "Host: $HOST" "${PROXY}/?n=$n" >> "$codes" 2>/dev/null &
    done
    wait || true
    grep -cv '^200$' "$codes" || true
    rm -f "$codes"
}

log "=== Log-sinks workers smoke: preflight ==="
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

# --- Login (with first-run password change handling) ---
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(tr -d '[:space:]' < /shared/admin_password)
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; exit 1; }

LOGIN_HEADERS=$(mktemp)
LOGIN_BODY=$(mktemp)
LOGIN_HTTP=$(curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" \
    -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}")
if [ "$LOGIN_HTTP" != "200" ]; then
    fail "login HTTP $LOGIN_HTTP: $(cat "$LOGIN_BODY")"
    exit 1
fi
SESSION=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
[ -n "$SESSION" ] || { fail "no session cookie returned"; exit 1; }
ok "initial login succeeded"

MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="LogSinksWorkersSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
        "$API/api/v1/auth/password" -X PUT \
        -H "Content-Type: application/json" -d "$CHANGE_JSON")
    [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; exit 1; }
    ok "first-run password rotated"
    RELOGIN_HEADERS=$(mktemp)
    RELOGIN_HTTP=$(curl -s -o /dev/null -D "$RELOGIN_HEADERS" \
        -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"${NEW_PW}\"}")
    [ "$RELOGIN_HTTP" = "200" ] || { fail "re-login HTTP $RELOGIN_HTTP"; exit 1; }
    SESSION=$(grep -i 'Set-Cookie:' "$RELOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
    [ -n "$SESSION" ] || { fail "no session cookie after re-login"; exit 1; }
    rm -f "$RELOGIN_HEADERS"
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ok "session ready"

# --- Configure both sinks ---
log "=== Log-sinks workers smoke: configure syslog + OTLP logs sinks ==="
SINKS_UPDATE=$(api_put /api/v1/settings "{
    \"syslog_endpoint\": \"${SYSLOG_ENDPOINT}\",
    \"syslog_transport\": \"tcp\",
    \"otlp_endpoint\": \"${OTLP_ENDPOINT}\",
    \"otlp_protocol\": \"http-proto\",
    \"otlp_logs_enabled\": true
}")
assert_json "$SINKS_UPDATE" '.data.syslog_endpoint' "$SYSLOG_ENDPOINT" 'syslog sink configured'
assert_json "$SINKS_UPDATE" '.data.syslog_transport' 'tcp' 'syslog transport is tcp'
assert_json "$SINKS_UPDATE" '.data.otlp_logs_enabled' 'true' 'OTLP logs sink configured'
sleep "$SETTLE"

# --- Backend and route, WAF off: every request is one access event ---
log "=== Log-sinks workers smoke: create route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"log-sinks-workers-backend1\",
    \"group\": \"log-sinks-workers\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"${HOST}\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "route created (id=$ROUTE_ID)"
sleep "$SETTLE"

# --- Drive traffic through the workers ---
log "=== Log-sinks workers smoke: drive traffic ==="
# One sequential request first, so a route that does not answer fails
# here with its status rather than as a short frame count later.
PROBE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "${PROXY}/" 2>/dev/null || true)
if [ "$PROBE_CODE" = "200" ]; then
    ok "the route answers 200"
else
    fail "the route answered '$PROBE_CODE'"
    print_results
fi

NON_200=$(fire_parallel "$FIRE")
[ "$NON_200" = "0" ] && ok "$FIRE concurrent requests answered 200" \
    || fail "$NON_200/$FIRE concurrent requests did not answer 200"

PAD=$(head -c "$OVERSIZE_PAD" /dev/zero | tr '\0' 'a')
OVERSIZE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" \
    "${PROXY}/?pad=${PAD}" 2>/dev/null || true)
if [ -n "$OVERSIZE_CODE" ] && [ "$OVERSIZE_CODE" != "000" ]; then
    ok "the oversized request was answered ($OVERSIZE_CODE)"
else
    fail "the oversized request got no answer"
fi
EXPECTED=$(( FIRE + 2 ))

# --- sent: the supervisor reports the sum of every worker's share ---
log "=== Log-sinks workers smoke: lorica_log_sink_sent_total aggregates ==="
FRAMES=0
for i in $(seq 1 30); do
    FRAMES=$(access_frame_pids | wc -l | tr -d ' ')
    [ "$FRAMES" -ge "$EXPECTED" ] && break
    sleep 1
done
if [ "$FRAMES" = "$EXPECTED" ]; then
    ok "the syslog collector holds $FRAMES access frames, one per request"
else
    fail "the syslog collector holds $FRAMES access frames, expected $EXPECTED"
fi

PER_PID=$(access_frame_pids | sort | uniq -c | awk '{printf "%s pid %s; ", $1, $2}')
PIDS=$(access_frame_pids | sort -u | wc -l | tr -d ' ')
LARGEST_SHARE=$(access_frame_pids | sort | uniq -c | awk 'BEGIN {m = 0} $1 > m {m = $1} END {print m}')
if [ "$PIDS" -ge 2 ] && [ "$PIDS" -le "$WORKERS" ]; then
    ok "access frames came from $PIDS worker processes: ${PER_PID}"
else
    fail "access frames came from $PIDS process(es), expected 2 to $WORKERS (${PER_PID}); unless all $FIRE connections landed on one worker, the sum below proves nothing"
fi

SENT=0
for i in $(seq 1 30); do
    SENT=$(metric_sum lorica_log_sink_sent_total 'sink="syslog"' 'kind="access"')
    [ "$SENT" -ge "$FRAMES" ] && break
    sleep 1
done
if [ "$SENT" = "$FRAMES" ] && [ "$SENT" -gt "$LARGEST_SHARE" ]; then
    ok "lorica_log_sink_sent_total{sink=\"syslog\",kind=\"access\"} reads $SENT on the supervisor: the sum across workers, not one worker's $LARGEST_SHARE"
else
    fail "lorica_log_sink_sent_total{sink=\"syslog\",kind=\"access\"} reads $SENT, the collector holds $FRAMES (largest single worker share $LARGEST_SHARE)"
fi

OTLP_SENT=0
for i in $(seq 1 30); do
    OTLP_SENT=$(metric_sum lorica_log_sink_sent_total 'sink="otlp"' 'kind="access"')
    [ "$OTLP_SENT" -ge "$EXPECTED" ] && break
    sleep 1
done
if [ "$OTLP_SENT" = "$EXPECTED" ]; then
    ok "lorica_log_sink_sent_total{sink=\"otlp\",kind=\"access\"} reads $OTLP_SENT on the supervisor, one per request"
else
    fail "lorica_log_sink_sent_total{sink=\"otlp\",kind=\"access\"} reads $OTLP_SENT, expected $EXPECTED"
fi

# --- truncated ---
log "=== Log-sinks workers smoke: lorica_log_sink_truncated_total aggregates ==="
TRUNCATED=0
for i in $(seq 1 30); do
    TRUNCATED=$(metric_sum lorica_log_sink_truncated_total 'sink="syslog"')
    [ "$TRUNCATED" -ge 1 ] && break
    sleep 1
done
if [ "$TRUNCATED" = "1" ]; then
    ok "lorica_log_sink_truncated_total{sink=\"syslog\"} reads 1 on the supervisor, the oversized access message"
else
    fail "lorica_log_sink_truncated_total{sink=\"syslog\"} reads $TRUNCATED, expected 1"
fi

# --- dropped: a dead collector, and the workers' sheds reach /metrics ---
log "=== Log-sinks workers smoke: lorica_log_sink_dropped_total aggregates ==="
DEAD_UPDATE=$(api_put /api/v1/settings "{\"syslog_endpoint\": \"${SYSLOG_HOST}:1\"}")
assert_json "$DEAD_UPDATE" '.data.syslog_endpoint' "${SYSLOG_HOST}:1" 'syslog re-pointed at a dead port'
sleep "$SETTLE"
DROPPED_BEFORE=$(metric_sum lorica_log_sink_dropped_total 'sink="syslog"' 'kind="access"')

NON_200=$(fire_parallel "$DEAD_FIRE")
[ "$NON_200" = "0" ] && ok "$DEAD_FIRE concurrent requests answered 200 with the collector dead" \
    || fail "$NON_200/$DEAD_FIRE concurrent requests failed with the collector dead"

DROPPED=0
for i in $(seq 1 30); do
    DROPPED=$(( $(metric_sum lorica_log_sink_dropped_total 'sink="syslog"' 'kind="access"') - DROPPED_BEFORE ))
    [ "$DROPPED" -ge "$DEAD_FIRE" ] && break
    sleep 1
done
if [ "$DROPPED" -ge "$DEAD_FIRE" ]; then
    ok "lorica_log_sink_dropped_total{sink=\"syslog\",kind=\"access\"} grew by $DROPPED on the supervisor for $DEAD_FIRE shed access events"
else
    fail "lorica_log_sink_dropped_total{sink=\"syslog\",kind=\"access\"} grew by $DROPPED, expected at least $DEAD_FIRE"
fi

# --- Summary ---
log "=== Log-sinks workers smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
