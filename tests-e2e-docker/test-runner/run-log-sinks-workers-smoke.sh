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
# Every request carries its phase as its first path segment
# (`/warmup/1`, `/burst/1`, `/pad/1aaa...`), which the frame body repeats
# in its `path` (the query string is not logged), so each phase's frames
# are counted on their own and per worker PID.
#
#   sent       lorica_log_sink_sent_total{sink="syslog",kind="access"}
#              equals the number of access frames the collector received,
#              those frames carry at least two distinct worker PIDs, and
#              the count exceeds the largest single PID's share: the
#              supervisor reports the SUM, not one worker's share. The
#              OTLP lane's series grows by the request count.
#   truncated  lorica_log_sink_truncated_total{sink="syslog"} equals the
#              number of oversized access frames, which carry at least
#              two PIDs and exceed the largest PID's share: the sum again.
#   dropped    with the collector re-pointed at a dead port,
#              lorica_log_sink_dropped_total{sink="syslog",kind="access"}
#              grows by exactly the number of shed access events. Nothing
#              reaches the collector in that phase, so the per-worker
#              split is not observable: this proves the family propagates
#              every worker's drops, not that a max-style aggregation
#              would be caught on it. Summation is proven on the two
#              families above, which share the aggregation path.
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
# Requests per probe round: the warm-up, the oversized rounds and the
# dead-endpoint probe each repeat a round until the property they wait
# for shows, instead of sleeping a fixed time.
ROUND=8
MAX_ROUNDS=30
# The stream transport cuts a message body at 7168 bytes; a path past
# that guarantees a truncated access message. It has to be the path: the
# access event logs `uri.path()`, so a long query string never reaches
# the body.
OVERSIZE_PAD=7500

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

# metric_sum, read every 2s until two reads agree: the value once the
# workers have stopped moving it, used as a baseline.
settled_metric_sum() {
    local prev cur i
    prev=$(metric_sum "$@")
    cur="$prev"
    for i in $(seq 1 15); do
        sleep 2
        cur=$(metric_sum "$@")
        [ "$cur" = "$prev" ] && break
        prev="$cur"
    done
    printf '%s' "$cur"
}

# One line per access frame the collector holds: "<pid> <tag> <status>".
# RFC 5424 header: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID. The
# JSON body holds no `<`, so a frame runs up to the next header. The tag
# is the request path's first segment; the status is "-" where the body was cut
# before it (the oversized frames). The patterns are strings, not
# /regex/ literals: busybox awk ends a literal at the `/` inside `[/]`.
access_frames() {
    cat "$SYSLOG_DIR"/*.log 2>/dev/null \
        | grep -aoE '<[0-9]+>1 [^ ]+ [^ ]+ lorica [0-9]+ access [^<]*' \
        | awk '{
            tag = "-"
            if (match($0, "\"path\":\"/[a-z]+/")) tag = substr($0, RSTART + 9, RLENGTH - 10)
            status = "-"
            if (match($0, "\"status\":[0-9]+")) status = substr($0, RSTART + 9, RLENGTH - 9)
            print $5, tag, status
        }' || true
}

# The frames of one tag, or of every tag when the argument is empty.
frames_tagged() {
    access_frames | awk -v tag="$1" 'tag == "" || $2 == tag'
}

# Filters over frame lines on stdin.
count_lines() { wc -l | tr -d ' '; }
distinct_pids() { awk '{print $1}' | sort -u | wc -l | tr -d ' '; }
largest_share() { awk '{n[$1]++} END {m = 0; for (p in n) if (n[p] > m) m = n[p]; print m}'; }
per_pid() { awk '{n[$1]++} END {for (p in n) printf "%s from pid %s; ", n[p], p}'; }

# Fire N requests at once, each to `/<tag>/<i><suffix>`, and print
# how many did not answer 200.
fire_parallel() {
    local count="$1" tag="$2" suffix="${3:-}"
    local codes
    codes=$(mktemp)
    local n
    for n in $(seq 1 "$count"); do
        curl -s -o /dev/null --max-time 30 -w '%{http_code}\n' \
            -H "Host: $HOST" "${PROXY}/${tag}/${n}${suffix}" >> "$codes" 2>/dev/null &
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

# --- Warm-up: the route and the syslog sink on every worker ---
log "=== Log-sinks workers smoke: wait for every worker ==="
# The sink settings and the route reach each worker over the supervisor
# RPC, each on its own schedule. A worker writes a frame with status 200
# only once it holds both, so rounds go on until every worker has: from
# then on no request is served without its frame, and the frames below
# carry each worker's PID whatever way the burst spreads.
READY=0
for round in $(seq 1 "$MAX_ROUNDS"); do
    fire_parallel "$ROUND" warmup >/dev/null
    sleep 1
    READY=$(frames_tagged warmup | awk '$3 == "200"' | distinct_pids)
    [ "$READY" -ge "$WORKERS" ] && break
done
if [ "$READY" -ge "$WORKERS" ]; then
    ok "$READY worker processes serve the route and feed the syslog sink"
else
    fail "$READY of $WORKERS worker processes wrote a 200 access frame after $MAX_ROUNDS rounds ($(frames_tagged warmup | per_pid))"
    print_results
fi

# The OTLP lane is observable only through the counter, so it is read
# as a delta from a baseline taken once the warm-up has been counted.
OTLP_BEFORE=$(settled_metric_sum lorica_log_sink_sent_total 'sink="otlp"' 'kind="access"')

# --- Drive traffic through the workers ---
log "=== Log-sinks workers smoke: drive traffic ==="
NON_200=$(fire_parallel "$FIRE" burst)
[ "$NON_200" = "0" ] && ok "$FIRE concurrent requests answered 200" \
    || fail "$NON_200/$FIRE concurrent requests did not answer 200"

# Oversized requests, in rounds until their frames carry two PIDs, so
# the truncated count is a sum over workers too.
PAD=$(head -c "$OVERSIZE_PAD" /dev/zero | tr '\0' 'a')
PAD_FIRED=0
PAD_PIDS=0
for round in $(seq 1 "$MAX_ROUNDS"); do
    fire_parallel "$ROUND" pad "$PAD" >/dev/null
    PAD_FIRED=$(( PAD_FIRED + ROUND ))
    sleep 1
    PAD_PIDS=$(frames_tagged pad | distinct_pids)
    [ "$PAD_PIDS" -ge 2 ] && break
done

# --- sent: the supervisor reports the sum of every worker's share ---
log "=== Log-sinks workers smoke: lorica_log_sink_sent_total aggregates ==="
BURST_FRAMES=0
PAD_FRAMES=0
for i in $(seq 1 30); do
    BURST_FRAMES=$(frames_tagged burst | count_lines)
    PAD_FRAMES=$(frames_tagged pad | count_lines)
    [ "$BURST_FRAMES" -ge "$FIRE" ] && [ "$PAD_FRAMES" -ge "$PAD_FIRED" ] && break
    sleep 1
done
if [ "$BURST_FRAMES" = "$FIRE" ]; then
    ok "the syslog collector holds $BURST_FRAMES burst access frames, one per request"
else
    fail "the syslog collector holds $BURST_FRAMES burst access frames, expected $FIRE"
fi
if [ "$PAD_FRAMES" = "$PAD_FIRED" ]; then
    ok "the syslog collector holds $PAD_FRAMES oversized access frames, one per request"
else
    fail "the syslog collector holds $PAD_FRAMES oversized access frames, expected $PAD_FIRED"
fi

FRAMES=$(frames_tagged "" | count_lines)
PIDS=$(frames_tagged "" | distinct_pids)
LARGEST_SHARE=$(frames_tagged "" | largest_share)
PER_PID=$(frames_tagged "" | per_pid)
if [ "$PIDS" -ge 2 ] && [ "$PIDS" -le "$WORKERS" ]; then
    ok "access frames came from $PIDS worker processes: ${PER_PID}"
else
    fail "access frames came from $PIDS process(es), expected 2 to $WORKERS (${PER_PID})"
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

OTLP_EXPECTED=$(( FIRE + PAD_FIRED ))
OTLP_SENT=0
for i in $(seq 1 30); do
    OTLP_SENT=$(( $(metric_sum lorica_log_sink_sent_total 'sink="otlp"' 'kind="access"') - OTLP_BEFORE ))
    [ "$OTLP_SENT" -ge "$OTLP_EXPECTED" ] && break
    sleep 1
done
if [ "$OTLP_SENT" = "$OTLP_EXPECTED" ]; then
    ok "lorica_log_sink_sent_total{sink=\"otlp\",kind=\"access\"} grew by $OTLP_SENT on the supervisor, one per request"
else
    fail "lorica_log_sink_sent_total{sink=\"otlp\",kind=\"access\"} grew by $OTLP_SENT, expected $OTLP_EXPECTED"
fi

# --- truncated: the oversized frames, summed over workers ---
log "=== Log-sinks workers smoke: lorica_log_sink_truncated_total aggregates ==="
PAD_LARGEST_SHARE=$(frames_tagged pad | largest_share)
PAD_PER_PID=$(frames_tagged pad | per_pid)
if [ "$PAD_PIDS" -ge 2 ]; then
    ok "oversized access frames came from $PAD_PIDS worker processes: ${PAD_PER_PID}"
else
    fail "oversized access frames came from $PAD_PIDS process(es) after $PAD_FIRED requests (${PAD_PER_PID})"
fi
TRUNCATED=0
for i in $(seq 1 30); do
    TRUNCATED=$(metric_sum lorica_log_sink_truncated_total 'sink="syslog"')
    [ "$TRUNCATED" -ge "$PAD_FRAMES" ] && break
    sleep 1
done
if [ "$TRUNCATED" = "$PAD_FRAMES" ] && [ "$TRUNCATED" -gt "$PAD_LARGEST_SHARE" ]; then
    ok "lorica_log_sink_truncated_total{sink=\"syslog\"} reads $TRUNCATED on the supervisor: the sum across workers, not one worker's $PAD_LARGEST_SHARE"
else
    fail "lorica_log_sink_truncated_total{sink=\"syslog\"} reads $TRUNCATED, the collector holds $PAD_FRAMES oversized frames (largest single worker share $PAD_LARGEST_SHARE)"
fi

# --- dropped: a dead collector, and the workers' sheds reach /metrics ---
log "=== Log-sinks workers smoke: lorica_log_sink_dropped_total aggregates ==="
DEAD_UPDATE=$(api_put /api/v1/settings "{\"syslog_endpoint\": \"${SYSLOG_HOST}:1\"}")
assert_json "$DEAD_UPDATE" '.data.syslog_endpoint' "${SYSLOG_HOST}:1" 'syslog re-pointed at a dead port'

# A worker still on the live collector writes a frame for every request
# it serves; probe rounds go on until two in a row leave none.
CLEAN=0
for round in $(seq 1 "$MAX_ROUNDS"); do
    PROBE_BEFORE=$(frames_tagged deadprobe | count_lines)
    fire_parallel "$ROUND" deadprobe >/dev/null
    sleep 2
    PROBE_AFTER=$(frames_tagged deadprobe | count_lines)
    if [ "$PROBE_AFTER" = "$PROBE_BEFORE" ]; then
        CLEAN=$(( CLEAN + 1 ))
    else
        CLEAN=0
    fi
    [ "$CLEAN" -ge 2 ] && break
done
if [ "$CLEAN" -ge 2 ]; then
    ok "two probe rounds left no frame: the workers write to the dead port"
else
    fail "probe requests still reach the live collector after $MAX_ROUNDS rounds ($(frames_tagged deadprobe | per_pid))"
fi
DROPPED_BEFORE=$(settled_metric_sum lorica_log_sink_dropped_total 'sink="syslog"' 'kind="access"')

NON_200=$(fire_parallel "$DEAD_FIRE" dead)
[ "$NON_200" = "0" ] && ok "$DEAD_FIRE concurrent requests answered 200 with the collector dead" \
    || fail "$NON_200/$DEAD_FIRE concurrent requests failed with the collector dead"

DROPPED=0
for i in $(seq 1 30); do
    DROPPED=$(( $(metric_sum lorica_log_sink_dropped_total 'sink="syslog"' 'kind="access"') - DROPPED_BEFORE ))
    [ "$DROPPED" -ge "$DEAD_FIRE" ] && break
    sleep 1
done
DEAD_FRAMES=$(frames_tagged dead | count_lines)
if [ "$DROPPED" = "$DEAD_FIRE" ] && [ "$DEAD_FRAMES" = "0" ]; then
    ok "lorica_log_sink_dropped_total{sink=\"syslog\",kind=\"access\"} grew by $DROPPED on the supervisor, one per shed access event"
else
    fail "lorica_log_sink_dropped_total{sink=\"syslog\",kind=\"access\"} grew by $DROPPED for $DEAD_FIRE requests, $DEAD_FRAMES of which reached the collector"
fi

# --- Summary ---
log "=== Log-sinks workers smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
