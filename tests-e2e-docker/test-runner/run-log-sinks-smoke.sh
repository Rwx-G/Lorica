#!/usr/bin/env bash
# =============================================================================
# Lorica log-sinks E2E smoke test (v1.7.0 Story 9.8, IV1/IV2/IV3)
#
# Pre-requisite: docker-compose `log-sinks` profile is up, so Lorica
# built with `--features otel` is running, a socat TCP syslog collector
# appends frames to /shared/syslog.log, and an OTel collector with a
# logs-only pipeline writes records to /shared/otlp-logs.json.
#
# Flow:
#   1. Wait for backend1 and the Lorica API.
#   2. Log in (with the first-run password rotation dance).
#   3. Configure both sinks over PUT /api/v1/settings: syslog over TCP
#      to syslog-collector:6601 and OTLP logs to otelcol-logs:4318.
#      (The audit event of that first PUT can race the hub install;
#      the audited backend/route creations in step 4 happen after the
#      reload settles and guarantee the audit-kind frames.)
#   4. Create a WAF-blocking route, send one 200 request carrying a
#      known W3C traceparent (access kind + trace correlation) and one
#      SQLi request answered 403 (waf kind).
#   5. Assert /shared/syslog.log holds well-formed RFC 5424 frames for
#      all three kinds (octet-count prefix, <PRI>1 header, MSGID,
#      [lorica@32473 structured data).
#   6. Assert /shared/otlp-logs.json holds the client trace id (IV2).
#   7. Re-point both sinks at dead ports, drive 20 requests, assert
#      zero non-200 (IV3) and a non-zero
#      lorica_log_sink_dropped_total{sink="syslog"} on /metrics.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
SYSLOG_LOG="${SYSLOG_LOG:-/shared/syslog.log}"
OTLP_LOG="${OTLP_LOG:-/shared/otlp-logs.json}"

# Fixed W3C trace id so the OTLP log-record assertion has a
# deterministic target (same id the otel smoke uses).
CLIENT_TRACE_ID="4bf92f3577b34da6a3ce929d0e0e4736"
CLIENT_SPAN_ID="00f067aa0ba902b7"
CLIENT_TRACEPARENT="00-${CLIENT_TRACE_ID}-${CLIENT_SPAN_ID}-01"

log "=== Log-sinks smoke: preflight ==="
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
    NEW_PW="LogSinksSmokePassword!42"
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
log "=== Log-sinks smoke: configure syslog + OTLP logs sinks ==="
SINKS_UPDATE=$(api_put /api/v1/settings '{
    "syslog_endpoint": "syslog-collector:6601",
    "syslog_transport": "tcp",
    "otlp_endpoint": "http://otelcol-logs:4318",
    "otlp_protocol": "http-proto",
    "otlp_logs_enabled": true
}')
assert_json "$SINKS_UPDATE" '.data.syslog_endpoint' 'syslog-collector:6601' 'syslog_endpoint persisted'
assert_json "$SINKS_UPDATE" '.data.syslog_transport' 'tcp' 'syslog_transport persisted'
assert_json "$SINKS_UPDATE" '.data.otlp_endpoint' 'http://otelcol-logs:4318' 'otlp_endpoint persisted'
assert_json "$SINKS_UPDATE" '.data.otlp_logs_enabled' 'true' 'otlp_logs_enabled persisted'

# The settings mutation above is itself audited, which produces the
# audit-kind sink message asserted later. Give the reload a moment to
# (re)install the sink hub.
sleep 2

# --- Per-sink test endpoints (AC #6) ---
log "=== Log-sinks smoke: test endpoints ==="
SYSLOG_TEST=$(api_post /api/v1/settings/syslog/test '{}')
assert_json "$SYSLOG_TEST" '.data.ok' 'true' 'syslog test endpoint reports ok'
assert_json_exists "$SYSLOG_TEST" '.data.latency_ms' 'syslog test reports latency'
OTLP_TEST=$(api_post /api/v1/settings/otlp-logs/test '{}')
assert_json "$OTLP_TEST" '.data.ok' 'true' 'otlp-logs test endpoint reports ok'
assert_json_exists "$OTLP_TEST" '.data.latency_ms' 'otlp-logs test reports latency'

# --- Create a WAF-blocking route through backend1 ---
log "=== Log-sinks smoke: create WAF-blocking route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"log-sinks-backend1\",
    \"group\": \"log-sinks\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
if [ -z "$BACKEND_ID" ]; then
    fail "backend create: $BACKEND"
    exit 1
fi
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"log-sinks-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"waf_enabled\": true,
    \"waf_mode\": \"blocking\"
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
if [ -z "$ROUTE_ID" ]; then
    fail "route create: $ROUTE"
    exit 1
fi
ok "route created (id=$ROUTE_ID, WAF blocking)"

sleep 2

# --- Drive traffic: one clean traced request, one WAF block ---
log "=== Log-sinks smoke: drive traffic ==="
RESP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: log-sinks-test.local" \
    -H "traceparent: ${CLIENT_TRACEPARENT}" \
    "${PROXY}/")
if [ "$RESP_CODE" = "200" ]; then
    ok "proxied request returned 200 (trace_id=${CLIENT_TRACE_ID})"
else
    fail "proxied request returned $RESP_CODE"
fi

BLOCK_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: log-sinks-test.local" \
    "${PROXY}/search?q=1%27%20OR%201%3D1--" 2>/dev/null || true)
if [ "$BLOCK_CODE" = "403" ]; then
    ok "WAF blocked the SQLi probe (403)"
else
    fail "WAF block expected 403, got $BLOCK_CODE"
fi

# --- Syslog assertions (IV1) ---
# Frames are RFC 6587 octet-counting: "LEN <PRI>1 TIMESTAMP HOST lorica
# PID MSGID [lorica@32473 ...] {json}". Default facility 16 with the
# default per-kind severities gives PRI 134 (access), 132 (waf),
# 133 (audit).
log "=== Log-sinks smoke: syslog delivery ==="
SYSLOG_OK=false
for i in $(seq 1 30); do
    if grep -qE '[0-9]+ <134>1 [^ ]+ [^ ]+ lorica [0-9]+ access \[lorica@32473' "$SYSLOG_LOG" 2>/dev/null \
        && grep -qE '<132>1 [^ ]+ [^ ]+ lorica [0-9]+ waf \[lorica@32473' "$SYSLOG_LOG" 2>/dev/null \
        && grep -qE '<133>1 [^ ]+ [^ ]+ lorica [0-9]+ audit \[lorica@32473' "$SYSLOG_LOG" 2>/dev/null; then
        SYSLOG_OK=true
        log "all three kinds landed in syslog after ${i}s"
        break
    fi
    sleep 1
done
if [ "$SYSLOG_OK" = "true" ]; then
    ok "RFC 5424 frames for access, waf and audit present with [lorica@32473 SD"
else
    fail "missing syslog frames after 30 s"
    echo "--- last 5 syslog frames for debug ---"
    tail -c 2000 "$SYSLOG_LOG" 2>/dev/null || true
fi

# Octet-count sanity on one access frame: the length prefix must match
# the byte length of the message that follows. Frames are concatenated
# with no separator, so validate just the first frame of the file.
FIRST_LEN=$(head -c 10 "$SYSLOG_LOG" 2>/dev/null | grep -oE '^[0-9]+' || true)
if [ -n "$FIRST_LEN" ]; then
    PREFIX_LEN=$(( ${#FIRST_LEN} + 1 ))
    FIRST_MSG=$(head -c $(( PREFIX_LEN + FIRST_LEN )) "$SYSLOG_LOG" | tail -c "$FIRST_LEN")
    if [ "${#FIRST_MSG}" = "$FIRST_LEN" ] && [ "$(printf '%s' "$FIRST_MSG" | head -c 1)" = "<" ]; then
        ok "octet-counting frame length matches message body"
    else
        fail "octet-count prefix $FIRST_LEN does not match frame body"
    fi
else
    fail "no octet-count prefix at start of $SYSLOG_LOG"
fi

# The access message carries the trace context as structured data.
if grep -q "trace_id=\"${CLIENT_TRACE_ID}\"" "$SYSLOG_LOG" 2>/dev/null; then
    ok "syslog access message carries trace_id SD param"
else
    fail "trace_id ${CLIENT_TRACE_ID} missing from syslog SD"
fi

# --- OTLP logs assertions (IV2) ---
log "=== Log-sinks smoke: OTLP logs delivery ==="
OTLP_OK=false
for i in $(seq 1 30); do
    if grep -q "$CLIENT_TRACE_ID" "$OTLP_LOG" 2>/dev/null; then
        OTLP_OK=true
        log "trace-correlated log record landed after ${i}s"
        break
    fi
    sleep 1
done
if [ "$OTLP_OK" = "true" ]; then
    ok "OTLP log record carries the client trace id (log/trace correlation)"
else
    fail "trace id ${CLIENT_TRACE_ID} missing from $OTLP_LOG after 30 s"
    echo "--- otlp-logs.json tail for debug ---"
    tail -c 1500 "$OTLP_LOG" 2>/dev/null || true
fi
if grep -q "lorica.kind" "$OTLP_LOG" 2>/dev/null; then
    ok "OTLP log records carry the lorica.kind attribute"
else
    fail "lorica.kind attribute missing from OTLP log records"
fi

# --- Failure isolation (IV3): dead collectors never affect requests --
log "=== Log-sinks smoke: dead collectors do not affect the data plane ==="
DEAD_UPDATE=$(api_put /api/v1/settings '{
    "syslog_endpoint": "syslog-collector:1",
    "otlp_endpoint": "http://otelcol-logs:1"
}')
assert_json "$DEAD_UPDATE" '.data.syslog_endpoint' 'syslog-collector:1' 'syslog re-pointed at dead port'
sleep 2

NON_200=0
for i in $(seq 1 20); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: log-sinks-test.local" "${PROXY}/" 2>/dev/null || echo "000")
    [ "$CODE" = "200" ] || NON_200=$((NON_200+1))
done
if [ "$NON_200" = "0" ]; then
    ok "20/20 requests returned 200 with both collectors dead"
else
    fail "$NON_200/20 requests failed with dead collectors"
fi

# Dropped-message accounting: the syslog consumer counts every message
# it sheds while the collector is unreachable.
sleep 2
DROPPED=$(curl -sf "$API/metrics" 2>/dev/null \
    | grep '^lorica_log_sink_dropped_total' \
    | grep 'sink="syslog"' \
    | awk '{sum += $NF} END {printf "%d", sum}' || echo "0")
if [ "${DROPPED:-0}" -gt 0 ] 2>/dev/null; then
    ok "lorica_log_sink_dropped_total{sink=\"syslog\"} is non-zero (=$DROPPED)"
else
    fail "expected non-zero syslog drop counter, got '${DROPPED:-0}'"
fi

# --- Summary ---
log "=== Log-sinks smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
