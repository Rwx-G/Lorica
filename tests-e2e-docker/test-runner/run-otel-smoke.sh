#!/usr/bin/env bash
# =============================================================================
# Lorica OpenTelemetry E2E smoke test (v1.4.0 story 1.8)
#
# Pre-requisite: docker-compose `otel` profile is up, so Lorica built
# with `--features otel` is running with `LORICA_API=http://lorica-otel:9443`,
# and Jaeger all-in-one is at `JAEGER_QUERY=http://jaeger:16686`.
#
# Flow:
#   1. Wait for Lorica API, backend1, and Jaeger.
#   2. Log into the Lorica management API.
#   3. Configure `GlobalSettings.otlp_*` so Lorica exports to jaeger:4318
#      (http-proto) with sampling_ratio=1.0 (every span exported so
#      the smoke test is deterministic).
#   4. Create a trivial route pointing at backend1, trigger a reload.
#   5. Send one request through the proxy carrying a known W3C
#      traceparent. The server-side span (trace_id preserved + Lorica
#      as the new parent_id) should land in Jaeger within a few
#      seconds via the BatchSpanProcessor's periodic flush.
#   6. Poll Jaeger's HTTP query API (/api/traces?service=lorica) for
#      the trace_id. Assert the span has the expected HTTP semconv
#      attributes (http.request.method, url.path,
#      http.response.status_code, lorica.route_id, lorica.latency_ms).
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
JAEGER="${JAEGER_QUERY:-http://jaeger:16686}"
BACKEND1="${BACKEND1_ADDR}"

# Fixed W3C trace id so the Jaeger query has a deterministic target.
# Trace id is 32 lowercase hex chars, parent id is 16 lowercase hex,
# flags 01 = sampled.
CLIENT_TRACE_ID="4bf92f3577b34da6a3ce929d0e0e4736"
CLIENT_SPAN_ID="00f067aa0ba902b7"
CLIENT_TRACEPARENT="00-${CLIENT_TRACE_ID}-${CLIENT_SPAN_ID}-01"

log "=== OTel smoke: preflight ==="
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

for i in $(seq 1 60); do
    curl -sf "$JAEGER/api/services" >/dev/null 2>&1 && break
    sleep 1
done
log "Jaeger query API ready"

# --- Login (with first-run password change handling) ---
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(cat /shared/admin_password | tr -d '[:space:]')
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

# First-run password change: the auth API forces a rotation away
# from the auto-generated bootstrap password. Run the full
# `PUT /api/v1/auth/password` + re-login dance so the rest of the
# smoke can call the management API normally.
MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="OtelSmokePassword!42"
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

# --- Configure OTel settings ---
log "=== OTel smoke: configure OTLP endpoint ==="
OTEL_UPDATE=$(api_put /api/v1/settings '{
    "otlp_endpoint": "http://jaeger:4318",
    "otlp_protocol": "http-proto",
    "otlp_service_name": "lorica",
    "otlp_sampling_ratio": 1.0
}')
assert_json "$OTEL_UPDATE" '.data.otlp_endpoint' 'http://jaeger:4318' 'otlp_endpoint persisted'
# Float serialisation may render 1.0 as "1" or "1.0" depending on the
# JSON writer; accept both.
SAMPLING=$(echo "$OTEL_UPDATE" | jq -r '.data.otlp_sampling_ratio')
case "$SAMPLING" in
    1|1.0) ok "sampling_ratio persisted (= $SAMPLING)" ;;
    *) fail "sampling_ratio persisted (expected 1 or 1.0, got '$SAMPLING')" ;;
esac

# Settings changes trigger a reload, which in turn re-calls
# otel::init. Give the provider a moment to swap.
sleep 2

# --- Create a route through backend1 ---
log "=== OTel smoke: create test route ==="
# Create a backend entry first, then a route that uses it.
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"otel-backend1\",
    \"group\": \"otel\",
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
    \"hostname\": \"otel-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
if [ -z "$ROUTE_ID" ]; then
    fail "route create: $ROUTE"
    exit 1
fi
ok "route created (id=$ROUTE_ID)"

sleep 2

# --- Send a traced request through the proxy ---
log "=== OTel smoke: issue traced request ==="
RESP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: otel-test.local" \
    -H "traceparent: ${CLIENT_TRACEPARENT}" \
    "${PROXY}/")
if [ "$RESP_CODE" = "200" ]; then
    ok "proxied request returned 200 (trace_id=${CLIENT_TRACE_ID})"
else
    fail "proxied request returned $RESP_CODE"
fi

# BatchSpanProcessor schedules export; give it a few seconds to flush.
# Since the v1.4.0 fix to wrap `request_filter` in
# `.instrument(span).await` with the W3C remote context attached
# before `info_span!` expansion, the OTel traceID on the exported
# span MUST match the client's W3C trace_id. We first look up the
# trace by id (the strict continuity check); the fallback scan by
# service is kept as a regression guard for the previous
# (broken) behaviour.
log "waiting for span export to Jaeger..."
TRACE_JSON=""
for i in $(seq 1 30); do
    BYID=$(curl -sf "${JAEGER}/api/traces/${CLIENT_TRACE_ID}" 2>/dev/null || echo '{}')
    if echo "$BYID" | jq -e '.data[0].spans | length > 0' >/dev/null 2>&1; then
        TRACE_JSON="$BYID"
        break
    fi
    sleep 1
done

if [ -z "$TRACE_JSON" ]; then
    fail "no trace with id ${CLIENT_TRACE_ID} in Jaeger after 30 s"
    LIST=$(curl -sf "${JAEGER}/api/traces?service=lorica&limit=5" 2>/dev/null || echo '{}')
    echo "Fallback: traces for service=lorica follow (for debug):"
    echo "$LIST" | jq -r '.data[].traceID' | head -5
    exit 1
fi
ok "trace ${CLIENT_TRACE_ID} landed in Jaeger (OTel traceID matches W3C client trace_id)"

# --- Find the http_request span inside the matched trace ---
log "=== OTel smoke: verify span attributes ==="
LORICA_SPAN=$(echo "$TRACE_JSON" | jq -c "
    .data[0].spans[] | select(.operationName == \"http_request\")
" | head -1)

if [ -z "$LORICA_SPAN" ] || [ "$LORICA_SPAN" = "null" ]; then
    fail "no http_request span inside trace ${CLIENT_TRACE_ID}"
    echo "$TRACE_JSON" | jq -r '.data[0].spans[].operationName' | head -10
    exit 1
fi
ok "http_request span present in trace"

# Tags in Jaeger format: array of {key, type, value} objects.
get_tag() {
    echo "$LORICA_SPAN" | jq -r ".tags[]? | select(.key == \"$1\") | .value" 2>/dev/null
}

METHOD=$(get_tag "http.request.method")
if [ "$METHOD" = "GET" ]; then
    ok "http.request.method = GET"
else
    fail "http.request.method expected GET, got '$METHOD'"
fi

STATUS=$(get_tag "http.response.status_code")
if [ "$STATUS" = "200" ]; then
    ok "http.response.status_code = 200"
else
    fail "http.response.status_code expected 200, got '$STATUS'"
fi

ROUTE_TAG=$(get_tag "lorica.route_id")
if [ "$ROUTE_TAG" = "$ROUTE_ID" ]; then
    ok "lorica.route_id matches created route"
else
    fail "lorica.route_id expected '$ROUTE_ID', got '$ROUTE_TAG'"
fi

URL_PATH=$(get_tag "url.path")
if [ "$URL_PATH" = "/" ]; then
    ok "url.path = /"
else
    fail "url.path expected '/', got '$URL_PATH'"
fi

# --- Summary ---
log "=== OTel smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
