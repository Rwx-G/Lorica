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

# --- Login ---
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(cat /shared/admin_password | tr -d '[:space:]')
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; exit 1; }

SESSION=$(mktemp)
LOGIN_RESP=$(curl -s -c "$SESSION" "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}")
if ! echo "$LOGIN_RESP" | jq -e '.data.user_id' >/dev/null 2>&1; then
    fail "login failed: $LOGIN_RESP"
    exit 1
fi
ok "logged in"

# --- Configure OTel settings ---
log "=== OTel smoke: configure OTLP endpoint ==="
OTEL_UPDATE=$(api_put /api/v1/settings '{
    "otlp_endpoint": "http://jaeger:4318",
    "otlp_protocol": "http-proto",
    "otlp_service_name": "lorica",
    "otlp_sampling_ratio": 1.0
}')
assert_json "$OTEL_UPDATE" '.data.otlp_endpoint' 'http://jaeger:4318' 'otlp_endpoint persisted'
assert_json "$OTEL_UPDATE" '.data.otlp_sampling_ratio' '1' 'sampling_ratio persisted'

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
log "waiting for span export to Jaeger..."
SPAN_FOUND=""
for i in $(seq 1 30); do
    TRACE=$(curl -sf "${JAEGER}/api/traces/${CLIENT_TRACE_ID}" 2>/dev/null || echo '{}')
    if echo "$TRACE" | jq -e '.data[0].spans | length > 0' >/dev/null 2>&1; then
        SPAN_FOUND="$TRACE"
        break
    fi
    sleep 1
done

if [ -z "$SPAN_FOUND" ]; then
    fail "span never appeared in Jaeger after 30 s"
    exit 1
fi
ok "span landed in Jaeger"

# --- Assert span attributes ---
log "=== OTel smoke: verify span attributes ==="
# Find the Lorica-emitted span (service.name = "lorica").
LORICA_SPAN=$(echo "$SPAN_FOUND" | jq -r '.data[0].spans[] | select(.process and (.process.serviceName == "lorica" or .processID == "p1"))' | head -50)
[ -n "$LORICA_SPAN" ] || LORICA_SPAN=$(echo "$SPAN_FOUND" | jq -r '.data[0].spans[0]')

# Traces in Jaeger expose tags as an array of {key, type, value} objects.
# Extract and assert.
get_tag() {
    echo "$LORICA_SPAN" | jq -r ".tags[] | select(.key == \"$1\") | .value" 2>/dev/null
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
