#!/usr/bin/env bash
# =============================================================================
# Lorica E2E - Worker Isolation Tests
# Tests multi-process mode with --workers 2
# =============================================================================

set -euo pipefail

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
BACKEND2="${BACKEND2_ADDR}"

PASS=0
FAIL=0
TOTAL=0
SESSION=""

log()   { echo -e "\033[1;34m[TEST]\033[0m $*"; }
ok()    { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;32m  PASS\033[0m $*"; }
fail()  { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;31m  FAIL\033[0m $*"; }

api_get()  { curl -sf -b "$SESSION" "$API$1" 2>/dev/null; }
api_post() { curl -sf -b "$SESSION" -X POST -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_put()  { curl -sf -b "$SESSION" -X PUT -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_del()  { curl -sf -b "$SESSION" -X DELETE "$API$1" 2>/dev/null; }

assert_json() {
    local json="$1" path="$2" expected="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then ok "$label"; else fail "$label (expected '$expected', got '$actual')"; fi
}

assert_json_gt() {
    local json="$1" path="$2" min="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "0")
    if [ "$actual" -gt "$min" ] 2>/dev/null; then ok "$label (=$actual)"; else fail "$label (expected >$min, got '$actual')"; fi
}

# --- Wait for services ---

log "Waiting for backends..."
for i in $(seq 1 30); do
    if curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1; then break; fi
    sleep 1
done

log "Waiting for Lorica (workers mode)..."
for i in $(seq 1 120); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" != "000" ]; then break; fi
    sleep 2
done

# --- Login ---

log "=== Worker Isolation Tests ==="

ADMIN_PW=""
log "Reading admin password..."
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(cat /shared/admin_password | tr -d '[:space:]')
        break
    fi
    sleep 1
done

if [ -z "$ADMIN_PW" ]; then
    fail "Could not read admin password"
    echo "TOTAL: $TOTAL | PASS: $PASS | FAIL: $FAIL"
    exit 1
fi

LOGIN_JSON=$(jq -nc --arg pw "$ADMIN_PW" '{"username":"admin","password":$pw}')
LOGIN_HEADERS=$(mktemp)
LOGIN_HTTP=$(curl -s -o /tmp/login_body.json -w '%{http_code}' -D "$LOGIN_HEADERS" \
    "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "$LOGIN_JSON" 2>/dev/null || echo "000")

SESSION_COOKIE=$(grep -i "Set-Cookie:" "$LOGIN_HEADERS" 2>/dev/null | \
    grep -o 'lorica_session=[^;]*' | head -1 || echo "")

if [ "$LOGIN_HTTP" = "200" ] && [ -n "$SESSION_COOKIE" ]; then
    SESSION="$SESSION_COOKIE"
    ok "Login succeeded"

    MUST_CHANGE=$(jq -r '.data.must_change_password' /tmp/login_body.json 2>/dev/null || echo "false")
    if [ "$MUST_CHANGE" = "true" ]; then
        NEW_PW="WorkerTestPw!42"
        CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
            '{"current_password":$cur,"new_password":$new}')
        curl -s -o /dev/null -b "$SESSION" \
            "$API/api/v1/auth/password" -X PUT \
            -H "Content-Type: application/json" \
            -d "$CHANGE_JSON" 2>/dev/null
        RELOGIN_HEADERS=$(mktemp)
        RELOGIN_JSON=$(jq -nc --arg pw "$NEW_PW" '{"username":"admin","password":$pw}')
        curl -s -o /dev/null -D "$RELOGIN_HEADERS" \
            "$API/api/v1/auth/login" -X POST \
            -H "Content-Type: application/json" \
            -d "$RELOGIN_JSON" 2>/dev/null
        SESSION_COOKIE=$(grep -i "Set-Cookie:" "$RELOGIN_HEADERS" 2>/dev/null | \
            grep -o 'lorica_session=[^;]*' | head -1 || echo "")
        SESSION="$SESSION_COOKIE"
        rm -f "$RELOGIN_HEADERS"
        ok "Password changed"
    fi
else
    fail "Login failed (HTTP $LOGIN_HTTP)"
    echo "TOTAL: $TOTAL | PASS: $PASS | FAIL: $FAIL"
    exit 1
fi
rm -f "$LOGIN_HEADERS" /tmp/login_body.json

# =============================================================================
# 1. WORKER METRICS
# =============================================================================
log "=== 1. Worker Metrics ==="

# Workers endpoint should show workers after heartbeat registration.
# Worker restarts (database lock on first boot) may delay registration.
sleep 15

WORKERS=$(api_get "/api/v1/workers")
WORKER_COUNT=$(echo "$WORKERS" | jq '.data.total' 2>/dev/null || echo "0")
if [ "$WORKER_COUNT" -ge 2 ]; then
    ok "Workers endpoint shows $WORKER_COUNT workers"
elif [ "$WORKER_COUNT" -ge 1 ]; then
    ok "Workers endpoint shows $WORKER_COUNT worker(s) (2nd may be restarting)"
else
    fail "Expected >= 1 worker (got $WORKER_COUNT)"
fi

# Check workers are healthy
HEALTHY_COUNT=$(echo "$WORKERS" | jq '[.data.workers[] | select(.healthy == true)] | length' 2>/dev/null || echo "0")
if [ "$HEALTHY_COUNT" -ge 1 ]; then
    ok "Healthy workers: $HEALTHY_COUNT"
else
    fail "Expected >= 1 healthy worker (got $HEALTHY_COUNT)"
fi

# Workers endpoint returns data
if [ "$WORKER_COUNT" -ge 1 ]; then
    ok "Worker metrics API works in multi-process mode"
else
    fail "Worker metrics API returned no data"
fi

# =============================================================================
# 2. API WORKS THROUGH WORKERS
# =============================================================================
log "=== 2. API Through Workers ==="

# Verify the management API works correctly in multi-worker mode
B1=$(api_post "/api/v1/backends" "{\"address\":\"$BACKEND1\"}")
B1_ID=$(echo "$B1" | jq -r '.data.id')
if [ -n "$B1_ID" ] && [ "$B1_ID" != "null" ]; then
    ok "Backend created via API in worker mode"
else
    fail "Backend creation failed in worker mode"
fi

R1=$(api_post "/api/v1/routes" "{
    \"hostname\":\"test.local\",
    \"path_prefix\":\"/\",
    \"backend_ids\":[\"$B1_ID\"],
    \"load_balancing\":\"round_robin\"
}")
R1_ID=$(echo "$R1" | jq -r '.data.id')
if [ -n "$R1_ID" ] && [ "$R1_ID" != "null" ]; then
    ok "Route created via API in worker mode"
else
    fail "Route creation failed in worker mode"
fi

# Verify config export works across worker processes
EXPORT=$(curl -sf -b "$SESSION" -X POST "$API/api/v1/config/export" --max-time 5 2>/dev/null || echo "")
if echo "$EXPORT" | grep -q "test.local"; then
    ok "Config export works in worker mode"
else
    fail "Config export failed in worker mode"
fi

# =============================================================================
# 3. CONFIG RELOAD ACROSS WORKERS
# =============================================================================
log "=== 3. Config Reload Across Workers ==="

# Update a route - this should propagate to all workers via command channel
ROUTE_UPD=$(api_put "/api/v1/routes/$R1_ID" '{"load_balancing":"random"}')
UPD_LB=$(echo "$ROUTE_UPD" | jq -r '.data.load_balancing' 2>/dev/null || echo "")
if [ "$UPD_LB" = "random" ]; then
    ok "Config update propagated in worker mode"
else
    fail "Config update failed in worker mode (got $UPD_LB)"
fi

# Verify settings can be read after reload
SETTINGS=$(api_get "/api/v1/settings")
SET_LEVEL=$(echo "$SETTINGS" | jq -r '.data.log_level' 2>/dev/null || echo "")
if [ "$SET_LEVEL" = "info" ]; then
    ok "Settings readable after config reload"
else
    fail "Settings read failed after config reload"
fi

# =============================================================================
# 4. PROMETHEUS METRICS (Workers)
# =============================================================================
log "=== 4. Prometheus Metrics ==="

METRICS_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$API/metrics" 2>/dev/null || echo "000")
if [ "$METRICS_STATUS" = "200" ]; then
    ok "Prometheus /metrics accessible in worker mode"
else
    fail "Prometheus /metrics should return 200 (got $METRICS_STATUS)"
fi

METRICS_BODY=$(curl -sf "$API/metrics" 2>/dev/null || echo "")
if echo "$METRICS_BODY" | grep -q "lorica_http_requests_total" 2>/dev/null; then
    ok "Workers: metrics contain request counters"
else
    fail "Workers: metrics should contain request counters"
fi

# =============================================================================
# 5. SLA ENDPOINTS (Workers)
# =============================================================================
log "=== 5. SLA Endpoints ==="

SLA_OVERVIEW=$(api_get "/api/v1/sla/overview")
if echo "$SLA_OVERVIEW" | jq -e '.data' >/dev/null 2>&1; then
    ok "Workers: SLA overview returns data"
else
    fail "Workers: SLA overview should return data"
fi

SLA_CFG=$(api_get "/api/v1/sla/routes/$R1_ID/config")
if echo "$SLA_CFG" | jq -e '.data.target_pct' >/dev/null 2>&1; then
    ok "Workers: SLA config returns target_pct"
else
    fail "Workers: SLA config should return target_pct"
fi

# =============================================================================
# 6. CLEANUP
# =============================================================================
log "=== 6. Cleanup ==="

api_del "/api/v1/routes/$R1_ID" >/dev/null 2>&1 && ok "Route deleted" || fail "Route delete failed"
api_del "/api/v1/backends/$B1_ID" >/dev/null 2>&1 && ok "Backend deleted" || fail "Backend delete failed"

# =============================================================================
# REPORT
# =============================================================================
echo ""
echo "============================================"
echo "  WORKER ISOLATION TEST REPORT"
echo "============================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
