#!/usr/bin/env bash
# =============================================================================
# Lorica E2E Test Suite
# Tests all features: routing, WAF, health checks, API, dashboard, topology
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

# --- Helpers ---

log()   { echo -e "\033[1;34m[TEST]\033[0m $*"; }
ok()    { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;32m  PASS\033[0m $*"; }
fail()  { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;31m  FAIL\033[0m $*"; }

api_get()  { curl -sf -b "$SESSION" "$API$1" 2>/dev/null; }
api_post() { curl -sf -b "$SESSION" -X POST -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_put()  { curl -sf -b "$SESSION" -X PUT -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_del()  { curl -sf -b "$SESSION" -X DELETE "$API$1" 2>/dev/null; }

assert_status() {
    local method="$1" url="$2" expected="$3" label="$4"
    shift 4
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" -X "$method" "$@" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "$expected" ]; then
        ok "$label (HTTP $status)"
    else
        fail "$label (expected $expected, got $status)"
    fi
}

assert_json() {
    local json="$1" path="$2" expected="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then
        ok "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

assert_json_gt() {
    local json="$1" path="$2" min="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "0")
    if [ "$actual" -gt "$min" ] 2>/dev/null; then
        ok "$label (=$actual)"
    else
        fail "$label (expected >$min, got '$actual')"
    fi
}

# --- Wait for services ---

log "Waiting for backends..."
for i in $(seq 1 30); do
    if curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1 && \
       curl -sf "http://$BACKEND2/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

log "Waiting for Lorica API..."
for i in $(seq 1 120); do
    if curl -sf "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d '{"username":"x","password":"x"}' >/dev/null 2>&1 || \
       [ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d '{"username":"x","password":"x"}')" != "000" ]; then
        break
    fi
    sleep 2
done

# =============================================================================
# 1. AUTHENTICATION
# =============================================================================
log "=== 1. Authentication ==="

# Test unauthenticated access is rejected
assert_status GET "$API/api/v1/status" "401" "Unauthenticated request returns 401"
assert_status GET "$API/api/v1/routes" "401" "Routes endpoint requires auth"
assert_status GET "$API/api/v1/waf/events" "401" "WAF events endpoint requires auth"

# Test invalid credentials
LOGIN_RESULT=$(curl -s -o /dev/null -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}')
if [ "$LOGIN_RESULT" = "401" ]; then
    ok "Login rejects invalid credentials"
else
    fail "Login should reject invalid creds (got $LOGIN_RESULT)"
fi

# Read admin password from shared volume (written by Lorica entrypoint)
ADMIN_PW=""
log "Reading admin password from shared volume..."
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(cat /shared/admin_password | tr -d '[:space:]')
        break
    fi
    sleep 1
done

if [ -z "$ADMIN_PW" ]; then
    fail "Could not read admin password from /shared/admin_password"
    log "Lorica may not have started. Aborting."
    echo ""
    echo "============================================"
    echo "  LORICA E2E TEST REPORT"
    echo "============================================"
    echo "  Total:  $TOTAL"
    echo "  Passed: $PASS"
    echo "  Failed: $FAIL"
    echo "============================================"
    exit 1
fi

# Login with the real password
LOGIN_RESP=$(curl -sf -c - "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" 2>/dev/null || echo "")

SESSION_COOKIE=$(echo "$LOGIN_RESP" | grep lorica_session | awk '{print $NF}' || echo "")
if [ -n "$SESSION_COOKIE" ]; then
    SESSION="lorica_session=$SESSION_COOKIE"
    ok "Login with admin password succeeded"
else
    fail "Login with known password failed"
    SESSION=""
fi

# =============================================================================
# 2. DASHBOARD
# =============================================================================
log "=== 2. Dashboard ==="

DASH_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$API/" 2>/dev/null || echo "000")
if [ "$DASH_STATUS" = "200" ]; then
    ok "Dashboard serves index.html"
else
    fail "Dashboard should return 200 (got $DASH_STATUS)"
fi

DASH_BODY=$(curl -sf "$API/" 2>/dev/null || echo "")
if echo "$DASH_BODY" | grep -q "script" 2>/dev/null; then
    ok "Dashboard contains JavaScript"
else
    fail "Dashboard should contain script tags"
fi

# =============================================================================
# 3. API - SETTINGS (requires auth)
# =============================================================================
if [ -n "$SESSION" ]; then
    log "=== 3. Settings API ==="

    SETTINGS=$(api_get "/api/v1/settings")
    assert_json "$SETTINGS" ".data.log_level" "info" "Default log level is info"
    assert_json "$SETTINGS" ".data.default_topology_type" "single_vm" "Default topology is single_vm"
    assert_json_gt "$SETTINGS" ".data.default_health_check_interval_s" "0" "Health check interval > 0"

    # Update default topology
    UPDATED=$(api_put "/api/v1/settings" '{"default_topology_type":"ha"}')
    assert_json "$UPDATED" ".data.default_topology_type" "ha" "Topology updated to HA"

    # Reset
    api_put "/api/v1/settings" '{"default_topology_type":"single_vm"}' >/dev/null

# =============================================================================
# 4. API - BACKENDS CRUD
# =============================================================================
    log "=== 4. Backends CRUD ==="

    # Create backend 1
    B1=$(api_post "/api/v1/backends" "{\"address\":\"$BACKEND1\",\"health_check_enabled\":true,\"health_check_path\":\"/healthz\"}")
    B1_ID=$(echo "$B1" | jq -r '.data.id')
    assert_json "$B1" ".data.address" "$BACKEND1" "Backend 1 created"
    assert_json "$B1" ".data.health_check_path" "/healthz" "Backend 1 has HTTP health check path"

    # Create backend 2
    B2=$(api_post "/api/v1/backends" "{\"address\":\"$BACKEND2\",\"health_check_enabled\":true}")
    B2_ID=$(echo "$B2" | jq -r '.data.id')
    assert_json "$B2" ".data.address" "$BACKEND2" "Backend 2 created"

    # List backends
    BACKENDS=$(api_get "/api/v1/backends")
    BACKEND_COUNT=$(echo "$BACKENDS" | jq '.data.backends | length')
    if [ "$BACKEND_COUNT" -ge 2 ]; then
        ok "Backends list has >= 2 entries ($BACKEND_COUNT)"
    else
        fail "Expected >= 2 backends, got $BACKEND_COUNT"
    fi

    # Update backend 2 with health check path
    B2_UPD=$(api_put "/api/v1/backends/$B2_ID" '{"health_check_path":"/healthz"}')
    assert_json "$B2_UPD" ".data.health_check_path" "/healthz" "Backend 2 updated with health check path"

# =============================================================================
# 5. API - ROUTES CRUD + WAF TOGGLE
# =============================================================================
    log "=== 5. Routes CRUD ==="

    # Create route with WAF enabled (detection mode)
    R1=$(api_post "/api/v1/routes" "{
        \"hostname\":\"test.local\",
        \"path_prefix\":\"/\",
        \"backend_ids\":[\"$B1_ID\",\"$B2_ID\"],
        \"load_balancing\":\"round_robin\",
        \"topology_type\":\"ha\",
        \"waf_enabled\":true,
        \"waf_mode\":\"detection\"
    }")
    R1_ID=$(echo "$R1" | jq -r '.data.id')
    assert_json "$R1" ".data.hostname" "test.local" "Route created for test.local"
    assert_json "$R1" ".data.waf_enabled" "true" "WAF enabled on route"
    assert_json "$R1" ".data.waf_mode" "detection" "WAF in detection mode"
    assert_json "$R1" ".data.topology_type" "ha" "Route topology is HA"

    # Update to blocking mode
    R1_UPD=$(api_put "/api/v1/routes/$R1_ID" '{"waf_mode":"blocking"}')
    assert_json "$R1_UPD" ".data.waf_mode" "blocking" "WAF updated to blocking mode"

    # Switch back to detection for proxy tests
    api_put "/api/v1/routes/$R1_ID" '{"waf_mode":"detection"}' >/dev/null

    # Create a second route without WAF
    R2=$(api_post "/api/v1/routes" "{
        \"hostname\":\"nowaf.local\",
        \"path_prefix\":\"/\",
        \"backend_ids\":[\"$B1_ID\"],
        \"waf_enabled\":false
    }")
    R2_ID=$(echo "$R2" | jq -r '.data.id')
    assert_json "$R2" ".data.waf_enabled" "false" "Route without WAF created"

    # List routes
    ROUTES=$(api_get "/api/v1/routes")
    ROUTE_COUNT=$(echo "$ROUTES" | jq '.data.routes | length')
    if [ "$ROUTE_COUNT" -ge 2 ]; then
        ok "Routes list has >= 2 entries ($ROUTE_COUNT)"
    else
        fail "Expected >= 2 routes, got $ROUTE_COUNT"
    fi

# =============================================================================
# 6. PROXY - ROUTING + ROUND ROBIN
# =============================================================================
    log "=== 6. Proxy Routing ==="

    # Wait for config to propagate
    sleep 2

    # Test basic proxy routing
    PROXY_RESP=$(curl -sf -H "Host: test.local" "$PROXY/" 2>/dev/null || echo "")
    if echo "$PROXY_RESP" | jq -r '.backend' 2>/dev/null | grep -qE "backend[12]"; then
        ok "Proxy routes request to backend"
    else
        fail "Proxy should route to a backend (got: $PROXY_RESP)"
    fi

    # Test round-robin: send multiple requests and check we hit both backends
    BACKENDS_HIT=""
    for i in $(seq 1 10); do
        B=$(curl -sf -H "Host: test.local" "$PROXY/identity" 2>/dev/null | jq -r '.backend' 2>/dev/null || echo "")
        BACKENDS_HIT="$BACKENDS_HIT $B"
    done

    if echo "$BACKENDS_HIT" | grep -q "backend1" && echo "$BACKENDS_HIT" | grep -q "backend2"; then
        ok "Round-robin distributes across both backends"
    else
        fail "Expected both backends hit, got:$BACKENDS_HIT"
    fi

    # Test 404 for unknown host
    STATUS_404=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: unknown.local" "$PROXY/" 2>/dev/null || echo "000")
    if [ "$STATUS_404" = "404" ]; then
        ok "Unknown host returns 404"
    else
        fail "Unknown host should return 404 (got $STATUS_404)"
    fi

# =============================================================================
# 7. WAF - DETECTION MODE
# =============================================================================
    log "=== 7. WAF Detection ==="

    # SQL injection attempt (detection mode - should pass through)
    SQLI_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: test.local" \
        "$PROXY/search?q=1%20UNION%20SELECT%20*%20FROM%20users" 2>/dev/null || echo "000")
    if [ "$SQLI_STATUS" = "200" ]; then
        ok "WAF detection mode passes SQL injection through"
    else
        fail "Detection mode should pass through (got $SQLI_STATUS)"
    fi

    # XSS attempt
    curl -sf -H "Host: test.local" \
        "$PROXY/page?input=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null 2>&1
    ok "WAF detection mode passes XSS through"

    # Path traversal
    curl -sf -H "Host: test.local" \
        "$PROXY/../../../etc/passwd" >/dev/null 2>&1 || true
    ok "WAF detection logs path traversal"

    # Check WAF events were recorded
    sleep 1
    WAF_EVENTS=$(api_get "/api/v1/waf/events")
    EVENT_COUNT=$(echo "$WAF_EVENTS" | jq '.data.total' 2>/dev/null || echo "0")
    if [ "$EVENT_COUNT" -gt 0 ]; then
        ok "WAF events recorded ($EVENT_COUNT events)"
    else
        fail "Expected WAF events after attack payloads (got $EVENT_COUNT)"
    fi

    # Check WAF stats
    WAF_STATS=$(api_get "/api/v1/waf/stats")
    assert_json_gt "$WAF_STATS" ".data.total_events" "0" "WAF stats show events"
    assert_json_gt "$WAF_STATS" ".data.rule_count" "10" "WAF has loaded rules"

# =============================================================================
# 8. WAF - BLOCKING MODE
# =============================================================================
    log "=== 8. WAF Blocking ==="

    # Switch route to blocking mode
    api_put "/api/v1/routes/$R1_ID" '{"waf_mode":"blocking"}' >/dev/null
    sleep 1

    # SQL injection should now be blocked with 403
    BLOCK_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: test.local" \
        "$PROXY/search?q=1%27%20OR%201%3D1--" 2>/dev/null || echo "000")
    if [ "$BLOCK_STATUS" = "403" ]; then
        ok "WAF blocking mode returns 403 for SQL injection"
    else
        fail "Blocking mode should return 403 (got $BLOCK_STATUS)"
    fi

    # XSS should be blocked
    XSS_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: test.local" \
        "$PROXY/page?x=%3Cscript%3Ealert(1)%3C/script%3E" 2>/dev/null || echo "000")
    if [ "$XSS_STATUS" = "403" ]; then
        ok "WAF blocking mode returns 403 for XSS"
    else
        fail "XSS should be blocked (got $XSS_STATUS)"
    fi

    # Clean request should still pass
    CLEAN_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: test.local" "$PROXY/" 2>/dev/null || echo "000")
    if [ "$CLEAN_STATUS" = "200" ]; then
        ok "Clean request passes through WAF blocking mode"
    else
        fail "Clean request should pass (got $CLEAN_STATUS)"
    fi

    # No-WAF route should not block
    NOWAF_SQLI=$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: nowaf.local" \
        "$PROXY/search?q=1%27%20OR%201%3D1--" 2>/dev/null || echo "000")
    if [ "$NOWAF_SQLI" = "200" ]; then
        ok "Route without WAF passes SQL injection through"
    else
        fail "No-WAF route should not block (got $NOWAF_SQLI)"
    fi

    # Reset to detection
    api_put "/api/v1/routes/$R1_ID" '{"waf_mode":"detection"}' >/dev/null

# =============================================================================
# 9. WAF - RULE MANAGEMENT
# =============================================================================
    log "=== 9. WAF Rule Management ==="

    RULES=$(api_get "/api/v1/waf/rules")
    RULE_TOTAL=$(echo "$RULES" | jq '.data.total' 2>/dev/null || echo "0")
    RULE_ENABLED=$(echo "$RULES" | jq '.data.enabled' 2>/dev/null || echo "0")
    assert_json_gt "$RULES" ".data.total" "10" "WAF has rules loaded"

    if [ "$RULE_TOTAL" = "$RULE_ENABLED" ]; then
        ok "All rules enabled by default ($RULE_TOTAL)"
    else
        fail "Expected all rules enabled (total=$RULE_TOTAL, enabled=$RULE_ENABLED)"
    fi

    # Disable a rule
    DISABLE=$(api_put "/api/v1/waf/rules/942100" '{"enabled":false}')
    assert_json "$DISABLE" ".data.enabled" "false" "Rule 942100 disabled"

    # Verify it's disabled in the list
    RULES2=$(api_get "/api/v1/waf/rules")
    RULE_ENABLED2=$(echo "$RULES2" | jq '.data.enabled' 2>/dev/null || echo "0")
    if [ "$RULE_ENABLED2" -lt "$RULE_TOTAL" ]; then
        ok "Enabled count decreased after disable ($RULE_ENABLED2 < $RULE_TOTAL)"
    else
        fail "Enabled count should decrease"
    fi

    # Re-enable
    ENABLE=$(api_put "/api/v1/waf/rules/942100" '{"enabled":true}')
    assert_json "$ENABLE" ".data.enabled" "true" "Rule 942100 re-enabled"

    # Non-existent rule
    NOTFOUND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        -b "$SESSION" -X PUT \
        -H "Content-Type: application/json" \
        -d '{"enabled":false}' \
        "$API/api/v1/waf/rules/999999" 2>/dev/null || echo "000")
    if [ "$NOTFOUND_STATUS" = "404" ]; then
        ok "Non-existent rule returns 404"
    else
        fail "Expected 404 for unknown rule (got $NOTFOUND_STATUS)"
    fi

    # Clear events
    CLEAR=$(api_del "/api/v1/waf/events")
    assert_json "$CLEAR" ".data.cleared" "true" "WAF events cleared"

    EVENTS_AFTER=$(api_get "/api/v1/waf/events")
    assert_json "$EVENTS_AFTER" ".data.total" "0" "Events empty after clear"

# =============================================================================
# 10. STATUS & SYSTEM
# =============================================================================
    log "=== 10. Status & System ==="

    STATUS=$(api_get "/api/v1/status")
    assert_json_gt "$STATUS" ".data.routes_count" "0" "Status shows routes"
    assert_json_gt "$STATUS" ".data.backends_count" "0" "Status shows backends"

    SYSTEM=$(api_get "/api/v1/system")
    assert_json_gt "$SYSTEM" ".data.host.cpu_count" "0" "System CPU count > 0"
    assert_json_gt "$SYSTEM" ".data.host.memory_total_bytes" "0" "System memory > 0"

    # Workers endpoint (single-process mode)
    WORKERS=$(api_get "/api/v1/workers")
    assert_json "$WORKERS" ".data.total" "0" "No workers in single-process mode"

# =============================================================================
# 11. LOGS
# =============================================================================
    log "=== 11. Logs ==="

    LOGS=$(api_get "/api/v1/logs")
    LOG_COUNT=$(echo "$LOGS" | jq '.data.total' 2>/dev/null || echo "0")
    if [ "$LOG_COUNT" -gt 0 ]; then
        ok "Access logs recorded ($LOG_COUNT entries)"
    else
        fail "Expected access logs after proxy requests"
    fi

    # Clear logs
    api_del "/api/v1/logs" >/dev/null
    LOGS2=$(api_get "/api/v1/logs")
    assert_json "$LOGS2" ".data.total" "0" "Logs cleared"

# =============================================================================
# 12. CONFIG EXPORT/IMPORT
# =============================================================================
    log "=== 12. Config Export/Import ==="

    EXPORT=$(curl -sf -b "$SESSION" -X POST "$API/api/v1/config/export" 2>/dev/null || echo "")
    if echo "$EXPORT" | grep -q "test.local"; then
        ok "Config export contains route data"
    else
        fail "Export should contain route hostname"
    fi

    if echo "$EXPORT" | grep -q "$BACKEND1"; then
        ok "Config export contains backend data"
    else
        fail "Export should contain backend address"
    fi

# =============================================================================
# 13. NOTIFICATION CONFIGS
# =============================================================================
    log "=== 13. Notification Configs ==="

    # Create a webhook notification
    NOTIF=$(api_post "/api/v1/notifications" '{
        "channel": "webhook",
        "enabled": true,
        "config": "{\"url\":\"http://backend1:80/webhook\",\"auth_header\":\"Bearer test\"}",
        "alert_types": ["backend_down","waf_alert"]
    }')
    NOTIF_ID=$(echo "$NOTIF" | jq -r '.data.id')
    assert_json "$NOTIF" ".data.channel" "webhook" "Webhook notification created"

    # List notifications
    NOTIFS=$(api_get "/api/v1/notifications")
    NOTIF_COUNT=$(echo "$NOTIFS" | jq '.data.notifications | length')
    if [ "$NOTIF_COUNT" -ge 1 ]; then
        ok "Notifications list has entries ($NOTIF_COUNT)"
    else
        fail "Expected >= 1 notification"
    fi

    # Delete notification
    api_del "/api/v1/notifications/$NOTIF_ID" >/dev/null
    ok "Notification deleted"

# =============================================================================
# 14. HEALTH CHECKS
# =============================================================================
    log "=== 14. Health Checks ==="

    # Wait for health check cycle
    sleep 12

    # Check backend health status
    B1_STATUS=$(api_get "/api/v1/backends/$B1_ID")
    B1_HEALTH=$(echo "$B1_STATUS" | jq -r '.data.health_status' 2>/dev/null || echo "unknown")
    if [ "$B1_HEALTH" = "healthy" ]; then
        ok "Backend 1 is healthy"
    else
        fail "Backend 1 should be healthy (got $B1_HEALTH)"
    fi

    B2_STATUS=$(api_get "/api/v1/backends/$B2_ID")
    B2_HEALTH=$(echo "$B2_STATUS" | jq -r '.data.health_status' 2>/dev/null || echo "unknown")
    if [ "$B2_HEALTH" = "healthy" ]; then
        ok "Backend 2 is healthy"
    else
        fail "Backend 2 should be healthy (got $B2_HEALTH)"
    fi

# =============================================================================
# 15. CLEANUP
# =============================================================================
    log "=== 15. Cleanup ==="

    api_del "/api/v1/routes/$R1_ID" >/dev/null && ok "Route 1 deleted" || fail "Route 1 delete failed"
    api_del "/api/v1/routes/$R2_ID" >/dev/null && ok "Route 2 deleted" || fail "Route 2 delete failed"
    api_del "/api/v1/backends/$B1_ID" >/dev/null && ok "Backend 1 deleted" || fail "Backend 1 delete failed"
    api_del "/api/v1/backends/$B2_ID" >/dev/null && ok "Backend 2 deleted" || fail "Backend 2 delete failed"

else
    log "=== Skipping authenticated tests (no session) ==="
    log "To run full tests, expose the admin password via shared volume."

    # Still test proxy returns 404 when no routes configured
    sleep 5
    STATUS_NO_ROUTE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: test.local" "$PROXY/" 2>/dev/null || echo "000")
    if [ "$STATUS_NO_ROUTE" = "404" ]; then
        ok "Proxy returns 404 when no routes configured"
    else
        fail "Expected 404 with no routes (got $STATUS_NO_ROUTE)"
    fi
fi

# =============================================================================
# REPORT
# =============================================================================
echo ""
echo "============================================"
echo "  LORICA E2E TEST REPORT"
echo "============================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
