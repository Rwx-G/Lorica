#!/usr/bin/env bash
# =============================================================================
# Lorica GeoIP E2E smoke test (v1.4.0 story 2.7).
#
# Pre-requisite: docker-compose `geoip` profile is up. `lorica-geoip`
# is started with MaxMind's open `GeoIP2-Country-Test.mmdb` fixture
# mounted at `/var/lib/lorica/geoip-test.mmdb` (volume mount, see
# docker-compose.yml). The smoke test itself sets `geoip_db_path` and
# `trusted_proxies` over the management API and relies on the
# `apply_geoip_settings_from_store` hot-reload hook to swap the
# resolver live. This exercises the v1.4.0 hot-reload path end-to-end
# rather than the boot-time load.
#
# The fixture's useful IP ranges (from
# github.com/maxmind/MaxMind-DB/source-data/GeoIP2-Country-Test.json):
#
#   214.78.120.0/22        → US
#   2001:218::/32          → JP
#   2001:220::1/128        → KR
#   (anything else)        → unknown (resolver returns None)
#
# Test flow:
#   1. Wait for backend1 + Lorica API.
#   2. Login + first-run password rotation.
#   3. Baseline scrape of /metrics for `lorica_geoip_block_total`.
#   4. Create a backend + route `geoip-test.local` with
#      `geoip: {mode: denylist, countries: [US]}`.
#   5. Drive requests with XFF pointing at US, KR, and unknown IPs.
#      Expect: US=403, KR=200, unknown=200 (fallthrough).
#   6. Update the route to `mode: allowlist, countries: [US]`,
#      wait for reload, drive the same three probes.
#      Expect: US=200, KR=403, unknown=403.
#   7. Scrape /metrics and assert the counter incremented for the
#      (route_id, country=US, mode=denylist) and
#      (route_id, country=KR, mode=allowlist) label combos.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"

# Known fixture IPs.
IP_US="214.78.120.5"
IP_KR="2001:220::1"
IP_UNKNOWN="192.0.2.1"  # TEST-NET-1 per RFC5737, absent from the fixture

log "=== GeoIP smoke: preflight ==="
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

# --- Login + first-run password rotation (shared with other smokes) --------
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

MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="GeoIpSmokePassword!42"
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

# --- Configure GeoIP DB path + trusted_proxies via API (hot-reload path) ---
# Set `trusted_proxies` so the XFF header injected by the test runner
# is honoured, and point `geoip_db_path` at the mounted fixture. The
# `apply_geoip_settings_from_store` hook in `lorica::reload` picks up
# the path and `load_from_path`s it atomically.
log "=== GeoIP smoke: configure DB path + trusted_proxies (hot-reload) ==="
SETTINGS_UPDATE=$(api_put /api/v1/settings '{
    "geoip_db_path": "/var/lib/lorica/geoip-test.mmdb",
    "trusted_proxies": ["0.0.0.0/0", "::/0"]
}')
SET_PATH=$(echo "$SETTINGS_UPDATE" | jq -r '.data.geoip_db_path // empty')
if [ "$SET_PATH" = "/var/lib/lorica/geoip-test.mmdb" ]; then
    ok "geoip_db_path persisted"
else
    fail "geoip_db_path update: got '$SET_PATH', body=$SETTINGS_UPDATE"
    exit 1
fi

# The reload fires asynchronously; give it a moment to run
# apply_geoip_settings_from_store -> load_from_path before the first
# probe exercises the resolver.
sleep 2

# Confirm the hot-reload actually loaded the DB by looking for the
# success log line. Cheap regression guard against a future refactor
# that forgets to wire the geoip hook into reload_proxy_config_with_mtls.
if grep -q "GeoIP database hot-reloaded" /shared/lorica.log 2>/dev/null; then
    ok "GeoIP hot-reload log line present"
else
    fail "GeoIP hot-reload log line missing (resolver may not have loaded)"
    tail -30 /shared/lorica.log 2>/dev/null || true
fi

# --- Baseline metrics scrape -----------------------------------------------
# Helper: read current value of `lorica_geoip_block_total` for a given
# label combo. Returns 0 if the counter has never incremented (the
# line is absent from the Prometheus response). This mirrors how the
# story 2.5 unit test interrogates the counter, but over the wire.
get_geoip_counter() {
    local route_id="$1" country="$2" mode="$3"
    local val
    val=$(curl -sf "$API/metrics" 2>/dev/null \
        | grep "^lorica_geoip_block_total{" \
        | grep "route_id=\"$route_id\"" \
        | grep "country=\"$country\"" \
        | grep "mode=\"$mode\"" \
        | awk '{print $NF}' \
        | head -1)
    # Counter lines only appear after the first inc, so absence means
    # "0" — default explicitly rather than letting empty flow into the
    # `-gt` arithmetic comparison below (bash errors on empty operand).
    if [ -z "$val" ]; then
        echo "0"
    else
        echo "$val"
    fi
}

# --- Create backend + denylist route ---------------------------------------
log "=== GeoIP smoke: create test route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"geoip-backend1\",
    \"group\": \"geoip\",
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
    \"hostname\": \"geoip-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"geoip\": {\"mode\": \"denylist\", \"countries\": [\"US\"]}
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
if [ -z "$ROUTE_ID" ]; then
    fail "route create: $ROUTE"
    exit 1
fi
ok "route created with denylist=[US] (id=$ROUTE_ID)"

# Give the reload broadcast time to reach the proxy config Arc swap.
sleep 2

# Baseline counters for the route we just created.
BASELINE_US_DENY=$(get_geoip_counter "$ROUTE_ID" "US" "denylist")
BASELINE_KR_ALLOW=$(get_geoip_counter "$ROUTE_ID" "KR" "allowlist")
log "baseline counters US/deny=$BASELINE_US_DENY KR/allow=$BASELINE_KR_ALLOW"

# --- Denylist probes -------------------------------------------------------
log "=== GeoIP smoke: denylist probes ==="
probe() {
    local xff="$1" label="$2"
    curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: geoip-test.local" \
        -H "X-Forwarded-For: $xff" \
        "${PROXY}/"
}

CODE_US=$(probe "$IP_US" "US")
if [ "$CODE_US" = "403" ]; then
    ok "denylist blocks US IP ($IP_US)"
else
    fail "denylist US IP expected 403, got $CODE_US"
fi

CODE_KR=$(probe "$IP_KR" "KR")
if [ "$CODE_KR" = "200" ]; then
    ok "denylist passes KR IP ($IP_KR)"
else
    fail "denylist KR IP expected 200, got $CODE_KR"
fi

CODE_UNK=$(probe "$IP_UNKNOWN" "unknown")
if [ "$CODE_UNK" = "200" ]; then
    ok "denylist passes unknown IP ($IP_UNKNOWN) [fallthrough]"
else
    fail "denylist unknown IP expected 200 (fallthrough), got $CODE_UNK"
fi

# --- Switch to allowlist and re-probe --------------------------------------
log "=== GeoIP smoke: switch route to allowlist=[US] ==="
UPDATE=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"geoip-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"geoip\": {\"mode\": \"allowlist\", \"countries\": [\"US\"]}
}")
UPDATE_MODE=$(echo "$UPDATE" | jq -r '.data.geoip.mode // empty')
if [ "$UPDATE_MODE" = "allowlist" ]; then
    ok "route updated to allowlist"
else
    fail "route update: expected allowlist, body=$UPDATE"
    exit 1
fi

sleep 2

log "=== GeoIP smoke: allowlist probes ==="
CODE_US=$(probe "$IP_US" "US")
if [ "$CODE_US" = "200" ]; then
    ok "allowlist passes US IP ($IP_US)"
else
    fail "allowlist US IP expected 200, got $CODE_US"
fi

CODE_KR=$(probe "$IP_KR" "KR")
if [ "$CODE_KR" = "403" ]; then
    ok "allowlist blocks KR IP ($IP_KR)"
else
    fail "allowlist KR IP expected 403, got $CODE_KR"
fi

# Unknown country falls through for BOTH modes - design choice in
# proxy_wiring so a client behind a corporate NAT (private IP, no
# country mapping) is never accidentally denied under an allowlist
# rule. Operators wanting strict fail-close pair GeoIP with a
# connection_allow_cidrs or route.ip_allowlist layer.
CODE_UNK=$(probe "$IP_UNKNOWN" "unknown")
if [ "$CODE_UNK" = "200" ]; then
    ok "allowlist fallthrough on unknown IP ($IP_UNKNOWN) [per design]"
else
    fail "allowlist unknown IP expected 200 (fallthrough), got $CODE_UNK"
fi

# --- Metrics assertions ----------------------------------------------------
log "=== GeoIP smoke: Prometheus counter ==="
AFTER_US_DENY=$(get_geoip_counter "$ROUTE_ID" "US" "denylist")
AFTER_KR_ALLOW=$(get_geoip_counter "$ROUTE_ID" "KR" "allowlist")

# For `assert` we need integer comparisons even when the counter is
# reported as "0" (grep miss) - bash handles them the same way.
if [ "$AFTER_US_DENY" -gt "$BASELINE_US_DENY" ] 2>/dev/null; then
    ok "lorica_geoip_block_total{route_id,US,denylist} incremented ($BASELINE_US_DENY -> $AFTER_US_DENY)"
else
    fail "lorica_geoip_block_total{route_id,US,denylist} did not increment ($BASELINE_US_DENY -> $AFTER_US_DENY)"
fi

if [ "$AFTER_KR_ALLOW" -gt "$BASELINE_KR_ALLOW" ] 2>/dev/null; then
    ok "lorica_geoip_block_total{route_id,KR,allowlist} incremented ($BASELINE_KR_ALLOW -> $AFTER_KR_ALLOW)"
else
    fail "lorica_geoip_block_total{route_id,KR,allowlist} did not increment ($BASELINE_KR_ALLOW -> $AFTER_KR_ALLOW)"
fi

# --- Summary ---------------------------------------------------------------
log "=== GeoIP smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
