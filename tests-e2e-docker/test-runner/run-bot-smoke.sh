#!/usr/bin/env bash
# =============================================================================
# Lorica bot-protection E2E smoke test (v1.4.0 story 3.9).
#
# Pre-requisite: docker-compose `bot` profile is up.
# `lorica-bot` runs the default entrypoint (no pre-seeding — the
# test exercises the hot-reload path for trusted_proxies and uses
# the API to configure everything).
#
# Test matrix:
#   1. Cookie mode: a fresh request renders the HTML refresh page
#      AND sets the verdict cookie in the same response. A follow-up
#      request with the cookie passes through to the backend.
#   2. JavaScript mode: initial request renders the PoW page; the
#      test runner extracts the nonce + difficulty from the HTML,
#      mines a counter via a tiny Python helper, POSTs the solution,
#      receives a 302 + Set-Cookie, and verifies the next request
#      passes.
#   3. Captcha mode: initial request renders the captcha page; the
#      test runner extracts the stash nonce AND fetches the image.
#      Since solving a real image captcha from a shell is not
#      feasible, we read the expected text out of the stash by a
#      side channel — in v1.4.0 no such channel exists, so the
#      captcha mode test asserts the rendering only (page served,
#      image URL returns 200 image/png, form present). Full solve
#      round-trip is deferred to a follow-up.
#   4. Bypass matrix:
#      a. IP CIDR: client IP in the allow-list CIDR passes without
#         seeing the challenge.
#      b. Country: client's resolved country in the bypass list
#         passes. Requires the GeoIP fixture mounted into the
#         container (reuses tests-e2e-docker/fixtures/*.mmdb from
#         the geoip profile).
#      c. User-Agent: UA matching one of the regex patterns passes.
#      d. `only_country` gate miss: a client whose country is NOT
#         in `only_country` passes without being challenged.
#   5. Metrics: `lorica_bot_challenge_total` counter increments for
#      outcome ∈ { shown, passed, bypassed } as traffic fires.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"

# Fixture IPs taken from the MaxMind GeoIP2-Country-Test.mmdb we
# already ship under tests-e2e-docker/fixtures/. One known-US
# IPv4, one unknown IPv4 outside every indexed range so the GeoIP
# resolver returns None.
IP_US="214.78.120.5"
IP_UNKNOWN="192.0.2.1"

log "=== bot smoke: preflight ==="
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

# --- Login + first-run password rotation ---------------------------------
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
    NEW_PW="BotSmokePassword!42"
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
    rm -f "$RELOGIN_HEADERS"
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ok "session ready"

# --- Configure trusted_proxies + GeoIP DB via API ------------------------
# trusted_proxies so the test runner can inject XFF. geoip_db_path
# points at the MaxMind test fixture mounted into the container so
# country-based bypass actually resolves. Both settings hot-reload
# via the v1.4.0 apply_*_from_store hooks.
log "=== bot smoke: configure global settings ==="
SET=$(api_put /api/v1/settings '{
    "trusted_proxies": ["0.0.0.0/0", "::/0"],
    "geoip_db_path": "/var/lib/lorica/geoip-test.mmdb"
}')
[ "$(echo "$SET" | jq -r '.data.geoip_db_path // empty')" = "/var/lib/lorica/geoip-test.mmdb" ] \
    && ok "trusted_proxies + geoip_db_path persisted" \
    || fail "settings update failed: $SET"

sleep 2

# Baseline Prometheus counter getter. Empty/missing returns "0".
get_counter() {
    local route_id="$1" mode="$2" outcome="$3"
    local v
    v=$(curl -sf "$API/metrics" 2>/dev/null \
        | grep "^lorica_bot_challenge_total{" \
        | grep "route_id=\"$route_id\"" \
        | grep "mode=\"$mode\"" \
        | grep "outcome=\"$outcome\"" \
        | awk '{print $NF}' | head -1)
    [ -z "$v" ] && echo "0" || echo "$v"
}

# --- Set up a backend + a route we will re-configure per mode ------------
log "=== bot smoke: create backend + route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"bot-backend1\",
    \"group\": \"bot\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"cookie\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {}
    }
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "route created (id=$ROUTE_ID), mode=cookie"

sleep 2

# --- Mode: Cookie --------------------------------------------------------
log "=== bot smoke: mode=cookie ==="
# Use --cookie-jar so curl captures Set-Cookie and replays on the
# follow-up request.
JAR=$(mktemp)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ]; then
    ok "cookie mode: challenge page served (HTTP 200)"
else
    fail "cookie mode: expected 200 on challenge render, got $CODE"
fi
# Verdict cookie must be present in the jar.
if grep -q lorica_bot_verdict "$JAR"; then
    ok "cookie mode: Set-Cookie issued in challenge response"
else
    fail "cookie mode: Set-Cookie missing from jar"
fi
# Replay with the cookie jar → backend responds (not the refresh
# page).
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ]; then
    ok "cookie mode: verdict cookie grants passthrough"
else
    fail "cookie mode: passthrough expected 200, got $CODE"
fi
rm -f "$JAR"

# --- Mode: JavaScript PoW -------------------------------------------------
log "=== bot smoke: switch to mode=javascript (difficulty=14) ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {}
    }
}")
[ "$(echo "$UP" | jq -r '.data.bot_protection.mode // empty')" = "javascript" ] \
    && ok "route switched to javascript mode" \
    || fail "route switch: $UP"
sleep 2

# Render the challenge page, extract nonce + difficulty.
PAGE=$(mktemp)
curl -s -o "$PAGE" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "Accept: text/html" \
    "${PROXY}/"
NONCE=$(grep -o 'NONCE_HEX = "[0-9a-f]*"' "$PAGE" | head -1 | sed 's/.*"\([0-9a-f]*\)".*/\1/')
DIFF=$(grep -o 'DIFFICULTY = [0-9]*' "$PAGE" | head -1 | awk '{print $NF}')
if [ -n "$NONCE" ] && [ "$DIFF" = "14" ]; then
    ok "pow challenge: nonce=$NONCE difficulty=$DIFF"
else
    fail "pow challenge: nonce/difficulty extraction failed"
    tail -20 "$PAGE" 2>/dev/null | head -10
    exit 1
fi
rm -f "$PAGE"

# Solve the PoW via a tiny Python helper (SHA-256 over the
# concatenation of the hex nonce and the decimal counter, mine
# until `difficulty` leading zero bits). At difficulty=14 this
# takes ~16k attempts median (sub-second).
log "=== bot smoke: mining PoW (difficulty=$DIFF) ==="
COUNTER=$(python3 - "$NONCE" "$DIFF" <<'PY'
import hashlib, sys
nonce = sys.argv[1]
diff = int(sys.argv[2])
full = diff // 8
rem = diff % 8
mask = (0xFF << (8 - rem)) & 0xFF if rem else 0
for c in range(0, 10_000_000):
    d = hashlib.sha256((nonce + str(c)).encode()).digest()
    if all(b == 0 for b in d[:full]):
        if rem == 0 or (d[full] & mask) == 0:
            print(c)
            sys.exit(0)
sys.exit(1)
PY
)
if [ -n "$COUNTER" ]; then
    ok "pow solved: counter=$COUNTER"
else
    fail "pow solve failed"
    exit 1
fi

# Submit the solution. Expect 302 + Set-Cookie. -L follows the
# redirect; the redirect target + cookie should now get us
# through the backend.
JAR=$(mktemp)
POST_HEAD=$(mktemp)
HTTP=$(curl -s -o /dev/null -D "$POST_HEAD" -w '%{http_code}' -c "$JAR" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "nonce=${NONCE}&counter=${COUNTER}" \
    "${PROXY}/lorica/bot/solve")
if [ "$HTTP" = "302" ]; then
    ok "pow solve: HTTP 302 redirect"
else
    fail "pow solve: expected 302, got $HTTP"
fi
if grep -q lorica_bot_verdict "$JAR"; then
    ok "pow solve: verdict cookie issued"
else
    fail "pow solve: verdict cookie missing"
fi
rm -f "$POST_HEAD"

# Replay with the cookie — should now passthrough to backend.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ]; then
    ok "pow mode: verdict cookie grants passthrough"
else
    fail "pow passthrough: expected 200, got $CODE"
fi

# Wrong counter must be rejected with 403.
BAD_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "nonce=${NONCE}&counter=0" \
    "${PROXY}/lorica/bot/solve")
# Note: the entry was consumed on first take(); a second solve for
# the same nonce returns 403 "challenge expired or unknown"
# regardless of the counter. Both outcomes collapse to 403.
if [ "$BAD_HTTP" = "403" ]; then
    ok "pow solve: wrong / replayed counter rejected with 403"
else
    fail "pow solve: replay expected 403, got $BAD_HTTP"
fi
rm -f "$JAR"

# --- Mode: Captcha (render-only, no human to type the answer) --------------
log "=== bot smoke: switch to mode=captcha ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"captcha\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {}
    }
}")
[ "$(echo "$UP" | jq -r '.data.bot_protection.mode // empty')" = "captcha" ] \
    && ok "route switched to captcha mode" \
    || fail "route switch: $UP"
sleep 2

PAGE=$(mktemp)
curl -s -o "$PAGE" \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "Accept: text/html" \
    "${PROXY}/"
CAPTCHA_NONCE=$(grep -oE '/lorica/bot/captcha/[0-9a-f]+' "$PAGE" | head -1 | sed 's|.*/||')
if [ -n "$CAPTCHA_NONCE" ]; then
    ok "captcha page: nonce extracted ($CAPTCHA_NONCE)"
else
    fail "captcha page: image URL not found"
    cat "$PAGE" | head -20
fi
rm -f "$PAGE"

# Fetch the image. Must be 200 image/png.
IMG_HEAD=$(mktemp)
IMG_CODE=$(curl -s -o /dev/null -D "$IMG_HEAD" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    "${PROXY}/lorica/bot/captcha/${CAPTCHA_NONCE}")
if [ "$IMG_CODE" = "200" ]; then
    ok "captcha image: HTTP 200"
else
    fail "captcha image: expected 200, got $IMG_CODE"
fi
CT=$(grep -i '^Content-Type:' "$IMG_HEAD" | head -1 | tr -d '\r')
if echo "$CT" | grep -qi "image/png"; then
    ok "captcha image: Content-Type image/png"
else
    fail "captcha image: expected image/png, got '$CT'"
fi
rm -f "$IMG_HEAD"

# Unknown nonce → 404.
CODE_404=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: bot-test.local" \
    "${PROXY}/lorica/bot/captcha/unknown-nonce-value")
if [ "$CODE_404" = "404" ]; then
    ok "captcha image: unknown nonce returns 404"
else
    fail "captcha image: unknown nonce expected 404, got $CODE_404"
fi

# --- Bypass matrix: IP CIDR ----------------------------------------------
log "=== bot smoke: bypass matrix — IP CIDR ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {\"ip_cidrs\": [\"203.0.113.0/24\"]}
    }
}")
sleep 2
RESP=$(mktemp)
CODE=$(curl -s -o "$RESP" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: 203.0.113.42" \
    -H "Accept: text/html" \
    "${PROXY}/")
# Bypass → backend responds directly. The backend echoes request
# details, not the PoW page. Grepping for "crypto.subtle" is a
# reliable marker for the PoW page.
if [ "$CODE" = "200" ] && ! grep -q "crypto.subtle" "$RESP"; then
    ok "bypass IP CIDR: client in 203.0.113.0/24 → backend passthrough"
else
    fail "bypass IP CIDR: expected backend response, got $CODE with PoW=$(grep -c crypto.subtle "$RESP")"
fi
rm -f "$RESP"

# Out-of-CIDR client still sees the challenge.
RESP=$(mktemp)
CODE=$(curl -s -o "$RESP" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: 198.51.100.42" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ] && grep -q "crypto.subtle" "$RESP"; then
    ok "bypass IP CIDR: client outside /24 still challenged"
else
    fail "bypass IP CIDR: outside /24 expected challenge, body missing PoW"
fi
rm -f "$RESP"

# --- Bypass matrix: country ----------------------------------------------
log "=== bot smoke: bypass matrix — country ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {\"countries\": [\"US\"]}
    }
}")
sleep 2
RESP=$(mktemp)
CODE=$(curl -s -o "$RESP" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_US" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ] && ! grep -q "crypto.subtle" "$RESP"; then
    ok "bypass country: US client → backend passthrough"
else
    fail "bypass country: US client expected passthrough, got challenge"
fi
rm -f "$RESP"

# --- Bypass matrix: User-Agent regex -------------------------------------
log "=== bot smoke: bypass matrix — User-Agent regex ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {\"user_agents\": [\"(?i)uptimebot\"]}
    }
}")
sleep 2
RESP=$(mktemp)
CODE=$(curl -s -o "$RESP" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_UNKNOWN" \
    -H "User-Agent: Mozilla/5.0 (compatible; UptimeBot/1.0)" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ] && ! grep -q "crypto.subtle" "$RESP"; then
    ok "bypass UA regex: UptimeBot matches → backend passthrough"
else
    fail "bypass UA regex: UptimeBot expected passthrough"
fi
rm -f "$RESP"

# --- only_country gate: miss passes --------------------------------------
log "=== bot smoke: only_country gate miss passes ==="
UP=$(api_put "/api/v1/routes/${ROUTE_ID}" "{
    \"hostname\": \"bot-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {},
        \"only_country\": [\"RU\", \"CN\"]
    }
}")
sleep 2
# US client is NOT in only_country → passes without challenge.
RESP=$(mktemp)
CODE=$(curl -s -o "$RESP" -w '%{http_code}' \
    -H "Host: bot-test.local" \
    -H "X-Forwarded-For: $IP_US" \
    -H "Accept: text/html" \
    "${PROXY}/")
if [ "$CODE" = "200" ] && ! grep -q "crypto.subtle" "$RESP"; then
    ok "only_country gate: US client not in [RU, CN] → passthrough"
else
    fail "only_country gate: expected passthrough for US client, got challenge"
fi
rm -f "$RESP"

# --- Metrics assertions --------------------------------------------------
log "=== bot smoke: Prometheus counter sanity ==="
# After the many challenge renders above, the `shown` counter for
# mode=javascript should be non-zero.
SHOWN=$(get_counter "$ROUTE_ID" "javascript" "shown")
if [ "$SHOWN" -gt 0 ] 2>/dev/null; then
    ok "lorica_bot_challenge_total{mode=javascript, outcome=shown} = $SHOWN"
else
    fail "shown counter expected > 0, got '$SHOWN'"
fi
# `passed` should be non-zero from the cookie mode success + pow solve.
PASSED_COOKIE=$(get_counter "$ROUTE_ID" "cookie" "passed")
PASSED_POW=$(get_counter "$ROUTE_ID" "javascript" "passed")
if [ "$PASSED_COOKIE" -gt 0 ] 2>/dev/null; then
    ok "lorica_bot_challenge_total{mode=cookie, outcome=passed} = $PASSED_COOKIE"
else
    fail "cookie passed expected > 0, got '$PASSED_COOKIE'"
fi
if [ "$PASSED_POW" -gt 0 ] 2>/dev/null; then
    ok "lorica_bot_challenge_total{mode=javascript, outcome=passed} = $PASSED_POW"
else
    fail "pow passed expected > 0, got '$PASSED_POW'"
fi
# `bypassed` from the bypass-matrix probes above.
BYPASSED=$(get_counter "$ROUTE_ID" "javascript" "bypassed")
if [ "$BYPASSED" -gt 0 ] 2>/dev/null; then
    ok "lorica_bot_challenge_total{mode=javascript, outcome=bypassed} = $BYPASSED"
else
    fail "bypassed counter expected > 0, got '$BYPASSED'"
fi

log "=== bot smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
