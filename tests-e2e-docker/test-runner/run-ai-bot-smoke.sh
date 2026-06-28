#!/usr/bin/env bash
# =============================================================================
# Lorica AI / LLM crawler deny-list E2E smoke test (Story 8.2, IV4).
#
# Pre-requisite: docker-compose `ai-bot` (or `ai-bot-workers`) profile is up.
# `lorica-ai-bot` runs the default entrypoint (socat + password scrape); the
# smoke drives everything over the management API.
#
# Docker-environment constraint that shapes the whole matrix
# ----------------------------------------------------------
# The test-runner's source IP lives on the docker `e2e` subnet, never inside
# a real vendor CIDR (OpenAI etc.). So a built-in `GPTBot` (IpRanges-verified)
# request from this runner is ALWAYS classified Spoofed. We use that on
# purpose:
#   - GPTBot exercises the spoofed-fallback chain (treat_spoofed_as / per-route
#     ai_bot_spoofed_fallback).
#   - Bytespider (built-in UaOnly) exercises the clean ApplyPolicy path
#     (Off / Log / Deny) with no IP dependency.
#   - A CUSTOM ip_ranges crawler (`MyTestBot`) whose CIDR is the runner's own
#     /32 is in-range, so it exercises the verified ApplyPolicy + AC #11
#     header-injection path.
# This is faithful to `check_ai_bot` in lorica/src/proxy_wiring/filters.rs:
# IpRanges verification reaches ApplyPolicy only when the peer IP is in-range;
# otherwise it is Spoofed regardless of the route policy.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"

# Set to 1 by the workers-mode runner: the in-process 5-minute stats
# buffer and the Prometheus ai_bot counter live in the worker processes
# while /metrics + /stats run in the supervisor, so cross-process counter
# aggregation is not guaranteed. The data-plane 403/200/header behavior is
# identical in both modes and is asserted unconditionally.
SKIP_METRICS="${AI_BOT_SMOKE_SKIP_METRICS:-0}"

log "=== ai-bot smoke: preflight ==="
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

# --- Login + first-run password rotation (mirrors run-bot-smoke.sh) -------
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
    NEW_PW="AiBotSmokePassword!42"
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

# Runner's own IP on the e2e network. The proxy sees this as the direct TCP
# peer (trusted_proxies is left at its empty secure default, so no XFF is
# consulted). We feed it as the custom crawler's /32 CIDR so an in-range
# verified path is reachable from this container.
# python3 is guaranteed in the test-runner image (used by the bot smoke);
# getent is not (no musl-utils), so resolve the container's primary IP via
# the stdlib. hostname -i is the busybox fallback.
RUNNER_IP=$(python3 -c 'import socket; print(socket.gethostbyname(socket.gethostname()))' 2>/dev/null || true)
[ -n "$RUNNER_IP" ] || RUNNER_IP=$(hostname -i 2>/dev/null | awk '{print $1}')
[ -n "$RUNNER_IP" ] || { fail "could not determine runner IP"; exit 1; }
ok "runner IP on e2e network: $RUNNER_IP"

# --- Global settings: pin AC #3 + AC #11 knobs to known values ------------
# Defaults already are treat_spoofed_as=deny + inject_headers=true, but set
# them explicitly so the smoke is hermetic against future default changes.
log "=== ai-bot smoke: configure global settings ==="
SET=$(api_put /api/v1/settings '{
    "ai_bot_treat_spoofed_as": "deny",
    "ai_bot_inject_headers": true
}')
[ "$(echo "$SET" | jq -r '.data.ai_bot_treat_spoofed_as // empty')" = "deny" ] \
    && ok "ai_bot_treat_spoofed_as=deny persisted" \
    || fail "settings update failed: $SET"
[ "$(echo "$SET" | jq -r '.data.ai_bot_inject_headers // empty')" = "true" ] \
    && ok "ai_bot_inject_headers=true persisted" \
    || fail "ai_bot_inject_headers persist failed: $SET"

# --- Backend + two routes -------------------------------------------------
log "=== ai-bot smoke: create backend + routes ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"ai-backend1\",
    \"group\": \"ai\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"ai-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"ai_bot_policy\": \"off\"
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "main route created (id=$ROUTE_ID, policy=off)"

ROUTE_ROBOTS=$(api_post /api/v1/routes "{
    \"hostname\": \"ai-robots.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"ai_bot_policy\": \"deny\",
    \"serve_robots_txt\": true
}")
ROBOTS_ID=$(echo "$ROUTE_ROBOTS" | jq -r '.data.id // empty')
[ -n "$ROBOTS_ID" ] || { fail "robots route create: $ROUTE_ROBOTS"; exit 1; }
ok "robots route created (id=$ROBOTS_ID, serve_robots_txt=true, policy=deny)"

# Dedicated routes for the spoofed-fallback matrix, one per fallback value.
# Each is created once with policy=deny and a fixed ai_bot_spoofed_fallback,
# then never mutated. This is deliberate: rapid successive PUTs to the SAME
# route's ai_bot_spoofed_fallback field do not converge promptly on the data
# plane (the config-reload pipeline coalesces a burst of edits to one route),
# so a toggle-in-place design flakes. One stable route per value sidesteps it
# entirely. GPTBot (built-in IpRanges) from the runner IP is always Spoofed,
# so each route's fixed fallback fully determines the outcome.
create_spoof_route() {
    local host="$1" fallback_json="$2"
    api_post /api/v1/routes "{
        \"hostname\": \"$host\",
        \"path_prefix\": \"/\",
        \"backend_ids\": [\"${BACKEND_ID}\"],
        \"enabled\": true,
        \"ai_bot_policy\": \"deny\"${fallback_json}
    }" | jq -r '.data.id // empty'
}
# inherit -> defers to global ai_bot_treat_spoofed_as=deny.
SPOOF_DENY_ID=$(create_spoof_route "ai-spoof-deny.local" "")
SPOOF_ALLOW_ID=$(create_spoof_route "ai-spoof-allow.local" ", \"ai_bot_spoofed_fallback\": \"allow\"")
SPOOF_LOG_ID=$(create_spoof_route "ai-spoof-log.local" ", \"ai_bot_spoofed_fallback\": \"log\"")
{ [ -n "$SPOOF_DENY_ID" ] && [ -n "$SPOOF_ALLOW_ID" ] && [ -n "$SPOOF_LOG_ID" ]; } \
    || { fail "spoof routes create failed"; exit 1; }
ok "spoof routes created (deny=$SPOOF_DENY_ID allow=$SPOOF_ALLOW_ID log=$SPOOF_LOG_ID)"

# --- Custom ip_ranges crawler scoped to the runner /32 --------------------
log "=== ai-bot smoke: create custom ip_ranges crawler (MyTestBot) ==="
CUSTOM=$(api_post /api/v1/ai-crawlers/custom "{
    \"name\": \"MyTestBot\",
    \"user_agent_pattern\": \"(?i)\\\\bMyTestBot\\\\b\",
    \"verification\": {\"kind\": \"ip_ranges\", \"cidrs\": [\"${RUNNER_IP}/32\"]},
    \"enabled\": true
}")
MYTESTBOT_ID=$(echo "$CUSTOM" | jq -r '.data.id // empty')
[ -n "$MYTESTBOT_ID" ] || { fail "custom crawler create: $CUSTOM"; exit 1; }
ok "custom crawler MyTestBot created (id=$MYTESTBOT_ID, cidr=${RUNNER_IP}/32)"

# Allow the merged registry hot-reload (and worker RPC propagation) to land.
sleep 3

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------
# Send a data-plane request and return the HTTP status only.
proxy_code() {
    local host="$1" ua="$2" path="${3:-/}"
    curl -s -o /dev/null -w '%{http_code}' \
        -H "Host: $host" -H "User-Agent: $ua" "${PROXY}${path}"
}

# Assert a data-plane status, retrying to absorb hot-reload propagation
# lag (config changes are eventually-consistent across the worker RPC /
# arc-swap publish; a fixed sleep flakes, a bounded retry does not).
expect_code() {
    local host="$1" ua="$2" expected="$3" label="$4" tries="${5:-20}"
    local code=""
    for _ in $(seq 1 "$tries"); do
        code=$(proxy_code "$host" "$ua")
        [ "$code" = "$expected" ] && break
        sleep 1
    done
    [ "$code" = "$expected" ] && ok "$label (HTTP $code)" \
        || fail "$label (expected $expected, got $code)"
}

# Block until a data-plane request converges to the expected status, with
# no assertion emitted. Used as a convergence gate after a config change so
# the following assertions are not racing the hot-reload publish.
wait_code() {
    local host="$1" ua="$2" expected="$3" tries="${4:-30}"
    local code=""
    for _ in $(seq 1 "$tries"); do
        code=$(proxy_code "$host" "$ua")
        [ "$code" = "$expected" ] && return 0
        sleep 1
    done
    return 1
}

# Set the main route's ai_bot_policy (partial update).
set_policy() {
    api_put "/api/v1/routes/${ROUTE_ID}" "{\"ai_bot_policy\":\"$1\"}" >/dev/null
    sleep 2
}

# Read one (lowercased) header value the backend echoed back from /echo.
echo_header() {
    local host="$1" ua="$2" header="$3"
    shift 3
    curl -s -H "Host: $host" -H "User-Agent: $ua" "$@" "${PROXY}/echo" \
        | jq -r ".received_headers[\"$header\"] // empty"
}

# Prometheus ai_bot counter getter (single-process only). Missing -> "0".
get_ai_counter() {
    local crawler="$1" action="$2" route="${3:-$ROUTE_ID}"
    local v
    v=$(curl -sf "$API/metrics" 2>/dev/null \
        | grep "^lorica_ai_bot_total{" \
        | grep "crawler=\"$crawler\"" \
        | grep "route_id=\"$route\"" \
        | grep "action=\"$action\"" \
        | awk '{print $NF}' | head -1)
    [ -z "$v" ] && echo "0" || echo "$v"
}

# ========================================================================
# S1. Read endpoints (AC #7)
# ========================================================================
log "=== ai-bot smoke: read endpoints (builtin / test / stats / robots-preview) ==="
BUILTIN=$(api_get /api/v1/ai-crawlers/builtin)
assert_json "$BUILTIN" '.data.entries | length' "16" "builtin: 16 entries"

TEST_GPT=$(api_get "/api/v1/ai-crawlers/test?ua=GPTBot/1.0&route_id=${ROUTE_ID}")
assert_json "$TEST_GPT" '.data.matched_crawler' "GPTBot" "test: GPTBot/1.0 -> matched_crawler GPTBot"

TEST_MY=$(api_get "/api/v1/ai-crawlers/test?ua=MyTestBot/9&route_id=${ROUTE_ID}")
assert_json "$TEST_MY" '.data.matched_crawler' "MyTestBot" "test: custom MyTestBot merged into classifier"

STATS_OK=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
    "$API/api/v1/ai-crawlers/stats?route_id=${ROUTE_ID}&window=5m")
[ "$STATS_OK" = "200" ] && ok "stats: window=5m -> 200" || fail "stats 5m expected 200, got $STATS_OK"

STATS_BAD=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
    "$API/api/v1/ai-crawlers/stats?route_id=${ROUTE_ID}&window=24h")
[ "$STATS_BAD" = "400" ] && ok "stats: window=24h -> 400" || fail "stats 24h expected 400, got $STATS_BAD"

ROBOTS_PREVIEW=$(api_get "/api/v1/ai-crawlers/robots-preview?route_id=${ROBOTS_ID}")
assert_json_exists "$ROBOTS_PREVIEW" '.data.body' "robots-preview: body present"

# ========================================================================
# S2. Policy Off -> filter is a no-op (passthrough)
# ========================================================================
log "=== ai-bot smoke: policy=off passthrough ==="
set_policy "off"
expect_code "ai-test.local" "Mozilla/5.0 (compatible; GPTBot/1.0)" "200" "policy=off: GPTBot UA -> 200 passthrough"
expect_code "ai-test.local" "Mozilla/5.0 (compatible; Bytespider)" "200" "policy=off: Bytespider UA -> 200 passthrough"
expect_code "ai-test.local" "MyTestBot/1.0" "200" "policy=off: MyTestBot UA -> 200 passthrough"

# ========================================================================
# S3. UaOnly ApplyPolicy: Bytespider (no IP dependency)
# ========================================================================
log "=== ai-bot smoke: UaOnly (Bytespider) Deny / Log ==="
set_policy "deny"
expect_code "ai-test.local" "Mozilla/5.0 (compatible; Bytespider)" "403" "policy=deny: Bytespider (UaOnly) -> 403"
# Re-issue once code is confirmed 403 to capture Retry-After cleanly.
HDRS=$(mktemp)
curl -s -o /dev/null -D "$HDRS" \
    -H "Host: ai-test.local" -H "User-Agent: Mozilla/5.0 (compatible; Bytespider)" "${PROXY}/"
assert_header_value "$(cat "$HDRS")" "Retry-After" "86400" "policy=deny: Retry-After 86400 on AI-bot deny"
rm -f "$HDRS"

set_policy "log"
expect_code "ai-test.local" "Mozilla/5.0 (compatible; Bytespider)" "200" "policy=log: Bytespider (UaOnly) allowed -> 200"

# ========================================================================
# S4. Custom ip_ranges in-range: MyTestBot (ApplyPolicy)
# ========================================================================
log "=== ai-bot smoke: custom ip_ranges in-range (MyTestBot) ==="
set_policy "deny"
expect_code "ai-test.local" "MyTestBot/2.0" "403" "policy=deny: MyTestBot in-range (ApplyPolicy) -> 403"
set_policy "off"
expect_code "ai-test.local" "MyTestBot/2.0" "200" "policy=off: MyTestBot -> 200"

# ========================================================================
# S5. Spoofed fallback chain on the dedicated, policy=deny-fixed route.
# GPTBot (built-in IpRanges) from the runner IP is always out-of-vendor-
# range -> Spoofed verdict, so the per-route ai_bot_spoofed_fallback drives
# the outcome.
# ========================================================================
log "=== ai-bot smoke: spoofed-fallback chain (GPTBot from out-of-range IP) ==="
GPT_UA="Mozilla/5.0 (compatible; GPTBot/1.0)"

# fallback=deny (inherited global): spoofed GPTBot -> 403 + Retry-After.
if wait_code "ai-spoof-deny.local" "$GPT_UA" "403" 40; then
    ok "spoofed fallback=deny (inherited global): GPTBot -> 403"
    HDRS=$(mktemp)
    curl -s -o /dev/null -D "$HDRS" \
        -H "Host: ai-spoof-deny.local" -H "User-Agent: $GPT_UA" "${PROXY}/"
    assert_header_value "$(cat "$HDRS")" "Retry-After" "86400" "spoofed-deny: Retry-After 86400"
    rm -f "$HDRS"
else
    fail "spoofed fallback=deny: GPTBot never converged to 403"
fi

# fallback=allow: spoofed GPTBot allowed -> 200.
expect_code "ai-spoof-allow.local" "$GPT_UA" "200" "spoofed fallback=allow: GPTBot -> 200" 40

# fallback=log: spoofed GPTBot allowed (counted) -> 200.
expect_code "ai-spoof-log.local" "$GPT_UA" "200" "spoofed fallback=log: GPTBot -> 200" 40

# ========================================================================
# S6. Header injection (AC #11)
# ========================================================================
log "=== ai-bot smoke: verified-bot header injection (AC #11) ==="
set_policy "log"
# Verified IpRanges bot (MyTestBot in-range, allowed under Log) -> backend
# must receive both injected headers.
VB=$(echo_header "ai-test.local" "MyTestBot/3.0" "x-lorica-verified-bot")
[ "$VB" = "MyTestBot" ] && ok "AC#11: backend sees X-Lorica-Verified-Bot: MyTestBot" \
    || fail "AC#11 verified-bot header expected MyTestBot, got '$VB'"
KIND=$(echo_header "ai-test.local" "MyTestBot/3.0" "x-lorica-bot-verification")
[ "$KIND" = "ip_ranges" ] && ok "AC#11: backend sees X-Lorica-Bot-Verification: ip_ranges" \
    || fail "AC#11 verification-kind header expected ip_ranges, got '$KIND'"

# Trust-laundering defense, part 1 (overwrite on the verified-bot path).
# proxy_wiring.rs injects with insert_header (overwrite), NOT append_header,
# so a verified bot's value REPLACES any client-sent value rather than being
# combined with it. A forged client header is overwritten with the real
# crawler name, never combined and never the forged value.
VB_FORGED=$(echo_header "ai-test.local" "MyTestBot/3.0" "x-lorica-verified-bot" \
    -H "X-Lorica-Verified-Bot: EvilCorp")
if [ "$VB_FORGED" = "MyTestBot" ]; then
    ok "AC#11 trust-laundering: forged client header overwritten with MyTestBot"
else
    fail "AC#11 trust-laundering: expected MyTestBot (overwrite), got '$VB_FORGED'"
fi

# Trust-laundering defense, part 2 (literal IV6): a non-bot request that
# forges BOTH Lorica-namespaced headers must reach the backend with NEITHER
# header present. proxy_wiring.rs unconditionally remove_header()s both on
# every upstream forward before the inject loop, and a non-bot request
# stages nothing, so the backend sees them stripped. A normal browser UA
# matches no crawler, so check_ai_bot falls through to the backend echo.
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
IV6_VB=$(echo_header "ai-test.local" "$BROWSER_UA" "x-lorica-verified-bot" \
    -H "X-Lorica-Verified-Bot: EvilCorp" -H "X-Lorica-Bot-Verification: rdns")
IV6_KIND=$(echo_header "ai-test.local" "$BROWSER_UA" "x-lorica-bot-verification" \
    -H "X-Lorica-Verified-Bot: EvilCorp" -H "X-Lorica-Bot-Verification: rdns")
[ -z "$IV6_VB" ] && ok "AC#11 IV6: non-bot forged X-Lorica-Verified-Bot stripped before backend" \
    || fail "AC#11 IV6: forged verified-bot header reached backend, got '$IV6_VB'"
[ -z "$IV6_KIND" ] && ok "AC#11 IV6: non-bot forged X-Lorica-Bot-Verification stripped before backend" \
    || fail "AC#11 IV6: forged verification-kind header reached backend, got '$IV6_KIND'"

# UaOnly verified bot stages only the kind header, never X-Lorica-Verified-Bot
# (backends can tell apart trust levels).
UA_VB=$(echo_header "ai-test.local" "Mozilla/5.0 (compatible; Bytespider)" "x-lorica-verified-bot")
UA_KIND=$(echo_header "ai-test.local" "Mozilla/5.0 (compatible; Bytespider)" "x-lorica-bot-verification")
[ -z "$UA_VB" ] && ok "AC#11: UaOnly bot gets NO X-Lorica-Verified-Bot" \
    || fail "AC#11 UaOnly should not set verified-bot header, got '$UA_VB'"
[ "$UA_KIND" = "ua_only" ] && ok "AC#11: UaOnly bot gets X-Lorica-Bot-Verification: ua_only" \
    || fail "AC#11 UaOnly kind header expected ua_only, got '$UA_KIND'"

# ========================================================================
# S7. Auto-served /robots.txt (AC #10)
# ========================================================================
log "=== ai-bot smoke: /robots.txt (AC #10) ==="
RBODY=$(mktemp); RHDRS=$(mktemp)
curl -s -o "$RBODY" -D "$RHDRS" -H "Host: ai-robots.local" "${PROXY}/robots.txt" >/dev/null
RCODE=$(awk 'NR==1 {print $2}' "$RHDRS")
[ "$RCODE" = "200" ] && ok "robots(serve=true): GET /robots.txt -> 200" || fail "robots serve=true expected 200, got $RCODE"
assert_header_value "$(cat "$RHDRS")" "Content-Type" "text/plain; charset=utf-8" "robots: Content-Type text/plain"
grep -qi '^User-agent:' "$RBODY" && ok "robots: body contains 'User-agent:'" || fail "robots: missing 'User-agent:'"
grep -q 'Disallow: /' "$RBODY" && ok "robots: body contains 'Disallow: /'" || fail "robots: missing 'Disallow: /'"
grep -q '# Generated by Lorica' "$RBODY" && ok "robots: Lorica-generated header present" || fail "robots: missing Lorica header"
rm -f "$RBODY" "$RHDRS"

# serve_robots_txt=false (main route) -> passthrough to backend, NOT the
# Lorica-generated body. Use a plain UA that matches no crawler so the
# AI-bot filter falls through and the request reaches the backend.
RBODY=$(mktemp); RHDRS=$(mktemp)
curl -s -o "$RBODY" -D "$RHDRS" -H "Host: ai-test.local" -H "User-Agent: curl-passthrough" \
    "${PROXY}/robots.txt" >/dev/null
if grep -q '# Generated by Lorica' "$RBODY"; then
    fail "robots(serve=false): expected backend passthrough, got Lorica-generated body"
else
    ok "robots(serve=false): /robots.txt passes through to backend (no Lorica body)"
fi
assert_header_present "$(cat "$RHDRS")" "X-Backend-Id" "robots(serve=false): backend reached (X-Backend-Id present)"
rm -f "$RBODY" "$RHDRS"

# ========================================================================
# S8. Custom-crawler CRUD round-trip + hot-reload (AC #6 / #7 / #8)
# ========================================================================
log "=== ai-bot smoke: custom-crawler CRUD + hot-reload ==="
CRUD=$(curl -s -o /tmp/crud_body -w '%{http_code}' -b "$SESSION" -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"CrudBot","user_agent_pattern":"(?i)\\bCrudBot\\b","verification":{"kind":"ua_only"},"enabled":true}' \
    "$API/api/v1/ai-crawlers/custom")
CRUD_ID=$(jq -r '.data.id // empty' /tmp/crud_body)
{ [ "$CRUD" = "201" ] || [ "$CRUD" = "200" ]; } && [ -n "$CRUD_ID" ] \
    && ok "CRUD: POST custom crawler -> $CRUD (id=$CRUD_ID)" \
    || fail "CRUD POST expected 200/201 + id, got $CRUD: $(cat /tmp/crud_body)"

LIST=$(api_get /api/v1/ai-crawlers/custom)
HAS_CRUD=$(echo "$LIST" | jq -r "[.data.entries[] | select(.name==\"CrudBot\")] | length")
[ "$HAS_CRUD" = "1" ] && ok "CRUD: GET list includes CrudBot" || fail "CRUD list expected CrudBot, got count=$HAS_CRUD"

PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"CrudBot","user_agent_pattern":"(?i)\\bCrudBotV2\\b","verification":{"kind":"ua_only"},"enabled":true}' \
    "$API/api/v1/ai-crawlers/custom/${CRUD_ID}")
[ "$PUT_CODE" = "200" ] && ok "CRUD: PUT update CrudBot -> 200" || fail "CRUD PUT expected 200, got $PUT_CODE"

DEL_CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" -X DELETE \
    "$API/api/v1/ai-crawlers/custom/${CRUD_ID}")
[ "$DEL_CODE" = "200" ] && ok "CRUD: DELETE CrudBot -> 200" || fail "CRUD DELETE expected 200, got $DEL_CODE"

BAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" -X POST \
    -H "Content-Type: application/json" \
    -d '{"name":"BadBot","user_agent_pattern":"[invalid","verification":{"kind":"ua_only"},"enabled":true}' \
    "$API/api/v1/ai-crawlers/custom")
[ "$BAD_CODE" = "400" ] && ok "CRUD: POST invalid regex '[invalid' -> 400" || fail "CRUD invalid regex expected 400, got $BAD_CODE"

# Hot-reload: a freshly created custom crawler takes effect on the data
# plane within a couple seconds (AC #8). HotBot is UaOnly so it reaches
# ApplyPolicy without an IP dependency.
HOT=$(api_post /api/v1/ai-crawlers/custom \
    '{"name":"HotBot","user_agent_pattern":"(?i)\\bHotReloadBot\\b","verification":{"kind":"ua_only"},"enabled":true}')
HOT_ID=$(echo "$HOT" | jq -r '.data.id // empty')
[ -n "$HOT_ID" ] || { fail "hot-reload custom create: $HOT"; }
set_policy "deny"
HOT_CODE="000"
for i in $(seq 1 10); do
    HOT_CODE=$(proxy_code "ai-test.local" "HotReloadBot/1.0")
    [ "$HOT_CODE" = "403" ] && break
    sleep 1
done
[ "$HOT_CODE" = "403" ] && ok "AC#8 hot-reload: new HotBot classified+denied within 10s -> 403" \
    || fail "AC#8 hot-reload: HotReloadBot expected 403, got $HOT_CODE"
[ -n "$HOT_ID" ] && curl -s -o /dev/null -b "$SESSION" -X DELETE "$API/api/v1/ai-crawlers/custom/${HOT_ID}"

# ========================================================================
# S9. Prometheus counter sanity (single-process only)
# ========================================================================
if [ "$SKIP_METRICS" = "1" ]; then
    log "=== ai-bot smoke: Prometheus counter check skipped (workers mode) ==="
else
    log "=== ai-bot smoke: Prometheus counter sanity ==="
    UA_ONLY=$(get_ai_counter "Bytespider" "ua_only_match")
    [ "$UA_ONLY" -gt 0 ] 2>/dev/null \
        && ok "lorica_ai_bot_total{crawler=Bytespider,action=ua_only_match} = $UA_ONLY" \
        || fail "ua_only_match counter expected > 0, got '$UA_ONLY'"
    DENY_CT=$(get_ai_counter "MyTestBot" "deny")
    [ "$DENY_CT" -gt 0 ] 2>/dev/null \
        && ok "lorica_ai_bot_total{crawler=MyTestBot,action=deny} = $DENY_CT" \
        || fail "MyTestBot deny counter expected > 0, got '$DENY_CT'"
    SPOOF_CT=$(get_ai_counter "GPTBot" "spoofed" "$SPOOF_DENY_ID")
    [ "$SPOOF_CT" -gt 0 ] 2>/dev/null \
        && ok "lorica_ai_bot_total{crawler=GPTBot,action=spoofed} = $SPOOF_CT" \
        || fail "GPTBot spoofed counter expected > 0, got '$SPOOF_CT'"
fi

log "=== ai-bot smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
