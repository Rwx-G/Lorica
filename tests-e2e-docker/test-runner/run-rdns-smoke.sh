#!/usr/bin/env bash
# =============================================================================
# Lorica rDNS-bypass E2E smoke test (v1.4.0 Epic 3 follow-up).
#
# Pre-requisite: docker-compose `rdns` profile is up. `lorica-rdns`
# starts with /etc/resolv.conf pointed at the `dnsmasq` sidecar, and
# `dnsmasq` serves the test zone from fixtures/dnsmasq-rdns.conf
# with:
#   - PTR 203.0.113.42  -> crawler.bot-e2e.local,  A crawler.bot-e2e.local -> 203.0.113.42 (CONFIRMS)
#   - PTR 203.0.113.77  -> spoofed.bot-e2e.local,  A spoofed.bot-e2e.local -> 198.51.100.99 (MISMATCH)
#
# Test matrix:
#   1. Route has bot_protection with `bypass.rdns = ["bot-e2e.local"]`.
#   2. First request from 203.0.113.42 MISSES the rDNS cache (the
#      populate is async), so the challenge renders.
#   3. After a brief settle, the cache is populated with the
#      forward-confirmed match; the SECOND request from 203.0.113.42
#      must bypass the challenge and hit the backend.
#   4. Requests from 203.0.113.77 fail forward-confirm — the cache
#      entry stores None and the challenge continues to render even
#      after settle (regression guard for the forward-confirm step,
#      which is the ONLY thing keeping a hostile resolver from
#      trivially bypassing via spoofed PTRs).
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"

IP_TRUSTED="203.0.113.42"   # PTR + forward match -> must bypass
IP_SPOOFED="203.0.113.77"   # PTR match, forward mismatch -> must NOT bypass

log "=== rdns smoke: preflight ==="
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

# Sanity-check: dnsmasq is reachable AND the zone resolves from the
# test-runner's own resolver. If this fails, the lorica-rdns
# entrypoint has overridden resolv.conf correctly on its side but
# our sanity probe would fail silently — so we query the dnsmasq
# sidecar directly.
#
# Use `getent` which is available in Debian-slim by default. We ask
# for a forward lookup of `crawler.bot-e2e.local` through the test-
# runner's default resolver — this will miss unless we explicitly
# point at dnsmasq. We skip the sanity in that case (the lorica
# side is what matters for the test).
log "rdns fixtures sanity (informational):"
DNSMASQ_IP=$(getent hosts dnsmasq | awk '{print $1}' || echo "")
if [ -n "$DNSMASQ_IP" ]; then
    log "dnsmasq reachable at $DNSMASQ_IP"
else
    log "WARN: dnsmasq sidecar not resolvable in test-runner namespace"
fi

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
    NEW_PW="RdnsSmokePassword!42"
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

# --- Configure trusted_proxies so the runner can inject XFF. ------------
log "=== rdns smoke: configure trusted_proxies ==="
SET=$(api_put /api/v1/settings '{
    "trusted_proxies": ["0.0.0.0/0", "::/0"]
}')
[ "$(echo "$SET" | jq -r '.data.trusted_proxies | length')" -ge 1 ] \
    && ok "trusted_proxies persisted" \
    || fail "settings update failed: $SET"
sleep 2

# --- Backend + route with rdns bypass ----------------------------------
log "=== rdns smoke: create backend + rdns-bypass route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"rdns-backend1\",
    \"group\": \"rdns\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"rdns-test.local\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true,
    \"bot_protection\": {
        \"mode\": \"javascript\",
        \"cookie_ttl_s\": 3600,
        \"pow_difficulty\": 14,
        \"captcha_alphabet\": \"23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ\",
        \"bypass\": {\"rdns\": [\"bot-e2e.local\"]}
    }
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "route created (id=$ROUTE_ID) with rdns bypass on suffix bot-e2e.local"
sleep 2

# Helper: issue a request as the given client IP and echo the PoW
# marker count (0 = backend passthrough, >0 = challenge page).
probe() {
    local ip="$1"
    local resp; resp=$(mktemp)
    local code; code=$(curl -s -o "$resp" -w '%{http_code}' \
        -H "Host: rdns-test.local" \
        -H "X-Forwarded-For: $ip" \
        -H "Accept: text/html" \
        "${PROXY}/")
    local pow; pow=$(grep -c "crypto.subtle" "$resp" 2>/dev/null || echo 0)
    rm -f "$resp"
    echo "$code $pow"
}

# --- Trusted client: forward-confirmed PTR must bypass after warmup ----
log "=== rdns smoke: trusted client (PTR + forward confirm) ==="
# First hit: cache MISS. The populate is async (tokio::spawn in the
# request_filter) so this request typically renders the challenge.
# We do not assert on this one — the important check is "the NEXT
# request from the same IP bypasses".
read -r CODE1 POW1 < <(probe "$IP_TRUSTED")
log "trusted client first request: HTTP $CODE1, PoW markers=$POW1 (cache miss expected)"

# Give the background populate time to complete. 2 s is
# conservative: dnsmasq is on the same Docker network and the PTR
# + forward lookups are ≤ 10 ms each with a warm tokio runtime.
sleep 2

# Second hit: cache HIT → bypass → backend passthrough.
BYPASS_PASSED=0
for attempt in 1 2 3 4 5; do
    read -r CODE2 POW2 < <(probe "$IP_TRUSTED")
    log "trusted client request #$((attempt + 1)): HTTP $CODE2, PoW markers=$POW2"
    if [ "$CODE2" = "200" ] && [ "$POW2" = "0" ]; then
        BYPASS_PASSED=1
        break
    fi
    # Give the populate one more second in case the runner machine
    # is slow — CI sometimes takes > 2 s to fire the background task.
    sleep 1
done
if [ "$BYPASS_PASSED" = "1" ]; then
    ok "trusted client: forward-confirmed PTR bypasses challenge"
else
    fail "trusted client: expected backend passthrough after cache warmup, still seeing challenge"
fi

# --- Spoofed client: forward-confirm must reject the PTR --------------
log "=== rdns smoke: spoofed client (PTR match, forward mismatch) ==="
# Warm the cache. The PTR lookup succeeds (spoofed.bot-e2e.local),
# but the forward A lookup returns 198.51.100.99 ≠ 203.0.113.77 so
# `lookup_with_forward_confirm` returns None. Cache stores negative
# entry; ALL future requests from this IP must see the challenge.
read -r _ _ < <(probe "$IP_SPOOFED")
sleep 2

SPOOF_BLOCKED=0
for attempt in 1 2 3; do
    read -r CODE POW < <(probe "$IP_SPOOFED")
    log "spoofed client request: HTTP $CODE, PoW markers=$POW"
    if [ "$CODE" = "200" ] && [ "$POW" -ge 1 ]; then
        SPOOF_BLOCKED=1
        break
    fi
    sleep 1
done
if [ "$SPOOF_BLOCKED" = "1" ]; then
    ok "spoofed client: forward-confirm rejects PTR, challenge still fires (threat model intact)"
else
    fail "spoofed client: forward-confirm FAILED — spoofed PTR bypassed the challenge (security regression)"
fi

# --- Summary ---
log "=== rdns smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
