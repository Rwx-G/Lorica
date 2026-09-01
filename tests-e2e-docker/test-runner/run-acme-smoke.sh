#!/usr/bin/env bash
# =============================================================================
# Lorica ACME E2E smoke test (v1.7.0 Story 9.1 AC #13, Pebble fixture)
#
# First end-to-end ACME coverage in the repo (the v1.5.2 audit item
# M-22 that requested it was never implemented). Topology:
#   - `pebble` (ghcr.io/letsencrypt/pebble:2.8.0) serves the ACME
#     directory on 443 under the network alias
#     acme-staging-v02.api.letsencrypt.org (kept so the fixture TLS
#     SAN matches a realistic hostname); the Lorica node points at it
#     via LORICA_ACME_DIRECTORY_URL, since Pebble serves /dir rather
#     than the Let's Encrypt /directory path.
#     Its directory TLS leaf is signed by a fixture CA generated at
#     boot by `acme-ca-init`; the Lorica node trusts that CA via
#     SSL_CERT_FILE (honoured by instant-acme's platform verifier
#     through openssl-probe).
#   - `challtestsrv` (pebble-challtestsrv:2.8.0) is Pebble's resolver
#     (-dnsserver challtestsrv:8053) and the mock DNS provider: the
#     smoke provisions A and TXT records over its management API on
#     8055.
#
# Flow:
#   1. Preflight pebble's directory, challtestsrv, backend1, Lorica.
#   2. Log in (first-run password rotation dance).
#   3. Assert the HTTP-01 challenge path is served on the proxy port.
#   4. Register an A record pointing the test hostname at the Lorica
#      container, create a backend + route for it (production mirror).
#   5. HTTP-01: POST /api/v1/acme/provision and assert the certificate
#      lands in GET /api/v1/certificates.
#   6. DNS-01 (manual flow + mock DNS): provision-dns-manual, publish
#      the returned TXT records on challtestsrv, confirm, assert the
#      certificate lands.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
CHALLTESTSRV="${CHALLTESTSRV:-http://challtestsrv:8055}"
PEBBLE_DIR_URL="https://acme-staging-v02.api.letsencrypt.org/dir"
HTTP01_DOMAIN="acme-e2e.test"
DNS01_DOMAIN="dns-e2e.test"

log "=== ACME smoke: preflight ==="
for i in $(seq 1 30); do
    curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1 && break
    sleep 1
done
log "backend1 ready"

PEBBLE_OK=false
for i in $(seq 1 60); do
    if curl -sk "$PEBBLE_DIR_URL" 2>/dev/null | jq -e '.newOrder' >/dev/null 2>&1; then
        PEBBLE_OK=true
        break
    fi
    sleep 1
done
if [ "$PEBBLE_OK" = "true" ]; then
    ok "pebble ACME directory reachable at the staging alias"
else
    fail "pebble directory never came up at $PEBBLE_DIR_URL"
    exit 1
fi

CHALL_OK=false
for i in $(seq 1 30); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$CHALLTESTSRV/" 2>/dev/null || true)
    if [ "$CODE" != "000" ] && [ -n "$CODE" ]; then
        CHALL_OK=true
        break
    fi
    sleep 1
done
if [ "$CHALL_OK" = "true" ]; then
    ok "challtestsrv management API reachable"
else
    fail "challtestsrv never came up at $CHALLTESTSRV"
    exit 1
fi

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
    NEW_PW="AcmeSmokePassword!42"
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

# --- HTTP-01 challenge path is served on the proxy port ---
# An unknown token must answer 404 from the challenge handler (a
# proxy-level 502/425 or connection error would mean the path is not
# wired at all).
CHAL_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: ${HTTP01_DOMAIN}" \
    "${PROXY}/.well-known/acme-challenge/e2e-smoke-nonexistent-token" || true)
if [ "$CHAL_CODE" = "404" ]; then
    ok "HTTP-01 challenge path served on the proxy port (404 for unknown token)"
else
    fail "challenge path expected 404, got $CHAL_CODE"
fi

# --- Point the test hostname at the Lorica container ---
log "=== ACME smoke: DNS + route setup ==="
LORICA_HOST=$(echo "$PROXY" | sed -E 's#^https?://##; s#:[0-9]+$##')
LORICA_IP=$(getent hosts "$LORICA_HOST" | awk '{print $1}' | head -1)
[ -n "$LORICA_IP" ] || { fail "could not resolve $LORICA_HOST"; exit 1; }
ADD_A=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CHALLTESTSRV/add-a" \
    -d "{\"host\":\"${HTTP01_DOMAIN}\",\"addresses\":[\"${LORICA_IP}\"]}")
if [ "$ADD_A" = "200" ]; then
    ok "A record ${HTTP01_DOMAIN} -> ${LORICA_IP} registered on challtestsrv"
else
    fail "challtestsrv add-a HTTP $ADD_A"
fi

BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"acme-backend1\",
    \"group\": \"acme\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"${HTTP01_DOMAIN}\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "route created (id=$ROUTE_ID)"

sleep 2

# --- HTTP-01 issuance against Pebble ---
log "=== ACME smoke: HTTP-01 issuance ==="
HTTP01_BODY=$(mktemp)
HTTP01_CODE=$(curl -s -o "$HTTP01_BODY" -w '%{http_code}' --max-time 240 \
    -b "$SESSION" -X POST -H "Content-Type: application/json" \
    -d "{\"domain\":\"${HTTP01_DOMAIN}\",\"staging\":true,\"contact_email\":\"admin@example.com\"}" \
    "$API/api/v1/acme/provision")
if [ "$HTTP01_CODE" = "200" ]; then
    ok "HTTP-01 provision returned 200"
else
    fail "HTTP-01 provision HTTP $HTTP01_CODE: $(cat "$HTTP01_BODY")"
fi
rm -f "$HTTP01_BODY"

CERTS=$(api_get /api/v1/certificates)
HTTP01_CERT=$(echo "$CERTS" | jq -r --arg d "$HTTP01_DOMAIN" \
    '[.data.certificates[]? | select(.domain == $d)] | length')
if [ "$HTTP01_CERT" -ge 1 ] 2>/dev/null; then
    ok "HTTP-01 certificate for ${HTTP01_DOMAIN} listed in /api/v1/certificates"
else
    fail "no certificate for ${HTTP01_DOMAIN} in: $(echo "$CERTS" | jq -c '.data.certificates | map(.domain)' 2>/dev/null)"
fi

# --- DNS-01 issuance via the manual flow + mock DNS provider ---
log "=== ACME smoke: DNS-01 issuance (manual flow, challtestsrv TXT) ==="
DNS_START=$(api_post /api/v1/acme/provision-dns-manual \
    "{\"domain\":\"${DNS01_DOMAIN}\",\"staging\":true,\"contact_email\":\"admin@example.com\"}")
TXT_COUNT=$(echo "$DNS_START" | jq -r '.data.txt_records | length // 0')
if [ "$TXT_COUNT" -ge 1 ] 2>/dev/null; then
    ok "manual DNS-01 returned $TXT_COUNT TXT record(s) to publish"
else
    fail "manual DNS-01 start: $DNS_START"
    exit 1
fi

# Publish every TXT record on the mock DNS provider. challtestsrv
# expects a fully-qualified name; the trailing dot is added here.
TXT_FAIL=0
while IFS=$'\t' read -r NAME VALUE; do
    [ -n "$NAME" ] || continue
    SET_TXT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CHALLTESTSRV/set-txt" \
        -d "{\"host\":\"${NAME}.\",\"value\":\"${VALUE}\"}")
    [ "$SET_TXT" = "200" ] || TXT_FAIL=1
done < <(echo "$DNS_START" | jq -r '.data.txt_records[] | [.name, .value] | @tsv')
if [ "$TXT_FAIL" = "0" ]; then
    ok "TXT record(s) published on challtestsrv"
else
    fail "publishing TXT record(s) on challtestsrv failed"
fi

DNS_CONFIRM_BODY=$(mktemp)
DNS_CONFIRM_CODE=$(curl -s -o "$DNS_CONFIRM_BODY" -w '%{http_code}' --max-time 240 \
    -b "$SESSION" -X POST -H "Content-Type: application/json" \
    -d "{\"domain\":\"${DNS01_DOMAIN}\"}" \
    "$API/api/v1/acme/provision-dns-manual/confirm")
if [ "$DNS_CONFIRM_CODE" = "200" ]; then
    ok "DNS-01 confirm returned 200"
else
    fail "DNS-01 confirm HTTP $DNS_CONFIRM_CODE: $(cat "$DNS_CONFIRM_BODY")"
fi
rm -f "$DNS_CONFIRM_BODY"

CERTS=$(api_get /api/v1/certificates)
DNS01_CERT=$(echo "$CERTS" | jq -r --arg d "$DNS01_DOMAIN" \
    '[.data.certificates[]? | select(.domain == $d)] | length')
if [ "$DNS01_CERT" -ge 1 ] 2>/dev/null; then
    ok "DNS-01 certificate for ${DNS01_DOMAIN} listed in /api/v1/certificates"
else
    fail "no certificate for ${DNS01_DOMAIN} in: $(echo "$CERTS" | jq -c '.data.certificates | map(.domain)' 2>/dev/null)"
fi

# --- Summary ---
echo ""
log "=== ACME smoke summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
