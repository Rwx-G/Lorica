#!/usr/bin/env bash
# =============================================================================
# Lorica cluster E2E: the automation phase (Epic 10, stories 10.3 to 10.5)
#
# Runs AFTER the main cluster smoke and the restart phase, against the
# same fleet, before revocation. The control plane serves the automation
# listener on 9446 (see entrypoint-cluster-cp.sh); the runner sits on
# the e2e network, which is allowlisted, and on a second network,
# `automation-outside`, which is not, so both sides of the source filter
# are reachable from one container.
#
# What it asserts, and which story each belongs to:
#   10.3 IV1  a connection from outside `automation_allowed_cidrs` gets
#             no HTTP answer at all; from inside, no token is 401 with
#             the bearer challenge; a revoked token is 401 with an audit
#             row that names the reason
#   10.3 IV2  a dashboard session cookie on the automation port is 401,
#             an automation token on the management port is 401
#   10.3 IV3  a follower started with --automation-listen exited non-zero
#             with the documented message (run.sh started it and left
#             its exit code and log on the shared volume); an environment
#             created on the control plane reaches both followers
#   10.4 IV1  PUT under a pre-provisioned wildcard certificate is 201
#             with that certificate; the hostname answers through the
#             proxy over TLS with a chain that validates; a second PUT is
#             200 with the same route id; a backend change moves traffic
#             with no 5xx in between
#   10.4 IV2  four refusals, each the documented status, and no row left
#   10.4 IV3  ttl 90 s is collected within 150 s with an audit row; a
#             DELETE removes at once and a second DELETE is 204
#   10.4 IV4  both followers converge past the generation floor while
#             reporting different hashes
#   10.4 IV5  a token of another principal is refused on GET, PUT and
#             DELETE with the 404 an unknown name gets, each with an
#             audit row
#   10.5 IV1  an ID token from the fixture creates an environment; the
#             wrong project, the wrong audience, an expired token, a
#             tampered one and a replay are each refused with their own
#             audit reason
#   10.5 IV4  HS256 under the public key is refused as wrong_alg; alg
#             none, whose signature segment is empty, never passes the
#             bearer shape test and is refused as not_a_credential
#   10.5 IV5  a thousand unknown kids cost at most one JWKS fetch
#   10.5 IV2  a rotated key is picked up without a restart; an issuer
#             outage keeps the cached keys working
#   10.5 IV3  removing the issuer entry refuses the next token at once
#
# Two things about the listener shape every assertion has to live with:
#
#   - The listener admits 20 connection attempts per source per minute
#     (`PreAuthBudgets::default`), a sliding window, and drops the 21st
#     before the handshake exactly the way it drops a source outside the
#     allowlist. Every curl is one attempt, so `automation_slot` keeps
#     the runner's own copy of the window and waits its turn rather than
#     reading a budget refusal as a product failure.
#   - Every refusal is one 401 on the wire; the reason lives in the
#     audit row's `action`, after the first colon
#     (`automation.request.unauthenticated:wrong_aud`). `GET /api/v1/audit`
#     filters on an action PREFIX, so the bare verb still lists every
#     refusal and the smoke reads the reason off the action string.
#   - Audit rows are queued and land within the writer's drain, so every
#     row assertion polls briefly rather than reading right after the
#     response.
#
# Pre-requisite: the `cluster` profile is up, the main smoke and the
# restart phase have run, and run.sh has produced
# /shared/edge-a_automation_refusal.{code,log}.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

CP_API="${CP_API:?CP_API is required}"
# Two DNS aliases of the control plane, one per network (see the
# lorica-cp service in docker-compose.yml for why one name is not
# enough): the allowlisted e2e address and the automation-outside one.
CP_HOST_INSIDE="${CP_HOST_INSIDE:-lorica-cp-inside}"
CP_HOST_OUTSIDE="${CP_HOST_OUTSIDE:-lorica-cp-outside}"
AUTOMATION_PORT="${AUTOMATION_PORT:-9446}"
EDGE_A_API="${EDGE_A_API:?EDGE_A_API is required}"
EDGE_B_API="${EDGE_B_API:?EDGE_B_API is required}"
BACKEND1="${BACKEND1_ADDR:-backend1:80}"
BACKEND2="${BACKEND2_ADDR:-backend2:80}"
OIDC_ISSUER="${OIDC_ISSUER:-https://oidc-issuer}"
OIDC_AUDIENCE="${OIDC_AUDIENCE:-lorica-e2e}"
CHALLTESTSRV="${CHALLTESTSRV:-http://challtestsrv:8055}"
PEBBLE_MGMT="${PEBBLE_MGMT:-https://pebble:15000}"
SHARED="${SHARED_DIR:-/shared}"
REVIEW_ZONE="review.example.com"
WILDCARD="*.${REVIEW_ZONE}"

# ---------------------------------------------------------------------
# Helpers specific to this phase.
# ---------------------------------------------------------------------

AUTOMATION_ATTEMPTS=()
automation_slot() {
    local now oldest
    now=$(date +%s)
    if [ "${#AUTOMATION_ATTEMPTS[@]}" -ge 20 ]; then
        oldest="${AUTOMATION_ATTEMPTS[0]}"
        if [ $((now - oldest)) -lt 62 ]; then
            log "connection budget: waiting $((62 - (now - oldest)))s for the attempt window"
            sleep $((62 - (now - oldest)))
            now=$(date +%s)
        fi
        AUTOMATION_ATTEMPTS=("${AUTOMATION_ATTEMPTS[@]:1}")
    fi
    AUTOMATION_ATTEMPTS+=("$now")
}

# One request on the automation listener, from inside the allowlist.
# $1 method, $2 path, $3 bearer credential ("" for none), $4 body ("").
# Leaves AUTO_CODE, AUTO_BODY and AUTO_HEADERS (a file) behind. The
# credential goes to curl through a header file, never argv.
AUTO_HEADERS=""
auto_call() {
    local method="$1" path="$2" bearer="$3" body="${4:-}"
    local body_file header_file
    automation_slot
    body_file=$(mktemp)
    [ -n "$AUTO_HEADERS" ] && rm -f "$AUTO_HEADERS"
    AUTO_HEADERS=$(mktemp)
    header_file=$(mktemp)
    if [ -n "$bearer" ]; then
        printf 'Authorization: Bearer %s\n' "$bearer" > "$header_file"
    else
        printf 'X-Lorica-E2E: no-credential\n' > "$header_file"
    fi
    local args=(-sk --max-time 30 -o "$body_file" -D "$AUTO_HEADERS" -w '%{http_code}'
                -X "$method" -H 'Content-Type: application/json' -H "@$header_file")
    [ -n "$body" ] && args+=(-d "$body")
    AUTO_CODE=$(curl "${args[@]}" "https://${CP_IN}:${AUTOMATION_PORT}${path}" 2>/dev/null || true)
    AUTO_BODY=$(cat "$body_file")
    rm -f "$body_file" "$header_file"
}

UNAUTH_ACTION="automation.request.unauthenticated"

# The reason of the newest unauthenticated row of this node's own
# trail: what the action spells after its first colon.
latest_unauth_reason() {
    api_get "/api/v1/audit?action=${UNAUTH_ACTION}&node=&limit=5" \
        | jq -r '[(.data.entries // [])[] | select(.target_type == "automation_request")] | .[0].action // ""' \
        | sed "s/^${UNAUTH_ACTION}://"
}

# $1 expected reason, $2 label. Polls: the row is queued before the
# response is sent and lands within the writer's drain.
assert_unauth_reason() {
    local expected="$1" label="$2" got
    for _ in $(seq 1 10); do
        got=$(latest_unauth_reason)
        [ "$got" = "$expected" ] && break
        sleep 1
    done
    if [ "$got" = "$expected" ]; then
        ok "$label (audit reason: $expected)"
    else
        fail "$label (expected audit reason '$expected', the newest row says '$got')"
    fi
}

count_audit() {
    # $1 action, $2 target_id ("" for any)
    api_get "/api/v1/audit?action=$1&node=&limit=1000" \
        | jq -r --arg t "$2" '[(.data.entries // [])[] | select($t == "" or .target_id == $t)] | length'
}

cp_cookie_header() {
    awk -F'\t' '$6 == "lorica_session" { print "Cookie: " $6 "=" $7 }' "$CP_SESSION" | head -1
}
cp_metric() {
    curl -sk -H "$(cp_cookie_header)" "$CP_API/metrics" 2>/dev/null \
        | grep "^$1" | awk '{print $2}' | head -1
}

route_count_for_hostname() {
    # $1 hostname; the CP session is in $SESSION when called.
    api_get /api/v1/routes | jq -r --arg h "$1" '[(.data.routes // [])[] | select(.hostname == $h)] | length'
}

MINTED_TOKEN=""
MINTED_PUBLIC_ID=""
mint_static_token() {
    # $1 name, $2 max_ttl_seconds. Leaves MINTED_TOKEN and
    # MINTED_PUBLIC_ID behind (not printed: a `$(...)` caller would
    # lose the second one to the subshell).
    local out
    out=$(api_post /api/v1/automation/tokens "{\"name\":\"$1\",\"scopes\":[\"environments:read\",\"environments:write\"],\"allowed_hostnames\":[\"${WILDCARD}\"],\"allowed_backend_cidrs\":[\"${ALLOW_CIDR}\"],\"max_ttl_seconds\":$2,\"lifetime_days\":1}")
    MINTED_PUBLIC_ID=$(echo "$out" | jq -r '.data.public_id // empty')
    MINTED_TOKEN=$(echo "$out" | jq -r '.data.token // empty')
}

fixture_mint() {
    # $1 JSON body for POST /mint. Prints the token.
    curl -sk --max-time 30 -X POST -H 'Content-Type: application/json' \
        -d "$1" "$OIDC_ISSUER/mint" 2>/dev/null | jq -r '.token // empty'
}
fixture_fetches() {
    curl -sk --max-time 10 "$OIDC_ISSUER/fetches" 2>/dev/null | jq -r '.fetches // 0'
}
fixture_last_fetch_epoch() {
    curl -sk --max-time 10 "$OIDC_ISSUER/fetches" 2>/dev/null | jq -r '.last_fetch_epoch // 0'
}
# The cache refetches on an unknown kid at most once a minute per URL,
# counted on attempts; a fetch that must be observed waits the window out.
wait_refetch_window() {
    local last now remaining
    last=$(fixture_last_fetch_epoch)
    now=$(date +%s)
    remaining=$((last + 62 - now))
    if [ "$remaining" -gt 0 ]; then
        log "waiting ${remaining}s for the JWKS refetch window"
        sleep "$remaining"
    fi
}

env_body() {
    # $1 hostname, $2 backend ip:port, $3 ttl seconds
    printf '{"hostname":"%s","backends":[{"address":"%s"}],"certificate":"auto","ttl_seconds":%s,"labels":{"suite":"e2e"}}' "$1" "$2" "$3"
}

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== automation phase: preflight ==="

for marker in cp_ready edge-a_ready edge-b_ready; do
    for i in $(seq 1 180); do
        [ -f "$SHARED/$marker" ] && break
        sleep 1
    done
    if [ ! -f "$SHARED/$marker" ]; then
        fail "$marker never appeared"
        print_results
    fi
done

ALLOW_CIDR=$(cat "$SHARED/automation_allowed_cidr" 2>/dev/null || true)
if [ -n "$ALLOW_CIDR" ]; then
    ok "the control plane seeded automation_allowed_cidrs = $ALLOW_CIDR"
else
    fail "the control plane never recorded the allowlist it seeded"
    print_results
fi

BACKEND1_IP=$(getent hosts "${BACKEND1%%:*}" | awk '{print $1}' | head -1)
BACKEND2_IP=$(getent hosts "${BACKEND2%%:*}" | awk '{print $1}' | head -1)
E2E_PREFIX=$(echo "$BACKEND1_IP" | awk -F. '{print $1"."$2"."$3"."}')
CP_IN=$(getent hosts "$CP_HOST_INSIDE" | awk '{print $1}' | head -1)
CP_OUT=$(getent hosts "$CP_HOST_OUTSIDE" | awk '{print $1}' | head -1)
case "$CP_IN" in
    "$E2E_PREFIX"*)
        ok "the control plane is reachable on the allowlisted network at $CP_IN" ;;
    *)
        fail "no control-plane address on the e2e network ($CP_HOST_INSIDE resolved to '$CP_IN', backend1 is $BACKEND1_IP)"
        print_results ;;
esac
case "$CP_OUT" in
    "") fail "the control plane has no address on the automation-outside network ($CP_HOST_OUTSIDE did not resolve)" ;;
    "$E2E_PREFIX"*) fail "$CP_HOST_OUTSIDE resolved to $CP_OUT, which is on the allowlisted e2e network" ;;
    *)  ok "the control plane is also reachable on the non-allowlisted network at $CP_OUT" ;;
esac
EDGE_A_IP=$(getent hosts lorica-edge-a | awk '{print $1}' | head -1)
EDGE_B_IP=$(getent hosts lorica-edge-b | awk '{print $1}' | head -1)

API="$CP_API"
wait_for_api 120 || { fail "the control plane API never answered"; print_results; }
login "$(cat "$SHARED/cp_admin_password")"
CP_SESSION="$SESSION"

# edge-a was stopped and started by run.sh for the follower refusal
# below; give the fleet time to be whole again before anything that
# counts on both followers.
for _ in $(seq 1 60); do
    NODES=$(api_get /api/v1/cluster/nodes)
    CONNECTED=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.connected == true)] | length')
    [ "$CONNECTED" = "2" ] && break
    sleep 2
done
if [ "${CONNECTED:-0}" = "2" ]; then
    ok "both followers hold a live session"
else
    fail "the fleet is not whole: $CONNECTED follower(s) connected"
fi
EDGE_A_ID=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].node_id')
EDGE_B_ID=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-b")] | .[0].node_id')

ISSUER_UP=false
for _ in $(seq 1 60); do
    if curl -sk --max-time 5 "$OIDC_ISSUER/healthz" 2>/dev/null | jq -e '.status == "ok"' >/dev/null 2>&1; then
        ISSUER_UP=true
        break
    fi
    sleep 2
done
if [ "$ISSUER_UP" = "true" ]; then
    ok "the OIDC issuer fixture answers at $OIDC_ISSUER"
else
    fail "the OIDC issuer fixture never came up at $OIDC_ISSUER"
fi

# ---------------------------------------------------------------------
# Story 10.3 IV3, first half: the follower refusal run.sh drove.
# ---------------------------------------------------------------------
log "=== 10.3 IV3: a follower refuses --automation-listen ==="

REFUSAL_CODE=$(cat "$SHARED/edge-a_automation_refusal.code" 2>/dev/null || echo "missing")
if [ "$REFUSAL_CODE" != "missing" ] && [ "$REFUSAL_CODE" != "0" ]; then
    ok "a follower started with --automation-listen exited non-zero (exit $REFUSAL_CODE)"
else
    fail "the follower started with --automation-listen exited '$REFUSAL_CODE', expected non-zero"
fi
if grep -q "this node holds a follower identity" "$SHARED/edge-a_automation_refusal.log" 2>/dev/null \
   && grep -q "Point the automation at the control plane" "$SHARED/edge-a_automation_refusal.log" 2>/dev/null; then
    ok "the refusal is the documented message, naming the control plane"
else
    fail "the follower's log lacks the documented refusal: $(tail -c 400 "$SHARED/edge-a_automation_refusal.log" 2>/dev/null)"
fi

# ---------------------------------------------------------------------
# Story 10.3 IV1: the source filter, then the bearer gate.
# ---------------------------------------------------------------------
log "=== 10.3 IV1: outside the allowlist there is no handshake ==="

REFUSED_BEFORE=$(cp_metric 'lorica_automation_source_refused_total')
# The counter is registered on its first increment (a `Lazy` the
# supervisor never forces, unlike the cluster counters), so before the
# first refusal it is absent from /metrics and reads as empty: that is 0.
REFUSED_BEFORE="${REFUSED_BEFORE:-0}"
if [ -n "$CP_OUT" ]; then
    OUT_CODE=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
        "https://${CP_OUT}:${AUTOMATION_PORT}/automation/v1/whoami" 2>/dev/null || true)
    if [ "$OUT_CODE" = "000" ]; then
        ok "a connection from outside automation_allowed_cidrs gets no HTTP response"
    else
        fail "a connection from outside the allowlist answered HTTP $OUT_CODE; it should have been dropped before the handshake"
    fi
    REFUSED_AFTER=$(cp_metric 'lorica_automation_source_refused_total')
    REFUSED_AFTER="${REFUSED_AFTER:-0}"
    if [ "${REFUSED_AFTER%.*}" -gt "${REFUSED_BEFORE%.*}" ] 2>/dev/null; then
        ok "lorica_automation_source_refused_total moved ($REFUSED_BEFORE -> $REFUSED_AFTER)"
    else
        fail "lorica_automation_source_refused_total did not move ($REFUSED_BEFORE -> $REFUSED_AFTER)"
    fi
fi

log "=== 10.3 IV1: inside, the bearer gate ==="

auto_call GET /automation/v1/whoami ""
if [ "$AUTO_CODE" = "401" ]; then
    ok "no credential is 401"
else
    fail "no credential answered $AUTO_CODE, expected 401"
fi
assert_header_value "$(cat "$AUTO_HEADERS")" "WWW-Authenticate" 'Bearer realm="lorica-automation"' \
    "the 401 carries the bearer challenge for the automation realm"
assert_unauth_reason "no_bearer" "the missing credential landed an audit row"

mint_static_token "acme-revoked" 600
TOKEN_REVOKED="$MINTED_TOKEN"
REVOKED_ID="$MINTED_PUBLIC_ID"
if [ -n "$TOKEN_REVOKED" ] && [ -n "$REVOKED_ID" ]; then
    ok "a token was minted on the management API (public id $REVOKED_ID)"
else
    fail "the management API did not mint a token"
fi
assert_status DELETE "$API/api/v1/automation/tokens/$REVOKED_ID" 200 "the token was revoked"
auto_call GET /automation/v1/whoami "$TOKEN_REVOKED"
if [ "$AUTO_CODE" = "401" ]; then
    ok "a revoked token is 401"
else
    fail "a revoked token answered $AUTO_CODE, expected 401"
fi
assert_unauth_reason "token_revoked" "the revoked token landed an audit row"

mint_static_token "acme-ci" 600
TOKEN_A="$MINTED_TOKEN"
TOKEN_A_ID="$MINTED_PUBLIC_ID"
mint_static_token "globex-ci" 600
TOKEN_B="$MINTED_TOKEN"
TOKEN_B_ID="$MINTED_PUBLIC_ID"
if [ -n "$TOKEN_A" ] && [ -n "$TOKEN_B" ]; then
    ok "two live tokens minted: acme-ci ($TOKEN_A_ID) and globex-ci ($TOKEN_B_ID)"
else
    fail "the working tokens were not minted"
fi

auto_call GET /automation/v1/whoami "$TOKEN_A"
if [ "$AUTO_CODE" = "200" ]; then
    ok "a live token reaches whoami"
else
    fail "a live token answered $AUTO_CODE on whoami: $(echo "$AUTO_BODY" | head -c 200)"
fi
assert_json "$AUTO_BODY" '.data.name' 'acme-ci' "whoami names the token"
assert_json "$AUTO_BODY" '.data.kind' 'static_token' "whoami reports the static-token kind"

# ---------------------------------------------------------------------
# Story 10.3 IV2: the two planes share no credential.
# ---------------------------------------------------------------------
log "=== 10.3 IV2: no credential crosses between the planes ==="

automation_slot
COOKIE_CODE=$(curl -sk --max-time 30 -o /dev/null -w '%{http_code}' -b "$CP_SESSION" \
    "https://${CP_IN}:${AUTOMATION_PORT}/automation/v1/whoami" 2>/dev/null || true)
if [ "$COOKIE_CODE" = "401" ]; then
    ok "a dashboard session cookie on the automation port is 401"
else
    fail "a dashboard session cookie on the automation port answered $COOKIE_CODE, expected 401"
fi
BEARER_HDR=$(mktemp)
printf 'Authorization: Bearer %s\n' "$TOKEN_A" > "$BEARER_HDR"
BEARER_CODE=$(curl -sk --max-time 30 -o /dev/null -w '%{http_code}' -H "@$BEARER_HDR" \
    "$CP_API/api/v1/status" 2>/dev/null || true)
rm -f "$BEARER_HDR"
if [ "$BEARER_CODE" = "401" ]; then
    ok "an automation token on the management port is 401"
else
    fail "an automation token on the management port answered $BEARER_CODE, expected 401"
fi

# ---------------------------------------------------------------------
# The wildcard certificate every environment below binds to, issued
# through Pebble by DNS-01 (the manual flow with challtestsrv publishing
# the TXT records), which is the path docs/automation.md points an
# operator at.
# ---------------------------------------------------------------------
log "=== 10.4: provisioning ${WILDCARD} through DNS-01 ==="

DNS_START=$(api_post /api/v1/acme/provision-dns-manual \
    "{\"domain\":\"${WILDCARD}\",\"staging\":true,\"contact_email\":\"admin@example.com\"}")
TXT_COUNT=$(echo "$DNS_START" | jq -r '.data.txt_records | length // 0')
if [ "${TXT_COUNT:-0}" -ge 1 ] 2>/dev/null; then
    ok "manual DNS-01 for ${WILDCARD} returned $TXT_COUNT TXT record(s)"
else
    fail "manual DNS-01 start for ${WILDCARD}: $(echo "$DNS_START" | head -c 300)"
fi
TXT_FAIL=0
while IFS=$'\t' read -r NAME VALUE; do
    [ -n "$NAME" ] || continue
    SET_TXT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CHALLTESTSRV/set-txt" \
        -d "{\"host\":\"${NAME}.\",\"value\":\"${VALUE}\"}")
    [ "$SET_TXT" = "200" ] || TXT_FAIL=1
done < <(echo "$DNS_START" | jq -r '(.data.txt_records // [])[] | [.name, .value] | @tsv')
if [ "$TXT_FAIL" = "0" ]; then
    ok "TXT record(s) published on challtestsrv"
else
    fail "publishing the TXT record(s) failed"
fi
CONFIRM_BODY=$(mktemp)
CONFIRM_CODE=$(curl -sk -o "$CONFIRM_BODY" -w '%{http_code}' --max-time 240 \
    -b "$SESSION" -X POST -H 'Content-Type: application/json' \
    -d "{\"domain\":\"${WILDCARD}\"}" "$API/api/v1/acme/provision-dns-manual/confirm")
if [ "$CONFIRM_CODE" = "200" ]; then
    ok "DNS-01 confirm issued the wildcard"
else
    fail "DNS-01 confirm HTTP $CONFIRM_CODE: $(head -c 300 "$CONFIRM_BODY")"
fi
rm -f "$CONFIRM_BODY"
CERT_ID=$(api_get /api/v1/certificates \
    | jq -r --arg d "$WILDCARD" '[.data.certificates[]? | select(.domain == $d)][0].id // empty')
if [ -n "$CERT_ID" ]; then
    ok "${WILDCARD} is in the control plane's store (id=$CERT_ID)"
else
    fail "no certificate for ${WILDCARD} on the control plane"
fi
# Pebble's root, so the chain the proxy serves can be validated for
# real rather than accepted with -k.
PEBBLE_ROOT=$(mktemp)
curl -sk --max-time 20 "$PEBBLE_MGMT/roots/0" > "$PEBBLE_ROOT" 2>/dev/null || true
if grep -q "BEGIN CERTIFICATE" "$PEBBLE_ROOT"; then
    ok "pebble's issuing root fetched for chain validation"
else
    fail "pebble's root could not be fetched from $PEBBLE_MGMT/roots/0"
fi

# $1 hostname, $2 node ip, $3 path. Validates the chain against pebble's
# root: `-q` keeps the image-wide `insecure` curlrc out of it.
tls_get() {
    curl -q -s --max-time 15 --cacert "$PEBBLE_ROOT" \
        --resolve "$1:8443:$2" "https://$1:8443$3" 2>/dev/null || true
}

# ---------------------------------------------------------------------
# Story 10.4 IV1: create, serve over TLS, idempotent PUT, move traffic.
# ---------------------------------------------------------------------
log "=== 10.4 IV1: the environment resource ==="

ENV1="pr-1"
ENV1_HOST="${ENV1}.${REVIEW_ZONE}"
ROUTES_BEFORE=$(api_get /api/v1/routes | jq -r '(.data.routes // []) | length')
BACKENDS_BEFORE=$(api_get /api/v1/backends | jq -r '(.data.backends // []) | length')

auto_call PUT "/automation/v1/environments/$ENV1" "$TOKEN_A" "$(env_body "$ENV1_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "201" ]; then
    ok "PUT $ENV1 created the environment (HTTP 201)"
else
    fail "PUT $ENV1 answered $AUTO_CODE: $(echo "$AUTO_BODY" | head -c 300)"
fi
assert_json "$AUTO_BODY" '.data.certificate_id' "$CERT_ID" "the response names the wildcard certificate"
assert_json "$AUTO_BODY" '.data.url' "https://${ENV1_HOST}/" "the response carries the environment URL"
assert_header_present "$(cat "$AUTO_HEADERS")" "ETag" "the response carries an ETag"
ROUTE1_ID=$(echo "$AUTO_BODY" | jq -r '.data.route_id // empty')
FLOOR_GEN=$(echo "$AUTO_BODY" | jq -r '.data.applied_generation // 0')
log "route $ROUTE1_ID, generation floor $FLOOR_GEN"

SERVED=""
for _ in $(seq 1 30); do
    SERVED=$(tls_get "$ENV1_HOST" "$CP_IN" /identity)
    echo "$SERVED" | jq -e '.backend == "backend1"' >/dev/null 2>&1 && break
    sleep 1
done
if echo "$SERVED" | jq -e '.backend == "backend1"' >/dev/null 2>&1; then
    ok "${ENV1_HOST} reaches backend1 through the proxy over TLS, chain validated against pebble's root"
else
    fail "${ENV1_HOST} over TLS did not reach backend1: '$(echo "$SERVED" | head -c 200)'"
fi

auto_call PUT "/automation/v1/environments/$ENV1" "$TOKEN_A" "$(env_body "$ENV1_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "200" ]; then
    ok "a second identical PUT is 200"
else
    fail "a second identical PUT answered $AUTO_CODE, expected 200"
fi
assert_json "$AUTO_BODY" '.data.route_id' "$ROUTE1_ID" "the second PUT kept the same route_id"

# Traffic through the control plane's own proxy while the backend set
# is replaced: every answer is recorded with its status and the
# backend that served it.
MOVE_LOG=$(mktemp)
(
    for _ in $(seq 1 80); do
        curl -s --max-time 5 -o /dev/null -w '%{http_code} %header{x-backend-id}\n' \
            -H "Host: $ENV1_HOST" "http://${CP_IN}:8080/identity" >> "$MOVE_LOG" 2>/dev/null \
            || echo "000 -" >> "$MOVE_LOG"
        sleep 0.1
    done
) &
MOVE_PID=$!
sleep 1
auto_call PUT "/automation/v1/environments/$ENV1" "$TOKEN_A" "$(env_body "$ENV1_HOST" "${BACKEND2_IP}:80" 300)"
if [ "$AUTO_CODE" = "200" ]; then
    ok "PUT with a new backend address is 200"
else
    fail "PUT with a new backend address answered $AUTO_CODE: $(echo "$AUTO_BODY" | head -c 200)"
fi
wait "$MOVE_PID" || true
MOVE_TOTAL=$(wc -l < "$MOVE_LOG" | tr -d ' ')
MOVE_BAD=$(awk '$1 >= 500 || $1 == "000" { n++ } END { print n+0 }' "$MOVE_LOG")
MOVE_B1=$(grep -c ' backend1' "$MOVE_LOG" || true)
MOVE_B2=$(grep -c ' backend2' "$MOVE_LOG" || true)
if [ "${MOVE_BAD:-1}" = "0" ] && [ "${MOVE_TOTAL:-0}" -gt 0 ]; then
    ok "no 5xx and no dropped request while the backend moved ($MOVE_TOTAL requests: $MOVE_B1 by backend1, $MOVE_B2 by backend2)"
else
    fail "$MOVE_BAD of $MOVE_TOTAL requests failed while the backend moved: $(awk '$1 >= 500 || $1 == "000"' "$MOVE_LOG" | sort | uniq -c | head -5 | tr '\n' ';')"
fi
rm -f "$MOVE_LOG"
MOVED=""
for _ in $(seq 1 30); do
    MOVED=$(curl -s --max-time 5 -H "Host: $ENV1_HOST" "http://${CP_IN}:8080/identity" 2>/dev/null || true)
    echo "$MOVED" | jq -e '.backend == "backend2"' >/dev/null 2>&1 && break
    sleep 1
done
if echo "$MOVED" | jq -e '.backend == "backend2"' >/dev/null 2>&1; then
    ok "traffic now reaches backend2"
else
    fail "traffic did not move to backend2: '$(echo "$MOVED" | head -c 200)'"
fi

# ---------------------------------------------------------------------
# Story 10.4 IV2: four refusals, no row behind any of them.
# ---------------------------------------------------------------------
log "=== 10.4 IV2: refusals leave nothing behind ==="

# A manual route INSIDE the token's grant, so the conflict is the
# refusal reached and not the hostname allowlist.
MANUAL_HOST="manual.${REVIEW_ZONE}"
MANUAL_BACKEND_ID=$(api_get /api/v1/backends | jq -r '(.data.backends // [])[0].id // empty')
MANUAL_ROUTE=$(api_post /api/v1/routes "{\"hostname\":\"${MANUAL_HOST}\",\"path_prefix\":\"/\",\"backend_ids\":[\"${MANUAL_BACKEND_ID}\"],\"enabled\":true}")
MANUAL_ROUTE_ID=$(echo "$MANUAL_ROUTE" | jq -r '.data.id // empty')
if [ -n "$MANUAL_ROUTE_ID" ]; then
    ok "an operator's manual route holds ${MANUAL_HOST} (id=$MANUAL_ROUTE_ID)"
else
    fail "the manual route was not created: $(echo "$MANUAL_ROUTE" | head -c 200)"
fi

ROUTES_AT=$(api_get /api/v1/routes | jq -r '(.data.routes // []) | length')
BACKENDS_AT=$(api_get /api/v1/backends | jq -r '(.data.backends // []) | length')

auto_call PUT /automation/v1/environments/pr-bad-host "$TOKEN_A" "$(env_body "pr-bad.other.example.com" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "403" ]; then
    ok "a hostname outside allowed_hostnames is 403"
else
    fail "a hostname outside allowed_hostnames answered $AUTO_CODE, expected 403"
fi
auto_call PUT /automation/v1/environments/pr-bad-backend "$TOKEN_A" "$(env_body "pr-bad-backend.${REVIEW_ZONE}" "192.0.2.10:80" 300)"
if [ "$AUTO_CODE" = "403" ]; then
    ok "a backend outside allowed_backend_cidrs is 403"
else
    fail "a backend outside allowed_backend_cidrs answered $AUTO_CODE, expected 403"
fi
auto_call PUT /automation/v1/environments/pr-bad-ttl "$TOKEN_A" "$(env_body "pr-bad-ttl.${REVIEW_ZONE}" "${BACKEND1_IP}:80" 601)"
if [ "$AUTO_CODE" = "422" ]; then
    ok "a ttl above the token's max_ttl_seconds is 422"
else
    fail "a ttl above max_ttl_seconds answered $AUTO_CODE, expected 422"
fi
auto_call PUT /automation/v1/environments/pr-bad-taken "$TOKEN_A" "$(env_body "$MANUAL_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "409" ]; then
    ok "a hostname owned by a manual route is 409"
else
    fail "a hostname owned by a manual route answered $AUTO_CODE, expected 409"
fi
if echo "$AUTO_BODY" | grep -q "$MANUAL_HOST" && ! echo "$AUTO_BODY" | grep -q "$MANUAL_ROUTE_ID"; then
    ok "the 409 names the hostname and nothing about the route holding it"
else
    fail "the 409 body is not the documented shape: $(echo "$AUTO_BODY" | head -c 200)"
fi

ROUTES_AFTER=$(api_get /api/v1/routes | jq -r '(.data.routes // []) | length')
BACKENDS_AFTER=$(api_get /api/v1/backends | jq -r '(.data.backends // []) | length')
if [ "$ROUTES_AFTER" = "$ROUTES_AT" ] && [ "$BACKENDS_AFTER" = "$BACKENDS_AT" ]; then
    ok "no route and no backend was left behind by the four refusals ($ROUTES_AFTER routes, $BACKENDS_AFTER backends)"
else
    fail "rows left behind: routes $ROUTES_AT -> $ROUTES_AFTER, backends $BACKENDS_AT -> $BACKENDS_AFTER"
fi
auto_call GET "/automation/v1/environments" "$TOKEN_A"
BAD_ENVS=$(echo "$AUTO_BODY" | jq -r '[(.data.environments // [])[] | select(.name | startswith("pr-bad"))] | length')
if [ "$BAD_ENVS" = "0" ]; then
    ok "no environment row was left behind either"
else
    fail "$BAD_ENVS refused environment(s) exist in the listing"
fi

# ---------------------------------------------------------------------
# Story 10.4 IV4 and 10.3 IV3, second half: the environment reaches
# both followers, past the generation floor, with two hashes.
# ---------------------------------------------------------------------
log "=== 10.4 IV4: convergence past the floor, with two hashes ==="

HASH_A0=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].applied_config_hash // "none"')
HASH_B0=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-b")] | .[0].applied_config_hash // "none"')
for _ in $(seq 1 60); do
    NODES=$(api_get /api/v1/cluster/nodes)
    PAST=$(echo "$NODES" | jq -r --argjson g "$FLOOR_GEN" \
        '[(.data // [])[] | select(.applied_config_generation > $g)] | length')
    [ "$PAST" = "2" ] && break
    sleep 2
done
if [ "${PAST:-0}" = "2" ]; then
    ok "both followers report a generation past the floor $FLOOR_GEN"
else
    fail "the followers did not pass the floor $FLOOR_GEN within 120s: $(echo "$NODES" | jq -c '[.data[]? | {name, applied_config_generation}]')"
fi
HASH_A1=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].applied_config_hash // "none"')
HASH_B1=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-b")] | .[0].applied_config_hash // "none"')
if [ "$HASH_A0" != "$HASH_B0" ] && [ "$HASH_A1" != "$HASH_B1" ] && [ "$HASH_A1" != "none" ]; then
    ok "the followers reported different hashes before and after, and the poll succeeded anyway"
else
    fail "hash agreement was expected to be irrelevant: before edge-a '$HASH_A0' edge-b '$HASH_B0', after edge-a '$HASH_A1' edge-b '$HASH_B1'"
fi

for node in edge-a edge-b; do
    case "$node" in
        edge-a) API="$EDGE_A_API"; NODE_IP="$EDGE_A_IP" ;;
        edge-b) API="$EDGE_B_API"; NODE_IP="$EDGE_B_IP" ;;
    esac
    wait_for_api 60 || { fail "$node's API never answered"; continue; }
    login "$(cat "$SHARED/${node}_admin_password")"
    for _ in $(seq 1 30); do
        NODE_ROUTES=$(api_get /api/v1/routes)
        HAS=$(echo "$NODE_ROUTES" | jq -r --arg h "$ENV1_HOST" '[(.data.routes // [])[] | select(.hostname == $h)] | length')
        [ "$HAS" = "1" ] && break
        sleep 2
    done
    if [ "${HAS:-0}" = "1" ]; then
        ok "$node holds the environment's route"
    else
        fail "$node never received the route for $ENV1_HOST"
    fi
    assert_json "$NODE_ROUTES" "[(.data.routes // [])[] | select(.hostname == \"$ENV1_HOST\")] | .[0].managed_by.environment" "$ENV1" \
        "$node's copy carries the managed_by mark"
    NODE_SERVED=""
    for _ in $(seq 1 30); do
        NODE_SERVED=$(tls_get "$ENV1_HOST" "$NODE_IP" /identity)
        echo "$NODE_SERVED" | jq -e '.backend == "backend2"' >/dev/null 2>&1 && break
        sleep 2
    done
    if echo "$NODE_SERVED" | jq -e '.backend == "backend2"' >/dev/null 2>&1; then
        ok "$node serves ${ENV1_HOST} over TLS with a chain that validates, so it received the wildcard's key"
    else
        fail "$node does not serve ${ENV1_HOST} over TLS: '$(echo "$NODE_SERVED" | head -c 200)'"
    fi
done
API="$CP_API"
SESSION="$CP_SESSION"

# ---------------------------------------------------------------------
# Story 10.4 IV5: ownership, on all three verbs.
# ---------------------------------------------------------------------
log "=== 10.4 IV5: another principal is refused on GET, PUT and DELETE ==="

# 404, not 403: a 403 would confirm the name is taken by somebody else.
FORBIDDEN_BEFORE=$(count_audit automation.environment.forbidden "$ENV1")
auto_call GET "/automation/v1/environments/$ENV1" "$TOKEN_B"
if [ "$AUTO_CODE" = "404" ]; then ok "globex-ci cannot read pr-1 (404, indistinguishable from an unknown name)"; else fail "globex-ci read pr-1 with $AUTO_CODE, expected 404"; fi
auto_call PUT "/automation/v1/environments/$ENV1" "$TOKEN_B" "$(env_body "$ENV1_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "404" ]; then ok "globex-ci cannot update pr-1 (404)"; else fail "globex-ci updated pr-1 with $AUTO_CODE, expected 404"; fi
auto_call DELETE "/automation/v1/environments/$ENV1" "$TOKEN_B"
if [ "$AUTO_CODE" = "404" ]; then ok "globex-ci cannot delete pr-1 (404)"; else fail "globex-ci deleted pr-1 with $AUTO_CODE, expected 404"; fi
for _ in $(seq 1 10); do
    FORBIDDEN_AFTER=$(count_audit automation.environment.forbidden "$ENV1")
    [ $((FORBIDDEN_AFTER - FORBIDDEN_BEFORE)) -ge 3 ] && break
    sleep 1
done
if [ $((FORBIDDEN_AFTER - FORBIDDEN_BEFORE)) -eq 3 ]; then
    ok "three automation.environment.forbidden rows name pr-1"
else
    fail "expected 3 new automation.environment.forbidden rows for pr-1, got $((FORBIDDEN_AFTER - FORBIDDEN_BEFORE))"
fi
auto_call GET "/automation/v1/environments" "$TOKEN_B"
LISTED=$(echo "$AUTO_BODY" | jq -r --arg n "$ENV1" '[(.data.environments // [])[] | select(.name == $n)] | length')
if [ "$LISTED" = "0" ]; then
    ok "pr-1 is absent from globex-ci's listing rather than refused"
else
    fail "pr-1 is visible in globex-ci's listing"
fi

# ---------------------------------------------------------------------
# Story 10.4 IV3: the reaper, then the pipeline's own DELETE.
# ---------------------------------------------------------------------
log "=== 10.4 IV3: ttl 90 s is collected within 150 s ==="

ENV_TTL="pr-ttl"
ENV_TTL_HOST="${ENV_TTL}.${REVIEW_ZONE}"
auto_call PUT "/automation/v1/environments/$ENV_TTL" "$TOKEN_A" "$(env_body "$ENV_TTL_HOST" "${BACKEND1_IP}:80" 90)"
TTL_T0=$(date +%s)
if [ "$AUTO_CODE" = "201" ]; then
    ok "PUT $ENV_TTL with ttl_seconds 90 is 201"
else
    fail "PUT $ENV_TTL answered $AUTO_CODE: $(echo "$AUTO_BODY" | head -c 200)"
fi
for _ in $(seq 1 10); do
    [ "$(route_count_for_hostname "$ENV_TTL_HOST")" = "1" ] && break
    sleep 1
done
if [ "$(route_count_for_hostname "$ENV_TTL_HOST")" = "1" ]; then
    ok "$ENV_TTL_HOST is in the route table"
else
    fail "$ENV_TTL_HOST never appeared in the route table"
fi
ENV_DEL="pr-del"
ENV_DEL_HOST="${ENV_DEL}.${REVIEW_ZONE}"
auto_call PUT "/automation/v1/environments/$ENV_DEL" "$TOKEN_A" "$(env_body "$ENV_DEL_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "201" ]; then
    ok "PUT $ENV_DEL is 201"
else
    fail "PUT $ENV_DEL answered $AUTO_CODE"
fi
auto_call DELETE "/automation/v1/environments/$ENV_DEL" "$TOKEN_A"
if [ "$AUTO_CODE" = "204" ]; then
    ok "DELETE $ENV_DEL is 204"
else
    fail "DELETE $ENV_DEL answered $AUTO_CODE, expected 204"
fi
if [ "$(route_count_for_hostname "$ENV_DEL_HOST")" = "0" ]; then
    ok "the DELETE removed the route immediately"
else
    fail "the route for $ENV_DEL_HOST is still there after the DELETE"
fi
auto_call GET "/automation/v1/environments/$ENV_DEL" "$TOKEN_A"
if [ "$AUTO_CODE" = "404" ]; then
    ok "the deleted environment is 404"
else
    fail "the deleted environment answered $AUTO_CODE, expected 404"
fi
auto_call DELETE "/automation/v1/environments/$ENV_DEL" "$TOKEN_A"
if [ "$AUTO_CODE" = "204" ]; then
    ok "a second DELETE is 204"
else
    fail "a second DELETE answered $AUTO_CODE, expected 204"
fi

# The reaper sweeps every 60 s; the route table is polled on the
# management API (no connection budget there) and the automation GET is
# asked once at the end.
GONE_AT=""
for _ in $(seq 1 160); do
    if [ "$(route_count_for_hostname "$ENV_TTL_HOST")" = "0" ]; then
        GONE_AT=$(date +%s)
        break
    fi
    sleep 1
done
if [ -n "$GONE_AT" ] && [ $((GONE_AT - TTL_T0)) -le 150 ]; then
    ok "$ENV_TTL was collected $((GONE_AT - TTL_T0))s after its creation (ttl 90 s)"
else
    fail "$ENV_TTL was not collected within 150 s (gone at: '${GONE_AT:-never}')"
fi
auto_call GET "/automation/v1/environments/$ENV_TTL" "$TOKEN_A"
if [ "$AUTO_CODE" = "404" ]; then
    ok "the collected environment is 404 on the automation API"
else
    fail "the collected environment answered $AUTO_CODE, expected 404"
fi
EXPIRED_ROWS=0
for _ in $(seq 1 10); do
    EXPIRED_ROWS=$(count_audit automation.environment.expired "$ENV_TTL")
    [ "${EXPIRED_ROWS:-0}" -ge 1 ] && break
    sleep 1
done
if [ "${EXPIRED_ROWS:-0}" -ge 1 ]; then
    ok "the reaper audited automation.environment.expired for $ENV_TTL"
else
    fail "no automation.environment.expired row names $ENV_TTL"
fi
# The TLS resolver is keyed by certificate SAN, not by route, so the
# wildcard is still presented for the hostname; what the proxy does
# behind the handshake is what shows the route is gone.
TTL_TLS_CODE=$(curl -q -s --max-time 15 -o /dev/null -w '%{http_code}' --cacert "$PEBBLE_ROOT" \
    --resolve "$ENV_TTL_HOST:8443:$CP_IN" "https://$ENV_TTL_HOST:8443/identity" 2>/dev/null || true)
if [ "$TTL_TLS_CODE" = "404" ]; then
    ok "over TLS the collected hostname answers 404: no route behind the handshake"
else
    fail "over TLS the collected hostname answered '$TTL_TLS_CODE', expected 404"
fi

# ---------------------------------------------------------------------
# Story 10.5: GitLab OIDC against the fixture issuer.
# ---------------------------------------------------------------------
log "=== 10.5: registering the fixture issuer ==="

ISSUER_OUT=$(api_post /api/v1/automation/oidc-issuers "{\"issuer\":\"${OIDC_ISSUER}\",\"audience\":\"${OIDC_AUDIENCE}\",\"bound_claims\":{\"project_path\":\"acme/*\",\"ref_protected\":\"true\"},\"allowed_hostnames\":[\"${WILDCARD}\"],\"allowed_backend_cidrs\":[\"${ALLOW_CIDR}\"],\"max_ttl_seconds\":600,\"scopes\":[\"environments:read\",\"environments:write\"]}")
ISSUER_ID=$(echo "$ISSUER_OUT" | jq -r '.data.id // empty')
if [ -n "$ISSUER_ID" ]; then
    ok "issuer entry registered (id=$ISSUER_ID)"
else
    fail "issuer registration: $(echo "$ISSUER_OUT" | head -c 300)"
fi
assert_json "$ISSUER_OUT" '.data.jwks_url' "${OIDC_ISSUER}/oauth/discovery/keys" \
    "the entry defaults jwks_url to the GitLab discovery path"

log "=== 10.5 IV1: an ID token creates an environment; each defect has its own reason ==="

ENV_OIDC="oidc-mr-1"
ENV_OIDC_HOST="${ENV_OIDC}.${REVIEW_ZONE}"
FETCHES_0=$(fixture_fetches)
ID_TOKEN=$(fixture_mint '{}')
auto_call PUT "/automation/v1/environments/$ENV_OIDC" "$ID_TOKEN" "$(env_body "$ENV_OIDC_HOST" "${BACKEND1_IP}:80" 300)"
if [ "$AUTO_CODE" = "201" ]; then
    ok "an ID token with matching bound claims created $ENV_OIDC (HTTP 201)"
else
    fail "an ID token answered $AUTO_CODE on PUT $ENV_OIDC: $(echo "$AUTO_BODY" | head -c 200); newest audit reason '$(latest_unauth_reason)'"
fi
FETCHES_1=$(fixture_fetches)
if [ "${FETCHES_1:-0}" -gt "${FETCHES_0:-0}" ]; then
    ok "the control plane fetched the fixture's JWKS ($FETCHES_0 -> $FETCHES_1)"
else
    fail "the control plane never fetched the fixture's JWKS (fetches $FETCHES_0 -> $FETCHES_1); the verifier cannot have trusted the fixture"
fi
auto_call GET "/automation/v1/environments/$ENV_OIDC" "$(fixture_mint '{}')"
if [ "$AUTO_CODE" = "200" ]; then
    ok "the project reads its own environment back"
else
    fail "GET $ENV_OIDC with an ID token answered $AUTO_CODE"
fi
assert_json "$AUTO_BODY" '.data.owner.kind' 'oidc_project' "the environment is owned by the project"
assert_json "$AUTO_BODY" '.data.owner.principal' 'acme/web' "the owner is the project path"
assert_json "$AUTO_BODY" '.data.pipeline.job_id' '5678' "the job identity was recorded"

auto_call GET /automation/v1/whoami "$(fixture_mint '{"claims":{"project_path":"globex/web","sub":"project_path:globex/web"}}')"
[ "$AUTO_CODE" = "401" ] && ok "a token for another project is 401" || fail "a token for another project answered $AUTO_CODE"
assert_unauth_reason "bound_claim_mismatch:project_path" "the wrong project is named in the audit row"

auto_call GET /automation/v1/whoami "$(fixture_mint '{"claims":{"aud":"lorica-somewhere-else"}}')"
[ "$AUTO_CODE" = "401" ] && ok "a token for another audience is 401" || fail "a token for another audience answered $AUTO_CODE"
assert_unauth_reason "no_issuer" "the unknown audience is named in the audit row"

NOW_EPOCH=$(date +%s)
auto_call GET /automation/v1/whoami "$(fixture_mint "{\"claims\":{\"iat\":$((NOW_EPOCH - 900)),\"nbf\":$((NOW_EPOCH - 900)),\"exp\":$((NOW_EPOCH - 600))}}")"
[ "$AUTO_CODE" = "401" ] && ok "an expired token is 401" || fail "an expired token answered $AUTO_CODE"
assert_unauth_reason "expired" "the expiry is named in the audit row"

TAMPERED="${ID_TOKEN%?}A"
[ "$TAMPERED" = "$ID_TOKEN" ] && TAMPERED="${ID_TOKEN%?}B"
auto_call GET /automation/v1/whoami "$TAMPERED"
[ "$AUTO_CODE" = "401" ] && ok "a token with a damaged signature is 401" || fail "a damaged signature answered $AUTO_CODE"
assert_unauth_reason "bad_signature" "the bad signature is named in the audit row"

auto_call GET /automation/v1/whoami "$ID_TOKEN"
[ "$AUTO_CODE" = "401" ] && ok "the token that created the environment is refused a second time" || fail "a replayed token answered $AUTO_CODE"
assert_unauth_reason "replayed" "the replay is named in the audit row"

log "=== 10.5 IV4: algorithm confusion ==="

auto_call GET /automation/v1/whoami "$(fixture_mint '{"alg":"HS256"}')"
[ "$AUTO_CODE" = "401" ] && ok "HS256 under the issuer's public key is 401" || fail "HS256 under the public key answered $AUTO_CODE"
assert_unauth_reason "wrong_alg" "HS256 is refused as wrong_alg"
# An alg-none token is `header.payload.` with an empty third segment:
# `looks_like_jwt` wants three non-empty segments, so the bearer gate
# refuses it before any header is decoded, as not_a_credential.
auto_call GET /automation/v1/whoami "$(fixture_mint '{"alg":"none"}')"
[ "$AUTO_CODE" = "401" ] && ok "alg none is 401" || fail "alg none answered $AUTO_CODE"
assert_unauth_reason "not_a_credential" "alg none never passes the bearer shape test"

log "=== 10.5 IV5: a thousand unknown kids, one connection, at most one fetch ==="

BATCH=$(mktemp)
curl -sk --max-time 300 -X POST -H 'Content-Type: application/json' \
    -d '{"count":1000}' "$OIDC_ISSUER/mint-batch" > "$BATCH" 2>/dev/null || true
BATCH_COUNT=$(jq -r '.tokens | length' "$BATCH" 2>/dev/null || echo 0)
if [ "$BATCH_COUNT" = "1000" ]; then
    ok "the fixture minted 1000 tokens under distinct unknown kids"
else
    fail "the fixture minted $BATCH_COUNT tokens, expected 1000"
fi
wait_refetch_window
FETCHES_2=$(fixture_fetches)
BURST=$(mktemp)
cat > "$BURST" <<'PYEOF'
import http.client
import json
import ssl
import sys

host, port, tokens_file, out_file = sys.argv[1:5]
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with open(tokens_file, encoding="utf-8") as handle:
    tokens = json.load(handle)["tokens"]
codes = {}
connections = 0
conn = None
for token in tokens:
    for attempt in range(2):
        try:
            if conn is None:
                conn = http.client.HTTPSConnection(host, int(port), context=context, timeout=20)
                connections += 1
            conn.request(
                "GET",
                "/automation/v1/whoami",
                headers={"Authorization": "Bearer " + token, "Connection": "keep-alive"},
            )
            response = conn.getresponse()
            response.read()
            codes[str(response.status)] = codes.get(str(response.status), 0) + 1
            if response.getheader("Connection", "").lower() == "close":
                conn.close()
                conn = None
            break
        except (http.client.HTTPException, OSError):
            conn = None
            if attempt == 1:
                codes["error"] = codes.get("error", 0) + 1
if conn is not None:
    conn.close()
with open(out_file, "w", encoding="utf-8") as handle:
    json.dump({"codes": codes, "connections": connections}, handle)
PYEOF
BURST_OUT=$(mktemp)
automation_slot
automation_slot
BURST_T0=$(date +%s)
python3 "$BURST" "$CP_IN" "$AUTOMATION_PORT" "$BATCH" "$BURST_OUT" || true
BURST_T1=$(date +%s)
BURST_401=$(jq -r '.codes["401"] // 0' "$BURST_OUT" 2>/dev/null || echo 0)
BURST_CONNS=$(jq -r '.connections // 0' "$BURST_OUT" 2>/dev/null || echo 0)
if [ "$BURST_401" = "1000" ]; then
    ok "all 1000 unknown-kid tokens were refused with 401 over $BURST_CONNS connection(s) in $((BURST_T1 - BURST_T0))s"
else
    fail "expected 1000 refusals, got: $(cat "$BURST_OUT" 2>/dev/null | head -c 200)"
fi
FETCHES_3=$(fixture_fetches)
if [ $((FETCHES_3 - FETCHES_2)) -le 1 ]; then
    ok "a thousand unknown kids cost $((FETCHES_3 - FETCHES_2)) JWKS fetch(es)"
else
    fail "a thousand unknown kids cost $((FETCHES_3 - FETCHES_2)) JWKS fetches, expected at most one"
fi
rm -f "$BATCH" "$BURST" "$BURST_OUT"

log "=== 10.5 IV2: rotation without a restart, and an issuer outage ==="

wait_refetch_window
ROTATED=$(curl -sk --max-time 60 -X POST -H 'Content-Type: application/json' -d '{}' "$OIDC_ISSUER/rotate" 2>/dev/null)
NEW_KID=$(echo "$ROTATED" | jq -r '.kid // empty')
if [ -n "$NEW_KID" ]; then
    ok "the fixture rotated its signing key to kid $NEW_KID"
else
    fail "the fixture did not rotate: $ROTATED"
fi
auto_call GET /automation/v1/whoami "$(fixture_mint '{}')"
if [ "$AUTO_CODE" = "200" ]; then
    ok "a token under the rotated key is accepted with no restart"
else
    fail "a token under the rotated key answered $AUTO_CODE; newest audit reason '$(latest_unauth_reason)'"
fi
assert_json "$AUTO_BODY" '.data.kind' 'oidc_project' "whoami reports the OIDC kind"
assert_json "$AUTO_BODY" '.data.pipeline.project_path' 'acme/web' "whoami reports the pipeline identity"

curl -sk --max-time 10 -X POST -H 'Content-Type: application/json' -d '{"enabled":true}' "$OIDC_ISSUER/outage" >/dev/null 2>&1 || true
auto_call GET /automation/v1/whoami "$(fixture_mint '{}')"
if [ "$AUTO_CODE" = "200" ]; then
    ok "with the issuer down, the cached key still verifies (fail-closed after the 6 h refresh interval is covered in-process)"
else
    fail "with the issuer down, a token under the cached key answered $AUTO_CODE"
fi
curl -sk --max-time 10 -X POST -H 'Content-Type: application/json' -d '{"enabled":false}' "$OIDC_ISSUER/outage" >/dev/null 2>&1 || true

log "=== 10.5 IV3: removing the issuer entry ==="

assert_status DELETE "$API/api/v1/automation/oidc-issuers/$ISSUER_ID" 204 "the issuer entry was removed"
auto_call GET /automation/v1/whoami "$(fixture_mint '{}')"
if [ "$AUTO_CODE" = "401" ]; then
    ok "the very next ID token is 401"
else
    fail "an ID token after the removal answered $AUTO_CODE, expected 401"
fi
assert_unauth_reason "no_issuer" "the removal reads as no_issuer in the audit row"

# ---------------------------------------------------------------------
# Cleanup: the static-token environment through its owner, the OIDC one
# through the management route (a managed route's DELETE cascades the
# environment), so the revocation phase runs against the fleet the
# cluster smoke left.
# ---------------------------------------------------------------------
auto_call DELETE "/automation/v1/environments/$ENV1" "$TOKEN_A"
[ "$AUTO_CODE" = "204" ] && ok "pr-1 deleted by its owner" || fail "deleting pr-1 answered $AUTO_CODE"
OIDC_ROUTE_ID=$(api_get /api/v1/routes | jq -r --arg h "$ENV_OIDC_HOST" '[(.data.routes // [])[] | select(.hostname == $h)] | .[0].id // empty')
if [ -n "$OIDC_ROUTE_ID" ]; then
    assert_status DELETE "$API/api/v1/routes/$OIDC_ROUTE_ID" 200 "the OIDC environment's managed route deleted through the management API (cascades the environment)"
fi
if [ -n "$MANUAL_ROUTE_ID" ]; then
    api_del "/api/v1/routes/$MANUAL_ROUTE_ID" >/dev/null
fi
rm -f "$PEBBLE_ROOT"
[ -n "$AUTO_HEADERS" ] && rm -f "$AUTO_HEADERS"

print_results
