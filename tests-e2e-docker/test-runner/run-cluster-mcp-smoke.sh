#!/usr/bin/env bash
# =============================================================================
# Lorica cluster E2E: the MCP phase (Story 11.2 IV3, backlog #91).
#
# Story 11.2 claims a config-tier mutation on the control plane
# replicates to the followers: the automation plane runs the management
# handler's own body, and the management API's writes are what the
# cluster replicates. The `mcp` profile proves the mutation on a
# standalone node; this phase proves the replication half, on the fleet
# the earlier cluster phases built. What it asserts:
#
#   - a config-tier token minted on the control plane by the real
#     `lorica mcp token create --tier config`;
#   - a `lorica-mcp` session on it creates a route inside the grant, and
#     the control plane's audit row names the MCP transport and the tool;
#   - each follower holds that route within a bounded wait;
#   - the same session changes the route (`waf_enabled` on, the one
#     direction a config-tier token may move it), and each follower
#     converges on the changed value within a bounded wait.
#
# The other half of the automation plane's cluster contract, a follower
# refusing to serve the automation listener, is the automation phase's
# Story 10.3 IV3 check (run-automation-smoke.sh) and is not repeated.
#
# It runs from the Lorica image in the control plane's network namespace
# (see the `cluster-mcp-smoke` service in docker-compose.yml): the CLI
# mints through the management API at 127.0.0.1 only, and the listener's
# certificate names 127.0.0.1, which the control plane allowlists for
# this phase (entrypoint-cluster-cp.sh). The followers' management APIs
# are reached over the e2e network, which that namespace sits on.
#
# Pre-requisite: the `cluster` profile is up and the main cluster smoke
# has run: it activates both followers, and a follower still pending
# after enrolment receives no configuration (Story 9.3 AC #5). run.sh
# runs this after the restart and automation phases and before
# revocation, which is terminal for a follower.
# =============================================================================

# `-u` without `-e`, as run-mcp-smoke.sh: the mint's exit code is
# asserted rather than aborted on.
set -u
# A write to a lorica-mcp that died would raise SIGPIPE and kill the
# shell before `print_results`. A broken write fails its call instead.
trap '' PIPE

source /tests/helpers.sh
source /tests/mcp-helpers.sh

SHARED="${SHARED_DIR:-/shared}"
EDGE_A_API="${EDGE_A_API:?EDGE_A_API is required}"
EDGE_B_API="${EDGE_B_API:?EDGE_B_API is required}"
MANAGEMENT_PORT=19443
CP_API="https://127.0.0.1:${MANAGEMENT_PORT}"
API="$CP_API"
ENDPOINT="https://127.0.0.1:9446"
# The listener serves the management plane's leaf; the control plane's
# data directory is mounted read-only at the CLI's default --data-dir.
CA_BUNDLE="/var/lib/lorica/management/cert.pem"
PASSWORD_FILE="$SHARED/cp_admin_password"
GRANTED_PATTERN="*.mcp-fleet.example.com"
ROUTE_HOST="app.mcp-fleet.example.com"
BACKEND_CIDR="192.0.2.0/24"
WORK=$(mktemp -d)
# Polls of 2 s: 60 s for a follower to converge on one write.
CONVERGE_POLLS=30

# $1 hostname, $2 field of the route the current API lists. Empty when
# no route carries that hostname.
route_field() {
    json "$(api_get /api/v1/routes)" \
        "SELECT e.value->>'$2' FROM d, json_each(d.doc, '\$.data.routes') e
         WHERE e.value->>'hostname' = '$1'"
}

# $1 node label, $2 API, $3 field, $4 expected value, $5 what converged.
# Logs in to the follower and polls its own route listing.
assert_follower_converges() {
    local node="$1" field="$3" expected="$4" what="$5" actual=""
    API="$2"
    if ! wait_for_api 60; then
        fail "[$node] the management API never answered"
        API="$CP_API"
        SESSION="$CP_SESSION"
        return
    fi
    login "$(cat "$SHARED/${node}_admin_password")"
    for _ in $(seq 1 "$CONVERGE_POLLS"); do
        actual=$(route_field "$ROUTE_HOST" "$field")
        [ "$actual" = "$expected" ] && break
        sleep 2
    done
    if [ "$actual" = "$expected" ]; then
        ok "[$node] converged on $what ($field = $expected)"
    else
        fail "[$node] did not converge on $what within $((CONVERGE_POLLS * 2))s ($field = '$actual', expected '$expected')"
    fi
    API="$CP_API"
    SESSION="$CP_SESSION"
}

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== cluster mcp phase: preflight ==="

for marker in cp_ready edge-a_ready edge-b_ready; do
    for _ in $(seq 1 180); do
        [ -f "$SHARED/$marker" ] && break
        sleep 1
    done
    if [ ! -f "$SHARED/$marker" ]; then
        fail "$marker never appeared"
        print_results
    fi
done

if ! wait_for_api 120; then
    fail "the control plane's management API never answered"
    print_results
fi
login "$(cat "$PASSWORD_FILE")"
CP_SESSION="$SESSION"

CONNECTED=0
for _ in $(seq 1 60); do
    CONNECTED=$(json "$(api_get /api/v1/cluster/nodes)" \
        "SELECT count(*) FROM d, json_each(d.doc, '\$.data') e
         WHERE e.value->>'connected' = 1 AND e.value->>'status' = 'active'")
    [ "$CONNECTED" = "2" ] && break
    sleep 2
done
if [ "$CONNECTED" = "2" ]; then
    ok "both followers are active and hold a live session with the control plane"
else
    fail "the fleet is not whole: '$CONNECTED' follower(s) active and connected (has the main cluster smoke run?)"
    print_results
fi

LISTENER_CODE=""
for _ in $(seq 1 15); do
    LISTENER_CODE=$(curl -s --cacert "$CA_BUNDLE" -o /dev/null -w '%{http_code}' \
        "$ENDPOINT/automation/v1/whoami" 2>/dev/null || true)
    [ -n "$LISTENER_CODE" ] && [ "$LISTENER_CODE" != "000" ] && break
    sleep 2
done
if [ "$LISTENER_CODE" = "401" ]; then
    ok "the control plane's automation listener admits loopback and verifies against its own certificate (401 without a token)"
else
    fail "the automation listener answered '$LISTENER_CODE' on $ENDPOINT, expected 401"
    print_results
fi

# ---------------------------------------------------------------------
# The mint and the session.
# ---------------------------------------------------------------------
log "=== cluster mcp phase: config-tier token on the control plane ==="

mint_tier config --hostname "$GRANTED_PATTERN" --backend-cidr "$BACKEND_CIDR"
PUBLIC_ID=$(sed -n 's/.*minted automation token \([^ ,]*\).*/\1/p' "$MINT_ERR" | head -1)
if [ "$MINT_CODE" = "0" ] && [ -n "$MINTED" ] && [ -n "$PUBLIC_ID" ]; then
    ok "lorica mcp token create --tier config minted $PUBLIC_ID on the control plane"
else
    fail "lorica mcp token create --tier config exited $MINT_CODE: $(tail -c 400 "$MINT_ERR")"
    print_results
fi
OPERATOR="mcp-config ($PUBLIC_ID)"

start_session "$MINTED" cluster-config
if [ -n "$REVISION" ] && grep -q "Token $PUBLIC_ID registered" "$SESSION_ERR"; then
    ok "lorica-mcp serves the token $PUBLIC_ID against the control plane (revision $REVISION)"
else
    fail "lorica-mcp did not start on the token: $(tail -c 400 "$SESSION_ERR")"
    print_results
fi

# ---------------------------------------------------------------------
# Story 11.2 IV3: a config-tier create replicates.
# ---------------------------------------------------------------------
log "=== cluster mcp phase: a route created through lorica-mcp reaches the followers ==="

call_tool lorica_route_create "{\"route\":{\"hostname\":\"$ROUTE_HOST\"}}"
ROUTE_ID=$(route_field "$ROUTE_HOST" id)
if [ "$(answer_field '$.result.isError')" = "0" ] && [ -n "$ROUTE_ID" ] \
    && [ "$(route_field "$ROUTE_HOST" waf_enabled)" = "0" ]; then
    ok "lorica_route_create created $ROUTE_HOST ($ROUTE_ID) on the control plane, waf off"
else
    fail "lorica_route_create answered: $RPC_ANSWER"
    print_results
fi
assert_audit "$OPERATOR" "automation.request.ok" "POST /automation/v1/routes" \
    lorica_route_create "[cp] the create"

assert_follower_converges edge-a "$EDGE_A_API" hostname "$ROUTE_HOST" "the created route"
assert_follower_converges edge-b "$EDGE_B_API" hostname "$ROUTE_HOST" "the created route"

# ---------------------------------------------------------------------
# Story 11.2 IV3: a config-tier change replicates.
# ---------------------------------------------------------------------
log "=== cluster mcp phase: the route changed through lorica-mcp converges on the followers ==="

call_tool lorica_route_update "{\"id\":\"$ROUTE_ID\",\"route\":{\"waf_enabled\":true}}"
if [ "$(answer_field '$.result.isError')" = "0" ] \
    && [ "$(route_field "$ROUTE_HOST" waf_enabled)" = "1" ]; then
    ok "lorica_route_update turned the WAF on for $ROUTE_HOST on the control plane"
else
    fail "lorica_route_update answered: $RPC_ANSWER"
fi
# The row records the path as lorica-mcp sent it, which keeps the id's
# hyphens, so the id an operator searches for is the one it finds.
assert_audit "$OPERATOR" "automation.request.ok" "PUT /automation/v1/routes/$ROUTE_ID" \
    lorica_route_update "[cp] the change"

assert_follower_converges edge-a "$EDGE_A_API" waf_enabled 1 "the changed route"
assert_follower_converges edge-b "$EDGE_B_API" waf_enabled 1 "the changed route"

end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "closing stdin ended the session with exit 0"
else
    fail "the session ended with exit $SESSION_CODE"
fi

print_results
