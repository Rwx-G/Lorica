#!/usr/bin/env bash
# =============================================================================
# Lorica cluster E2E smoke (Epic 9 Integration Verification, backlog #66)
#
# One profile covering the Integration Verification of stories 9.2
# through 9.9, which until now had never run against real nodes: every
# one of those stories shipped on unit and integration tests alone, and
# their story files say so.
#
# Topology: one control plane (`lorica-cp`) and two followers, one
# single-process (`edge-a`) and one in workers mode (`edge-b`), so the
# supervisor path is exercised too. Both joined by redeeming a real
# token over the enrollment listener, from a file, never on argv.
#
# What it asserts, and which story each belongs to:
#   9.2  the mutual-TLS plane is up and both nodes hold a live session
#   9.3  enrolment landed a roster row, and the node reports its role
#   9.4  a route created on the control plane reaches both followers,
#        and a follower refuses a local mutation with 409
#   9.5  an HTTP-01 order is validated through the selected follower
#        (the challenge fanned out), and the issued certificate's
#        private key reaches that node and no other
#   9.6  access rows and WAF events fan in, stamped with the node the
#        session proved
#   9.7  the roster carries resource gauges and certificate entitlement
#   9.9  audit rows fan in with their chain intact, and every chain
#        verifies separately
#   9.4  break-glass opens a follower to local edits and closes again
#   9.6  AC #4 (backlog #64): both followers under a sustained load from
#        their own load-test engine; the fan-in keeps up with zero quota
#        drops and the measured throughput is printed
#
# Revocation is NOT here: it is terminal for a node, so it runs after
# the restart phase, in `run-cluster-revocation-smoke.sh` (backlog #77).
#
# Pre-requisite: the `cluster` compose profile is up, Pebble included.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

CP_API="${CP_API:?CP_API is required}"
EDGE_A_API="${EDGE_A_API:?EDGE_A_API is required}"
EDGE_A_PROXY="${EDGE_A_PROXY:?EDGE_A_PROXY is required}"
EDGE_B_API="${EDGE_B_API:?EDGE_B_API is required}"
EDGE_B_PROXY="${EDGE_B_PROXY:?EDGE_B_PROXY is required}"
# The load phase (backlog #64): per follower, sustained for this long.
LOAD_RPS="${LOAD_RPS:-300}"
LOAD_DURATION_S="${LOAD_DURATION_S:-60}"
BACKEND1="${BACKEND1_ADDR:-backend1:80}"
SHARED="${SHARED_DIR:-/shared}"
CHALLTESTSRV="${CHALLTESTSRV:-http://challtestsrv:8055}"
PEBBLE_DIR_URL="https://acme-staging-v02.api.letsencrypt.org/dir"
FLEET_HOST="fleet.example.com"

log "=== Cluster smoke: preflight ==="

wait_for_backend "$BACKEND1" 60 || { fail "backend1 never came up"; print_results; }
log "backend1 ready"

for marker in cp_ready edge-a_ready edge-b_ready; do
    for i in $(seq 1 180); do
        [ -f "$SHARED/$marker" ] && break
        sleep 1
    done
    if [ ! -f "$SHARED/$marker" ]; then
        fail "$marker never appeared; the node did not finish joining"
        print_results
    fi
done
log "all three nodes reported ready"

API="$CP_API"
wait_for_api 120 || { fail "the control plane API never answered"; print_results; }
login "$(cat "$SHARED/cp_admin_password")"

# ---------------------------------------------------------------------
# Story 9.2 / 9.3: the plane is up and both nodes are enrolled.
# ---------------------------------------------------------------------
log "=== 9.2/9.3: enrolment and live sessions ==="

STATUS=$(api_get /api/v1/cluster/status)
assert_json "$STATUS" '.data.role' 'control_plane' "the control plane reports its role"

# The roster is written by the enrolment path and the session by the
# operational listener, so both being true is the whole handshake.
for attempt in $(seq 1 60); do
    NODES=$(api_get /api/v1/cluster/nodes)
    CONNECTED=$(echo "$NODES" | jq '[.data[] | select(.connected == true)] | length')
    [ "$CONNECTED" = "2" ] && break
    sleep 2
done
assert_json "$NODES" '[.data[] | select(.connected == true)] | length' '2' \
    "both followers hold a live cluster session"

for name in edge-a edge-b; do
    PRESENT=$(echo "$NODES" | jq --arg n "$name" '[.data[] | select(.name == $n)] | length')
    if [ "$PRESENT" = "1" ]; then
        ok "$name enrolled under the name its token bound"
    else
        fail "$name is not in the roster under its bound name"
    fi
done

# Story 9.3 AC #5: a node that enrolled is PENDING, and receives no
# configuration until an operator activates it. Asserting the gate is
# shut before opening it is the point; a smoke that used
# `--cluster-auto-activate` would exercise a path the product does not
# take by default and would prove nothing about the gate.
assert_json "$NODES" '[.data[] | select(.status == "pending")] | length' '2' \
    "an enrolled node waits for activation rather than receiving configuration"

for id in $(echo "$NODES" | jq -r '.data[].node_id'); do
    ACT=$(api_post "/api/v1/cluster/nodes/$id/activate" '{}')
    assert_json "$ACT" '.data.status' 'active' "node $id activated"
done

for attempt in $(seq 1 30); do
    NODES=$(api_get /api/v1/cluster/nodes)
    ACTIVE=$(echo "$NODES" | jq '[.data[] | select(.status == "active")] | length')
    [ "$ACTIVE" = "2" ] && break
    sleep 2
done
assert_json "$NODES" '[.data[] | select(.status == "active")] | length' '2' \
    "both followers are active in the roster"

# ---------------------------------------------------------------------
# Story 9.7: resource gauges ride the heartbeat.
# ---------------------------------------------------------------------
log "=== 9.7: resource gauges ==="

for attempt in $(seq 1 30); do
    NODES=$(api_get /api/v1/cluster/nodes)
    WITH_GAUGES=$(echo "$NODES" | jq '[.data[] | select(.resources != null)] | length')
    [ "$WITH_GAUGES" = "2" ] && break
    sleep 2
done
assert_json "$NODES" '[.data[] | select(.resources != null)] | length' '2' \
    "both nodes reported a resource reading on the heartbeat"
# A total of zero would render as unknown; a used-over-total that is
# actually populated is what the gauge needs.
assert_json_gt "$NODES" '[.data[] | select(.resources.memory_total_bytes > 0)] | length' '1' \
    "the readings carry a memory total, so the gauge has a denominator"

# ---------------------------------------------------------------------
# Story 9.4: configuration replicates, and a follower refuses locally.
# ---------------------------------------------------------------------
log "=== 9.4: configuration replication ==="

BACKEND=$(api_post /api/v1/backends \
    "{\"name\":\"cluster-be\",\"address\":\"$BACKEND1\",\"weight\":1}")
assert_json_exists "$BACKEND" '.data.id' "the backend was created on the control plane"
# Ids are server-assigned: a route naming a backend by a made-up id
# has no backend at all and answers 502 everywhere. The first runs of
# this profile did exactly that and never noticed, because nothing
# asserted the status of a request through the route.
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id')

# `node_selector: ["edge-a"]` is the Story 9.5 lever: only that node is
# entitled to this route's certificate key.
ROUTE=$(api_post /api/v1/routes \
    '{"id":"cluster-route","hostname":"fleet.example.com","path_prefix":"/",
      "backend_ids":["'"$BACKEND_ID"'"],"load_balancing":"round_robin",
      "waf_enabled":true,"enabled":true,"node_selector":["edge-a"]}')
assert_json_exists "$ROUTE" '.data.id' "the selected route was created"
# The field is `backend_ids`, not `backends`: the first runs sent the
# latter, the API ignored it, and every request answered 502.
assert_json_gt "$ROUTE" '.data.backends | length' 0 "the route binds its backend"
# The id in the body is not honoured; routes get a server-assigned id.
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id')

GEN=$(echo "$STATUS" | jq -r '.data.applied_config_generation')
log "control plane was at generation $GEN before the mutation"

for attempt in $(seq 1 60); do
    NODES=$(api_get /api/v1/cluster/nodes)
    CONVERGED=$(echo "$NODES" | jq --argjson g "$GEN" \
        '[.data[] | select(.applied_config_generation > $g)] | length')
    [ "$CONVERGED" = "2" ] && break
    sleep 2
done
assert_json "$NODES" '[.data[] | select(.applied_config_generation > '"$GEN"')] | length' '2' \
    "both followers applied a newer generation"

# ---------------------------------------------------------------------
# Story 10.0 IV2: one generation, two hashes, and neither is drift.
#
# The control plane resolves `node_selector` itself and hands each
# follower only what it is selected for, so edge-a (which serves the
# route above) and edge-b (which does not) legitimately hold different
# bytes. The generation stays fleet-wide, the hash is per recipient.
# This replaces a fleet-wide hash comparison that demanded one hash
# across the fleet: from the moment a selector was used it would have
# called both followers drifted, forever.
# ---------------------------------------------------------------------
log "=== 10.0 IV2: one generation, two payloads ==="

GEN_A=$(echo "$NODES" | jq -r '[.data[] | select(.name == "edge-a")] | .[0].applied_config_generation')
GEN_B=$(echo "$NODES" | jq -r '[.data[] | select(.name == "edge-b")] | .[0].applied_config_generation')
HASH_A=$(echo "$NODES" | jq -r '[.data[] | select(.name == "edge-a")] | .[0].applied_config_hash')
HASH_B=$(echo "$NODES" | jq -r '[.data[] | select(.name == "edge-b")] | .[0].applied_config_hash')
if [ "$GEN_A" = "$GEN_B" ]; then
    ok "both followers converged on the same generation ($GEN_A)"
else
    fail "the followers disagree on the generation: edge-a '$GEN_A', edge-b '$GEN_B'"
fi
# A missing field reads as `null` through `jq -r`, which would satisfy
# a bare inequality and prove nothing, so both are required to be real.
if [ "$HASH_A" != "null" ] && [ "$HASH_B" != "null" ] && \
   [ -n "$HASH_A" ] && [ -n "$HASH_B" ] && [ "$HASH_A" != "$HASH_B" ]; then
    ok "the two payloads differ at one generation (edge-a $(echo "$HASH_A" | cut -c1-8), edge-b $(echo "$HASH_B" | cut -c1-8))"
else
    fail "edge-a and edge-b report the same hash '$HASH_A'; the payload was not cut per recipient"
fi

# Each node is judged against its OWN expected hash, so two converged
# followers holding different bytes must BOTH read as in sync.
for attempt in $(seq 1 30); do
    DRIFT=$(api_get /api/v1/cluster/drift)
    NAMED=$(echo "$DRIFT" | jq '[(.data.drifted // [])[] | select(.name == "edge-a" or .name == "edge-b")] | length')
    IN_SYNC=$(echo "$DRIFT" | jq -r '.data.in_sync // 0')
    [ "${NAMED:-1}" = "0" ] && [ "${IN_SYNC:-0}" -ge 2 ] && break
    sleep 2
done
if [ "${NAMED:-1}" = "0" ]; then
    ok "neither follower is named in the drift report"
else
    fail "the drift report names a converged follower: $(echo "$DRIFT" | head -c 240)"
fi
if [ "${IN_SYNC:-0}" -ge 2 ] 2>/dev/null; then
    ok "the drift report counts both followers in sync (in_sync=$IN_SYNC)"
else
    fail "the drift report counts $IN_SYNC nodes in sync, expected at least 2"
fi

# ---------------------------------------------------------------------
# Story 10.0 IV1: what a node does not serve is absent from the wire,
# not filtered on arrival.
#
# Before Story 10.0 the control plane shipped one fleet-wide blob and
# the recipient dropped the routes it was not selected for. That older
# behaviour would still pass the route half of this check, because the
# route really was deleted locally: it is the BACKEND that gives it
# away. The backend travelled with the route and the recipient kept
# the rows it had been sent, so finding no backend either is what
# proves the cut happened on the sender's side.
# ---------------------------------------------------------------------
log "=== 10.0 IV1: edge-b never receives the route it is not selected for ==="

CP_SESSION="$SESSION"
API="$EDGE_B_API"
wait_for_api 60 || { fail "edge-b's API never answered"; print_results; }
login "$(cat "$SHARED/edge-b_admin_password")"

B_ROUTES=$(api_get /api/v1/routes)
HAS_ROUTE=$(echo "$B_ROUTES" | jq --arg r "$ROUTE_ID" \
    '[(.data.routes // [])[] | select(.id == $r)] | length')
if [ "$HAS_ROUTE" = "0" ]; then
    ok "edge-b holds no route for the selector that names edge-a"
else
    fail "edge-b holds the route $ROUTE_ID it was never selected for"
fi

B_BACKENDS=$(api_get /api/v1/backends)
HAS_BACKEND=$(echo "$B_BACKENDS" | jq --arg b "$BACKEND_ID" \
    '[(.data.backends // [])[] | select(.id == $b)] | length')
if [ "$HAS_BACKEND" = "0" ]; then
    ok "the route's backend is absent from edge-b too, so the cut happened before the wire"
else
    fail "edge-b holds the backend $BACKEND_ID of a route it does not serve"
fi

API="$CP_API"
SESSION="$CP_SESSION"

# ---------------------------------------------------------------------
# Story 10.0 IV4: a selector naming nobody is refused at write time.
#
# Only the control plane owns an authoritative roster, so only it can
# tell "not enrolled" from "not replicated here yet". A selector that
# resolves to no node would otherwise be stored happily and deliver the
# route to nobody at all.
# ---------------------------------------------------------------------
log "=== 10.0 IV4: an unknown selector name is refused ==="

GHOST_BODY=$(mktemp)
GHOST_CODE=$(curl -sk -o "$GHOST_BODY" -w '%{http_code}' -b "$SESSION" \
    -X POST -H 'Content-Type: application/json' \
    -d '{"hostname":"ghost.example.com","path_prefix":"/",
         "backend_ids":["'"$BACKEND_ID"'"],"load_balancing":"round_robin",
         "enabled":true,"node_selector":["edge-does-not-exist"]}' \
    "$API/api/v1/routes")
case "$GHOST_CODE" in
    4??) ok "a route naming an unenrolled node is refused (HTTP $GHOST_CODE)" ;;
    *)   fail "a route naming an unenrolled node answered $GHOST_CODE, expected a 4xx" ;;
esac
# The API wraps the message with its own bad-request prefix, so the
# offending entry is matched as a substring, not as the whole body.
if grep -qF 'node_selector entry `edge-does-not-exist` matches no enrolled cluster node' "$GHOST_BODY"; then
    ok "the refusal names the offending selector entry"
else
    fail "the refusal does not name the offending entry: $(head -c 240 "$GHOST_BODY")"
fi
rm -f "$GHOST_BODY"

CP_ROUTES=$(api_get /api/v1/routes)
GHOST_ROUTES=$(echo "$CP_ROUTES" | jq \
    '[(.data.routes // [])[] | select(.hostname == "ghost.example.com")] | length')
if [ "$GHOST_ROUTES" = "0" ]; then
    ok "the refused route was not created"
else
    fail "the refused route exists on the control plane anyway"
fi

log "=== 9.4: a follower refuses a local mutation ==="
CP_SESSION="$SESSION"
API="$EDGE_A_API"
wait_for_api 60 || { fail "edge-a's API never answered"; print_results; }
login "$(cat "$SHARED/edge-a_admin_password")"

EDGE_STATUS=$(api_get /api/v1/cluster/status)
assert_json "$EDGE_STATUS" '.data.role' 'follower' "edge-a reports itself a follower"

CODE=$(curl -sk -b "$SESSION" -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"id":"local-be","address":"'"$BACKEND1"'","weight":1}' \
    "$API/api/v1/backends")
if [ "$CODE" = "409" ]; then
    ok "a follower answers 409 to a configuration mutation"
else
    fail "a follower answered $CODE to a local mutation, expected 409"
fi

# The read-like paths Story 9.4 AC #10 promises stay reachable, and the
# ones Story 9.7 D19 found hidden in the dashboard.
CODE=$(curl -sk -b "$SESSION" -o /dev/null -w '%{http_code}' \
    -X POST "$API/api/v1/config/export")
if [ "$CODE" = "200" ]; then
    ok "a follower still serves its own configuration export"
else
    fail "config export on a follower answered $CODE, expected 200"
fi

# ---------------------------------------------------------------------
# Story 9.6: telemetry fans in, stamped by the session.
# ---------------------------------------------------------------------
log "=== 9.6: telemetry fan-in ==="

SERVED=0
for i in $(seq 1 5); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: fleet.example.com' "$EDGE_A_PROXY/" || true)
    [ "$CODE" = "200" ] && SERVED=$((SERVED + 1))
done
if [ "$SERVED" = "5" ]; then
    ok "edge-a serves the replicated route end to end (5/5 answered 200)"
else
    fail "edge-a answered 200 to $SERVED/5 requests through the replicated route"
fi
# One request the WAF blocks, so a WAF event exists to fan in.
curl -s -o /dev/null -H 'Host: fleet.example.com' \
    "$EDGE_A_PROXY/?id=1%20OR%201=1--" || true

API="$CP_API"
SESSION="$CP_SESSION"

EDGE_A_ID=$(api_get /api/v1/cluster/nodes | jq -r '.data[] | select(.name == "edge-a") | .node_id')
for attempt in $(seq 1 45); do
    FLEET_LOGS=$(api_get "/api/v1/cluster/logs?node=$EDGE_A_ID&limit=50")
    ROWS=$(echo "$FLEET_LOGS" | jq '.data.rows | length')
    [ "$ROWS" != "0" ] && [ -n "$ROWS" ] && break
    sleep 2
done
assert_json_gt "$FLEET_LOGS" '.data.rows | length' '0' \
    "edge-a's access rows reached the control plane"

# The stamp comes from the session, never from the payload (9.6 D2), so
# every row in a node-scoped query must carry that node.
STAMPED=$(echo "$FLEET_LOGS" | jq --arg id "$EDGE_A_ID" \
    '[.data.rows[] | select(.node_id != $id)] | length')
if [ "$STAMPED" = "0" ]; then
    ok "every fanned-in row is stamped with the node the session proved"
else
    fail "$STAMPED rows carry a node id the session did not prove"
fi

for attempt in $(seq 1 45); do
    FLEET_WAF=$(api_get "/api/v1/cluster/waf-events?node=$EDGE_A_ID&limit=50")
    ROWS=$(echo "$FLEET_WAF" | jq '.data.rows | length')
    [ "$ROWS" != "0" ] && [ -n "$ROWS" ] && break
    sleep 2
done
assert_json_gt "$FLEET_WAF" '.data.rows | length' '0' \
    "edge-a's WAF events reached the control plane"

# ---------------------------------------------------------------------
# Story 9.5: a real issuance through the selected follower, and the
# key goes only to the node the selector names.
# ---------------------------------------------------------------------
log "=== 9.5: HTTP-01 through the fleet, and per-node key distribution ==="

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
fi

# Pebble validates HTTP-01 by dialling the hostname on port 8080. Point
# it at edge-a, the ONLY node the route selects. The control plane runs
# the order, but Pebble never talks to it: the validation can succeed
# only if the challenge token fanned out to the selected follower (AC
# #6), which is the cross-story path no unit test reaches.
EDGE_A_IP=$(getent hosts lorica-edge-a | awk '{print $1}' | head -1)
ADD_A=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$CHALLTESTSRV/add-a" \
    -d "{\"host\":\"${FLEET_HOST}\",\"addresses\":[\"${EDGE_A_IP}\"]}")
if [ "$ADD_A" = "200" ]; then
    ok "${FLEET_HOST} resolves to edge-a (${EDGE_A_IP}) for Pebble's validation"
else
    fail "challtestsrv add-a HTTP $ADD_A"
fi

PROV_BODY=$(mktemp)
PROV_CODE=$(curl -sk -o "$PROV_BODY" -w '%{http_code}' --max-time 240 \
    -b "$SESSION" -X POST -H 'Content-Type: application/json' \
    -d "{\"domain\":\"${FLEET_HOST}\",\"staging\":true,\"contact_email\":\"admin@example.com\"}" \
    "$API/api/v1/acme/provision")
if [ "$PROV_CODE" = "200" ]; then
    ok "HTTP-01 order validated through the selected follower (challenge fan-out)"
else
    fail "HTTP-01 provision HTTP $PROV_CODE: $(cat "$PROV_BODY")"
fi
rm -f "$PROV_BODY"

CERTS=$(api_get /api/v1/certificates)
CERT_ID=$(echo "$CERTS" | jq -r --arg d "$FLEET_HOST" \
    '[.data.certificates[]? | select(.domain == $d)][0].id // empty')
if [ -n "$CERT_ID" ]; then
    ok "the issued certificate is in the control plane's store (id=$CERT_ID)"
else
    fail "no certificate for ${FLEET_HOST} on the control plane"
fi

# Bind it to the selected route: entitlement follows
# `routes.certificate_id`, the same column the push path resolves.
BIND=$(api_put "/api/v1/routes/$ROUTE_ID" "{\"certificate_id\":\"${CERT_ID}\"}")
assert_json "$BIND" '.data.certificate_id' "$CERT_ID" "the certificate is bound to the selected route"

# The roster's entitlement column: edge-a holds it, edge-b never does.
for attempt in $(seq 1 30); do
    NODES=$(api_get /api/v1/cluster/nodes)
    # `// []` so an error body (a limiter, a hiccup) polls again
    # instead of killing the script under set -e.
    A_HAS=$(echo "$NODES" | jq --arg c "$CERT_ID" \
        '[(.data // [])[] | select(.name == "edge-a") | (.certificate_ids // [])[] | select(. == $c)] | length')
    [ "$A_HAS" = "1" ] && break
    sleep 2
done
assert_json "$NODES" \
    '[.data[] | select(.name == "edge-a") | .certificate_ids[] | select(. == "'"$CERT_ID"'")] | length' '1' \
    "edge-a, the selected node, is entitled to the certificate's key"
assert_json "$NODES" \
    '[.data[] | select(.name == "edge-b") | .certificate_ids[] | select(. == "'"$CERT_ID"'")] | length' '0' \
    "edge-b, not selected, is entitled to nothing"

# What the followers actually did with it. Each follower tees its log
# to the shared volume: the push lands as an install line on edge-a
# and never on edge-b. The metadata replicates to both (the route row
# does), the KEY to one.
for attempt in $(seq 1 30); do
    grep -q "installed certificate keys from the control plane" "$SHARED/edge-a.log" 2>/dev/null && break
    sleep 2
done
if grep -q "installed certificate keys from the control plane" "$SHARED/edge-a.log" 2>/dev/null; then
    ok "edge-a installed the private key the control plane pushed"
else
    fail "edge-a never logged a key install"
fi
if grep -q "installed certificate keys from the control plane" "$SHARED/edge-b.log" 2>/dev/null; then
    fail "edge-b installed a key it is not entitled to"
else
    ok "edge-b received no private key"
fi

# ---------------------------------------------------------------------
# Story 9.9: the audit trail fans in and every chain verifies.
# ---------------------------------------------------------------------
log "=== 9.9: fleet-wide audit trail ==="

for attempt in $(seq 1 45); do
    AUDIT=$(api_get "/api/v1/audit?limit=500")
    FANNED=$(echo "$AUDIT" | jq '[.data.entries[] | select(.node_id != "")] | length')
    [ "$FANNED" != "0" ] && [ -n "$FANNED" ] && break
    sleep 2
done
assert_json_gt "$AUDIT" '[.data.entries[] | select(.node_id != "")] | length' '0' \
    "a follower's audit rows reached the control plane"

# The apply is the row Story 9.9 added, and it is what links the
# operator's single record of the mutation to each node's outcome.
APPLIES=$(echo "$AUDIT" | jq '[.data.entries[] | select(.action == "cluster.config.apply")] | length')
if [ "$APPLIES" != "0" ]; then
    ok "the node-scoped apply is recorded and fanned in"
else
    fail "no cluster.config.apply row reached the control plane"
fi

# Every fanned-in row must carry the origin's own id, which is what
# matches it against that node's copy.
BAD_ORIGIN=$(echo "$AUDIT" | jq '[.data.entries[] | select(.node_id != "" and .origin_id == 0)] | length')
if [ "$BAD_ORIGIN" = "0" ]; then
    ok "every fanned-in audit row carries its origin id"
else
    fail "$BAD_ORIGIN fanned-in rows lost their origin id"
fi

VERIFY=$(api_get /api/v1/audit/verify)
assert_json "$VERIFY" '.data.verified' 'true' "every audit chain verifies"
CHAINS=$(echo "$VERIFY" | jq '.data.nodes | length')
if [ "$CHAINS" -ge 2 ]; then
    ok "verify reports per chain ($CHAINS chains), not once for the table"
else
    fail "verify reported $CHAINS chain(s); the aggregate should hold at least two"
fi

# The control plane's own chain must be intact independently: this is
# the case that breaks if a local entry ever chains off a fanned-in row.
LOCAL_OK=$(echo "$VERIFY" | jq '[.data.nodes[] | select(.node_id == "" and .verified == true)] | length')
if [ "$LOCAL_OK" = "1" ]; then
    ok "the control plane's own chain verifies on its own"
else
    fail "the control plane's own chain did not verify"
fi

# ---------------------------------------------------------------------
# Story 9.4 AC #11: break-glass opens a follower and closes again.
# ---------------------------------------------------------------------
log "=== 9.4: break-glass on a follower ==="

API="$EDGE_A_API"
login "$(cat "$SHARED/edge-a_admin_password")"

GLASS=$(api_post /api/v1/cluster/break-glass '{"duration_s":120}')
assert_json_exists "$GLASS" '.data.until' "break-glass opened on edge-a with a deadline"

CODE=$(curl -sk -b "$SESSION" -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d '{"id":"glass-be","address":"'"$BACKEND1"'","weight":1}' \
    "$API/api/v1/backends")
if [ "$CODE" = "201" ]; then
    ok "a local mutation is admitted while the window is open"
else
    fail "a local mutation answered $CODE inside break-glass, expected 201"
fi

CLOSE=$(curl -sk -b "$SESSION" -o /dev/null -w '%{http_code}' -X DELETE "$API/api/v1/cluster/break-glass")
if [ "$CLOSE" = "200" ] || [ "$CLOSE" = "204" ]; then
    ok "break-glass closed"
else
    fail "closing break-glass answered $CLOSE"
fi
CODE=$(curl -sk -b "$SESSION" -o /dev/null -w '%{http_code}' \
    -X DELETE "$API/api/v1/backends/glass-be")
if [ "$CODE" = "409" ]; then
    ok "the follower is read-only again once the window is closed"
else
    fail "a local mutation answered $CODE after break-glass closed, expected 409"
fi

GLASS=$(api_get /api/v1/cluster/break-glass)
assert_json "$GLASS" '.data.active' 'false' "edge-a reports its window closed"

# ---------------------------------------------------------------------
# Story 9.6 AC #4 / backlog #64: the fan-in envelope, measured.
#
# Each follower drives its OWN proxy with the built-in load-test
# engine (the config is a mutation, so it is created inside a short
# break-glass window; starting a test is follower-local). The control
# plane's ingest counter is then compared with each follower's local
# access-log growth: the drain must close the gap and the quota must
# drop nothing at this rate.
# ---------------------------------------------------------------------
log "=== 9.6/#64: fan-in under load (${LOAD_RPS} rps per follower, ${LOAD_DURATION_S}s) ==="

API="$CP_API"
SESSION="$CP_SESSION"
EDGE_B_ID=$(api_get /api/v1/cluster/nodes | jq -r '.data[] | select(.name == "edge-b") | .node_id')

# The session cookie is scoped `Path=/api`, so a cookie JAR never sends
# it to /metrics (the first run of this phase read every counter as 0
# through a silent 401). The value is sent as an explicit header
# instead, which is what the base suite does too.
cp_cookie_header() {
    awk -F'\t' '$6 == "lorica_session" { print "Cookie: " $6 "=" $7 }' "$CP_SESSION" | head -1
}
ingested_for() {
    curl -sk -H "$(cp_cookie_header)" "$CP_API/metrics" 2>/dev/null \
        | grep "^lorica_cluster_telemetry_ingested_total{node_id=\"$1\"}" \
        | awk '{print $2}' | head -1
}
dropped_quota_for() {
    curl -sk -H "$(cp_cookie_header)" "$CP_API/metrics" 2>/dev/null \
        | grep "^lorica_cluster_telemetry_dropped_total{node_id=\"$1\",reason=\"node_quota\"}" \
        | awk '{print $2}' | head -1
}
local_total() {
    # $1 = API, $2 = session
    curl -sk -b "$2" "$1/api/v1/logs?limit=1" 2>/dev/null | jq -r '.data.total // 0'
}
start_load_on() {
    # $1 = node name, $2 = API. Opens a window, creates the config,
    # starts it, closes the window. The session is the follower's.
    # Publishes LOAD_CFG_ID for the caller, the way `login` publishes
    # SESSION: the assertions below need it to ask the engine how many
    # requests it really completed.
    API="$2"
    login "$(cat "$SHARED/$1_admin_password")"
    api_post /api/v1/cluster/break-glass '{"duration_s":120}' > /dev/null
    CFG=$(api_post /api/v1/loadtest/configs "{\"name\":\"fan-in-$1\",\"target_url\":\"http://127.0.0.1:8080/\",\"headers\":{\"Host\":\"${FLEET_HOST}\"},\"concurrency\":20,\"requests_per_second\":${LOAD_RPS},\"duration_s\":${LOAD_DURATION_S},\"error_threshold_pct\":100}")
    CFG_ID=$(echo "$CFG" | jq -r '.data.id // empty')
    LOAD_CFG_ID="$CFG_ID"
    if [ -z "$CFG_ID" ]; then
        fail "$1: load-test config not created: $(echo "$CFG" | head -c 300)"
        return
    fi
    START=$(api_post "/api/v1/loadtest/start/$CFG_ID" '{}')
    if [ "$(echo "$START" | jq -r '.data.status')" = "requires_confirmation" ]; then
        START=$(api_post "/api/v1/loadtest/start/$CFG_ID/confirm" '{}')
    fi
    assert_json "$START" '.data.status' 'started' "$1: load test started"
    curl -sk -b "$SESSION" -o /dev/null -X DELETE "$API/api/v1/cluster/break-glass"
}
wait_load_done() {
    # $1 = API, $2 = session. The engine reports active=false once done.
    for i in $(seq 1 $((LOAD_DURATION_S + 60))); do
        ACTIVE=$(curl -sk -b "$2" "$1/api/v1/loadtest/status" 2>/dev/null | jq -r '.data.active // false')
        [ "$ACTIVE" != "true" ] && return 0
        sleep 2
    done
    return 1
}

requests_sent() {
    # $1 = API, $2 = session, $3 = config id. The newest stored result
    # for that config, and the request count the engine finished with.
    #
    # This is the denominator every assertion below needs. The load
    # generator is Lorica's own engine running ON the node under test,
    # so what it manages to send is a property of the machine the suite
    # happens to run on, not of the fleet. Asserting against the
    # REQUESTED rate measured the runner instead: on a contended CI
    # runner the same commit produced 624 rows where a quiet one
    # produced 17807, against a fixed threshold of 9000.
    # The engine flips `active` to false and then stores its result, so
    # a read that lands between the two sees an empty list. Poll for a
    # short while rather than turning that window into the next flake.
    for _ in $(seq 1 15); do
        n=$(curl -sk -b "$2" "$1/api/v1/loadtest/results/$3" 2>/dev/null \
            | jq -r '[(.data // [])[] | .total_requests] | max // 0')
        case "$n" in
            ''|*[!0-9]*) n=0 ;;
        esac
        [ "$n" -gt 0 ] && { echo "$n"; return 0; }
        sleep 1
    done
    echo 0
}

# Baselines: this node's local rows and what the control plane holds.
API="$EDGE_A_API"; login "$(cat "$SHARED/edge-a_admin_password")"; SESSION_A="$SESSION"
API="$EDGE_B_API"; login "$(cat "$SHARED/edge-b_admin_password")"; SESSION_B="$SESSION"
A0_LOCAL=$(local_total "$EDGE_A_API" "$SESSION_A")
B0_LOCAL=$(local_total "$EDGE_B_API" "$SESSION_B")
A0_IN=$(ingested_for "$EDGE_A_ID"); A0_IN=${A0_IN:-0}
B0_IN=$(ingested_for "$EDGE_B_ID"); B0_IN=${B0_IN:-0}

start_load_on edge-a "$EDGE_A_API"; CFG_ID_A="$LOAD_CFG_ID"
start_load_on edge-b "$EDGE_B_API"; CFG_ID_B="$LOAD_CFG_ID"
LOAD_T0=$(date +%s)
wait_load_done "$EDGE_A_API" "$SESSION_A" || fail "edge-a's load test did not finish"
wait_load_done "$EDGE_B_API" "$SESSION_B" || fail "edge-b's load test did not finish"
LOAD_T1=$(date +%s)

A1_LOCAL=$(local_total "$EDGE_A_API" "$SESSION_A")
B1_LOCAL=$(local_total "$EDGE_B_API" "$SESSION_B")
A_ROWS=$((A1_LOCAL - A0_LOCAL)); B_ROWS=$((B1_LOCAL - B0_LOCAL))
ELAPSED=$((LOAD_T1 - LOAD_T0)); [ "$ELAPSED" -gt 0 ] || ELAPSED=1
A_SENT=$(requests_sent "$EDGE_A_API" "$SESSION_A" "$CFG_ID_A")
B_SENT=$(requests_sent "$EDGE_B_API" "$SESSION_B" "$CFG_ID_B")
log "edge-a wrote $A_ROWS rows, edge-b wrote $B_ROWS rows in ${ELAPSED}s ($(( (A_ROWS + B_ROWS) / ELAPSED )) rows/s across the fleet)"
log "the engines sent $A_SENT and $B_SENT requests against ${LOAD_RPS}x${LOAD_DURATION_S} requested (the shortfall, if any, is the runner's)"

# Two separate questions, because they have two different answers when
# the machine is busy.
#
# First: did the load engine run at all? A zero here is a broken engine
# or a refused start, and no ratio below would be meaningful.
assert_json_gt "{\"n\":$A_SENT}" '.n' 0 "edge-a's load engine sent requests"
assert_json_gt "{\"n\":$B_SENT}" '.n' 0 "edge-b's load engine sent requests"

# Second, and this is what the phase exists for: did the node write a
# row for what it actually served? Against what was SENT, never against
# what was requested. A slow runner then shows up in the log line above
# and fails nothing, while a node that drops rows still fails here.
assert_json_gt "{\"n\":$A_ROWS}" '.n' $((A_SENT / 2)) "edge-a logged at least half of what its engine sent"
# edge-b holds no route for this hostname (the selector names edge-a),
# so its rows are 404s: still access rows, still fanned in, which is
# what this phase measures.
assert_json_gt "{\"n\":$B_ROWS}" '.n' $((B_SENT / 2)) "edge-b (workers) logged at least half of what its engine sent (404s by selector)"

# The drain must close the gap: ingested delta within 5% of the local
# delta, given time to catch up.
DRAIN_T0=$(date +%s)
for i in $(seq 1 90); do
    A_IN=$(ingested_for "$EDGE_A_ID"); A_IN=${A_IN:-0}
    B_IN=$(ingested_for "$EDGE_B_ID"); B_IN=${B_IN:-0}
    A_GOT=$(( ${A_IN%.*} - ${A0_IN%.*} )); B_GOT=$(( ${B_IN%.*} - ${B0_IN%.*} ))
    [ "$A_GOT" -ge $((A_ROWS * 95 / 100)) ] && [ "$B_GOT" -ge $((B_ROWS * 95 / 100)) ] && break
    sleep 2
done
DRAIN_T1=$(date +%s)
log "control plane ingested $A_GOT of edge-a's rows and $B_GOT of edge-b's rows, caught up $((DRAIN_T1 - DRAIN_T0))s after the load ended"
if [ "$A_GOT" -ge $((A_ROWS * 95 / 100)) ]; then
    ok "the drain kept up with edge-a ($A_GOT/$A_ROWS rows fanned in)"
else
    fail "the drain fell behind edge-a ($A_GOT/$A_ROWS rows fanned in)"
fi
if [ "$B_GOT" -ge $((B_ROWS * 95 / 100)) ]; then
    ok "the drain kept up with edge-b ($B_GOT/$B_ROWS rows fanned in)"
else
    fail "the drain fell behind edge-b ($B_GOT/$B_ROWS rows fanned in)"
fi
SCRAPE_CODE=$(curl -sk -o /dev/null -w '%{http_code}' -H "$(cp_cookie_header)" "$CP_API/metrics")
if [ "$SCRAPE_CODE" = "200" ]; then
    ok "the control plane's /metrics answers the session (HTTP 200)"
else
    fail "the control plane's /metrics answered $SCRAPE_CODE to the session; the counters below are meaningless"
fi
A_DROP=$(dropped_quota_for "$EDGE_A_ID"); B_DROP=$(dropped_quota_for "$EDGE_B_ID")
if [ "${A_DROP:-0}" = "0" ] || [ -z "$A_DROP" ]; then
    ok "edge-a: no row shed by the per-node quota at ${LOAD_RPS} rps"
else
    fail "edge-a: $A_DROP rows shed by the per-node quota at ${LOAD_RPS} rps"
fi
if [ "${B_DROP:-0}" = "0" ] || [ -z "$B_DROP" ]; then
    ok "edge-b: no row shed by the per-node quota at ${LOAD_RPS} rps"
else
    fail "edge-b: $B_DROP rows shed by the per-node quota at ${LOAD_RPS} rps"
fi
echo "FAN_IN_MEASUREMENT rps_per_node=${LOAD_RPS} nodes=2 rows_a=${A_ROWS} rows_b=${B_ROWS} elapsed_s=${ELAPSED} caught_up_s=$((DRAIN_T1 - DRAIN_T0))"

API="$CP_API"
SESSION="$CP_SESSION"

# ---------------------------------------------------------------------
# Story 9.7 AC #5: one follower's SLA, read through the control plane.
# The load above is what the followers measured; the passive collector
# flushes its minute bucket within a minute, so this polls.
# ---------------------------------------------------------------------
log "=== 9.7 AC #5: per-node SLA through the control plane ==="

# Each node's collector flushes on its own 60 s tick (each WORKER's,
# on edge-b), so both are polled rather than read once.
for attempt in $(seq 1 75); do
    SLA_A=$(api_get "/api/v1/sla/overview?node=$EDGE_A_ID")
    SLA_B=$(api_get "/api/v1/sla/overview?node=$EDGE_B_ID")
    NA=$(echo "$SLA_A" | jq '[(.data // [])[] | select(.total_requests > 0)] | length')
    NB=$(echo "$SLA_B" | jq -r 'if (.data | type) == "array" then "1" else "0" end' 2>/dev/null)
    [ "${NA:-0}" != "0" ] && [ "${NB:-0}" != "0" ] && break
    sleep 2
done
assert_json_gt "$SLA_A" '[.data[] | select(.total_requests > 0)] | length' 0 \
    "edge-a's SLA overview, computed on edge-a, served by the control plane"
# edge-b holds no route: the selector names edge-a only, so the apply
# excluded it there and its load-test requests were 404s. Its overview
# through the control plane is therefore EMPTY, and that is the
# correct answer, served from edge-b over the plane rather than
# invented on the control plane. (The first version of this check
# expected a figure and blamed backlog #68; the selector was the
# reason.)
if echo "$SLA_B" | jq -e '.data | type == "array" and length == 0' >/dev/null 2>&1; then
    ok "edge-b's SLA overview (workers mode, no route selected for it) is empty, served through the control plane"
else
    fail "edge-b's proxied SLA overview should be an empty list, got: $(echo "$SLA_B" | head -c 240)"
fi
ROUTE_SLA=$(api_get "/api/v1/sla/routes/$ROUTE_ID?node=$EDGE_A_ID")
assert_json_gt "$ROUTE_SLA" '[.data[] | select(.window == "1h" and .total_requests > 0)] | length' 0 \
    "one route's windows for one node"
BUCKETS=$(api_get "/api/v1/sla/routes/$ROUTE_ID/buckets?node=$EDGE_A_ID")
assert_json_gt "$BUCKETS" '.data | length' 0 "one route's raw minute buckets for one node"
# The control plane's OWN overview is unaffected: it served no
# fleet.example.com traffic, so its figure for the route is empty.
OWN=$(api_get "/api/v1/sla/overview")
assert_json "$OWN" '[.data[] | select(.route_id == "'"$ROUTE_ID"'" and .total_requests > 0)] | length' '0' \
    "the control plane's own SLA is not the follower's"

# ---------------------------------------------------------------------
# Story 12.4, key replication (Story 12.12 Lot D, 12.4 Resolved 2): a
# terminating stream targeted at one follower, naming a certificate and
# an upstream client identity no route names. Its keys reach the
# targeted follower and no other; a handshake completes there, through to
# a TLS backend that verifies the identity. Retargeted, the keys follow.
# Prints exactly one `L4-SCENARIO` line (Story 12.12 D-c).
# ---------------------------------------------------------------------
log "=== 12.4: stream key replication follows the selector ==="
l4_kr_line() {
    echo "L4-SCENARIO 12.4-x-key-replication-targeted $1 $2"
    if [ "$1" = PASS ]; then ok "12.4 key replication: $2"; else fail "12.4 key replication: $2"; fi
}
# The roster's entitlement of <node> to <certificate id>: 1 or 0.
l4_kr_entitled() {
    API="$CP_API" SESSION="$CP_SESSION" api_get /api/v1/cluster/nodes | jq --arg n "$1" --arg c "$2" \
        '[(.data // [])[] | select(.name == $n) | (.certificate_ids // [])[] | select(. == $c)] | length'
}
# Whether <node>'s own API hands out a private key for <certificate id>,
# on the follower sessions l4_kr opens once (the login limit is 5 a
# minute per address).
l4_kr_key() {
    local api session
    case "$1" in
        edge-a) api="$EDGE_A_API" session="$L4_KR_SESSION_A" ;;
        *) api="$EDGE_B_API" session="$L4_KR_SESSION_B" ;;
    esac
    if curl -sk -b "$session" "$api/api/v1/certificates/$2/download?part=key" | grep -q 'PRIVATE KEY'; then
        echo key
    else
        echo none
    fi
}
# Whether <node>'s own API lists the row of <certificate id>: 1 or 0.
l4_kr_row() {
    local api session
    case "$1" in
        edge-a) api="$EDGE_A_API" session="$L4_KR_SESSION_A" ;;
        *) api="$EDGE_B_API" session="$L4_KR_SESSION_B" ;;
    esac
    curl -sk -b "$session" "$api/api/v1/certificates/$2" | jq -r --arg id "$2" 'if .data.id == $id then 1 else 0 end'
}
# A handshake on <node>'s stream port, through to the TLS backend.
l4_kr_handshake() {
    python3 /tests/l4/tls_backend.py term --host "lorica-$1" --port 7601 --sni kr.l4d.test
}
l4_kr() {
    local pki=/tmp/kr-pki smoke_ip server client backend stream body i seen other a_srv a_cli b_srv b_cli
    mkdir -p "$pki/backend"
    (
        cd "$pki"
        for c in ca-up ca-client; do
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$c" \
                -keyout "$c.key" -out "$c.crt" -addext basicConstraints=critical,CA:TRUE \
                -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
        done
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=kr.l4d.test" \
            -keyout server.key -out server.crt -addext subjectAltName=DNS:kr.l4d.test 2>/dev/null
        for leaf in "tls-backend.l4d.test ca-up serverAuth" "kr-client.l4d.test ca-client clientAuth"; do
            set -- $leaf
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
                -keyout "$1.key" -out "$1.csr" 2>/dev/null
            printf 'subjectAltName=DNS:%s\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n' "$1" "$3" > "$1.ext"
            openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 30 \
                -extfile "$1.ext" -out "$1.crt" 2>/dev/null
        done
        cp tls-backend.l4d.test.crt backend/backend.crt
        cp tls-backend.l4d.test.key backend/backend.key
        cp ca-client.crt backend/client-ca.crt
    )
    python3 /tests/l4/tls_backend.py tls --name kr-backend --port 9701 --pki "$pki/backend" &
    smoke_ip=$(python3 -c 'import socket; print(socket.gethostbyname(socket.gethostname()))')

    API="$EDGE_A_API"; login "$(cat "$SHARED/edge-a_admin_password")"; L4_KR_SESSION_A="$SESSION"
    API="$EDGE_B_API"; login "$(cat "$SHARED/edge-b_admin_password")"; L4_KR_SESSION_B="$SESSION"
    API="$CP_API"
    SESSION="$CP_SESSION"
    upload() {
        api_post /api/v1/certificates "$(jq -n --arg d "$1" --rawfile c "$pki/$2.crt" --rawfile k "$pki/$2.key" \
            '{domain: $d, cert_pem: $c, key_pem: $k}')" | jq -r '.data.id // empty'
    }
    server=$(upload kr.l4d.test server)
    client=$(upload kr-client.l4d.test kr-client.l4d.test)
    [ -n "$server" ] && [ -n "$client" ] || { l4_kr_line FAIL "certificate upload refused on the control plane"; return; }
    backend=$(api_post /api/v1/backends "{\"address\":\"${smoke_ip}:9701\",\"health_check_enabled\":false}" | jq -r '.data.id // empty')
    [ -n "$backend" ] || { l4_kr_line FAIL "backend create refused"; return; }
    body=$(jq -n --arg srv "$server" --arg cli "$client" --arg b "$backend" --rawfile ca "$pki/ca-up.crt" \
        '{name: "l4d-key-replication", protocol: "tcp", listen_address: "0.0.0.0", port_first: 7601,
          node_selector: ["edge-a"], tls_mode: "terminate",
          match_rules: [{name: "kr", matcher: {kind: "tls", server_names: ["kr.l4d.test"]}, backend_ids: [$b]}],
          tls_terminate: {certificate_ids: [$srv]},
          upstream_tls: {server_name: {mode: "fixed", name: "tls-backend.l4d.test"}, ca_cert_pem: $ca, client_certificate_id: $cli}}')
    # A follower's reserved ports arrive with its heartbeat; until then
    # the control plane refuses a stream it cannot check there.
    local answer=""
    for i in $(seq 1 30); do
        answer=$(api_post /api/v1/streams "$body")
        stream=$(echo "$answer" | jq -r '.data.id // empty')
        [ -n "$stream" ] && break
        echo "$answer" | grep -q 'has not reported its reserved ports' || break
        sleep 2
    done
    [ -n "$stream" ] || { l4_kr_line FAIL "stream create refused: $(echo "$answer" | head -c 300)"; return; }

    for i in $(seq 1 60); do
        seen=$(l4_kr_handshake edge-a)
        case "$seen" in "name=kr-backend "*) break ;; esac
        sleep 1
    done
    case "$seen" in
        "name=kr-backend sni=tls-backend.l4d.test client=kr-client.l4d.test "*) ;;
        *) l4_kr_line FAIL "no handshake through edge-a's stream: ${seen}"; return ;;
    esac
    other=$(l4_kr_handshake edge-b)
    a_srv=$(l4_kr_key edge-a "$server"); a_cli=$(l4_kr_key edge-a "$client")
    b_srv=$(l4_kr_key edge-b "$server"); b_cli=$(l4_kr_key edge-b "$client")
    if [ "$a_srv $a_cli $b_srv $b_cli" != "key key none none" ] \
        || [ "$(l4_kr_entitled edge-a "$server")$(l4_kr_entitled edge-a "$client")" != 11 ] \
        || [ "$(l4_kr_entitled edge-b "$server")$(l4_kr_entitled edge-b "$client")" != 00 ]; then
        l4_kr_line FAIL "targeted at edge-a: edge-a keys ${a_srv}/${a_cli}, edge-b keys ${b_srv}/${b_cli}, entitlements a=$(l4_kr_entitled edge-a "$server")$(l4_kr_entitled edge-a "$client") b=$(l4_kr_entitled edge-b "$server")$(l4_kr_entitled edge-b "$client")"
        return
    fi
    case "$other" in name=*) l4_kr_line FAIL "edge-b, not targeted, served the stream: ${other}"; return ;; esac
    # Not even the rows: since Story 10.0 a node receives only the
    # certificates of what it serves (`restrict_for_recipient`), so the
    # "rows without a key" Story 12.4 Lot H expected predates that cut.
    [ "$(l4_kr_row edge-a "$server")$(l4_kr_row edge-a "$client")" = 11 ] \
        || { l4_kr_line FAIL "edge-a does not hold both certificate rows"; return; }
    [ "$(l4_kr_row edge-b "$server")$(l4_kr_row edge-b "$client")" = 00 ] \
        || { l4_kr_line FAIL "edge-b, not targeted, holds a certificate row of the stream"; return; }

    api_put "/api/v1/streams/$stream" '{"node_selector":["edge-b"]}' >/dev/null
    for i in $(seq 1 60); do
        seen=$(l4_kr_handshake edge-b)
        case "$seen" in "name=kr-backend "*) break ;; esac
        sleep 1
    done
    case "$seen" in
        "name=kr-backend sni=tls-backend.l4d.test client=kr-client.l4d.test "*) ;;
        *) l4_kr_line FAIL "no handshake through edge-b's stream after the retarget: ${seen}"; return ;;
    esac
    for i in $(seq 1 30); do
        [ "$(l4_kr_entitled edge-a "$server")$(l4_kr_entitled edge-a "$client")" = 00 ] && break
        sleep 2
    done
    other=$(l4_kr_handshake edge-a)
    b_srv=$(l4_kr_key edge-b "$server"); b_cli=$(l4_kr_key edge-b "$client")
    a_srv=$(l4_kr_key edge-a "$server"); a_cli=$(l4_kr_key edge-a "$client")
    local a_ent b_ent
    a_ent="$(l4_kr_entitled edge-a "$server")$(l4_kr_entitled edge-a "$client")"
    b_ent="$(l4_kr_entitled edge-b "$server")$(l4_kr_entitled edge-b "$client")"
    # What edge-a keeps, asserted as the cluster smoke asserts a node's
    # entitlement (the roster) plus what its own API holds: the next
    # generation's cut no longer carries the rows, and the apply deletes
    # a row the blob dropped, key and all.
    local a_rows
    a_rows="$(l4_kr_row edge-a "$server")$(l4_kr_row edge-a "$client")"
    if [ "$b_srv $b_cli" != "key key" ] || [ "$b_ent" != 11 ] || [ "$a_ent" != 00 ] \
        || [ "$a_rows" != 00 ] || [ "$a_srv $a_cli" != "none none" ]; then
        l4_kr_line FAIL "retargeted to edge-b: edge-b keys ${b_srv}/${b_cli} entitled ${b_ent}; edge-a entitled ${a_ent}, rows ${a_rows}, keys ${a_srv}/${a_cli}"
        return
    fi
    case "$other" in name=*) l4_kr_line FAIL "edge-a still served the stream after the retarget: ${other}"; return ;; esac
    api_del "/api/v1/streams/$stream" >/dev/null
    l4_kr_line PASS "targeted at edge-a: its own API hands out both keys, edge-b holds neither row nor key, the roster entitles edge-a only, a handshake through edge-a reaches the TLS backend with the replicated client identity; retargeted to edge-b: the same there, and edge-a is no longer entitled, holds neither row nor key, and no longer serves the stream"
}
# Without errexit: every path of l4_kr ends on its one line.
set +e
l4_kr
set -e

# ---------------------------------------------------------------------
# Story 12.1 IV1 and IV2 (Story 12.12 Lot L). IV1: a TCP stream targeted
# at edge-a is listed by edge-a's own API, held by the control plane,
# absent from edge-b, which never receives it; a connection through it
# reaches backend1 on edge-a and is refused on edge-b and on the control
# plane (the node image has no `ss`: a connect from here is the external
# truth). IV2: a stream on edge-a's HTTPS port is refused 409 by the
# control plane, naming edge-a. Each prints exactly one `L4-SCENARIO`
# line (Story 12.12 D-c).
# ---------------------------------------------------------------------
log "=== 12.1: a targeted stream binds on one node; a follower's HTTPS port is refused ==="
l4_121_line() {
    echo "L4-SCENARIO $1 $2 $3"
    if [ "$2" = PASS ]; then ok "$1: $3"; else fail "$1: $3"; fi
}
# Whether <node>'s own API lists stream <id>: 1 or 0 (`cp` is the
# control plane).
l4_121_listed() {
    local api session
    case "$1" in
        edge-a) api="$EDGE_A_API" session="$L4_KR_SESSION_A" ;;
        edge-b) api="$EDGE_B_API" session="$L4_KR_SESSION_B" ;;
        *) api="$CP_API" session="$CP_SESSION" ;;
    esac
    curl -sk -b "$session" "$api/api/v1/streams" | jq --arg id "$2" '[(.data.streams // [])[] | select(.id == $id)] | length'
}
# One HTTP request through <host>:<port> to backend1: the status, or
# `refused` when nothing listens there.
l4_121_through() {
    python3 - "$1" "$2" <<'PY'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
except ConnectionRefusedError:
    print("refused")
    sys.exit(0)
except OSError as e:
    print(f"unreachable ({e.__class__.__name__})")
    sys.exit(0)
s.settimeout(3)
s.sendall(b"GET /healthz HTTP/1.0\r\nHost: backend1\r\n\r\n")
try:
    head = s.recv(64).decode("latin-1").split("\r\n")[0]
except OSError as e:
    head = f"no answer ({e.__class__.__name__})"
print(head.split(" ")[1] if head.startswith("HTTP/") else head or "closed")
PY
}
# The applied generation of <follower> in the roster.
l4_121_generation() {
    API="$CP_API" SESSION="$CP_SESSION" api_get /api/v1/cluster/nodes \
        | jq -r --arg n "$1" '[(.data // [])[] | select(.name == $n)][0].applied_config_generation // 0'
}
l4_121() {
    local iv1=12.1-iv1-targeted-stream-binds-on-one-node iv2=12.1-iv2-follower-https-port-refused
    local backend_ip backend body answer stream i a_listed b_listed cp_listed a_through b_through cp_through gen_a gen_b
    API="$CP_API"
    SESSION="$CP_SESSION"
    if [ -z "${L4_KR_SESSION_A:-}" ] || [ -z "${L4_KR_SESSION_B:-}" ]; then
        API="$EDGE_A_API"; login "$(cat "$SHARED/edge-a_admin_password")"; L4_KR_SESSION_A="$SESSION"
        API="$EDGE_B_API"; login "$(cat "$SHARED/edge-b_admin_password")"; L4_KR_SESSION_B="$SESSION"
        API="$CP_API"; SESSION="$CP_SESSION"
    fi
    backend_ip=$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "${BACKEND1%%:*}")
    backend=$(api_post /api/v1/backends "{\"address\":\"${backend_ip}:${BACKEND1##*:}\",\"health_check_enabled\":false}" | jq -r '.data.id // empty')
    if [ -z "$backend" ]; then
        l4_121_line "$iv1" FAIL "backend create refused"
        l4_121_line "$iv2" FAIL "not run: the IV1 backend was refused"
        return
    fi
    body="{\"name\":\"l4l-iv1-targeted\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7602,\"node_selector\":[\"edge-a\"],\"backend_ids\":[\"${backend}\"]}"
    # A follower's reserved ports arrive with its heartbeat; until then
    # the control plane refuses a stream it cannot check there.
    for i in $(seq 1 30); do
        answer=$(api_post /api/v1/streams "$body")
        stream=$(echo "$answer" | jq -r '.data.id // empty')
        [ -n "$stream" ] && break
        echo "$answer" | grep -q 'has not reported its reserved ports' || break
        sleep 2
    done
    if [ -z "$stream" ]; then
        l4_121_line "$iv1" FAIL "stream create refused: $(echo "$answer" | head -c 300)"
    else
        for i in $(seq 1 60); do
            a_through=$(l4_121_through lorica-edge-a 7602)
            [ "$a_through" = 200 ] && break
            sleep 1
        done
        # edge-b never receives the stream: wait until it has applied the
        # generation edge-a serves it from, so its absence is not a lag.
        gen_a=$(l4_121_generation edge-a)
        for i in $(seq 1 60); do
            gen_b=$(l4_121_generation edge-b)
            [ "$gen_b" -ge "$gen_a" ] 2>/dev/null && break
            sleep 1
        done
        a_listed=$(l4_121_listed edge-a "$stream")
        b_listed=$(l4_121_listed edge-b "$stream")
        cp_listed=$(l4_121_listed cp "$stream")
        b_through=$(l4_121_through lorica-edge-b 7602)
        cp_through=$(l4_121_through lorica-cp 7602)
        if [ "$a_through" != 200 ]; then
            l4_121_line "$iv1" FAIL "nothing reached backend1 through edge-a's stream: ${a_through}"
        elif [ "$a_listed $b_listed $cp_listed" != "1 0 1" ]; then
            l4_121_line "$iv1" FAIL "listed by edge-a ${a_listed}, edge-b ${b_listed}, control plane ${cp_listed}; expected 1 0 1"
        elif [ "$b_through" != refused ] || [ "$cp_through" != refused ]; then
            l4_121_line "$iv1" FAIL "port 7602 answered elsewhere: edge-b ${b_through}, control plane ${cp_through}"
        else
            l4_121_line "$iv1" PASS "selector [edge-a]: listed by edge-a's API and held by the control plane's, absent from edge-b's at generation ${gen_b} (edge-a's ${gen_a}); through edge-a:7602 backend1 answered ${a_through}; edge-b:7602 ${b_through}, control plane:7602 ${cp_through}"
        fi
        api_del "/api/v1/streams/$stream" >/dev/null
    fi

    local https code msg
    https=$(curl -sk -b "$L4_KR_SESSION_A" "$EDGE_A_API/api/v1/system" | jq -r '.data.proxy.https_port // empty')
    if [ -z "$https" ]; then
        l4_121_line "$iv2" FAIL "edge-a did not report its HTTPS port"
        return
    fi
    code=$(curl -sk -o /tmp/l4l-iv2.json -w '%{http_code}' -b "$CP_SESSION" -X POST -H "Content-Type: application/json" \
        -d "{\"name\":\"l4l-iv2-https\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${https},\"node_selector\":[\"edge-a\"],\"backend_ids\":[\"${backend}\"]}" \
        "$CP_API/api/v1/streams")
    msg=$(jq -r '.error.message // .error // empty' /tmp/l4l-iv2.json 2>/dev/null | tr '\n' ' ' | head -c 300)
    if [ "$code" = 409 ] && echo "$msg" | grep -q 'edge-a'; then
        l4_121_line "$iv2" PASS "a stream on edge-a's HTTPS port ${https} refused 409 by the control plane: ${msg}"
    else
        l4_121_line "$iv2" FAIL "a stream on edge-a's HTTPS port ${https} answered ${code}: $(tr '\n' ' ' < /tmp/l4l-iv2.json | head -c 300)"
        api_del "/api/v1/streams/$(jq -r '.data.id // empty' /tmp/l4l-iv2.json)" >/dev/null
    fi
    api_del "/api/v1/backends/$backend" >/dev/null
}
# Without errexit: every path of l4_121 ends on its two lines.
set +e
l4_121
set -e

print_results
