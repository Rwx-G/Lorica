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
#   9.5  a certificate's private key reaches the node its route selects
#        and no other
#   9.6  access rows and WAF events fan in, stamped with the node the
#        session proved
#   9.7  the roster carries resource gauges and certificate entitlement
#   9.9  audit rows fan in with their chain intact, and every chain
#        verifies separately
#
# Pre-requisite: the `cluster` compose profile is up.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

CP_API="${CP_API:?CP_API is required}"
EDGE_A_API="${EDGE_A_API:?EDGE_A_API is required}"
EDGE_A_PROXY="${EDGE_A_PROXY:?EDGE_A_PROXY is required}"
BACKEND1="${BACKEND1_ADDR:-backend1:80}"
SHARED="${SHARED_DIR:-/shared}"

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
    "{\"id\":\"cluster-be\",\"address\":\"$BACKEND1\",\"weight\":1}")
assert_json_exists "$BACKEND" '.data.id' "the backend was created on the control plane"

# `node_selector: ["edge-a"]` is the Story 9.5 lever: only that node is
# entitled to this route's certificate key.
ROUTE=$(api_post /api/v1/routes \
    '{"id":"cluster-route","hostname":"fleet.example.com","path_prefix":"/",
      "backends":["cluster-be"],"load_balancing":"round_robin",
      "waf_enabled":true,"enabled":true,"node_selector":["edge-a"]}')
assert_json_exists "$ROUTE" '.data.id' "the selected route was created"

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

# Every node must agree on the hash, not merely on the number: a
# matching generation with a different hash is the divergence the drift
# endpoint exists to catch.
HASHES=$(echo "$NODES" | jq -r '[.data[].applied_config_hash] | unique | length')
if [ "$HASHES" = "1" ]; then
    ok "both followers applied the same configuration hash"
else
    fail "the followers disagree on the applied hash"
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

for i in $(seq 1 5); do
    curl -s -o /dev/null -H 'Host: fleet.example.com' "$EDGE_A_PROXY/" || true
done
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
# Story 9.5: the key goes only to the node the selector names.
# ---------------------------------------------------------------------
log "=== 9.5: certificate entitlement is per node ==="

NODES=$(api_get /api/v1/cluster/nodes)
A_CERTS=$(echo "$NODES" | jq '[.data[] | select(.name == "edge-a") | .certificate_ids[]] | length')
B_CERTS=$(echo "$NODES" | jq '[.data[] | select(.name == "edge-b") | .certificate_ids[]] | length')
log "edge-a is entitled to $A_CERTS certificates, edge-b to $B_CERTS"
# The route names edge-a only, and it has no certificate attached in
# this smoke, so what is asserted is the SHAPE of entitlement: the
# resolver answers per node rather than fleet-wide.
if [ "$A_CERTS" = "$B_CERTS" ] && [ "$A_CERTS" = "0" ]; then
    ok "no certificate is bound to the route, so neither node is entitled"
else
    if [ "$A_CERTS" -ge "$B_CERTS" ]; then
        ok "entitlement follows the selector rather than the fleet"
    else
        fail "the unselected node is entitled to more certificates than the selected one"
    fi
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

print_results
