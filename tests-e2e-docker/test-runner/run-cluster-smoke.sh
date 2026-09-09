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
#   9.3  revocation ends the session, and names the keys it cannot
#        take back
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
    API="$2"
    login "$(cat "$SHARED/$1_admin_password")"
    api_post /api/v1/cluster/break-glass '{"duration_s":120}' > /dev/null
    CFG=$(api_post /api/v1/loadtest/configs "{\"name\":\"fan-in-$1\",\"target_url\":\"http://127.0.0.1:8080/\",\"headers\":{\"Host\":\"${FLEET_HOST}\"},\"concurrency\":20,\"requests_per_second\":${LOAD_RPS},\"duration_s\":${LOAD_DURATION_S},\"error_threshold_pct\":100}")
    CFG_ID=$(echo "$CFG" | jq -r '.data.id // empty')
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

# Baselines: this node's local rows and what the control plane holds.
API="$EDGE_A_API"; login "$(cat "$SHARED/edge-a_admin_password")"; SESSION_A="$SESSION"
API="$EDGE_B_API"; login "$(cat "$SHARED/edge-b_admin_password")"; SESSION_B="$SESSION"
A0_LOCAL=$(local_total "$EDGE_A_API" "$SESSION_A")
B0_LOCAL=$(local_total "$EDGE_B_API" "$SESSION_B")
A0_IN=$(ingested_for "$EDGE_A_ID"); A0_IN=${A0_IN:-0}
B0_IN=$(ingested_for "$EDGE_B_ID"); B0_IN=${B0_IN:-0}

start_load_on edge-a "$EDGE_A_API"
start_load_on edge-b "$EDGE_B_API"
LOAD_T0=$(date +%s)
wait_load_done "$EDGE_A_API" "$SESSION_A" || fail "edge-a's load test did not finish"
wait_load_done "$EDGE_B_API" "$SESSION_B" || fail "edge-b's load test did not finish"
LOAD_T1=$(date +%s)

A1_LOCAL=$(local_total "$EDGE_A_API" "$SESSION_A")
B1_LOCAL=$(local_total "$EDGE_B_API" "$SESSION_B")
A_ROWS=$((A1_LOCAL - A0_LOCAL)); B_ROWS=$((B1_LOCAL - B0_LOCAL))
ELAPSED=$((LOAD_T1 - LOAD_T0)); [ "$ELAPSED" -gt 0 ] || ELAPSED=1
log "edge-a wrote $A_ROWS rows, edge-b wrote $B_ROWS rows in ${ELAPSED}s ($(( (A_ROWS + B_ROWS) / ELAPSED )) rows/s across the fleet)"
assert_json_gt "{\"n\":$A_ROWS}" '.n' $((LOAD_RPS * LOAD_DURATION_S / 2)) "edge-a served at least half the requested load locally"
assert_json_gt "{\"n\":$B_ROWS}" '.n' $((LOAD_RPS * LOAD_DURATION_S / 2)) "edge-b (workers) served at least half the requested load locally"

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

for attempt in $(seq 1 60); do
    SLA_A=$(api_get "/api/v1/sla/overview?node=$EDGE_A_ID")
    N=$(echo "$SLA_A" | jq '[(.data // [])[] | select(.total_requests > 0)] | length')
    [ "$N" != "0" ] && [ -n "$N" ] && break
    sleep 2
done
assert_json_gt "$SLA_A" '[.data[] | select(.total_requests > 0)] | length' 0 \
    "edge-a's SLA overview, computed on edge-a, served by the control plane"
SLA_B=$(api_get "/api/v1/sla/overview?node=$EDGE_B_ID")
assert_json_gt "$SLA_B" '[.data[] | select(.total_requests > 0)] | length' 0 \
    "edge-b's SLA overview (workers mode) through the control plane"
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
# Story 9.3 AC #7: revocation ends the session at once, and names the
# keys it cannot take back (Epic 9 close, security audit).
# ---------------------------------------------------------------------
log "=== 9.3: revocation ==="

EDGE_B_ID=$(api_get /api/v1/cluster/nodes | jq -r '.data[] | select(.name == "edge-b") | .node_id')
REVOKE_B=$(api_del "/api/v1/cluster/nodes/$EDGE_B_ID")
assert_json "$REVOKE_B" '.data.newly_revoked' 'true' "edge-b revoked"
assert_json "$REVOKE_B" '.data.session_ended' 'true' "edge-b's live session was ended synchronously"
assert_json "$REVOKE_B" '.data.certificates_to_reissue | length' '0' \
    "edge-b held no key, so nothing is to re-issue"

for attempt in $(seq 1 15); do
    NODES=$(api_get /api/v1/cluster/nodes)
    B_CONNECTED=$(echo "$NODES" | jq -r '.data[] | select(.name == "edge-b") | .connected')
    [ "$B_CONNECTED" = "false" ] && break
    sleep 2
done
assert_json "$NODES" '.data[] | select(.name == "edge-b") | .status' 'revoked' \
    "edge-b is revoked in the roster"
assert_json "$NODES" '.data[] | select(.name == "edge-b") | .connected' 'false' \
    "edge-b holds no session any more"

# edge-a holds the fleet certificate's key: revoking it must say so.
REVOKE_A=$(api_del "/api/v1/cluster/nodes/$EDGE_A_ID")
assert_json "$REVOKE_A" '.data.newly_revoked' 'true' "edge-a revoked"
assert_json "$REVOKE_A" '[.data.certificates_to_reissue[] | select(. == "'"$CERT_ID"'")] | length' '1' \
    "revoking edge-a names the certificate whose key it keeps, for re-issue"

print_results
