#!/usr/bin/env bash
# =============================================================================
# Lorica cluster E2E: the restart phase (backlog #77)
#
# The `cluster` profile never restarted a node, so nothing covered what
# survives a process boundary. This runs AFTER the main cluster smoke,
# against the same fleet, once `run.sh` has restarted a container.
#
# What it asserts, by phase:
#
#   follower       a restarted follower re-opens its session with no
#                  operator action, comes back on the same applied
#                  generation and does not read as drifted (9.2/9.4);
#                  the SLA history it recorded before the restart is
#                  still there (backlog #67); the private key it held
#                  is still held after the apply that runs at startup
#                  (backlog #60)
#
#   control-plane  a restarted control plane says its replication policy
#                  state started empty, its followers come back, and the
#                  flag clears once this process has run a round
#                  (backlog #58)
#
# Pre-requisite: the `cluster` profile is up and the main smoke has run.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

PHASE="${1:?usage: run-cluster-restart-smoke.sh follower|control-plane}"
CP_API="${CP_API:?CP_API is required}"
EDGE_A_API="${EDGE_A_API:?EDGE_A_API is required}"
SHARED="${SHARED_DIR:-/shared}"
BACKEND1="${BACKEND1_ADDR:-backend1:80}"
FLEET_HOST="${FLEET_HOST:-fleet.example.com}"

# The control plane answers before anything can be asked of it. The
# login endpoint is the one public POST, so any answer from it means
# the server is up and routing.
for _ in $(seq 1 60); do
    if curl -sk -o /dev/null -X POST -H "Content-Type: application/json" \
        -d '{"username":"probe","password":"probe"}' \
        "$CP_API/api/v1/auth/login" 2>/dev/null; then
        break
    fi
    sleep 2
done

API="$CP_API"
login "$(cat "$SHARED/cp_admin_password")"

# A restarted node dials out and the control plane notices on its next
# heartbeat, not instantly, so every roster read here is a poll.
wait_for_edge_a_session() {
    for _ in $(seq 1 60); do
        NODES=$(api_get /api/v1/cluster/nodes)
        CONNECTED=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].connected // "false"')
        [ "$CONNECTED" = "true" ] && return 0
        sleep 2
    done
    return 1
}

wait_for_both_sessions() {
    for _ in $(seq 1 60); do
        NODES=$(api_get /api/v1/cluster/nodes)
        CONNECTED=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.connected == true)] | length')
        [ "$CONNECTED" = "2" ] && return 0
        sleep 2
    done
    return 1
}

# The generation and the per-recipient hash a named node last reported,
# as the control plane's roster holds them. $1 = node name.
roster_generation() {
    api_get /api/v1/cluster/nodes \
        | jq -r --arg n "$1" '[(.data // [])[] | select(.name == $n)] | .[0].applied_config_generation // "none"'
}
roster_hash() {
    api_get /api/v1/cluster/nodes \
        | jq -r --arg n "$1" '[(.data // [])[] | select(.name == $n)] | .[0].applied_config_hash // "none"'
}

if [ "$PHASE" = "follower" ]; then
    log "=== restart: a follower comes back on its own (#77) ==="

    if wait_for_edge_a_session; then
        ok "edge-a re-opened its session after the restart, with no operator action"
    else
        fail "edge-a did not re-open its session within 120s of the restart"
    fi

    STATUS=$(api_get /api/v1/cluster/status)
    CURRENT=$(echo "$STATUS" | jq -r '.data.applied_config_generation')
    for _ in $(seq 1 30); do
        NODES=$(api_get /api/v1/cluster/nodes)
        APPLIED=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].applied_config_generation // -1')
        [ "$APPLIED" = "$CURRENT" ] && break
        sleep 2
    done
    if [ "$APPLIED" = "$CURRENT" ]; then
        ok "edge-a is back on the control plane's generation ($APPLIED)"
    else
        fail "edge-a applied generation is '$APPLIED', the control plane is at '$CURRENT'"
    fi

    DRIFT=$(api_get /api/v1/cluster/drift)
    if echo "$DRIFT" | jq -e '[(.data.drifted // [])[] | select(.name == "edge-a")] | length == 0' >/dev/null 2>&1; then
        ok "a plain restart is not drift"
    else
        fail "edge-a reads as drifted after a restart: $(echo "$DRIFT" | head -c 200)"
    fi

    # Backlog #67: the SLA history edge-a recorded before the restart,
    # read back through the control plane from the node that owns it.
    EDGE_A_ID=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].node_id')
    for _ in $(seq 1 30); do
        SLA=$(api_get "/api/v1/sla/overview?node=$EDGE_A_ID")
        echo "$SLA" | jq -e '[(.data // [])[] | select(.total_requests > 0)] | length > 0' >/dev/null 2>&1 && break
        sleep 2
    done
    if echo "$SLA" | jq -e '[(.data // [])[] | select(.total_requests > 0)] | length > 0' >/dev/null 2>&1; then
        ok "edge-a's SLA history survived the restart"
    else
        fail "edge-a's SLA history is empty after the restart: $(echo "$SLA" | head -c 200)"
    fi

    # Backlog #60: the key edge-a held is still held after the apply that
    # runs at startup. The certificate row surviving proves nothing (the
    # metadata replicates either way), so the socket is asked: a chain
    # whose key was dropped is skipped by the TLS resolver and the node
    # answers with its default certificate instead.
    API="$EDGE_A_API"
    login "$(cat "$SHARED/edge-a_admin_password")"
    CERTS=$(api_get /api/v1/certificates)
    if echo "$CERTS" | jq -e '(.data // []) | length > 0' >/dev/null 2>&1; then
        ok "edge-a still holds its certificate row after the restart"
    else
        fail "edge-a holds no certificate after the restart: $(echo "$CERTS" | head -c 240)"
    fi
    SERVED=$(echo | openssl s_client -connect lorica-edge-a:8443 \
        -servername "$FLEET_HOST" 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true)
    if echo "$SERVED" | grep -q "$FLEET_HOST"; then
        ok "edge-a still serves the issued certificate for $FLEET_HOST, so it kept the key"
    else
        fail "edge-a no longer serves the issued certificate for $FLEET_HOST: the startup apply dropped the key"
    fi
    API="$CP_API"
    login "$(cat "$SHARED/cp_admin_password")"
fi

if [ "$PHASE" = "control-plane" ]; then
    # Read first, assert later: the roster rows still carry what each
    # follower reported BEFORE the restart. Neither follower was
    # restarted, this process has replicated nothing yet (the flag
    # asserted just below says exactly that), and nothing here has
    # mutated the store, so these are the pre-restart values.
    # run.sh owns the restart, so this runner cannot read them any
    # earlier than its own first API call.
    BEFORE_GEN_A=$(roster_generation edge-a)
    BEFORE_GEN_B=$(roster_generation edge-b)
    BEFORE_HASH_A=$(roster_hash edge-a)
    BEFORE_HASH_B=$(roster_hash edge-b)

    log "=== restart: the control plane says its policy state started empty (#58) ==="

    REPL=$(api_get /api/v1/cluster/replication)
    if echo "$REPL" | jq -e '.data.policy_state_reset_by_restart == true' >/dev/null 2>&1; then
        ok "a restarted control plane reports that replication policy state started empty"
    else
        fail "policy_state_reset_by_restart should be true right after a restart: $(echo "$REPL" | head -c 240)"
    fi

    if wait_for_edge_a_session; then
        ok "edge-a re-opened its session against the restarted control plane"
    else
        fail "edge-a did not reconnect to the restarted control plane within 120s"
    fi

    # -----------------------------------------------------------------
    # Story 10.0 IV3: a control-plane restart raises no drift.
    #
    # Each node's expected version is derived from the payload the
    # control plane cut for it, never stored in a column, so a restart
    # has to rebuild every follower's expected hash from the store
    # alone. That recomputation is the thing under test: if it were not
    # byte-for-byte deterministic, every follower would read as drifted
    # the moment the process came back, and an operator would be handed
    # a fleet-wide alert caused by nothing but a restart.
    # -----------------------------------------------------------------
    log "=== 10.0 IV3: the rebuilt expectation raises no drift ==="

    # A vacuous run is worse than a failing one: if the fleet holds no
    # `node_selector`-scoped route, both followers carry identical bytes
    # and this phase would pass without exercising the per-recipient
    # recomputation at all. The main smoke creates that route; say so
    # loudly if it is missing rather than reporting a green run.
    if [ "$BEFORE_HASH_A" != "$BEFORE_HASH_B" ] && [ "$BEFORE_HASH_A" != "none" ]; then
        ok "the followers went into the restart holding different payloads"
    else
        fail "both followers hold the same payload ('$BEFORE_HASH_A'); no scoped route in the fleet, so this phase proves nothing"
    fi

    if wait_for_both_sessions; then
        ok "both followers re-opened their sessions against the restarted control plane"
    else
        fail "the fleet did not fully reconnect within 120s of the control-plane restart"
    fi

    for _ in $(seq 1 45); do
        DRIFT=$(api_get /api/v1/cluster/drift)
        DRIFTED=$(echo "$DRIFT" | jq '(.data.drifted // []) | length')
        [ "${DRIFTED:-1}" = "0" ] && break
        sleep 2
    done
    if [ "${DRIFTED:-1}" = "0" ]; then
        ok "no node is drifted after the control plane rebuilt its expectations"
    else
        fail "$DRIFTED node(s) read as drifted after the restart: $(echo "$DRIFT" | head -c 240)"
    fi

    AFTER_GEN_A=$(roster_generation edge-a)
    AFTER_GEN_B=$(roster_generation edge-b)
    AFTER_HASH_A=$(roster_hash edge-a)
    AFTER_HASH_B=$(roster_hash edge-b)
    if [ "$AFTER_GEN_A" = "$AFTER_GEN_B" ]; then
        ok "both followers still share one generation after the restart ($AFTER_GEN_A)"
    else
        fail "the followers split on the generation after the restart: edge-a '$AFTER_GEN_A', edge-b '$AFTER_GEN_B'"
    fi
    if [ "$AFTER_HASH_A" = "$BEFORE_HASH_A" ] && [ "$AFTER_HASH_B" = "$BEFORE_HASH_B" ]; then
        ok "each follower kept its own hash across the restart"
    else
        fail "a hash moved across the restart: edge-a '$BEFORE_HASH_A' -> '$AFTER_HASH_A', edge-b '$BEFORE_HASH_B' -> '$AFTER_HASH_B'"
    fi
    if [ "$AFTER_HASH_A" != "$AFTER_HASH_B" ]; then
        ok "the two payloads are still distinct, so the restart did not collapse them into one blob"
    else
        fail "the followers now report one hash; the restart lost the per-recipient cut"
    fi
    log "pre-restart generations: edge-a $BEFORE_GEN_A, edge-b $BEFORE_GEN_B"

    # A mutation drives one round, after which the flag must clear: it
    # means "this process has not replicated yet", not "no round ever".
    api_post /api/v1/backends '{"id":"restart-be","address":"'"$BACKEND1"'","weight":1}' >/dev/null
    for _ in $(seq 1 45); do
        REPL=$(api_get /api/v1/cluster/replication)
        echo "$REPL" | jq -e '.data.policy_state_reset_by_restart == false' >/dev/null 2>&1 && break
        sleep 2
    done
    if echo "$REPL" | jq -e '.data.policy_state_reset_by_restart == false and .data.last != null' >/dev/null 2>&1; then
        ok "the flag clears once this process has run a round"
    else
        fail "policy_state_reset_by_restart should clear after a round: $(echo "$REPL" | head -c 240)"
    fi
fi

print_results
