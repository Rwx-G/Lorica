#!/usr/bin/env bash
# =============================================================================
# Lorica cluster E2E: revocation (Story 9.3 AC #7)
#
# Split out of `run-cluster-smoke.sh` when the restart phase (backlog
# #77) was added: revocation is terminal for a node, so anything that
# needs a live follower has to run before it. `run.sh` therefore orders
# the cluster profile as smoke, restart, revocation.
#
# Every id is re-derived from the API rather than carried over, so this
# runs standalone against whatever fleet the earlier phases left.
#
# What it asserts:
#   9.3  revoking a node ends its live session synchronously and marks
#        it revoked in the roster
#   9.3  revoking a node that holds a certificate's private key names
#        that certificate for re-issue, because revocation cannot take
#        a key back
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

CP_API="${CP_API:?CP_API is required}"
SHARED="${SHARED_DIR:-/shared}"
FLEET_HOST="${FLEET_HOST:-fleet.example.com}"

API="$CP_API"
login "$(cat "$SHARED/cp_admin_password")"

log "=== 9.3: revocation ==="

NODES=$(api_get /api/v1/cluster/nodes)
EDGE_A_ID=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-a")] | .[0].node_id')
EDGE_B_ID=$(echo "$NODES" | jq -r '[(.data // [])[] | select(.name == "edge-b")] | .[0].node_id')
# The certificate the fleet route carries: the key edge-a was pushed.
CERT_ID=$(api_get /api/v1/certificates \
    | jq -r --arg d "$FLEET_HOST" '[.data.certificates[]? | select(.domain == $d)][0].id // empty')

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
