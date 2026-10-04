#!/usr/bin/env bash
# =============================================================================
# Driving `lorica-mcp` over stdio, shared by the smokes that run from the
# Lorica image (run-mcp-smoke.sh, run-cluster-mcp-smoke.sh). Sourced after
# helpers.sh, never executed.
#
# The caller sets:
#   WORK              a scratch directory
#   MANAGEMENT_PORT   the node's loopback management port
#   PASSWORD_FILE     the admin password, for `--password-file`
#   ENDPOINT          the automation listener lorica-mcp dials
#   CA_BUNDLE         the listener's certificate, LORICA_MCP_CA_BUNDLE
#   API, SESSION      the logged-in management API (helpers.sh)
#
# The Lorica image carries no jq, so JSON is read with the sqlite3 CLI's
# JSON functions through `json` below.
# =============================================================================

# ---------------------------------------------------------------------
# JSON through sqlite3. $1 is the document, $2 a SELECT over the one-row
# table `d(doc)`. The document is fed on stdin as a SQL literal, so its
# size is not bounded by the argument limit.
# ---------------------------------------------------------------------
json() {
    local quoted=${1//\'/\'\'}
    printf "WITH d(doc) AS (SELECT '%s') %s;\n" "$quoted" "$2" \
        | sqlite3 -batch -noheader :memory: 2>/dev/null
}

# ---------------------------------------------------------------------
# Minting through the CLI.
# ---------------------------------------------------------------------

# $1 tier, then any extra flag. Leaves MINTED (stdout), MINT_CODE and
# MINT_ERR (a file holding stderr).
mint_tier() {
    local tier="$1"
    shift
    MINT_ERR="$WORK/mint-$tier.err"
    MINTED=$(lorica --management-port "$MANAGEMENT_PORT" mcp token create --tier "$tier" \
        --password-file "$PASSWORD_FILE" "$@" 2>"$MINT_ERR")
    MINT_CODE=$?
}

# ---------------------------------------------------------------------
# One lorica-mcp session over stdio.
# ---------------------------------------------------------------------

REVISION=""
RPC_ID=0
RPC_ANSWER=""

# $1 token, $2 label. Spawns lorica-mcp with the token in its
# environment (never argv) and waits for its startup notice, which it
# writes after the `whoami` round trip and only once it is serving; the
# banner comes before that trip, so waiting on the banner alone raced
# the notice check that follows.
start_session() {
    SESSION_ERR="$WORK/mcp-$2.err"
    : > "$SESSION_ERR"
    coproc MCP {
        export LORICA_MCP_ENDPOINT="$ENDPOINT"
        export LORICA_MCP_TOKEN="$1"
        export LORICA_MCP_CA_BUNDLE="$CA_BUNDLE"
        exec lorica-mcp 2>"$SESSION_ERR"
    }
    MCP_OUT=${MCP[0]}
    MCP_IN=${MCP[1]}
    MCP_CHILD=$MCP_PID
    for _ in $(seq 1 30); do
        grep -q '^lorica-mcp: Token ' "$SESSION_ERR" && break
        kill -0 "$MCP_CHILD" 2>/dev/null || break
        sleep 1
    done
    REVISION=$(sed -n 's/.*(MCP protocol revision \([^)]*\)).*/\1/p' "$SESSION_ERR" | head -1)
    if ! kill -0 "$MCP_CHILD" 2>/dev/null; then
        fail "[$2] lorica-mcp is not running after startup: $(tail -c 400 "$SESSION_ERR")"
    fi
}

# $1 method, $2 extra members of params ("" for none). The protocol
# revision rides in `_meta` on every request. Leaves RPC_ANSWER.
rpc() {
    RPC_ID=$((RPC_ID + 1))
    local params="{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$REVISION\"}${2:+,$2}}"
    printf '{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}\n' "$RPC_ID" "$1" "$params" >&"$MCP_IN"
    RPC_ANSWER=""
    IFS= read -r -t 60 RPC_ANSWER <&"$MCP_OUT" || true
}

# $1 tool, $2 arguments object.
call_tool() {
    rpc tools/call "\"name\":\"$1\",\"arguments\":$2"
}

answer_field() {
    json "$RPC_ANSWER" "SELECT json_extract(doc, '$1') FROM d"
}

# Close stdin, the portable end of a stdio session, and leave the exit
# code in SESSION_CODE.
end_session() {
    exec {MCP_IN}>&-
    wait "$MCP_CHILD"
    SESSION_CODE=$?
    exec {MCP_OUT}<&- 2>/dev/null || true
}

# ---------------------------------------------------------------------
# Audit rows.
# ---------------------------------------------------------------------

# $1 operator, $2 action and $3 target_id, both LIKE patterns. Prints
# the number of matching automation rows.
audit_count() {
    json "$(api_get "/api/v1/audit?action=automation.request.&limit=500")" \
        "SELECT count(*) FROM d, json_each(d.doc, '\$.data.entries') e
         WHERE e.value->>'operator_username' = '$1'
           AND e.value->>'action' LIKE '$2'
           AND e.value->>'target_id' LIKE '$3'"
}

# $1 operator, $2 action, $3 method and path, $4 tool, $5 label. The
# request line is established by the node; over stdio the transport and
# the tool are the caller's claim and sit in the asserted clause, so the
# row's target is `<method> <path>[?filters] asserted[transport=mcp-stdio,tool=<tool>]`.
# Polls: rows are queued and land within the writer's drain.
assert_audit() {
    local operator="$1" action="$2" request="$3" tool="$4" label="$5" count=0
    local pattern="$request% asserted[transport=mcp-stdio,tool=$tool]"
    for _ in $(seq 1 10); do
        count=$(audit_count "$operator" "$action" "$pattern")
        [ "${count:-0}" -ge 1 ] 2>/dev/null && break
        sleep 1
    done
    if [ "${count:-0}" -ge 1 ] 2>/dev/null; then
        ok "$label: row '$action' by '$operator' on '$request ... asserted[transport=mcp-stdio,tool=$tool]'"
    else
        fail "$label: no row '$action' by '$operator' matching '$pattern'"
    fi
}
