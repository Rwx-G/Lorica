#!/usr/bin/env bash
# =============================================================================
# Lorica MCP E2E smoke (Story 11.4 AC #4, IV1, IV2).
#
# A real node, a real automation listener, and a client driving each
# tier over stdio: this script spawns `lorica-mcp` as a coprocess and
# writes newline-delimited JSON-RPC to its stdin, the way an operator's
# MCP client does. What it asserts:
#
#   - each tier's token is minted by `lorica mcp token create --tier`,
#     the real CLI, and taken from its stdout alone;
#   - `server/discover` answers the revision the binary announces, and
#     `tools/list` lists exactly the tools the CLI's blast radius printed
#     for that tier (the expected list is read off the CLI's stderr, not
#     retyped here). Both are computed by one rule, `Tier::registers`,
#     so this proves the printed blast radius and the served list agree
#     end to end, through the real mint and the real server. It cannot
#     see the tier half of that rule (`Tier::serves`), which removes
#     nothing for a token the tier check accepts and is a tripwire the
#     unit tests hold, not something this run exercises;
#   - one mutation per mutating tier (config: a route inside the
#     hostname grant; admin: `access_log_retention` raised, its safe
#     direction), one refusal each (a hostname outside the grant; the
#     same setting lowered), and a tool of another tier not callable,
#     with no row for it once a later row of the same session landed;
#   - the audit row of each call: the principal and the request line are
#     what the node established, the transport and the tool sit inside
#     the `asserted[...]` clause, because over stdio they are the
#     caller's claim;
#   - one revocation mid-session: the next call fails with the plane's
#     401 and a `token_revoked` row, and a fresh start is refused;
#   - IV1 end to end: a token carrying logs:read and routes:write, minted
#     by `lorica automation token create`, makes lorica-mcp exit 78
#     naming both scopes;
#   - IV2: the audit chain verifies afterwards.
#
# It runs from the Lorica image, sharing the node's network namespace
# (see the `mcp-smoke` service in docker-compose.yml for why). That
# image carries no jq, so JSON is read with the sqlite3 CLI's JSON
# functions through `json` below.
# =============================================================================

# `-u` without `-e`, unlike the other smokes: this one captures the
# exit code of commands that are expected to fail (the IV1 refusal, a
# revoked token's restart) and asserts on it, which `-e` would abort.
set -u
# A write to a lorica-mcp that died would raise SIGPIPE and kill the
# shell before `print_results`, losing every line collected so far. A
# broken write fails the call it belongs to instead.
trap '' PIPE

source /tests/helpers.sh

SHARED="${SHARED_DIR:-/shared}"
MANAGEMENT_PORT=19443
API="https://127.0.0.1:${MANAGEMENT_PORT}"
ENDPOINT="https://127.0.0.1:9446"
CA_BUNDLE="$SHARED/automation-listener-ca.pem"
PASSWORD_FILE="$SHARED/admin_password"
GRANTED_PATTERN="*.mcp.example.com"
GRANTED_HOST="app.mcp.example.com"
OUTSIDE_HOST="app.outside.example.org"
BACKEND_CIDR="192.0.2.0/24"
WORK=$(mktemp -d)

# The exit codes lorica-mcp documents (lorica-mcp/src/main.rs).
EXIT_MISCONFIGURED=78
EXIT_PLANE_UNREACHABLE=69

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

# The stored row of the token labelled $1, as the management API lists
# it: the node's own record of what it minted.
token_row() {
    json "$(api_get /api/v1/automation/tokens)" \
        "SELECT e.value FROM d, json_each(d.doc, '\$.data.tokens') e
         WHERE e.value->>'name' = '$1' ORDER BY e.value->>'created_at' DESC LIMIT 1"
}

# The tools the CLI's blast radius names, one per line, sorted.
blast_radius_tools() {
    grep -oE '^    lorica_[a-z_]+ \[' "$1" | awk '{print $1}' | sort
}

# $1 tier, then the grant flags. Mints, asserts the CLI's contract, and
# leaves TOKEN, PUBLIC_ID and EXPECTED_TOOLS behind.
mint_and_check() {
    local tier="$1" row scopes_row scopes_printed
    shift
    mint_tier "$tier" "$@"
    if [ "$MINT_CODE" = "0" ]; then
        ok "[$tier] lorica mcp token create --tier $tier exited 0"
    else
        fail "[$tier] lorica mcp token create --tier $tier exited $MINT_CODE: $(tail -c 400 "$MINT_ERR")"
    fi
    if [ "$(printf '%s\n' "$MINTED" | wc -l)" = "1" ] && [[ "$MINTED" =~ ^[[:graph:]]+$ ]]; then
        ok "[$tier] stdout carries one line and nothing but the token"
    else
        fail "[$tier] stdout is not a single token line"
    fi
    TOKEN="$MINTED"

    row=$(token_row "mcp-$tier")
    PUBLIC_ID=$(json "$row" "SELECT doc->>'public_id' FROM d")
    if [ -n "$PUBLIC_ID" ] && grep -q "minted automation token $PUBLIC_ID" "$MINT_ERR"; then
        ok "[$tier] the node stored mcp-$tier as $PUBLIC_ID, the id the CLI printed on stderr"
    else
        fail "[$tier] no stored row mcp-$tier matching the CLI's notice (row: '$row')"
    fi

    # The scopes the node stored against the ones the CLI said it minted.
    scopes_row=$(json "$row" "SELECT value FROM d, json_each(d.doc, '\$.scopes') ORDER BY 1" | tr '\n' ' ')
    scopes_printed=$(sed -n 's/^  Scopes: //p' "$MINT_ERR" | tr ',' '\n' | tr -d ' ' | sed '/^$/d' | sort | tr '\n' ' ')
    if [ -n "$scopes_row" ] && [ "$scopes_row" = "$scopes_printed" ]; then
        ok "[$tier] the stored scopes are the ones the blast radius printed ($scopes_row)"
    else
        fail "[$tier] stored scopes '$scopes_row' differ from printed '$scopes_printed'"
    fi

    EXPECTED_TOOLS=$(blast_radius_tools "$MINT_ERR")
    if [ -z "$EXPECTED_TOOLS" ]; then
        fail "[$tier] the blast radius named no tool"
    fi
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
# the notice check below.
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

# $1 tier label. Discovery, then the tool list against the blast radius.
check_discovery_and_tools() {
    local tier="$1" listed
    if [ -n "$REVISION" ]; then
        ok "[$tier] lorica-mcp started and announced revision $REVISION on stderr"
    else
        fail "[$tier] lorica-mcp announced no revision: $(tail -c 400 "$SESSION_ERR")"
    fi
    if grep -q "Token $PUBLIC_ID registered" "$SESSION_ERR"; then
        ok "[$tier] the startup notice names the token $PUBLIC_ID"
    else
        fail "[$tier] the startup notice does not name $PUBLIC_ID: $(tail -c 400 "$SESSION_ERR")"
    fi

    rpc server/discover ""
    if [ "$(answer_field '$.result.supportedVersions')" = "[\"$REVISION\"]" ] \
        && [ "$(answer_field '$.result.serverInfo.name')" = "lorica-mcp" ]; then
        ok "[$tier] server/discover answers lorica-mcp speaking $REVISION alone"
    else
        fail "[$tier] server/discover answered: $RPC_ANSWER"
    fi

    rpc tools/list ""
    listed=$(json "$RPC_ANSWER" "SELECT e.value->>'name' FROM d, json_each(d.doc, '\$.result.tools') e ORDER BY 1")
    if [ -n "$listed" ] && [ "$listed" = "$EXPECTED_TOOLS" ]; then
        ok "[$tier] tools/list is exactly the blast radius's $(echo "$listed" | wc -l) tools"
    else
        fail "[$tier] tools/list differs from the blast radius: listed [$(echo $listed)] expected [$(echo $EXPECTED_TOOLS)]"
    fi
}

# $1 tier label, $2 a tool of another tier. The tool does not exist to be
# called: a protocol error, no result, and nothing reaches the plane,
# which `assert_no_row_for` checks once a later row has landed.
check_foreign_tool() {
    local tier="$1" tool="$2"
    call_tool "$tool" '{}'
    if [ -n "$(answer_field '$.error.code')" ] && [ -z "$(answer_field '$.result')" ]; then
        ok "[$tier] $tool, of another tier, is a protocol error ($(answer_field '$.error.code'))"
    else
        fail "[$tier] $tool answered: $RPC_ANSWER"
    fi
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

# $1 operator, $2 tool, $3 label. No request row names the tool for the
# operator. Rows are queued and land in order, so this is called after
# `assert_audit` has seen a LATER row of the same token land: a row for
# the refused call, had one been written, would be there by then.
assert_no_row_for() {
    if [ "$(audit_count "$1" "%" "%tool=$2%")" = "0" ]; then
        ok "$3: the refused $2 left no row: it never reached the plane"
    else
        fail "$3: a row names $2 for $1"
    fi
}

route_count() {
    json "$(api_get /api/v1/routes)" \
        "SELECT count(*) FROM d, json_each(d.doc, '\$.data.routes') e WHERE e.value->>'hostname' = '$1'"
}

setting_value() {
    json "$(api_get /api/v1/settings)" "SELECT doc->>'\$.data.$1' FROM d"
}

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== mcp smoke: preflight ==="

for _ in $(seq 1 120); do
    [ -f "$SHARED/mcp_ready" ] && break
    sleep 1
done
if [ ! -f "$SHARED/mcp_ready" ]; then
    fail "the mcp node never became ready"
    print_results
fi
if ! wait_for_api 60; then
    fail "the management API never answered"
    print_results
fi
login "$(cat "$PASSWORD_FILE")"
if [ -n "$(api_get /api/v1/settings | grep -o '"data"')" ]; then
    ok "logged in to the management API"
else
    fail "cannot log in to the management API"
    print_results
fi

# The listener opens with the process; a handful of probes at most, well
# inside the per-source connection budget.
LISTENER_UP=0
for _ in $(seq 1 15); do
    code=$(curl -s --cacert "$CA_BUNDLE" -o /dev/null -w '%{http_code}' \
        "$ENDPOINT/automation/v1/whoami" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        LISTENER_UP=1
        break
    fi
    sleep 2
done
if [ "$LISTENER_UP" = "1" ]; then
    ok "the automation listener answers on $ENDPOINT, verified against the node's own certificate"
else
    fail "the automation listener never answered on $ENDPOINT"
    print_results
fi

# ---------------------------------------------------------------------
# Read tier, and the revocation.
# ---------------------------------------------------------------------
log "=== mcp smoke: read tier ==="
mint_and_check read
READ_OPERATOR="mcp-read ($PUBLIC_ID)"
READ_PUBLIC_ID="$PUBLIC_ID"
READ_TOKEN="$TOKEN"

start_session "$READ_TOKEN" read
check_discovery_and_tools read

call_tool lorica_routes '{}'
if [ "$(answer_field '$.result.isError')" = "0" ]; then
    ok "[read] lorica_routes answered"
else
    fail "[read] lorica_routes answered: $RPC_ANSWER"
fi
assert_audit "$READ_OPERATOR" "automation.request.ok" "GET /automation/v1/routes" lorica_routes "[read] the read"

check_foreign_tool read lorica_route_create

log "=== mcp smoke: revocation mid-session ==="
assert_status DELETE "$API/api/v1/automation/tokens/$READ_PUBLIC_ID" 200 "[read] the token was revoked"
call_tool lorica_routes '{}'
REVOKED_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] && [[ "$REVOKED_TEXT" == *"HTTP 401"* ]]; then
    ok "[read] the next call is an execution error carrying the plane's 401"
else
    fail "[read] the call after revocation answered: $RPC_ANSWER"
fi
# A refused credential names nobody: the row's principal is the plane's
# anonymous marker and the reason rides in the action.
assert_audit "-" "automation.request.unauthenticated:token_revoked" \
    "GET /automation/v1/routes" lorica_routes "[read] the refused call"
assert_no_row_for "$READ_OPERATOR" lorica_route_create "[read]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[read] closing stdin ended the session with exit 0"
else
    fail "[read] the session ended with exit $SESSION_CODE"
fi

REVOKED_ERR="$WORK/mcp-revoked.err"
REVOKED_OUT=$(LORICA_MCP_ENDPOINT="$ENDPOINT" LORICA_MCP_TOKEN="$READ_TOKEN" \
    LORICA_MCP_CA_BUNDLE="$CA_BUNDLE" lorica-mcp </dev/null 2>"$REVOKED_ERR")
REVOKED_CODE=$?
if [ "$REVOKED_CODE" = "$EXIT_PLANE_UNREACHABLE" ] && [ -z "$REVOKED_OUT" ]; then
    ok "[read] a fresh start on the revoked token exits $EXIT_PLANE_UNREACHABLE with nothing on stdout"
else
    fail "[read] a fresh start on the revoked token exited $REVOKED_CODE: $(tail -c 400 "$REVOKED_ERR")"
fi

# ---------------------------------------------------------------------
# Config tier.
# ---------------------------------------------------------------------
log "=== mcp smoke: config tier ==="
mint_and_check config --hostname "$GRANTED_PATTERN" --backend-cidr "$BACKEND_CIDR"
CONFIG_OPERATOR="mcp-config ($PUBLIC_ID)"

start_session "$TOKEN" config
check_discovery_and_tools config
check_foreign_tool config lorica_settings_update

call_tool lorica_route_create "{\"route\":{\"hostname\":\"$GRANTED_HOST\"}}"
if [ "$(answer_field '$.result.isError')" = "0" ] && [ "$(route_count "$GRANTED_HOST")" = "1" ]; then
    ok "[config] lorica_route_create inside the grant created $GRANTED_HOST"
else
    fail "[config] lorica_route_create answered: $RPC_ANSWER"
fi
assert_audit "$CONFIG_OPERATOR" "automation.request.ok" "POST /automation/v1/routes" \
    lorica_route_create "[config] the mutation"

call_tool lorica_route_create "{\"route\":{\"hostname\":\"$OUTSIDE_HOST\"}}"
OUTSIDE_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] \
    && [[ "$OUTSIDE_TEXT" == *"outside this token's allowed_hostnames"* ]] \
    && [ "$(route_count "$OUTSIDE_HOST")" = "0" ]; then
    ok "[config] a hostname outside the grant is refused by the plane and nothing is created"
else
    fail "[config] the out-of-grant create answered: $RPC_ANSWER"
fi
assert_audit "$CONFIG_OPERATOR" "automation.request.forbidden" "POST /automation/v1/routes" \
    lorica_route_create "[config] the refusal"
assert_no_row_for "$CONFIG_OPERATOR" lorica_settings_update "[config]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[config] closing stdin ended the session with exit 0"
else
    fail "[config] the session ended with exit $SESSION_CODE"
fi

# ---------------------------------------------------------------------
# Admin tier.
# ---------------------------------------------------------------------
log "=== mcp smoke: admin tier ==="
mint_and_check admin
ADMIN_OPERATOR="mcp-admin ($PUBLIC_ID)"

start_session "$TOKEN" admin
check_discovery_and_tools admin
check_foreign_tool admin lorica_route_create

RETENTION_BEFORE=$(setting_value access_log_retention)
RETENTION_RAISED=$((RETENTION_BEFORE + 1000))
call_tool lorica_settings_update "{\"settings\":{\"access_log_retention\":$RETENTION_RAISED}}"
if [ "$(answer_field '$.result.isError')" = "0" ] \
    && [ "$(setting_value access_log_retention)" = "$RETENTION_RAISED" ]; then
    ok "[admin] access_log_retention raised from $RETENTION_BEFORE to $RETENTION_RAISED"
else
    fail "[admin] raising access_log_retention answered: $RPC_ANSWER"
fi
assert_audit "$ADMIN_OPERATOR" "automation.request.ok" "PUT /automation/v1/settings" \
    lorica_settings_update "[admin] the mutation"

call_tool lorica_settings_update "{\"settings\":{\"access_log_retention\":$RETENTION_BEFORE}}"
LOWER_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] && [[ "$LOWER_TEXT" == *"access_log_retention"* ]] \
    && [ "$(setting_value access_log_retention)" = "$RETENTION_RAISED" ]; then
    ok "[admin] lowering a raise-only retention is refused by the plane, naming the field"
else
    fail "[admin] lowering access_log_retention answered: $RPC_ANSWER"
fi
assert_audit "$ADMIN_OPERATOR" "automation.request.refused" "PUT /automation/v1/settings" \
    lorica_settings_update "[admin] the refusal"
assert_no_row_for "$ADMIN_OPERATOR" lorica_route_create "[admin]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[admin] closing stdin ended the session with exit 0"
else
    fail "[admin] the session ended with exit $SESSION_CODE"
fi

# ---------------------------------------------------------------------
# IV1: one process, one tier, end to end.
# ---------------------------------------------------------------------
log "=== mcp smoke: IV1, a token spanning two tiers ==="
IV1_ERR="$WORK/iv1-mint.err"
IV1_TOKEN=$(lorica --management-port "$MANAGEMENT_PORT" automation token create \
    --name mcp-iv1-spans --scope logs:read --scope routes:write \
    --hostname "$GRANTED_HOST" --backend-cidr "$BACKEND_CIDR" \
    --password-file "$PASSWORD_FILE" 2>"$IV1_ERR")
IV1_MINT_CODE=$?
if [ "$IV1_MINT_CODE" = "0" ] && [ -n "$IV1_TOKEN" ]; then
    ok "[iv1] lorica automation token create minted logs:read + routes:write"
else
    fail "[iv1] the mint exited $IV1_MINT_CODE: $(tail -c 400 "$IV1_ERR")"
fi
IV1_RUN_ERR="$WORK/iv1-run.err"
IV1_OUT=$(LORICA_MCP_ENDPOINT="$ENDPOINT" LORICA_MCP_TOKEN="$IV1_TOKEN" \
    LORICA_MCP_CA_BUNDLE="$CA_BUNDLE" lorica-mcp </dev/null 2>"$IV1_RUN_ERR")
IV1_CODE=$?
if [ "$IV1_CODE" = "$EXIT_MISCONFIGURED" ] && [ -z "$IV1_OUT" ]; then
    ok "[iv1] lorica-mcp refused to start with exit $EXIT_MISCONFIGURED and nothing on stdout"
else
    fail "[iv1] lorica-mcp exited $IV1_CODE: $(tail -c 400 "$IV1_RUN_ERR")"
fi
if grep -q "logs:read" "$IV1_RUN_ERR" && grep -q "routes:write" "$IV1_RUN_ERR"; then
    ok "[iv1] the refusal names both logs:read and routes:write"
else
    fail "[iv1] the refusal does not name both scopes: $(tail -c 600 "$IV1_RUN_ERR")"
fi

# ---------------------------------------------------------------------
# IV2: the audit chain verifies after all of it.
# ---------------------------------------------------------------------
log "=== mcp smoke: IV2, audit chain ==="
VERIFY=$(api_get /api/v1/audit/verify)
VERIFIED=$(json "$VERIFY" "SELECT json_extract(doc, '\$.data.verified') FROM d")
LOCAL_ROWS=$(json "$VERIFY" "SELECT e.value->>'total_rows' FROM d, json_each(d.doc, '\$.data.nodes') e WHERE e.value->>'node_id' = ''")
if [ "$VERIFIED" = "1" ] && [ "${LOCAL_ROWS:-0}" -gt 0 ] 2>/dev/null; then
    ok "[iv2] the audit chain verifies over $LOCAL_ROWS rows"
else
    fail "[iv2] audit verify answered: $VERIFY"
fi

print_results
