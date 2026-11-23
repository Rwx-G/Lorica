# shellcheck shell=bash
# Story 12.12 scenarios. Sourced by l4/run-l4.sh; see that file for the
# scenario contract.

# The harness self-test (Lot A): proves each mechanism the scenario
# Lots rely on, in the profile being run.
# - A timed in-container command: the client connects to the node's HTTP
#   listener and reads a status line, timer inside the container.
# - The management API from the client (l4_api, login included).
# - In the `streams` profile, the probe's shared namespaces: it sees the
#   supervisor and both workers, and the node's :8080 listener.
scenario_12_12_x_harness_self_test() {
    local http api_body probe_detail=""

    http=$(l4_client python3 -c '
import socket, time
start = time.monotonic()
with socket.create_connection(("l4-node", 8080), timeout=5) as s:
    s.sendall(b"GET / HTTP/1.1\r\nHost: l4-self-test\r\nConnection: close\r\n\r\n")
    status = s.recv(64).split(b"\r\n", 1)[0].decode()
print(f"{status} in {(time.monotonic() - start) * 1000:.1f} ms")
')
    case "$http" in
        HTTP/1.1\ *) ;;
        *) fail "no HTTP status line from l4-node:8080: ${http}" ;;
    esac

    api_body=$(l4_api GET /api/v1/streams)
    case "$api_body" in
        *'"streams":[]'*) ;;
        *) fail "GET /api/v1/streams on a fresh node did not list zero streams: ${api_body}" ;;
    esac

    if [ "$L4_PROFILE" = streams ]; then
        local processes listener
        # By comm: busybox `pgrep -x` matches the workers' full exe path.
        processes=$(l4_probe ps -o comm | grep -cx lorica || true)
        listener=$(l4_probe ss -ltnH 'sport = :8080')
        [ "$processes" -ge 3 ] \
            || fail "the probe sees ${processes} lorica processes, expected a supervisor and 2 workers"
        [ -n "$listener" ] \
            || fail "the probe does not see the node's :8080 listener"
        probe_detail="; probe sees ${processes} lorica processes and the :8080 listener"
    fi

    pass "client got '${http}'; API lists zero streams${probe_detail}"
}

# The fd reserve (D-f): on a node whose fd limit is 8192, a UDP stream
# takes the node's whole session ceiling `C` (per-source caps and rates
# lifted for the client), a client opens `C + 10 %` sessions and keeps
# them alive, and HTTP stays whole throughout: a loop opening a new
# connection per request at 50 per second, and `R - 64` keep-alive
# connections (`R` the HTTP reserve) opened after the fill, each
# answering twice. The sessions past `C` are refused as `session_cap`
# and counted; no EMFILE or accept error reaches the node's log. The
# shared `l4s_*` helpers are l4/lib.sh's.
#
# The stream sets `unbounded_responses` and no request bound: with the
# defaults a session ends on its one answer (`response_bound_reached`),
# so an echo backend would never hold more than a handful at once and
# the ceiling would never be reached.
scenario_12_12_fd_reserve_http_unaffected() {
    local node=lorica-budget-8k port=7200 budget limit reserve ceiling client bid id udp held
    local sessions hold loop refused errors every never some
    l4s_wait_ready "$node"
    L4S_API_SCRIPT=$(l4s_node_api_script "$node")
    l4s_echo_backends
    l4s_http_ready "$node"
    client=$(l4s_client_ip)

    budget=$(l4s_client_script 'api GET /api/v1/streams/budget | jq -r ".data.nodes[0] | \"\(.fd_limit) \(.http_reserve)\""' | tr -d '\r')
    read -r limit reserve <<< "$budget"
    [ "$limit" = 8192 ] || fail "${node} reports fd_limit ${limit}, expected the compose ulimit 8192"

    bid=$(l4s_create_backend "{\"address\":\"${client}:${L4S_UDP_ECHO_PORT}\",\"health_check_enabled\":false}") \
        || fail "backend create refused: ${bid}"
    udp='"source_session_cap":65535,"source_datagram_rate":1000000,"source_byte_rate":1073741824,"unbounded_responses":true,"requests_per_session":null'
    id=$(l4s_create_stream "{\"name\":\"l4s-fd-udp\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${port},\"backend_ids\":[\"${bid}\"],\"idle_timeout_s\":120,\"source_allow_cidrs\":[\"${client}/32\"],\"udp\":{\"max_sessions\":100,${udp}}}") \
        || fail "stream create refused: ${id}"
    # The ceiling as the node counts it with this stream's listening
    # socket in, then the stream's share raised to all of it.
    ceiling=$(l4s_client_script 'api GET /api/v1/streams/budget | jq -r ".data.nodes[0].session_ceiling"' | tr -d '\r')
    [ "${ceiling:-0}" -gt 1000 ] || fail "implausible session ceiling ${ceiling} on ${node}"
    held=$(l4s_client_script 'api PUT "/api/v1/streams/$1" "$2" | jq -r .data.udp.max_sessions' \
        "$id" "{\"udp\":{\"max_sessions\":${ceiling},${udp}}}" 2>&1 | tr -d '\r') \
        || fail "raising max_sessions to the ceiling ${ceiling} was refused: ${held}"
    [ "$held" = "$ceiling" ] || fail "max_sessions reads ${held} after the update to ${ceiling}"
    l4s_wait_bind "$id" bound 10 >/dev/null || fail "the UDP stream did not bind on ${node}"

    sessions=$(( ceiling + ceiling / 10 ))
    l4_client rm -f /tmp/l4s-fd-udp.json
    l4_compose exec -d streams-client python3 /tests/l4/udp_hold.py hold --target "${node}:${port}" \
        --sessions "$sessions" --interval 5 --duration 60 --timeout 1 --out /tmp/l4s-fd-udp.json
    l4s_loop_start fd "$node"
    # One full round (5 s) plus its echo timeout: the table is full.
    sleep 8
    hold=$(l4_client python3 /tests/l4/http_loop.py hold --target "${node}:8080" --host-header "$L4S_HTTP_HOST" \
        --count $(( reserve - 64 )) --hold-s 5 --timeout 10 | tr -d '\r')
    udp=$(l4_client bash -c 'for i in $(seq 1 900); do [ -s /tmp/l4s-fd-udp.json ] && break; sleep 0.1; done; cat /tmp/l4s-fd-udp.json' | tr -d '\r')
    loop=$(l4s_loop_stop fd)
    refused=$(l4s_client_script 'api GET /api/v1/streams/status | jq -r --arg id "$1" "[.data.streams[] | select(.id == \$id) | .counters.refused[]? | select(.reason == \"session_cap\") | .count] | add // 0"' "$id" | tr -d '\r')
    errors=$(l4_compose logs --no-color "$node" 2>&1 | grep -ciE 'emfile|too many open files|accept error|failed to accept' || true)
    l4s_cleanup_streams l4s-fd-

    every=$(printf '%s' "$udp" | l4_client jq -r .answered_every_round | tr -d '\r')
    never=$(printf '%s' "$udp" | l4_client jq -r .never_answered | tr -d '\r')
    some=$(printf '%s' "$udp" | l4_client jq -r .answered_some_rounds | tr -d '\r')
    [ "$every" = "$ceiling" ] && [ "$never" = $(( sessions - ceiling )) ] && [ "$some" = 0 ] \
        || fail "UDP: ${ceiling} sessions should hold and $(( sessions - ceiling )) be refused: ${udp}"
    [ "${refused:-0}" -ge $(( sessions - ceiling )) ] \
        || fail "only ${refused} session_cap refusals counted for $(( sessions - ceiling )) sessions past the ceiling"
    case "$loop" in
        *" failed=0 "*) ;;
        *) fail "the HTTP loop saw failures during the fill: ${loop}" ;;
    esac
    case "$hold" in
        *"\"first_ok\": $(( reserve - 64 ))"*"\"second_ok\": $(( reserve - 64 ))"*) ;;
        *) fail "not every held HTTP connection answered twice: ${hold}" ;;
    esac
    [ "$errors" = 0 ] || fail "${errors} EMFILE or accept error line(s) in ${node}'s log"
    pass "fd limit ${limit}, HTTP reserve ${reserve}, ceiling ${ceiling}: ${every} of ${sessions} UDP sessions held every round, ${never} refused (${refused} session_cap refusals counted); HTTP loop ${loop%% errors=*}; $(( reserve - 64 )) keep-alive connections answered twice; no EMFILE or accept error logged"
}
