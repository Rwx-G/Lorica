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
