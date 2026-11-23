# shellcheck shell=bash
# Story 12.1 scenarios in the L4 phase (Story 12.12 Lot L): the cold
# rollback to the released 1.10.7 of AC #3 (D-h), in the
# `streams-single` profile. IV1 and IV2 run in the `cluster` profile's
# smoke, the hot rollback in the `hot-upgrade` profile's. Sourced by
# l4/run-l4.sh; the shared `l4s_*` helpers are l4/lib.sh's.
#
# The baseline is `lorica-baseline-single` (docker-compose.l4.yml): the
# 1.10.7 package's binary on the streams-single node's volumes, started
# through the node's own entrypoint, in a profile of its own so the
# `streams-single` profile never starts it. It carries the `l4-node`
# alias, so the client's API script and tools reach whichever binary
# runs.

L4L_BASELINE=lorica-baseline-single
L4L_BASELINE_PROFILE=streams-single-baseline
L4L_HOST=l4l-rollback.test
L4L_STREAM_PORT=7900

l4l_baseline() {
    l4_compose --profile "$L4L_BASELINE_PROFILE" "$@"
}

# `<count> <max version>` of schema_migrations, read in <service> as the
# `lorica` user: a reader of a WAL database may create its -shm and -wal
# files, which root would leave unwritable to Lorica.
l4l_schema() {
    l4_compose exec -T -u lorica "$1" sqlite3 /var/lib/lorica/lorica.db \
        "SELECT COUNT(*) || ' ' || MAX(version) FROM schema_migrations" | tr -d '\r'
}

# The status of one request to the rollback route through l4-node:8080.
l4l_route_status() {
    l4_client python3 /tests/l4/http_loop.py get --target l4-node:8080 --host-header "$L4L_HOST" --timeout 2 \
        | tr -d '\r' | l4_client jq -r .status | tr -d '\r'
}

# The route answering 200, polled for up to 20 s; prints the last status.
l4l_wait_route() {
    local i status=000
    for i in $(seq 1 100); do
        status=$(l4l_route_status 2>/dev/null) || status=000
        [ "$status" = 200 ] && break
        sleep 0.2
    done
    echo "$status"
}

# One line echoed through the stream port of l4-node: prints the echo,
# or `refused` / `no answer`.
L4L_ECHO='import socket, sys
try:
    s = socket.create_connection(("l4-node", int(sys.argv[1])), timeout=3)
    s.sendall(b"rollback\n")
    data = s.recv(64)
    print(data.decode().strip() or "closed")
except ConnectionRefusedError:
    print("refused")
except OSError as e:
    print(f"no answer ({e.__class__.__name__})")
'

l4l_echo() {
    l4_client python3 -c "$L4L_ECHO" "$L4L_STREAM_PORT" | tr -d '\r'
}

# Wait until the API on l4-node answers, whichever binary serves it.
l4l_wait_api() {
    local service="$1" i
    for i in $(seq 1 60); do
        if l4_compose exec -T "$service" sh -c 'curl -skf https://127.0.0.1:19443/ >/dev/null' >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# AC #3 (D-h): 1.11.0 has migrated the node's database and holds a
# stream, its link, a backend with an HTTP check on `/h` and one with a
# send/expect check 1.10.7 cannot express. The node is stopped and the
# released 1.10.7 runs on the same volume: it starts, applies no
# migration, serves an HTTP route, binds no stream, and lists both
# backends; through its API the first backend's path becomes `/x`, and
# nothing else is touched. Stopped, and 1.11.0 started again: the first
# backend reads `http /x`, the send/expect check is unchanged, the stream
# and its link are intact and the stream binds and echoes again.
scenario_12_1_ac3_rollback_cold_1_10_7() {
    local client_ip http echo stream hc_http hc_se stream_before schema_new version schema_old \
        status_old echo_old listed path_old schema_back hc_http_back hc_se_back stream_after bound echo_back
    trap 'l4l_baseline rm -sf "$L4L_BASELINE" >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4l-
    l4s_echo_backends
    l4s_client_daemon tcp "$L4S_HTTP_PORT" python3 /tests/l4/http_loop.py serve --port "$L4S_HTTP_PORT"
    client_ip=$(l4s_client_ip)

    http=$(l4s_create_backend "{\"name\":\"l4l-http-check\",\"address\":\"${client_ip}:${L4S_HTTP_PORT}\",\"health_check_enabled\":false,\"health_check\":{\"kind\":\"http\",\"path\":\"/h\"}}") \
        || fail "backend with an HTTP check refused: ${http}"
    echo=$(l4s_create_backend "{\"name\":\"l4l-send-expect\",\"address\":\"${client_ip}:${L4S_TCP_ECHO_PORT}\",\"health_check_enabled\":true,\"health_check_interval_s\":5,\"health_check\":{\"kind\":\"tcp_send_expect\",\"send\":{\"text\":\"PING\\r\\n\"},\"expect\":[{\"match\":\"prefix\",\"bytes\":{\"text\":\"PING\"}}],\"timeout_ms\":2000}}") \
        || fail "backend with a send/expect check refused: ${echo}"
    l4s_client_script 'api POST /api/v1/routes "$1" >/dev/null' \
        "{\"hostname\":\"${L4L_HOST}\",\"backend_ids\":[\"${http}\"]}" || fail "route create refused"
    stream=$(l4s_create_stream "{\"name\":\"l4l-cold-stream\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${L4L_STREAM_PORT},\"backend_ids\":[\"${echo}\"]}") \
        || fail "stream create refused: ${stream}"
    l4s_wait_bind "$stream" bound 5 >/dev/null || fail "the stream did not bind under 1.11.0"
    [ "$(l4l_echo)" = rollback ] || fail "the stream did not echo under 1.11.0: $(l4l_echo)"
    [ "$(l4l_wait_route)" = 200 ] || fail "the route did not answer under 1.11.0"
    hc_http=$(l4_api GET "/api/v1/backends/${http}" | l4_client jq -c '[.data.health_check, .data.health_check_path]' | tr -d '\r')
    hc_se=$(l4_api GET "/api/v1/backends/${echo}" | l4_client jq -c '[.data.health_check, .data.health_check_path]' | tr -d '\r')
    stream_before=$(l4_api GET "/api/v1/streams/${stream}" | l4_client jq -cS '.data | del(.bind)' | tr -d '\r')
    [ "$hc_http" = '[{"kind":"http","path":"/h"},"/h"]' ] || fail "the HTTP check reads ${hc_http} under 1.11.0"
    schema_new=$(l4l_schema "$L4_NODE")

    # 1.10.7 on the same volume.
    l4_compose stop "$L4_NODE" >/dev/null 2>&1
    l4l_baseline up -d --no-deps "$L4L_BASELINE" >/dev/null 2>&1 || fail "the 1.10.7 container did not start"
    l4l_wait_api "$L4L_BASELINE" || { l4_dump_node_log "$L4L_BASELINE"; fail "1.10.7 did not answer its API on the 1.11.0 database"; }
    version=$(l4_compose exec -T "$L4L_BASELINE" lorica --version | tr -d '\r')
    [ "$version" = "lorica 1.10.7" ] || fail "the baseline container runs ${version}"
    schema_old=$(l4l_schema "$L4L_BASELINE")
    [ "$schema_old" = "$schema_new" ] || fail "1.10.7 changed schema_migrations: ${schema_new} before, ${schema_old} under 1.10.7"
    status_old=$(l4l_wait_route)
    [ "$status_old" = 200 ] || fail "1.10.7 did not serve the HTTP route (status ${status_old})"
    echo_old=$(l4l_echo)
    case "$echo_old" in refused) ;; *) fail "1.10.7 answered on the stream port: ${echo_old}" ;; esac
    listed=$(l4_api GET /api/v1/backends | l4_client jq -r --arg a "$http" --arg b "$echo" \
        '[.data.backends[] | select(.id == $a or .id == $b)] | length' | tr -d '\r')
    [ "$listed" = 2 ] || fail "1.10.7 lists ${listed} of the two backends"
    path_old=$(l4_api GET "/api/v1/backends/${echo}" | l4_client jq -c .data.health_check_path | tr -d '\r')
    l4_api PUT "/api/v1/backends/${http}" '{"health_check_path":"/x"}' >/dev/null || fail "1.10.7 refused the path edit"

    # 1.11.0 again.
    l4l_baseline stop "$L4L_BASELINE" >/dev/null 2>&1
    l4l_baseline rm -f "$L4L_BASELINE" >/dev/null 2>&1
    l4s_restart_node
    schema_back=$(l4l_schema "$L4_NODE")
    hc_http_back=$(l4_api GET "/api/v1/backends/${http}" | l4_client jq -c '[.data.health_check, .data.health_check_path]' | tr -d '\r')
    hc_se_back=$(l4_api GET "/api/v1/backends/${echo}" | l4_client jq -c '[.data.health_check, .data.health_check_path]' | tr -d '\r')
    stream_after=$(l4_api GET "/api/v1/streams/${stream}" | l4_client jq -cS '.data | del(.bind)' | tr -d '\r')
    bound=$(l4s_wait_bind "$stream" bound 10) || fail "the stream did not bind again under 1.11.0: ${bound}"
    echo_back=$(l4l_echo)
    l4s_cleanup_streams l4l-

    [ "$schema_back" = "$schema_new" ] || fail "schema_migrations moved across the round trip: ${schema_new} then ${schema_back}"
    [ "$hc_http_back" = '[{"kind":"http","path":"/x"},"/x"]' ] \
        || fail "the path edited under 1.10.7 is not the check 1.11.0 reads: ${hc_http_back}"
    [ "$hc_se_back" = "$hc_se" ] || fail "the send/expect check changed across the rollback: ${hc_se} then ${hc_se_back}"
    [ "$stream_after" = "$stream_before" ] || fail "the stream changed across the rollback: ${stream_before} then ${stream_after}"
    [ "$echo_back" = rollback ] || fail "the stream bound again but did not echo: ${echo_back}"
    pass "schema_migrations ${schema_new} (count, max) unchanged by ${version}, which served the route (200), bound nothing on ${L4L_STREAM_PORT} (${echo_old}) and listed both backends (send/expect one with health_check_path ${path_old}); path set to /x there; back on 1.11.0: http check ${hc_http_back}, send/expect check unchanged, stream and its link unchanged, bound and echoing again"
}
