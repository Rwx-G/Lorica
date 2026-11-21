# shellcheck shell=bash
# Story 12.6 scenarios (Story 12.12 Lot F: the items of Story 12.6 Lot I,
# IV1 to IV3, an IP allow/deny entry beside IV2's GeoIP, and the
# concurrency-caps row of the parity matrix, D-e). Sourced by
# l4/run-l4.sh; see that file for the scenario contract. The `l4s_*` and
# `l4c_*` helpers are l4/scenarios/12.2.sh's and 12.3.sh's.
#
# Sources. Each scenario connects the client to `streams-geo`, whose /24
# is in the GeoIP test database's US block (l4/lib.sh derives it per
# lane), and disconnects it when it ends: attached for the whole profile,
# the client's host name would resolve to either address, and the other
# stories' scenarios take the client's address from it. The client
# reaches the worker node as `l4-node` from its `l4` address, a source
# the database does not know, and as `l4-node-geo` from its US address.
# test-runner/l4/protect_tools.py takes the source with `--bind` and
# resolves over IPv4 only, so the address judged is the one named here.
# Streams use ports 77xx, stream names start with `l4f-`, and files in
# the client with /tmp/l4f-.

L4F_TOOL=/tests/l4/protect_tools.py
L4F_GEOIP_DB=/etc/lorica-l4/GeoIP2-Country-Test.mmdb
L4F_TLS_PORT=9610
L4F_SNI=protect.l4.test

# One protect_tools.py invocation in the client; prints its JSON line.
l4f_tool() {
    l4_client python3 "$L4F_TOOL" "$@" | tr -d '\r'
}

# A jq filter applied to a JSON text, in the client (the host has no jq).
l4f_jq() {
    printf '%s' "$1" | l4_client jq -r "$2" | tr -d '\r'
}

L4F_GEO_NET="${L4_PROJECT}_streams-geo"

l4f_client_container() {
    l4_compose ps -q streams-client | tr -d '\r'
}

# Disconnect the client from streams-geo (every scenario's EXIT trap).
l4f_geo_detach() {
    docker network disconnect "$L4F_GEO_NET" "$(l4f_client_container)" >/dev/null 2>&1 || true
}

# Connects the client to streams-geo and sets L4F_GEO (its US address
# there), L4F_GEO_DEV and L4F_GEO_PREFIX (its interface), L4F_NODE (the
# node's address on `l4`) and L4F_L4 (the client's source towards it,
# the route's choice).
l4f_addresses() {
    local geo i
    l4f_geo_detach
    docker network connect "$L4F_GEO_NET" "$(l4f_client_container)" || fail "could not connect the client to ${L4F_GEO_NET}"
    for i in $(seq 1 25); do
        geo=$(l4f_tool addr-in --subnet "$L4_GEO_SUBNET") && break
        sleep 0.2
    done
    [ -n "$(l4f_jq "$geo" '.address // empty')" ] || fail "the client has no address in ${L4_GEO_SUBNET}: ${geo}"
    L4F_GEO=$(l4f_jq "$geo" .address)
    L4F_GEO_DEV=$(l4f_jq "$geo" .dev)
    L4F_GEO_PREFIX=$(l4f_jq "$geo" .prefix)
    L4F_NODE=$(l4c_ip l4-node)
    L4F_L4=$(l4_client ip -o -4 route get "$L4F_NODE" | tr -d '\r' | grep -o 'src [0-9.]*' | cut -d' ' -f2)
    [ -n "$L4F_GEO" ] && [ -n "$L4F_L4" ] && [ "$L4F_GEO" != "$L4F_L4" ] \
        || fail "client addresses: US '${L4F_GEO}', l4 '${L4F_L4}'"
}

# The node's GeoIP database, set once per profile run (a settings write
# reaches every worker through the reload).
l4f_geoip_ready() {
    local path
    path=$(l4_api GET /api/v1/settings | l4_client jq -r .data.geoip_db_path | tr -d '\r')
    [ "$path" = "$L4F_GEOIP_DB" ] && return 0
    l4_api PUT /api/v1/settings "{\"geoip_db_path\":\"${L4F_GEOIP_DB}\"}" >/dev/null || fail "geoip_db_path not accepted"
}

# Stream access-log rows of one stream and refusal reason: prints
# `<refusal rows> <suppressed rows> <refusals the suppressed rows count>`.
L4F_LOG_ROWS_SCRIPT='
api GET "/api/v1/stream-logs?stream_id=$1&refusal_reason=$2&limit=1000" | jq -r "
    [.data.entries[] | select(.entry == \"ended\")] as \$r
    | [.data.entries[] | select(.entry == \"refusals_suppressed\")] as \$s
    | \"\(\$r | length) \(\$s | length) \([\$s[].suppressed] | add // 0)\""
'

l4f_log_rows() {
    l4s_client_script "$L4F_LOG_ROWS_SCRIPT" "$1" "$2" | tr -d '\r'
}

# Waits, up to <seconds>, until the access log accounts for every
# refusal the counters hold for <stream> and <reason>: refusal rows plus
# the refusals the suppressed rows count. A window's suppressed row is
# written when the window (REFUSAL_LOG_WINDOW, 10 s) closes. Prints
# `<counter> <refusal rows> <suppressed rows> <suppressed count>`.
l4f_wait_log_accounts() {
    local id="$1" reason="$2" limit="$3" t0=$SECONDS counter rows
    while :; do
        counter=$(l4c_reason_count "$id" "$reason")
        rows=$(l4f_log_rows "$id" "$reason")
        set -- $rows
        if [ "${counter:-0}" -gt 0 ] && [ $(( $1 + $3 )) -eq "$counter" ]; then
            echo "$counter $rows"
            return 0
        fi
        if [ $(( SECONDS - t0 )) -ge "$limit" ]; then
            echo "$counter $rows"
            return 1
        fi
        sleep 1
    done
}

# The worker count of the node, from the budget view.
l4f_workers() {
    l4_api GET /api/v1/streams/budget | l4_client jq -r '.data.nodes[0].worker_count' | tr -d '\r'
}

# ---- IV1 -------------------------------------------------------------

# IV1: a TCP echo stream with source_open_rate = 5. 30 connects in one
# second from the US address are partly refused (closed before any
# echo); three connects from the client's `l4` address in the same
# second are all served. Every refusal is counted as source_open_rate,
# and the access log holds at most one refusal row per worker for the
# window, then a suppressed row counting the rest.
scenario_12_6_iv1_source_rate_refused_other_served() {
    local echo id burst served closed odd other refused log workers
    trap 'l4s_cleanup_streams l4f-iv1-; l4f_geo_detach' EXIT
    l4s_cleanup_streams l4f-iv1-
    l4f_addresses
    workers=$(l4f_workers)
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000" nocheck) || fail "backend: ${echo}"
    id=$(l4s_create_stream "{\"name\":\"l4f-iv1-rate\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7700,\"backend_ids\":[\"${echo}\"],\"source_open_rate\":5}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"

    burst=$(l4f_tool tcp-burst --target l4-node-geo:7700 --bind "$L4F_GEO" --count 30 --period 1 \
        --other-target l4-node:7700 --other-bind "$L4F_L4" --other-count 3) || fail "the burst did not run: ${burst}"
    read -r served closed odd other <<< "$(l4f_jq "$burst" '"\(.primary.served) \(.primary.closed) \(.primary.other) \(.other.served)"')"
    [ "$odd" = 0 ] || fail "connections from ${L4F_GEO} neither served nor closed: ${burst}"
    [ "$served" -ge 1 ] && [ "$closed" -ge 1 ] || fail "30 connects in one second from ${L4F_GEO} at 5/s were not partly refused: ${burst}"
    [ "$other" = 3 ] || fail "the other source ${L4F_L4} was not served in the same second: ${burst}"

    refused=$(l4c_wait_reason_count "$id" source_open_rate "$closed")
    [ "$refused" = "$closed" ] || fail "${closed} connections closed, ${refused} counted source_open_rate"
    log=$(l4f_wait_log_accounts "$id" source_open_rate 25) || fail "the access log does not account for the refusals (counter, rows, suppressed rows, suppressed): ${log}"
    set -- $log
    [ "$2" -ge 1 ] && [ "$2" -le "$workers" ] || fail "${2} source_open_rate refusal rows for one window, ${workers} workers"
    [ "$3" -ge 1 ] || fail "no refusals_suppressed row after ${refused} refusals"
    pass "from ${L4F_GEO}: ${served} of 30 served, ${closed} closed before any echo, ${refused} counted source_open_rate; from ${L4F_L4}: 3 of 3 served in the same second (burst took $(l4f_jq "$burst" .period_seconds) s); access log: ${2} refusal row(s) (${workers} workers), ${3} suppressed row(s) counting ${4}"
}

# ---- IV2, and the IP allow/deny entries ------------------------------

# One connection per plan item (`<bind>><host>:<port>:<n>`), printing
# each item's outcomes joined with commas, one item per line.
l4f_outcomes() {
    local out
    out=$(l4f_tool hold-tcp --plan "$1" --hold 0) || { echo "hold-tcp failed: ${out}"; return 1; }
    l4f_jq "$out" '.items[] | .outcomes | join(",")'
}

l4f_udp() {
    l4f_jq "$(l4f_tool udp-query --target "$1" --bind "$2" --timeout 2)" .answered
}

# IV2: geoip denylist US on a TCP stream and a UDP stream. From the US
# address the TCP connection closes with no echo and the UDP query gets
# no answer; from the `l4` address (not in the database: unknown, which
# passes) both are served; both refusals are counted `geoip` and have
# their access-log rows. Then the IP-literal entries (the "IP allow/deny"
# row of the parity matrix): a TCP stream denying the US address /32
# serves `l4` and refuses it; a UDP stream allowing the `l4` address /32
# (an allowlist, so no explicit session cap is needed on 0.0.0.0) serves
# `l4` and refuses the US address; both count `source_denied`.
scenario_12_6_iv2_geo_deny_tcp_and_udp() {
    local echo udp_echo tcp udp deny allow got i tcp_geo tcp_l4 udp_geo udp_l4 n rows
    trap 'l4s_cleanup_streams l4f-iv2-; l4f_geo_detach' EXIT
    l4s_cleanup_streams l4f-iv2-
    l4f_addresses
    l4f_geoip_ready
    l4s_echo_backends
    echo=$(l4c_backend "$(l4c_ip tcp-backend-1):9000" nocheck) || fail "backend: ${echo}"
    udp_echo=$(l4c_backend "${L4F_L4}:${L4S_UDP_ECHO_PORT}" nocheck) || fail "backend: ${udp_echo}"
    local geo='"geoip":{"mode":"denylist","countries":["US"]}'
    tcp=$(l4s_create_stream "{\"name\":\"l4f-iv2-geo-tcp\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7701,\"backend_ids\":[\"${echo}\"],${geo}}") \
        || fail "stream create refused: ${tcp}"
    udp=$(l4s_create_stream "{\"name\":\"l4f-iv2-geo-udp\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7702,\"backend_ids\":[\"${udp_echo}\"],${geo},\"udp\":{\"source_session_cap\":64}}") \
        || fail "stream create refused: ${udp}"
    deny=$(l4s_create_stream "{\"name\":\"l4f-iv2-deny-tcp\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7703,\"backend_ids\":[\"${echo}\"],\"source_deny_cidrs\":[\"${L4F_GEO}/32\"]}") \
        || fail "stream create refused: ${deny}"
    allow=$(l4s_create_stream "{\"name\":\"l4f-iv2-allow-udp\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7704,\"backend_ids\":[\"${udp_echo}\"],\"source_allow_cidrs\":[\"${L4F_L4}/32\"]}") \
        || fail "stream create refused: ${allow}"
    for i in "$tcp" "$udp" "$deny" "$allow"; do
        l4s_wait_bind "$i" bound 5 >/dev/null || fail "stream ${i} did not bind"
    done

    # The database reaches the workers through the settings reload; give
    # it a few seconds before judging.
    for i in $(seq 1 20); do
        got=$(l4f_outcomes "${L4F_GEO}>l4-node-geo:7701:1")
        [ "$got" = closed ] && break
        sleep 0.5
    done
    tcp_geo=$got
    tcp_l4=$(l4f_outcomes "${L4F_L4}>l4-node:7701:1")
    udp_geo=$(l4f_udp l4-node-geo:7702 "$L4F_GEO")
    udp_l4=$(l4f_udp l4-node:7702 "$L4F_L4")
    [ "$tcp_geo" = closed ] || fail "GeoIP deny US, TCP from ${L4F_GEO}: ${tcp_geo}"
    case "$tcp_l4" in "served name=tcp-backend-1") ;; *) fail "GeoIP deny US, TCP from ${L4F_L4}: ${tcp_l4}" ;; esac
    [ "$udp_geo" = false ] || fail "GeoIP deny US, the UDP query from ${L4F_GEO} was answered"
    [ "$udp_l4" = true ] || fail "GeoIP deny US, the UDP query from ${L4F_L4} was not answered"
    [ "$(l4c_wait_reason_count "$tcp" geoip 1)" -ge 1 ] || fail "the TCP refusal was not counted geoip"
    [ "$(l4c_wait_reason_count "$udp" geoip 1)" -ge 1 ] || fail "the UDP refusal was not counted geoip"
    for i in "$tcp" "$udp"; do
        n=0
        for _ in $(seq 1 25); do
            rows=$(l4f_log_rows "$i" geoip)
            n=${rows%% *}
            [ "${n:-0}" -ge 1 ] && break
            sleep 0.4
        done
        [ "${n:-0}" -ge 1 ] || fail "no geoip refusal row in the access log of stream ${i}"
    done

    local deny_geo deny_l4 allow_geo allow_l4
    deny_geo=$(l4f_outcomes "${L4F_GEO}>l4-node-geo:7703:1")
    deny_l4=$(l4f_outcomes "${L4F_L4}>l4-node:7703:1")
    allow_l4=$(l4f_udp l4-node:7704 "$L4F_L4")
    allow_geo=$(l4f_udp l4-node-geo:7704 "$L4F_GEO")
    [ "$deny_geo" = closed ] || fail "deny ${L4F_GEO}/32, TCP from it: ${deny_geo}"
    case "$deny_l4" in "served name=tcp-backend-1") ;; *) fail "deny ${L4F_GEO}/32, TCP from ${L4F_L4}: ${deny_l4}" ;; esac
    [ "$allow_l4" = true ] || fail "allow ${L4F_L4}/32, the UDP query from it was not answered"
    [ "$allow_geo" = false ] || fail "allow ${L4F_L4}/32, the UDP query from ${L4F_GEO} was answered"
    [ "$(l4c_wait_reason_count "$deny" source_denied 1)" -ge 1 ] || fail "the deny-list refusal was not counted source_denied"
    [ "$(l4c_wait_reason_count "$allow" source_denied 1)" -ge 1 ] || fail "the allowlist refusal was not counted source_denied"
    pass "GeoIP deny US: from ${L4F_GEO} TCP closed with no echo and UDP unanswered, from ${L4F_L4} (unknown country) TCP echoed and UDP answered, both counted geoip with access-log rows; IP lists: TCP deny ${L4F_GEO}/32 refused it and served ${L4F_L4}, UDP allow ${L4F_L4}/32 (no explicit session cap) served it and refused ${L4F_GEO}, both counted source_denied"
}

# ---- IV3 -------------------------------------------------------------

# The TLS echo backend in the client, with a self-signed certificate.
l4f_tls_backend_up() {
    l4_client sh -c "test -s /tmp/l4f-tls.crt || openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=${L4F_SNI} -days 2 -keyout /tmp/l4f-tls.key -out /tmp/l4f-tls.crt >/dev/null 2>&1" \
        || fail "could not make the TLS backend's certificate"
    l4s_client_daemon tcp "$L4F_TLS_PORT" python3 "$L4F_TOOL" tls-serve --port "$L4F_TLS_PORT" \
        --cert /tmp/l4f-tls.crt --key /tmp/l4f-tls.key
}

# IV3: a TLS passthrough stream with defaults (pending cap 256, a source's
# share 256 / PENDING_SOURCE_SHARE_DIVISOR = 32, ClientHello deadline
# 5 s). Step 1: 10,000 silent connections from the US address, 1,000 a
# second, while a TLS client from `l4` completes a fresh handshake every
# 250 ms: every handshake succeeds; the silent sockets the proxy holds
# (sampled every 100 ms, those open for a second or more) never pass
# the share, with the shard bound of the workers count minus one
# (docs/streams.md, "Caps"); the excess is refused at once and counted
# source_pending_cap, with its access-log row and suppressed counts.
# Step 2: eight more US addresses on the client; 40 silent connections
# from each of the nine at once fill the stream's 256: a TLS connection
# established before keeps echoing, new handshakes are refused
# (pending_cap) until the silent connections' 5 s deadline frees the
# slots, then served.
scenario_12_6_iv3_10k_silent_pending_cap() {
    local bid id share workers flood held_geo young old tls_n tls_ok refused log i addr
    # Global, not local: the trap runs when the driver's subshell exits,
    # after this function has returned.
    L4F_EXTRA=()
    trap 'l4s_cleanup_streams l4f-iv3-; for a in "${L4F_EXTRA[@]}"; do l4_compose exec -T -u root streams-client ip addr del "${a}/${L4F_GEO_PREFIX}" dev "${L4F_GEO_DEV}" >/dev/null 2>&1 || true; done; l4f_geo_detach' EXIT
    l4s_cleanup_streams l4f-iv3-
    l4f_addresses
    workers=$(l4f_workers)
    share=$(( 256 / 8 ))
    l4f_tls_backend_up
    bid=$(l4c_backend "${L4F_L4}:${L4F_TLS_PORT}" nocheck) || fail "backend: ${bid}"
    id=$(l4s_create_stream "{\"name\":\"l4f-iv3-tls\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7705,\"tls_mode\":\"passthrough\",\"match_rules\":[{\"name\":\"protect\",\"matcher\":{\"kind\":\"tls\",\"server_names\":[\"${L4F_SNI}\"]},\"backend_ids\":[\"${bid}\"]}]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the TLS stream did not bind"
    local view
    view=$(l4_api GET "/api/v1/streams/${id}" | l4_client jq -r '"\(.data.max_pending_connections) \(.data.max_connections)"' | tr -d '\r')
    [ "$view" = "256 1024" ] || fail "the stream's defaults are not max_pending_connections 256, max_connections 1024: ${view}"

    flood=$(l4f_tool pending-flood --target l4-node-geo:7705 --bind "$L4F_GEO" --tls-target l4-node:7705 \
        --tls-bind "$L4F_L4" --sni "$L4F_SNI" --count 10000 --rate 1000 --hold 6) || fail "the flood did not run: ${flood}"
    read -r held_geo young old tls_n tls_ok <<< "$(printf '%s' "$flood" | l4_client jq -r --arg g "$L4F_GEO" '"\(.max_held_per_source[$g] // 0) \(.closed_young) \(.closed_old) \(.tls_attempts) \(.tls_ok)"' | tr -d '\r')"
    [ "$(l4f_jq "$flood" '.opened + .connect_errors')" = 10000 ] || fail "the flood did not open 10,000 connections: ${flood}"
    [ "$(l4f_jq "$flood" .connect_errors)" = 0 ] || fail "silent connections failed to connect: ${flood}"
    [ "$tls_n" -ge 20 ] && [ "$tls_ok" = "$tls_n" ] || fail "TLS handshakes from ${L4F_L4} during the flood: ${tls_ok} of ${tls_n} completed ($(l4f_jq "$flood" '.tls_failures | tojson'))"
    [ "$held_geo" -le $(( share + workers - 1 )) ] || fail "${held_geo} silent connections from ${L4F_GEO} held at once, past the share ${share} (+$(( workers - 1 )))"
    [ "$held_geo" -ge $(( share - 2 )) ] || fail "only ${held_geo} silent connections held at once: the share ${share} was never reached"
    [ "$young" -ge 9000 ] && [ "$old" -ge "$share" ] || fail "silent connections closed at once ${young}, after a second or more ${old}: ${flood}"
    refused=$(l4c_wait_reason_count "$id" source_pending_cap 9000)
    [ "$refused" -ge 9000 ] || fail "${refused} refusals counted source_pending_cap for ${young} closed at once"
    log=$(l4f_wait_log_accounts "$id" source_pending_cap 25) || fail "the access log does not account for the source_pending_cap refusals (counter, rows, suppressed rows, suppressed): ${log}"
    set -- $log
    [ "$3" -ge 1 ] || fail "no refusals_suppressed row for source_pending_cap: ${log}"
    local step1="10,000 silent from ${L4F_GEO} at 1,000/s: at most ${held_geo} held at once (share ${share}, ${workers} workers), ${young} closed at once, ${old} at their ClientHello deadline; ${tls_ok} of ${tls_n} handshakes from ${L4F_L4} completed; ${refused} counted source_pending_cap, access log ${2} row(s) and ${3} suppressed row(s) counting ${4}"

    for i in $(seq 3 10); do
        addr=$(l4c_subnet_address "$L4_GEO_SUBNET" "-${i}")
        l4_compose exec -T -u root streams-client ip addr add "${addr}/${L4F_GEO_PREFIX}" dev "$L4F_GEO_DEV" \
            || fail "could not add ${addr} to the client's ${L4F_GEO_DEV}"
        L4F_EXTRA+=("$addr")
    done
    local sources fill total held_pings held_failures during after first_ok last_fail
    sources=$(IFS=,; echo "${L4F_GEO},${L4F_EXTRA[*]}")
    fill=$(l4f_tool pending-fill --target l4-node-geo:7705 --bind "$sources" --tls-target l4-node:7705 \
        --tls-bind "$L4F_L4" --sni "$L4F_SNI" --per-source 40 --settle 1.5 --duration 11) || fail "the fill did not run: ${fill}"
    read -r total held_pings held_failures <<< "$(l4f_jq "$fill" '"\(.max_held_total) \(.held_pings) \(.held_failures)"')"
    # Handshakes started after the fill and before the first silent
    # connection's 5 s deadline, and those started once every deadline
    # has passed (the fill takes under a second).
    read -r during after first_ok last_fail <<< "$(l4f_jq "$fill" '
        .fill_seconds as $f
        | [.tls_attempts[] | select(.[0] >= $f and .[0] < 4.5)] as $d
        | [.tls_attempts[] | select(.[0] >= 7)] as $a
        | "\([$d[] | select(.[1] == "ok")] | length)/\($d | length) \([$a[] | select(.[1] == "ok")] | length)/\($a | length) \([.tls_attempts[] | select(.[1] == "ok") | .[0]] | first // "none") \([.tls_attempts[] | select(.[1] != "ok") | .[0]] | last // "none")"')"
    [ "$total" -le 256 ] || fail "${total} silent connections held at once, past the pending cap of 256: ${fill}"
    [ "$total" -ge 240 ] || fail "nine sources of 40 held only ${total} at once: the pending cap was not filled: ${fill}"
    [ "$held_failures" = 0 ] && [ "$held_pings" -ge 15 ] || fail "the TLS connection established before the fill: ${held_pings} echoes, ${held_failures} failures ($(l4f_jq "$fill" .held_error))"
    case "$during" in 0/0|0/*) ;; *) fail "handshakes started while the cap was full: ${during} completed" ;; esac
    [ "${during#*/}" -ge 1 ] || fail "no handshake was tried while the cap was full: $(l4f_jq "$fill" '.tls_attempts | tojson')"
    case "$after" in 0/*|*/0) fail "handshakes after the silent connections' deadline: ${after} completed ($(l4f_jq "$fill" '.tls_attempts | tojson'))" ;; esac
    [ "${after%/*}" = "${after#*/}" ] || fail "handshakes after the silent connections' deadline: ${after} completed ($(l4f_jq "$fill" '.tls_attempts | tojson'))"
    [ "$(l4c_wait_reason_count "$id" pending_cap 1)" -ge 1 ] || fail "no refusal counted pending_cap while the cap was full"
    pass "${step1}. Nine sources x 40 silent: at most ${total} held at once (cap 256); a TLS connection established before echoed ${held_pings} times, 0 failures; new handshakes ${during} completed while full (pending_cap), last refused at ${last_fail} s, ${after} completed from 7 s"
}

# ---- Concurrency caps (D-e) -----------------------------------------

# Connection limit per source, per listener and per backend: a TCP
# stream with max_connections 5 and source_max_connections 3 serves three
# held connections from the US address and refuses its fourth
# (source_connection_cap), then two from `l4` and refuses its third (the
# stream's 5 reached: connection_cap); a stream over two backends capped
# at 1 and 2 (backend_max_active) serves three held connections, one on
# the first and two on the second, and refuses the fourth (backend_cap).
scenario_12_6_matrix_concurrency_caps() {
    local b1 b2 caps links got geo_out l4_out link_out
    trap 'l4s_cleanup_streams l4f-cap-; l4f_geo_detach' EXIT
    l4s_cleanup_streams l4f-cap-
    l4f_addresses
    b1=$(l4c_backend "$(l4c_ip tcp-backend-1):9000" nocheck) || fail "backend: ${b1}"
    b2=$(l4c_backend "$(l4c_ip tcp-backend-2):9000" nocheck) || fail "backend: ${b2}"
    caps=$(l4s_create_stream "{\"name\":\"l4f-cap-source\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7706,\"backend_ids\":[\"${b1}\"],\"max_connections\":5,\"source_max_connections\":3}") \
        || fail "stream create refused: ${caps}"
    links=$(l4s_create_stream "{\"name\":\"l4f-cap-links\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7707,\"backend_ids\":[\"${b1}\",\"${b2}\"],\"backend_max_active\":{\"${b1}\":1,\"${b2}\":2}}") \
        || fail "stream create refused: ${links}"
    for id in "$caps" "$links"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done

    got=$(l4f_outcomes "${L4F_GEO}>l4-node-geo:7706:4;${L4F_L4}>l4-node:7706:3")
    geo_out=$(printf '%s\n' "$got" | sed -n 1p)
    l4_out=$(printf '%s\n' "$got" | sed -n 2p)
    local s="served name=tcp-backend-1"
    [ "$geo_out" = "${s},${s},${s},closed" ] || fail "source cap 3, four held from ${L4F_GEO}: ${geo_out}"
    [ "$l4_out" = "${s},${s},closed" ] || fail "stream cap 5, three more held from ${L4F_L4}: ${l4_out}"
    [ "$(l4c_wait_reason_count "$caps" source_connection_cap 1)" = 1 ] || fail "the fourth from one source was not counted source_connection_cap once"
    [ "$(l4c_wait_reason_count "$caps" connection_cap 1)" = 1 ] || fail "the sixth on the stream was not counted connection_cap once"

    link_out=$(l4f_outcomes "${L4F_L4}>l4-node:7707:4")
    local tally
    tally=$(printf '%s' "$link_out" | tr ',' '\n' | sort | uniq -c | awk '{printf "%s=%s ", $NF, $1}')
    case "$link_out" in *,closed) ;; *) fail "backend caps 1 and 2, four held: ${link_out}" ;; esac
    [ "$tally" = "closed=1 name=tcp-backend-1=1 name=tcp-backend-2=2 " ] || fail "backend caps 1 and 2, four held: ${link_out}"
    [ "$(l4c_wait_reason_count "$links" backend_cap 1)" = 1 ] || fail "the fourth was not counted backend_cap once"
    pass "max_connections 5, source_max_connections 3: ${L4F_GEO} held 3, its 4th refused (source_connection_cap); ${L4F_L4} held 2, its 3rd refused (connection_cap); backend_max_active 1 and 2: held 1 on tcp-backend-1 and 2 on tcp-backend-2, the 4th refused (backend_cap)"
}
