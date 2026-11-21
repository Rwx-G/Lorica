# shellcheck shell=bash
# Story 12.5 scenarios in the `streams` profile (Story 12.12 Lot E, the
# items of Story 12.5 Lot I, IV2 on CoreDNS and dnsperf, and the UDP
# idle-timeout row of the parity matrix). Sourced by l4/run-l4.sh; the
# `l4s_*` and `l4c_*` helpers are 12.2.sh's and 12.3.sh's.
#
# Services: `udp-amplifier`, `udp-spoofer` and `udp-victim` run
# test-runner/l4/udp_tools.py; `coredns` and `coredns-2` serve the IV2
# zone (l4/coredns/iv2.test.zone); `dns-loadgen` runs dnsperf;
# `lorica-budget-16k` is the AC #6 node. Every stream listens on the
# node's own `l4` address (RFC 1918) unless the item says otherwise, so a
# stream at default settings passes the listen-address rule (D-k).

# The documented reflection bound at the 1.11.0 defaults, bytes per
# second towards one source key (docs/streams.md, "The reflection
# bound"), and the request size the flood sends.
L4E_BOUND=8192000
L4E_REQUEST_BYTES=60
L4E_FLOOD_SECONDS=30

l4e_tool() {
    local service="$1"
    shift
    l4_compose exec -T "$service" python3 /tests/l4/udp_tools.py "$@" | tr -d '\r'
}

# Wait until <file> exists in <service> and print it; return 1 after
# <seconds>.
l4e_wait_file() {
    local service="$1" file="$2" seconds="$3" i out
    for i in $(seq 1 "$seconds"); do
        if out=$(l4_compose exec -T "$service" cat "$file" 2>/dev/null); then
            printf '%s' "$out" | tr -d '\r'
            return 0
        fi
        sleep 1
    done
    return 1
}

# One stream's live counters on the node, `{}` while it has none.
l4e_counters() {
    l4s_client_script '
        api GET /api/v1/streams/status | jq -c --arg id "$1" \
            "[.data.streams[] | select(.id == \$id) | .counters // {}][0] // {}"
    ' "$1" | tr -d '\r'
}

# A stream's live session total on the node (`active`), 0 while it has
# none.
l4e_active() {
    l4s_client_script '
        api GET /api/v1/streams/status | jq -r --arg id "$1" \
            "[.data.streams[] | select(.id == \$id) | .counters.active // 0][0] // 0"
    ' "$1" | tr -d '\r'
}

# jq, run in the client: the host has none.
l4e_jq() {
    l4_client jq "$@" | tr -d '\r'
}

# The count of <reason> under <field> (refused, ended, datagrams_dropped)
# of a counters object.
l4e_count() {
    printf '%s' "$1" | l4e_jq -r --arg f "$2" --arg r "$3" '[(.[$f] // [])[] | select(.reason == $r) | .count] | add // 0'
}

# `reason=count ...` of one field of a counters object, `-` when empty.
l4e_reasons() {
    local out
    out=$(printf '%s' "$1" | l4e_jq -r --arg f "$2" '[(.[$f] // [])[] | "\(.reason)=\(.count)"] | join(" ")')
    echo "${out:--}"
}

# Counters read every second until they have not moved for 7 s: in
# worker mode the workers' counters reach the API with the supervisor's
# heartbeat round, every 5 s, and a session ends a moment after its last
# datagram. At most 40 s.
l4e_settled_counters() {
    local id="$1" last now i same=0
    last=$(l4e_counters "$id")
    for i in $(seq 1 40); do
        sleep 1
        now=$(l4e_counters "$id")
        if [ "$now" = "$last" ]; then
            same=$(( same + 1 ))
            [ "$same" -ge 7 ] && break
        else
            same=0
            last="$now"
        fi
    done
    echo "$last"
}

l4e_create_udp_stream() {
    l4s_create_stream "$1"
}

# The flood of IV1 and of the byte bound against <port> of the node:
# the victim records first, the legitimate client (unless `noclient`)
# sends one request every 100 ms, the spoofer forges the victim's
# address from random ports at 20,000 datagrams per second for 30 s.
# Sets L4E_VICTIM, L4E_SPOOF, L4E_CLIENT (JSON lines); returns 1 with
# L4E_ERR set when a tool did not report.
l4e_flood() {
    local tag="$1" port="$2" with_client="${3:-client}" node_ip victim_ip i
    node_ip=$(l4c_ip l4-node)
    victim_ip=$(l4c_ip udp-victim)
    L4E_CLIENT='{}'
    l4_compose exec -T udp-victim rm -f "/tmp/${tag}.ready" "/tmp/${tag}.json"
    l4_compose exec -d udp-victim python3 /tests/l4/udp_tools.py victim --from "$node_ip" \
        --duration $(( L4E_FLOOD_SECONDS + 8 )) --ready "/tmp/${tag}.ready" --out "/tmp/${tag}.json"
    l4e_wait_file udp-victim "/tmp/${tag}.ready" 20 >/dev/null || { L4E_ERR="the victim did not start"; return 1; }
    if [ "$with_client" = client ]; then
        l4_client rm -f "/tmp/${tag}-client.json"
        l4_compose exec -d streams-client python3 /tests/l4/udp_tools.py client --target "${node_ip}:${port}" \
            --interval 0.1 --duration "$L4E_FLOOD_SECONDS" --size "$L4E_REQUEST_BYTES" --out "/tmp/${tag}-client.json"
    fi
    L4E_SPOOF=$(l4e_tool udp-spoofer spoof --target "${node_ip}:${port}" --source "$victim_ip" \
        --rate 20000 --duration "$L4E_FLOOD_SECONDS" --size "$L4E_REQUEST_BYTES") \
        || { L4E_ERR="the spoofer failed: ${L4E_SPOOF}"; return 1; }
    L4E_VICTIM=$(l4e_wait_file udp-victim "/tmp/${tag}.json" 30) || { L4E_ERR="the victim did not report"; return 1; }
    if [ "$with_client" = client ]; then
        L4E_CLIENT=$(l4e_wait_file streams-client "/tmp/${tag}-client.json" 30) \
            || { L4E_ERR="the legitimate client did not report"; return 1; }
    fi
    return 0
}

# ---- IV1 -------------------------------------------------------------

# IV1: a UDP stream at default settings in front of an amplifier that
# answers every request with 10 datagrams of 1,800 bytes; the spoofer
# forges the victim's address at 20,000 datagrams per second for 30 s; a
# legitimate client on another address sends one request every 100 ms.
# The reflected rate at the victim stays under the documented bound B
# (30 s mean), every second under 2 B (bound plus burst); the victim
# receives at most 32 times the request bytes Lorica accepted from its
# key and at most one datagram per accepted request; the per-source
# datagram rate dropped the excess; the legitimate client got every
# answer.
scenario_12_5_iv1_reflection_bounded() {
    local amp id c vbytes vgrams vmax mean upload cbytes accepted_bytes accepted_reqs rate_drops count_drops forwarded to_victim
    trap 'l4s_cleanup_streams l4e-iv1-' EXIT
    l4s_cleanup_streams l4e-iv1-
    amp=$(l4c_backend "$(l4c_ip udp-amplifier):9200" nocheck) || fail "backend: ${amp}"
    id=$(l4e_create_udp_stream "{\"name\":\"l4e-iv1-reflect\",\"protocol\":\"udp\",\"listen_address\":\"$(l4c_ip l4-node)\",\"port_first\":7700,\"backend_ids\":[\"${amp}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the UDP stream did not bind"

    l4e_flood l4e-iv1 7700 || fail "$L4E_ERR"
    c=$(l4e_settled_counters "$id")

    vbytes=$(printf '%s' "$L4E_VICTIM" | l4e_jq -r .bytes)
    vgrams=$(printf '%s' "$L4E_VICTIM" | l4e_jq -r .datagrams)
    vmax=$(printf '%s' "$L4E_VICTIM" | l4e_jq -r .max_window_bytes)
    mean=$(( vbytes / L4E_FLOOD_SECONDS ))
    upload=$(printf '%s' "$c" | l4e_jq -r '.bytes_upload_total // 0')
    cbytes=$(printf '%s' "$L4E_CLIENT" | l4e_jq -r .bytes_sent)
    accepted_bytes=$(( upload - cbytes ))
    accepted_reqs=$(( accepted_bytes / L4E_REQUEST_BYTES ))
    rate_drops=$(l4e_count "$c" datagrams_dropped source_datagram_rate)
    count_drops=$(l4e_count "$c" datagrams_dropped response_count_bound)
    # The node's own count of what it reflected: every response forwarded
    # is one 1,800-byte datagram, the legitimate client's answers included.
    forwarded=$(( $(printf '%s' "$c" | l4e_jq -r '.bytes_download_total // 0') / 1800 ))
    to_victim=$(( forwarded - $(printf '%s' "$L4E_CLIENT" | l4e_jq -r '.answered // 0') ))
    local diag="node forwarded ${to_victim} responses to the victim's key; counters ${c}; client ${L4E_CLIENT}; victim ${L4E_VICTIM}"

    # The client first: the per-key figures below take its requests out
    # of the stream's upload total, which is exact only when every one of
    # them reached the backend.
    [ "$(printf '%s' "$L4E_CLIENT" | l4e_jq -r '.answered == .sent and .sent > 0')" = true ] \
        || fail "the legitimate client was not answered every time; ${diag}"
    [ "$vgrams" -gt 0 ] || fail "nothing reached the victim: the flood was not reflected at all, the check proves nothing (spoofer ${L4E_SPOOF}, counters ${c})"
    [ "$mean" -le "$L4E_BOUND" ] || fail "the victim received ${mean} bytes/s over ${L4E_FLOOD_SECONDS} s, above the bound ${L4E_BOUND}"
    [ "$vmax" -le $(( 2 * L4E_BOUND )) ] || fail "one second at the victim carried ${vmax} bytes, above 2 x ${L4E_BOUND}"
    [ "$vbytes" -le $(( 32 * accepted_bytes )) ] \
        || fail "the victim received ${vbytes} bytes for ${accepted_bytes} request bytes accepted from its key (ratio 32)"
    [ "$vgrams" -le "$accepted_reqs" ] \
        || fail "the victim received ${vgrams} datagrams for ${accepted_reqs} requests accepted from its key; ${diag}"
    [ "$rate_drops" -gt 0 ] || fail "no source_datagram_rate drop under a 20,000/s flood from one key: $(l4e_reasons "$c" datagrams_dropped)"
    pass "spoofer $(printf '%s' "$L4E_SPOOF" | l4e_jq -r '"\(.sent) datagrams at \(.rate)/s"'); victim ${vgrams} datagrams, ${vbytes} bytes: mean ${mean} B/s (bound ${L4E_BOUND}), worst second ${vmax} B; ${accepted_reqs} requests (${accepted_bytes} B) accepted from its key, so <= 1 response each and <= 32x the bytes; drops $(l4e_reasons "$c" datagrams_dropped) (response_count_bound ${count_drops}: a session ends on its owed response, the other 9 never reach one); legitimate client $(printf '%s' "$L4E_CLIENT" | l4e_jq -r '"\(.answered)/\(.sent)"') answered"
}

# ---- Byte bound ------------------------------------------------------

# The same flood against a backend answering one datagram of 4,000
# bytes: every response is past the 1,920 bytes a 60-byte request earns,
# so the victim receives nothing and the drops are response_byte_bound.
scenario_12_5_ac2_byte_bound() {
    local amp id c vgrams byte_drops forwarded
    trap 'l4s_cleanup_streams l4e-bb-' EXIT
    l4s_cleanup_streams l4e-bb-
    amp=$(l4c_backend "$(l4c_ip udp-amplifier):9201" nocheck) || fail "backend: ${amp}"
    id=$(l4e_create_udp_stream "{\"name\":\"l4e-bb-bytes\",\"protocol\":\"udp\",\"listen_address\":\"$(l4c_ip l4-node)\",\"port_first\":7701,\"backend_ids\":[\"${amp}\"]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the UDP stream did not bind"

    l4e_flood l4e-bb 7701 noclient || fail "$L4E_ERR"
    c=$(l4e_settled_counters "$id")
    vgrams=$(printf '%s' "$L4E_VICTIM" | l4e_jq -r .datagrams)
    byte_drops=$(l4e_count "$c" datagrams_dropped response_byte_bound)
    forwarded=$(printf '%s' "$c" | l4e_jq -r '.bytes_download_total // 0')
    [ "$vgrams" -eq 0 ] || fail "the victim received ${vgrams} datagrams of 4,000-byte answers"
    [ "$forwarded" -eq 0 ] || fail "the stream forwarded ${forwarded} response bytes"
    [ "$byte_drops" -gt 0 ] || fail "no response_byte_bound drop: $(l4e_reasons "$c" datagrams_dropped)"
    pass "spoofer $(printf '%s' "$L4E_SPOOF" | l4e_jq -r .sent) datagrams; victim received nothing, 0 response bytes forwarded; drops $(l4e_reasons "$c" datagrams_dropped); ends $(l4e_reasons "$c" ended)"
}

# ---- AC #5, table isolation ------------------------------------------

# AC #5: the spoofer floods stream A from random source addresses (a
# benchmark range, RFC 2544), so every datagram is a new source and A's
# rate table fills; A's backend answers past the byte bound, so nothing
# is ever sent to those addresses. Stream B, on the same node, keeps
# serving a client throughout, and A's refusals are session_table_full
# only.
scenario_12_5_ac5_table_isolation() {
    local amp echo a b node_ip ca cb client full other spoof
    trap 'l4s_cleanup_streams l4e-ti-' EXIT
    l4s_cleanup_streams l4e-ti-
    l4s_echo_backends
    node_ip=$(l4c_ip l4-node)
    amp=$(l4c_backend "$(l4c_ip udp-amplifier):9201" nocheck) || fail "backend: ${amp}"
    echo=$(l4c_backend "$(l4s_client_ip):${L4S_UDP_ECHO_PORT}" nocheck) || fail "backend: ${echo}"
    a=$(l4e_create_udp_stream "{\"name\":\"l4e-ti-a\",\"protocol\":\"udp\",\"listen_address\":\"${node_ip}\",\"port_first\":7702,\"backend_ids\":[\"${amp}\"]}") \
        || fail "stream A create refused: ${a}"
    b=$(l4e_create_udp_stream "{\"name\":\"l4e-ti-b\",\"protocol\":\"udp\",\"listen_address\":\"${node_ip}\",\"port_first\":7703,\"backend_ids\":[\"${echo}\"]}") \
        || fail "stream B create refused: ${b}"
    for id in "$a" "$b"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done

    l4_client rm -f /tmp/l4e-ti-client.json
    l4_compose exec -d streams-client python3 /tests/l4/udp_tools.py client --target "${node_ip}:7703" \
        --interval 0.1 --duration 15 --out /tmp/l4e-ti-client.json
    spoof=$(l4e_tool udp-spoofer spoof --target "${node_ip}:7702" --random-sources 198.18.0.0/15 \
        --rate 20000 --duration 15) || fail "the spoofer failed: ${spoof}"
    client=$(l4e_wait_file streams-client /tmp/l4e-ti-client.json 30) || fail "the client of stream B did not report"
    ca=$(l4e_settled_counters "$a")
    cb=$(l4e_settled_counters "$b")

    full=$(l4e_count "$ca" refused session_table_full)
    other=$(printf '%s' "$ca" | l4e_jq -r '[(.refused // [])[] | select(.reason != "session_table_full")] | length')
    [ "$full" -gt 0 ] || fail "stream A refused nothing as session_table_full: refused $(l4e_reasons "$ca" refused), accepted $(printf '%s' "$ca" | l4e_jq -r '.accepted_total // 0')"
    [ "$other" -eq 0 ] || fail "stream A refused for other reasons too: $(l4e_reasons "$ca" refused)"
    [ "$(printf '%s' "$client" | l4e_jq -r '.answered == .sent and .sent > 0')" = true ] \
        || fail "stream B's client was not answered every time during the flood: ${client}"
    [ "$(l4e_reasons "$cb" refused)" = - ] || fail "stream B refused sessions: $(l4e_reasons "$cb" refused)"
    pass "stream A: $(printf '%s' "$spoof" | l4e_jq -r .sent) datagrams from random sources, $(printf '%s' "$ca" | l4e_jq -r '.accepted_total // 0') sessions accepted, refused $(l4e_reasons "$ca" refused) and nothing else; stream B: client $(printf '%s' "$client" | l4e_jq -r '"\(.answered)/\(.sent)"') answered, no refusal"
}

# ---- IV2 -------------------------------------------------------------

# Writes the query file in the load generator and runs dnsperf through
# the node: l4e_dnsperf <port> <seconds> [detach-tag]. Foreground, prints
# dnsperf's output; with a tag, runs detached, its output in
# /tmp/<tag>.out and /tmp/<tag>.done once it ended.
L4E_DNSPERF_SCRIPT='
target=$1 port=$2 seconds=$3 out=${4:-}
printf "a.iv2.test A\nb.iv2.test A\nc.iv2.test A\nd.iv2.test A\ntxt.iv2.test TXT\n" > /tmp/l4e-queries
run() {
    dnsperf -s "$target" -p "$port" -d /tmp/l4e-queries -l "$seconds" -Q 820 -c 64 -t 2 -q 256
}
if [ -n "$out" ]; then
    rm -f "/tmp/$out.out" "/tmp/$out.done"
    run > "/tmp/$out.out" 2>&1
    touch "/tmp/$out.done"
else
    run 2>&1
fi
'

l4e_dnsperf() {
    l4_compose exec -T dns-loadgen bash -c "$L4E_DNSPERF_SCRIPT" l4e "$(l4c_ip l4-node)" "$@" | tr -d '\r'
}

l4e_dnsperf_detached() {
    l4_compose exec -d dns-loadgen bash -c "$L4E_DNSPERF_SCRIPT" l4e "$(l4c_ip l4-node)" "$@"
}

# `sent completed lost noerror` from dnsperf's report.
l4e_dnsperf_tally() {
    printf '%s\n' "$1" | awk '
        /Queries sent:/ { s = $3 }
        /Queries completed:/ { c = $3 }
        /Queries lost:/ { l = $3 }
        /Response codes:/ { for (i = 3; i <= NF; i++) if ($i ~ /^NOERROR/) n = $(i + 1) }
        END { printf "%s %s %s %s\n", s + 0, c + 0, l + 0, n + 0 }'
}

# A DNS stream in front of both resolvers, at default settings.
l4e_dns_stream() {
    local name="$1" port="$2" r1 r2
    r1=$(l4c_backend "${L4_DNS_IP}:53" nocheck) || { echo "backend: ${r1}"; return 1; }
    r2=$(l4c_backend "$(l4c_ip coredns-2):53" nocheck) || { echo "backend: ${r2}"; return 1; }
    l4e_create_udp_stream "{\"name\":\"${name}\",\"protocol\":\"udp\",\"listen_address\":\"$(l4c_ip l4-node)\",\"port_first\":${port},\"backend_ids\":[\"${r1}\",\"${r2}\"]}"
}

# IV2: two resolvers behind a UDP stream at default settings; dnsperf at
# twice the capacity formula (2 x 4,096 / 10 = 820 queries per second)
# for 60 s across 64 source ports from one address. Every query answered
# within 2 s, no refusal, no drop, no idle_timeout end, every end
# response_bound_reached or request_bound_reached, and the session gauge
# far below max_sessions.
scenario_12_5_iv2_dns_above_capacity_all_answered() {
    local id out tally sent completed lost noerror c peak=0 active i ends other_ends accepted ended
    trap 'l4s_cleanup_streams l4e-iv2-' EXIT
    l4s_cleanup_streams l4e-iv2-
    id=$(l4e_dns_stream l4e-iv2-dns 7704) || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the DNS stream did not bind"

    l4e_dnsperf_detached 7704 60 l4e-iv2
    # The session gauge, sampled while the load runs (the node's exact
    # region total, refreshed every second).
    for i in $(seq 1 12); do
        sleep 5
        active=$(l4e_active "$id")
        [ "$active" -gt "$peak" ] && peak=$active
    done
    l4e_wait_file dns-loadgen /tmp/l4e-iv2.done 60 >/dev/null || fail "dnsperf did not finish"
    out=$(l4_compose exec -T dns-loadgen cat /tmp/l4e-iv2.out | tr -d '\r')
    read -r sent completed lost noerror <<< "$(l4e_dnsperf_tally "$out")"
    c=$(l4e_settled_counters "$id")

    [ "$sent" -ge $(( 820 * 60 * 95 / 100 )) ] || fail "dnsperf sent ${sent} queries, not about 820/s for 60 s: ${out//$'\n'/ }"
    [ "$lost" -eq 0 ] && [ "$completed" -eq "$sent" ] || fail "queries lost or unanswered within 2 s: sent ${sent}, completed ${completed}, lost ${lost}"
    [ "$noerror" -eq "$completed" ] || fail "not every answer was NOERROR: ${noerror} of ${completed}"
    [ "$(l4e_reasons "$c" refused)" = - ] || fail "refusals: $(l4e_reasons "$c" refused)"
    [ "$(l4e_reasons "$c" datagrams_dropped)" = - ] || fail "drops: $(l4e_reasons "$c" datagrams_dropped)"
    other_ends=$(printf '%s' "$c" | l4e_jq -r '[(.ended // [])[] | select(.reason != "response_bound_reached" and .reason != "request_bound_reached") | "\(.reason)=\(.count)"] | join(" ")')
    [ -z "$other_ends" ] || fail "sessions ended otherwise than on their bounds: ${other_ends}"
    accepted=$(printf '%s' "$c" | l4e_jq -r '.accepted_total // 0')
    ended=$(printf '%s' "$c" | l4e_jq -r '[(.ended // [])[] | .count] | add // 0')
    [ "$ended" -eq "$accepted" ] || fail "${accepted} sessions accepted, ${ended} ended"
    [ "$peak" -lt 410 ] || fail "the session gauge reached ${peak}, not far below max_sessions 4,096"
    ends=$(l4e_reasons "$c" ended)
    pass "dnsperf ${sent} queries in 60 s over 64 ports, ${completed} answered within 2 s (${noerror} NOERROR), 0 lost; no refusal, no drop; ${accepted} sessions, ends ${ends}; session gauge peaked at ${peak} of 4,096"
}

# ---- Reply source ----------------------------------------------------

# A stream on 0.0.0.0 (an explicit source_session_cap, as the
# listen-address rule asks of a wildcard); a client sends to a second
# address of the node and receives the reply from that address, and
# from the first when it sends to the first.
L4E_REPLY_FROM='import socket, sys
port = int(sys.argv[1])
out = []
for addr in sys.argv[2:]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(b"which address", (addr, port))
    data, peer = s.recvfrom(2048)
    out.append(f"{addr}->{peer[0]}")
print(" ".join(out))
'

scenario_12_5_x_reply_source_address() {
    local node_ip dev prefix second echo id seen
    node_ip=$(l4c_ip l4-node)
    read -r dev prefix <<< "$(l4c_l4_interface "$node_ip")"
    [ -n "$dev" ] || fail "no interface of the node carries ${node_ip}"
    second=$(l4c_subnet_address "${node_ip}/${prefix}" -7)
    trap 'l4s_cleanup_streams l4e-rs-; l4s_probe ip addr del "'"${second}/${prefix}"'" dev "'"${dev}"'" >/dev/null 2>&1 || true' EXIT
    l4s_cleanup_streams l4e-rs-
    l4s_probe ip addr add "${second}/${prefix}" dev "$dev" || fail "could not add ${second} to ${dev}"
    l4s_echo_backends
    echo=$(l4c_backend "$(l4s_client_ip):${L4S_UDP_ECHO_PORT}" nocheck) || fail "backend: ${echo}"
    id=$(l4e_create_udp_stream "{\"name\":\"l4e-rs-wildcard\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7709,\"backend_ids\":[\"${echo}\"],\"udp\":{\"source_session_cap\":16}}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the wildcard stream did not bind"
    seen=$(l4_client python3 -c "$L4E_REPLY_FROM" 7709 "$second" "$node_ip" 2>&1 | tr -d '\r') || fail "no reply: ${seen}"
    [ "$seen" = "${second}->${second} ${node_ip}->${node_ip}" ] || fail "replies did not leave from the address targeted: ${seen}"
    pass "on 0.0.0.0:7709, sent to ${second} (a second address of the node): reply from ${second}; sent to ${node_ip}: reply from ${node_ip}"
}

# ---- Worker death ----------------------------------------------------

# Opens <n> sessions on <port> of the node, one datagram from each of
# <n> sockets, and closes the sockets (a session lives in the proxy).
L4E_OPEN_SESSIONS='import socket, sys
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
socks = []
for _ in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"held", (host, port))
    socks.append(s)
print(len(socks))
'

# The node's live sessions towards <backend port>: one connected
# upstream socket each, read in the node's namespace.
l4e_upstream_sockets() {
    l4s_probe ss -uanH "dport = :$1" | tr -d '\r' | grep -c . || true
}

# Worker death: under IV2's load, one worker is killed with SIGKILL. The
# node's session total of a stream holding 200 sessions (no response
# expected, a long idle timeout) returns to exactly the sessions still
# alive, the upstream sockets of the surviving worker, so the dead
# worker's share leaked nothing; the DNS stream's total returns to 0
# once the load ends; the respawned worker serves its slot's clients (a
# second load over 64 source ports, every query answered).
scenario_12_5_x_worker_death_no_leaked_count() {
    local sent completed lost noerror held_port=9110 dns held echo i before_api before_ss victim pids after_pids after_api after_ss out tally dns_active again
    trap 'l4s_cleanup_streams l4e-wd-' EXIT
    l4s_cleanup_streams l4e-wd-
    l4s_client_daemon udp "$held_port" python3 /tests/l4/udp_hold.py serve --port "$held_port"
    echo=$(l4c_backend "$(l4s_client_ip):${held_port}" nocheck) || fail "backend: ${echo}"
    held=$(l4e_create_udp_stream "{\"name\":\"l4e-wd-held\",\"protocol\":\"udp\",\"listen_address\":\"$(l4c_ip l4-node)\",\"port_first\":7706,\"backend_ids\":[\"${echo}\"],\"idle_timeout_s\":300,\"udp\":{\"responses_per_request\":0}}") \
        || fail "held stream create refused: ${held}"
    dns=$(l4e_dns_stream l4e-wd-dns 7705) || fail "DNS stream create refused: ${dns}"
    for id in "$held" "$dns"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done

    l4_client python3 -c "$L4E_OPEN_SESSIONS" "$(l4c_ip l4-node)" 7706 200 >/dev/null || fail "could not open the held sessions"
    for i in $(seq 1 20); do
        before_api=$(l4e_active "$held")
        before_ss=$(l4e_upstream_sockets "$held_port")
        [ "$before_api" = 200 ] && [ "$before_ss" = 200 ] && break
        sleep 0.5
    done
    [ "$before_api" = 200 ] && [ "$before_ss" = 200 ] \
        || fail "200 sessions not held before the kill: total ${before_api}, upstream sockets ${before_ss}"

    l4e_dnsperf_detached 7705 30 l4e-wd
    sleep 8
    pids=$(l4s_worker_pids)
    victim=${pids%% *}
    [ -n "$victim" ] || fail "no worker to kill"
    l4s_probe kill -9 "$victim"
    for i in $(seq 1 400); do
        after_pids=$(l4s_worker_pids)
        case " ${after_pids} " in *" ${victim} "*) ;; *) [ "$(echo "$after_pids" | wc -w)" -eq 2 ] && break ;; esac
        sleep 0.1
    done
    [ "$(echo "$after_pids" | wc -w)" -eq 2 ] || fail "worker ${victim} was not respawned within 40 s (workers ${after_pids})"

    for i in $(seq 1 30); do
        after_api=$(l4e_active "$held")
        after_ss=$(l4e_upstream_sockets "$held_port")
        [ "$after_api" = "$after_ss" ] && break
        sleep 0.5
    done
    [ "$after_ss" -lt 200 ] || fail "the killed worker held none of the 200 sessions: the check proves nothing"
    [ "$after_api" = "$after_ss" ] \
        || fail "the node counts ${after_api} sessions of the held stream, ${after_ss} are alive: the dead worker's share leaked"

    l4e_wait_file dns-loadgen /tmp/l4e-wd.done 60 >/dev/null || fail "dnsperf under the kill did not finish"
    out=$(l4_compose exec -T dns-loadgen cat /tmp/l4e-wd.out | tr -d '\r')
    tally=$(l4e_dnsperf_tally "$out")
    for i in $(seq 1 30); do
        dns_active=$(l4e_active "$dns")
        [ "$dns_active" = 0 ] && break
        sleep 0.5
    done
    [ "$dns_active" = 0 ] || fail "the DNS stream still counts ${dns_active} sessions after its load ended"

    again=$(l4e_dnsperf 7705 10)
    read -r sent completed lost noerror <<< "$(l4e_dnsperf_tally "$again")"
    [ "$sent" -gt 0 ] && [ "$lost" -eq 0 ] && [ "$completed" -eq "$sent" ] \
        || fail "after the respawn, queries over 64 ports were lost: sent ${sent}, completed ${completed}, lost ${lost}"
    pass "killed worker ${victim} under 820 q/s (sent completed lost noerror: ${tally}); the held stream's total went from 200 to ${after_api}, equal to the ${after_ss} sessions still alive; the DNS stream's total back to 0; after the respawn ${completed}/${sent} queries over 64 ports answered, 0 lost"
}

# ---- AC #6, the budget -----------------------------------------------

# AC #6: on a node at fd limit 16,384 (stream budget 7,168, two
# workers), one default UDP stream fits (one listening socket plus 4,096
# sessions in one worker) and a second one is refused naming worker_fds
# and the numbers (2 + 2 x 4,096 = 8,194 against 7,168).
scenario_12_5_ac6_budget_refuses_second_stream() {
    local node=lorica-budget-16k node_ip budget first second
    l4s_wait_ready "$node"
    L4S_API_SCRIPT=$(l4s_node_api_script "$node")
    budget=$(l4s_client_script 'api GET /api/v1/streams/budget | jq -c ".data.nodes[0] | {fd_limit, stream_budget, worker_count}"' | tr -d '\r')
    [ "$budget" = '{"fd_limit":16384,"stream_budget":7168,"worker_count":2}' ] \
        || fail "unexpected budget on ${node}: ${budget}"
    node_ip=$(l4c_ip "$node")
    first=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | head -n 1' \
        "{\"name\":\"l4e-ac6-first\",\"protocol\":\"udp\",\"listen_address\":\"${node_ip}\",\"port_first\":7707}" | tr -d '\r')
    [ "$first" = 2xx ] || fail "the first default UDP stream was refused: ${first}"
    second=$(l4s_client_script 'api_try POST /api/v1/streams "$1" | tr "\n" " "' \
        "{\"name\":\"l4e-ac6-second\",\"protocol\":\"udp\",\"listen_address\":\"${node_ip}\",\"port_first\":7708}" | tr -d '\r')
    case "$second" in
        422\ *stream_fd_budget*worker_fds*8194\ committed*7168*) ;;
        *) fail "the second default UDP stream was not refused on worker_fds with 8194 against 7168: ${second}" ;;
    esac
    pass "fd limit 16384, S 7168, 2 workers: the first default UDP stream accepted; the second refused: $(printf '%s' "${second#* }" | l4e_jq -r .error.message)"
}

# ---- Parity matrix: the UDP idle timeout -----------------------------

# A UDP session with unbounded responses and idle_timeout_s 2: a
# datagram 1.5 s into the session keeps it (no second session), and it
# ends `idle_timeout` about 2 s after its last datagram. Timed in the
# probe, in the node's namespace: it is the session's client (its
# datagrams leave from the node's own address) and watches the session's
# upstream socket to the echo backend close. The stream counters are no
# clock: in worker mode they reach the API with the workers' next push.
# Prints `<seconds from the last echo to the close>`.
L4E_IDLE_PROBE='import socket, subprocess, sys, time
target, port, backend_port = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def upstream():
    out = subprocess.run(["ss", "-uanH", f"dport = :{backend_port}"],
                         capture_output=True, text=True).stdout
    return len([l for l in out.splitlines() if l.strip()])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((target, port))
for delay in (0, 1.5):
    time.sleep(delay)
    s.send(b"idle")
    s.recv(64)
last = time.monotonic()
if upstream() != 1:
    print(f"expected one upstream socket after the echo, saw {upstream()}")
    sys.exit(1)
while upstream():
    if time.monotonic() - last > 10:
        print("the session outlived 10 s")
        sys.exit(1)
    time.sleep(0.01)
print(f"{time.monotonic() - last:.3f}")
'

scenario_12_5_matrix_udp_idle_timeout() {
    local echo_port=9111 node_ip echo id elapsed c i idle accepted
    trap 'l4s_cleanup_streams l4e-it-' EXIT
    l4s_cleanup_streams l4e-it-
    l4s_client_daemon udp "$echo_port" python3 /tests/l4/udp_hold.py serve --port "$echo_port"
    node_ip=$(l4c_ip l4-node)
    echo=$(l4c_backend "$(l4s_client_ip):${echo_port}" nocheck) || fail "backend: ${echo}"
    id=$(l4e_create_udp_stream "{\"name\":\"l4e-it-idle\",\"protocol\":\"udp\",\"listen_address\":\"${node_ip}\",\"port_first\":7710,\"backend_ids\":[\"${echo}\"],\"idle_timeout_s\":2,\"udp\":{\"unbounded_responses\":true}}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the UDP stream did not bind"
    elapsed=$(l4s_probe python3 -c "$L4E_IDLE_PROBE" "$node_ip" 7710 "$echo_port" | tr -d '\r') || fail "${elapsed}"
    for i in $(seq 1 20); do
        c=$(l4e_counters "$id")
        idle=$(l4e_count "$c" ended idle_timeout)
        [ "$idle" -ge 1 ] && break
        sleep 0.5
    done
    accepted=$(printf '%s' "$c" | l4e_jq -r '.accepted_total // 0')
    [ "$idle" = 1 ] || fail "idle_timeout counted ${idle}, expected 1 (ends $(l4e_reasons "$c" ended))"
    [ "$accepted" = 1 ] || fail "the datagram at 1.5 s did not keep the session: ${accepted} sessions accepted"
    l4s_less_than 1.9 "$elapsed" && l4s_less_than "$elapsed" 2.5 \
        || fail "the session ended ${elapsed} s after its last datagram, not about 2 s"
    pass "one session kept alive by a datagram at 1.5 s, closed ${elapsed} s after its last datagram (idle_timeout_s 2), counted idle_timeout; ends $(l4e_reasons "$c" ended)"
}
