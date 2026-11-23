# shellcheck shell=bash
# Story 12.4 scenarios in the `streams` profile (Story 12.12 Lot D: IV1
# with its ALPN-routed name, the two-CA proof of AC #5, upstream mTLS of
# AC #4). IV2 runs in the `acme` profile's smoke and the key-replication
# check in the `cluster` profile's smoke. Sourced by l4/run-l4.sh;
# the shared `l4s_*` helpers are l4/lib.sh's.
#
# Backends: test-runner/l4/tls_backend.py (`tls-raw-1`, `tls-raw-2`
# behind passthrough, `tls-backend` behind upstream TLS) and Lot C's
# `tcp-backend-1` behind termination. The PKI is generated in the client
# with openssl at the first scenario that needs it.

# The test PKI, in the client's /tmp/l4d-pki: two client CAs (`ca-a`,
# `ca-b`) and a client certificate under each, a server certificate for
# the terminating streams (a/b/tls.l4d.test, under `ca-server`), the TLS
# backend's certificate (tls-backend.l4d.test, under `ca-up`) and the
# identity Lorica presents to it (lorica-upstream, under `ca-upclient`).
# /tmp/l4d-tls-backend holds what the TLS backend loads.
L4D_PKI_SCRIPT='
set -eu
d=/tmp/l4d-pki
[ -e "$d/done" ] && exit 0
mkdir -p "$d" /tmp/l4d-tls-backend
cd "$d"
ca() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=$1" -keyout "$1.key" -out "$1.crt" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}
leaf() {
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
        -keyout "$1.key" -out "$1.csr" 2>/dev/null
    printf "subjectAltName=%s\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n" "$3" "$4" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 30 \
        -extfile "$1.ext" -out "$1.crt" 2>/dev/null
}
for c in ca-a ca-b ca-server ca-up ca-upclient; do ca "$c"; done
leaf server ca-server "DNS:a.l4d.test,DNS:b.l4d.test,DNS:tls.l4d.test" serverAuth
leaf client-a ca-a "DNS:client-a.l4d.test" clientAuth
leaf client-b ca-b "DNS:client-b.l4d.test" clientAuth
leaf tls-backend.l4d.test ca-up "DNS:tls-backend.l4d.test" serverAuth
leaf lorica-upstream.l4d.test ca-upclient "DNS:lorica-upstream.l4d.test" clientAuth
cp tls-backend.l4d.test.crt /tmp/l4d-tls-backend/backend.crt
cp tls-backend.l4d.test.key /tmp/l4d-tls-backend/backend.key
cp ca-upclient.crt /tmp/l4d-tls-backend/client-ca.crt
touch done
'

# Upload a certificate of the PKI as a stored certificate; prints its id
# (an existing one of the same domain is reused).
L4D_UPLOAD_SCRIPT='
domain=$1 file=$2
existing=$(api GET /api/v1/certificates | jq -r --arg d "$domain" "[.data.certificates[]? | select(.domain == \$d)][0].id // empty")
if [ -n "$existing" ]; then echo "$existing"; exit 0; fi
body=$(jq -n --arg d "$domain" --rawfile c "/tmp/l4d-pki/$file.crt" --rawfile k "/tmp/l4d-pki/$file.key" \
    "{domain: \$d, cert_pem: \$c, key_pem: \$k}")
api POST /api/v1/certificates "$body" | jq -r .data.id
'

# File by file, through results/: `docker cp` of a directory onto one
# that exists nests it instead of replacing its files.
l4d_pki() {
    local f
    l4_client bash -c "$L4D_PKI_SCRIPT" || return 1
    l4_compose exec -T tls-backend mkdir -p /tmp/pki || return 1
    mkdir -p results
    for f in backend.crt backend.key client-ca.crt; do
        l4_compose cp "streams-client:/tmp/l4d-tls-backend/${f}" "${L4_RESULTS}-l4d-${f}" >/dev/null 2>&1 || return 1
        l4_compose cp "${L4_RESULTS}-l4d-${f}" "tls-backend:/tmp/pki/${f}" >/dev/null 2>&1 || return 1
    done
}

l4d_upload() {
    l4s_client_script "$L4D_UPLOAD_SCRIPT" "$1" "$2" 2>&1 | tr -d '\r'
}

# test-runner/l4/tls_backend.py's clients, against l4-node, from the
# client container:
#   l4d_tls hello <port> <sni> <alpn,...|->   prints the backend's line
#       (or `closed`) and ` sent=<SHA-256 of the ClientHello sent>`
#   l4d_tls term <port> <sni> <PKI client certificate|->   prints the
#       first line answered (or `refused <reason>`) and ` fp=<SHA-256 of
#       the server certificate>`
l4d_tls() {
    local cmd="$1" port="$2" sni="$3" extra=()
    if [ "$cmd" = hello ] && [ "$4" != - ]; then
        extra=(--alpn "$4")
    elif [ "$cmd" = term ] && [ "$4" != - ]; then
        extra=(--cert "/tmp/l4d-pki/$4.crt" --key "/tmp/l4d-pki/$4.key")
    fi
    l4_client python3 /tests/l4/tls_backend.py "$cmd" --host l4-node --port "$port" --sni "$sni" "${extra[@]}" | tr -d '\r'
}


# IV1: one passthrough port serves two SNI names to two backends, each
# receiving byte for byte the ClientHello the client sent; a third name
# is closed before any byte is forwarded and counted `no_match`. Plus the
# ALPN row: one name routed by the protocols offered (`h2` to one
# backend, anything else to the other).
scenario_12_4_iv1_sni_passthrough_two_names() {
    local r1 r2 r3 r4 id one two three h2 h1 counted
    trap 'l4s_cleanup_streams l4d-iv1-' EXIT
    l4s_cleanup_streams l4d-iv1-
    r1=$(l4s_backend "$(l4s_ip tls-raw-1):9443" nocheck) || fail "backend: ${r1}"
    r2=$(l4s_backend "$(l4s_ip tls-raw-2):9443" nocheck) || fail "backend: ${r2}"
    r3=$(l4s_backend "$(l4s_ip tls-raw-1):9443" nocheck) || fail "backend: ${r3}"
    r4=$(l4s_backend "$(l4s_ip tls-raw-2):9443" nocheck) || fail "backend: ${r4}"
    id=$(l4s_create_stream "{\"name\":\"l4d-iv1-sni\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":7500,\"tls_mode\":\"passthrough\",\"match_rules\":[
        {\"name\":\"one\",\"matcher\":{\"kind\":\"tls\",\"server_names\":[\"one.l4d.test\"]},\"backend_ids\":[\"${r1}\"]},
        {\"name\":\"two\",\"matcher\":{\"kind\":\"tls\",\"server_names\":[\"two.l4d.test\"]},\"backend_ids\":[\"${r2}\"]},
        {\"name\":\"alpn-h2\",\"matcher\":{\"kind\":\"tls\",\"server_names\":[\"alpn.l4d.test\"],\"alpn\":[\"h2\"]},\"backend_ids\":[\"${r3}\"]},
        {\"name\":\"alpn-any\",\"matcher\":{\"kind\":\"tls\",\"server_names\":[\"alpn.l4d.test\"]},\"backend_ids\":[\"${r4}\"]}]}") \
        || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the passthrough stream did not bind"

    one=$(l4d_tls hello 7500 one.l4d.test -)
    two=$(l4d_tls hello 7500 two.l4d.test -)
    three=$(l4d_tls hello 7500 three.l4d.test -)
    h2=$(l4d_tls hello 7500 alpn.l4d.test h2,http/1.1)
    h1=$(l4d_tls hello 7500 alpn.l4d.test http/1.1)
    for line in "$one" "$two" "$h2" "$h1"; do
        case "$line" in
            name=*" sha256="*" sent="*)
                local got sent
                got=${line#* sha256=}
                got=${got%% *}
                sent=${line##* sent=}
                [ "$got" = "$sent" ] || fail "a backend received a ClientHello other than the one sent: ${line}"
                ;;
            *) fail "a routed name was not forwarded: ${line}" ;;
        esac
    done
    case "$one" in name=tls-raw-1\ *) ;; *) fail "one.l4d.test reached ${one%% *}" ;; esac
    case "$two" in name=tls-raw-2\ *) ;; *) fail "two.l4d.test reached ${two%% *}" ;; esac
    case "$h2" in name=tls-raw-1\ *) ;; *) fail "alpn.l4d.test offering h2 reached ${h2%% *}" ;; esac
    case "$h1" in name=tls-raw-2\ *) ;; *) fail "alpn.l4d.test offering http/1.1 reached ${h1%% *}" ;; esac
    case "$three" in closed\ *) ;; *) fail "three.l4d.test was not closed: ${three}" ;; esac
    counted=$(l4s_wait_reason_count "$id" no_match 1)
    [ "${counted:-0}" -ge 1 ] || fail "the unmatched name was not counted no_match"
    pass "one.l4d.test to tls-raw-1 and two.l4d.test to tls-raw-2, each ClientHello byte for byte (${one#* bytes=}); alpn.l4d.test with h2 to tls-raw-1, with http/1.1 to tls-raw-2; three.l4d.test closed, ${counted} no_match counted"
}

# AC #5: two terminating streams, each verifying client certificates
# against its own CA; each client certificate is accepted on its own
# stream only, and a client without one on neither.
scenario_12_4_ac5_two_cas_two_streams() {
    local cert ca_a ca_b e1 e2 sa sb aa ab ba bb na
    trap 'l4s_cleanup_streams l4d-ac5-' EXIT
    l4s_cleanup_streams l4d-ac5-
    l4d_pki || fail "the test PKI could not be prepared"
    cert=$(l4d_upload a.l4d.test server) || fail "certificate upload refused: ${cert}"
    ca_a=$(l4_client cat /tmp/l4d-pki/ca-a.crt | tr -d '\r')
    ca_b=$(l4_client cat /tmp/l4d-pki/ca-b.crt | tr -d '\r')
    e1=$(l4s_backend "$(l4s_ip tcp-backend-1):9000" nocheck) || fail "backend: ${e1}"
    e2=$(l4s_backend "$(l4s_ip tcp-backend-1):9000" nocheck) || fail "backend: ${e2}"
    sa=$(l4s_client_script 'api POST /api/v1/streams "$(jq -n --arg ca "$2" --arg cert "$3" --arg b "$4" --arg name "$1" --arg host "$5" --argjson port "$6" \
        "{name: \$name, protocol: \"tcp\", listen_address: \"0.0.0.0\", port_first: \$port, tls_mode: \"terminate\",
          match_rules: [{name: \"r\", matcher: {kind: \"tls\", server_names: [\$host]}, backend_ids: [\$b]}],
          tls_terminate: {certificate_ids: [\$cert], client_auth: {ca_cert_pem: \$ca, required: true}}}")" | jq -r .data.id' \
        l4d-ac5-a "$ca_a" "$cert" "$e1" a.l4d.test 7501 2>&1 | tr -d '\r') || fail "stream create refused: ${sa}"
    sb=$(l4s_client_script 'api POST /api/v1/streams "$(jq -n --arg ca "$2" --arg cert "$3" --arg b "$4" --arg name "$1" --arg host "$5" --argjson port "$6" \
        "{name: \$name, protocol: \"tcp\", listen_address: \"0.0.0.0\", port_first: \$port, tls_mode: \"terminate\",
          match_rules: [{name: \"r\", matcher: {kind: \"tls\", server_names: [\$host]}, backend_ids: [\$b]}],
          tls_terminate: {certificate_ids: [\$cert], client_auth: {ca_cert_pem: \$ca, required: true}}}")" | jq -r .data.id' \
        l4d-ac5-b "$ca_b" "$cert" "$e2" b.l4d.test 7502 2>&1 | tr -d '\r') || fail "stream create refused: ${sb}"
    for id in "$sa" "$sb"; do
        l4s_wait_bind "$id" bound 5 >/dev/null || fail "stream ${id} did not bind"
    done
    aa=$(l4d_tls term 7501 a.l4d.test client-a)
    ab=$(l4d_tls term 7502 b.l4d.test client-a)
    ba=$(l4d_tls term 7501 a.l4d.test client-b)
    bb=$(l4d_tls term 7502 b.l4d.test client-b)
    na=$(l4d_tls term 7501 a.l4d.test -)
    case "$aa" in name=tcp-backend-1*) ;; *) fail "client-a refused on its own stream: ${aa}" ;; esac
    case "$bb" in name=tcp-backend-1*) ;; *) fail "client-b refused on its own stream: ${bb}" ;; esac
    case "$ab" in name=*) fail "client-a (CA a) accepted on the stream trusting CA b: ${ab}" ;; esac
    case "$ba" in name=*) fail "client-b (CA b) accepted on the stream trusting CA a: ${ba}" ;; esac
    case "$na" in name=*) fail "a client without a certificate accepted: ${na}" ;; esac
    pass "client-a served on its stream, refused on the other (${ab%% fp=*}); client-b likewise (${ba%% fp=*}); no certificate refused (${na%% fp=*})"
}

# AC #4: a terminate-and-re-encrypt stream verifies the TLS backend
# against its CA, sends the configured name, and presents a stored client
# certificate, which the backend verifies and reports.
scenario_12_4_ac4_upstream_mtls() {
    local cert ident ca_up b id seen
    trap 'l4s_cleanup_streams l4d-ac4-' EXIT
    l4s_cleanup_streams l4d-ac4-
    l4d_pki || fail "the test PKI could not be prepared"
    cert=$(l4d_upload tls.l4d.test server) || fail "certificate upload refused: ${cert}"
    ident=$(l4d_upload lorica-upstream.l4d.test lorica-upstream.l4d.test) || fail "client identity upload refused: ${ident}"
    ca_up=$(l4_client cat /tmp/l4d-pki/ca-up.crt | tr -d '\r')
    b=$(l4s_backend "$(l4s_ip tls-backend):9443" nocheck) || fail "backend: ${b}"
    id=$(l4s_client_script 'api POST /api/v1/streams "$(jq -n --arg ca "$1" --arg cert "$2" --arg ident "$3" --arg b "$4" \
        "{name: \"l4d-ac4-mtls\", protocol: \"tcp\", listen_address: \"0.0.0.0\", port_first: 7503, tls_mode: \"terminate\",
          match_rules: [{name: \"r\", matcher: {kind: \"tls\", server_names: [\"tls.l4d.test\"]}, backend_ids: [\$b]}],
          tls_terminate: {certificate_ids: [\$cert]},
          upstream_tls: {server_name: {mode: \"fixed\", name: \"tls-backend.l4d.test\"}, ca_cert_pem: \$ca, client_certificate_id: \$ident}}")" | jq -r .data.id' \
        "$ca_up" "$cert" "$ident" "$b" 2>&1 | tr -d '\r') || fail "stream create refused: ${id}"
    l4s_wait_bind "$id" bound 5 >/dev/null || fail "the stream did not bind"
    seen=$(l4d_tls term 7503 tls.l4d.test -)
    case "$seen" in
        "name=tls-backend sni=tls-backend.l4d.test client=lorica-upstream.l4d.test "*) ;;
        *) fail "the TLS backend did not see the stored client certificate and the fixed name: ${seen}" ;;
    esac
    pass "the backend verified Lorica's stored client certificate and saw: ${seen%% fp=*}"
}
