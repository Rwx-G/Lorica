#!/usr/bin/env bash
# =============================================================================
# Lorica AD CS E2E smoke (v1.10.0 Story 13.6 AC #2, IV1)
#
# Drives the management API of a node joined to the Story 13.1 Kerberos
# harness: an MIT KDC for CORP.EXAMPLE.ORG and a CES fixture that
# enforces the TLS channel binding and issues from a throwaway PKI. The
# harness volume is mounted read-only at /harness: the fixture's CA
# certificates, its issuing CA key, and the KDC log.
#
#   1. authority creation and connection test;
#   2. issuance from a route's hostname, bound to the route and served
#      on the HTTPS listener for that SNI, chained to the harness CA;
#   3. "Renew now": same id, new key;
#   4. renewal by the loop: not driven here (see below);
#   5. adoption and reversion of a certificate the authority issued
#      outside Lorica, and none of one another CA issued;
#   6. the D15 breaker: a wrong password opens the failed state after
#      one pre-authentication, a second test is refused with no KDC
#      exchange, and saving the right password closes it.
#
# Woven through them, the decisions the epic audit added: a Viewer reads
# that the authority exists but not how it is reached (D18); a template
# the authority does not list is refused before any Kerberos exchange
# (D17); the private key of an AD CS certificate, issued or adopted, is
# downloadable by nobody and its PEM is not replaceable (D16).
#
# The probe client without a channel binding (IV1's third leg) runs from
# run.sh inside the fixture container, which has python-gssapi.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
TLS_LISTENER="${LORICA_TLS}"
HARNESS=/harness
ENDPOINT="https://ces.corp.example.org/issued/valid/CES"
HOSTNAME_UNDER_TEST="app.corp.example.org"
ADOPTED_NAME="legacy.corp.example.org"
FOREIGN_NAME="elsewhere.corp.example.org"
# Harness-only values: the KDC creates this principal with this password
# at every start (adcs/kdc/entrypoint.sh), in a realm nothing else uses.
HARNESS_PASSWORD="harness-only-password"
WRONG_PASSWORD="harness-only-wrong-password"
KDC_PRINCIPAL=" svc-lorica@CORP.EXAMPLE.ORG for "

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- preflight ----------------------------------------------------------------
log "=== AD CS smoke: preflight ==="
for f in ca/root.pem ca/issuing.pem ca/issuing.key.pem kdc.log; do
    [ -s "$HARNESS/$f" ] && [ -r "$HARNESS/$f" ] \
        || { fail "the harness did not publish $f, or it is not readable here"; exit 1; }
done
ok "harness CA material and KDC log present"

if wait_for_api 120; then
    log "Lorica API ready"
else
    fail "Lorica API never came up at $API"
    exit 1
fi

# --- login as the SuperAdmin, rotating the first-run password -----------------
ADMIN_PW=""
for _ in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(tr -d '[:space:]' < /shared/admin_password)
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; exit 1; }

session_from() {
    grep -i 'Set-Cookie:' "$1" | grep -o 'lorica_session=[^;]*' | head -1
}

LOGIN_HEADERS="$WORK/login.headers"
LOGIN_BODY="$WORK/login.body"
LOGIN_HTTP=$(curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" -w '%{http_code}' \
    "$API/api/v1/auth/login" -X POST -H "Content-Type: application/json" \
    -d "$(jq -nc --arg u admin --arg p "$ADMIN_PW" '{username:$u,password:$p}')")
[ "$LOGIN_HTTP" = "200" ] || { fail "login HTTP $LOGIN_HTTP: $(cat "$LOGIN_BODY")"; exit 1; }
SESSION=$(session_from "$LOGIN_HEADERS")
[ -n "$SESSION" ] || { fail "no session cookie returned"; exit 1; }
if [ "$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")" = "true" ]; then
    NEW_PW="AdcsSmokePassword!42"
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
        "$API/api/v1/auth/password" -X PUT -H "Content-Type: application/json" \
        -d "$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" '{current_password:$cur,new_password:$new}')")
    [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; exit 1; }
    curl -s -o /dev/null -D "$LOGIN_HEADERS" "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d "$(jq -nc --arg u admin --arg p "$NEW_PW" '{username:$u,password:$p}')"
    SESSION=$(session_from "$LOGIN_HEADERS")
    [ -n "$SESSION" ] || { fail "no session cookie after re-login"; exit 1; }
fi
ok "logged in as the SuperAdmin"

# --- helpers --------------------------------------------------------------------

# The session cookie of a fresh login as $1 with password $2, or nothing.
login_user() {
    local headers="$WORK/user.headers"
    local http
    http=$(curl -s -o /dev/null -D "$headers" -w '%{http_code}' \
        "$API/api/v1/auth/login" -X POST -H "Content-Type: application/json" \
        -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')")
    [ "$http" = "200" ] && session_from "$headers"
}

# `call` with the session cookie $1 instead of the SuperAdmin's.
call_as() {
    local saved="$SESSION"
    SESSION="$1"
    shift
    call "$@"
    SESSION="$saved"
}

# Sets CODE and BODY. Usage: call <method> <path> [json body]
call() {
    local method="$1" path="$2" data="${3:-}"
    local out="$WORK/response"
    if [ -n "$data" ]; then
        CODE=$(curl -s -o "$out" -w '%{http_code}' --max-time 150 -b "$SESSION" \
            -X "$method" -H "Content-Type: application/json" -d "$data" "$API$path" || true)
    else
        CODE=$(curl -s -o "$out" -w '%{http_code}' --max-time 150 -b "$SESSION" \
            -X "$method" "$API$path" || true)
    fi
    BODY=$(cat "$out" 2>/dev/null || true)
}

expect_code() {
    local expected="$1" label="$2"
    if [ "$CODE" = "$expected" ]; then
        ok "$label (HTTP $CODE)"
    else
        fail "$label (expected HTTP $expected, got $CODE: $(echo "$BODY" | head -c 400))"
    fi
}

# `call`, with a 429 waited out rather than counted as the answer. The
# connection test, and issuance with "Renew now", each have a rate-limit
# bucket smaller than the calls this smoke makes in a minute; the wait is
# logged so it shows in the run's timings.
call_past_rate_limit() {
    local waited=0
    for _ in $(seq 1 60); do
        call "$@"
        if [ "$CODE" != "429" ]; then
            [ "$waited" = "0" ] || log "$1 $2: waited ${waited}s for the rate limit"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
}

connection_test() { call_past_rate_limit POST /api/v1/adcs/authority/test; }

as_reqs() { grep "AS_REQ" "$HARNESS/kdc.log" | grep -c -- "$KDC_PRINCIPAL" || true; }
preauth_failures() {
    grep "AS_REQ" "$HARNESS/kdc.log" | grep -- "$KDC_PRINCIPAL" | grep -c "PREAUTH_FAILED" || true
}

# The certificate the HTTPS listener serves for an SNI, verified against
# the harness root for that name. Empty when the handshake or the
# verification fails.
served_certificate() {
    echo | openssl s_client -connect "$TLS_LISTENER" -servername "$1" \
        -CAfile "$HARNESS/ca/root.pem" -verify_hostname "$1" -verify_return_error \
        2>/dev/null | openssl x509 2>/dev/null || true
}

public_key_of() { echo "$1" | openssl x509 -noout -pubkey 2>/dev/null || true; }

# The authority as stored, as a PUT body with the given password: the
# write replaces every field, as the settings form sends them all.
authority_update() {
    call GET /api/v1/adcs/authority
    echo "$BODY" | jq -c --arg pw "$1" '.data.authority
        | {endpoint, realm, kdcs, principal, endpoint_ca_pem, issuing_ca_pem,
           default_template, allowed_templates, default_key_type, subject,
           allowed_suffixes, auto_renew_default}
        + {password: $pw}'
}

# --- 1. authority and connection test -------------------------------------------
log "=== 1. authority and connection test ==="
AUTHORITY=$(jq -nc --arg endpoint "$ENDPOINT" --arg pw "$HARNESS_PASSWORD" \
    --rawfile ca "$HARNESS/ca/root.pem" '{
        endpoint: $endpoint,
        realm: "CORP.EXAMPLE.ORG",
        kdcs: ["kdc.corp.example.org"],
        principal: "svc-lorica",
        password: $pw,
        endpoint_ca_pem: $ca,
        default_template: "LoricaWebServer",
        allowed_templates: ["LoricaWebServerAlt"],
        allowed_suffixes: ["corp.example.org"],
        auto_renew_default: true
    }')
call PUT /api/v1/adcs/authority "$AUTHORITY"
expect_code 201 "authority created"
assert_json "$BODY" '.data.password_set' "true" "the password is reported set, never returned"
assert_json "$BODY" '.data | has("password")' "false" "no password field in the answer"
assert_json "$BODY" '.data.allowed_templates | join(",")' "LoricaWebServer,LoricaWebServerAlt" \
    "the allowed templates are stored with the default first (D17)"

# D18: every role learns that the authority exists; only Operators and
# above learn how it is reached.
VIEWER_PW="AdcsSmokeViewer!4242"
OPERATOR_PW="AdcsSmokeOperator!4242"
call POST /api/v1/users "$(jq -nc --arg p "$VIEWER_PW" '{username:"adcs-viewer",password:$p,role:"viewer"}')"
expect_code 201 "viewer account created"
call POST /api/v1/users "$(jq -nc --arg p "$OPERATOR_PW" '{username:"adcs-operator",password:$p,role:"operator"}')"
expect_code 201 "operator account created"
VIEWER_SESSION=$(login_user adcs-viewer "$VIEWER_PW" || true)
OPERATOR_SESSION=$(login_user adcs-operator "$OPERATOR_PW" || true)
[ -n "$VIEWER_SESSION" ] && [ -n "$OPERATOR_SESSION" ] \
    || { fail "viewer or operator login failed"; exit 1; }

call_as "$VIEWER_SESSION" GET /api/v1/adcs/authority
expect_code 200 "a viewer reads the authority"
assert_json "$BODY" '.data.configured' "true" "the viewer learns an authority is configured"
assert_json "$BODY" '.data.summary.allowed_suffixes[0]' "corp.example.org" "and its allowed suffixes"
assert_json "$BODY" '.data.authority' "null" "but not the authority itself"
case "$BODY" in
    *ces.corp.example.org*|*svc-lorica*|*CORP.EXAMPLE.ORG*|*LoricaWebServer*)
        fail "the viewer's answer names the endpoint, principal, realm or template: $BODY" ;;
    *) ok "the viewer's answer names no endpoint, principal, realm or template" ;;
esac
call_as "$OPERATOR_SESSION" GET /api/v1/adcs/authority
assert_json "$BODY" '.data.authority.endpoint' "$ENDPOINT" "an operator reads the endpoint"
assert_json "$BODY" '.data.authority.principal' "svc-lorica" "and the principal"

BEFORE=$(as_reqs)
connection_test
expect_code 200 "connection test answered"
assert_json "$BODY" '.data.ok' "true" "connection test ok: ticket, bound SPNEGO, mutual authentication"
sleep 1
AFTER=$(as_reqs)
if [ $((AFTER - BEFORE)) -ge 1 ]; then
    ok "the test went through the KDC ($((AFTER - BEFORE)) AS-REQ lines)"
else
    fail "the test left no AS-REQ in the KDC log"
fi

# --- 2. issuance from a route ---------------------------------------------------
log "=== 2. issuance from a route ==="
call POST /api/v1/backends '{"name":"adcs-backend","group":"adcs","address":"192.0.2.10:80","h2_upstream":false,"tls":false}'
BACKEND_ID=$(echo "$BODY" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: HTTP $CODE $BODY"; exit 1; }
call POST /api/v1/routes "{\"hostname\":\"${HOSTNAME_UNDER_TEST}\",\"path_prefix\":\"/\",\"backend_ids\":[\"${BACKEND_ID}\"],\"enabled\":true}"
ROUTE_ID=$(echo "$BODY" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: HTTP $CODE $BODY"; exit 1; }
ok "route for ${HOSTNAME_UNDER_TEST} created"

# D17: a template the authority does not list is refused before any
# Kerberos exchange.
BEFORE=$(as_reqs)
call POST /api/v1/certificates/adcs "{\"sans\":[\"${HOSTNAME_UNDER_TEST}\"],\"template\":\"User\"}"
expect_code 422 "a template outside the allowlist is refused"
assert_json "$BODY" '.error.code' "adcs_template_refused" "refused as adcs_template_refused"
sleep 1
AFTER=$(as_reqs)
if [ "$AFTER" = "$BEFORE" ]; then
    ok "the refused template reached no KDC"
else
    fail "the refused template reached the KDC: $BEFORE AS-REQ lines before, $AFTER after"
fi

call POST /api/v1/certificates/adcs "{\"sans\":[\"${HOSTNAME_UNDER_TEST}\"]}"
expect_code 201 "issued from AD CS for the route's hostname"
CERT_ID=$(echo "$BODY" | jq -r '.data.id // empty')
[ -n "$CERT_ID" ] || { fail "no certificate id in the issuance answer"; exit 1; }
assert_json "$BODY" '.data.source' "adcs" "the certificate is AD CS-managed"
assert_json "$BODY" '.data.domain' "$HOSTNAME_UNDER_TEST" "its domain is the requested name"

call PUT "/api/v1/routes/$ROUTE_ID" "{\"certificate_id\":\"${CERT_ID}\"}"
assert_json "$BODY" '.data.certificate_id' "$CERT_ID" "the certificate is bound to the route"

SERVED=""
for _ in $(seq 1 20); do
    SERVED=$(served_certificate "$HOSTNAME_UNDER_TEST")
    [ -n "$SERVED" ] && break
    sleep 1
done
if [ -n "$SERVED" ]; then
    ok "served on ${TLS_LISTENER} for SNI ${HOSTNAME_UNDER_TEST}, verified to the harness root"
else
    fail "no certificate for ${HOSTNAME_UNDER_TEST} that verifies to the harness root"
fi
ISSUER=$(echo "$SERVED" | openssl x509 -noout -issuer 2>/dev/null || true)
case "$ISSUER" in
    *"Lorica Harness Issuing CA"*) ok "issued by the harness issuing CA ($ISSUER)" ;;
    *) fail "unexpected issuer: '$ISSUER'" ;;
esac

call GET /api/v1/adcs/authority
assert_json "$BODY" '.data.authority.issuing_ca_pem != null' "true" \
    "the authority learned its issuing CA from the first issuance"

# D16: the private key of an AD CS certificate is downloadable by no
# role; its certificate is. The download bucket admits five a minute,
# and this smoke makes five.
for part in "?part=key" "?part=bundle" ""; do
    call GET "/api/v1/certificates/$CERT_ID/download$part"
    expect_code 403 "the key is not downloadable (download$part)"
    assert_json "$BODY" '.error.code' "adcs_key_not_exportable" "refused as adcs_key_not_exportable"
done
call GET "/api/v1/certificates/$CERT_ID/download?part=cert"
expect_code 200 "the certificate itself is downloadable"
case "$BODY" in
    *"PRIVATE KEY"*) fail "the certificate download carries a private key" ;;
    *"BEGIN CERTIFICATE"*) ok "the download is the certificate, without a key" ;;
    *) fail "the certificate download carries no certificate: $(echo "$BODY" | head -c 200)" ;;
esac
call PUT "/api/v1/certificates/$CERT_ID" "$(jq -nc --arg d "other.corp.example.org" '{domain:$d}')"
expect_code 409 "the domain of an AD CS certificate is not replaceable"
assert_json "$BODY" '.error.code' "adcs_certificate_managed" "refused as adcs_certificate_managed"

# --- 3. renew now -----------------------------------------------------------------
log "=== 3. renew now ==="
KEY_BEFORE=$(public_key_of "$SERVED")
call POST "/api/v1/certificates/$CERT_ID/renew"
expect_code 200 "renewed now"
assert_json "$BODY" '.data.id' "$CERT_ID" "renewed in place: same id"
KEY_AFTER=""
for _ in $(seq 1 20); do
    KEY_AFTER=$(public_key_of "$(served_certificate "$HOSTNAME_UNDER_TEST")")
    [ -n "$KEY_AFTER" ] && [ "$KEY_AFTER" != "$KEY_BEFORE" ] && break
    sleep 1
done
if [ -n "$KEY_BEFORE" ] && [ -n "$KEY_AFTER" ] && [ "$KEY_AFTER" != "$KEY_BEFORE" ]; then
    ok "the listener serves the renewed certificate, with a new key"
else
    fail "the served key did not change after the renewal"
fi
call GET /api/v1/routes/"$ROUTE_ID"
assert_json "$BODY" '.data.certificate_id' "$CERT_ID" "the route still references the renewed certificate"

# --- 4. renewal by the loop -------------------------------------------------------
# The loop renews on its own tick, inside its renewal window. Driving it
# here would mean waiting a tick out; its selection, its breaker and its
# back-off are covered by the unit tests in
# lorica-api/src/adcs/renew/tests.rs. Not asserted here.
log "=== 4. renewal by the loop: time-based, covered by unit tests, not driven ==="

# --- 5. adoption and reversion -----------------------------------------------------
log "=== 5. adoption and reversion ==="
cat > "$WORK/leaf.ext" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

# A leaf for $1 signed by the CA in $2 / $3, in $WORK/$1.{crt,key}.
sign_leaf() {
    local name="$1" ca="$2" ca_key="$3"
    openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/$name.key" \
        -subj "/O=Example Corp/CN=$name" -out "$WORK/$name.csr" 2>/dev/null
    cp "$WORK/leaf.ext" "$WORK/$name.ext"
    echo "subjectAltName = DNS:$name" >> "$WORK/$name.ext"
    openssl x509 -req -in "$WORK/$name.csr" -CA "$ca" -CAkey "$ca_key" \
        -set_serial "0x$(openssl rand -hex 16)" -days 30 -sha256 \
        -extfile "$WORK/$name.ext" -out "$WORK/$name.crt" 2>/dev/null
}

# Uploads the leaf of $1 with the chain in $2 and sets UPLOADED_ID, empty
# on failure. Called directly, not through $(...): CODE and BODY must
# survive for the failure message.
upload() {
    local name="$1" chain="$2"
    call POST /api/v1/certificates "$(jq -nc --arg d "$name" \
        --arg c "$(cat "$WORK/$name.crt" "$chain")" --rawfile k "$WORK/$name.key" \
        '{domain:$d, cert_pem:$c, key_pem:$k}')"
    UPLOADED_ID=$(echo "$BODY" | jq -r '.data.id // empty')
}

sign_leaf "$ADOPTED_NAME" "$HARNESS/ca/issuing.pem" "$HARNESS/ca/issuing.key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$WORK/foreign-ca.key" \
    -subj "/O=Elsewhere/CN=Foreign Issuing CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$WORK/foreign-ca.pem" 2>/dev/null
sign_leaf "$FOREIGN_NAME" "$WORK/foreign-ca.pem" "$WORK/foreign-ca.key"

upload "$ADOPTED_NAME" "$HARNESS/ca/issuing.pem"
ADOPTED_ID="$UPLOADED_ID"
[ -n "$ADOPTED_ID" ] || { fail "upload of the harness-signed certificate: HTTP $CODE $BODY"; exit 1; }
upload "$FOREIGN_NAME" "$WORK/foreign-ca.pem"
FOREIGN_ID="$UPLOADED_ID"
[ -n "$FOREIGN_ID" ] || { fail "upload of the foreign certificate: HTTP $CODE $BODY"; exit 1; }
ok "uploaded a manual certificate from the harness CA and one from another CA"

call GET /api/v1/adcs/adoption-candidates
expect_code 200 "adoption candidates listed"
assert_json "$BODY" '.data.reason' "null" "the candidate list is a real one"
only_candidate_is() {
    echo "$BODY" | jq -e --arg id "$1" '[.data.candidates[].certificate_id] == [$id]' >/dev/null
}
if only_candidate_is "$ADOPTED_ID"; then
    ok "only the certificate the authority's issuing CA signed is a candidate"
else
    fail "expected the harness-signed certificate alone as a candidate: $BODY"
fi

call POST "/api/v1/certificates/$FOREIGN_ID/adcs/adopt"
expect_code 422 "the foreign certificate is refused as not a candidate"
assert_json "$BODY" '.error.code' "adcs_not_candidate" "refused with adcs_not_candidate"

call POST "/api/v1/certificates/$ADOPTED_ID/adcs/adopt"
expect_code 200 "adopted"
assert_json "$BODY" '.data.source' "adcs" "the adopted certificate is AD CS-managed"
assert_json "$BODY" '.data.adcs_template' "LoricaWebServer" "it renews with the authority's template"
call GET "/api/v1/certificates/$ADOPTED_ID/download?part=key"
expect_code 403 "the key of an adopted certificate is no longer downloadable"
call GET /api/v1/adcs/adoption-candidates
assert_json "$BODY" '.data.candidates | length' "0" "an adopted certificate is no longer a candidate"

call POST "/api/v1/certificates/$ADOPTED_ID/adcs/revert"
expect_code 200 "reverted to manual"
assert_json "$BODY" '.data.source' "manual" "the reverted certificate is manual"
assert_json "$BODY" '.data.adcs_authority_id' "null" "it no longer references the authority"
call GET /api/v1/adcs/adoption-candidates
if only_candidate_is "$ADOPTED_ID"; then
    ok "the reverted certificate is offered again"
else
    fail "the reverted certificate is not offered again: $BODY"
fi

# --- 6. the D15 breaker -----------------------------------------------------------
log "=== 6. the breaker ==="
call PUT /api/v1/adcs/authority "$(authority_update "$WRONG_PASSWORD")"
expect_code 200 "a wrong password saved (identity unchanged, so no other field needed)"

BEFORE_FAILURES=$(preauth_failures)
connection_test
expect_code 200 "connection test with the wrong password answered"
assert_json "$BODY" '.data.ok' "false" "the test fails"
assert_json "$BODY" '.data.step' "ticket_acquisition" "at ticket acquisition"
assert_json "$BODY" '.data.authority_failed' "true" "and puts the authority in the failed state"
sleep 1
NEW_FAILURES=$(( $(preauth_failures) - BEFORE_FAILURES ))
if [ "$NEW_FAILURES" = "1" ]; then
    ok "one failed pre-authentication in the KDC log, no more"
else
    fail "expected exactly one PREAUTH_FAILED in the KDC log, got $NEW_FAILURES"
fi
call GET /api/v1/adcs/authority
assert_json "$BODY" '.data.authority.failed_since != null' "true" "the authority reports the failed state"
assert_json "$BODY" '.data.authority.failed_kdc_code' "24" "with KDC_ERR_PREAUTH_FAILED"
call_as "$VIEWER_SESSION" GET /api/v1/adcs/authority
assert_json "$BODY" '.data.summary.failed_kdc_code' "24" "a viewer sees the failed state too"
assert_json "$BODY" '.data.summary.failed_reason != null' "true" "with what the code means"

BEFORE=$(as_reqs)
connection_test
expect_code 409 "a second test is refused in the failed state"
assert_json "$BODY" '.error.code' "adcs_failed_state" \
    "refused as adcs_failed_state, the code issuance answers too"
case "$(echo "$BODY" | jq -r '.error.message // empty')" in
    *"failed state"*) ok "the refusal names the failed state" ;;
    *) fail "the refusal does not name the failed state: $BODY" ;;
esac
sleep 1
AFTER=$(as_reqs)
if [ "$AFTER" = "$BEFORE" ]; then
    ok "the refused test sent nothing to the KDC ($AFTER AS-REQ lines before and after)"
else
    fail "the refused test reached the KDC: $BEFORE AS-REQ lines before, $AFTER after"
fi
call_past_rate_limit POST /api/v1/certificates/adcs "{\"sans\":[\"other.corp.example.org\"]}"
expect_code 409 "issuance is refused in the failed state too"
assert_json "$BODY" '.error.code' "adcs_failed_state" "refused as adcs_failed_state"

call PUT /api/v1/adcs/authority "$(authority_update "$HARNESS_PASSWORD")"
expect_code 200 "the right password saved"
assert_json "$BODY" '.data.failed_since' "null" "saving a password closes the failed state"
connection_test
expect_code 200 "connection test after the fix answered"
assert_json "$BODY" '.data.ok' "true" "connection test ok again"

print_results
