#!/bin/sh
# =============================================================================
# Pebble ACME fixture bootstrap (Story 9.1 AC #13).
#
# Generates, at container start, the throwaway PKI the `acme` profile
# needs:
#   - pebble-ca.pem / pebble-ca.key : a root CA trusted by the Lorica
#     node via SSL_CERT_FILE (instant-acme's platform verifier loads
#     native roots through openssl-probe, which honours that env var).
#   - pebble-dir.pem / pebble-dir.key : the leaf Pebble presents on its
#     ACME directory listener. Its SANs cover the Let's Encrypt staging
#     and production hostnames: the compose network aliases the pebble
#     service to the staging hostname so the fixture's TLS identity is
#     realistic, and LORICA_ACME_DIRECTORY_URL points issuance at its
#     /dir path (Pebble does not serve /directory).
#   - oidc-issuer.pem / oidc-issuer.key : the leaf the OIDC issuer
#     fixture of the `cluster` profile presents (Story 10.5). Signed by
#     the same CA, so the control plane's trust shape is one file for
#     both fixtures.
#
# Generated at runtime (never committed): the Pebble 2.8.0 image is
# distroless with no bundled test certificates to extract, and
# committing private keys - even test-only ones - would trip the
# repository's own secret hygiene rules. Everything lands in the
# ephemeral `shared-acme` named volume, wiped by `down -v`.
#
# Runs as root (volume ownership); the volume is chmod 0777 at the end
# because several different users need it afterwards: pebble (root,
# reads the leaf), lorica (unprivileged, reads the CA and writes
# /shared/admin_password from its entrypoint), the oidc-issuer fixture
# (unprivileged, reads its leaf), and the test-runner (testuser, reads
# the password).
# =============================================================================
set -eu

OUT=/shared
mkdir -p "$OUT"

if [ -f "$OUT/pebble-ca.pem" ] && [ -f "$OUT/pebble-dir.pem" ]; then
    echo "pebble fixture PKI already present, skipping generation"
else
    echo "generating pebble fixture CA"
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/pebble-ca.key"
    openssl req -x509 -new -key "$OUT/pebble-ca.key" -sha256 -days 3650 \
        -subj "/CN=Lorica e2e Pebble directory CA" -out "$OUT/pebble-ca.pem"

    echo "generating pebble directory leaf"
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/pebble-dir.key"
    openssl req -new -key "$OUT/pebble-dir.key" \
        -subj "/CN=acme-staging-v02.api.letsencrypt.org" -out "$OUT/pebble-dir.csr"
    printf 'subjectAltName=DNS:acme-staging-v02.api.letsencrypt.org,DNS:acme-v02.api.letsencrypt.org,DNS:pebble\n' \
        > "$OUT/pebble-san.ext"
    openssl x509 -req -in "$OUT/pebble-dir.csr" \
        -CA "$OUT/pebble-ca.pem" -CAkey "$OUT/pebble-ca.key" -CAcreateserial \
        -days 825 -sha256 -extfile "$OUT/pebble-san.ext" -out "$OUT/pebble-dir.pem"
    rm -f "$OUT/pebble-dir.csr" "$OUT/pebble-san.ext" "$OUT/pebble-ca.srl"

    chmod 0644 "$OUT/pebble-ca.pem" "$OUT/pebble-dir.pem" "$OUT/pebble-dir.key"
    chmod 0600 "$OUT/pebble-ca.key"
fi

# The OIDC issuer leaf (Story 10.5). Its own guard, so a volume that
# predates this fixture still gets one. The key is world-readable for
# the same reason pebble-dir.key is: the fixture runs unprivileged and
# the material is throwaway.
if [ -f "$OUT/oidc-issuer.pem" ] && [ -f "$OUT/oidc-issuer.key" ]; then
    echo "oidc issuer fixture leaf already present, skipping generation"
else
    echo "generating oidc issuer fixture leaf"
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/oidc-issuer.key"
    openssl req -new -key "$OUT/oidc-issuer.key" \
        -subj "/CN=oidc-issuer" -out "$OUT/oidc-issuer.csr"
    printf 'subjectAltName=DNS:oidc-issuer\n' > "$OUT/oidc-issuer-san.ext"
    openssl x509 -req -in "$OUT/oidc-issuer.csr" \
        -CA "$OUT/pebble-ca.pem" -CAkey "$OUT/pebble-ca.key" -CAcreateserial \
        -days 825 -sha256 -extfile "$OUT/oidc-issuer-san.ext" -out "$OUT/oidc-issuer.pem"
    rm -f "$OUT/oidc-issuer.csr" "$OUT/oidc-issuer-san.ext" "$OUT/pebble-ca.srl"
    chmod 0644 "$OUT/oidc-issuer.pem" "$OUT/oidc-issuer.key"
fi

chmod 0777 "$OUT"
echo "pebble fixture PKI ready"
