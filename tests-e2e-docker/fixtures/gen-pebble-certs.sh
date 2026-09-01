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
#
# Generated at runtime (never committed): the Pebble 2.8.0 image is
# distroless with no bundled test certificates to extract, and
# committing private keys - even test-only ones - would trip the
# repository's own secret hygiene rules. Everything lands in the
# ephemeral `shared-acme` named volume, wiped by `down -v`.
#
# Runs as root (volume ownership); the volume is chmod 0777 at the end
# because three different users need it afterwards: pebble (root, reads
# the leaf), lorica (unprivileged, reads the CA and writes
# /shared/admin_password from its entrypoint), and the test-runner
# (testuser, reads the password).
# =============================================================================
set -eu

OUT=/shared
mkdir -p "$OUT"

if [ -f "$OUT/pebble-ca.pem" ] && [ -f "$OUT/pebble-dir.pem" ]; then
    echo "pebble fixture PKI already present, skipping generation"
    exit 0
fi

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
chmod 0777 "$OUT"
echo "pebble fixture PKI ready"
