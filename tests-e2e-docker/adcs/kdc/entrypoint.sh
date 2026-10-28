#!/bin/sh
# Creates the realm and its two principals, exports the CES service key
# to the shared volume, then runs the KDC in the foreground.
#
# Every secret here is a harness-only value: the realm exists only inside
# this container for the length of one run.
set -eu

kdb5_util create -s -r CORP.EXAMPLE.ORG -P harness-only-master-key >/dev/null

kadmin.local -q "addprinc -pw harness-only-password svc-lorica@CORP.EXAMPLE.ORG" >/dev/null
kadmin.local -q "addprinc -randkey HTTP/ces.corp.example.org@CORP.EXAMPLE.ORG" >/dev/null

# The fixture waits for the keytab to exist: write it under a temporary
# name and rename, so it never reads a half-written file.
kadmin.local -q "ktadd -k /harness/ces.keytab.tmp HTTP/ces.corp.example.org@CORP.EXAMPLE.ORG" >/dev/null
chmod 0644 /harness/ces.keytab.tmp
mv /harness/ces.keytab.tmp /harness/ces.keytab

exec krb5kdc -n
