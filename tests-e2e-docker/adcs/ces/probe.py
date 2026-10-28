"""The harness probe client (Story 13.1 AC #12, IV1 third leg).

It authenticates to the fixture the way a client without Extended
Protection support does: a valid Kerberos ticket, a SPNEGO token, and no
channel binding. The fixture must refuse it with 401, and must refuse it
because the binding is missing, not because something else went wrong.

Three legs, each with a fresh context from the same credential:

1. no channel binding: 401, and the fixture names the missing
   GSS_C_CHANNEL_BOUND_FLAG as the reason;
2. a binding to another certificate: 401 from GSS-API itself;
3. the correct binding: 405, the positive control that proves the
   ticket, the SPN and the keytab are good, so the 401 of leg 1 is the
   binding check and nothing else.

Exits non-zero on any other result. Run by tests-e2e-docker/adcs/run.sh.
"""

import base64
import hashlib
import http.client
import socket
import ssl
import sys

import gssapi
import gssapi.raw

from harness_ca import CES_HOST, tls_server_end_point

PRINCIPAL = "svc-lorica@CORP.EXAMPLE.ORG"
PASSWORD = b"harness-only-password"
ROOT_CA = "/harness/ca/root.pem"
SPNEGO = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")


def tls_context():
    context = ssl.create_default_context(cafile=ROOT_CA)
    context.check_hostname = True
    return context


def server_certificate():
    with socket.create_connection((CES_HOST, 443), timeout=10) as raw:
        with tls_context().wrap_socket(raw, server_hostname=CES_HOST) as tls:
            return tls.getpeercert(binary_form=True)


def credential():
    name = gssapi.Name(PRINCIPAL, gssapi.NameType.kerberos_principal)
    # The mechanism set lorica-adcs asks for: without SPNEGO in it, MIT
    # acquires a krb5-only credential that a SPNEGO context cannot use.
    return gssapi.raw.acquire_cred_with_password(
        name, PASSWORD, mechs=[SPNEGO], usage="initiate"
    ).creds


def attempt(creds, application_data):
    bindings = (
        None
        if application_data is None
        else gssapi.raw.ChannelBindings(application_data=application_data)
    )
    context = gssapi.SecurityContext(
        name=gssapi.Name(f"HTTP@{CES_HOST}", gssapi.NameType.hostbased_service),
        creds=creds,
        usage="initiate",
        mech=SPNEGO,
        flags=[gssapi.RequirementFlag.mutual_authentication],
        channel_bindings=bindings,
    )
    token = context.step()
    connection = http.client.HTTPSConnection(CES_HOST, 443, timeout=10, context=tls_context())
    connection.request(
        "GET",
        "/issued/valid/CES",
        headers={"Authorization": f"Negotiate {base64.b64encode(token).decode('ascii')}"},
    )
    response = connection.getresponse()
    body = response.read().decode("utf-8", "replace")
    connection.close()
    return response.status, body


def main():
    creds = credential()
    binding = tls_server_end_point(server_certificate())
    other_binding = b"tls-server-end-point:" + hashlib.sha256(b"another certificate").digest()

    failures = []

    status, body = attempt(creds, None)
    print(f"probe: no channel binding -> {status} {body!r}")
    if status != 401 or "GSS_C_CHANNEL_BOUND_FLAG" not in body:
        failures.append("an unbound token was not refused for its missing binding")

    status, body = attempt(creds, other_binding)
    print(f"probe: binding to another certificate -> {status} {body!r}")
    if status != 401:
        failures.append("a token bound to another certificate was not refused")

    status, body = attempt(creds, binding)
    print(f"probe: correct binding (positive control) -> {status} {body!r}")
    if status != 405:
        failures.append("a correctly bound token was not accepted")

    if failures:
        for failure in failures:
            print(f"probe: FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
    print("probe: OK, the fixture refuses tokens without a channel binding")


if __name__ == "__main__":
    main()
