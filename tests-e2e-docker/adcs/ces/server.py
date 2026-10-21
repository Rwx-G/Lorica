"""The CES fixture of the AD CS harness (Story 13.1 Lot 4).

An HTTPS server for ces.corp.example.org that authenticates the way an
IIS CES application with Extended Protection set to Required does:
Kerberos SPNEGO, and a context is accepted only when it is bound to the
TLS channel. Port 443 serves a certificate signed under SHA-256, port
8443 one signed under SHA-512 (IV2).

Behaviour is chosen per request by the URL path, so tests can run in
any order and nothing is shared between them:

    /<outcome>/<mutual>/CES

    outcome: issued | pending | denied | permission | template | nodetail
    mutual:  valid  | none    | forged

`mutual` decides the WWW-Authenticate token of the authenticated answer:
the acceptor's real output token, no token, or that token with its last
byte flipped. `outcome` decides the answer to a POSTed enrollment
request. An unknown path is answered as issued/valid.
"""

import base64
import http.server
import logging
import ssl
import sys
import threading
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import gssapi
import gssapi.raw
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from harness_ca import HarnessPki, oid, random_request_id, tls_server_end_point

HARNESS_DIR = Path("/harness")
KEYTAB = HARNESS_DIR / "ces.keytab"
CA_DIR = HARNESS_DIR / "ca"
TLS_DIR = Path("/run/ces-tls")

SOAP = "http://www.w3.org/2003/05/soap-envelope"
WSA = "http://www.w3.org/2005/08/addressing"
WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
ENROLLMENT = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
RST_ACTION = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
RSTRC_ACTION = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
FAULT_ACTION = "http://www.w3.org/2005/08/addressing/soap/fault"
X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
PKCS7 = WSSE + "#PKCS7"
BASE64 = WSSE + "#base64binary"

# The CertificateTemplate name-value pair (MS-WCCE 2.2.2.7.10). A CA
# given no template in the request refuses it as an unknown template;
# so does this fixture.
TEMPLATE_ATTRIBUTE_OID_DER = oid("1.3.6.1.4.1.311.13.2.1")

CHANNEL_BOUND = int(gssapi.raw.RequirementFlag.channel_bound)

OUTCOMES = {"issued", "pending", "denied", "permission", "template", "nodetail"}
MUTUAL_MODES = {"valid", "none", "forged"}

log = logging.getLogger("ces")


def wait_for_keytab():
    deadline = time.monotonic() + 60
    while not KEYTAB.exists():
        if time.monotonic() > deadline:
            raise SystemExit(f"{KEYTAB} never appeared: is the KDC up?")
        time.sleep(0.5)


def modes(path):
    parts = [part for part in path.split("?")[0].split("/") if part]
    outcome = parts[0] if len(parts) >= 1 and parts[0] in OUTCOMES else "issued"
    mutual = parts[1] if len(parts) >= 2 and parts[1] in MUTUAL_MODES else "valid"
    return outcome, mutual


def b64(data):
    return base64.b64encode(data).decode("ascii")


def wrapped_b64(data):
    """Base64 wrapped at 64 columns with CR LF, as Windows sends it."""
    text = b64(data)
    return "\r\n".join(text[i : i + 64] for i in range(0, len(text), 64))


def envelope(action, relates_to, body):
    relates = f"<a:RelatesTo>{relates_to}</a:RelatesTo>" if relates_to else ""
    return (
        f'<s:Envelope xmlns:s="{SOAP}" xmlns:a="{WSA}">'
        f'<s:Header><a:Action s:mustUnderstand="1">{action}</a:Action>{relates}</s:Header>'
        f"<s:Body>{body}</s:Body></s:Envelope>"
    )


def rstr(inner):
    return (
        f'<RequestSecurityTokenResponseCollection xmlns="{WST}">'
        f"<RequestSecurityTokenResponse><TokenType>{X509V3}</TokenType>{inner}"
        f"</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>"
    )


def binary_token(value_type, der):
    return (
        f'<BinarySecurityToken ValueType="{value_type}" EncodingType="{BASE64}" '
        f'xmlns="{WSSE}">{wrapped_b64(der)}</BinarySecurityToken>'
    )


def fault(reason, detail):
    detail_xml = ""
    if detail is not None:
        error_code, invalid_request, request_id = detail
        signed = error_code - (1 << 32) if error_code & 0x80000000 else error_code
        detail_xml = (
            f'<s:Detail><CertificateEnrollmentWSDetail xmlns="{ENROLLMENT}" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<BinaryResponse xsi:nil="true"/><ErrorCode>{signed}</ErrorCode>'
            f"<InvalidRequest>{'true' if invalid_request else 'false'}</InvalidRequest>"
            f"<RequestID>{request_id}</RequestID>"
            f"</CertificateEnrollmentWSDetail></s:Detail>"
        )
    return (
        f"<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>"
        f'<s:Reason><s:Text xml:lang="en-US">{reason}</s:Text></s:Reason>'
        f"{detail_xml}</s:Fault>"
    )


class Enrollment:
    def __init__(self, pki):
        self.pki = pki

    def answer(self, outcome, body):
        """(status, SOAP body) for a POSTed request."""
        try:
            message_id, csr_der = self.read_request(body)
        except ValueError as err:
            log.warning("malformed enrollment request: %s", err)
            return 500, envelope(FAULT_ACTION, None, fault(f"malformed request: {err}", None))
        if TEMPLATE_ATTRIBUTE_OID_DER not in csr_der:
            return 500, envelope(
                FAULT_ACTION,
                message_id,
                fault("no certificate template in the request", (0x80094800, False, 0)),
            )
        request_id = random_request_id()
        if outcome == "issued":
            return 200, envelope(RSTRC_ACTION, message_id, self.issued(csr_der, request_id))
        if outcome == "pending":
            return 200, envelope(RSTRC_ACTION, message_id, self.pending(request_id))
        if outcome == "denied":
            # The outcome keys on InvalidRequest; the code is incidental.
            detail = (0x80070005, True, request_id)
            return 500, envelope(FAULT_ACTION, message_id, fault("Denied by Policy Module", detail))
        if outcome == "permission":
            detail = (0x80094012, False, request_id)
            return 500, envelope(
                FAULT_ACTION,
                message_id,
                fault("The permissions on the certificate template do not allow enrollment", detail),
            )
        if outcome == "template":
            detail = (0x80094800, False, request_id)
            return 500, envelope(
                FAULT_ACTION,
                message_id,
                fault("The requested certificate template is not supported by this CA", detail),
            )
        return 500, envelope(FAULT_ACTION, message_id, fault("An internal error occurred", None))

    @staticmethod
    def read_request(body):
        try:
            root = ElementTree.fromstring(body)
        except ElementTree.ParseError as err:
            raise ValueError(f"not XML: {err}") from err
        action = root.find(f"{{{SOAP}}}Header/{{{WSA}}}Action")
        if action is None or (action.text or "").strip() != RST_ACTION:
            raise ValueError("the Action is not the MS-WSTEP RST action")
        message_id = root.find(f"{{{SOAP}}}Header/{{{WSA}}}MessageID")
        rst = root.find(f"{{{SOAP}}}Body/{{{WST}}}RequestSecurityToken")
        if rst is None:
            raise ValueError("no RequestSecurityToken")
        token = rst.find(f"{{{WSSE}}}BinarySecurityToken")
        if token is None or not (token.text or "").strip():
            raise ValueError("no BinarySecurityToken")
        try:
            csr_der = base64.b64decode("".join(token.text.split()), validate=True)
        except ValueError as err:
            raise ValueError(f"the token is not base64: {err}") from err
        return (message_id.text if message_id is not None else None), csr_der

    def issued(self, csr_der, request_id):
        csr = x509.load_der_x509_csr(csr_der)
        if not csr.is_signature_valid:
            raise ValueError("the CSR signature does not verify")
        try:
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            sans = None
        leaf = self.pki.issue(csr.subject, csr.public_key(), sans, True, hashes.SHA256())
        cmc = self.pki.cmc_response([self.pki.root, leaf, self.pki.issuing])
        inner = (
            f'<DispositionMessage xml:lang="en-US" xmlns="{ENROLLMENT}">Issued</DispositionMessage>'
            + binary_token(PKCS7, cmc)
            + "<RequestedSecurityToken>"
            + binary_token(X509V3, leaf.public_bytes(serialization.Encoding.DER))
            + "</RequestedSecurityToken>"
            + f'<RequestID xmlns="{ENROLLMENT}">{request_id}</RequestID>'
        )
        return rstr(inner)

    def pending(self, request_id):
        # MS-WSTEP has no pending example: a reference instead of a
        # certificate, and a RequestID, which is what the client keys on.
        cmc = self.pki.cmc_response([self.pki.issuing, self.pki.root])
        inner = (
            f'<DispositionMessage xml:lang="en-US" xmlns="{ENROLLMENT}">Taken Under Submission</DispositionMessage>'
            + binary_token(PKCS7, cmc)
            + "<RequestedSecurityToken>"
            + f'<SecurityTokenReference xmlns="{WSSE}"><Reference URI="{request_id}"/></SecurityTokenReference>'
            + "</RequestedSecurityToken>"
            + f'<RequestID xmlns="{ENROLLMENT}">{request_id}</RequestID>'
        )
        return rstr(inner)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LoricaHarnessCES"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.server.label, fmt % args)

    def respond(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def refuse(self, reason):
        """401 with a bare Negotiate challenge, as IIS answers. The reason
        in the body is for the probe client, which asserts on it."""
        log.info("%s refused: %s", self.server.label, reason)
        self.respond(
            401,
            reason.encode("utf-8"),
            [("WWW-Authenticate", "Negotiate"), ("Content-Type", "text/plain")],
        )

    def authenticate(self):
        """The acceptor's output token when the request carries a context
        bound to this listener's certificate, None after a refusal."""
        header = self.headers.get("Authorization", "")
        scheme, _, credentials = header.partition(" ")
        if scheme.lower() != "negotiate" or not credentials.strip():
            self.refuse("no Negotiate credentials")
            return None
        try:
            token = base64.b64decode(credentials.strip(), validate=True)
        except ValueError:
            self.refuse("the Negotiate token is not base64")
            return None
        bindings = gssapi.raw.ChannelBindings(application_data=self.server.channel_binding)
        context = gssapi.SecurityContext(
            creds=self.server.acceptor_credentials, usage="accept", channel_bindings=bindings
        )
        # python-gssapi's step() keeps a failure and raises it on the next
        # attribute access, so every read of the context sits in the try.
        try:
            output = context.step(token)
            complete = context.complete
            flags = int(context.actual_flags) if complete else 0
        except gssapi.exceptions.GSSError as err:
            self.refuse(f"GSS-API refused the token: {err}")
            return None
        if not complete:
            self.refuse("the security context is not complete after one token")
            return None
        # An MIT acceptor given bindings still accepts a token that carries
        # none; only the returned flag tells the two apart. Without this
        # check IV1's third leg would pass while enforcing nothing.
        if not flags & CHANNEL_BOUND:
            self.refuse("channel binding missing: GSS_C_CHANNEL_BOUND_FLAG not set")
            return None
        log.info("%s authenticated %s", self.server.label, context.initiator_name)
        return output or b""

    def mutual_header(self, mutual, output):
        if mutual == "none" or not output:
            return []
        if mutual == "forged":
            # The last byte sits in the integrity checksum of the AP-REP or
            # of the mechListMIC: a client that verifies the token must
            # reject it on cryptographic grounds, not on its framing.
            output = output[:-1] + bytes([output[-1] ^ 0x01])
        return [("WWW-Authenticate", f"Negotiate {b64(output)}")]

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        self.read_body()
        _, mutual = modes(self.path)
        output = self.authenticate()
        if output is None:
            return
        self.respond(
            405,
            b"Method Not Allowed",
            self.mutual_header(mutual, output) + [("Content-Type", "text/plain"), ("Allow", "POST")],
        )

    def do_POST(self):
        body = self.read_body()
        outcome, mutual = modes(self.path)
        output = self.authenticate()
        if output is None:
            return
        try:
            status, soap = self.server.enrollment.answer(outcome, body)
        except ValueError as err:
            status, soap = 500, envelope(FAULT_ACTION, None, fault(str(err), None))
        self.respond(
            status,
            soap.encode("utf-8"),
            self.mutual_header(mutual, output)
            + [("Content-Type", "application/soap+xml; charset=utf-8")],
        )


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client that closes right after the handshake (the healthcheck,
        # the probe reading the certificate) is not a fixture failure.
        if isinstance(sys.exc_info()[1], (ConnectionError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


def serve(label, port, chain_path, key_path, leaf_der, acceptor_credentials, enrollment):
    server = Server(("0.0.0.0", port), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(chain_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.label = label
    server.channel_binding = tls_server_end_point(leaf_der)
    server.acceptor_credentials = acceptor_credentials
    server.enrollment = enrollment
    log.info("%s listening on %d", label, port)
    server.serve_forever()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    wait_for_keytab()
    pki = HarnessPki()
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    listeners = [
        ("sha256", 443, *pki.server_identity(hashes.SHA256(), TLS_DIR, "sha256")),
        ("sha512", 8443, *pki.server_identity(hashes.SHA512(), TLS_DIR, "sha512")),
    ]
    acceptor_credentials = gssapi.Credentials(usage="accept", store={"keytab": str(KEYTAB)})
    enrollment = Enrollment(pki)
    threads = [
        threading.Thread(
            target=serve,
            args=(*listener, acceptor_credentials, enrollment),
            daemon=True,
        )
        for listener in listeners
    ]
    for thread in threads:
        thread.start()
    CA_DIR.mkdir(parents=True, exist_ok=True)
    pki.write_issuing_key(CA_DIR)
    pki.write_public(CA_DIR)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
