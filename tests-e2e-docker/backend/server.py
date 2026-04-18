#!/usr/bin/env python3
"""Simple HTTP/HTTPS backend for Lorica e2e tests.

Responds with backend identity on all paths, supports /healthz for HTTP health checks.
Set TLS_ENABLED=1 to serve HTTPS with a self-signed certificate.
"""

import json
import os
import ssl
import subprocess
import tempfile
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

BACKEND_ID = os.environ.get("BACKEND_ID", "unknown")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))
TLS_ENABLED = os.environ.get("TLS_ENABLED", "") == "1"
# When set, the backend acts as a forward-auth gate: every GET returns
# 200 iff the request carries `Authorization: Bearer good-token`, else
# 401. Used by the Lorica e2e forward_auth test (TESTING-GUIDE #4).
FORWARD_AUTH_MODE = os.environ.get("FORWARD_AUTH_MODE", "") == "1"
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "good-token")

request_count = 0
mirror_count = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global request_count, mirror_count
        request_count += 1
        # Track requests carrying the Lorica mirror marker so the
        # mirroring e2e test can confirm the shadow backend actually
        # saw a cloned request vs. never being hit.
        if self.headers.get("X-Lorica-Mirror", "") == "1":
            mirror_count += 1

        # Forward-auth gate mode: 200 if Bearer token matches, else 401.
        # Placed at the top of do_GET so `/healthz` still works for
        # compose healthchecks (it falls through the branch below).
        if FORWARD_AUTH_MODE and self.path != "/healthz":
            auth = self.headers.get("Authorization", "")
            if auth == f"Bearer {AUTH_TOKEN}":
                # Echo the user identity as Remote-User so Lorica's
                # forward-auth filter can relay it to the upstream.
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Remote-User", "testuser")
                self.send_header("Remote-Groups", "admins")
                self.send_header("Content-Length", "17")
                self.end_headers()
                self.wfile.write(b'{"auth":"granted"}'[:17])
                return
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "16")
            self.end_headers()
            self.wfile.write(b'{"auth":"denied"}'[:16])
            return

        if self.path == "/healthz":
            self._json_response(200, {
                "status": "healthy",
                "backend": BACKEND_ID,
                "tls": TLS_ENABLED,
                "uptime": time.monotonic(),
            })
        elif self.path == "/identity":
            self._json_response(200, {
                "backend": BACKEND_ID,
                "requests": request_count,
                "tls": TLS_ENABLED,
            })
        elif self.path == "/count":
            # Introspection endpoint for mirror tests: exposes the
            # per-process counters so the test-runner can assert the
            # shadow actually received the cloned request.
            self._json_response(200, {
                "backend": BACKEND_ID,
                "requests": request_count,
                "mirror_requests": mirror_count,
            })
        elif self.path == "/reset":
            request_count = 0
            mirror_count = 0
            self._json_response(200, {"reset": True})
        elif self.path == "/slow":
            time.sleep(3)
            self._json_response(200, {"backend": BACKEND_ID, "slow": True})
        elif self.path.startswith("/echo"):
            self._echo_response()
        elif self.path == "/error":
            self._json_response(500, {"error": "intentional error"})
        else:
            self._json_response(200, {
                "message": f"Hello from {BACKEND_ID}",
                "path": self.path,
                "backend": BACKEND_ID,
                "tls": TLS_ENABLED,
                "request_number": request_count,
            })

    def do_POST(self):
        if self.path.startswith("/echo"):
            self._echo_response()
            return

        global request_count
        request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        received_headers = {}
        for key, value in self.headers.items():
            received_headers[key.lower()] = value

        self._json_response(200, {
            "backend": BACKEND_ID,
            "method": "POST",
            "path": self.path,
            "body_length": len(body),
            "received_headers": received_headers,
        })

    def do_HEAD(self):
        if self.path.startswith("/echo"):
            self._echo_response()
        else:
            self.do_GET()

    def do_PUT(self):
        if self.path.startswith("/echo"):
            self._echo_response()
        else:
            self.do_POST()

    def do_DELETE(self):
        if self.path.startswith("/echo"):
            self._echo_response()
        else:
            self._json_response(200, {"deleted": True, "backend": BACKEND_ID})

    def _echo_response(self):
        global request_count
        request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        received_headers = {}
        for key, value in self.headers.items():
            received_headers[key.lower()] = value

        query = ""
        path = self.path
        if "?" in self.path:
            path, query = self.path.split("?", 1)

        self._json_response(200, {
            "method": self.command,
            "path": path,
            "query": query,
            "received_headers": received_headers,
            "body": body,
            "backend": BACKEND_ID,
            "tls": TLS_ENABLED,
        })

    def _json_response(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Id", BACKEND_ID)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def generate_self_signed_cert():
    """Generate a self-signed cert+key pair using openssl."""
    cert_dir = tempfile.mkdtemp()
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "1", "-nodes",
        "-subj", f"/CN={BACKEND_ID}",
    ], check=True, capture_output=True)
    return cert_file, key_file


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), Handler)

    if TLS_ENABLED:
        cert_file, key_file = generate_self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        print(f"Backend {BACKEND_ID} listening on HTTPS port {LISTEN_PORT}")
    else:
        print(f"Backend {BACKEND_ID} listening on HTTP port {LISTEN_PORT}")

    server.serve_forever()
