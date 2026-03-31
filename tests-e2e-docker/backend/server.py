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

request_count = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global request_count
        request_count += 1

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
        elif self.path == "/slow":
            time.sleep(3)
            self._json_response(200, {"backend": BACKEND_ID, "slow": True})
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
        global request_count
        request_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        self._json_response(200, {
            "backend": BACKEND_ID,
            "method": "POST",
            "path": self.path,
            "body_length": len(body),
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
