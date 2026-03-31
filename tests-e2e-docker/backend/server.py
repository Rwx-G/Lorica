#!/usr/bin/env python3
"""Simple HTTP backend for Lorica e2e tests.

Responds with backend identity on all paths, supports /healthz for HTTP health checks.
"""

import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

BACKEND_ID = os.environ.get("BACKEND_ID", "unknown")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))

# Track request count for round-robin verification
request_count = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global request_count
        request_count += 1

        if self.path == "/healthz":
            self._json_response(200, {
                "status": "healthy",
                "backend": BACKEND_ID,
                "uptime": time.monotonic(),
            })
        elif self.path == "/identity":
            self._json_response(200, {
                "backend": BACKEND_ID,
                "requests": request_count,
            })
        elif self.path == "/slow":
            # Simulate slow response for degraded health check testing
            time.sleep(3)
            self._json_response(200, {"backend": BACKEND_ID, "slow": True})
        elif self.path == "/error":
            self._json_response(500, {"error": "intentional error"})
        else:
            self._json_response(200, {
                "message": f"Hello from {BACKEND_ID}",
                "path": self.path,
                "backend": BACKEND_ID,
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
        # Quiet logging
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"Backend {BACKEND_ID} listening on port {LISTEN_PORT}")
    server.serve_forever()
