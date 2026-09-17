#!/usr/bin/env python3
"""A tiny OIDC issuer for the Lorica automation e2e (Story 10.5).

Reproduces `lorica-api/src/automation/oidc/test_support.rs` over HTTPS:
an RSA signing key generated at start, the key set GitLab would publish
at `/oauth/discovery/keys`, a counter of key-set fetches, and a mint
endpoint so the test runner can ask for valid, expired, wrong-audience,
wrong-project, replayed, HS256 and `alg: none` tokens without ever
holding a private key itself.

Endpoints:
  GET  /healthz                          liveness, current kid
  GET  /.well-known/openid-configuration issuer + jwks_uri
  GET  /oauth/discovery/keys             the JWKS (counted; 503 in outage)
  GET  /fetches                          {"fetches", "last_fetch_epoch", "kid", "outage"}
  POST /mint                             {"claims": {...}, "alg", "kid", "key"} -> {"token", "kid", "jti"}
  POST /mint-batch                       {"count": N} -> N tokens under distinct kids
                                         signed by a key the JWKS never publishes
  POST /rotate                           new signing key, new kid; the old key is
                                         dropped from the JWKS
  POST /outage                           {"enabled": bool} -> the JWKS answers 503

Signing goes through the openssl CLI so the image needs nothing beyond
the Python standard library; the same base image as `backend/`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ISSUER_URL = os.environ.get("OIDC_ISSUER_URL", "https://oidc-issuer")
AUDIENCE = os.environ.get("OIDC_AUDIENCE", "lorica-e2e")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "443"))
TLS_CERT = Path(os.environ.get("TLS_CERT", "/shared/oidc-issuer.pem"))
TLS_KEY = Path(os.environ.get("TLS_KEY", "/shared/oidc-issuer.key"))
JWKS_PATH = "/oauth/discovery/keys"
MINT_BATCH_CAP = 5000

logging.basicConfig(level=logging.INFO, format="[oidc-issuer] %(message)s")
LOG = logging.getLogger("oidc-issuer")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def compact_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def say(message: str) -> None:
    LOG.info(message)


class SigningKey:
    """One RSA-2048 key, named by its kid, as the issuer publishes it."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.key_path = Path(tempfile.mkdtemp()) / "key.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(self.key_path), "2048"],
            check=True,
            capture_output=True,
        )
        modulus = subprocess.run(
            ["openssl", "rsa", "-in", str(self.key_path), "-noout", "-modulus"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.n = bytes.fromhex(modulus.split("=", 1)[1])
        self.e = (65537).to_bytes(3, "big")
        # SubjectPublicKeyInfo DER: what a confused verifier would use
        # as an HMAC secret (the IV4 forgery).
        self.public_der = subprocess.run(
            ["openssl", "rsa", "-in", str(self.key_path), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout

    def jwk(self) -> dict:
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url(self.n),
            "e": b64url(self.e),
        }

    def sign(self, message: bytes) -> bytes:
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key_path)],
            input=message,
            check=True,
            capture_output=True,
        ).stdout


def new_kid() -> str:
    return "e2e-" + secrets.token_hex(6)


class Issuer:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.current = SigningKey(new_kid())
        self.unpublished: SigningKey | None = None
        self.fetches = 0
        self.last_fetch_epoch = 0
        self.outage = False

    def default_claims(self) -> dict[str, Any]:
        now = int(time.time())
        return {
            "iss": ISSUER_URL,
            "aud": AUDIENCE,
            "sub": "project_path:acme/web:ref_type:branch:ref:main",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "project_path": "acme/web",
            "namespace_path": "acme",
            "ref": "main",
            "ref_protected": "true",
            "environment": "review/mr-42",
            "environment_protected": "false",
            "deployment_tier": "development",
            "pipeline_id": "1234",
            "job_id": "5678",
            "user_login": "dev",
        }

    def mint(self, body: dict[str, Any]) -> dict[str, Any]:
        claims = self.default_claims()
        for name, value in (body.get("claims") or {}).items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        alg = body.get("alg", "RS256")
        with self.lock:
            key = self.current
            if body.get("key") == "unpublished":
                key = self.unpublished_key()
        kid = body.get("kid") or key.kid
        header = {"alg": alg, "typ": "JWT", "kid": kid}
        message = f"{b64url(compact_json(header))}.{b64url(compact_json(claims))}".encode("ascii")
        if alg == "RS256":
            signature = key.sign(message)
        elif alg == "HS256":
            signature = hmac.new(key.public_der, message, hashlib.sha256).digest()
        elif alg == "none":
            signature = b""
        else:
            raise ValueError(f"unsupported alg {alg!r}")
        return {
            "token": f"{message.decode('ascii')}.{b64url(signature)}",
            "kid": kid,
            "jti": claims.get("jti"),
            "alg": alg,
        }

    def unpublished_key(self) -> SigningKey:
        # Called under self.lock. A key the JWKS never carries, so a
        # token under it can only ever be an unknown kid (IV5).
        if self.unpublished is None:
            self.unpublished = SigningKey("unpublished-" + secrets.token_hex(4))
        return self.unpublished

    def mint_batch(self, count: int) -> list[str]:
        with self.lock:
            key = self.unpublished_key()
        prefix = secrets.token_hex(3)
        tokens = []
        for index in range(count):
            tokens.append(
                self.mint({"key": "unpublished", "kid": f"unknown-{prefix}-{index}"})["token"]
            )
        return tokens

    def rotate(self) -> dict[str, str]:
        fresh = SigningKey(new_kid())
        with self.lock:
            previous = self.current.kid
            self.current = fresh
        return {"kid": fresh.kid, "previous": previous}

    def jwks(self) -> tuple[int, dict[str, Any]]:
        with self.lock:
            self.fetches += 1
            self.last_fetch_epoch = int(time.time())
            if self.outage:
                return 503, {"error": "issuer outage (e2e fixture)"}
            return 200, {"keys": [self.current.jwk()]}

    def stats(self) -> dict[str, Any]:
        with self.lock:
            return {
                "fetches": self.fetches,
                "last_fetch_epoch": self.last_fetch_epoch,
                "kid": self.current.kid,
                "outage": self.outage,
            }


ISSUER = Issuer()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json(200, {"status": "ok", "kid": ISSUER.stats()["kid"]})
        elif path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": ISSUER_URL,
                    "jwks_uri": ISSUER_URL + JWKS_PATH,
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        elif path == JWKS_PATH:
            status, body = ISSUER.jwks()
            say(f"JWKS fetch #{ISSUER.stats()['fetches']} from {self.client_address[0]} -> {status}")
            self._json(status, body)
        elif path == "/fetches":
            self._json(200, ISSUER.stats())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            self._json(400, {"error": "body is not JSON"})
            return
        if path == "/mint":
            try:
                minted = ISSUER.mint(body)
            except ValueError as e:
                self._json(400, {"error": str(e)})
                return
            say(f"minted {minted['alg']} token kid={minted['kid']} jti={minted['jti']}")
            self._json(200, minted)
        elif path == "/mint-batch":
            count = max(1, min(int(body.get("count", 1)), MINT_BATCH_CAP))
            started = time.monotonic()
            tokens = ISSUER.mint_batch(count)
            say(f"minted a batch of {count} unknown-kid tokens in {time.monotonic() - started:.1f}s")
            self._json(200, {"count": count, "tokens": tokens})
        elif path == "/rotate":
            rotated = ISSUER.rotate()
            say(f"rotated signing key: {rotated['previous']} -> {rotated['kid']}")
            self._json(200, rotated)
        elif path == "/outage":
            enabled = bool(body.get("enabled", True))
            with ISSUER.lock:
                ISSUER.outage = enabled
            say(f"outage {'on' if enabled else 'off'}")
            self._json(200, {"outage": enabled})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, status: int, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def wait_for_tls_material() -> None:
    for _ in range(120):
        if TLS_CERT.is_file() and TLS_KEY.is_file():
            return
        time.sleep(1)
    raise SystemExit(f"{TLS_CERT} / {TLS_KEY} never appeared (acme-ca-init failed?)")


if __name__ == "__main__":
    wait_for_tls_material()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(TLS_CERT), str(TLS_KEY))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    say(f"issuer {ISSUER_URL} (aud {AUDIENCE}) listening on HTTPS {LISTEN_PORT}, kid {ISSUER.current.kid}")
    server.serve_forever()
