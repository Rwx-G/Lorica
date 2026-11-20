#!/usr/bin/env python3
"""TLS backends and clients for the L4 phase and the stream sections of
the `acme` and `cluster` smokes (Story 12.12 Lot D, the design of Story
12.4 Lot H), standard library only.

Backends:

  raw    Behind a passthrough stream. Reads the client's first flight up
         to the end of the ClientHello (one handshake message over one or
         more TLS records), answers `name=<name> sha256=<hex of every
         byte read> bytes=<n>` and closes. The client hashes what it
         sent, so equal hashes prove the stream forwarded the ClientHello
         unchanged.
  tls    Behind an upstream-TLS stream. Its certificate, key and the CA
         it verifies client certificates against (`backend.crt`,
         `backend.key`, `client-ca.crt`) are read from --pki at each
         connection, so a scenario can copy them in after the container
         starts. After the handshake it answers `name=<name> sni=<server
         name> client=<client certificate CN or none>`, then echoes.

Clients (--host, --port; certificates are not verified unless a CA is
given: what is asserted is which certificate was presented):

  hello  Builds a ClientHello (--sni, --alpn), sends it as the first
         flight, prints the backend's line (or `closed`) and
         ` sent=<SHA-256 of what was sent>`.
  term   Completes a handshake (--sni, optionally --cert/--key), sends a
         line, prints the first line answered (or `refused <reason>`)
         and ` fp=<SHA-256 of the server certificate>`.
  held   Completes a handshake, then sends `ping <n>` every 0.5 s and
         expects it echoed back (a plain echo backend) until --stop
         exists, keeping {fp, pings, failures, error} in --out as JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import ssl
import struct
import threading
import time
from pathlib import Path


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed in the ClientHello")
        buf += chunk
    return buf


def read_client_hello(conn: socket.socket) -> bytes:
    """Every byte of the records carrying the first handshake message."""
    raw = b""
    handshake = b""
    while len(handshake) < 4 or len(handshake) < 4 + int.from_bytes(handshake[1:4], "big"):
        header = read_exact(conn, 5)
        length = struct.unpack("!H", header[3:5])[0]
        body = read_exact(conn, length)
        raw += header + body
        if header[0] != 22:
            break
        handshake += body
    return raw


def read_line(s: socket.socket) -> str:
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0].decode(errors="replace").strip()


def serve_raw(conn: socket.socket, name: str) -> None:
    with conn:
        try:
            hello = read_client_hello(conn)
            digest = hashlib.sha256(hello).hexdigest()
            conn.sendall(f"name={name} sha256={digest} bytes={len(hello)}\n".encode())
        except OSError:
            return


def serve_tls(conn: socket.socket, name: str, pki: Path) -> None:
    sni: list[str] = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(pki / "backend.crt", pki / "backend.key")
        context.load_verify_locations(pki / "client-ca.crt")
    except OSError:
        conn.close()
        return
    context.verify_mode = ssl.CERT_OPTIONAL
    context.sni_callback = lambda _sock, server_name, _ctx: sni.append(server_name or "")
    try:
        with context.wrap_socket(conn, server_side=True) as tls:
            cert = tls.getpeercert()
            client = "none"
            for rdn in (cert or {}).get("subject", ()):
                for key, value in rdn:
                    if key == "commonName":
                        client = value
            tls.sendall(f"name={name} sni={sni[0] if sni else 'none'} client={client}\n".encode())
            while True:
                data = tls.recv(65536)
                if not data:
                    return
                tls.sendall(data)
    except (OSError, ssl.SSLError):
        return


def serve(args: argparse.Namespace) -> None:
    # PID 1 ignores a signal it has no handler for.
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("::", args.port))
    listener.listen(256)
    while True:
        conn, _ = listener.accept()
        if args.cmd == "raw":
            target, extra = serve_raw, (args.name,)
        else:
            target, extra = serve_tls, (args.name, Path(args.pki))
        threading.Thread(target=target, args=(conn, *extra), daemon=True).start()


def client_context(args: argparse.Namespace) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if getattr(args, "cert", None):
        ctx.load_cert_chain(args.cert, args.key)
    if getattr(args, "alpn", None):
        ctx.set_alpn_protocols(args.alpn.split(","))
    return ctx


def hello(args: argparse.Namespace) -> None:
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = client_context(args).wrap_bio(incoming, outgoing, server_hostname=args.sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    first_flight = outgoing.read()
    with socket.create_connection((args.host, args.port), timeout=10) as s:
        s.sendall(first_flight)
        line = read_line(s) or "closed"
    print(f"{line} sent={hashlib.sha256(first_flight).hexdigest()}")


def handshake(args: argparse.Namespace) -> tuple[ssl.SSLSocket, str]:
    raw = socket.create_connection((args.host, args.port), timeout=10)
    tls = client_context(args).wrap_socket(raw, server_hostname=args.sni)
    return tls, hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def term(args: argparse.Namespace) -> None:
    try:
        tls, fp = handshake(args)
        with tls:
            tls.sendall(b"hello\n")
            line = read_line(tls) or "refused closed"
        print(f"{line} fp={fp}")
    except (OSError, ssl.SSLError) as e:
        print(f"refused {type(e).__name__}")


def held(args: argparse.Namespace) -> None:
    status: dict = {"fp": None, "pings": 0, "failures": 0, "error": None}

    def save() -> None:
        tmp = Path(args.out + ".tmp")
        tmp.write_text(json.dumps(status))
        tmp.replace(args.out)

    try:
        tls, status["fp"] = handshake(args)
    except (OSError, ssl.SSLError) as e:
        status["error"] = f"{type(e).__name__}: {e}"
        save()
        return
    save()
    n = 0
    while not Path(args.stop).exists():
        n += 1
        try:
            tls.sendall(f"ping {n}\n".encode())
            if read_line(tls) == f"ping {n}":
                status["pings"] += 1
            else:
                status["failures"] += 1
        except (OSError, ssl.SSLError) as e:
            status["failures"] += 1
            status["error"] = f"{type(e).__name__}: {e}"
        save()
        time.sleep(0.5)
    tls.close()


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("raw", "tls"):
        s = sub.add_parser(name)
        s.add_argument("--name", required=True)
        s.add_argument("--port", type=int, default=9443)
        s.add_argument("--pki", default="/tmp/pki", help="tls: directory of the PEM files")
    for name in ("hello", "term", "held"):
        c = sub.add_parser(name)
        c.add_argument("--host", required=True)
        c.add_argument("--port", type=int, required=True)
        c.add_argument("--sni", required=True)
        if name == "hello":
            c.add_argument("--alpn", help="comma-separated protocols to offer")
        else:
            c.add_argument("--cert", help="client certificate (PEM)")
            c.add_argument("--key", help="its private key (PEM)")
        if name == "held":
            c.add_argument("--stop", required=True)
            c.add_argument("--out", required=True)
    args = p.parse_args()
    handlers = {"raw": serve, "tls": serve, "hello": hello, "term": term, "held": held}
    handlers[args.cmd](args)


if __name__ == "__main__":
    main()
