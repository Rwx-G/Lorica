#!/usr/bin/env python3
"""A PROXY protocol client for the Story 12.8 scenarios (Story 12.12 Lot H),
standard library only. It stands in for the L4 load balancer: no HAProxy
image.

`request` opens one TCP connection, writes a PROXY v1 or v2 header
carrying the chosen source (or none, `--version none`), then speaks
HTTP/1.1 over the same socket, through TLS with `--tls` (SNI from
`--sni`, the certificate not verified: the routes use self-signed ones).
It prints one JSON object:

- `{"outcome": "response", "status": 200, "headers": {...}, "body": "..."}`
  when the server answered;
- `{"outcome": "disconnected", "error": "..."}` when it closed or reset
  the connection without a byte of response, which is how Lorica refuses
  a PROXY header (no 400, no TLS alert).

`self-ip` prints the local address this container uses to reach a host,
the address Lorica sees as the socket peer.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import struct
import sys

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def v1_header(src: str, sport: int, dst: str, dport: int) -> bytes:
    family = "TCP6" if ipaddress.ip_address(src).version == 6 else "TCP4"
    return f"PROXY {family} {src} {dst} {sport} {dport}\r\n".encode("ascii")


def v2_header(src: str, sport: int, dst: str, dport: int) -> bytes:
    source = ipaddress.ip_address(src)
    destination = ipaddress.ip_address(dst)
    if source.version != destination.version:
        raise SystemExit("v2: source and destination must be one family")
    # Version 2, command PROXY; AF_INET or AF_INET6 over STREAM.
    family = 0x11 if source.version == 4 else 0x21
    addresses = source.packed + destination.packed + struct.pack("!HH", sport, dport)
    return V2_SIGNATURE + bytes([0x21, family]) + struct.pack("!H", len(addresses)) + addresses


def read_response(sock: socket.socket | ssl.SSLSocket) -> bytes:
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
        if not chunk:
            break
        data += chunk
    return bytes(data)


def parse_response(raw: bytes) -> dict:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return {
        "outcome": "response",
        "status": status,
        "headers": headers,
        "body": body.decode("utf-8", errors="replace"),
    }


def request(args: argparse.Namespace) -> dict:
    host, port = args.target.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=args.timeout)
    try:
        if args.version == "1":
            sock.sendall(v1_header(args.src, args.src_port, args.dst, args.dst_port))
        elif args.version == "2":
            sock.sendall(v2_header(args.src, args.src_port, args.dst, args.dst_port))
        conn: socket.socket | ssl.SSLSocket = sock
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            conn = context.wrap_socket(sock, server_hostname=args.sni or args.host)
        lines = [
            f"GET {args.path} HTTP/1.1",
            f"Host: {args.host}",
            "Connection: close",
            "User-Agent: lorica-e2e-proxy-protocol",
        ]
        lines.extend(args.header)
        conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        raw = read_response(conn)
    except (ConnectionError, ssl.SSLError, socket.timeout, OSError) as error:
        return {"outcome": "disconnected", "error": f"{type(error).__name__}: {error}"}
    finally:
        sock.close()
    if not raw:
        return {"outcome": "disconnected", "error": "closed without a response"}
    return parse_response(raw)


def self_ip(args: argparse.Namespace) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((args.host, 9))
        return probe.getsockname()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    req = commands.add_parser("request", help="one request behind an optional PROXY header")
    req.add_argument("--target", required=True, help="host:port of the listener")
    req.add_argument("--version", choices=["1", "2", "none"], required=True)
    req.add_argument("--src", default="203.0.113.7", help="carried source address")
    req.add_argument("--src-port", type=int, default=40000)
    req.add_argument("--dst", default="192.0.2.1", help="carried destination address")
    req.add_argument("--dst-port", type=int, default=443)
    req.add_argument("--tls", action="store_true")
    req.add_argument("--sni", default="")
    req.add_argument("--host", required=True, help="the Host header")
    req.add_argument("--path", default="/")
    req.add_argument("--header", action="append", default=[], help="an extra request header line")
    req.add_argument("--timeout", type=float, default=5.0)

    own = commands.add_parser("self-ip", help="the local address used to reach a host")
    own.add_argument("--host", required=True)

    args = parser.parse_args()
    if args.command == "self-ip":
        print(self_ip(args))
        return 0
    json.dump(request(args), sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
