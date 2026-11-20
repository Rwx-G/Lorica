#!/usr/bin/env python3
"""A TCP backend for the L4 phase (Story 12.12 Lot C, the design of Story
12.3 Lot G), standard library only.

On every connection it waits for the client's first bytes, then:

- an HTTP request (`GET `, `HEAD `) is answered 200 with the body
  `name=<name> port=<port> peer=<ip>`, keep-alive, so the backend can
  serve an HTTP route as well as a stream;
- anything else is answered with that line followed by an echo of
  everything the client sends, for as long as it sends.

`peer` is the TCP peer, the address the proxy connected from. With
--proxy it first reads a PROXY protocol header (v1 or v2) and adds the
source address it carried: `... src=<ip>`.

It listens on one port or a range (`--ports 7300-7315`, port N reporting
N). SIGUSR1 closes the listening sockets and keeps every established
connection; SIGUSR2 opens them again. Signals reach it as the container's
PID 1 because it installs handlers (the driver sends them with
`docker compose kill -s`).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import signal
import socket
import struct
import threading

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def read_exact(conn: socket.socket, n: int, buf: bytearray) -> bytes:
    while len(buf) < n:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("closed in the PROXY header")
        buf += chunk
    out = bytes(buf[:n])
    del buf[:n]
    return out


def read_proxy_header(conn: socket.socket) -> tuple[str, bytes]:
    """Return the carried source address and the bytes read past the header."""
    buf = bytearray()
    first = read_exact(conn, 12, buf)
    if first == V2_SIGNATURE:
        rest = read_exact(conn, 4, buf)
        family = rest[1] >> 4
        length = struct.unpack("!H", rest[2:4])[0]
        body = read_exact(conn, length, buf)
        if family == 1:
            src = str(ipaddress.IPv4Address(body[0:4]))
        elif family == 2:
            src = str(ipaddress.IPv6Address(body[0:16]))
        else:
            src = "unspec"
        return src, bytes(buf)
    buf[0:0] = first
    while b"\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("closed in the PROXY v1 header")
        buf += chunk
    line, _, rest = bytes(buf).partition(b"\r\n")
    fields = line.decode(errors="replace").split()
    src = fields[2] if len(fields) > 2 and fields[0] == "PROXY" else "invalid"
    return src, rest


class Backend:
    def __init__(self, name: str, ports: list[int], proxy: bool) -> None:
        self.name = name
        self.ports = ports
        self.proxy = proxy
        self.lock = threading.Lock()
        self.listeners: list[socket.socket] = []

    def identity(self, port: int, peer: str, src: str | None) -> bytes:
        text = f"name={self.name} port={port} peer={peer}"
        if src is not None:
            text += f" src={src}"
        return text.encode()

    def handle(self, conn: socket.socket, port: int) -> None:
        with conn:
            try:
                address = ipaddress.ip_address(conn.getpeername()[0])
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                peer = str(address)
                src = None
                pending = b""
                if self.proxy:
                    src, pending = read_proxy_header(conn)
                data = pending or conn.recv(65536)
                if not data:
                    return
                if data.startswith((b"GET ", b"HEAD ")):
                    self.serve_http(conn, self.identity(port, peer, src), data)
                    return
                conn.sendall(self.identity(port, peer, src) + b"\n")
                while data:
                    conn.sendall(data)
                    data = conn.recv(65536)
            except OSError:
                return

    def serve_http(self, conn: socket.socket, body: bytes, data: bytes) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        while True:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            _, _, data = data.partition(b"\r\n\r\n")
            conn.sendall(response)

    def accept_loop(self, listener: socket.socket, port: int) -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn, port), daemon=True).start()

    def open(self) -> None:
        with self.lock:
            if self.listeners:
                return
            for port in self.ports:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("::", port))
                s.listen(1024)
                self.listeners.append(s)
                threading.Thread(target=self.accept_loop, args=(s, port), daemon=True).start()

    def close(self) -> None:
        with self.lock:
            for s in self.listeners:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()
            self.listeners = []


def parse_ports(text: str) -> list[int]:
    first, _, last = text.partition("-")
    return list(range(int(first), int(last or first) + 1))


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--name", required=True)
    p.add_argument("--ports", default="9000", help="a port or a range first-last")
    p.add_argument("--proxy", action="store_true", help="read a PROXY v1/v2 header first")
    args = p.parse_args()

    backend = Backend(args.name, parse_ports(args.ports), args.proxy)
    backend.open()
    signal.signal(signal.SIGUSR1, lambda *_: threading.Thread(target=backend.close).start())
    signal.signal(signal.SIGUSR2, lambda *_: threading.Thread(target=backend.open).start())
    # PID 1 ignores a signal it has no handler for: without this one,
    # `docker compose stop` would wait out its grace period.
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        signal.pause()


if __name__ == "__main__":
    main()
