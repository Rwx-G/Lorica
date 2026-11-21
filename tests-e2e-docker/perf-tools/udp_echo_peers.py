#!/usr/bin/env python3
"""UDP echo backend that counts its distinct peers (Story 12.12 D-j, measurement 3).

Standard library only.

  serve    Echoes every datagram once, to its sender, and remembers every
           distinct sender address since the last reset. Behind a proxy each
           UDP session is one upstream socket, so the count is the number of
           sessions the proxy opened: a session evicted and opened again comes
           back on a new upstream port and counts twice. A TCP control port
           answers `RESET` (forget the peers) and `COUNT` (the peers and
           datagrams since the reset, as JSON).
  control  Sends one control command and prints the answer.
"""

from __future__ import annotations

import argparse
import json
import selectors
import socket


def serve(args: argparse.Namespace) -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", args.port))
    udp.setblocking(False)
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control.bind(("0.0.0.0", args.control_port))
    control.listen(16)
    sel = selectors.DefaultSelector()
    sel.register(udp, selectors.EVENT_READ, "udp")
    sel.register(control, selectors.EVENT_READ, "control")
    peers: set[tuple[str, int]] = set()
    datagrams = 0

    while True:
        for key, _ in sel.select():
            if key.data == "udp":
                while True:
                    try:
                        data, peer = udp.recvfrom(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    datagrams += 1
                    peers.add(peer)
                    try:
                        udp.sendto(data, peer)
                    except OSError:
                        pass
                continue
            conn, _ = control.accept()
            with conn:
                conn.settimeout(5)
                try:
                    command = conn.recv(64).decode(errors="replace").strip()
                except OSError:
                    continue
                if command == "RESET":
                    peers.clear()
                    datagrams = 0
                    reply = {"reset": True}
                elif command == "COUNT":
                    reply = {"peers": len(peers), "datagrams": datagrams}
                else:
                    reply = {"error": f"unknown command {command!r}"}
                try:
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                except OSError:
                    pass


def control_command(args: argparse.Namespace) -> None:
    host, port = args.target.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=10) as s:
        s.sendall(args.command.encode() + b"\n")
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    print(b"".join(chunks).decode().strip(), flush=True)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--control-port", type=int, required=True)
    c = sub.add_parser("control")
    c.add_argument("--target", required=True, help="host:port of the control port")
    c.add_argument("--command", required=True, choices=["RESET", "COUNT"])
    args = p.parse_args()
    {"serve": serve, "control": control_command}[args.cmd](args)


if __name__ == "__main__":
    main()
