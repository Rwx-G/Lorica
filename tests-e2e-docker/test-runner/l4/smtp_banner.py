#!/usr/bin/env python3
"""An SMTP banner server for the L4 phase (Story 12.12 Lot G, Resolved 4),
standard library only. It stands in for an MTA to check Story 12.7's
`smtp_banner` health-check template; it is not an MTA.

  --mode banner  On every connection, writes `220 example.com ESMTP`
                 and then waits, reading and discarding, until the client
                 closes.
  --mode silent  Accepts every connection and never writes a byte: an
                 MTA that hangs after the handshake.

Every connection and how it ended is printed on stdout, one line each,
so the scenario can count the probes the server saw.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import threading

BANNER = b"220 example.com ESMTP\r\n"


def handle(conn: socket.socket, peer: str, mode: str) -> None:
    received = 0
    with conn:
        try:
            if mode == "banner":
                conn.sendall(BANNER)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                received += len(data)
        except OSError as e:
            print(f"connection from {peer} ended: {type(e).__name__}", flush=True)
            return
    print(f"connection from {peer} closed by the client after {received} bytes", flush=True)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["banner", "silent"], required=True)
    p.add_argument("--port", type=int, default=2525)
    args = p.parse_args()

    # PID 1 ignores a signal it has no handler for: without this one,
    # `docker compose stop` would wait out its grace period.
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.port))
    listener.listen(128)
    print(f"smtp_banner {args.mode} listening on {args.port}", flush=True)
    while True:
        conn, addr = listener.accept()
        print(f"connection from {addr[0]}", flush=True)
        threading.Thread(target=handle, args=(conn, addr[0], args.mode), daemon=True).start()


if __name__ == "__main__":
    main()
