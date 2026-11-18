#!/usr/bin/env python3
"""UDP sessions for the L4 phase (Story 12.12 D-f and D-j), standard library only.

Subcommands:

  hold    Opens N UDP sockets from one address, each its own session at the
          proxy, and keeps them alive: every socket sends one datagram per
          interval for the duration, the sends spread evenly over the
          interval (so the proxy sees a steady rate, not a burst that would
          overflow a receive buffer), and each datagram expects its echo
          within the timeout. Reports, per socket, whether every datagram,
          some or none was answered, and the echoes lost in all.
  ping    From one fixed source port, sends a datagram every 200 ms until
          one is echoed or the deadline passes, and reports how long it
          took. A fixed port keeps the 4-tuple, so the proxy's SO_REUSEPORT
          group hashes the client to the same socket every time.
  serve   A backend that echoes every datagram once, to its sender.

The result is one JSON line on stdout and, with --out, a file.
"""

from __future__ import annotations

import argparse
import json
import selectors
import socket
import time
from collections import deque
from pathlib import Path


def write_result(result: dict, out: str | None) -> None:
    text = json.dumps(result, sort_keys=True)
    if out:
        tmp = Path(out + ".tmp")
        tmp.write_text(text + "\n")
        tmp.replace(out)
    print(text, flush=True)


def split_target(target: str) -> tuple[str, int]:
    host, port = target.rsplit(":", 1)
    return host.strip("[]"), int(port)


def hold(args: argparse.Namespace) -> None:
    host, port = split_target(args.target)
    family, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    sel = selectors.DefaultSelector()
    socks: list[socket.socket] = []
    for i in range(args.sessions):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setblocking(False)
        s.connect(addr)
        sel.register(s, selectors.EVENT_READ, i)
        socks.append(s)

    rounds = max(1, int(args.duration // args.interval))
    answered = [0] * args.sessions
    # The time each socket's outstanding datagram was sent, or None.
    outstanding: list[float | None] = [None] * args.sessions
    in_flight: deque[tuple[float, int]] = deque()
    lost = 0
    late = 0
    start = time.monotonic()
    # Socket i sends round r at start + r * interval + i * interval / N.
    schedule = [
        (start + r * args.interval + i * args.interval / args.sessions, i, r)
        for r in range(rounds)
        for i in range(args.sessions)
    ]
    end = schedule[-1][0] + args.timeout
    next_send = 0
    while True:
        now = time.monotonic()
        while next_send < len(schedule) and schedule[next_send][0] <= now:
            _, i, r = schedule[next_send]
            next_send += 1
            if outstanding[i] is not None:
                lost += 1
            try:
                socks[i].send(f"hold {i} {r}".encode())
                outstanding[i] = now
                in_flight.append((now, i))
            except OSError:
                outstanding[i] = None
                lost += 1
        # Sends are in time order, so the expired ones are at the left.
        while in_flight and now - in_flight[0][0] > args.timeout:
            sent_at, i = in_flight.popleft()
            if outstanding[i] == sent_at:
                outstanding[i] = None
                lost += 1
        if next_send >= len(schedule) and (
            now >= end or all(sent_at is None for sent_at in outstanding)
        ):
            break
        wait = 0.05
        if next_send < len(schedule):
            wait = min(wait, max(0.0, schedule[next_send][0] - now))
        for key, _ in sel.select(timeout=wait):
            i = key.data
            try:
                while True:
                    key.fileobj.recv(65535)
                    if outstanding[i] is not None:
                        answered[i] += 1
                        outstanding[i] = None
                    else:
                        late += 1
            except BlockingIOError:
                pass
            except OSError:
                pass

    for s in socks:
        s.close()
    write_result(
        {
            "sessions": args.sessions,
            "rounds": rounds,
            "answered_every_round": sum(1 for a in answered if a == rounds),
            "answered_some_rounds": sum(1 for a in answered if 0 < a < rounds),
            "never_answered": sum(1 for a in answered if a == 0),
            "lost": lost,
            "late": late,
            "seconds": round(time.monotonic() - start, 3),
        },
        args.out,
    )


def ping(args: argparse.Namespace) -> None:
    host, port = split_target(args.target)
    family, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    start = time.monotonic()
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", args.sport))
        s.connect(addr)
        s.settimeout(0.2)
        sent = 0
        while time.monotonic() - start < args.deadline:
            sent += 1
            try:
                s.send(f"ping {sent}".encode())
                reply = s.recv(65535)
                write_result(
                    {
                        "answered": True,
                        "reply": reply.decode(errors="replace"),
                        "sent": sent,
                        "seconds": round(time.monotonic() - start, 3),
                    },
                    args.out,
                )
                return
            except (TimeoutError, ConnectionRefusedError):
                continue
    write_result(
        {"answered": False, "sent": sent, "seconds": round(time.monotonic() - start, 3)},
        args.out,
    )


def serve(args: argparse.Namespace) -> None:
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind(("::" if args.ipv6 else "0.0.0.0", args.port))
        while True:
            data, peer = s.recvfrom(65535)
            s.sendto(data, peer)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hold")
    h.add_argument("--target", required=True, help="host:port of the UDP stream")
    h.add_argument("--sessions", type=int, required=True)
    h.add_argument("--interval", type=float, default=5.0, help="seconds between a socket's datagrams")
    h.add_argument("--duration", type=float, default=30.0)
    h.add_argument("--timeout", type=float, default=1.0, help="seconds an echo may take")
    h.add_argument("--out")

    g = sub.add_parser("ping")
    g.add_argument("--target", required=True)
    g.add_argument("--sport", type=int, required=True)
    g.add_argument("--deadline", type=float, default=10.0)
    g.add_argument("--out")

    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--ipv6", action="store_true")

    args = p.parse_args()
    {"hold": hold, "ping": ping, "serve": serve}[args.cmd](args)


if __name__ == "__main__":
    main()
