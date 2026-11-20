#!/usr/bin/env python3
"""UDP tools of the Story 12.5 scenarios (Story 12.12 Lot E), standard library only.

Subcommands:

  amplify  A UDP backend with one listener per `--listen PORT:COUNT:SIZE`:
           every datagram received on PORT is answered with COUNT
           datagrams of SIZE bytes, sent back to its sender.
  spoof    Sends UDP datagrams with a forged source over a raw socket
           (IP_HDRINCL, so root with CAP_NET_RAW): from `--source` (one
           address) or from random addresses of `--random-sources`
           (a CIDR), from random ports of `--sport-range`, at `--rate`
           datagrams per second for `--duration` seconds.
  victim   Binds every port of `--ports` and records, per one-second
           window, the datagrams and payload bytes received from
           `--from` (the proxy), for `--duration` seconds. Ports, not a
           raw socket: it needs no privilege, and the spoofer's random
           ports are drawn from the same range.
  client   A legitimate client: from one socket, one datagram every
           `--interval` seconds for `--duration` seconds, counting the
           answers, each expected within `--timeout`.

Every subcommand but amplify prints one JSON line on stdout and, with
--out, writes it to a file (renamed into place, so a reader polling for
the file never sees half of it).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import selectors
import socket
import struct
import time
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
    return socket.gethostbyname(host.strip("[]")), int(port)


def port_range(text: str) -> range:
    first, _, last = text.partition("-")
    return range(int(first), int(last or first) + 1)


def amplify(args: argparse.Namespace) -> None:
    sel = selectors.DefaultSelector()
    for spec in args.listen:
        port, count, size = (int(v) for v in spec.split(":"))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
        s.bind(("0.0.0.0", port))
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, (count, b"r" * size))
    print(f"amplify listening on {', '.join(args.listen)}", flush=True)
    while True:
        for key, _ in sel.select():
            count, answer = key.data
            sock = key.fileobj
            while True:
                try:
                    _, peer = sock.recvfrom(65535)
                except BlockingIOError:
                    break
                for _ in range(count):
                    try:
                        sock.sendto(answer, peer)
                    except OSError:
                        # A closed upstream port answers ICMP; the next
                        # datagram is the proxy's business, not ours.
                        break


def udp_packet(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    # Linux fills in the total length and the header checksum of an
    # IP_HDRINCL packet; a zero UDP checksum means "none" on IPv4.
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), random.getrandbits(16), 0, 64,
        socket.IPPROTO_UDP, 0, socket.inet_aton(src), socket.inet_aton(dst),
    )
    return ip + udp


def spoof(args: argparse.Namespace) -> None:
    dst, dport = split_target(args.target)
    ports = port_range(args.sport_range)
    payload = b"q" * args.size
    if args.random_sources:
        net = ipaddress.ip_network(args.random_sources)
        base, span = int(net.network_address) + 1, net.num_addresses - 2

        def source() -> str:
            return str(ipaddress.IPv4Address(base + random.randrange(span)))
    else:
        fixed = socket.gethostbyname(args.source)

        def source() -> str:
            return fixed
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    sent = errors = 0
    start = time.monotonic()
    end = start + args.duration
    while True:
        now = time.monotonic()
        if now >= end:
            break
        due = int((now - start) * args.rate)
        if sent >= due:
            time.sleep(0.0005)
            continue
        for _ in range(min(due - sent, 500)):
            packet = udp_packet(source(), random.choice(ports), dst, dport, payload)
            try:
                s.sendto(packet, (dst, 0))
            except OSError:
                errors += 1
            sent += 1
    elapsed = time.monotonic() - start
    write_result({"sent": sent, "errors": errors, "seconds": round(elapsed, 3),
                  "rate": round(sent / elapsed, 1)}, args.out)


def victim(args: argparse.Namespace) -> None:
    proxy = socket.gethostbyname(args.from_host)
    sel = selectors.DefaultSelector()
    socks = []
    for port in port_range(args.ports):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)
        socks.append(s)
    if args.ready:
        Path(args.ready).write_text("ready\n")
    windows_bytes = [0] * (int(args.duration) + 1)
    windows_datagrams = [0] * (int(args.duration) + 1)
    other = 0
    start = time.monotonic()
    end = start + args.duration
    while True:
        now = time.monotonic()
        if now >= end:
            break
        for key, _ in sel.select(timeout=min(0.2, end - now)):
            while True:
                try:
                    data, peer = key.fileobj.recvfrom(65535)
                except BlockingIOError:
                    break
                if peer[0] != proxy:
                    other += 1
                    continue
                w = min(int(time.monotonic() - start), len(windows_bytes) - 1)
                windows_bytes[w] += len(data)
                windows_datagrams[w] += 1
    total = sum(windows_bytes)
    write_result({
        "bytes": total,
        "datagrams": sum(windows_datagrams),
        "max_window_bytes": max(windows_bytes),
        "windows_bytes": windows_bytes,
        "from_others": other,
        "seconds": args.duration,
    }, args.out)


def client(args: argparse.Namespace) -> None:
    host, port = split_target(args.target)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, port))
    s.setblocking(False)
    sel = selectors.DefaultSelector()
    sel.register(s, selectors.EVENT_READ)
    payload = b"c" * args.size
    rounds = int(args.duration / args.interval)
    sent = answered = late = 0
    pending: list[float] = []
    start = time.monotonic()
    end = start + rounds * args.interval + args.timeout
    while True:
        now = time.monotonic()
        if now >= end:
            break
        if sent < rounds and now >= start + sent * args.interval:
            try:
                s.send(payload)
            except ConnectionRefusedError:
                # An earlier ICMP error surfaces on the next call; the
                # datagram went out regardless of it.
                s.send(payload)
            pending.append(now)
            sent += 1
        wake = start + sent * args.interval if sent < rounds else end
        for _ in sel.select(timeout=max(0.0, min(wake, end) - time.monotonic())):
            while True:
                try:
                    s.recv(65535)
                except BlockingIOError:
                    break
                except ConnectionRefusedError:
                    break
                if pending:
                    t0 = pending.pop(0)
                    if time.monotonic() - t0 <= args.timeout:
                        answered += 1
                    else:
                        late += 1
                else:
                    late += 1
    write_result({"sent": sent, "answered": answered, "late_or_extra": late,
                  "bytes_sent": sent * args.size}, args.out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("amplify")
    p.add_argument("--listen", action="append", required=True, help="PORT:COUNT:SIZE")

    p = sub.add_parser("spoof")
    p.add_argument("--target", required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source")
    group.add_argument("--random-sources")
    p.add_argument("--sport-range", default="30000-31999")
    p.add_argument("--rate", type=float, default=20000)
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--size", type=int, default=60)
    p.add_argument("--out")

    p = sub.add_parser("victim")
    p.add_argument("--from", dest="from_host", required=True)
    p.add_argument("--ports", default="30000-31999")
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--ready")
    p.add_argument("--out")

    p = sub.add_parser("client")
    p.add_argument("--target", required=True)
    p.add_argument("--interval", type=float, default=0.1)
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--size", type=int, default=60)
    p.add_argument("--out")

    args = parser.parse_args()
    {"amplify": amplify, "spoof": spoof, "victim": victim, "client": client}[args.cmd](args)


if __name__ == "__main__":
    main()
