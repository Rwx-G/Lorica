#!/usr/bin/env python3
"""Connection-setup latency through a TCP proxy (Story 12.12 D-j, measurement 2).

Standard library only. Two halves that read one clock: containers share the
kernel and Docker creates no time namespace, so CLOCK_MONOTONIC in the client
and in the backend is the same clock, and the difference between the two
stamps is the proxy's accept to backend connect, plus wake-up costs both
proxies pay alike.

  serve  The backend. One event loop stamps CLOCK_MONOTONIC the moment each
         connection is accepted, reads the 16-byte id the client sends through
         the proxy, and closes first, so TIME_WAIT lands on the backend and not
         on the proxy's ephemeral ports. A control port answers `TAKE <run>`
         with the stamps of that run as JSON, then forgets them.
  run    The client. Opens --count connections at --rate per second, open
         loop: connection k is started at start + k / rate whatever the earlier
         ones are doing, so a slow connection never delays the schedule. It
         stamps CLOCK_MONOTONIC when the connect completes, sends the id, and
         waits for the backend's close. Then it takes the run's stamps from the
         control port and reports the distribution of accept minus connect.

Both halves are single-threaded non-blocking loops: one thread means no
interpreter lock between a socket event and its stamp.

The result of `run` is one JSON line on stdout and, with --out, a file.
"""

from __future__ import annotations

import argparse
import errno
import json
import math
import os
import selectors
import socket
import time
from pathlib import Path

ID_LEN = 16
RUN_ID_LEN = 8
CONNECT_DEADLINE_S = 5.0


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


def listener(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(4096)
    srv.setblocking(False)
    return srv


def serve(args: argparse.Namespace) -> None:
    data_srv = listener(args.port)
    control_srv = listener(args.control_port)
    sel = selectors.DefaultSelector()
    sel.register(data_srv, selectors.EVENT_READ, ("data-listen", None))
    sel.register(control_srv, selectors.EVENT_READ, ("control-listen", None))
    # run id -> {sequence: accept stamp in ns}
    stamps: dict[str, dict[str, int]] = {}

    while True:
        for key, _ in sel.select():
            kind, state = key.data
            if kind == "data-listen":
                while True:
                    try:
                        conn, _ = data_srv.accept()
                    except BlockingIOError:
                        break
                    accepted = time.monotonic_ns()
                    conn.setblocking(False)
                    sel.register(conn, selectors.EVENT_READ, ("data", {"t": accepted, "buf": b""}))
            elif kind == "data":
                conn = key.fileobj
                try:
                    chunk = conn.recv(ID_LEN)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                state["buf"] += chunk
                if chunk and len(state["buf"]) < ID_LEN:
                    continue
                if len(state["buf"]) >= ID_LEN:
                    ident = state["buf"][:ID_LEN].decode(errors="replace")
                    stamps.setdefault(ident[:RUN_ID_LEN], {})[ident[RUN_ID_LEN:]] = state["t"]
                sel.unregister(conn)
                conn.close()
            elif kind == "control-listen":
                try:
                    conn, _ = control_srv.accept()
                except BlockingIOError:
                    continue
                conn.setblocking(False)
                sel.register(conn, selectors.EVENT_READ, ("control", {"buf": b""}))
            elif kind == "control":
                conn = key.fileobj
                try:
                    chunk = conn.recv(256)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                state["buf"] += chunk
                if chunk and b"\n" not in state["buf"]:
                    continue
                sel.unregister(conn)
                words = state["buf"].decode(errors="replace").split()
                if len(words) == 2 and words[0] == "TAKE":
                    reply = json.dumps(stamps.pop(words[1], {})).encode()
                    conn.setblocking(True)
                    try:
                        conn.sendall(reply)
                    except OSError:
                        pass
                conn.close()


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile of an already sorted list."""
    rank = max(1, math.ceil(fraction * len(sorted_values)))
    return sorted_values[rank - 1]


def take_stamps(control: str, run_id: str) -> dict[str, int]:
    host, port = split_target(control)
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(f"TAKE {run_id}\n".encode())
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks) or b"{}")


def run(args: argparse.Namespace) -> None:
    host, port = split_target(args.target)
    addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
    run_id = os.urandom(RUN_ID_LEN // 2).hex()
    sel = selectors.DefaultSelector()
    connected_at: dict[str, int] = {}
    failures: dict[str, int] = {}
    # socket -> (sequence, started monotonic s)
    open_socks: dict[socket.socket, tuple[str, float]] = {}
    schedule_lag_max = 0.0

    def fail(sock: socket.socket, reason: str) -> None:
        failures[reason] = failures.get(reason, 0) + 1
        try:
            sel.unregister(sock)
        except (KeyError, ValueError):
            pass
        open_socks.pop(sock, None)
        sock.close()

    start = time.monotonic() + 0.1
    next_k = 0
    while next_k < args.count or open_socks:
        now = time.monotonic()
        while next_k < args.count and start + next_k / args.rate <= now:
            schedule_lag_max = max(schedule_lag_max, now - (start + next_k / args.rate))
            seq = f"{next_k:0{ID_LEN - RUN_ID_LEN}x}"
            next_k += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            code = sock.connect_ex(addr)
            if code not in (0, errno.EINPROGRESS):
                reason = errno.errorcode.get(code, str(code))
                failures[reason] = failures.get(reason, 0) + 1
                sock.close()
                continue
            open_socks[sock] = (seq, now)
            sel.register(sock, selectors.EVENT_WRITE, "connecting")
        for sock, (seq, started) in list(open_socks.items()):
            if now - started > CONNECT_DEADLINE_S:
                fail(sock, "deadline")
        wait = 0.05
        if next_k < args.count:
            wait = min(wait, max(0.0, start + next_k / args.rate - time.monotonic()))
        for key, _ in sel.select(timeout=wait):
            sock = key.fileobj
            if sock not in open_socks:
                continue
            seq, _ = open_socks[sock]
            if key.data == "connecting":
                stamped = time.monotonic_ns()
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err:
                    fail(sock, errno.errorcode.get(err, str(err)))
                    continue
                connected_at[seq] = stamped
                try:
                    sock.send((run_id + seq).encode())
                except OSError as exc:
                    fail(sock, type(exc).__name__)
                    continue
                sel.modify(sock, selectors.EVENT_READ, "waiting-close")
            else:
                try:
                    chunk = sock.recv(64)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(sock)
                    open_socks.pop(sock, None)
                    sock.close()
    seconds = time.monotonic() - start

    accepted_at = take_stamps(args.control, run_id)
    latencies_us = sorted(
        (accepted_at[seq] - t) / 1000.0 for seq, t in connected_at.items() if seq in accepted_at
    )
    result: dict = {
        "count": args.count,
        "rate": args.rate,
        "connected": len(connected_at),
        "failed": sum(failures.values()),
        "failures": failures,
        "matched": len(latencies_us),
        "missing_at_backend": len(connected_at) - len(latencies_us),
        "schedule_lag_max_ms": round(schedule_lag_max * 1000, 3),
        "seconds": round(seconds, 3),
    }
    if latencies_us:
        result.update(
            {
                "min_us": round(latencies_us[0], 1),
                "p50_us": round(percentile(latencies_us, 0.50), 1),
                "p90_us": round(percentile(latencies_us, 0.90), 1),
                "p99_us": round(percentile(latencies_us, 0.99), 1),
                "max_us": round(latencies_us[-1], 1),
                "mean_us": round(sum(latencies_us) / len(latencies_us), 1),
            }
        )
    write_result(result, args.out)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, required=True, help="the port the proxy connects to")
    s.add_argument("--control-port", type=int, required=True, help="the port answering TAKE <run>")

    r = sub.add_parser("run")
    r.add_argument("--target", required=True, help="host:port of the proxy's stream")
    r.add_argument("--control", required=True, help="host:port of the backend's control port")
    r.add_argument("--count", type=int, default=10_000)
    r.add_argument("--rate", type=float, default=500.0, help="new connections per second")
    r.add_argument("--out")

    args = p.parse_args()
    {"serve": serve, "run": run}[args.cmd](args)


if __name__ == "__main__":
    main()
