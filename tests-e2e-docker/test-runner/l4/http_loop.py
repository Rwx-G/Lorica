#!/usr/bin/env python3
"""HTTP traffic for the L4 phase (Story 12.12 Lot B), standard library only.

Subcommands:

  serve   An HTTP/1.1 backend: `GET /` answers 200 `ok`, `GET /delay/<s>`
          answers 200 after <s> seconds. Keep-alive, one thread per
          connection.
  loop    A new TCP connection per request (`Connection: close`, so every
          request exercises accept) at a fixed rate, until a stop file
          appears or a duration passes.
  hold    Opens N keep-alive connections, one request each, holds them,
          then sends a second request on each; a bounded number of
          requests is in flight at once.
  get     One request, with the wall-clock times it was sent and answered
          (CLOCK_REALTIME, the clock every container of the VM shares).

Every result is one JSON line on stdout and, with --out, a file, so a run
started detached can be read afterwards.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import socketserver
import threading
import time
from pathlib import Path


def write_result(result: dict, out: str | None) -> None:
    text = json.dumps(result, sort_keys=True)
    if out:
        tmp = Path(out + ".tmp")
        tmp.write_text(text + "\n")
        tmp.replace(out)
    print(text, flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.startswith("/delay/"):
            time.sleep(float(self.path[len("/delay/"):]))
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024


def serve(args: argparse.Namespace) -> None:
    ThreadingServer(("0.0.0.0", args.port), Handler).serve_forever()


def request_bytes(host_header: str, path: str, keep_alive: bool) -> bytes:
    connection = "keep-alive" if keep_alive else "close"
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        f"Connection: {connection}\r\n\r\n"
    ).encode()


def read_response(sock: socket.socket) -> int:
    """Read one response and return its status code; raise on a short read."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before the headers")
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed in the body")
        body += chunk
    return status


def split_target(target: str) -> tuple[str, int]:
    host, port = target.rsplit(":", 1)
    return host, int(port)


def one_request(target: str, host_header: str, path: str, timeout: float) -> int:
    with socket.create_connection(split_target(target), timeout=timeout) as s:
        s.sendall(request_bytes(host_header, path, keep_alive=False))
        return read_response(s)


def loop(args: argparse.Namespace) -> None:
    interval = 1.0 / args.rate
    deadline = time.monotonic() + args.duration if args.duration else None
    result: dict = {"sent": 0, "ok": 0, "failed": 0, "errors": []}
    next_at = time.monotonic()
    while True:
        if args.stop_file and Path(args.stop_file).exists():
            break
        if deadline and time.monotonic() >= deadline:
            break
        result["sent"] += 1
        try:
            status = one_request(args.target, args.host_header, args.path, args.timeout)
            failure = None if status == args.expect else f"status {status}"
        except OSError as e:
            failure = f"{type(e).__name__}: {e}"
        if failure is None:
            result["ok"] += 1
        else:
            result["failed"] += 1
            if len(result["errors"]) < 10:
                result["errors"].append(failure)
        next_at += interval
        delay = next_at - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_at = time.monotonic()
    write_result(result, args.out)


def exchange(socks: list[socket.socket], request: bytes, window: int, label: str,
             errors: list[str]) -> list[socket.socket]:
    """One request and its response on every socket, at most `window` in
    flight at once; return the sockets that answered. The window keeps
    the run short (the first connection must not sit idle past the
    proxy's keep-alive timeout while the last opens) without opening one
    upstream connection per held downstream one."""
    answered: list[socket.socket] = []
    for start in range(0, len(socks), window):
        batch = socks[start:start + window]
        threads = []
        results: dict[int, str | None] = {}

        def one(i: int, s: socket.socket) -> None:
            try:
                s.sendall(request)
                read_response(s)
                results[i] = None
            except OSError as e:
                results[i] = f"{label}: {type(e).__name__}: {e}"

        for i, s in enumerate(batch):
            t = threading.Thread(target=one, args=(i, s))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        for i, s in enumerate(batch):
            if results.get(i) is None:
                answered.append(s)
            else:
                s.close()
                if len(errors) < 10:
                    errors.append(results[i] or f"{label}: no result")
    return answered


def hold(args: argparse.Namespace) -> None:
    socks: list[socket.socket] = []
    errors: list[str] = []
    for _ in range(args.count):
        try:
            socks.append(socket.create_connection(split_target(args.target), timeout=args.timeout))
        except OSError as e:
            if len(errors) < 10:
                errors.append(f"connect: {type(e).__name__}: {e}")
    request = request_bytes(args.host_header, args.path, keep_alive=True)
    started = time.monotonic()
    held = exchange(socks, request, args.window, "first request", errors)
    first_s = time.monotonic() - started
    time.sleep(args.hold_s)
    second = exchange(held, request, args.window, "second request", errors)
    for s in second:
        s.close()
    write_result(
        {
            "requested": args.count,
            "first_ok": len(held),
            "second_ok": len(second),
            "first_round_s": round(first_s, 3),
            "errors": errors,
        },
        args.out,
    )


def get(args: argparse.Namespace) -> None:
    sent = time.time()
    status: int | None = None
    error: str | None = None
    try:
        status = one_request(args.target, args.host_header, args.path, args.timeout)
    except OSError as e:
        error = f"{type(e).__name__}: {e}"
    write_result({"sent": sent, "done": time.time(), "status": status, "error": error}, args.out)


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8000)

    for name in ("loop", "hold", "get"):
        c = sub.add_parser(name)
        c.add_argument("--target", required=True, help="host:port of the HTTP listener")
        c.add_argument("--host-header", required=True)
        c.add_argument("--path", default="/")
        c.add_argument("--timeout", type=float, default=10.0)
        c.add_argument("--out")
        if name == "loop":
            c.add_argument("--rate", type=float, default=50.0, help="requests per second")
            c.add_argument("--duration", type=float, help="seconds; default until --stop-file")
            c.add_argument("--stop-file")
            c.add_argument("--expect", type=int, default=200)
        if name == "hold":
            c.add_argument("--count", type=int, required=True)
            c.add_argument("--hold-s", type=float, default=5.0)
            c.add_argument("--window", type=int, default=32, help="requests in flight at once")

    args = p.parse_args()
    {"serve": serve, "loop": loop, "hold": hold, "get": get}[args.cmd](args)


if __name__ == "__main__":
    main()
