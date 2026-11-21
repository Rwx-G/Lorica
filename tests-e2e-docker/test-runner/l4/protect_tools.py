#!/usr/bin/env python3
"""Clients and a TLS backend for Story 12.6's scenarios (Story 12.12 Lot F,
the design of Story 12.6 Lot I), standard library only.

Every timed assertion of a scenario runs inside one invocation of this
tool, its timer included. Targets are `host:port`, resolved over IPv4
only, so the address a stream judges is the one the scenario names.
`--bind` picks the client's source address (an address of this
container: on `l4`, on `streams-geo`, or one the scenario added).

Subcommands (each prints one JSON line):

  addr-in       This container's IPv4 address inside a subnet.
  tls-serve     A TLS echo backend (self-signed certificate given).
  tcp-burst     Connections from one source spread evenly over a period,
                each sending a line and reading the backend's identity
                line, plus a few from another source in the middle of
                the period: served or closed, per source.
  hold-tcp      Connections opened one after the other and all held, by
                plan items `<bind>><host>:<port>:<count>`: what each got.
  udp-query     One datagram from a source; whether it was echoed.
  pending-flood Silent connections (they never send a byte) from one
                source at a fixed rate, while a TLS client from another
                source opens a new handshake every interval: how many of
                the silent sockets the proxy had not closed, sampled
                every 100 ms, and every handshake's outcome.
  pending-fill  One TLS connection held and echoing; then silent
                connections from several sources at once; then a new
                handshake every interval until the end: the most silent
                sockets held at once, and when handshakes failed and
                succeeded relative to the fill.

"Held" means a connected socket the proxy has not closed for at least
`--age-ms`: a refused connection is closed within milliseconds of its
accept, a pending one stays until its ClientHello deadline. The age
keeps a socket the proxy has not accepted yet, or has just refused and
whose close the sampler has not read, out of the count.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import selectors
import socket
import ssl
import subprocess
import threading
import time


def emit(result: dict) -> None:
    print(json.dumps(result, sort_keys=True), flush=True)


def resolve(target: str) -> tuple[str, int]:
    host, port = target.rsplit(":", 1)
    return socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)[0][4]


def tcp_socket(bind: str | None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if bind:
        s.bind((bind, 0))
    return s


def read_line(s: socket.socket) -> str | None:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            return None
        buf += chunk
    return buf.decode(errors="replace").strip()


def exchange_line(addr: tuple[str, int], bind: str | None, timeout: float) -> tuple[str, socket.socket | None]:
    """Connect, send a line, read the first line back. Returns the outcome
    (`served <line>`, `closed`, `timeout` or `error <kind>`) and the
    socket when it is still open."""
    s = tcp_socket(bind)
    s.settimeout(timeout)
    try:
        s.connect(addr)
        s.sendall(b"hello\n")
        line = read_line(s)
    except socket.timeout:
        s.close()
        return "timeout", None
    except OSError as e:
        s.close()
        return f"error {type(e).__name__}", None
    if line is None:
        s.close()
        return "closed", None
    return f"served {line}", s


# ---- addr-in ---------------------------------------------------------


def addr_in(args: argparse.Namespace) -> None:
    net = ipaddress.ip_network(args.subnet, strict=False)
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        fields = line.split()
        addr = ipaddress.ip_interface(fields[3])
        if addr.ip in net:
            emit({"address": str(addr.ip), "dev": fields[1], "prefix": addr.network.prefixlen})
            return
    emit({"address": None})
    raise SystemExit(1)


# ---- TLS -------------------------------------------------------------


def tls_serve(args: argparse.Namespace) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.port))
    listener.listen(1024)

    def handle(conn: socket.socket) -> None:
        conn.settimeout(30)
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                while True:
                    data = tls.recv(4096)
                    if not data:
                        return
                    tls.sendall(data)
        except (OSError, ssl.SSLError):
            conn.close()

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_attempt(addr: tuple[str, int], sni: str, bind: str | None, timeout: float) -> str:
    """A fresh handshake and one echo: `ok`, or why not."""
    s = tcp_socket(bind)
    s.settimeout(timeout)
    try:
        s.connect(addr)
        with client_context().wrap_socket(s, server_hostname=sni) as tls:
            tls.sendall(b"ping\n")
            if tls.recv(16) != b"ping\n":
                return "bad-echo"
            return "ok"
    except socket.timeout:
        return "timeout"
    except ssl.SSLError as e:
        return f"tls {e.reason or type(e).__name__}"
    except OSError as e:
        return f"error {type(e).__name__}"
    finally:
        s.close()


class TlsLoop(threading.Thread):
    """A new handshake every `every` seconds until stopped, each outcome
    recorded with its start time."""

    def __init__(self, addr: tuple[str, int], sni: str, bind: str | None, every: float) -> None:
        super().__init__(daemon=True)
        self.addr, self.sni, self.bind, self.every = addr, sni, bind, every
        self.attempts: list[tuple[float, str]] = []
        self.stop = threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            started = time.monotonic()
            self.attempts.append((started, tls_attempt(self.addr, self.sni, self.bind, 2.0)))
            self.stop.wait(max(0.0, self.every - (time.monotonic() - started)))


class TlsHeld(threading.Thread):
    """One TLS connection opened at start, echoing a line every 0.5 s."""

    def __init__(self, addr: tuple[str, int], sni: str, bind: str | None) -> None:
        super().__init__(daemon=True)
        self.addr, self.sni, self.bind = addr, sni, bind
        self.pings = 0
        self.failures = 0
        self.error: str | None = None
        self.ready = threading.Event()
        self.stop = threading.Event()

    def run(self) -> None:
        s = tcp_socket(self.bind)
        s.settimeout(3)
        try:
            s.connect(self.addr)
            tls = client_context().wrap_socket(s, server_hostname=self.sni)
        except (OSError, ssl.SSLError) as e:
            self.error = f"open: {type(e).__name__} {e}"
            self.ready.set()
            return
        self.ready.set()
        n = 0
        while not self.stop.wait(0.5):
            n += 1
            try:
                line = f"held {n}\n".encode()
                tls.sendall(line)
                if tls.recv(64) == line:
                    self.pings += 1
                else:
                    self.failures += 1
            except (OSError, ssl.SSLError) as e:
                self.failures += 1
                self.error = f"{type(e).__name__} {e}"
                break
        tls.close()


# ---- Silent connections ----------------------------------------------


class SilentHolder:
    """Silent connections, opened on a schedule and watched for closes."""

    def __init__(self, addr: tuple[str, int], age_ms: int) -> None:
        self.addr = addr
        self.age = age_ms / 1000.0
        self.sel = selectors.DefaultSelector()
        # socket -> [source, connected_at or None]
        self.socks: dict[socket.socket, list] = {}
        self.opened = 0
        self.connect_errors = 0
        self.closed_young = 0
        self.closed_old = 0
        self.max_total = 0
        self.max_per_source: dict[str, int] = {}
        self.samples = 0

    def open(self, source: str) -> None:
        s = tcp_socket(source)
        s.setblocking(False)
        try:
            s.connect(self.addr)
        except BlockingIOError:
            pass
        except OSError:
            self.connect_errors += 1
            s.close()
            return
        self.opened += 1
        self.socks[s] = [source, None]
        self.sel.register(s, selectors.EVENT_WRITE)

    def drop(self, s: socket.socket, now: float) -> None:
        connected = self.socks.pop(s)[1]
        if connected is not None and now - connected >= self.age:
            self.closed_old += 1
        else:
            self.closed_young += 1
        self.sel.unregister(s)
        s.close()

    def poll(self, timeout: float) -> None:
        for key, events in self.sel.select(timeout):
            s = key.fileobj
            now = time.monotonic()
            if events & selectors.EVENT_WRITE:
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                    self.connect_errors += 1
                    self.drop(s, now)
                    continue
                self.socks[s][1] = now
                self.sel.modify(s, selectors.EVENT_READ)
            elif events & selectors.EVENT_READ:
                try:
                    data = s.recv(1)
                except OSError:
                    data = b""
                if not data:
                    self.drop(s, now)

    def sample(self) -> None:
        self.poll(0)
        now = time.monotonic()
        per: dict[str, int] = {}
        for source, connected in self.socks.values():
            if connected is not None and now - connected >= self.age:
                per[source] = per.get(source, 0) + 1
        total = sum(per.values())
        self.samples += 1
        self.max_total = max(self.max_total, total)
        for source, n in per.items():
            self.max_per_source[source] = max(self.max_per_source.get(source, 0), n)

    def run(self, schedule: list[tuple[float, str]], until: float, sample_every: float) -> None:
        """Open each (time, source) of `schedule`, sampling throughout,
        until the monotonic time `until`."""
        i = 0
        next_sample = time.monotonic()
        while True:
            now = time.monotonic()
            while i < len(schedule) and schedule[i][0] <= now:
                self.open(schedule[i][1])
                i += 1
            if now >= next_sample:
                self.sample()
                next_sample += sample_every
            if now >= until and i >= len(schedule):
                break
            wake = min(next_sample, schedule[i][0] if i < len(schedule) else until, until)
            self.poll(max(0.0, min(wake - time.monotonic(), 0.05)))

    def close_all(self) -> int:
        left = len(self.socks)
        for s in list(self.socks):
            self.sel.unregister(s)
            s.close()
        self.socks.clear()
        return left

    def report(self) -> dict:
        return {
            "opened": self.opened,
            "connect_errors": self.connect_errors,
            "closed_young": self.closed_young,
            "closed_old": self.closed_old,
            "max_held_total": self.max_total,
            "max_held_per_source": self.max_per_source,
            "samples": self.samples,
        }


def summarise(attempts: list[tuple[float, str]], origin: float) -> list[list]:
    return [[round(t - origin, 3), outcome] for t, outcome in attempts]


def pending_flood(args: argparse.Namespace) -> None:
    addr = resolve(args.target)
    holder = SilentHolder(addr, args.age_ms)
    loop = TlsLoop(resolve(args.tls_target), args.sni, args.tls_bind, args.tls_every)
    start = time.monotonic() + 0.5
    schedule = [(start + i / args.rate, args.bind) for i in range(args.count)]
    loop.start()
    holder.run(schedule, schedule[-1][0] + args.hold, 0.1)
    loop.stop.set()
    loop.join()
    result = holder.report()
    result["left_open_at_end"] = holder.close_all()
    result["flood_seconds"] = round(schedule[-1][0] - start, 3)
    outcomes = [o for _, o in loop.attempts]
    result["tls_attempts"] = len(outcomes)
    result["tls_ok"] = outcomes.count("ok")
    result["tls_failures"] = summarise([a for a in loop.attempts if a[1] != "ok"], start)
    emit(result)


def pending_fill(args: argparse.Namespace) -> None:
    addr = resolve(args.target)
    tls_addr = resolve(args.tls_target)
    held = TlsHeld(tls_addr, args.sni, args.tls_bind)
    held.start()
    held.ready.wait(5)
    if held.error:
        emit({"error": f"the held TLS connection did not open: {held.error}"})
        raise SystemExit(1)
    time.sleep(1.0)
    holder = SilentHolder(addr, args.age_ms)
    sources = args.bind.split(",")
    start = time.monotonic()
    # Interleaved, so every source reaches its share at about the same time.
    schedule = [(start + 0.002 * (i * len(sources) + j), src)
                for i in range(args.per_source) for j, src in enumerate(sources)]
    fill_until = schedule[-1][0] + args.settle
    holder.run(schedule, fill_until, 0.1)
    loop = TlsLoop(tls_addr, args.sni, args.tls_bind, args.tls_every)
    loop.start()
    holder.run([], start + args.duration, 0.1)
    loop.stop.set()
    loop.join()
    held.stop.set()
    held.join()
    result = holder.report()
    result["left_open_at_end"] = holder.close_all()
    result["fill_seconds"] = round(fill_until - start, 3)
    result["tls_attempts"] = summarise(loop.attempts, start)
    result["held_pings"] = held.pings
    result["held_failures"] = held.failures
    result["held_error"] = held.error
    emit(result)


# ---- Plain TCP and UDP -----------------------------------------------


def tcp_burst(args: argparse.Namespace) -> None:
    addr = resolve(args.target)
    other_addr = resolve(args.other_target)
    results: dict[str, list[str]] = {"primary": [], "other": []}
    lock = threading.Lock()

    def attempt(kind: str, target: tuple[str, int], bind: str) -> None:
        outcome, s = exchange_line(target, bind, 3.0)
        if s:
            s.close()
        with lock:
            results[kind].append(outcome)

    start = time.monotonic() + 0.2
    plan = [(start + args.period * i / args.count, "primary", addr, args.bind) for i in range(args.count)]
    plan += [(start + args.period * (i + 1) / (args.other_count + 1), "other", other_addr, args.other_bind)
             for i in range(args.other_count)]
    plan.sort(key=lambda p: p[0])
    threads = []
    for at, kind, target, bind in plan:
        time.sleep(max(0.0, at - time.monotonic()))
        t = threading.Thread(target=attempt, args=(kind, target, bind))
        t.start()
        threads.append(t)
    elapsed = time.monotonic() - start
    for t in threads:
        t.join()

    def tally(outcomes: list[str]) -> dict:
        served = sum(1 for o in outcomes if o.startswith("served name="))
        closed = outcomes.count("closed")
        return {"served": served, "closed": closed, "other": len(outcomes) - served - closed,
                "outcomes": sorted(set(o.split(" port=")[0] for o in outcomes))}

    emit({"primary": tally(results["primary"]), "other": tally(results["other"]),
          "period_seconds": round(elapsed, 3)})


def hold_tcp(args: argparse.Namespace) -> None:
    held: list[socket.socket] = []
    items = []
    for item in args.plan.split(";"):
        bind, _, rest = item.partition(">")
        target, _, count = rest.rpartition(":")
        addr = resolve(target)
        outcomes = []
        for _ in range(int(count)):
            outcome, s = exchange_line(addr, bind or None, 3.0)
            outcomes.append(outcome.split(" port=")[0])
            if s:
                held.append(s)
            time.sleep(0.1)
        items.append({"bind": bind, "target": target, "outcomes": outcomes})
    # Every admitted connection is still open here: re-check that the
    # proxy did not close one after its line.
    still_open = 0
    for s in held:
        s.setblocking(False)
        try:
            still_open += 1 if s.recv(1) else 0
        except BlockingIOError:
            still_open += 1
        except OSError:
            pass
    time.sleep(args.hold)
    for s in held:
        s.close()
    emit({"items": items, "held": len(held), "still_open": still_open})


def udp_query(args: argparse.Namespace) -> None:
    host, port = args.target.rsplit(":", 1)
    addr = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.bind:
        s.bind((args.bind, 0))
    s.settimeout(args.timeout)
    payload = f"query {os.getpid()} {time.time()}".encode()
    s.sendto(payload, addr)
    try:
        data, peer = s.recvfrom(2048)
        emit({"answered": data == payload, "from": f"{peer[0]}:{peer[1]}"})
    except socket.timeout:
        emit({"answered": False})


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("addr-in")
    a.add_argument("--subnet", required=True)
    a.set_defaults(fn=addr_in)

    a = sub.add_parser("tls-serve")
    a.add_argument("--port", type=int, required=True)
    a.add_argument("--cert", required=True)
    a.add_argument("--key", required=True)
    a.set_defaults(fn=tls_serve)

    a = sub.add_parser("tcp-burst")
    a.add_argument("--target", required=True)
    a.add_argument("--bind", required=True)
    a.add_argument("--count", type=int, required=True)
    a.add_argument("--period", type=float, default=1.0)
    a.add_argument("--other-target", required=True)
    a.add_argument("--other-bind", required=True)
    a.add_argument("--other-count", type=int, default=3)
    a.set_defaults(fn=tcp_burst)

    a = sub.add_parser("hold-tcp")
    a.add_argument("--plan", required=True, help="items <bind>><host>:<port>:<count>, ;-separated")
    a.add_argument("--hold", type=float, default=0.5)
    a.set_defaults(fn=hold_tcp)

    a = sub.add_parser("udp-query")
    a.add_argument("--target", required=True)
    a.add_argument("--bind")
    a.add_argument("--timeout", type=float, default=2.0)
    a.set_defaults(fn=udp_query)

    for name, fn in (("pending-flood", pending_flood), ("pending-fill", pending_fill)):
        a = sub.add_parser(name)
        a.add_argument("--target", required=True, help="the TLS stream, as the silent sources reach it")
        a.add_argument("--bind", required=True, help="silent source(s); comma-separated for pending-fill")
        a.add_argument("--tls-target", required=True, help="the TLS stream, as the TLS client reaches it")
        a.add_argument("--tls-bind", required=True)
        a.add_argument("--sni", required=True)
        a.add_argument("--tls-every", type=float, default=0.25)
        a.add_argument("--age-ms", type=int, default=1000)
        a.set_defaults(fn=fn)
        if name == "pending-flood":
            a.add_argument("--count", type=int, default=10000)
            a.add_argument("--rate", type=float, default=1000.0)
            a.add_argument("--hold", type=float, default=6.0)
        else:
            a.add_argument("--per-source", type=int, default=40)
            a.add_argument("--settle", type=float, default=1.5)
            a.add_argument("--duration", type=float, default=10.0)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
