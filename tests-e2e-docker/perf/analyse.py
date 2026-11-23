#!/usr/bin/env python3
"""Records, statistics and verdicts of the performance phase (Story 12.12 D-k).

Standard library only; run in the perf-tools container (perf-client), so the
host needs no Python. perf/run-perf.sh drives it, one subcommand per step:

  env      append the environment record (key=value pairs)
  guard    append an environment-guard result: the containers found running
           outside the perf project (none is a clean guard)
  record   parse one tool output (iperf3, the connect-latency client, the UDP
           hold, oha) into one run record and append it; with --samples or
           --db, keep the run's every latency beside the runs file
  settled  whether every gated check of a measurement has a conclusive attempt
           yet (exit 0) or needs another attempt (exit 1)
  rate     a fraction of one arm's median requests per second, from the last
           attempt of a measurement (the NFR1 fixed rate)
  report   the verdicts: results/perf-<ts>.json (the environment, every run's
           numbers, every check per attempt) and perf-summary.md; exit 0 when
           every gated check passes

The runs file is JSON lines, appended as the phase goes, so a phase that dies
half-way still leaves every run it measured.

Statistics (D-k): the spread of a series is its interquartile range over its
median (with 5 values, the 4th minus the 2nd sorted value, which is what the
inclusive quartile method gives); a check is conclusive on an attempt when each
series it compares has at least MIN_REPS values and a spread of at most
MAX_SPREAD; the ratio is median over median; the verdict is taken on the first
conclusive attempt.

p99 checks (D-k as amended on 2026-11-24) do not use the spread rule. Each arm's
latencies are pooled over its runs and the pooled p99 is the nearest-rank
99th percentile; the ratio is pooled p99 over pooled p99. Its 95 % interval
is a percentile bootstrap that resamples whole runs, with replacement, within
each arm, so the interval carries the run-to-run variation the spread rule
was about. An attempt is complete with P99_RUNS runs per arm. Verdict, for a
`<=` threshold: PASS when the upper bound is within it, FAIL when the lower
bound is past it, INCONCLUSIVE otherwise. The bootstrap is seeded (report
--seed) and the seed is in the report.

Samples live beside the runs file, one gzip text file per run (one latency
per line, in the check's unit) under perf-<ts>.samples/, named in the run
record.
"""

from __future__ import annotations

import argparse
import bisect
import gzip
import json
import random
import sqlite3
import statistics
import sys
from array import array
from functools import lru_cache
from pathlib import Path

MIN_REPS = 5
MAX_SPREAD = 0.05
GIB = 2**30
P99_RUNS = 10
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_LEVEL = 0.95
DEFAULT_SEED = 12012

# Every check the phase reports. `gated` ones decide the phase's exit; the
# others are printed beside them. `num` over `den` is the ratio held to
# `threshold` with `op`. `method: bootstrap` checks are judged on pooled
# samples and a bootstrap interval, every other ratio on the spread rule.
CHECKS: list[dict] = [
    {"id": "tcp-up-throughput", "measurement": "tcp-up", "metric": "gbps", "num": "lorica", "den": "nginx",
     "op": ">=", "threshold": 0.90, "gated": True, "label": "TCP upload throughput, Gbit/s"},
    {"id": "tcp-up-cpu-per-gib", "measurement": "tcp-up", "metric": "cpu_s_per_gib", "num": "lorica", "den": "nginx",
     "op": "<=", "threshold": 1.15, "gated": True, "label": "TCP upload proxy CPU, s per GiB"},
    {"id": "tcp-down-throughput", "measurement": "tcp-down", "metric": "gbps", "num": "lorica", "den": "nginx",
     "op": ">=", "threshold": 0.90, "gated": True, "label": "TCP download throughput, Gbit/s"},
    {"id": "tcp-down-cpu-per-gib", "measurement": "tcp-down", "metric": "cpu_s_per_gib", "num": "lorica", "den": "nginx",
     "op": "<=", "threshold": 1.15, "gated": True, "label": "TCP download proxy CPU, s per GiB"},
    {"id": "connect-p99", "method": "bootstrap", "measurement": "connect", "metric": "p99_us", "num": "lorica", "den": "nginx",
     "op": "<=", "threshold": 1.5, "gated": True, "label": "Accept to backend connect p99, us"},
    {"id": "udp-hold", "measurement": "udp", "kind": "hold", "gated": True,
     "label": "UDP hold at 80 % of the ceiling, no loss, no eviction"},
    {"id": "udp-memory-per-1000", "measurement": "udp", "metric": "pss_kib_per_1000", "num": "lorica", "den": "nginx",
     "gated": False, "label": "PSS per 1,000 UDP sessions, KiB"},
    {"id": "nfr1-http-rps-l0", "measurement": "nfr1-http-rps", "metric": "rps", "num": "L0", "den": "B",
     "op": ">=", "threshold": 0.95, "gated": True, "label": "NFR1 HTTP requests/s, 1.11.0 no stream vs 1.10.7"},
    {"id": "nfr1-http-rps-l1", "measurement": "nfr1-http-rps", "metric": "rps", "num": "L1", "den": "B",
     "op": ">=", "threshold": 0.95, "gated": True, "label": "NFR1 HTTP requests/s, 1.11.0 idle stream vs 1.10.7"},
    {"id": "nfr1-http-p99-l0", "method": "bootstrap", "measurement": "nfr1-http-p99", "metric": "p99_ms", "num": "L0", "den": "B",
     "op": "<=", "threshold": 1.05, "gated": True, "label": "NFR1 HTTP p99 at a fixed rate, ms, no stream"},
    {"id": "nfr1-http-p99-l1", "method": "bootstrap", "measurement": "nfr1-http-p99", "metric": "p99_ms", "num": "L1", "den": "B",
     "op": "<=", "threshold": 1.05, "gated": True, "label": "NFR1 HTTP p99 at a fixed rate, ms, idle stream"},
    {"id": "nfr1-https-rps-l0", "measurement": "nfr1-https-rps", "metric": "rps", "num": "L0", "den": "B",
     "op": ">=", "threshold": 0.95, "gated": False, "label": "NFR1 HTTPS requests/s, no stream (reported)"},
    {"id": "nfr1-https-rps-l1", "measurement": "nfr1-https-rps", "metric": "rps", "num": "L1", "den": "B",
     "op": ">=", "threshold": 0.95, "gated": False, "label": "NFR1 HTTPS requests/s, idle stream (reported)"},
    {"id": "nfr1-https-p99-l0", "method": "bootstrap", "measurement": "nfr1-https-p99", "metric": "p99_ms", "num": "L0", "den": "B",
     "op": "<=", "threshold": 1.05, "gated": False, "label": "NFR1 HTTPS p99, ms, no stream (reported)"},
    {"id": "nfr1-https-p99-l1", "method": "bootstrap", "measurement": "nfr1-https-p99", "metric": "p99_ms", "num": "L1", "den": "B",
     "op": "<=", "threshold": 1.05, "gated": False, "label": "NFR1 HTTPS p99, ms, idle stream (reported)"},
]


# ---- The runs file ---------------------------------------------------------

def append(runs: str, record: dict) -> None:
    with open(runs, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def load(runs: str) -> list[dict]:
    path = Path(runs)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def number(text: str) -> int | float | str:
    for kind in (int, float):
        try:
            return kind(text)
        except ValueError:
            pass
    return text


def cmd_env(args: argparse.Namespace) -> None:
    values = {}
    for pair in args.pairs:
        key, _, value = pair.partition("=")
        values[key] = number(value)
    append(args.runs, {"type": "env", **values})


def cmd_guard(args: argparse.Namespace) -> None:
    append(args.runs, {"type": "guard", "at": args.at, "foreign": args.foreign})
    if args.foreign:
        print(f"environment guard ({args.at}): containers outside the perf project: {' '.join(args.foreign)}")


# ---- One run ---------------------------------------------------------------

def parse_ticks(text: str) -> dict[str, int]:
    pairs = (item.split(":") for item in text.split(",") if ":" in item)
    return {pid: int(ticks) for pid, ticks in pairs}


def busiest_share(before: str, after: str) -> tuple[float | None, dict[str, int]]:
    """The share of the proxy's CPU ticks over a run that its busiest process took."""
    start, end = parse_ticks(before), parse_ticks(after)
    deltas = {pid: end[pid] - start.get(pid, 0) for pid in end}
    total = sum(deltas.values())
    return (max(deltas.values()) / total if total > 0 else None), deltas


# A run whose busiest process did more than this share of the work ran on
# one worker. With several workers such a run measured how the accepts
# fell, not the proxy, and is kept out of its series (Story 12.12 Lot M:
# the `-P 4` dry run had nginx on one worker in 4 runs of 5, Lorica in 1).
ONE_WORKER_SHARE = 0.9


def parse_iperf(data: dict, args: argparse.Namespace) -> tuple[dict, dict, str | None]:
    if data.get("error"):
        return {}, {}, f"iperf3: {data['error']}"
    end = data["end"]
    received = end["sum_received"]
    cpu_s = (args.cpu_after - args.cpu_before) / 1e6
    gib = received["bytes"] / GIB
    metrics = {"gbps": received["bits_per_second"] / 1e9, "cpu_s_per_gib": cpu_s / gib}
    share, deltas = busiest_share(args.ticks_before, args.ticks_after)
    raw = {
        "busiest_process_share": share,
        "process_ticks": deltas,
        "bytes_received": received["bytes"],
        "seconds": received["seconds"],
        "retransmits": end.get("sum_sent", {}).get("retransmits"),
        "proxy_cpu_s": cpu_s,
        "client_cpu_percent": end.get("cpu_utilization_percent", {}).get("host_total"),
        "server_cpu_percent": end.get("cpu_utilization_percent", {}).get("remote_total"),
    }
    if args.workers > 1 and share is not None and share > ONE_WORKER_SHARE:
        return metrics, raw, (f"one worker carried {share:.0%} of the proxy's CPU: the run measured "
                              f"the accept spread, not the proxy")
    return metrics, raw, None


def parse_connect(data: dict, args: argparse.Namespace) -> tuple[dict, dict, str | None]:
    if "p99_us" not in data:
        return {}, data, "no connection was matched at the backend"
    metrics = {"p99_us": data["p99_us"], "p50_us": data["p50_us"]}
    return metrics, data, None


def parse_udp(data: dict, args: argparse.Namespace) -> tuple[dict, dict, str | None]:
    held = (
        data["lost"] == 0
        and data["answered_every_round"] == args.sessions
        and args.peers == args.sessions
    )
    metrics: dict = {"held": 1 if held else 0}
    if args.pss_before is not None and args.pss_during is not None:
        metrics["pss_kib_per_1000"] = (args.pss_during - args.pss_before) / args.sessions * 1000
    raw = {**data, "backend_peers": args.peers, "pss_kib_before": args.pss_before, "pss_kib_during": args.pss_during}
    return metrics, raw, None


def parse_oha(data: dict, args: argparse.Namespace) -> tuple[dict, dict, str | None]:
    summary = data["summary"]
    raw = {
        "success_rate": summary["successRate"],
        "total_s": summary["total"],
        "status_codes": data.get("statusCodeDistribution"),
        "errors": data.get("errorDistribution"),
        "p50_ms": data["latencyPercentiles"]["p50"] * 1000,
    }
    codes = data.get("statusCodeDistribution") or {}
    if summary["successRate"] < 1.0 or set(codes) != {"200"}:
        return {}, raw, f"not every request answered 200: success {summary['successRate']}, codes {codes}"
    metrics = {"rps": summary["requestsPerSec"], "p99_ms": data["latencyPercentiles"]["p99"] * 1000}
    return metrics, raw, None


PARSERS = {"iperf": parse_iperf, "connect": parse_connect, "udp": parse_udp, "oha": parse_oha}


# ---- Samples -----------------------------------------------------------------

def samples_dir(runs: str) -> Path:
    """perf-<ts>.samples/ beside perf-<ts>.runs.jsonl."""
    path = Path(runs)
    stem = path.name[: -len(".runs.jsonl")] if path.name.endswith(".runs.jsonl") else path.stem
    return path.parent / f"{stem}.samples"


def read_tool_samples(args: argparse.Namespace) -> list[float] | None:
    """The run's every latency, in the unit of its check: oha's SQLite
    database in ms, the connect tool's sample file in us. With
    --latency-correction, oha 1.16 stores as `duration` the end minus the
    scheduled start, the latency its own percentiles are taken on."""
    if args.db:
        db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        try:
            return [row[0] * 1000 for row in db.execute("SELECT duration FROM oha")]
        finally:
            db.close()
    if args.samples:
        return [float(word) for word in Path(args.samples).read_text(encoding="ascii").split()]
    return None


def write_samples(runs: str, name: str, values: list[float]) -> str:
    """Writes one run's samples and returns their path relative to the
    runs file's directory, which is what the run record names."""
    directory = samples_dir(runs)
    directory.mkdir(exist_ok=True)
    path = directory / f"{name}.txt.gz"
    with gzip.open(path, "wt", encoding="ascii") as f:
        f.write("".join(f"{v:.6g}\n" for v in values))
    return f"{directory.name}/{path.name}"


@lru_cache(maxsize=None)
def load_samples(base: Path, relative: str) -> array:
    with gzip.open(base / relative, "rt", encoding="ascii") as f:
        return array("d", sorted(float(word) for word in f.read().split()))


def cmd_record(args: argparse.Namespace) -> None:
    error = None
    metrics: dict = {}
    raw: dict = {}
    values: list[float] | None = None
    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        metrics, raw, error = PARSERS[args.kind](data, args)
        values = read_tool_samples(args)
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        error = error or f"{type(exc).__name__}: {exc}"
    samples = None
    if values:
        samples = write_samples(args.runs, f"{args.measurement}.a{args.attempt}.r{args.rep}.{args.arm}", values)
        raw["samples_n"] = len(values)
    elif values is not None and error is None:
        error = "the run kept no latency sample"
    record = {
        "type": "run",
        "measurement": args.measurement,
        "attempt": args.attempt,
        "rep": args.rep,
        "arm": args.arm,
        "warmup": args.rep == 0,
        "ok": error is None,
        "error": error,
        "metrics": metrics,
        "raw": raw,
        "samples": samples,
    }
    append(args.runs, record)
    shown = ", ".join(f"{k} {v:.4g}" for k, v in metrics.items())
    label = "warm-up" if args.rep == 0 else f"rep {args.rep}"
    print(f"  {args.measurement} attempt {args.attempt} {label} {args.arm}: {shown or '-'}{'  ERROR ' + error if error else ''}")


# ---- Statistics ------------------------------------------------------------

def spread(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    median = statistics.median(values)
    if median == 0:
        return None
    q1, _, q3 = statistics.quantiles(values, n=4, method="inclusive")
    return (q3 - q1) / median


def series(runs: list[dict], measurement: str, attempt: int, arm: str, metric: str) -> list[float]:
    return [
        r["metrics"][metric]
        for r in runs
        if r["type"] == "run" and r["measurement"] == measurement and r["attempt"] == attempt
        and r["arm"] == arm and not r["warmup"] and r["ok"] and metric in r["metrics"]
    ]


def attempts_of(runs: list[dict], measurement: str) -> list[int]:
    return sorted({r["attempt"] for r in runs if r["type"] == "run" and r["measurement"] == measurement})


def describe(values: list[float]) -> dict:
    return {
        "n": len(values),
        "median": statistics.median(values) if values else None,
        "spread": spread(values),
        "values": values,
    }


def ratio_attempt(check: dict, runs: list[dict], attempt: int) -> dict:
    m = check["measurement"]
    num = describe(series(runs, m, attempt, check["num"], check["metric"]))
    den = describe(series(runs, m, attempt, check["den"], check["metric"]))
    conclusive = all(
        s["n"] >= MIN_REPS and s["spread"] is not None and s["spread"] <= MAX_SPREAD for s in (num, den)
    )
    ratio = num["median"] / den["median"] if num["median"] is not None and den["median"] else None
    measured = [
        r for r in runs
        if r["type"] == "run" and r["measurement"] == m and r["attempt"] == attempt and not r["warmup"]
    ]
    errors = [r["error"] for r in measured if not r["ok"]]
    one_worker = {}
    for arm in (check["num"], check["den"]):
        shares = [r["raw"].get("busiest_process_share") for r in measured if r["arm"] == arm]
        shares = [s for s in shares if s is not None]
        if shares:
            one_worker[arm] = f"{sum(1 for s in shares if s > ONE_WORKER_SHARE)}/{len(shares)}"
    return {"attempt": attempt, check["num"]: num, check["den"]: den, "ratio": ratio,
            "conclusive": conclusive, "errors": errors, "one_worker_runs": one_worker}


def pooled_percentile(runs: list[array], weights: list[int], percent: int, union: array) -> float:
    """Nearest-rank percentile of the multiset that holds each sorted run
    `weights[i]` times. `union` is every run's values, sorted: the answer
    is one of them, the smallest whose rank reaches the target."""
    chosen = [(run, weight) for run, weight in zip(runs, weights) if weight]
    total = sum(weight * len(run) for run, weight in chosen)
    target = max(1, -(-total * percent // 100))
    lo, hi = 0, len(union) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if sum(weight * bisect.bisect_right(run, union[mid]) for run, weight in chosen) >= target:
            hi = mid
        else:
            lo = mid + 1
    return union[lo]


def resample_weights(rng: random.Random, n: int) -> list[int]:
    """How many times each of n runs is drawn in one resample of n runs
    with replacement."""
    weights = [0] * n
    for _ in range(n):
        weights[rng.randrange(n)] += 1
    return weights


def merged(runs: list[array]) -> array:
    return array("d", sorted(v for run in runs for v in run))


def bootstrap_interval(
    num: list[array], den: list[array], rng: random.Random,
    resamples: int = BOOTSTRAP_RESAMPLES, level: float = BOOTSTRAP_LEVEL, percent: int = 99,
) -> tuple[float, float]:
    """Percentile bootstrap interval of pooled-p99(num) / pooled-p99(den),
    each arm's runs resampled whole and independently."""
    num_union, den_union = merged(num), merged(den)
    ratios = sorted(
        pooled_percentile(num, resample_weights(rng, len(num)), percent, num_union)
        / pooled_percentile(den, resample_weights(rng, len(den)), percent, den_union)
        for _ in range(resamples)
    )
    cut = round((1 - level) / 2 * resamples)
    return ratios[cut], ratios[resamples - 1 - cut]


def interval_verdict(check: dict, low: float, high: float) -> str:
    threshold = check["threshold"]
    if check["op"] == "<=":
        if high <= threshold:
            return "PASS"
        if low > threshold:
            return "FAIL"
    else:
        if low >= threshold:
            return "PASS"
        if high < threshold:
            return "FAIL"
    return "INCONCLUSIVE"


def bootstrap_attempt(check: dict, runs: list[dict], attempt: int,
                      base: Path | None = None, seed: int | None = None) -> dict:
    """One attempt of a p99 check. Complete (`conclusive`) with P99_RUNS
    runs per arm that kept their samples. With `base` (the samples'
    directory), the pooled p99s and the ratio; with `seed` too, the
    bootstrap interval, seeded per check and attempt."""
    m = check["measurement"]
    measured = [
        r for r in runs
        if r["type"] == "run" and r["measurement"] == m and r["attempt"] == attempt and not r["warmup"]
    ]
    result: dict = {"attempt": attempt, "ratio": None, "interval": None,
                    "errors": [r["error"] for r in measured if not r["ok"]], "one_worker_runs": {}}
    loaded: dict[str, list[array]] = {}
    for arm in (check["num"], check["den"]):
        mine = [r for r in measured if r["arm"] == arm and r["ok"] and r.get("samples")]
        result[arm] = {"n": len(mine), "values": [r["metrics"].get(check["metric"]) for r in mine],
                       "samples": [r["samples"] for r in mine], "pooled_p99": None}
        if base is not None and mine:
            loaded[arm] = [load_samples(base, r["samples"]) for r in mine]
            result[arm]["pooled_p99"] = pooled_percentile(loaded[arm], [1] * len(mine), 99, merged(loaded[arm]))
    result["conclusive"] = all(result[arm]["n"] >= P99_RUNS for arm in (check["num"], check["den"]))
    num, den = result[check["num"]]["pooled_p99"], result[check["den"]]["pooled_p99"]
    if num is not None and den:
        result["ratio"] = num / den
        if seed is not None:
            rng = random.Random(f"{seed}:{check['id']}:{attempt}")
            result["interval"] = list(bootstrap_interval(loaded[check["num"]], loaded[check["den"]], rng))
    return result


def hold_attempt(check: dict, runs: list[dict], attempt: int) -> dict:
    m = check["measurement"]
    held = {arm: series(runs, m, attempt, arm, "held") for arm in ("lorica", "nginx")}
    conclusive = len(held["lorica"]) >= MIN_REPS and len(held["nginx"]) >= MIN_REPS and all(held["nginx"])
    details = [
        {"rep": r["rep"], "arm": r["arm"], "held": r["metrics"].get("held"),
         "lost": r["raw"].get("lost"), "answered_every_round": r["raw"].get("answered_every_round"),
         "peers": r["raw"].get("backend_peers"), "sessions": r["raw"].get("sessions")}
        for r in runs
        if r["type"] == "run" and r["measurement"] == m and r["attempt"] == attempt and not r["warmup"]
    ]
    return {"attempt": attempt, "held": held, "conclusive": conclusive, "runs": details,
            "lorica_all_held": bool(held["lorica"]) and all(held["lorica"])}


def meets(check: dict, ratio: float) -> bool:
    return ratio >= check["threshold"] if check["op"] == ">=" else ratio <= check["threshold"]


def attempt_of(check: dict, runs: list[dict], attempt: int) -> dict:
    if check.get("kind") == "hold":
        return hold_attempt(check, runs, attempt)
    if check.get("method") == "bootstrap":
        return bootstrap_attempt(check, runs, attempt)
    return ratio_attempt(check, runs, attempt)


def evaluate(check: dict, runs: list[dict], base: Path | None = None, seed: int | None = None) -> dict:
    """A check's verdict over every attempt. A bootstrap check reads its
    samples (under `base`) and resamples (with `seed`) only for the attempt
    it shows; without them it reports completeness alone (`settled`)."""
    attempts = attempts_of(runs, check["measurement"])
    per_attempt = [attempt_of(check, runs, a) for a in attempts]
    result = {**check, "attempts": per_attempt, "verdict": "NOT-RUN", "decided_on": None, "ratio": None,
              "interval": None}
    if not per_attempt:
        return result
    decided = next((a for a in per_attempt if a["conclusive"]), None)
    shown = decided or per_attempt[-1]
    result["decided_on"] = decided["attempt"] if decided else None
    if check.get("method") == "bootstrap":
        if base is not None:
            index = per_attempt.index(shown)
            shown = per_attempt[index] = bootstrap_attempt(check, runs, shown["attempt"], base, seed)
        result["ratio"], result["interval"] = shown["ratio"], shown["interval"]
        if not check["gated"]:
            result["verdict"] = "REPORTED"
        elif decided is None or shown["interval"] is None:
            result["verdict"] = "INCONCLUSIVE"
        else:
            result["verdict"] = interval_verdict(check, *shown["interval"])
        return result
    if check.get("kind") == "hold":
        if decided is None:
            result["verdict"] = "INCONCLUSIVE"
        else:
            result["verdict"] = "PASS" if decided["lorica_all_held"] else "FAIL"
        return result
    result["ratio"] = shown["ratio"]
    if not check["gated"]:
        result["verdict"] = "REPORTED"
    elif decided is None or decided["ratio"] is None:
        result["verdict"] = "INCONCLUSIVE"
    else:
        result["verdict"] = "PASS" if meets(check, decided["ratio"]) else "FAIL"
    return result


def cmd_settled(args: argparse.Namespace) -> None:
    runs = load(args.runs)
    unsettled = []
    for check in CHECKS:
        if check["measurement"] != args.measurement or not check["gated"]:
            continue
        result = evaluate(check, runs)
        last = result["attempts"][-1] if result["attempts"] else None
        if result["decided_on"] is None:
            unsettled.append(check["id"])
        if check.get("method") == "bootstrap":
            state = f"complete on attempt {result['decided_on']}" if result["decided_on"] else "not complete yet"
        else:
            state = f"conclusive on attempt {result['decided_on']}" if result["decided_on"] else "not conclusive yet"
        print(f"  {check['id']}: {state}; last attempt {summarise(check, last)}")
    sys.exit(1 if unsettled else 0)


def cmd_rate(args: argparse.Namespace) -> None:
    runs = load(args.runs)
    attempts = attempts_of(runs, args.measurement)
    if not attempts:
        sys.exit(f"no attempt of {args.measurement} to take a rate from")
    values = series(runs, args.measurement, attempts[-1], args.arm, "rps")
    if not values:
        sys.exit(f"no {args.arm} requests/s in attempt {attempts[-1]} of {args.measurement}")
    print(max(1, int(statistics.median(values) * args.fraction)))


# ---- Report ----------------------------------------------------------------

def fmt(value: float | None, digits: int = 4) -> str:
    return "-" if value is None else f"{value:.{digits}g}"


def pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f} %"


def interval_text(interval: list[float] | None) -> str:
    return "[-]" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"


def summarise(check: dict, attempt: dict | None) -> str:
    if attempt is None:
        return "none"
    if check.get("kind") == "hold":
        return (f"lorica held {sum(attempt['held']['lorica'])}/{len(attempt['held']['lorica'])}, "
                f"nginx held {sum(attempt['held']['nginx'])}/{len(attempt['held']['nginx'])}")
    num, den = attempt[check["num"]], attempt[check["den"]]
    if check.get("method") == "bootstrap":
        return (f"{check['num']} {num['n']} runs, pooled p99 {fmt(num['pooled_p99'])}; "
                f"{check['den']} {den['n']} runs, pooled p99 {fmt(den['pooled_p99'])}; "
                f"ratio {fmt(attempt['ratio'], 3)} {interval_text(attempt['interval'])}")
    one = attempt.get("one_worker_runs")
    return (f"{check['num']} {fmt(num['median'])} ({pct(num['spread'])}), "
            f"{check['den']} {fmt(den['median'])} ({pct(den['spread'])}), ratio {fmt(attempt['ratio'], 3)}"
            + (f"; runs on one worker {one}" if one else ""))


def cmd_report(args: argparse.Namespace) -> None:
    runs = load(args.runs)
    env: dict = {}
    for r in runs:
        if r["type"] == "env":
            env.update({k: v for k, v in r.items() if k != "type"})
    guards = [r for r in runs if r["type"] == "guard"]
    foreign = sorted({name for g in guards for name in g["foreign"]})
    environment_problems = []
    if foreign:
        environment_problems.append(f"containers outside the perf project were running: {', '.join(foreign)}")
    if str(env.get("release_run")) == "1" and env.get("layout") != "large":
        environment_problems.append(
            f"a release run needs the larger layout (8 CPUs or more, Resolved 13); this one ran {env.get('layout')}"
        )

    base = Path(args.runs).parent
    results = [evaluate(check, runs, base, args.seed) for check in CHECKS]
    if args.not_run:
        for result in results:
            result["verdict"] = "NOT-RUN"
    elif environment_problems:
        for result in results:
            if result["gated"] and result["verdict"] != "NOT-RUN":
                result["verdict"] = "INCONCLUSIVE (environment)"

    gated = [r for r in results if r["gated"]]
    passed = bool(gated) and all(r["verdict"] == "PASS" for r in gated)
    inconclusive = any(r["verdict"].startswith("INCONCLUSIVE") for r in gated)

    Path(args.json).write_text(json.dumps(
        {"environment": env, "environment_problems": environment_problems, "guards": guards,
         "not_run": args.not_run, "checks": results,
         "bootstrap": {"seed": args.seed, "resamples": BOOTSTRAP_RESAMPLES, "level": BOOTSTRAP_LEVEL,
                       "runs_per_arm": P99_RUNS, "percentile": "nearest rank, pooled over an arm's runs"},
         "runs": [r for r in runs if r["type"] == "run"],
         "passed": passed},
        indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = ["# Performance phase (Story 12.12)", ""]
    if args.not_run:
        lines += [f"**NOT-RUN**: {args.not_run}", ""]
    lines += ["| Environment | |", "|---|---|"]
    for key in sorted(env):
        lines.append(f"| {key} | `{env[key]}` |")
    lines.append("")
    for problem in environment_problems:
        lines += [f"**Environment guard**: {problem}. Every gated verdict is INCONCLUSIVE (environment).", ""]
    lines += ["## Verdicts", "",
              "| Check | Gated | Threshold | Ratio | Decided on attempt | Verdict |",
              "|---|---|---|---|---|---|"]
    for r in results:
        threshold = f"{r['op']} {r['threshold']}" if "threshold" in r and r.get("op") else "-"
        if r.get("kind") == "hold":
            threshold = "every Lorica run holds"
        ratio = fmt(r["ratio"], 3)
        if r.get("method") == "bootstrap":
            ratio += f" {interval_text(r['interval'])}"
        lines.append(f"| {r['label']} | {'yes' if r['gated'] else 'no'} | {threshold} | "
                     f"{ratio} | {r['decided_on'] or '-'} | {r['verdict']} |")
    lines += ["", f"Spread is IQR over median; a series is conclusive at {MAX_SPREAD * 100:.0f} % or less "
              f"with at least {MIN_REPS} runs. A p99 check pools every latency of an arm's runs (nearest-rank "
              f"p99) and brackets the ratio with a {BOOTSTRAP_LEVEL * 100:.0f} % bootstrap interval, "
              f"{BOOTSTRAP_RESAMPLES} resamples of whole runs, seed {args.seed}; an attempt is complete with "
              f"{P99_RUNS} runs per arm; PASS when the interval is within the threshold, FAIL when it is "
              "wholly past it, INCONCLUSIVE otherwise. Every attempt is listed below.", ""]
    for r in results:
        if not r["attempts"]:
            continue
        lines += [f"### {r['label']}", ""]
        if r.get("method") == "bootstrap":
            lines += [f"| Attempt | {r['num']} pooled p99 | {r['num']} runs | {r['den']} pooled p99 | "
                      f"{r['den']} runs | Ratio | {BOOTSTRAP_LEVEL * 100:.0f} % interval | Complete | Errors |",
                      "|---|---|---|---|---|---|---|---|---|"]
            for a in r["attempts"]:
                num, den = a[r["num"]], a[r["den"]]
                lines.append(f"| {a['attempt']} | {fmt(num['pooled_p99'])} | {num['n']} | "
                             f"{fmt(den['pooled_p99'])} | {den['n']} | {fmt(a['ratio'], 3)} | "
                             f"{interval_text(a['interval'])} | {'yes' if a['conclusive'] else 'no'} | "
                             f"{len(a['errors'])} |")
                values = "; ".join(f"{arm} per-run p99 " + ", ".join(fmt(v) for v in a[arm]["values"])
                                   for arm in (r["num"], r["den"]))
                lines.append(f"| | {values} | | | | | | | |")
        elif r.get("kind") == "hold":
            lines += ["| Attempt | Rep | Arm | Held | Lost | Every round | Backend peers | Sessions |",
                      "|---|---|---|---|---|---|---|---|"]
            for a in r["attempts"]:
                for d in a["runs"]:
                    lines.append(f"| {a['attempt']} | {d['rep']} | {d['arm']} | {d['held']} | {d['lost']} | "
                                 f"{d['answered_every_round']} | {d['peers']} | {d['sessions']} |")
        else:
            lines += [f"| Attempt | {r['num']} median | {r['num']} spread | {r['den']} median | "
                      f"{r['den']} spread | Ratio | Conclusive | Errors | Runs on one worker |",
                      "|---|---|---|---|---|---|---|---|---|"]
            for a in r["attempts"]:
                num, den = a[r["num"]], a[r["den"]]
                one = ", ".join(f"{arm} {count}" for arm, count in a["one_worker_runs"].items()) or "-"
                lines.append(f"| {a['attempt']} | {fmt(num['median'])} | {pct(num['spread'])} | "
                             f"{fmt(den['median'])} | {pct(den['spread'])} | {fmt(a['ratio'], 3)} | "
                             f"{'yes' if a['conclusive'] else 'no'} | {len(a['errors'])} | {one} |")
                values = "; ".join(f"{arm} " + ", ".join(fmt(v) for v in a[arm]["values"])
                                   for arm in (r["num"], r["den"]))
                lines.append(f"| | {values} | | | | | | | |")
        if r.get("metric") == "pss_kib_per_1000":
            first = [
                f"{x['arm']} {fmt(x['metrics'].get(r['metric']))} (attempt {x['attempt']})"
                for x in runs
                if x["type"] == "run" and x["measurement"] == r["measurement"] and x["warmup"]
            ]
            lines += ["", "A proxy's allocator keeps what a fill took, so a run measures what a "
                      "refill costs on top of the previous one; the warm-up runs, the first fill of "
                      f"each attempt, read: {'; '.join(first)}."]
        lines.append("")
    if inconclusive:
        lines += ["**Release blocked pending owner decision**: a gated measurement is inconclusive "
                  "(Story 12.12 AC #3).", ""]
    lines.append(f"**Phase verdict**: {'PASS' if passed else 'NOT PASSED'}")
    text = "\n".join(lines) + "\n"
    Path(args.markdown).write_text(text, encoding="utf-8")

    print("")
    print("=== Performance phase verdicts ===")
    for r in results:
        print(f"  {r['verdict']:<28} {r['id']}: {summarise(r, next((a for a in r['attempts'] if a['attempt'] == r['decided_on']), r['attempts'][-1] if r['attempts'] else None))}")
    for problem in environment_problems:
        print(f"  environment guard: {problem}")
    if inconclusive:
        print("  release blocked pending owner decision (a gated measurement is inconclusive)")
    print(f"=== PERF PHASE {'PASSED' if passed else 'NOT PASSED'} ===")
    sys.exit(0 if passed else 1)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("env")
    e.add_argument("--runs", required=True)
    e.add_argument("pairs", nargs="*")

    g = sub.add_parser("guard")
    g.add_argument("--runs", required=True)
    g.add_argument("--at", required=True)
    g.add_argument("foreign", nargs="*")

    r = sub.add_parser("record")
    r.add_argument("--runs", required=True)
    r.add_argument("--measurement", required=True)
    r.add_argument("--attempt", type=int, required=True)
    r.add_argument("--rep", type=int, required=True, help="0 is the warm-up run")
    r.add_argument("--arm", required=True)
    r.add_argument("--kind", required=True, choices=sorted(PARSERS))
    r.add_argument("--file", required=True)
    r.add_argument("--cpu-before", type=int, default=0)
    r.add_argument("--cpu-after", type=int, default=0)
    r.add_argument("--ticks-before", default="", help="pid:ticks,... of the proxy's processes")
    r.add_argument("--ticks-after", default="")
    r.add_argument("--workers", type=int, default=1, help="worker processes per proxy")
    r.add_argument("--sessions", type=int, default=0)
    r.add_argument("--peers", type=int, default=0)
    r.add_argument("--pss-before", type=int)
    r.add_argument("--pss-during", type=int)
    r.add_argument("--samples", help="the connect tool's latency file, one value in us per line")
    r.add_argument("--db", help="oha's --db-url SQLite file, every request of the run")

    s = sub.add_parser("settled")
    s.add_argument("--runs", required=True)
    s.add_argument("--measurement", required=True)

    t = sub.add_parser("rate")
    t.add_argument("--runs", required=True)
    t.add_argument("--measurement", required=True)
    t.add_argument("--arm", required=True)
    t.add_argument("--fraction", type=float, default=0.5)

    o = sub.add_parser("report")
    o.add_argument("--runs", required=True)
    o.add_argument("--json", required=True)
    o.add_argument("--markdown", required=True)
    o.add_argument("--not-run", default="", help="the reason the phase did not run")
    o.add_argument("--seed", type=int, default=DEFAULT_SEED, help="the p99 bootstrap's seed, recorded in the report")

    args = p.parse_args()
    {"env": cmd_env, "guard": cmd_guard, "record": cmd_record, "settled": cmd_settled,
     "rate": cmd_rate, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    main()
