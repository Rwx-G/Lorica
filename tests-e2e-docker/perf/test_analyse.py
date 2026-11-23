"""Tests of the performance phase's statistics, analyse.py (Story 12.12 D-k).

Standard library only, like analyse.py. Run from this directory:

    python3 -m unittest test_analyse

or in a container, from tests-e2e-docker/:

    docker run --rm -v "$PWD/perf:/t:ro" -w /t python:3 python3 -m unittest -v test_analyse
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import random
import re
import sqlite3
import sys
import tempfile
import unittest
from array import array
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyse  # noqa: E402

CONNECT = next(c for c in analyse.CHECKS if c["id"] == "connect-p99")
HTTPS_P99 = next(c for c in analyse.CHECKS if c["id"] == "nfr1-https-p99-l0")
TCP_UP = next(c for c in analyse.CHECKS if c["id"] == "tcp-up-throughput")


def nearest_rank(values: list[float], percent: int) -> float:
    ordered = sorted(values)
    rank = -(-len(ordered) * percent // 100)
    return ordered[max(1, rank) - 1]


def latencies(rng: random.Random, n: int, scale: float, tail: float) -> list[float]:
    """n latencies around `scale` with a 2 % tail near `scale * tail`."""
    return [scale * (tail if rng.random() < 0.02 else 1.0) * rng.uniform(0.9, 1.1) for _ in range(n)]


def run_main(*argv: str) -> int:
    saved = sys.argv
    sys.argv = ["analyse.py", *argv]
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            analyse.main()
    except SystemExit as exit_:
        return int(exit_.code or 0)
    finally:
        sys.argv = saved
    return 0


class PooledPercentile(unittest.TestCase):
    def test_matches_the_nearest_rank_of_the_weighted_concatenation(self) -> None:
        rng = random.Random(1)
        for _ in range(50):
            runs = [sorted(rng.uniform(0, 100) for _ in range(rng.randint(1, 40))) for _ in range(rng.randint(1, 6))]
            weights = [rng.randint(0, 3) for _ in runs]
            if not any(weights):
                weights[0] = 1
            for percent in (50, 99):
                flat = [v for run, w in zip(runs, weights) for _ in range(w) for v in run]
                got = analyse.pooled_percentile([array("d", r) for r in runs], weights, percent,
                                                analyse.merged([array("d", r) for r in runs]))
                self.assertEqual(got, nearest_rank(flat, percent))

    def test_pooled_p99_is_not_the_median_of_the_per_run_p99s(self) -> None:
        # One run of ten carries the tail: its own p99 is high, every
        # other run's is low, so the median of the per-run p99s hides it;
        # the pooled p99 of 1,000 values sits on the 990th.
        quiet = [array("d", [1.0] * 100) for _ in range(9)]
        tail = array("d", [1.0] * 80 + [9.0] * 20)
        pooled = analyse.pooled_percentile(quiet + [tail], [1] * 10, 99, analyse.merged(quiet + [tail]))
        self.assertEqual(pooled, 9.0)


class Resampling(unittest.TestCase):
    def test_a_resample_draws_n_runs(self) -> None:
        rng = random.Random(2)
        for n in (1, 5, 10):
            self.assertEqual(sum(analyse.resample_weights(rng, n)), n)

    def test_the_interval_is_reproducible_from_its_seed(self) -> None:
        rng = random.Random(3)
        num = [array("d", sorted(latencies(rng, 500, 1.0, 3.0))) for _ in range(10)]
        den = [array("d", sorted(latencies(rng, 500, 1.0, 3.0))) for _ in range(10)]
        first = analyse.bootstrap_interval(num, den, random.Random("s"), resamples=200)
        again = analyse.bootstrap_interval(num, den, random.Random("s"), resamples=200)
        self.assertEqual(first, again)
        low, high = first
        self.assertLessEqual(low, high)

    def test_the_interval_brackets_a_known_ratio(self) -> None:
        rng = random.Random(4)
        num = [array("d", sorted(latencies(rng, 1000, 2.0, 3.0))) for _ in range(10)]
        den = [array("d", sorted(latencies(rng, 1000, 1.0, 3.0))) for _ in range(10)]
        low, high = analyse.bootstrap_interval(num, den, random.Random("k"), resamples=300)
        self.assertTrue(1.7 < low <= high < 2.3, (low, high))

    def test_whole_runs_carry_the_run_to_run_variation(self) -> None:
        # Two runs of ten with a tail twice as heavy widen the interval;
        # resampling single latencies would average them away.
        rng = random.Random(5)
        steady = [array("d", sorted(latencies(rng, 1000, 1.0, 3.0))) for _ in range(10)]
        uneven = [array("d", sorted(latencies(rng, 1000, 1.0, 3.0 if i > 1 else 6.0))) for i in range(10)]
        reference = [array("d", sorted(latencies(rng, 1000, 1.0, 3.0))) for _ in range(10)]
        narrow = analyse.bootstrap_interval(steady, reference, random.Random("w"), resamples=300)
        wide = analyse.bootstrap_interval(uneven, reference, random.Random("w"), resamples=300)
        self.assertGreater(wide[1] - wide[0], 2 * (narrow[1] - narrow[0]))


class IntervalVerdict(unittest.TestCase):
    def test_at_most_threshold(self) -> None:
        check = {"op": "<=", "threshold": 1.05}
        self.assertEqual(analyse.interval_verdict(check, 0.90, 1.05), "PASS")
        self.assertEqual(analyse.interval_verdict(check, 0.90, 1.06), "INCONCLUSIVE")
        self.assertEqual(analyse.interval_verdict(check, 1.05, 1.20), "INCONCLUSIVE")
        self.assertEqual(analyse.interval_verdict(check, 1.06, 1.20), "FAIL")

    def test_at_least_threshold(self) -> None:
        check = {"op": ">=", "threshold": 0.95}
        self.assertEqual(analyse.interval_verdict(check, 0.95, 1.10), "PASS")
        self.assertEqual(analyse.interval_verdict(check, 0.94, 1.10), "INCONCLUSIVE")
        self.assertEqual(analyse.interval_verdict(check, 0.80, 0.94), "FAIL")


class Phase(unittest.TestCase):
    """Runs recorded through `analyse.py record`, judged by `report`."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.runs = str(self.dir / "perf-t.runs.jsonl")
        analyse.load_samples.cache_clear()

    def tearDown(self) -> None:
        analyse.load_samples.cache_clear()
        self.tmp.cleanup()

    def record_connect(self, attempt: int, rep: int, arm: str, values: list[float]) -> None:
        ordered = sorted(values)
        (self.dir / "run.json").write_text(json.dumps(
            {"p99_us": nearest_rank(ordered, 99), "p50_us": nearest_rank(ordered, 50)}), encoding="utf-8")
        (self.dir / "run.samples").write_text("".join(f"{v:.3f}\n" for v in values), encoding="ascii")
        self.assertEqual(run_main("record", "--runs", self.runs, "--measurement", "connect",
                                  "--attempt", str(attempt), "--rep", str(rep), "--arm", arm, "--kind", "connect",
                                  "--file", str(self.dir / "run.json"), "--samples", str(self.dir / "run.samples")), 0)

    def connect_attempt(self, attempt: int, reps: int, lorica: float, rng: random.Random,
                        uneven_p99: bool = False) -> None:
        for rep in range(reps + 1):
            for arm, scale in (("lorica", lorica), ("nginx", 1.0)):
                # With uneven_p99, every other run is 20 % slower than
                # the one before: the per-run p99s spread past 5 %.
                jitter = (1.1 if rep % 2 else 0.9) if uneven_p99 else 1.0
                self.record_connect(attempt, rep, arm, latencies(rng, 2000, 400.0 * scale * jitter, 3.0))

    def report(self, seed: int = 7) -> tuple[int, dict, str]:
        status = run_main("report", "--runs", self.runs, "--json", str(self.dir / "perf.json"),
                          "--markdown", str(self.dir / "summary.md"), "--seed", str(seed))
        return (status, json.loads((self.dir / "perf.json").read_text(encoding="utf-8")),
                (self.dir / "summary.md").read_text(encoding="utf-8"))

    def connect_result(self, report: dict) -> dict:
        return next(c for c in report["checks"] if c["id"] == "connect-p99")

    def test_a_record_keeps_the_runs_every_latency(self) -> None:
        self.record_connect(1, 1, "lorica", [3.0, 1.0, 2.0])
        record = analyse.load(self.runs)[0]
        self.assertTrue(record["ok"])
        self.assertEqual(record["samples"], "perf-t.samples/connect.a1.r1.lorica.txt.gz")
        self.assertEqual(record["raw"]["samples_n"], 3)
        with gzip.open(self.dir / record["samples"], "rt", encoding="ascii") as f:
            self.assertEqual(sorted(float(v) for v in f.read().split()), [1.0, 2.0, 3.0])

    def test_oha_samples_are_read_from_its_database_in_ms(self) -> None:
        db = self.dir / "run.db"
        conn = sqlite3.connect(db)
        # oha 1.16's table, as `--db-url` creates it (durations in s).
        conn.execute("CREATE TABLE oha (url TEXT NOT NULL, start REAL NOT NULL, start_latency_correction REAL, "
                     "end REAL NOT NULL, duration REAL NOT NULL, status INTEGER NOT NULL, "
                     "len_bytes INTEGER NOT NULL, run INTEGER NOT NULL)")
        conn.executemany("INSERT INTO oha VALUES ('u', 0, 0, 0, ?, 200, 1, 0)", [(0.002,), (0.004,)])
        conn.commit()
        conn.close()
        (self.dir / "oha.json").write_text(json.dumps({
            "summary": {"successRate": 1.0, "total": 20.0, "requestsPerSec": 8000.0},
            "statusCodeDistribution": {"200": 2},
            "latencyPercentiles": {"p50": 0.002, "p99": 0.004}}), encoding="utf-8")
        run_main("record", "--runs", self.runs, "--measurement", "nfr1-http-p99", "--attempt", "1", "--rep", "1",
                 "--arm", "B", "--kind", "oha", "--file", str(self.dir / "oha.json"), "--db", str(db))
        record = analyse.load(self.runs)[0]
        self.assertTrue(record["ok"], record["error"])
        self.assertEqual(list(analyse.load_samples(self.dir, record["samples"])), [2.0, 4.0])

    def test_a_run_with_no_sample_is_not_ok(self) -> None:
        (self.dir / "run.json").write_text(json.dumps({"p99_us": 1.0, "p50_us": 1.0}), encoding="utf-8")
        (self.dir / "run.samples").write_text("", encoding="ascii")
        run_main("record", "--runs", self.runs, "--measurement", "connect", "--attempt", "1", "--rep", "1",
                 "--arm", "lorica", "--kind", "connect", "--file", str(self.dir / "run.json"),
                 "--samples", str(self.dir / "run.samples"))
        record = analyse.load(self.runs)[0]
        self.assertFalse(record["ok"])
        self.assertEqual(record["error"], "the run kept no latency sample")

    def test_a_missing_sample_file_is_an_error_not_a_crash(self) -> None:
        (self.dir / "run.json").write_text(json.dumps({"p99_us": 1.0, "p50_us": 1.0}), encoding="utf-8")
        run_main("record", "--runs", self.runs, "--measurement", "connect", "--attempt", "1", "--rep", "1",
                 "--arm", "lorica", "--kind", "connect", "--file", str(self.dir / "run.json"),
                 "--samples", str(self.dir / "absent"))
        record = analyse.load(self.runs)[0]
        self.assertFalse(record["ok"])
        self.assertIn("FileNotFoundError", record["error"])

    def test_uneven_per_run_p99s_still_reach_a_verdict(self) -> None:
        # The spread rule calls this INCONCLUSIVE on every attempt (the
        # per-run p99s alternate 20 % apart); pooled, with a bootstrap
        # interval on whole runs, equal arms pass the 1.5 threshold.
        self.connect_attempt(1, analyse.P99_RUNS, 1.0, random.Random(10), uneven_p99=True)
        per_run = [r["metrics"]["p99_us"] for r in analyse.load(self.runs)
                   if r["arm"] == "lorica" and not r["warmup"]]
        self.assertGreater(analyse.spread(per_run), analyse.MAX_SPREAD)
        status, report, summary = self.report()
        result = self.connect_result(report)
        self.assertEqual(result["verdict"], "PASS", result["interval"])
        self.assertEqual(result["decided_on"], 1)
        self.assertLessEqual(result["interval"][1], CONNECT["threshold"])
        self.assertIn("seed 7", summary)
        self.assertEqual(report["bootstrap"]["seed"], 7)

    def test_an_arm_p99_pools_every_latency_of_its_runs(self) -> None:
        # One run in ten carries the whole tail: the median of the per-run
        # p99s would not see it, the pooled p99 does.
        values = {"lorica": [], "nginx": []}
        for rep in range(1, analyse.P99_RUNS + 1):
            for arm in values:
                run = [100.0] * 80 + [900.0] * 20 if arm == "lorica" and rep == 1 else [100.0] * 100
                values[arm] += run
                self.record_connect(1, rep, arm, run)
        attempt = analyse.bootstrap_attempt(CONNECT, analyse.load(self.runs), 1, self.dir)
        for arm, pooled in values.items():
            self.assertEqual(attempt[arm]["pooled_p99"], nearest_rank(pooled, 99))
        self.assertEqual(attempt["ratio"], 9.0)

    def test_a_slower_arm_fails(self) -> None:
        self.connect_attempt(1, analyse.P99_RUNS, 2.0, random.Random(11))
        _, report, _ = self.report()
        result = self.connect_result(report)
        self.assertEqual(result["verdict"], "FAIL", result["interval"])
        self.assertGreater(result["interval"][0], CONNECT["threshold"])

    def test_an_interval_across_the_threshold_is_inconclusive(self) -> None:
        self.connect_attempt(1, analyse.P99_RUNS, CONNECT["threshold"], random.Random(12), uneven_p99=True)
        _, report, _ = self.report()
        result = self.connect_result(report)
        self.assertEqual(result["verdict"], "INCONCLUSIVE", result["interval"])
        low, high = result["interval"]
        self.assertTrue(low <= CONNECT["threshold"] < high, result["interval"])

    def test_the_seed_makes_the_report_reproducible(self) -> None:
        self.connect_attempt(1, analyse.P99_RUNS, 1.2, random.Random(13), uneven_p99=True)
        first = self.connect_result(self.report(seed=5)[1])["interval"]
        analyse.load_samples.cache_clear()
        self.assertEqual(self.connect_result(self.report(seed=5)[1])["interval"], first)
        self.assertNotEqual(self.connect_result(self.report(seed=6)[1])["interval"], first)

    def test_an_attempt_short_of_p99_runs_is_incomplete(self) -> None:
        self.connect_attempt(1, analyse.P99_RUNS - 1, 1.0, random.Random(14))
        self.assertEqual(run_main("settled", "--runs", self.runs, "--measurement", "connect"), 1)
        _, report, _ = self.report()
        result = self.connect_result(report)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIsNone(result["decided_on"])

    def test_failed_and_warm_up_runs_do_not_count(self) -> None:
        self.connect_attempt(1, analyse.P99_RUNS - 1, 1.0, random.Random(15))
        (self.dir / "run.json").write_text("{}", encoding="utf-8")
        for arm in ("lorica", "nginx"):
            run_main("record", "--runs", self.runs, "--measurement", "connect", "--attempt", "1",
                     "--rep", str(analyse.P99_RUNS), "--arm", arm, "--kind", "connect",
                     "--file", str(self.dir / "run.json"))
        attempt = analyse.bootstrap_attempt(CONNECT, analyse.load(self.runs), 1)
        self.assertEqual((attempt["lorica"]["n"], attempt["nginx"]["n"]), (analyse.P99_RUNS - 1,) * 2)
        self.assertFalse(attempt["conclusive"])
        self.assertEqual(len(attempt["errors"]), 2)

    def test_the_first_complete_attempt_decides(self) -> None:
        rng = random.Random(16)
        self.connect_attempt(1, analyse.P99_RUNS - 1, 2.0, rng)
        self.connect_attempt(2, analyse.P99_RUNS, 1.0, rng)
        self.connect_attempt(3, analyse.P99_RUNS, 2.0, rng)
        self.assertEqual(run_main("settled", "--runs", self.runs, "--measurement", "connect"), 0)
        _, report, _ = self.report()
        result = self.connect_result(report)
        self.assertEqual((result["decided_on"], result["verdict"]), (2, "PASS"))

    def test_a_reported_p99_check_is_never_gated(self) -> None:
        runs = [{"type": "run", "measurement": HTTPS_P99["measurement"], "attempt": 1, "rep": 1, "arm": arm,
                 "warmup": False, "ok": True, "error": None, "metrics": {}, "raw": {}, "samples": None}
                for arm in ("L0", "B")]
        self.assertEqual(analyse.evaluate(HTTPS_P99, runs)["verdict"], "REPORTED")

    def test_throughput_keeps_the_spread_rule(self) -> None:
        runs = [{"type": "run", "measurement": "tcp-up", "attempt": 1, "rep": rep, "arm": arm, "warmup": False,
                 "ok": True, "error": None, "metrics": {"gbps": value}, "raw": {}}
                for rep in range(1, analyse.MIN_REPS + 1)
                for arm, value in (("lorica", 9.5 + rep * 0.01), ("nginx", 10.0 + rep * 0.01))]
        result = analyse.evaluate(TCP_UP, runs)
        self.assertEqual((result["decided_on"], result["verdict"], result["interval"]), (1, "PASS", None))
        runs[0]["metrics"]["gbps"] = 5.0
        runs[2]["metrics"]["gbps"] = 5.0
        self.assertEqual(analyse.evaluate(TCP_UP, runs)["verdict"], "INCONCLUSIVE")


class Driver(unittest.TestCase):
    """run-perf.sh's limits are analyse.py's constants, not copies that drift."""

    SCRIPT = (Path(__file__).resolve().parent / "run-perf.sh").read_text(encoding="utf-8")

    def shell_value(self, pattern: str) -> int:
        found = re.search(pattern, self.SCRIPT, re.MULTILINE)
        self.assertIsNotNone(found, pattern)
        assert found is not None
        return int(found.group(1))

    def test_p99_series_have_p99_runs_by_default_and_at_least(self) -> None:
        self.assertEqual(self.shell_value(r'^PERF_P99_REPS="\$\{PERF_P99_REPS:-(\d+)\}"'), analyse.P99_RUNS)
        self.assertEqual(self.shell_value(r'"\$PERF_P99_REPS" -lt (\d+)'), analyse.P99_RUNS)

    def test_spread_rule_series_have_min_reps_at_least(self) -> None:
        self.assertEqual(self.shell_value(r'"\$PERF_REPS" -lt (\d+)'), analyse.MIN_REPS)

    def test_the_default_seed_is_analyses(self) -> None:
        self.assertEqual(self.shell_value(r'^PERF_BOOTSTRAP_SEED="\$\{PERF_BOOTSTRAP_SEED:-(\d+)\}"'),
                         analyse.DEFAULT_SEED)

    def test_every_p99_measurement_runs_p99_series(self) -> None:
        p99 = {c["measurement"] for c in analyse.CHECKS if c.get("method") == "bootstrap"}
        calls = dict(re.findall(r'^\s*(?:wanted \S+ && )?measure (\S+) \S+ \S+ "\$(\w+)"', self.SCRIPT, re.MULTILINE))
        self.assertTrue(p99 <= set(calls), (p99, calls))
        for measurement, reps in calls.items():
            with self.subTest(measurement):
                self.assertEqual(reps, "PERF_P99_REPS" if measurement in p99 else "PERF_REPS")


if __name__ == "__main__":
    unittest.main()
