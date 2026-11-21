"""Tests of the L4 release gate, report.py (Story 12.12 D-c).

Standard library only, like the gate itself. Run from this directory:

    python3 -m unittest test_report

or in a container, from tests-e2e-docker/:

    docker run --rm -v "$PWD/test-runner/l4:/t:ro" -w /t python:3 python3 -m unittest -v test_report
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402

STREAMS = "streams"
SINGLE = "streams-single"


def row(
    name: str = "12.2-iv1-bind",
    *,
    profiles: tuple[str, ...] = (STREAMS,),
    level: str = "full",
    lot: str = "B",
    state: str = "live",
    matrix: tuple[str, ...] = (),
) -> report.Row:
    return report.Row(
        name=name,
        source="IV1",
        story=name.split("-", 1)[0],
        profiles=list(profiles),
        level=level,
        lot=lot,
        state=state,
        matrix=list(matrix),
    )


def verdict(name: str, status: str = "PASS", profile: str | None = STREAMS, detail: str = "ok") -> report.Verdict:
    return report.Verdict(profile=profile, name=name, status=status, detail=detail)


def judge(
    r: report.Row,
    verdicts: list[report.Verdict],
    ran: tuple[str, ...] = (STREAMS,),
    strict: bool = False,
    lots: set[str] | None = None,
) -> list[str]:
    return [o.result for o in report.judge_row(r, verdicts, list(ran), strict, lots)]


def build(
    rows: list[report.Row],
    verdicts: list[report.Verdict],
    ran: tuple[str, ...] = (STREAMS,),
    features: tuple[str, ...] = (),
    strict: bool = False,
    lots: set[str] | None = None,
) -> report.Report:
    return report.build_report(rows, verdicts, list(ran), list(features), strict, lots)


class JudgeRow(unittest.TestCase):
    def test_a_live_row_that_passed_is_pass(self) -> None:
        r = row()
        self.assertEqual(judge(r, [verdict(r.name)]), ["PASS"])

    def test_a_live_row_with_no_line_in_a_profile_that_ran_is_missing(self) -> None:
        self.assertEqual(judge(row(), []), ["MISSING"])

    def test_a_pending_row_with_no_line_is_pending(self) -> None:
        self.assertEqual(judge(row(state="pending"), []), ["PENDING"])

    def test_strict_turns_a_silent_pending_row_into_missing(self) -> None:
        self.assertEqual(judge(row(state="pending"), [], strict=True), ["MISSING"])

    def test_a_profile_that_did_not_run_is_not_run(self) -> None:
        self.assertEqual(judge(row(), [], ran=(SINGLE,)), ["NOT-RUN"])

    def test_strict_counts_every_profile_as_run(self) -> None:
        self.assertEqual(judge(row(), [], ran=(), strict=True), ["MISSING"])

    def test_one_outcome_per_profile_of_the_row(self) -> None:
        r = row(profiles=(STREAMS, SINGLE))
        self.assertEqual(judge(r, [verdict(r.name)], ran=(STREAMS,)), ["PASS", "NOT-RUN"])

    def test_a_row_of_a_lot_not_selected_is_not_run(self) -> None:
        outcomes = report.judge_row(row(lot="B"), [], [STREAMS], False, {"C"})
        self.assertEqual([o.result for o in outcomes], ["NOT-RUN"])
        self.assertIn("Lot B not selected", outcomes[0].detail)

    def test_a_row_of_a_selected_lot_with_no_line_is_still_missing(self) -> None:
        self.assertEqual(judge(row(lot="B"), [], lots={"B"}), ["MISSING"])

    def test_a_lot_not_selected_never_hides_a_line_it_printed(self) -> None:
        r = row(lot="B")
        self.assertEqual(judge(r, [verdict(r.name, "FAIL")], lots={"C"}), ["FAIL"])

    def test_a_profile_that_did_not_run_wins_over_the_lot_filter(self) -> None:
        outcomes = report.judge_row(row(lot="B"), [], [SINGLE], False, {"C"})
        self.assertEqual(outcomes[0].detail, "profile did not run")

    def test_two_lines_for_one_profile_are_duplicate(self) -> None:
        r = row()
        self.assertEqual(judge(r, [verdict(r.name), verdict(r.name, "FAIL")]), ["DUPLICATE"])

    def test_a_line_under_another_profile_does_not_count_for_this_one(self) -> None:
        r = row()
        self.assertEqual(judge(r, [verdict(r.name, profile=SINGLE)], ran=(STREAMS, SINGLE)), ["MISSING"])

    def test_partial_from_a_full_row_is_downgraded(self) -> None:
        r = row(level="full")
        self.assertEqual(judge(r, [verdict(r.name, "PARTIAL")]), ["DOWNGRADED"])

    def test_partial_from_a_partial_row_is_partial(self) -> None:
        r = row(level="partial")
        self.assertEqual(judge(r, [verdict(r.name, "PARTIAL")]), ["PARTIAL"])

    def test_a_pending_row_that_reports_is_unmarked(self) -> None:
        r = row(state="pending")
        self.assertEqual(judge(r, [verdict(r.name)]), ["UNMARKED"])

    def test_a_failure_is_fail(self) -> None:
        r = row()
        self.assertEqual(judge(r, [verdict(r.name, "FAIL")]), ["FAIL"])


class BuildReport(unittest.TestCase):
    def test_which_results_fail_the_run(self) -> None:
        # The gate's policy, stated here rather than read from
        # report.FAILING: a test derived from the constant would pass
        # whatever the constant says.
        cases = {
            "PASS": (False, row("12.2-a"), [verdict("12.2-a")]),
            "PENDING": (False, row("12.2-b", state="pending"), []),
            "PARTIAL": (False, row("12.2-c", level="partial"), [verdict("12.2-c", "PARTIAL")]),
            "NOT-RUN": (False, row("12.2-d", profiles=(SINGLE,)), []),
            "MISSING": (True, row("12.2-e"), []),
            "FAIL": (True, row("12.2-f"), [verdict("12.2-f", "FAIL")]),
            "DOWNGRADED": (True, row("12.2-g"), [verdict("12.2-g", "PARTIAL")]),
            "UNMARKED": (True, row("12.2-h", state="pending"), [verdict("12.2-h")]),
            "DUPLICATE": (True, row("12.2-i"), [verdict("12.2-i"), verdict("12.2-i")]),
        }
        rows = [r for _, r, _ in cases.values()]
        verdicts = [v for _, _, vs in cases.values() for v in vs]
        built = build(rows, verdicts)
        self.assertEqual({o.row.name: o.result for o in built.outcomes},
                         {r.name: result for result, (_, r, _) in cases.items()})
        failed = {error.split(" ", 1)[0] for error in built.errors}
        self.assertEqual(failed, {r.name for fails, r, _ in cases.values() if fails})

    def test_a_clean_run_has_no_error(self) -> None:
        r = row(matrix=("TCP stream",))
        self.assertEqual(build([r], [verdict(r.name)], features=("TCP stream",)).errors, [])

    def test_a_not_e2e_row_reports_not_e2e_whatever_ran(self) -> None:
        r = row(profiles=(), level="not-e2e", state="-")
        built = build([r], [], ran=())
        self.assertEqual([o.result for o in built.outcomes], ["NOT-E2E"])
        self.assertEqual(built.errors, [])

    def test_a_line_under_a_profile_the_row_does_not_name_fails(self) -> None:
        r = row(profiles=(STREAMS,))
        built = build([r], [verdict(r.name), verdict(r.name, profile=SINGLE)], ran=(STREAMS, SINGLE))
        self.assertTrue(any("under profile streams-single" in e for e in built.errors), built.errors)

    def test_a_line_before_any_profile_marker_fails(self) -> None:
        r = row()
        built = build([r], [verdict(r.name), verdict(r.name, profile=None)])
        self.assertTrue(any("under profile (none)" in e for e in built.errors), built.errors)

    def test_a_name_the_registry_does_not_know_fails(self) -> None:
        built = build([], [verdict("12.2-unknown")])
        self.assertEqual(built.errors, ["12.2-unknown: reported PASS but is not in the registry"])

    def test_a_p1_row_no_registry_row_proves_fails(self) -> None:
        r = row(matrix=("TCP stream",))
        built = build([r], [verdict(r.name)], features=("TCP stream", "UDP stream"))
        self.assertEqual(built.errors, ["PRD coverage matrix: P1 row 'UDP stream' has no registry row proving it"])

    def test_a_matrix_label_that_is_not_a_p1_feature_fails(self) -> None:
        r = row(matrix=("TCP stream", "Typo stream"))
        built = build([r], [verdict(r.name)], features=("TCP stream",))
        self.assertEqual(len(built.errors), 1)
        self.assertIn("'Typo stream' is not a P1 Feature", built.errors[0])

    def test_a_not_e2e_row_proves_its_matrix_rows(self) -> None:
        r = row(profiles=(), level="not-e2e", state="-", matrix=("Unit-proved",))
        self.assertEqual(build([r], [], features=("Unit-proved",)).errors, [])


class ReadLog(unittest.TestCase):
    def read(self, text: str) -> tuple[list[report.Verdict], list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.log"
            path.write_text(text, encoding="utf-8")
            return report.read_log(path)

    def test_a_verdict_belongs_to_the_last_profile_marker(self) -> None:
        verdicts, ran = self.read(
            "noise\n"
            "L4-SCENARIO 12.2-a PASS before any marker\n"
            "L4-PROFILE streams\n"
            "L4-SCENARIO 12.2-a PASS 3 ms\n"
            "L4-PROFILE streams-single\n"
            "L4-SCENARIO 12.2-a FAIL\n"
            "L4-PROFILE streams\n"
        )
        self.assertEqual(ran, [STREAMS, SINGLE])
        self.assertEqual(
            [(v.profile, v.status, v.detail) for v in verdicts],
            [(None, "PASS", "before any marker"), (STREAMS, "PASS", "3 ms"), (SINGLE, "FAIL", "")],
        )

    def test_colour_codes_and_carriage_returns_are_stripped(self) -> None:
        verdicts, ran = self.read("\x1b[1mL4-PROFILE streams\x1b[0m\r\n\x1b[32mL4-SCENARIO 12.2-a PASS ok\x1b[0m\r\n")
        self.assertEqual(ran, [STREAMS])
        self.assertEqual([(v.name, v.status) for v in verdicts], [("12.2-a", "PASS")])

    def test_a_line_not_at_the_start_or_with_an_unknown_status_is_ignored(self) -> None:
        verdicts, _ = self.read("L4-PROFILE streams\necho L4-SCENARIO 12.2-a PASS\nL4-SCENARIO 12.2-a OK\n")
        self.assertEqual(verdicts, [])


class ReadRegistry(unittest.TestCase):
    HEADER = "\t".join(report.COLUMNS)

    def read(self, *lines: str) -> tuple[list[report.Row], list[str]]:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scenarios.tsv"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            rows = report.read_registry(path, errors)
        return rows, errors

    def test_a_valid_registry_parses_with_no_error(self) -> None:
        rows, errors = self.read(
            "# comment",
            self.HEADER,
            "12.2-iv1-bind\tIV1\t12.2\tstreams,streams-single\tfull\tB\tlive\tTCP stream;UDP stream",
            "12.3-x-unit\tunit test\t12.3\t-\tnot-e2e\tC\t-\t-",
        )
        self.assertEqual(errors, [])
        self.assertEqual(rows[0].profiles, [STREAMS, SINGLE])
        self.assertEqual(rows[0].matrix, ["TCP stream", "UDP stream"])
        self.assertEqual((rows[1].profiles, rows[1].matrix), ([], []))

    def test_crlf_is_tolerated(self) -> None:
        _, errors = self.read(self.HEADER + "\r", "12.2-a\tIV1\t12.2\tstreams\tfull\tB\tlive\t-\r")
        self.assertEqual(errors, [])

    def test_shape_errors_are_reported(self) -> None:
        cases = {
            "header is": ("name\tsource",),
            "columns, expected": (self.HEADER, "12.2-a\tIV1\t12.2"),
            "is not <story>-<lowercase slug>": (self.HEADER, "12.2-Bad\tIV1\t12.2\tstreams\tfull\tB\tlive\t-"),
            "does not start with its story": (self.HEADER, "12.3-a\tIV1\t12.2\tstreams\tfull\tB\tlive\t-"),
            "level 'strong'": (self.HEADER, "12.2-a\tIV1\t12.2\tstreams\tstrong\tB\tlive\t-"),
            "a not-e2e row has no profile": (self.HEADER, "12.2-a\tIV1\t12.2\tstreams\tnot-e2e\tB\t-\t-"),
            "names no profile": (self.HEADER, "12.2-a\tIV1\t12.2\t-\tfull\tB\tlive\t-"),
            "state 'done'": (self.HEADER, "12.2-a\tIV1\t12.2\tstreams\tfull\tB\tdone\t-"),
            "appears more than once": (
                self.HEADER,
                "12.2-a\tIV1\t12.2\tstreams\tfull\tB\tlive\t-",
                "12.2-a\tIV2\t12.2\tstreams\tfull\tB\tlive\t-",
            ),
        }
        for expected, lines in cases.items():
            with self.subTest(expected):
                _, errors = self.read(*lines)
                self.assertTrue(any(expected in e for e in errors), errors)


class P1Features(unittest.TestCase):
    PRD = """# Epic 12

### Coverage matrix

| Feature | nginx | HAProxy | Lorica |
|---|---|---|---|
| TCP stream | yes | yes | P1 |
| UDP stream | yes | no | P1 (12.5) |
| Live transfer | no | no | P2 |
| P1 lookalike | no | no | AP10 |

### Another table

| Feature | Lorica |
|---|---|
| Not in the matrix | P1 |
"""

    def test_only_the_p1_rows_of_the_coverage_matrix_are_features(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prd.md"
            path.write_text(self.PRD, encoding="utf-8")
            self.assertEqual(report.p1_features(path), ["TCP stream", "UDP stream"])


class Main(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "scenarios.tsv").write_text(
            "\t".join(report.COLUMNS) + "\n" + "12.2-a\tIV1\t12.2\tstreams\tfull\tB\tlive\tTCP stream\n",
            encoding="utf-8",
        )
        (self.dir / "prd.md").write_text(P1Features.PRD.split("### Another")[0], encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_main(self, log: str, *extra: str) -> int:
        (self.dir / "run.log").write_text(log, encoding="utf-8")
        argv = ["report.py", "--log", str(self.dir / "run.log"), "--registry", str(self.dir / "scenarios.tsv"),
                "--prd", str(self.dir / "prd.md"), "--markdown", str(self.dir / "summary.md"), *extra]
        saved = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return report.main()
        finally:
            sys.argv = saved

    def test_a_run_that_misses_a_p1_row_exits_1(self) -> None:
        self.assertEqual(self.run_main("L4-PROFILE streams\nL4-SCENARIO 12.2-a PASS ok\n"), 1)
        self.assertIn("'UDP stream' has no registry row", (self.dir / "summary.md").read_text(encoding="utf-8"))

    def test_a_clean_run_exits_0(self) -> None:
        registry = self.dir / "scenarios.tsv"
        registry.write_text(registry.read_text(encoding="utf-8").replace("TCP stream", "TCP stream;UDP stream"),
                            encoding="utf-8")
        self.assertEqual(self.run_main("L4-PROFILE streams\nL4-SCENARIO 12.2-a PASS ok\n"), 0)
        self.assertIn("**L4 report PASSED.**", (self.dir / "summary.md").read_text(encoding="utf-8"))

    def test_lots_with_strict_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as refused:
            self.run_main("", "--strict", "--lots", "B")
        self.assertEqual(refused.exception.code, 2)

    def test_a_prd_with_no_p1_row_fails(self) -> None:
        (self.dir / "prd.md").write_text("# no matrix\n", encoding="utf-8")
        self.assertEqual(self.run_main("L4-PROFILE streams\nL4-SCENARIO 12.2-a PASS ok\n"), 1)


if __name__ == "__main__":
    unittest.main()
