"""The L4 report (Story 12.12 D-c): checks a run's log against the
scenario registry and prints the scenario table and the parity matrix.

The log is the tee of a whole run.sh run. Two kinds of lines matter,
each at the start of a line:

    L4-PROFILE <profile>                       a profile (phase) starts
    L4-SCENARIO <name> <PASS|FAIL|PARTIAL> ... one scenario's verdict

A verdict belongs to the profile of the last marker before it. For every
registry row and every profile of that row that ran (every profile, with
--strict), exactly one verdict is expected. The run fails on a missing
verdict (unless the row is still pending and the run is not strict), a
duplicate, a FAIL, a PARTIAL from a `full` row, a verdict from a pending
row, a verdict under a profile the row does not name, a name the registry
does not know, and a P1 row of the PRD coverage matrix that no registry
row proves.

Standard library only; runs in the runner image.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

COLUMNS = ["name", "source", "story", "profiles", "level", "lot", "state", "matrix"]
# D-c names a kind after the story (iv<n>, ac<n>, x, matrix), but keeps
# names already chosen (D-f's 12.12-fd-reserve-http-unaffected), so only
# the story prefix and the character set are enforced.
NAME_PATTERN = re.compile(r"^\d+\.\d+-[a-z0-9][a-z0-9.-]*$")
LEVELS = {"full", "partial", "not-e2e"}
STATES = {"live", "pending"}
VERDICT_LINE = re.compile(r"^L4-SCENARIO (\S+) (PASS|FAIL|PARTIAL)(?: (.*))?$")
PROFILE_LINE = re.compile(r"^L4-PROFILE (\S+)\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Results that fail the run; PASS, PARTIAL (on a partial row), PENDING,
# NOT-RUN and NOT-E2E do not.
FAILING = {"FAIL", "MISSING", "DUPLICATE", "DOWNGRADED", "UNMARKED"}


@dataclass
class Row:
    name: str
    source: str
    story: str
    profiles: list[str]
    level: str
    lot: str
    state: str
    matrix: list[str]


@dataclass
class Verdict:
    profile: str | None
    name: str
    status: str
    detail: str


@dataclass
class Outcome:
    row: Row
    profile: str
    result: str
    detail: str


@dataclass
class Report:
    outcomes: list[Outcome] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def read_registry(path: Path, errors: list[str]) -> list[Row]:
    rows: list[Row] = []
    header_seen = False
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if not header_seen:
            header_seen = True
            if cells != COLUMNS:
                errors.append(f"registry line {number}: header is {cells}, expected {COLUMNS}")
            continue
        if len(cells) != len(COLUMNS):
            errors.append(f"registry line {number}: {len(cells)} columns, expected {len(COLUMNS)}")
            continue
        values = dict(zip(COLUMNS, cells))
        row = Row(
            name=values["name"],
            source=values["source"],
            story=values["story"],
            profiles=[] if values["profiles"] == "-" else values["profiles"].split(","),
            level=values["level"],
            lot=values["lot"],
            state=values["state"],
            matrix=[] if values["matrix"] == "-" else values["matrix"].split(";"),
        )
        rows.append(row)
        if not NAME_PATTERN.match(row.name):
            errors.append(f"registry line {number}: {row.name!r} is not <story>-<lowercase slug>")
        if not row.name.startswith(f"{row.story}-"):
            errors.append(f"registry line {number}: {row.name} does not start with its story {row.story}")
        if row.level not in LEVELS:
            errors.append(f"registry line {number}: level {row.level!r} is not one of {sorted(LEVELS)}")
        if row.level == "not-e2e":
            if row.profiles or row.state != "-":
                errors.append(f"registry line {number}: a not-e2e row has no profile and no state")
        else:
            if not row.profiles:
                errors.append(f"registry line {number}: {row.name} names no profile")
            if row.state not in STATES:
                errors.append(f"registry line {number}: state {row.state!r} is not one of {sorted(STATES)}")
    names = [row.name for row in rows]
    for name in sorted({n for n in names if names.count(n) > 1}):
        errors.append(f"registry: {name} appears more than once")
    return rows


def read_log(path: Path) -> tuple[list[Verdict], list[str]]:
    verdicts: list[Verdict] = []
    profiles_ran: list[str] = []
    current: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = ANSI.sub("", raw).rstrip("\r").strip()
        marker = PROFILE_LINE.match(line)
        if marker:
            current = marker.group(1)
            if current not in profiles_ran:
                profiles_ran.append(current)
            continue
        verdict = VERDICT_LINE.match(line)
        if verdict:
            verdicts.append(Verdict(current, verdict.group(1), verdict.group(2), verdict.group(3) or ""))
    return verdicts, profiles_ran


def p1_features(prd: Path) -> list[str]:
    """The Feature cells of the PRD coverage matrix whose Lorica column
    commits to Phase 1."""
    features: list[str] = []
    in_matrix = False
    for line in prd.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            in_matrix = line.startswith("### Coverage matrix")
            continue
        if not in_matrix or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells[0] in ("Feature", "") or set(cells[0]) <= {"-"}:
            continue
        if re.search(r"\bP1\b", cells[-1]):
            features.append(cells[0])
    return features


def judge_row(
    row: Row, verdicts: list[Verdict], profiles_ran: list[str], strict: bool, lots: set[str] | None
) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for profile in row.profiles:
        mine = [v for v in verdicts if v.name == row.name and v.profile == profile]
        ran = strict or profile in profiles_ran
        if not ran:
            outcomes.append(Outcome(row, profile, "NOT-RUN", "profile did not run"))
        elif lots is not None and row.lot not in lots and not mine:
            outcomes.append(Outcome(row, profile, "NOT-RUN", f"Lot {row.lot} not selected (L4_LOTS)"))
        elif not mine:
            if row.state == "pending" and not strict:
                outcomes.append(Outcome(row, profile, "PENDING", f"Lot {row.lot} has not landed"))
            else:
                outcomes.append(Outcome(row, profile, "MISSING", "no L4-SCENARIO line"))
        elif len(mine) > 1:
            statuses = ", ".join(v.status for v in mine)
            outcomes.append(Outcome(row, profile, "DUPLICATE", f"{len(mine)} lines ({statuses})"))
        else:
            verdict = mine[0]
            if row.state == "pending":
                outcomes.append(Outcome(row, profile, "UNMARKED", f"reported {verdict.status} while its row is pending: mark it live"))
            elif verdict.status == "PARTIAL" and row.level == "full":
                outcomes.append(Outcome(row, profile, "DOWNGRADED", f"PARTIAL from a full row: {verdict.detail}"))
            else:
                outcomes.append(Outcome(row, profile, verdict.status, verdict.detail))
    return outcomes


def build_report(
    rows: list[Row],
    verdicts: list[Verdict],
    profiles_ran: list[str],
    features: list[str],
    strict: bool,
    lots: set[str] | None = None,
) -> Report:
    report = Report()
    by_name: dict[str, Row] = {row.name: row for row in rows}
    for verdict in verdicts:
        row = by_name.get(verdict.name)
        if row is None:
            report.errors.append(f"{verdict.name}: reported {verdict.status} but is not in the registry")
        elif verdict.profile not in row.profiles:
            report.errors.append(
                f"{verdict.name}: reported {verdict.status} under profile {verdict.profile or '(none)'}, "
                f"the registry names {','.join(row.profiles) or 'none'}"
            )
    for row in rows:
        if row.level == "not-e2e":
            report.outcomes.append(Outcome(row, "-", "NOT-E2E", row.source))
        else:
            report.outcomes.extend(judge_row(row, verdicts, profiles_ran, strict, lots))
    for outcome in report.outcomes:
        if outcome.result in FAILING:
            report.errors.append(f"{outcome.row.name} [{outcome.profile}]: {outcome.result} {outcome.detail}")
    known = set(features)
    for row in rows:
        for label in row.matrix:
            if label not in known:
                report.errors.append(f"{row.name}: matrix row {label!r} is not a P1 Feature of the PRD coverage matrix")
    proved = {label for row in rows for label in row.matrix}
    for feature in features:
        if feature not in proved:
            report.errors.append(f"PRD coverage matrix: P1 row {feature!r} has no registry row proving it")
    return report


def row_result(outcomes: list[Outcome]) -> str:
    """One result for a row across its profiles: the first failing one,
    else the first that is not a pass, else PASS."""
    results = [o.result for o in outcomes]
    for result in results:
        if result in FAILING:
            return result
    for result in results:
        if result != "PASS":
            return result
    return "PASS"


def render(report: Report, features: list[str], profiles_ran: list[str], strict: bool) -> tuple[str, str]:
    by_row: dict[str, list[Outcome]] = {}
    for outcome in report.outcomes:
        by_row.setdefault(outcome.row.name, []).append(outcome)

    counts: dict[str, int] = {}
    for outcome in report.outcomes:
        counts[outcome.result] = counts.get(outcome.result, 0) + 1
    summary = ", ".join(f"{result} {count}" for result, count in sorted(counts.items()))
    mode = "strict (every row must report)" if strict else "per profile that ran"
    verdict = "FAILED" if report.errors else "PASSED"

    text: list[str] = ["", "=== L4 scenario report ===", f"Profiles that ran: {', '.join(profiles_ran) or 'none'}; mode: {mode}"]
    md: list[str] = ["## L4 scenarios", "", f"Profiles that ran: {', '.join(profiles_ran) or 'none'}; mode: {mode}.", ""]
    md += ["| Scenario | Profile | Result | Detail |", "|---|---|---|---|"]
    width = max(len(o.row.name) for o in report.outcomes) if report.outcomes else 10
    for outcome in report.outcomes:
        text.append(f"  {outcome.result:<10} {outcome.row.name:<{width}}  {outcome.profile:<15} {outcome.detail}")
        md.append(f"| `{outcome.row.name}` | {outcome.profile} | {outcome.result} | {outcome.detail.replace('|', '/')} |")

    text += ["", "=== Parity matrix (PRD coverage matrix, P1 rows) ==="]
    md += ["", "## Parity matrix", "", "| P1 row | Proved by |", "|---|---|"]
    for feature in features:
        provers = [o for o in report.outcomes if feature in o.row.matrix]
        names = sorted({o.row.name for o in provers})
        cells = [f"{name} ({row_result(by_row[name])})" for name in names]
        text.append(f"  {feature}: {'; '.join(cells) or 'NONE'}")
        md.append(f"| {feature} | {'<br>'.join(cells) or 'NONE'} |")

    text += ["", f"Results: {summary}"]
    md += ["", f"Results: {summary}."]
    if report.errors:
        text += ["", "Failures:"] + [f"  - {error}" for error in report.errors]
        md += ["", "### Failures", ""] + [f"- {error}" for error in report.errors]
    text.append(f"=== L4 REPORT {verdict} ===")
    md += ["", f"**L4 report {verdict}.**"]
    return "\n".join(text), "\n".join(md) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=Path("/l4/scenarios.tsv"))
    parser.add_argument("--prd", type=Path, default=Path("/l4/prd.md"))
    parser.add_argument("--markdown", type=Path, help="write the tables as Markdown here")
    parser.add_argument("--strict", action="store_true", help="every row must report, whatever ran (the release run)")
    parser.add_argument(
        "--lots",
        help="comma-separated Lots the run selected (L4_LOTS): a row of another Lot that did not "
        "report is NOT-RUN rather than MISSING; refused with --strict",
    )
    args = parser.parse_args()
    if args.lots and args.strict:
        parser.error("--lots selects part of the registry; the strict run checks all of it")
    lots = {lot.strip() for lot in args.lots.split(",")} if args.lots else None

    registry_errors: list[str] = []
    rows = read_registry(args.registry, registry_errors)
    verdicts, profiles_ran = read_log(args.log)
    features = p1_features(args.prd)
    if not features:
        registry_errors.append(f"no P1 row found in the coverage matrix of {args.prd}")
    report = build_report(rows, verdicts, profiles_ran, features, args.strict, lots)
    report.errors = registry_errors + report.errors

    text, markdown = render(report, features, profiles_ran, args.strict)
    print(text)
    if args.markdown:
        args.markdown.write_text(markdown, encoding="utf-8")
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
