#!/usr/bin/env python3
"""analyzers/security_score.py — deterministic quick Security Score (0-100) for a repository.

A fast indication, not an assessment. The score runs the deterministic scanner
layer only: no agents, no LLM, no run state, nothing written into the target
repository. A full ``/appsec-advisor:appsec-analyzer`` run stays the
authority on severity and risk.

What the number means
---------------------
One score per indicator — Output Handling, Access Control, Hardening and the
rest of ``data/security-score-indicators.yaml`` — each built from that
indicator's own signals:

  * the applicable architecture-coverage rules routed to it, where a rule that
    only raised a hypothesis earns a quarter of the credit a confirmed control
    earns. ``analyzers/architecture_coverage_checks.py`` decides per rule whether it
    applies at all (REQ-006: an absent surface is not applicable), which
    gives each indicator an honest denominator.
  * that indicator's own findings from the config/IaC and source-auth scanners,
    as a saturating deduction weighted by catalog severity. Low never counts —
    every Low check states a build practice rather than a weakness — and
    repeated hits of one config check are damped, because a policy evaluated
    once per workflow file is still one policy.

The headline is the mean of the weaker half of the scored indicators. A
repository is attacked where it is weakest, and averaging everything lets a
well-covered aspect pay for a broken one.

What it deliberately does NOT do
--------------------------------
There is no asset tier, no exposure, and no abuse chain here, so the severities
are catalog defaults and carry none of the caps and elevations the report
applies. Two repositories are therefore not comparable through this number; the
same repository across commits requires matching scoring, catalog and coverage fingerprints.

Below ``MIN_APPLICABLE_RULES`` applicable rules the verdict is ``undetermined``
instead of a value. The rule catalog is language-bound (JS/TS, Python,
Java/Spring, parts of .NET), and a repository it does not cover would otherwise
score high purely for the absence of evidence.

Exit codes:
  0  score computed
  2  undetermined (too few applicable rules)
  1  error or incomplete execution
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))


import argparse
import contextlib
import json
import subprocess as subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema as jsonschema
import yaml

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from shared._path_guard import iter_escaping_symlinks  # noqa: E402

from analyzers.scan_excludes import is_assessment_artifact  # noqa: E402
from appsec_analyzer.score.calculation import (
    _INDICATORS_YAML,
    _RULES_YAML,
    DAMPED_SCANNERS,
    DECISION_CEILING,
    MIN_APPLICABLE_RULES,
    PENALTY_CAP,
    PENALTY_HALF_WEIGHT,
    SEVERITY_WEIGHT,
    STATUS_POINTS,
    TOP_FINDINGS,
    _cwe_list,
    _load_yaml,
    _location,
    _tally,
    compute,
    finding_indicator,
    finding_penalty,
    finding_title,
    indicator_for,
    indicators,
    rule_cwes,
    rule_points,
    rule_signal,
    top_findings,
)

__all__ = [
    "DAMPED_SCANNERS",
    "DECISION_CEILING",
    "MIN_APPLICABLE_RULES",
    "PENALTY_CAP",
    "PENALTY_HALF_WEIGHT",
    "SEVERITY_WEIGHT",
    "STATUS_POINTS",
    "TOP_FINDINGS",
    "_INDICATORS_YAML",
    "_RULES_YAML",
    "_cwe_list",
    "_load_yaml",
    "_location",
    "_tally",
    "compute",
    "finding_indicator",
    "finding_penalty",
    "finding_title",
    "indicator_for",
    "indicators",
    "rule_cwes",
    "rule_points",
    "rule_signal",
    "top_findings",
]

# Per-scanner wall-clock ceiling. A pathological repository must not hang the
# probe; a scanner that times out withholds the headline score.
SCANNER_TIMEOUT_S = 600
CLONE_TIMEOUT_S = 60


from appsec_analyzer.score.collection import SCANNER_SCHEMAS as SCANNER_SCHEMAS
from appsec_analyzer.score.collection import _load as _load
from appsec_analyzer.score.collection import _run as _run
from appsec_analyzer.sources.legacy_git import clone as _clone
from appsec_analyzer.sources.legacy_git import remote_url as _remote_url


def collect(repo_root, work_dir, *, progress=None, completed=None):
    """Compatibility adapter for the retained direct-script command."""
    from appsec_analyzer.score.collection import collect as collect_signals

    return collect_signals(repo_root, work_dir, progress=progress, completed=completed, runner=_run)


def _drop_assessment_artifacts(findings: list[dict], repo_root: Path) -> tuple[list[dict], int]:
    """Drop findings located inside a previous assessment output directory.

    A prior report stored in the repository contains quoted source lines, and
    the config/IaC and source-auth scanners do not filter those directories
    themselves. Without this, an old report inflates the finding count of the
    repository it describes.
    """
    kept = [f for f in findings if not is_assessment_artifact(str(f.get("file") or ""), repo_root)]
    return kept, len(findings) - len(kept)


def _contaminated_rules(rules: list[dict], repo_root: Path) -> list[str]:
    """Rule ids whose every evidence line comes from a prior assessment output."""
    contaminated = []
    for rule in rules:
        evidence = [e for e in rule.get("evidence") or [] if isinstance(e, dict)]
        if not evidence:
            continue
        if all(is_assessment_artifact(str(e.get("file") or ""), repo_root) for e in evidence):
            contaminated.append(str(rule.get("rule_id") or "?"))
    return sorted(contaminated)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


# Plural forms for the rule signals; "hypothesis" is the one that needs it.
_PLURALS = {"hypothesis": "hypotheses", "anti-pattern": "anti-patterns"}


# Rides in the headline itself, where it cannot be cropped away from the number.
CAVEAT = "a limited quick check, not a full security analysis"

# One glyph, on the headline only. It is the summary signal, and there it saves
# the reader a comparison; repeated down every row it would only be decoration
# beside numbers that already sort worst-first. Not ANSI colour: the skill
# reprints this block into Markdown, where escape sequences are either invisible
# or visible noise.
_BANDS = ((25, "🔴"), (50, "🟠"), (75, "🟡"))
_UNSCORED_DOT = "⚪"


def _dot(score: int | None) -> str:
    """Band glyph for a score. An unscored indicator gets the neutral one."""
    if score is None:
        return _UNSCORED_DOT
    for ceiling, glyph in _BANDS:
        if score < ceiling:
            return glyph
    return "🟢"


def _found(row: dict[str, Any]) -> str:
    """The findings half of an indicator line."""
    total = row.get("findings") or 0
    return "no findings" if not total else _count(total, "finding")


def _signals(row: dict[str, Any]) -> str:
    """The checks half of an indicator line."""
    signals = row.get("signals") or {}
    if not signals:
        return "no check applied"
    return ", ".join(
        f"{n} {_PLURALS.get(signal, signal) if n > 1 else signal}"
        for signal, n in sorted(signals.items(), key=lambda kv: (-kv[1], kv[0]))
    )


def render_text(result: dict[str, Any]) -> str:
    """The human-readable report: a headline, the categories, then the caveats.

    The qualifiers ride in the second line rather than in a closing paragraph —
    the number must not travel without them, and prose would be skipped anyway.
    """
    counts = result["findings"]
    scan = f"{result['checks_applicable']} of {result['checks_total']} checks applied · no exposure context"

    headline = f"{result['score']} / 100" if result["verdict"] == "scored" else result["verdict"]
    lines = [f"{_dot(result['score'])} Security Score  {headline} — {CAVEAT}", scan]
    if result.get("reason"):
        lines.append(result["reason"])
    for key, label in (
        ("unscored_findings", "Findings without a scored baseline"),
        ("excluded_findings", "Findings excluded by severity policy"),
    ):
        if result.get(key):
            detail = ", ".join(f"{count} {severity}" for severity, count in sorted(result[key].items()))
            lines.append(f"{label}: {detail}")
    lines.append("")

    width = max((len(row["label"]) for row in result["categories"]), default=0)
    found_width = max((len(_found(row)) for row in result["categories"]), default=0)
    for row in result["categories"]:
        score = (
            "unscored"
            if result["verdict"] != "scored"
            else "no check"
            if row["score"] is None
            else f"{row['score']:>3}/100"
        )
        lines.append(f"  {score:>8}  {row['label']:<{width}}  {_found(row):>{found_width}} · {_signals(row)}")

    lines += [
        "",
        f"  {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium",
    ]

    top = result.get("top_findings") or []
    if top:
        lines += ["", "  most severe findings"]
        width = max(len(row["title"]) for row in top)
        for row in top:
            seen = f"{row['count']}×" if row["count"] > 1 else ""
            lines.append(f"  {row['severity']:<8}  {row['title']:<{width}}  {seen:>4}  {row['location']}")

    for warning in result.get("warnings") or []:
        lines += ["", f"  {warning}"]

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic quick Security Score (0-100) for a repository.")
    parser.add_argument("--repo", default=".", help="Local directory or HTTPS Git URL (default: current working dir)")
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Emit the result as machine-readable JSON")
    formats.add_argument("--yaml", action="store_true", help="Emit the result as machine-readable YAML")
    args = parser.parse_args(argv)

    with contextlib.ExitStack() as cleanup:
        if "://" in args.repo:
            try:
                remote = _remote_url(args.repo)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            clone_parent = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="appsec-score-repo-")))
            repo_root = clone_parent / "checkout"
            try:
                _clone(remote, repo_root)
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            escaping = next(iter_escaping_symlinks(repo_root), None)
            if escaping is not None:
                rel = escaping.path.relative_to(repo_root)
                print(f"error: checkout contains a symlink outside the repository: {str(rel)!r}", file=sys.stderr)
                return 1
            display_repo = remote
        else:
            repo_root = Path(args.repo).expanduser().resolve()
            if not repo_root.is_dir():
                print(f"error: not a directory: {repo_root}", file=sys.stderr)
                return 1
            display_repo = str(repo_root)

        escaping = next(iter_escaping_symlinks(repo_root), None)
        if escaping is not None:
            print(
                f"error: repository contains a symlink outside the repository: {str(escaping.path.relative_to(repo_root))!r}",
                file=sys.stderr,
            )
            return 1

        work_dir = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="appsec-score-")))
        rules, findings, warnings, statuses = collect(repo_root, work_dir)

        findings, dropped = _drop_assessment_artifacts(findings, repo_root)
        if dropped:
            warnings.append(f"ignored {dropped} findings quoting a previous assessment in the repo")
        contaminated = _contaminated_rules(rules, repo_root)
        if contaminated:
            warnings.append("judged on a previous assessment's evidence: " + ", ".join(contaminated))

        result = compute(rules, findings)
        result["scanner_status"] = statuses
        if any(statuses.get(label) != "complete" for label in SCANNER_SCHEMAS):
            result.update(
                verdict="incomplete", score=None, reason="required scanner execution or output validation is incomplete"
            )
        result["top_findings"] = top_findings(findings)
        result["repo"] = display_repo
        result["warnings"] = warnings

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.yaml:
            print(yaml.safe_dump(result, sort_keys=False, allow_unicode=True), end="")
        else:
            print(render_text(result))

        return {"scored": 0, "undetermined": 2, "incomplete": 1}[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
