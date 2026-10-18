"""Repository scoring through the Analyzer's admitted, redacted source boundary.

Only the operator's selection authorizes a checkout. Trusted bundled scanners
read a private snapshot; repository configuration and executables stay inert.
"""

from __future__ import annotations

import tempfile
import textwrap
import unicodedata
from collections.abc import Callable
from pathlib import Path

import yaml
from analyzers import security_score
from jsonschema import Draft202012Validator
from renderers.term_style import Style
from runtime.multi_repo_scope import ScopeError, _git, admit
from runtime.remote_repositories import RemoteError, checkout_arguments, parse_remote
from validators.secret_scan import mask_text

from appsec_analyzer import INTERFACE_VERSION, resource_root
from appsec_analyzer.score_progress import _styled_repository_label

SOURCE_POLICY = "analyzer-admitted-redacted-v1"
SCANNER_PROGRESS = {
    "route-inventory": "Discovering application routes...",
    "architecture-coverage": "Checking architecture coverage...",
    "config-iac": "Scanning configuration and infrastructure...",
    "source-auth": "Scanning source code...",
}
SCANNER_NAMES = {
    "route-inventory": "Application routes",
    "architecture-coverage": "Architecture coverage",
    "config-iac": "Configuration and infrastructure",
    "source-auth": "Source code",
}


def _scanner_warning(label: str, status: str, diagnostics: list[str]) -> str:
    if f"{label}: timed out, excluded" in diagnostics:
        detail = "exceeded its time limit"
    else:
        detail = {
            "failed": "could not complete",
            "missing": "produced no result",
            "invalid": "produced an invalid result",
        }.get(status, "did not complete")
    return f"{SCANNER_NAMES[label]}: {detail}. Retry the scan; if it persists, check the Analyzer installation."


class ScoreError(ValueError):
    """A bounded diagnostic safe to display without scanner stderr or sources."""


def _safe_fields(value):
    if isinstance(value, str):
        return "".join(
            " " if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char for char in mask_text(value)[0]
        )
    if isinstance(value, list):
        return [_safe_fields(item) for item in value]
    if isinstance(value, dict):
        return {key: _safe_fields(item) for key, item in value.items()}
    return value


def _check_evidence(rules: list[dict], findings: list[dict], files) -> None:
    for rule in rules:
        if any(evidence["file"] not in files for evidence in rule.get("evidence", [])):
            raise ScoreError("A coverage check cites source outside the admitted snapshot")
    for finding in findings:
        paths = finding.get("searched_files", []) if finding.get("evidence_kind") == "absence" else [finding["file"]]
        if not isinstance(paths, list) or any(path not in files for path in paths):
            raise ScoreError("A scanner finding cites source outside the admitted snapshot")


def score_repository(selection: str, *, progress: Callable[[str], None] | None = None) -> dict:
    """Score one operator-selected source; publish nothing until revalidation."""

    def report(message: str) -> None:
        if progress is not None:
            progress(message)

    try:
        if (
            not isinstance(selection, str)
            or not selection.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in selection)
        ):
            raise ScoreError("Invalid repository selection")
        remote = parse_remote(selection)
        if remote is None:
            report("Reading repository sources...")
            try:
                root = Path(selection).expanduser().resolve(strict=True)
            except FileNotFoundError:
                raise ScoreError(
                    "Selected repository does not exist. Check the local path or supply an HTTPS/SSH Git URL."
                ) from None
            if not root.is_dir():
                raise ScoreError("Selected repository is not a directory. Select the top-level Git checkout.")
            try:
                top = _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
            except ScopeError:
                raise ScoreError(
                    "Cannot read the Git checkout. Select a Git repository and check Git installation and read permissions."
                ) from None
            if root != Path(top).resolve():
                raise ScoreError("Select the top-level Git checkout rather than a subdirectory.")
            try:
                _git(root, "rev-parse", "--verify", "HEAD")
            except ScopeError:
                raise ScoreError(
                    "Repository has no readable commit. Select a checkout with an existing commit."
                ) from None
            temporary = Path(tempfile.gettempdir()).resolve()
            if temporary == root or root in temporary.parents:
                raise ScoreError("Temporary storage must be outside the selected repository")
            selection = str(root)
        display = remote.url if remote else selection
        with tempfile.TemporaryDirectory(prefix="appsec-score-output-") as directory:
            work = Path(directory)
            if remote:
                report("Cloning Git repository...")
            with checkout_arguments(["--repo", selection, "--output", directory, "--quiet"]) as local:
                report("Reading repository sources...")
                root = Path(local[1])
                scope = admit([str(root)], directory, minimum=1)
                if scope.output_in_checkout():
                    raise ScoreError("Temporary storage must be outside the selected repository")
                view = scope.repositories[0]
                for excluded in view.exclusions:
                    if excluded["reason"] == "symlink":
                        target = (view.root / excluded["path"]).resolve()
                        if not target.is_relative_to(view.root):
                            raise ScoreError("Repository contains a symlink outside the selected source boundary")
                report("Preparing source scan...")
                with scope.scanner_snapshot(view.repository_id) as snapshot:
                    rules, findings, diagnostics, statuses = security_score.collect(
                        snapshot,
                        work,
                        progress=lambda label: report(SCANNER_PROGRESS[label]),
                        completed=lambda label, status: report(f"Scanner result: {label}: {status}"),
                    )
                _check_evidence(rules, findings, view.files)
                report("Calculating security score...")
                result = security_score.compute(rules, findings)
                result["scanner_status"] = statuses
                result["warnings"] = [
                    _scanner_warning(label, statuses.get(label, "missing"), diagnostics)
                    for label in security_score.SCANNER_SCHEMAS
                    if statuses.get(label) != "complete"
                ]
                if result["warnings"]:
                    result.update(
                        verdict="incomplete",
                        score=None,
                        reason="Required scanners did not complete successfully. No security score is available; see warnings.",
                    )
                elif diagnostics:
                    result["warnings"].append("Scanners reported diagnostics; detailed source output is withheld")
                result["top_findings"] = security_score.top_findings(findings, full_titles=True)
                result["repo"] = display
                result["interface_version"] = INTERFACE_VERSION
                result["assessment_status"] = "not_run"
                result["evidence_status"] = "unverified"
                result["comparability"]["source_policy"] = SOURCE_POLICY
                result["source"] = {
                    "head": view.head,
                    "state_sha256": view.state_sha256,
                    "dirty": view.dirty,
                    "captured_files": len(view.files),
                }
                report("Checking source consistency...")
                scope.verify_unchanged()
                result = _safe_fields(result)
                schema = yaml.safe_load((resource_root() / "schemas/security-score.schema.yaml").read_text())
                if list(Draft202012Validator(schema).iter_errors(result)):
                    raise ScoreError("Security score result failed its public schema")
                return result
    except (RemoteError, ScopeError) as exc:
        message = str(exc)
        if message == "Selected source state changed; a fresh assessment is required":
            message = "Selected source state changed during analysis. Retry when repository changes have finished."
        raise ScoreError(_safe_fields(message)) from None
    except ScoreError:
        raise
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, yaml.YAMLError):
        raise ScoreError(
            "Security score could not be computed; check the Git checkout and Analyzer resources"
        ) from None


def _score_role(score: int | None) -> str:
    if score is None:
        return "warn"
    # Match the retained score renderer's visual bands; these are not CI gates.
    for ceiling, role in ((25, "critical"), (50, "high"), (75, "medium")):
        if score < ceiling:
            return role
    return "ok"


def render_text(result: dict, *, style: Style | None = None, width: int = 88) -> str:
    """Show score, coverage, ranked areas, then actionable finding references."""
    st = style if style is not None else Style(False)
    width = max(40, min(width, 120))
    source = result["source"]
    headline = f"{result['score']} / 100" if result["verdict"] == "scored" else result["verdict"]
    findings = result["findings"]
    complete = sum(status == "complete" for status in result["scanner_status"].values())
    rule = st("─" * min(width, 64), "muted")
    totals = " · ".join(st(f"{findings[severity]} {severity}", severity) for severity in ("critical", "high", "medium"))
    lines = [
        st("Security Score", "accent", "bold"),
        rule,
        f"  {st(headline, _score_role(result['score']), 'bold')}  (limited quick check)",
        "  Not a full security analysis; no exposure context.",
        rule,
        "",
        f"Repository: {_styled_repository_label(result['repo'], st)}",
        f"Coverage:   {result['checks_applicable']}/{result['checks_total']} applicable checks"
        f" · {complete}/{len(security_score.SCANNER_SCHEMAS)} scanners complete",
        f"Findings:   {result['findings_total']} (unverified) · {totals}",
    ]
    if result.get("reason"):
        lines += ["", st(f"Result: {result['reason']}", "warn")]
    for field, label in (
        ("unscored_findings", "Findings without a scored baseline"),
        ("excluded_findings", "Findings excluded by severity policy"),
    ):
        if result.get(field):
            detail = ", ".join(f"{count} {severity}" for severity, count in sorted(result[field].items()))
            lines.append(st(f"{label}: {detail}", "warn"))

    if result["verdict"] == "scored":
        categories = sorted(
            result["categories"],
            key=lambda row: (row["score"] is None, row["score"] if row["score"] is not None else 0, row["label"]),
        )
        area_heading = "Areas · weakest first"
    else:
        categories = sorted(result["categories"], key=lambda row: row["label"])
        area_heading = "Areas · unscored"
    lines += ["", st(area_heading, "accent", "bold"), ""]
    if categories:
        area_width = max(len("Area"), *(len(row["label"]) for row in categories))
        lines += [
            st(f"  {'Area':<{area_width}}  {'Score':>10}  {'Checks':>6}  {'Findings':>8}", "bold"),
            st(f"  {'-' * area_width}  {'-' * 10}  {'-' * 6}  {'-' * 8}", "muted"),
        ]
        for row in categories:
            score = f"{row['score']}/100" if result["verdict"] == "scored" and row["score"] is not None else "unscored"
            score = st(f"{score:>10}", _score_role(row["score"]) if result["verdict"] == "scored" else "warn")
            lines.append(f"  {row['label']:<{area_width}}  {score}  {row['checks']:>6}  {row['findings']:>8}")
    else:
        lines.append("  No applicable scoring areas.")

    lines += ["", st("Top findings · unverified", "accent", "bold"), ""]
    for index, finding in enumerate(result["top_findings"], start=1):
        count = finding["count"]
        severity = finding["severity"]
        role = severity if severity in {"critical", "high", "medium", "low"} else "warn"
        prefix = f"  {index:>2}. {severity.upper():<8} "
        title = textwrap.wrap(finding["title"], width=max(12, width - len(prefix)), break_on_hyphens=False) or [""]
        lines.append(st(f"  {index:>2}.", "muted") + " " + st(f"{severity.upper():<8}", role, "bold") + " " + title[0])
        lines.extend(" " * len(prefix) + part for part in title[1:])
        repeated = f"  · {count} occurrences" if count > 1 else ""
        location = textwrap.wrap(
            finding["location"] + repeated,
            width=width,
            initial_indent="      ",
            subsequent_indent="      ",
            break_on_hyphens=False,
        )
        lines.extend(st(part, "muted") for part in location)
        lines.append("")
    if lines[-1] == "":
        lines.pop()
    if not result["top_findings"]:
        lines.append(
            "  No scored-severity findings reported by the completed scanners; this does not establish safety."
        )
    if result["warnings"]:
        lines += ["", st("Warnings", "warn", "bold")]
        lines.extend(f"  - {warning}" for warning in result["warnings"])
    lines += [
        "",
        f"Source: {source['head'][:12]} ({'dirty' if source['dirty'] else 'clean'})"
        f" · {source['captured_files']} captured files",
        "Compare only commits of this repository with matching scoring and coverage settings.",
    ]
    return "\n".join(lines)
