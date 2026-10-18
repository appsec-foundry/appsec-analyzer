"""Terminal rendering of validated score results."""

from __future__ import annotations

import textwrap

from appsec_analyzer.engine import initialize

initialize()
from renderers.term_style import Style

from appsec_analyzer.score.collection import SCANNER_SCHEMAS
from appsec_analyzer.score.progress import _styled_repository_label


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
        f" · {complete}/{len(SCANNER_SCHEMAS)} scanners complete",
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
