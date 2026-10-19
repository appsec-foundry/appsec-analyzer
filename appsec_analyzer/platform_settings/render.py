"""Terminal text for a platform security settings result."""

from __future__ import annotations

from appsec_analyzer.platform_settings.checks import NOT_CHECKABLE, NOT_SET, SET
from appsec_analyzer.terminal import field


def render_text(result: dict) -> str:
    summary = result["summary"]
    lines = [
        "Platform security settings",
        f"Repository: {field(result['host'])}/{field(result['repository'])} ({result['visibility']})",
        f"Access:     {result['access']}" + (" (public data only)" if result["access"] == "anonymous" else ""),
        f"Checked:    {result['checked_at']}",
        f"Result:     {summary[SET]} set · {summary[NOT_SET]} not set · {summary[NOT_CHECKABLE]} not checkable",
        "",
    ]
    for row in result["checks"]:
        reason = f" ({row['reason']})" if row["reason"] else ""
        lines.append(f"  {row['id']}  {row['state']:<13} {row['title']}{reason}")
    lines += ["", result["limits"]]
    return "\n".join(lines)
