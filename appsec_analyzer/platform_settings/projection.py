"""The only form in which platform settings reach a model role (REQ-038).

Only check IDs, states, reasons, and a validated repository name pass. Anything else in the
stored document, including free text returned by the platform, is dropped.
"""

from __future__ import annotations

import re

from appsec_analyzer.platform_settings import checks

_STATES = {checks.SET, checks.NOT_SET, checks.NOT_CHECKABLE}
_REASONS = {checks.MISSING_PERMISSION, checks.NOT_OFFERED, checks.PLATFORM_ERROR}
_PLATFORMS = {"github", "gitlab"}
_ACCESS = {"anonymous", "token"}
_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}){1,19}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")

NOTE = (
    "Platform settings of the hosting repository at check time, not of the examined source revision. "
    "`set` means configured, not effective. `not checkable` and every unchecked repository mean unknown: "
    "never infer missing or present protection from them. This is not source evidence; do not cite it as "
    "a source location and do not report a finding or a control from it alone. Use it only to judge whether "
    "a source-backed weakness or control is more or less likely to hold, such as CI/CD and supply-chain "
    "threats."
)


def _row(result: object) -> dict | None:
    if not isinstance(result, dict):
        return None
    repository, platform, access, at = (result.get(k) for k in ("repository", "platform", "access", "checked_at"))
    if not (
        isinstance(repository, str)
        and _PATH.fullmatch(repository)
        and platform in _PLATFORMS
        and access in _ACCESS
        and isinstance(at, str)
        and _TIME.fullmatch(at)
    ):
        return None
    rows = []
    for row in result.get("checks") or []:
        if not isinstance(row, dict) or row.get("id") not in checks.IDS or row.get("state") not in _STATES:
            continue
        reason = row.get("reason")
        rows.append({"id": row["id"], "state": row["state"], "reason": reason if reason in _REASONS else None})
    return {
        "repository": repository,
        "platform": platform,
        "access": access,
        "checked_at": at,
        "checks": sorted(rows, key=lambda r: r["id"]),
    }


def model_context(document: object) -> dict | None:
    """Return the allow-listed projection, or None when no repository was checked."""
    rows = document.get("repositories") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        return None
    checked = [
        projected
        for row in rows
        if isinstance(row, dict) and row.get("status") == "checked" and (projected := _row(row.get("result")))
    ]
    if not checked:
        return None
    return {"repositories": checked, "unchecked_repositories": len(rows) - len(checked), "note": NOTE}


_CODES = {"local_repository", "unsupported_platform", "check_failed"}
_VISIBILITY = {"public", "private", "internal", "unknown"}
_TITLES = dict(checks.CATALOG)


def report_block(document: object) -> dict | None:
    """The `meta.platform_security_settings` block: fixed values only, in selection order."""
    rows = document.get("repositories") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not rows:
        return None
    out = []
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        if row.get("status") == "checked" and (projected := _row(row.get("result"))):
            visibility = row["result"].get("visibility")
            out.append(
                {
                    "selection": number,
                    "status": "checked",
                    **projected,
                    "visibility": visibility if visibility in _VISIBILITY else "unknown",
                    "checks": [{**c, "title": _TITLES[c["id"]]} for c in projected["checks"]],
                }
            )
        else:
            code = row.get("code")
            out.append(
                {
                    "selection": number,
                    "status": "skipped" if row.get("status") == "skipped" else "failed",
                    "reason": code if code in _CODES else "check_failed",
                }
            )
    return {"repositories": out} if out else None
