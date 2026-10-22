"""The Platform Security Settings phase of a scan (REQ-038).

The phase runs only for repositories the user selected as a supported GitHub or GitLab URL.
Nothing is derived from repository content, so a Git remote in a local checkout never starts it.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from pathlib import Path

from appsec_analyzer.platform_settings.checks import CATALOG, MISSING_PERMISSION, NOT_CHECKABLE, NOT_SET, SET
from appsec_analyzer.platform_settings.service import PlatformSettingsError, check_platform_settings
from appsec_analyzer.platform_settings.source import SourceError, parse_repository
from appsec_analyzer.terminal import field

ARTIFACT = "platform-settings.json"
SCHEMA_VERSION = 1
LOCAL = "local repository; give a GitHub or GitLab URL to check its platform settings"
UNSUPPORTED = "not a github.com or gitlab.com repository URL"
FAILED = "the platform check could not finish"
# The start-check line of a skipped repository; the stored reason keeps the full text.
_SKIPPED = {"local_repository": "local checkout; needs a GitHub or GitLab URL", "unsupported_platform": UNSUPPORTED}


def _display(source: str) -> str:
    """The selection without any credentials a URL might carry."""
    return field(re.sub(r"(://)[^/@]*@", r"\1", source))


def _looks_like_url(source: str) -> bool:
    return "://" in source or source.startswith("git@")


def _short(source: str) -> str:
    """A local checkout by its folder name, which the run header already shows in full; a URL as selected."""
    return _display(source) if _looks_like_url(source) else field(Path(source).name or source)


def _checked(path: str, result: dict) -> tuple[str, str]:
    """The start check of a checked repository: its counts, naming the settings that are not set.

    ✓ when every setting is set, ⚠ when one is not set, otherwise ·. Titles come from the catalog.
    """
    summary, titles = result["summary"], dict(CATALOG)
    missing = [titles[row["id"]] for row in result["checks"] if row["state"] == NOT_SET and row["id"] in titles]
    tokenless = sum(row["state"] == NOT_CHECKABLE and row["reason"] == MISSING_PERMISSION for row in result["checks"])
    text = f"{path}: {summary[SET]} set, {summary[NOT_SET]} not set"
    text += f" ({'; '.join(missing)})" if missing else ""
    text += f", {summary[NOT_CHECKABLE]} not checkable"
    if tokenless and result["access"] == "anonymous":
        text += f" ({tokenless} {'needs' if tokenless == 1 else 'need'} a read-only token)"
    return ("⚠" if missing else "·" if summary[NOT_CHECKABLE] else "✓"), text


def _reusable(path: Path, sources: Sequence[str]) -> dict | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    rows = document.get("repositories") if isinstance(document, dict) else None
    if document.get("schema_version") != SCHEMA_VERSION or not isinstance(rows, list):
        return None
    return (
        document
        if [row.get("source") for row in rows if isinstance(row, dict)] == [_display(s) for s in sources]
        else None
    )


def run_phase(
    sources: Sequence[str],
    directory: Path,
    *,
    token_env: str | None,
    resume: bool,
    say: Callable[[str, str], None],
) -> dict:
    """Check each selected URL once and keep the result for a resumed run.

    ``say(symbol, text)`` reports each step as a start check of the run.
    """
    target = directory / ARTIFACT
    if resume and (document := _reusable(target, sources)) is not None:
        say("·", "reusing the result of the interrupted run")
        return document
    token = os.environ.get(token_env, "").strip() if token_env else None
    rows = []
    for source in sources:
        label = _display(source)
        try:
            repo = parse_repository(source)
        except SourceError:
            code, reason = (
                ("unsupported_platform", UNSUPPORTED) if _looks_like_url(source) else ("local_repository", LOCAL)
            )
            say("·", f"{_short(source)} skipped ({_SKIPPED[code]})")
            rows.append({"source": label, "status": "skipped", "reason": reason, "code": code})
            continue
        access = "with your read-only token" if token else "anonymously (public data only)"
        say("·", f"sending read requests to {repo.host} {access}; no source code is sent")
        try:
            result = check_platform_settings(source, token)
        except PlatformSettingsError:
            say("⚠", f"{field(repo.path)} could not be checked; treated as unknown")
            rows.append({"source": label, "status": "failed", "reason": FAILED, "code": "check_failed"})
            continue
        say(*_checked(field(repo.path), result))
        rows.append({"source": label, "status": "checked", "result": result})
    document = {"schema_version": SCHEMA_VERSION, "repositories": rows}
    from shared._atomic_io import atomic_write_json

    directory.mkdir(mode=0o700, exist_ok=True)
    atomic_write_json(target, document)
    return document
