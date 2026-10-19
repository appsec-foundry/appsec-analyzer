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

from appsec_analyzer.platform_settings.service import PlatformSettingsError, check_platform_settings
from appsec_analyzer.platform_settings.source import SourceError, parse_repository
from appsec_analyzer.terminal import field

ARTIFACT = "platform-settings.json"
SCHEMA_VERSION = 1
LOCAL = "local repository; give a GitHub or GitLab URL to check its platform settings"
UNSUPPORTED = "not a github.com or gitlab.com repository URL"
FAILED = "the platform check could not finish"


def _display(source: str) -> str:
    """The selection without any credentials a URL might carry."""
    return field(re.sub(r"(://)[^/@]*@", r"\1", source))


def _looks_like_url(source: str) -> bool:
    return "://" in source or source.startswith("git@")


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
    say: Callable[[str], None],
) -> dict:
    """Check each selected URL once and keep the result for a resumed run."""
    target = directory / ARTIFACT
    if resume and (document := _reusable(target, sources)) is not None:
        say("Platform Security Settings: reusing the result of the interrupted run")
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
            say(f"Platform Security Settings: skipped for {label} ({reason})")
            rows.append({"source": label, "status": "skipped", "reason": reason, "code": code})
            continue
        access = "with your read-only token" if token else "anonymously (public data only)"
        say(f"Platform Security Settings: sending read requests to {repo.host} {access}; no source code is sent")
        try:
            result = check_platform_settings(source, token)
        except PlatformSettingsError:
            say(f"Platform Security Settings: {repo.label} could not be checked; treated as unknown")
            rows.append({"source": label, "status": "failed", "reason": FAILED, "code": "check_failed"})
            continue
        summary = result["summary"]
        say(
            f"Platform Security Settings: {repo.label}: {summary['set']} set, "
            f"{summary['not set']} not set, {summary['not checkable']} not checkable"
        )
        rows.append({"source": label, "status": "checked", "result": result})
    document = {"schema_version": SCHEMA_VERSION, "repositories": rows}
    from shared._atomic_io import atomic_write_json

    directory.mkdir(mode=0o700, exist_ok=True)
    atomic_write_json(target, document)
    return document
