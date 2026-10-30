"""Describe the installed Analyzer for `--version`: a release version, or the commit and its date."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# The build writes build-info.json into the package. This module must import nothing from
# appsec_analyzer at load time, because setup.py loads it from its file to write that file.
PACKAGE = Path(__file__).resolve().parent
BUILD_INFO = "build-info.json"
GIT_TIMEOUT = 10
VERSION_TIMEOUT = 30
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TAG = re.compile(r"v\d+\.\d+\.\d+[0-9A-Za-z.+-]*")


def _git(root: Path, *args: str) -> str | None:
    search_path = os.pathsep.join(p for p in os.get_exec_path() if Path(p).is_absolute())
    git = shutil.which("git", path=search_path)
    if not git:
        return None
    try:
        result = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            check=False,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def read_git(root: Path) -> dict:
    """Commit, commit date, release tag and local-change flag of the checkout at root; empty if unreadable."""
    commit = _git(root, "rev-parse", "HEAD")
    date = _git(root, "show", "-s", "--format=%cs", "HEAD")
    if not commit or not date:
        return {}
    return {
        "commit": commit,
        "date": date,
        "tag": _git(root, "describe", "--tags", "--exact-match", "--match", "v[0-9]*", "HEAD") or None,
        "dirty": bool(_git(root, "status", "--porcelain", "--untracked-files=no")),
    }


def _clean(info: object) -> dict | None:
    """Keep only well-formed values, because the text is printed to the terminal."""
    if not isinstance(info, dict):
        return None
    commit, date, tag = info.get("commit"), info.get("date"), info.get("tag")
    if not (isinstance(commit, str) and _COMMIT.fullmatch(commit) and isinstance(date, str) and _DATE.fullmatch(date)):
        return None
    if tag is not None and not (isinstance(tag, str) and _TAG.fullmatch(tag)):
        return None
    return {"commit": commit, "date": date, "tag": tag, "dirty": info.get("dirty") is True}


def build_info() -> dict | None:
    """The stamp of an installed package, else the checkout the package runs from."""
    try:
        stamped = json.loads((PACKAGE / BUILD_INFO).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stamped = None
    info = _clean(stamped)
    if info is None and (PACKAGE.parent / ".git").exists():
        info = _clean(read_git(PACKAGE.parent))
    return info


def describe() -> str:
    """The release version for a tagged build, else the short commit and its date."""
    info = build_info()
    if info is None:
        from appsec_analyzer import ENGINE_VERSION

        return f"{ENGINE_VERSION} (commit unknown)"
    suffix = " +local changes" if info["dirty"] else ""
    if info["tag"]:
        return info["tag"].removeprefix("v") + suffix
    return f"{info['commit'][:8]} ({info['date']}){suffix}"


def installed_version() -> str | None:
    """What `--version` of the installed package reports now; ``None`` when it cannot be read.

    After a reinstall this process still runs the replaced code, so the new
    installation is asked in a process of its own, from the same environment.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "appsec_analyzer", "--version"],
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    # `--version` prints the program name, then the version; the text reaches the terminal.
    _, _, version = result.stdout.strip().partition(" ")
    version = " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", version).split())[:120]
    return version or None


def version_change(before: str, after: str | None) -> str | None:
    """The installed version after an update, marked as unchanged or with the one it replaced."""
    if after is None:
        return None
    return after + (" (unchanged)" if after == before else f" (was {before})")
