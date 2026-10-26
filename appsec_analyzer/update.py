"""Update the installed Analyzer on request."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from appsec_analyzer.review import PIPX_PACKAGE, UPDATE_TIMEOUT, _pipx_source


def update_installation() -> int:
    """Run `pipx upgrade` for a pipx installation after an explicit yes; install nothing otherwise."""
    source = _pipx_source()
    if not source:
        raise ValueError(
            "this Analyzer was not installed with pipx; update it the way you installed it (README, Install)"
        )
    if os.environ.get("CI") or not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError(
            f"update asks before it installs and needs an interactive terminal; run `pipx upgrade {PIPX_PACKAGE}` yourself"
        )
    search_path = os.pathsep.join(p for p in os.get_exec_path() if Path(p).is_absolute())
    pipx = shutil.which("pipx", path=search_path)
    if not pipx:
        raise ValueError("pipx was not found on PATH; install pipx or update the way you installed Analyzer")
    print(f"Update the installed Analyzer from {source} with `pipx upgrade {PIPX_PACKAGE}`? [y/N] ", end="", flush=True)
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("y", "yes"):
        print("Nothing was installed.")
        return 0
    try:
        result = subprocess.run([pipx, "upgrade", PIPX_PACKAGE], timeout=UPDATE_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("the update could not be completed") from None
    if result.returncode:
        raise ValueError("the update failed, see its output above")
    return 0
