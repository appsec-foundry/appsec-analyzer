"""Update the installed Analyzer on request."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from appsec_analyzer.review import PIPX_UPGRADE, UPDATE_TIMEOUT, _pipx_source


def update_installation() -> int:
    """Upgrade a pipx installation after a yes or Enter; install nothing otherwise."""
    source = _pipx_source()
    if not source:
        raise ValueError(
            "this Analyzer was not installed with pipx; update it the way you installed it (README, Install)"
        )
    if os.environ.get("CI") or not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError(
            f"update asks before it installs and needs an interactive terminal; run `pipx {' '.join(PIPX_UPGRADE)}` yourself"
        )
    search_path = os.pathsep.join(p for p in os.get_exec_path() if Path(p).is_absolute())
    pipx = shutil.which("pipx", path=search_path)
    if not pipx:
        raise ValueError("pipx was not found on PATH; install pipx or update the way you installed Analyzer")
    print(
        f"Update the installed Analyzer from {source} with `pipx {' '.join(PIPX_UPGRADE)}`? [Y/n] ", end="", flush=True
    )
    try:
        answer = input().strip().lower()
    except EOFError:
        answer = "n"
    if answer not in ("", "y", "yes"):
        print("Nothing was installed.")
        return 0
    try:
        result = subprocess.run([pipx, *PIPX_UPGRADE], timeout=UPDATE_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("the update could not be completed") from None
    if result.returncode:
        raise ValueError("the update failed, see its output above")
    print(
        'Update finished. pipx may say "already at latest version" when only the code changed; Analyzer was reinstalled anyway.'
    )
    return 0
