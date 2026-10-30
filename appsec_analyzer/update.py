"""Update the installed Analyzer on request."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from appsec_analyzer.review import PIPX_UPGRADE, UPDATE_TIMEOUT, _pipx_source
from appsec_analyzer.terminal import field

VERSION_TIMEOUT = 30


def _installed_version() -> str | None:
    """What `--version` of the freshly installed package reports; ``None`` when it cannot be read.

    This process still runs the replaced code, so the new installation is asked
    in a process of its own, from the same pipx environment.
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
    # `--version` prints the program name, then the version.
    _, _, version = result.stdout.strip().partition(" ")
    return field(version) or None


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
    from appsec_analyzer.version_info import describe

    before = describe()
    print(f"Installed version: {before}")
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
    print("Reinstalling ...", flush=True)
    try:
        result = subprocess.run(
            [pipx, *PIPX_UPGRADE],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=UPDATE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("the update could not be completed") from None
    if result.returncode:
        print(result.stdout, end="", file=sys.stderr)
        raise ValueError("the update failed, see the pipx output above")
    print(f"Analyzer was reinstalled from {source}.")
    after = _installed_version()
    if after is None:
        print("The new version could not be read; check it with `appsec-analyzer --version`.")
    else:
        print(f"Installed version: {after}" + (" (unchanged)" if after == before else f" (was {before})"))
    return 0
