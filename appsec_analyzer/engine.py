"""Locate the retained engine packages for checkout and wheel execution.

New application modules use regular package imports. The retained script
entry points still use their established domain names during migration.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from appsec_analyzer import resource_root


def initialize() -> None:
    """Make the bundled engine available without importing the CLI."""
    scripts = str(resource_root() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def implementation_files():
    """Yield bounded regular application source paths for run identity."""
    package = Path(__file__).resolve().parent
    excluded = {
        "scripts",
        "agents",
        "schemas",
        "data",
        "templates",
        "assets",
        "examples",
        "docs",
        "skills",
        "__pycache__",
    }
    count, total = 0, 0
    for parent, directories, files in os.walk(package, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in excluded)
        for name in directories:
            if not stat.S_ISDIR((Path(parent) / name).lstat().st_mode):
                raise RuntimeError("application runtime must not contain directory links")
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = Path(parent) / name
            info = path.lstat()
            count += 1
            total += info.st_size
            if not stat.S_ISREG(info.st_mode) or info.st_size > 2_097_152 or count > 10_000 or total > 67_108_864:
                raise RuntimeError("application runtime must contain bounded regular files")
            yield "appsec_analyzer/" + path.relative_to(package).as_posix(), path
