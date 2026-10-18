"""Bounded discovery of configuration and infrastructure surfaces."""

import fnmatch
import os
from pathlib import Path

_IAC_SURFACE_GLOBS = (
    "Dockerfile",
    "*.dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".npmrc",
    ".yarnrc.yml",
    # Committed coding-agent configuration is a config surface of its own: a
    # repository can carry an agent posture and no IaC file at all.
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".kiro/settings/mcp.json",
    ".vscode/settings.json",
)


# Directories that never carry a deployable IaC surface but dominate a
# recursive walk on a real repository.
_IAC_WALK_PRUNE = {".git", "node_modules", ".venv", "venv", "dist", "build", ".appsec-cache"}
_IAC_WALK_MAX_ENTRIES = 200_000


def has_iac_surface(repo_root: Path, *, max_entries: int = _IAC_WALK_MAX_ENTRIES) -> bool:
    """Deterministic IaC-surface pre-check for the Phase-2.5 selection.

    One bounded walk matching every pattern at once. Thirteen separate
    recursive globs re-walk the tree per pattern and are the documented
    cold-cache hazard on a monorepo. Hitting the entry cap answers "true" so an
    unwalked remainder can never silently drop the config scan.
    """
    relative_globs = [pattern for pattern in _IAC_SURFACE_GLOBS if "/" in pattern]
    name_globs = [pattern for pattern in _IAC_SURFACE_GLOBS if "/" not in pattern]
    visited = 0
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in _IAC_WALK_PRUNE]
        visited += len(filenames)
        if visited > max_entries:
            return True
        for filename in filenames:
            if any(fnmatch.fnmatch(filename, pattern) for pattern in name_globs):
                return True
            relative = (Path(dirpath) / filename).relative_to(repo_root).as_posix()
            if any(fnmatch.fnmatch(relative, f"*{pattern}") for pattern in relative_globs):
                return True
    return False
