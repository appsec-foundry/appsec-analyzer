"""Repository preflight shared by assessment, deterministic scan and reviews."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from appsec_analyzer import resource_root

# Exit codes of validators/preflight_untrusted.py with --strict.
FINDINGS_EXIT = 2
UNREADABLE_EXIT = 3


class SourcePreflightError(ValueError):
    """Selected repositories failed the existing admission preflight."""


def _failure(name: str, args: list[str]) -> str | None:
    done = subprocess.run(
        [sys.executable, str(resource_root() / "scripts" / name), *args], text=True, capture_output=True, check=False
    )
    if done.returncode == UNREADABLE_EXIT:
        raise SourcePreflightError("Selected repository does not exist or cannot be read. Check the path.")
    if done.returncode == FINDINGS_EXIT:
        return f"{Path(name).name} failed with exit {done.returncode}: {(done.stderr or done.stdout).strip()}"
    if done.returncode:
        # Not a verdict on the repository, so neither its files nor the trust mode are the way out.
        raise SourcePreflightError(
            f"Repository preflight could not run (exit {done.returncode}). Check the Analyzer installation."
        )
    return None


def check_repositories(roots: list[str], *, runner=None) -> None:
    """Check every root; repository-owned model configuration stays inert."""
    runner = runner or _failure
    for root in roots:
        failure = runner(
            "validators/preflight_untrusted.py",
            ["--repo-root", root, "--strict", "--strict-urls", "--isolated-host", "--format", "text", "--output", "-"],
        )
        if failure:
            raise SourcePreflightError(
                f"untrusted-repository preflight rejected {Path(root).name}: {failure}. "
                "Remove the listed paths or URLs from the checkout, or pass --trust-mode trusted "
                "only for repositories you control."
            )
