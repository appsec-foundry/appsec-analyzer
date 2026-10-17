"""Host-specific preflights kept outside deterministic scanning."""

from __future__ import annotations

import json
import os
import shutil
import subprocess


def claude_preflight() -> None:
    executable = os.environ.get("APPSEC_CLAUDE_EXECUTABLE") or "claude"
    if not shutil.which(executable):
        raise ValueError("Claude CLI is unavailable for the selected claude-cli host")
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return
    try:
        result = subprocess.run([executable, "auth", "status"], capture_output=True, timeout=10, check=False)
        response = json.loads(result.stdout[:8192])
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise ValueError("Claude CLI authentication status is unavailable") from None
    if result.returncode or response.get("loggedIn") is not True:
        raise ValueError("Claude CLI is not authenticated")
