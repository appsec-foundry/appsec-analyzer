"""Shared fixtures for standalone engine tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


@pytest.fixture(autouse=True)
def claude_cli_reports_subscription(monkeypatch):
    """Billing detection must not depend on the developer's real Claude login."""
    from appsec_analyzer.assessment import console

    console._claude_cli_bills_api.cache_clear()
    console._claude_cli_provider.cache_clear()
    monkeypatch.setenv("APPSEC_CLAUDE_EXECUTABLE", "/nonexistent/claude")
    for name in list(os.environ):
        if console._CLAUDE_BASE_URL.fullmatch(name) or console._CLAUDE_CLOUD_SWITCH.fullmatch(name):
            monkeypatch.delenv(name)
    yield
    console._claude_cli_bills_api.cache_clear()
    console._claude_cli_provider.cache_clear()


@pytest.fixture
def run_plugin_script():
    """Run one repository-owned engine script without a shell."""

    def run(script: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        relative = Path(script)
        target = (SCRIPTS / relative).resolve()
        if relative.is_absolute() or SCRIPTS not in target.parents or not target.is_file():
            raise ValueError("script must name an existing file under scripts/")

        env = os.environ.copy()
        search_path = [str(SCRIPTS), str(ROOT)]
        if env.get("PYTHONPATH"):
            search_path.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(search_path)
        env["CLAUDE_PLUGIN_ROOT"] = str(ROOT)
        return subprocess.run(
            [sys.executable, str(target), *map(str, args)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=check,
        )

    return run
