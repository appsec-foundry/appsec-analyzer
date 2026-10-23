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
def _no_live_model_test(request, monkeypatch):
    """`assess` tests a model before every run; without this, an installed CLI or API key would be called.

    Tests of that check request the `model_test` fixture and mock the transports themselves.
    """
    if "model_test" not in request.fixturenames:
        from appsec_analyzer import preflight

        monkeypatch.setattr(preflight, "_test_low_cost_model", lambda ns, **kw: "test_model_inconclusive")


@pytest.fixture
def model_test():
    """Run the real model test before an assessment; the test must mock every transport it reaches."""


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
