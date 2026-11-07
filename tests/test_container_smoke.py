"""Smoke test of a built container image under OpenShift-like restrictions.

Set APPSEC_CONTAINER_IMAGE to the image to test, for example after
`docker build -t appsec-analyzer .`. Needs Docker; makes no model calls and runs
the container without network access.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

IMAGE = os.environ.get("APPSEC_CONTAINER_IMAGE", "")
ENGINE = shutil.which("docker")

pytestmark = pytest.mark.skipif(
    not IMAGE or not ENGINE, reason="container smoke test; set APPSEC_CONTAINER_IMAGE and install Docker"
)

# A user ID unknown to the image, in group 0 as OpenShift starts containers. Rootless
# Docker maps only 65536 IDs, so it stays below the range OpenShift assigns.
RANDOM_USER = "54321:0"


@functools.cache
def _checkout_user() -> str:
    """The container user that owns a mounted checkout, as docs/container.md describes."""
    info = subprocess.run([ENGINE, "info", "--format", "{{.SecurityOptions}}"], capture_output=True, text=True)
    # Rootless Docker maps your own user to root in the container.
    return "0:0" if "rootless" in info.stdout else f"{os.getuid()}:0"


def _run(
    *args: str, user: str = RANDOM_USER, volumes: tuple[str, ...] = (), env: tuple[str, ...] = (), entrypoint=None
):
    command = [ENGINE, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL"]
    command += ["--security-opt", "no-new-privileges", "--tmpfs", "/tmp", "--tmpfs", "/home/analyzer", "--user", user]
    command += [item for volume in volumes for item in ("--volume", volume)]
    command += [item for name in env for item in ("--env", name)]
    command += ["--entrypoint", entrypoint] if entrypoint else []
    return subprocess.run([*command, IMAGE, *args], capture_output=True, text=True, timeout=300, check=False)


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    git = ["git", "-C", str(repo), "-c", "user.name=Smoke Test", "-c", "user.email=smoke@example.invalid"]
    subprocess.run([*git, "init", "--quiet"], check=True)
    subprocess.run([*git, "add", "app.py"], check=True)
    subprocess.run([*git, "commit", "--quiet", "--message", "fixture"], check=True)
    return repo


def test_version_runs_as_a_random_user_on_a_read_only_root():
    result = _run("--version")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()


@pytest.mark.parametrize("tool", ["claude", "git", "pandoc"])
def test_bundled_tools_start(tool):
    result = _run("--version", entrypoint=tool)
    assert result.returncode == 0, result.stderr


def test_scan_reads_a_read_only_checkout_and_writes_to_the_output_volume(checkout: Path, tmp_path: Path):
    output = tmp_path / "output"
    output.mkdir()
    volumes = (f"{checkout}:/repo:ro", f"{output}:/output")
    result = _run("scan-sources", "--repo", "/repo", "--output", "/output", user=_checkout_user(), volumes=volumes)
    assert result.returncode == 0, result.stderr
    assert (output / "scan-result.json").is_file()
    assert sorted(path.name for path in checkout.iterdir()) == [".git", "app.py"]


def test_checkout_owned_by_another_user_is_rejected(checkout: Path):
    # Git's ownership check stays active: a foreign .git could configure commands that Git runs.
    result = _run("scan-sources", "--repo", "/repo", volumes=(f"{checkout}:/repo:ro",))
    assert result.returncode == 2
    assert "Git cannot read" in result.stderr


def test_preflight_without_credentials_fails_closed(checkout: Path):
    result = _run(
        "preflight", "--repo", "/repo", "--profile", "claude", "--json",
        user=_checkout_user(), volumes=(f"{checkout}:/repo:ro",),
    )  # fmt: skip
    assert result.returncode == 2
    assert "not authenticated" in result.stderr


def test_preflight_accepts_credentials_from_the_environment(checkout: Path, monkeypatch):
    # An artificial value: preflight checks only that credentials are configured and makes no model call.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-not-a-key")
    result = _run(
        "preflight", "--repo", "/repo", "--profile", "claude", "--json",
        user=_checkout_user(), volumes=(f"{checkout}:/repo:ro",), env=("ANTHROPIC_API_KEY",),
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["provider_check"] == "local_configuration"
