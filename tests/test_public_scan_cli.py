"""Public deterministic scan contract and its source boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _repo(path: Path, *, escaping_link: bool = False) -> Path:
    path.mkdir()
    (path / "handler.py").write_text("def handler(value):\n    return value\n", encoding="utf-8")
    if escaping_link:
        (path / "outside.py").symlink_to(path.parent / "not-admitted.py")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "fixture"],
        check=True,
    )
    return path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("OPENAI_API_KEY", None)
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    env["APPSEC_CLAUDE_EXECUTABLE"] = "/nonexistent/claude"
    return subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_scan_without_provider_or_claude_reports_only_scanner_coverage(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    result = _run("scan", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["kind"] == "deterministic-scan"
    assert document["assessment_status"] == "not_run"
    assert document["coverage"]["semantic_analysis"] is False
    assert document["repositories"][0]["captured_files"] == 1


def test_scan_rejects_escaping_source_link(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project", escaping_link=True)
    result = _run("scan", "--repo", str(repo))
    assert result.returncode != 0
    assert result.stdout == ""
    assert "preflight rejected" in result.stderr


def test_scan_refuses_output_inside_checkout(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    output = repo / "docs" / "security"
    output.mkdir(parents=True)
    result = _run("scan", "--repo", str(repo), "--output", str(output))
    assert result.returncode != 0
    assert not (output / "scan-result.json").exists()
