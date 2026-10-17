"""Public state and result operations reject untrusted output artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def _run(command: str, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", command, "--output", str(output)],
        capture_output=True, text=True, timeout=20, check=False,
    )


def _state(output: Path, *, status: str = "complete", deliverables: dict | None = None) -> None:
    output.mkdir()
    state = {
        "schema_version": 1,
        "run_id": "assessment-" + "a" * 32,
        "identity": {"scope_sha256": "a" * 64, "configuration_sha256": "b" * 64,
                     "runtime_sha256": "c" * 64,
                     "limits": {"max_usd": 10, "call_usd": 1, "max_calls": 10, "timeout_s": 60}},
        "started_at": 1, "expires_at": 2, "status": status,
        "accounting": {"calls": 0, "spent_usd": 0, "unavailable": False},
        "deliverables": deliverables or {},
    }
    (output / ".assessment-state.json").write_text(json.dumps(state), encoding="utf-8")


def test_status_reports_assessment_scope_without_exposing_internal_identity(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _state(output)
    result = _run("status", output)
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["kind"] == "assessment-status"
    assert body["assessment_status"] == "complete"
    assert "identity" not in body


def test_results_verify_recorded_digest_and_reject_symlink(tmp_path: Path) -> None:
    output = tmp_path / "out"
    content = b"verified report\n"
    name = "security-assessment.md"
    _state(output, deliverables={name: hashlib.sha256(content).hexdigest()})
    report = output / name
    report.write_bytes(content)
    assert _run("results", output).returncode == 0
    report.write_bytes(b"changed\n")
    assert _run("results", output).returncode != 0
    report.unlink()
    report.symlink_to(tmp_path / "external")
    assert _run("results", output).returncode != 0


def test_progress_and_stop_refuse_symlinked_state(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _state(output)
    state = output / ".assessment-state.json"
    external = tmp_path / "state.json"
    state.rename(external)
    state.symlink_to(external)
    for command in ("status", "progress", "stop", "results"):
        result = _run(command, output)
        assert result.returncode != 0
        assert result.stdout == ""


def test_progress_reports_final_state_after_feed_cleanup(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _state(output)
    result = _run("progress", output)
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["assessment_status"] == "complete"
    assert body["feed_available"] is False
    assert body["events"] == []


def test_progress_rejects_symlinked_feed(tmp_path: Path) -> None:
    output = tmp_path / "out"
    _state(output)
    external = tmp_path / "external-feed.jsonl"
    external.write_text('{"message":"untrusted"}\n', encoding="utf-8")
    (output / ".assessment-progress.jsonl").symlink_to(external)
    result = _run("progress", output)
    assert result.returncode != 0
    assert result.stdout == ""


def test_assess_rejects_missing_operator_profile_before_host_call(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "handler.py").write_text("def handler():\n    return True\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
    fake = Path(__file__).resolve().parent / "e2e" / "fake_claude.py"
    result = subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", "assess", "--repo", str(repo),
         "--host", "claude-cli", "--hard-budget", "1", "--trust-mode", "trusted",
         "--output", str(tmp_path / "out"), "--org-profile", str(tmp_path / "missing.yaml")],
        env={**os.environ, "APPSEC_CLAUDE_EXECUTABLE": str(fake),
             "ANTHROPIC_API_KEY": "offline-test"},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode != 0
    assert "org profile not found" in result.stdout + result.stderr
    assert not (tmp_path / "out" / "security-assessment.yaml").exists()
