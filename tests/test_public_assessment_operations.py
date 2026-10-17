"""Public state and result operations reject untrusted output artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


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


def test_assess_forwards_hyphenated_export_and_control_flags(tmp_path: Path, monkeypatch) -> None:
    from appsec_analyzer import cli

    cli._engine_imports()
    from orchestrator import orchestration_controller

    from appsec_analyzer import hosts

    repo = tmp_path / "repo"
    repo.mkdir()
    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main",
                        lambda arguments: observed.extend(arguments) or 0)
    ns = cli._parser().parse_args([
        "assess", "--repo", str(repo), "--host", "claude-cli", "--hard-budget", "1",
        "--pentest-tasks", "--no-requirements", "--skip-context", "--no-qa",
        "--no-org-profile", "--threatdragon", "--sarif",
    ])
    assert cli._assess(ns) == 0
    for flag in ("--pentest-tasks", "--no-requirements", "--skip-context", "--no-qa",
                 "--no-org-profile", "--threatdragon", "--sarif"):
        assert flag in observed
    assert not any("_" in argument for argument in observed if argument.startswith("--"))


def test_scan_starts_full_assessment_with_headless_defaults(tmp_path: Path, monkeypatch) -> None:
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main",
                        lambda arguments: observed.extend(arguments) or 0)
    arguments = [
        "scan", "--repo", str(repo), "--output", str(output),
        "--assessment-depth", "thorough", "--rebuild", "--keep-runtime-files",
        "--sarif", "--pentest-tasks", "--pentest-format", "strix",
        "--pentest-target", "http://localhost:3000", "--threatdragon", "--pdf", "--html",
        "--slug", "juice-shop-thorough-v0.6.0b5", "--hard-budget", "30",
    ]
    ns = cli._parser().parse_args(arguments)
    assert ns.host == "claude-cli"
    assert cli.main(arguments) == 0
    assert observed[:2] == ["--repo", str(repo)]
    assert "--hard-budget" in observed
    for flag in ("--rebuild", "--keep-runtime-files", "--sarif", "--pentest-tasks",
                 "--threatdragon", "--pdf", "--html"):
        assert flag in observed
    assert observed[observed.index("--assessment-depth") + 1] == "thorough"
    assert observed[observed.index("--output") + 1] == str(output)
    assert observed[observed.index("--pentest-format") + 1] == "strix"
    assert observed[observed.index("--pentest-target") + 1] == "http://localhost:3000"
    assert observed[observed.index("--slug") + 1] == "juice-shop-thorough-v0.6.0b5"


def test_scan_kept_runtime_files_require_private_output(tmp_path: Path, monkeypatch, capsys) -> None:
    from appsec_analyzer import cli, hosts

    output = tmp_path / "public"
    output.mkdir(mode=0o755)
    output.chmod(0o755)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    assert cli.main(["scan", "--repo", str(tmp_path), "--output", str(output),
                     "--hard-budget", "30", "--keep-runtime-files"]) == 2
    assert "requires an existing private --output directory" in capsys.readouterr().err


def test_openai_codex_profile_reaches_full_controller_without_claude_preflight(tmp_path, monkeypatch) -> None:
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    observed = {}
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("Claude host must not be called"))

    def fake_assess(arguments, *, api_profile=None):
        observed["arguments"] = arguments
        observed["profile"] = api_profile
        return 0

    monkeypatch.setattr(orchestration_controller, "assess_main", fake_assess)
    assert cli.main(["scan", "--repo", str(tmp_path), "--host", "openai",
                     "--profile", "codex-thorough", "--assessment-depth", "thorough",
                     "--hard-budget", "30"]) == 0
    assert observed["profile"].model == "gpt-6.1-sol"
    assert observed["profile"].reasoning_effort == "high"
    assert observed["arguments"][0:2] == ["--repo", str(tmp_path)]


@pytest.mark.parametrize("extra, message", [
    (["--host", "openai", "--profile", "codex-thorough"], "must match --assessment-depth"),
    (["--host", "openai", "--reasoning-model", "opus"], "cannot be used"),
    (["--profile", "codex-standard"], "requires --host openai"),
])
def test_codex_profile_invalid_combinations_fail_before_host(tmp_path, monkeypatch, capsys, extra, message):
    from appsec_analyzer import cli, hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    assert cli.main(["scan", "--repo", str(tmp_path), "--hard-budget", "1", *extra]) == 2
    assert message in capsys.readouterr().err
