"""Public deterministic scan contract and its source boundary."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _repo(path: Path, *, escaping_link: bool = False) -> Path:
    path.mkdir()
    (path / "handler.py").write_text("def handler(value):\n    return value\n", encoding="utf-8")
    if escaping_link:
        (path / "outside.py").symlink_to(path.parent / "not-admitted.py")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
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


def test_capabilities_distinguish_adapters_from_live_qualification() -> None:
    result = _run("capabilities")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    providers = document["assessment"]["providers"]
    assert providers["claude-cli"]["adapter"] == "compatibility"
    assert providers["openai"]["adapter"] == "responses"
    assert providers["claude-cli"]["profiles"] == ["claude"]
    assert providers["openai"]["profiles"] == ["codex", "codex-quick", "codex-standard", "codex-thorough"]
    assert providers["gateway"]["adapter"] == "offline-only"
    assert providers["codex-cli"]["adapter"] == "cli"
    assert providers["codex-cli"]["billing"] == "chatgpt-subscription"
    assert providers["codex-cli"]["profiles"] == ["codex-cli"]
    assert providers["copilot-cli"]["adapter"] == "cli"
    assert providers["copilot-cli"]["billing"] == "github-copilot-subscription"
    assert providers["copilot-cli"]["profiles"] == ["copilot-cli"]
    assert all(provider["qualified"] is False for provider in providers.values())


def test_scan_without_provider_or_claude_reports_only_scanner_coverage(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    result = _run("scan-sources", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    assert "Deterministic scan completed." in result.stdout
    assert "Scanner findings: 0 (unverified)" in result.stdout
    assert "Full assessment was not run." in result.stdout
    assert not result.stdout.lstrip().startswith("{")

    result = _run("scan-sources", "--repo", str(repo), "--json")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["kind"] == "deterministic-scan"
    assert document["assessment_status"] == "not_run"
    assert document["coverage"]["semantic_analysis"] is False
    assert document["repositories"][0]["captured_files"] == 1


def test_scan_output_writes_complete_json_and_prints_summary(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    output = tmp_path / "result"
    output.mkdir()
    result = _run("scan-sources", "--repo", str(repo), "--output", str(output))
    assert result.returncode == 0, result.stderr
    assert "Complete JSON result:" in result.stdout
    assert json.loads((output / "scan-result.json").read_text())["scan_status"] == "completed"


def test_entry_skill_scanner_example_runs_without_a_model_host(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    skill = (ROOT / "skills/appsec-analyzer/SKILL.md").read_text()
    example = skill.split("For a scanner-only request, invoke:", 1)[1].split("```sh\n", 1)[1].split("```", 1)[0]
    command = shlex.split(example.replace("<absolute-local-path>", str(repo)))
    assert command[0] == "appsec-analyzer"
    result = _run(*command[1:])
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["kind"] == "deterministic-scan"
    assert document["assessment_status"] == "not_run"
    assert document["coverage"]["semantic_analysis"] is False


def test_scan_bad_or_missing_options_show_text_errors() -> None:
    for args in (
        ("assess", "--budget"),
        ("assess", "--hard-budget", "0"),
        ("assess", "--hard-budget", "nan"),
        ("assess", "--hard-budget", "20", "--assessment-depth", "invalid"),
        ("assess", "--profile", "unknown-provider"),
        ("assess", "--hard-budget", "20", "--pentest-target", "file:///etc/passwd"),
        ("assess", "--hard-budget", "20", "--pentest-target", "http://localhost:3000\x01x"),
        ("assess", "--hard-budget", "20", "--slug", "../escape"),
    ):
        result = _run(*args)
        assert result.returncode != 0
        assert result.stdout == ""
        assert "error:" in result.stderr
        assert not result.stderr.lstrip().startswith("{")


def test_scan_summary_cannot_render_control_characters_from_findings() -> None:
    from appsec_analyzer.cli import _scan_summary

    summary = _scan_summary(
        {
            "repositories": [
                {
                    "label": "project\x1b[31m\nspoofed",
                    "captured_files": 1,
                    "excluded_files": [],
                    "findings": [
                        {
                            "finding": {
                                "severity": "High",
                                "file": "src/a.py\nFAKE",
                                "line": 1,
                                "title": "problem\x1b[0m\nFAKE",
                            }
                        }
                    ],
                }
            ]
        },
        output=None,
    )
    assert "\x1b" not in summary
    assert "\nFAKE" not in summary


def test_scan_rejects_escaping_source_link(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project", escaping_link=True)
    result = _run("scan-sources", "--repo", str(repo))
    assert result.returncode != 0
    assert result.stdout == ""
    assert "preflight rejected" in result.stderr


def test_scan_refuses_output_inside_checkout(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "project")
    output = repo / "docs" / "security"
    output.mkdir(parents=True)
    result = _run("scan-sources", "--repo", str(repo), "--output", str(output))
    assert result.returncode != 0
    assert not (output / "scan-result.json").exists()


@pytest.mark.parametrize("link_parent", [False, True])
def test_preflight_never_discloses_external_declaration(tmp_path, link_parent):
    repo = _repo(tmp_path / "project")
    external = tmp_path / "private"
    external.mkdir()
    marker = "SYNTHETIC_PRIVATE_CANARY"
    (external / "related-repos.yaml").write_text("related:\n  - name: [" + marker + "\n")
    if link_parent:
        (repo / "docs").symlink_to(external, target_is_directory=True)
    else:
        (repo / "docs").mkdir()
        (repo / "docs/related-repos.yaml").symlink_to(external / "related-repos.yaml")
    result = _run("scan-sources", "--repo", str(repo), "--json")
    assert result.returncode == 2
    assert marker not in result.stdout + result.stderr
    assert "preflight rejected" in result.stderr


@pytest.mark.parametrize(
    "declaration",
    [
        "related:\n  - name: [SYNTHETIC_PRIVATE_CANARY\n",
        "related:\n  - threat_model: https://user:SYNTHETIC_PRIVATE_CANARY@127.0.0.1/model.yaml\n",
    ],
)
def test_preflight_diagnostics_never_echo_declaration_values(tmp_path, declaration):
    repo = _repo(tmp_path / "project")
    (repo / "docs").mkdir()
    (repo / "docs/related-repos.yaml").write_text(declaration)
    result = _run("scan-sources", "--repo", str(repo), "--json")
    assert result.returncode == 2
    assert "SYNTHETIC_PRIVATE_CANARY" not in result.stdout + result.stderr


def test_scan_preserves_existing_result_and_concurrent_publication(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from appsec_analyzer.cli import _write_result

    repo = _repo(tmp_path / "project")
    output = tmp_path / "result"
    output.mkdir()
    target = output / "scan-result.json"
    target.write_text("operator data")
    result = _run("scan-sources", "--repo", str(repo), "--output", str(output))
    assert result.returncode == 2
    assert target.read_text() == "operator data"
    target.unlink()

    def publish(value):
        try:
            _write_result(output, value)
            return value
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = [value for value in pool.map(publish, ["first", "second"]) if value is not None]
    assert len(winners) == 1
    assert target.read_text() == winners[0]
    assert target.stat().st_mode & 0o777 == 0o600


def test_audit_discloses_transmission_before_first_model_operation(tmp_path, monkeypatch, capsys):
    from appsec_analyzer import cli, hosts, requirements_audit

    repo = _repo(tmp_path / "project")
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def audit(**kwargs):
        output = capsys.readouterr()
        assert "Claude CLI" in output.err
        assert "masked source excerpts" in output.err
        assert "catalog" in output.err and "Git retrieval is separate" in output.err
        assert "retention is not verified" in output.err
        return 0, {"audit_status": "complete"}

    monkeypatch.setattr(requirements_audit, "audit_repository", audit)
    assert (
        cli.main(
            [
                "audit-requirements",
                "--repo",
                str(repo),
                "--output",
                str(tmp_path / "out"),
                "--demo",
                "--host",
                "claude-cli",
            ]
        )
        == 0
    )


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize(
    "budget_args, expected",
    [([], 20.0), (["--budget", "20"], 20.0), (["--budget", "7.5"], 7.5), (["--hard-budget", "3"], 3.0)],
)
def test_public_budget_reaches_assessment_controller(tmp_path, monkeypatch, capsys, command, budget_args, expected):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    observed = []
    profiles = []

    def record_assessment(args, **kwargs):
        observed.extend(args)
        profiles.append(kwargs["run_profile"])
        return 0

    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", record_assessment)
    arguments = [command, "--repo", str(tmp_path), *budget_args]
    assert cli.main(arguments) == 0
    assert observed[:2] == ["--repo", str(tmp_path)]
    assert observed.count("--hard-budget") == 1
    assert float(observed[observed.index("--hard-budget") + 1]) == expected
    assert "Model budget limit:" not in capsys.readouterr().err
    ns, _ = orchestration_controller._assessment_argument_parser().parse_known_args(observed)
    rows = dict(
        orchestration_controller._assessment_intro(
            ns,
            orchestration_controller._assessment_budget(ns),
            profiles[0]["settings"]["assessment_depth"],
            "Models: test",
            "test pipeline",
            cfg={"operator_profile": profiles[0]},
        )
    )
    assert rows["Budget"].startswith(f"model calls stop at ${expected:.2f}")
    assert ("default for the scan profile" in rows["Budget"]) is (not budget_args)


@pytest.mark.parametrize("command", ["assess"])
def test_non_interactive_reaches_the_controller_and_is_documented(tmp_path, monkeypatch, command):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    observed = []
    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda args, **kwargs: observed.extend(args) or 0)
    assert cli.main([command, "--repo", str(tmp_path), "--profile", "claude", "--non-interactive"]) == 0
    assert "--non-interactive" in observed
    assert "--non-interactive" in _run(command, "--help").stdout


@pytest.mark.parametrize(
    "budget_args, expected", [([], 5.0), (["--budget", "7.5"], 7.5), (["--hard-budget", "3"], 3.0)]
)
def test_public_budget_reaches_requirements_audit(tmp_path, monkeypatch, capsys, budget_args, expected):
    from appsec_analyzer import cli, hosts, requirements_audit

    observed = {}

    def record_audit(**kwargs):
        observed.update(kwargs)
        return 0, {"kind": "requirements-audit"}

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(requirements_audit, "audit_repository", record_audit)
    assert (
        cli.main(
            [
                "audit-requirements",
                "--repo",
                str(tmp_path),
                "--output",
                str(tmp_path / "output"),
                "--host",
                "claude-cli",
                "--requirements",
                str(tmp_path / "catalog.yaml"),
                *budget_args,
            ]
        )
        == 0
    )
    assert observed["hard_budget"] == expected
    captured = capsys.readouterr()
    assert f"Model budget limit: USD {expected:g}" in captured.err
    assert json.loads(captured.out)["kind"] == "requirements-audit"


@pytest.mark.parametrize("command", ["assess", "audit-requirements"])
@pytest.mark.parametrize("flag", ["--budget", "--hard-budget"])
@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "invalid"])
def test_public_budget_rejects_invalid_values_before_host(tmp_path, monkeypatch, capsys, command, flag, value):
    from appsec_analyzer import cli, hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    arguments = [command, "--repo", str(tmp_path), "--host", "claude-cli", f"{flag}={value}"]
    if command == "audit-requirements":
        arguments += ["--output", str(tmp_path / "output"), "--demo"]
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "positive finite USD amount" in captured.err


@pytest.mark.parametrize("api_key", [False, True])
def test_claude_budget_line_values_a_subscription_limit_at_api_prices(monkeypatch, api_key):
    from appsec_analyzer import cli

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-api-key")
    unit = "" if api_key else " of subscription usage at API prices"
    assert cli._claude_budget_line(5.0) == f"Model budget limit: USD 5{unit}"


@pytest.mark.parametrize("command, default", [("assess", 20), ("audit-requirements", 5)])
def test_public_budget_help_documents_default_and_alias(command, default):
    result = _run(command, "--help")
    assert result.returncode == 0
    assert "--budget USD, --hard-budget USD" in result.stdout
    help_text = " ".join(result.stdout.split())
    if command == "audit-requirements":
        assert f"Maximum model cost in USD (default: {default})" in help_text
    else:
        assert (
            f"Maximum model cost in USD (built-in default: {default}; user profile may override; unavailable with codex-cli and copilot-cli)"
            in help_text
        )
    assert "with a Claude subscription, usage at API prices" in help_text


def test_an_internal_defect_in_a_command_ends_with_a_message_not_a_traceback(tmp_path, monkeypatch, capsys):
    from appsec_analyzer import cli

    def fail(ns):
        raise KeyError("jobs")

    monkeypatch.setattr(cli, "_scan", fail)
    monkeypatch.delenv("APPSEC_PLUGIN_DEV", raising=False)
    assert cli.main(["scan-sources", "--repo", str(tmp_path)]) == 1
    error = capsys.readouterr().err
    assert error.startswith("appsec-analyzer: internal error: KeyError: 'jobs' in main (appsec_analyzer/cli.py:")
    assert error.rstrip().endswith("; this is a defect in appsec-analyzer") and "Traceback" not in error
