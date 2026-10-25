"""Public state and result operations reject untrusted output artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def git_root(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


@pytest.fixture
def openai_metadata(monkeypatch):
    from appsec_analyzer import api_hosts

    class Connection:
        status = 200

        def __init__(self, *args, **kwargs):
            self.model = None

        def request(self, method, path, *, body, headers):
            assert method == "GET" and body is None and path.startswith("/v1/models/")
            assert headers["Authorization"] == "Bearer synthetic-preflight-test-key"
            self.model = path.rsplit("/", 1)[-1]

        def getresponse(self):
            return self

        def read(self, limit):
            return json.dumps({"id": self.model}).encode()

        def close(self):
            pass

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Connection)
    monkeypatch.setattr(api_hosts, "_public_addresses", lambda _: ("203.0.113.5",))
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-preflight-test-key")


def _run(command: str, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", command, "--output", str(output)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def _state(output: Path, *, status: str = "complete", deliverables: dict | None = None) -> None:
    output.mkdir()
    state = {
        "schema_version": 1,
        "run_id": "assessment-" + "a" * 32,
        "identity": {
            "scope_sha256": "a" * 64,
            "configuration_sha256": "b" * 64,
            "runtime_sha256": "c" * 64,
            "limits": {"max_usd": 10, "call_usd": 1, "max_calls": 10, "timeout_s": 60},
        },
        "started_at": 1,
        "expires_at": 2,
        "status": status,
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
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
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
    fake = Path(__file__).resolve().parent / "e2e" / "fake_claude.py"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer.cli",
            "assess",
            "--repo",
            str(repo),
            "--host",
            "claude-cli",
            "--hard-budget",
            "1",
            "--trust-mode",
            "trusted",
            "--output",
            str(tmp_path / "out"),
            "--org-profile",
            str(tmp_path / "missing.yaml"),
        ],
        env={**os.environ, "APPSEC_CLAUDE_EXECUTABLE": str(fake), "ANTHROPIC_API_KEY": "offline-test"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
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
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(
        orchestration_controller, "assess_main", lambda arguments, **kwargs: observed.extend(arguments) or 0
    )
    ns = cli._parser().parse_args(
        [
            "assess",
            "--repo",
            str(repo),
            "--host",
            "claude-cli",
            "--hard-budget",
            "1",
            "--pentest-tasks",
            "--no-requirements",
            "--skip-context",
            "--no-qa",
            "--no-org-profile",
            "--threatdragon",
            "--sarif",
        ]
    )
    assert cli._assess(ns) == 0
    for flag in (
        "--pentest-tasks",
        "--no-requirements",
        "--skip-context",
        "--no-qa",
        "--no-org-profile",
        "--threatdragon",
        "--sarif",
    ):
        assert flag in observed
    assert not any("_" in argument for argument in observed if argument.startswith("--"))


def test_assess_starts_full_assessment_with_headless_defaults(tmp_path: Path, monkeypatch) -> None:
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(
        orchestration_controller, "assess_main", lambda arguments, **kwargs: observed.extend(arguments) or 0
    )
    arguments = [
        "assess",
        "--repo",
        str(repo),
        "--output",
        str(output),
        "--assessment-depth",
        "thorough",
        "--rebuild",
        "--keep-runtime-files",
        "--sarif",
        "--pentest-tasks",
        "--pentest-format",
        "strix",
        "--pentest-target",
        "http://localhost:3000",
        "--threatdragon",
        "--pdf",
        "--html",
        "--slug",
        "juice-shop-thorough-v0.6.0b5",
        "--hard-budget",
        "30",
    ]
    ns = cli._parser().parse_args(arguments)
    assert cli._assessment_host(ns) == "claude-cli"
    assert cli.main(arguments) == 0
    assert observed[:2] == ["--repo", str(repo)]
    assert "--hard-budget" in observed
    for flag in (
        "--rebuild",
        "--keep-runtime-files",
        "--sarif",
        "--pentest-tasks",
        "--threatdragon",
        "--pdf",
        "--html",
    ):
        assert flag in observed
    assert observed[observed.index("--assessment-depth") + 1] == "thorough"
    assert observed[observed.index("--output") + 1] == str(output)
    assert observed[observed.index("--pentest-format") + 1] == "strix"
    assert observed[observed.index("--pentest-target") + 1] == "http://localhost:3000"
    assert observed[observed.index("--slug") + 1] == "juice-shop-thorough-v0.6.0b5"


def test_assess_kept_runtime_files_require_private_output(tmp_path: Path, monkeypatch, capsys) -> None:
    from appsec_analyzer import cli, hosts

    output = tmp_path / "public"
    output.mkdir(mode=0o755)
    output.chmod(0o755)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    assert (
        cli.main(
            ["assess", "--repo", str(tmp_path), "--output", str(output), "--hard-budget", "30", "--keep-runtime-files"]
        )
        == 2
    )
    assert "requires a private --output directory" in capsys.readouterr().err


def test_assess_kept_runtime_files_create_missing_output_privately(tmp_path: Path, monkeypatch) -> None:
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    output = tmp_path / "runs" / "151"
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda arguments, **kwargs: 0)
    arguments = ["assess", "--repo", str(repo), "--output", str(output), "--hard-budget", "30", "--keep-runtime-files"]
    assert cli.main(arguments) == 0
    assert output.is_dir() and not output.is_symlink()
    assert output.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("placement", ["checkout", "link"])
def test_assess_kept_runtime_files_never_create_output_in_checkout_or_through_link(
    tmp_path: Path, monkeypatch, capsys, placement
) -> None:
    from appsec_analyzer import cli, hosts

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    if placement == "checkout":
        created, output = repo / "runs", repo / "runs" / "151"
    else:
        (tmp_path / "real").mkdir(mode=0o700)
        (tmp_path / "link").symlink_to(tmp_path / "real")
        created, output = tmp_path / "real" / "151", tmp_path / "link" / "151"
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    arguments = ["assess", "--repo", str(repo), "--output", str(output), "--hard-budget", "30", "--keep-runtime-files"]
    assert cli.main(arguments) == 2
    assert "requires a private --output directory" in capsys.readouterr().err
    assert not created.exists()


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize(
    "depth, effort, output_cap",
    [
        ("quick", "low", None),
        ("standard", "medium", None),
        ("thorough", "high", None),
    ],
)
@pytest.mark.parametrize("selection", ["profile", "legacy-profile", "legacy-host", "matching-host"])
def test_openai_codex_profile_reaches_full_controller_without_claude_preflight(
    tmp_path,
    monkeypatch,
    command,
    depth,
    effort,
    output_cap,
    selection,
    git_root,
    openai_metadata,
) -> None:
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    observed = {}
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("Claude host must not be called"))

    def fake_assess(arguments, *, api_profile=None, run_profile=None):
        observed["arguments"] = arguments
        observed["profile"] = api_profile
        return 0

    monkeypatch.setattr(orchestration_controller, "assess_main", fake_assess)
    options = {
        "profile": ["--profile", "codex"],
        "legacy-profile": ["--host", "openai", "--profile", f"codex-{depth}"],
        "legacy-host": ["--host", "openai"],
        "matching-host": ["--profile", "codex", "--host", "openai"],
    }[selection]
    assert (
        cli.main([command, "--repo", str(tmp_path), *options, "--assessment-depth", depth, "--hard-budget", "30"]) == 0
    )
    assert observed["profile"].model == "gpt-6.1-sol"
    assert observed["profile"].reasoning_effort == effort
    assert observed["profile"].max_output_tokens == output_cap
    from appsec_analyzer.assessment.request import AssessmentRequest

    assert isinstance(observed["arguments"], AssessmentRequest)
    assert list(observed["arguments"][0:2]) == ["--repo", str(tmp_path)]
    assert observed["arguments"][observed["arguments"].index("--assessment-depth") + 1] == depth


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize("depth", ["quick", "standard", "thorough"])
def test_claude_profile_preserves_controller_model_resolution(tmp_path, monkeypatch, command, depth, git_root):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller

    preflight = []
    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: preflight.append(True))
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda args, **kwargs: observed.extend(args) or 0)
    assert (
        cli.main(
            [command, "--repo", str(tmp_path), "--profile", "claude", "--assessment-depth", depth, "--model", "sonnet"]
        )
        == 0
    )
    assert preflight == [True]
    assert observed[observed.index("--assessment-depth") + 1] == depth
    assert observed[observed.index("--model") + 1] == "sonnet"


def test_codex_profile_selects_the_model_configured_for_each_depth(tmp_path, monkeypatch, git_root, openai_metadata):
    from dataclasses import replace

    from appsec_analyzer import cli, hosts
    from appsec_analyzer.codex_profiles import CODEX_PROFILES

    cli._engine_imports()
    from orchestrator import orchestration_controller

    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("Claude host must not be called"))
    monkeypatch.setattr(
        orchestration_controller,
        "assess_main",
        lambda args, *, api_profile, run_profile: observed.append(api_profile.model) or 0,
    )
    for depth in ("quick", "standard", "thorough"):
        monkeypatch.setitem(CODEX_PROFILES, depth, replace(CODEX_PROFILES[depth], model=f"test-{depth}"))
    for depth in ("quick", "standard", "thorough"):
        assert cli.main(["assess", "--repo", str(tmp_path), "--profile", "codex", "--assessment-depth", depth]) == 0
    assert observed == ["test-quick", "test-standard", "test-thorough"]


@pytest.mark.parametrize(
    "extra, message",
    [
        (["--host", "openai", "--profile", "codex-thorough"], "must match --assessment-depth"),
        (["--host", "openai", "--reasoning-model", "opus"], "cannot be used"),
        (["--profile", "codex-standard"], "requires --host openai"),
        (["--profile", "codex", "--host", "claude-cli"], "conflicts with --host"),
        (["--profile", "claude", "--host", "openai"], "conflicts with --host"),
        (["--profile", "codex", "--host", "gateway"], "conflicts with --host"),
        (["--profile", "claude", "--host", "gateway"], "conflicts with --host"),
        (["--host", "gateway"], "has no configured model/depth profile"),
        (["--profile", "codex", "--model", "other-model"], "differs from the selected OpenAI profile"),
        (["--profile", "codex", "--reasoning-model", "opus"], "cannot be used"),
        (["--profile", "codex", "--stride-model", "opus"], "cannot be used"),
        (["--profile", "codex", "--triage-model", "opus"], "cannot be used"),
        (["--profile", "codex", "--merger-model", "opus"], "cannot be used"),
    ],
)
@pytest.mark.parametrize("command", ["assess"])
def test_codex_profile_invalid_combinations_fail_before_host(tmp_path, monkeypatch, capsys, command, extra, message):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import remote_repositories

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a: pytest.fail("must not retrieve sources"))
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda *a, **kw: pytest.fail("must not assess"))
    assert cli.main([command, "--repo", str(tmp_path), "--hard-budget", "1", *extra]) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    [
        ["--repo", "{repo}"],
        ["--profile", "claude"],
        ["--host", "claude-cli"],
        [],
    ],
)
def test_non_interactive_assess_requires_repo_and_explicit_provider(tmp_path, monkeypatch, capsys, arguments):
    from appsec_analyzer import cli, hosts

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not be called"))
    arguments = [value.format(repo=tmp_path) for value in arguments]
    assert cli.main(["assess", "--non-interactive", *arguments]) == 2
    assert "requires --repo and an explicit --profile" in capsys.readouterr().err


def test_scan_command_is_removed(capsys):
    from appsec_analyzer import cli

    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "--repo", "."])
    assert error.value.code == 2
    assert "invalid choice: 'scan'" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["assess"])
def test_model_profile_defaults_to_standard_depth(command):
    from appsec_analyzer import cli

    ns = cli._parser().parse_args([command, "--repo", ".", "--profile", "codex"])
    assert cli._assessment_host(ns) == "openai"
    assert ns.assessment_depth == "standard"


@pytest.mark.parametrize("name", ["billing-service", "order-worker"])
def test_host_entry_retains_advisor_destination_and_source(tmp_path, name, monkeypatch, capsys):
    from appsec_analyzer import cli

    repo = tmp_path / name
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private data"))
    assert cli.main(["assessment-entry", "destination", "--repo", str(repo), "--storage", "advisor"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert Path(result["output"]).parent == tmp_path / "private data/appsec-advisor/assessments"
    assert Path(result["output"]).name.startswith(name + "-")
    assert not Path(result["output"]).exists()
    assert result["repo"] == str(repo)
    assert cli.main(["assessment-entry", "destination", "--repo", str(repo), "--output", str(repo / "result")]) == 2
    assert not (repo / "result").exists()


def test_host_entry_context_trust_and_retained_answer(tmp_path, capsys):
    from appsec_analyzer import cli

    repo = tmp_path / "service"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("# Order management\nA service for managing customer orders.\n")
    output = tmp_path / "private output"
    args = ["--repo", str(repo), "--output", str(output)]
    assert cli.main(["assessment-entry", "trust", "--repo", str(repo)]) == 0
    assert json.loads(capsys.readouterr().out)["finding_count"] == 0
    assert cli.main(["assessment-entry", "context-preview", *args]) == 0
    assert "preview" in json.loads(capsys.readouterr().out)
    raw = output / ".business-context-raw.md"
    raw.write_text("## Business purpose\n**Question:** What should be assessed?\n**Answer:** Manage customer orders.\n")
    assert cli.main(["assessment-entry", "context-save", *args, "--context-answer", "answered"]) == 0
    assert not raw.exists()
    saved = repo / "docs/security/business-context.md"
    assert "Manage customer orders." in saved.read_text()
    assert cli.main(["assessment-entry", "context-preview", *args]) == 0
    assert "Manage customer orders." in capsys.readouterr().out
    outside = tmp_path / "outside"
    outside.write_text("not source")
    (repo / "escape").symlink_to(outside)
    assert cli.main(["assessment-entry", "trust", "--repo", str(repo)]) == 2
    assert json.loads(capsys.readouterr().out)["finding_count"] > 0


@pytest.mark.parametrize("defect", ["symlink", "source", "public"])
def test_host_entry_refuses_unsafe_output_before_context_write(tmp_path, capsys, defect):
    from appsec_analyzer import cli

    repo = tmp_path / "service"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    target = tmp_path / "output"
    target.mkdir(mode=0o700)
    selection = target
    if defect == "symlink":
        selection = tmp_path / "linked"
        selection.symlink_to(target, target_is_directory=True)
    elif defect == "source":
        selection = repo / "output"
    else:
        target.chmod(0o755)
    assert cli.main(["assessment-entry", "context-preview", "--repo", str(repo), "--output", str(selection)]) == 2
    assert list(target.iterdir()) == []
    assert "Traceback" not in capsys.readouterr().err


def test_host_entry_holder_and_cleanup_preserve_live_owner_and_receipts(tmp_path):
    output = tmp_path / "private output"
    _state(output, status="running")
    output.chmod(0o700)
    import time

    (output / ".appsec-lock").write_text(f"{os.getpid()}\n{int(time.time())}\n")
    (output / ".appsec-checkpoint").write_text("phase=1 status=started\n")
    before = (output / ".assessment-state.json").read_bytes()
    base = [sys.executable, "-m", "appsec_analyzer.cli", "assessment-entry"]
    result = subprocess.run([*base, "holder", "--output", str(output)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and json.loads(result.stdout)["live"] is True
    refusal = subprocess.run([*base, "clean", "--output", str(output), "--apply"], capture_output=True, timeout=20)
    assert refusal.returncode == 2
    assert (output / ".appsec-lock").exists()
    (output / ".appsec-lock").write_text("999999999\n1\n")
    dry = subprocess.run([*base, "clean", "--output", str(output)], capture_output=True, text=True, timeout=20)
    assert dry.returncode == 0 and (output / ".appsec-lock").exists()
    applied = subprocess.run(
        [*base, "clean", "--output", str(output), "--apply"], capture_output=True, text=True, timeout=20
    )
    assert applied.returncode == 0, applied.stderr
    assert not (output / ".appsec-lock").exists()
    assert not (output / ".appsec-checkpoint").exists()
    assert (output / ".assessment-state.json").read_bytes() == before
    assert (output / ".appsec-lock.guard").exists()


def test_progress_cursor_omissions_and_terminal_state(tmp_path):
    output = tmp_path / "out"
    _state(output)
    feed = output / ".assessment-progress.jsonl"
    feed.write_text("".join(json.dumps({"event": "warning", "detail": str(i)}) + "\n" for i in range(120)))

    def progress(cursor):
        return subprocess.run(
            [sys.executable, "-m", "appsec_analyzer.cli", "progress", "--output", str(output), "--after", str(cursor)],
            capture_output=True,
            text=True,
            timeout=20,
        )

    first = json.loads(progress(0).stdout)
    assert first["events_omitted"] and first["next_offset"] == 120 and len(first["events"]) == 100
    assert json.loads(progress(120).stdout)["events"] == []
    assert progress(-1).returncode == 2


@pytest.mark.parametrize("depth,budget", [("quick", 10), ("standard", 20), ("thorough", 40)])
def test_claude_host_defaults_and_explicit_limits(depth, budget, tmp_path, monkeypatch):
    from appsec_analyzer import cli

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    ns = cli._parser().parse_args(["assess", "--repo", str(repo), "--interactive-launch", "--assessment-depth", depth])
    cli._prepare_profile(ns)
    assert ns.hard_budget == budget and ns.max_parallel == 4 and ns.width == 72 and ns.non_interactive
    ns = cli._parser().parse_args(
        [
            "assess",
            "--repo",
            str(repo),
            "--interactive-launch",
            "--assessment-depth",
            depth,
            "--hard-budget",
            "2",
            "--component-workers",
            "1",
            "--width",
            "90",
        ]
    )
    cli._prepare_profile(ns)
    assert ns.hard_budget == 2 and ns.max_parallel == 1 and ns.width == 90


def test_claude_host_rejects_provider_switch_and_keeps_deprecated_budget(tmp_path):
    from appsec_analyzer import cli

    with pytest.raises(ValueError, match="requires the Claude"):
        cli._prepare_profile(cli._parser().parse_args(["assess", "--interactive-launch", "--profile", "codex"]))
    ns = cli._parser().parse_args(["assess", "--interactive-launch", "--soft-budget", "8"])
    cli._prepare_profile(ns)
    assert ns.hard_budget == 10


def test_public_query_and_summary_keep_validation_and_do_not_call_models(tmp_path, capsys, monkeypatch):
    from appsec_analyzer import cli, hosts
    from tests.test_public_export_cli import _bundle

    output = _bundle(tmp_path)
    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("query cannot call a model"))
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    assert cli.main(["query", "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)
    assert cli.main(["query", "--output", str(output), "--summary"]) == 0
    summary = capsys.readouterr().out
    assert "Questions: use query" in summary and "/appsec-advisor:" not in summary
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before
    (output / "security-assessment.yaml").write_text("changed")
    assert cli.main(["query", "--output", str(output)]) == 2


def test_host_cleanup_inspection_is_read_only(tmp_path):
    output = tmp_path / "private output"
    output.mkdir(mode=0o700)
    (output / ".appsec-lock").write_text("999999999\n1\n")
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    result = subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", "assessment-entry", "clean", "--output", str(output)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "stale"
    assert {p.name: p.read_bytes() for p in output.iterdir()} == before


@pytest.mark.parametrize("depth", ["quick", "standard", "thorough"])
@pytest.mark.parametrize("options", [[], ["--max-cost", "8"], ["--max-budget", "2", "--component-workers", "1"]])
def test_launch_defaults_preserve_compatibility_identity_without_display_settings(
    depth, options, tmp_path, monkeypatch
):
    from appsec_analyzer import cli

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "configuration"))
    base = ["assess", "--assessment-depth", depth, *options]
    legacy = cli._parser().parse_args([*base, "--interactive-launch"])
    canonical = cli._parser().parse_args([*base, "--launch-defaults", "advisor"])
    for ns in (legacy, canonical):
        cli._prepare_profile(ns)
    assert canonical.run_profile == legacy.run_profile
    assert canonical.width is None and canonical.non_interactive is False
    assert legacy.width == 72 and legacy.non_interactive is True


def test_launch_defaults_reject_provider_switch_without_changing_standalone_defaults():
    from appsec_analyzer import cli

    with pytest.raises(ValueError, match="requires the Claude"):
        cli._prepare_profile(cli._parser().parse_args(["assess", "--launch-defaults=advisor", "--profile", "codex"]))
    ns = cli._parser().parse_args(["assess", "--assessment-depth", "thorough"])
    cli._prepare_profile(ns)
    assert ns.hard_budget == 20 and ns.max_parallel == 4
    assert ns.width is None and not ns.non_interactive


@pytest.mark.parametrize("explicit", [False, True])
def test_launch_defaults_own_progress_path(tmp_path, monkeypatch, git_root, explicit):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime.assessment_state import PROGRESS_NAME

    observed = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda args, **kw: observed.append(args) or 0)
    output = tmp_path.parent / (tmp_path.name + "-results")
    selected = str(tmp_path / "explicit-feed")
    assert (
        cli.main(
            [
                "assess",
                "--repo",
                str(tmp_path),
                "--output",
                str(output),
                "--launch-defaults=advisor",
                *(["--progress-file", selected] if explicit else []),
            ]
        )
        == 0
    )
    assert observed[0].options.progress_file == (selected if explicit else str(output / PROGRESS_NAME))


@pytest.mark.parametrize("defect", ["source", "symlink", "hardlink", "live"])
def test_launch_progress_refuses_unsafe_or_owned_output(tmp_path, defect):
    from runtime.assessment_state import PROGRESS_NAME

    from appsec_analyzer import cli
    from appsec_analyzer.assessment_entry import progress_path

    output = tmp_path / "results"
    output.mkdir(mode=0o700)
    victim = tmp_path / "retained"
    victim.write_text("preserve")
    if defect == "source":
        subprocess.run(["git", "init", "-q", str(output)], check=True)
    elif defect == "symlink":
        (output / PROGRESS_NAME).symlink_to(victim)
    elif defect == "hardlink":
        os.link(victim, output / PROGRESS_NAME)
    else:
        (output / ".appsec-lock").write_text(f"{os.getpid()}\n{int(__import__('time').time())}\n")
    cli._engine_imports()
    with pytest.raises(ValueError):
        progress_path(str(output))
    assert victim.read_text() == "preserve"
